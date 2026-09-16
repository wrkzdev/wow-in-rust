//! The rustls [`CryptoProvider`] under the RPC server's TLS (`specs/11` §1.2),
//! and under a wallet's TLS to a node, built from pure-Rust RustCrypto crates:
//! no C, C++ or assembly, so neither ring nor aws-lc-rs.
//!
//! It is narrow on purpose: what the C++'s `ssl_options_t` negotiates, and
//! what a client of it may bring.
//!
//! - TLS 1.3 with AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305.
//! - TLS 1.2 with ECDHE, an ECDSA or RSA certificate and the same three
//!   ciphers: the C++'s `SSL_CTX_set_cipher_list`, suite for suite.
//! - Key exchange on X25519, secp256r1 or secp384r1.
//! - Private keys: RSA (PKCS#1, PKCS#8), ECDSA P-256 and P-384 (PKCS#8,
//!   SEC1), Ed25519 (PKCS#8).
//! - A peer's signatures: ECDSA P-256 and P-384, Ed25519, and RSA PKCS#1 v1.5
//!   and PSS on keys of 2048 to 8192 bits.
//!
//! The suites, groups and signature algorithms are those of the `ring`
//! provider this replaces, in its order, so a client negotiates what it did.
//!
//! # RSA private keys
//!
//! The C++ makes RSA-4096 pairs (`create_rsa_ssl_certificate`) and keeps them
//! as `rpc_ssl.key`, and `wownero-gen-ssl-cert` makes the same, so RSA keys are
//! served as they are. The `rsa` crate signs with them, blinded by a fresh
//! factor from the OS for every signature. Its big-integer arithmetic is not
//! constant-time, though (RUSTSEC-2023-0071, with no fixed release), so the
//! blinding narrows that timing side channel without closing it, and
//! `rpc::tls` warns when an RSA key is served. ECDSA and Ed25519 signing are
//! constant-time, and the pair this build generates is ECDSA P-256.
//!
//! Nothing here refers to the rest of `wownerod`: `tests/tls.rs` includes this
//! file as it is.

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::{self, AeadCore, AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::digest::core_api::BlockSizeUser;
use hmac::{Mac, SimpleHmac};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::signature::Signer as _;
use p256::elliptic_curve::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use p256::elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey};
use p256::pkcs8::spki::SubjectPublicKeyInfoRef;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::{OsRng, RngCore};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError, NONCE_LEN,
};
use rustls::crypto::hash::{self, HashAlgorithm};
use rustls::crypto::hmac as rustls_hmac;
use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    ActiveKeyExchange, CipherSuiteCommon, CryptoProvider, GetRandomFailed, KeyExchangeAlgorithm,
    KeyProvider, SecureRandom, SharedSecret, SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, PrivatePkcs8KeyDer,
    SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer,
};
use rustls::sign::{Signer, SigningKey};
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, NamedGroup, PeerMisbehaved,
    ProtocolVersion, SignatureAlgorithm, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite,
    Tls13CipherSuite,
};
use sha2::digest::const_oid::AssociatedOid;
use sha2::digest::DynDigest;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// The provider: every suite, group and algorithm below.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: CIPHER_SUITES.to_vec(),
        kx_groups: KX_GROUPS.to_vec(),
        signature_verification_algorithms: VERIFY_ALGORITHMS,
        secure_random: &OsRandom,
        key_provider: &Keys,
    }
}

/// The kinds of private key [`provider`] loads, for messages.
pub const SUPPORTED_KEYS: &str = "RSA of 2048 to 4096 bits (PKCS#1 or PKCS#8), ECDSA P-256 or \
                                  P-384 (PKCS#8 or SEC1), and Ed25519 (PKCS#8)";

// ---------------------------------------------------------------------------
// Cipher suites
// ---------------------------------------------------------------------------

/// The suites, most preferred first.
pub static CIPHER_SUITES: &[SupportedCipherSuite] = &[
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// AES-GCM's record limit, as rustls sets it for its own providers; the
/// AEAD-limits draft allows more for TLS 1.3, not less.
const GCM_CONFIDENTIALITY_LIMIT: u64 = 1 << 24;

pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: GCM_CONFIDENTIALITY_LIMIT,
        },
        hkdf_provider: &HkdfUsingHmac(&HMAC_SHA256),
        aead_alg: &AES_128_GCM,
        quic: None,
    });

pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: GCM_CONFIDENTIALITY_LIMIT,
        },
        hkdf_provider: &HkdfUsingHmac(&HMAC_SHA384),
        aead_alg: &AES_256_GCM,
        quic: None,
    });

pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(&HMAC_SHA256),
        aead_alg: &CHACHA20_POLY1305,
        quic: None,
    });

pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: GCM_CONFIDENTIALITY_LIMIT,
        },
        prf_provider: &PrfUsingHmac(&HMAC_SHA256),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &AES_128_GCM,
    });

pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: GCM_CONFIDENTIALITY_LIMIT,
        },
        prf_provider: &PrfUsingHmac(&HMAC_SHA384),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &AES_256_GCM,
    });

pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        prf_provider: &PrfUsingHmac(&HMAC_SHA256),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &CHACHA20_POLY1305,
    });

pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: GCM_CONFIDENTIALITY_LIMIT,
        },
        prf_provider: &PrfUsingHmac(&HMAC_SHA256),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &AES_128_GCM,
    });

pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: GCM_CONFIDENTIALITY_LIMIT,
        },
        prf_provider: &PrfUsingHmac(&HMAC_SHA384),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &AES_256_GCM,
    });

pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        prf_provider: &PrfUsingHmac(&HMAC_SHA256),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &CHACHA20_POLY1305,
    });

/// What a TLS 1.2 ECDHE_ECDSA suite may be signed with, as in rustls's own
/// providers.
static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

/// What a TLS 1.2 ECDHE_RSA suite may be signed with.
static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

// ---------------------------------------------------------------------------
// Hashes and HMAC: the transcript hash, TLS 1.2's PRF and TLS 1.3's HKDF
// ---------------------------------------------------------------------------

static SHA256: Sha<Sha256> = Sha(HashAlgorithm::SHA256, PhantomData);
static SHA384: Sha<Sha384> = Sha(HashAlgorithm::SHA384, PhantomData);
static HMAC_SHA256: HmacSha<Sha256> = HmacSha(PhantomData);
static HMAC_SHA384: HmacSha<Sha384> = HmacSha(PhantomData);

struct Sha<D>(HashAlgorithm, PhantomData<fn() -> D>);

impl<D> hash::Hash for Sha<D>
where
    D: Digest + Clone + Send + Sync + 'static,
{
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(ShaContext(<D as Digest>::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&D::digest(data))
    }

    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.0
    }
}

struct ShaContext<D>(D);

impl<D> hash::Context for ShaContext<D>
where
    D: Digest + Clone + Send + Sync + 'static,
{
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(ShaContext(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }
}

struct HmacSha<D>(PhantomData<fn() -> D>);

impl<D> rustls_hmac::Hmac for HmacSha<D>
where
    D: Digest + BlockSizeUser + Clone + Send + Sync + 'static,
{
    fn with_key(&self, key: &[u8]) -> Box<dyn rustls_hmac::Key> {
        // HMAC takes a key of any length, hashing a long one first, so this
        // cannot fail.
        let mac = <SimpleHmac<D> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
        Box::new(HmacKey(mac))
    }

    fn hash_output_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

struct HmacKey<D: Digest + BlockSizeUser>(SimpleHmac<D>);

impl<D> rustls_hmac::Key for HmacKey<D>
where
    D: Digest + BlockSizeUser + Clone + Send + Sync + 'static,
{
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> rustls_hmac::Tag {
        let mut mac = self.0.clone();
        Mac::update(&mut mac, first);
        for part in middle {
            Mac::update(&mut mac, part);
        }
        Mac::update(&mut mac, last);
        rustls_hmac::Tag::new(&mac.finalize().into_bytes())
    }

    fn tag_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

// ---------------------------------------------------------------------------
// Record protection
// ---------------------------------------------------------------------------

static AES_128_GCM: Aead<Aes128Gcm> = Aead(Cipher::Aes128Gcm, PhantomData);
static AES_256_GCM: Aead<Aes256Gcm> = Aead(Cipher::Aes256Gcm, PhantomData);
static CHACHA20_POLY1305: Aead<ChaCha20Poly1305> = Aead(Cipher::ChaCha20Poly1305, PhantomData);

const TAG_LEN: usize = 16;

/// What a TLS 1.2 GCM record carries of its nonce (RFC 5288 §3).
const GCM_EXPLICIT_NONCE_LEN: usize = 8;

/// The most plaintext a record may carry (RFC 5246 §6.2.1, RFC 8446 §5.1).
const MAX_FRAGMENT_LEN: usize = 16_384;

#[derive(Clone, Copy)]
enum Cipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// An AEAD as the record layer uses them: a 12-byte nonce, a 16-byte tag.
trait RecordCipher:
    KeyInit + AeadInPlace + AeadCore<NonceSize = U12, TagSize = U16> + Send + Sync + 'static
{
}

impl<C> RecordCipher for C where
    C: KeyInit + AeadInPlace + AeadCore<NonceSize = U12, TagSize = U16> + Send + Sync + 'static
{
}

struct Aead<C>(Cipher, PhantomData<fn() -> C>);

impl<C: RecordCipher> Aead<C> {
    fn cipher(&self, key: &AeadKey) -> C {
        // rustls cuts the key to `key_len()`, or `key_block_shape()`'s length.
        C::new_from_slice(key.as_ref()).expect("rustls gives a key of the length asked for")
    }

    fn secrets(&self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        match self.0 {
            Cipher::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            Cipher::Aes256Gcm => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            Cipher::ChaCha20Poly1305 => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
        }
    }

    /// TLS 1.2 sends part of a GCM record's nonce with the record; RFC 7905's
    /// ChaCha20-Poly1305 sends none.
    fn explicit_nonce_len(&self) -> usize {
        match self.0 {
            Cipher::Aes128Gcm | Cipher::Aes256Gcm => GCM_EXPLICIT_NONCE_LEN,
            Cipher::ChaCha20Poly1305 => 0,
        }
    }
}

impl<C: RecordCipher> Tls13AeadAlgorithm for Aead<C> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Records {
            cipher: self.cipher(&key),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Records {
            cipher: self.cipher(&key),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        C::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(self.secrets(key, iv))
    }
}

impl<C: RecordCipher> Tls12AeadAlgorithm for Aead<C> {
    fn encrypter(&self, key: AeadKey, iv: &[u8], explicit: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12Records {
            cipher: self.cipher(&key),
            iv: tls12_iv(iv, explicit),
            explicit_nonce_len: self.explicit_nonce_len(),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12Records {
            cipher: self.cipher(&key),
            iv: tls12_iv(iv, &[]),
            explicit_nonce_len: self.explicit_nonce_len(),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        let explicit = self.explicit_nonce_len();
        KeyBlockShape {
            enc_key_len: C::key_size(),
            fixed_iv_len: NONCE_LEN - explicit,
            explicit_nonce_len: explicit,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(self.secrets(key, tls12_iv(iv, explicit)))
    }
}

/// The 12 bytes a TLS 1.2 record's nonce starts from: the fixed part from the
/// key block, then, for a GCM encrypter, the explicit part; zeros for what
/// there is not.
fn tls12_iv(fixed: &[u8], explicit: &[u8]) -> Iv {
    let mut iv = [0u8; NONCE_LEN];
    for (to, from) in iv.iter_mut().zip(fixed.iter().chain(explicit)) {
        *to = *from;
    }
    Iv::new(iv)
}

/// TLS 1.3 record protection (RFC 8446 §5.2): the content type rides inside,
/// the nonce is the IV XOR the sequence number, the record header is the
/// additional data.
struct Tls13Records<C> {
    cipher: C,
    iv: Iv,
}

impl<C: RecordCipher> MessageEncrypter for Tls13Records<C> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let nonce = Nonce::new(&self.iv, seq).0;
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce.into(), &make_tls13_aad(total_len), payload.as_mut())
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        // Every protected TLS 1.3 record says it is TLS 1.2 application data
        // (RFC 8446 §5.1).
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl<C: RecordCipher> MessageDecrypter for Tls13Records<C> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let text_len = payload
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::DecryptError)?;
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(payload.len());
        let (text, tag) = payload.split_at_mut(text_len);
        self.cipher
            .decrypt_in_place_detached(&nonce.into(), &aad, text, aead::Tag::<C>::from_slice(tag))
            .map_err(|_| Error::DecryptError)?;
        payload.truncate(text_len);
        msg.into_tls13_unpadded_message()
    }
}

/// TLS 1.2 AEAD record protection (RFC 5246 §6.2.3.3). The nonce is the IV
/// XOR the sequence number: RFC 7905's construction for ChaCha20-Poly1305,
/// and for GCM, whose RFC 5288 leaves the explicit part to the sender, the one
/// rustls's own providers use, sending the explicit part before the
/// ciphertext.
struct Tls12Records<C> {
    cipher: C,
    iv: Iv,
    explicit_nonce_len: usize,
}

impl<C: RecordCipher> MessageEncrypter for Tls12Records<C> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        payload.extend_from_slice(&nonce[NONCE_LEN - self.explicit_nonce_len..]);
        payload.extend_from_chunks(&msg.payload);
        let tag = self
            .cipher
            .encrypt_in_place_detached(
                &nonce.into(),
                &aad,
                &mut payload.as_mut()[self.explicit_nonce_len..],
            )
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + self.explicit_nonce_len + TAG_LEN
    }
}

impl<C: RecordCipher> MessageDecrypter for Tls12Records<C> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let (typ, version) = (msg.typ, msg.version);
        let explicit = self.explicit_nonce_len;
        let payload = &mut msg.payload;
        let text_len = payload
            .len()
            .checked_sub(explicit + TAG_LEN)
            .ok_or(Error::DecryptError)?;
        let mut nonce = Nonce::new(&self.iv, seq).0;
        nonce[NONCE_LEN - explicit..].copy_from_slice(&payload[..explicit]);
        let aad = make_tls12_aad(seq, typ, version, text_len);
        let (text, tag) = payload[explicit..].split_at_mut(text_len);
        self.cipher
            .decrypt_in_place_detached(&nonce.into(), &aad, text, aead::Tag::<C>::from_slice(tag))
            .map_err(|_| Error::DecryptError)?;
        if text_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        payload.copy_within(explicit..explicit + text_len, 0);
        payload.truncate(text_len);
        Ok(msg.into_plain_message())
    }
}

// ---------------------------------------------------------------------------
// Key exchange
// ---------------------------------------------------------------------------

/// The groups, most preferred first.
pub static KX_GROUPS: &[&dyn SupportedKxGroup] = &[X25519, SECP256R1, SECP384R1];

pub static X25519: &dyn SupportedKxGroup = &X25519Group;

pub static SECP256R1: &dyn SupportedKxGroup = &NistGroup::<p256::NistP256> {
    name: NamedGroup::secp256r1,
    curve: PhantomData,
};

pub static SECP384R1: &dyn SupportedKxGroup = &NistGroup::<p384::NistP384> {
    name: NamedGroup::secp384r1,
    curve: PhantomData,
};

#[derive(Debug)]
struct X25519Group;

impl SupportedKxGroup for X25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Ok(Box::new(X25519Exchange { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct X25519Exchange {
    secret: x25519_dalek::EphemeralSecret,
    public: [u8; 32],
}

impl ActiveKeyExchange for X25519Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
        let X25519Exchange { secret, .. } = *self;
        let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        // All zeros: the peer's point had a small order (RFC 7748 §6.1).
        if !shared.was_contributory() {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared.as_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// Ephemeral ECDH on a NIST curve.
struct NistGroup<C> {
    name: NamedGroup,
    curve: PhantomData<fn() -> C>,
}

impl<C> fmt::Debug for NistGroup<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)
    }
}

impl<C> SupportedKxGroup for NistGroup<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = EphemeralSecret::<C>::random(&mut OsRng);
        let public = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Ok(Box::new(NistExchange {
            name: self.name,
            secret,
            public,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.name
    }
}

struct NistExchange<C: CurveArithmetic> {
    name: NamedGroup,
    secret: EphemeralSecret<C>,
    public: Vec<u8>,
}

impl<C> ActiveKeyExchange for NistExchange<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        // Uncompressed points only: all TLS 1.3 allows (RFC 8446 §4.2.8.2),
        // and all this side offers TLS 1.2 (RFC 8422 §5.1.2).
        if peer.first() != Some(&0x04) {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let peer =
            PublicKey::<C>::from_sec1_bytes(peer).map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(SharedSecret::from(shared.raw_secret_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct OsRandom;

impl SecureRandom for OsRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        OsRng.try_fill_bytes(buf).map_err(|_| GetRandomFailed)
    }
}

// ---------------------------------------------------------------------------
// Checking signatures: certificates, and a peer's handshake signature
// ---------------------------------------------------------------------------

/// The algorithms, and which a TLS signature scheme may use: for TLS 1.3 the
/// first, whose curve the scheme fixes; for TLS 1.2 any.
static VERIFY_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ED25519,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
        RSA_PKCS1_SHA256_ABSENT_PARAMS,
        RSA_PKCS1_SHA384_ABSENT_PARAMS,
        RSA_PKCS1_SHA512_ABSENT_PARAMS,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256],
        ),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::ECDSA_P256,
    signature: alg_id::ECDSA_SHA256,
    check: ecdsa_p256::<Sha256>,
};

static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::ECDSA_P256,
    signature: alg_id::ECDSA_SHA384,
    check: ecdsa_p256::<Sha384>,
};

static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::ECDSA_P384,
    signature: alg_id::ECDSA_SHA256,
    check: ecdsa_p384::<Sha256>,
};

static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::ECDSA_P384,
    signature: alg_id::ECDSA_SHA384,
    check: ecdsa_p384::<Sha384>,
};

static ED25519: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::ED25519,
    signature: alg_id::ED25519,
    check: ed25519,
};

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PSS_SHA256,
    check: rsa_pss::<Sha256>,
};

static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PSS_SHA384,
    check: rsa_pss::<Sha384>,
};

static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PSS_SHA512,
    check: rsa_pss::<Sha512>,
};

static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PKCS1_SHA256,
    check: rsa_pkcs1::<Sha256>,
};

static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PKCS1_SHA384,
    check: rsa_pkcs1::<Sha384>,
};

static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PKCS1_SHA512,
    check: rsa_pkcs1::<Sha512>,
};

// Certificates signed with the RSA PKCS#1 v1.5 OIDs but without their NULL
// parameters, which RFC 4055 §5 says to accept and webpki does.

static RSA_PKCS1_SHA256_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::RSA_ENCRYPTION,
    // sha256WithRSAEncryption, 1.2.840.113549.1.1.11
    signature: AlgorithmIdentifier::from_slice(&[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    ]),
    check: rsa_pkcs1::<Sha256>,
};

static RSA_PKCS1_SHA384_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::RSA_ENCRYPTION,
    // sha384WithRSAEncryption, 1.2.840.113549.1.1.12
    signature: AlgorithmIdentifier::from_slice(&[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
    ]),
    check: rsa_pkcs1::<Sha384>,
};

static RSA_PKCS1_SHA512_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key: alg_id::RSA_ENCRYPTION,
    // sha512WithRSAEncryption, 1.2.840.113549.1.1.13
    signature: AlgorithmIdentifier::from_slice(&[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
    ]),
    check: rsa_pkcs1::<Sha512>,
};

/// A signature check: public key, message, signature.
type Check = fn(&[u8], &[u8], &[u8]) -> Result<(), InvalidSignature>;

/// A signature algorithm: which key and signature it takes, and the check.
/// The public key is what a certificate's `subjectPublicKey` bit string
/// holds.
#[derive(Debug)]
struct Verify {
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
    check: Check,
}

impl SignatureVerificationAlgorithm for Verify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        (self.check)(public_key, message, signature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }
}

/// ECDSA on P-256 with any hash: a prehash longer than the curve is cut to
/// its leftmost bits, a shorter one taken as it is (FIPS 186-5 §6.4.1).
fn ecdsa_p256<D: Digest>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    let key =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
    let signature = p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
    key.verify_prehash(&D::digest(message), &signature)
        .map_err(|_| InvalidSignature)
}

/// ECDSA on P-384 with any hash, as [`ecdsa_p256`].
fn ecdsa_p384<D: Digest>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    let key =
        p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
    let signature = p384::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
    key.verify_prehash(&D::digest(message), &signature)
        .map_err(|_| InvalidSignature)
}

fn ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
    let key: &[u8; 32] = public_key.try_into().map_err(|_| InvalidSignature)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|_| InvalidSignature)?;
    let signature =
        ed25519_dalek::Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| InvalidSignature)
}

/// A certificate's RSA key, `RSAPublicKey` DER, of 2048 to 8192 bits: what
/// webpki took with ring. (`rsa`'s own decoding stops at 4096 bits.)
fn rsa_public_key(der: &[u8]) -> Result<rsa::RsaPublicKey, InvalidSignature> {
    let key = rsa::pkcs1::RsaPublicKey::try_from(der).map_err(|_| InvalidSignature)?;
    let n = rsa::BigUint::from_bytes_be(key.modulus.as_bytes());
    let e = rsa::BigUint::from_bytes_be(key.public_exponent.as_bytes());
    // ring counts the lower bound in whole bytes.
    if n.bits().div_ceil(8) * 8 < 2048 {
        return Err(InvalidSignature);
    }
    rsa::RsaPublicKey::new_with_max_size(n, e, 8192).map_err(|_| InvalidSignature)
}

/// RSASSA-PSS with MGF1 on the same hash and a salt as long as it, which is
/// all TLS allows (RFC 8446 §4.2.3).
fn rsa_pss<D>(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature>
where
    D: 'static + Digest + DynDigest + Send + Sync,
{
    rsa_public_key(public_key)?
        .verify(rsa::Pss::new::<D>(), &D::digest(message), signature)
        .map_err(|_| InvalidSignature)
}

fn rsa_pkcs1<D>(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature>
where
    D: Digest + AssociatedOid,
{
    rsa_public_key(public_key)?
        .verify(
            rsa::Pkcs1v15Sign::new::<D>(),
            &D::digest(message),
            signature,
        )
        .map_err(|_| InvalidSignature)
}

// ---------------------------------------------------------------------------
// Private keys
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Keys;

impl KeyProvider for Keys {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        Ok(Arc::new(PrivateKey::load(&key_der)?))
    }
}

/// A private key this provider signs with.
enum Key {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
    /// Blinded, not constant-time: see the module's documentation.
    Rsa(rsa::RsaPrivateKey),
}

impl Key {
    /// A key as PEM carries it: `RSA PRIVATE KEY` (PKCS#1), `EC PRIVATE KEY`
    /// (SEC1) or `PRIVATE KEY` (PKCS#8).
    fn from_der(der: &PrivateKeyDer<'_>) -> Result<Key, Error> {
        match der {
            PrivateKeyDer::Pkcs1(der) => {
                Key::rsa(rsa::RsaPrivateKey::from_pkcs1_der(der.secret_pkcs1_der()))
            }
            PrivateKeyDer::Sec1(der) => {
                let der = der.secret_sec1_der();
                if let Ok(key) = p256::SecretKey::from_sec1_der(der) {
                    return Ok(Key::P256(key.into()));
                }
                if let Ok(key) = p384::SecretKey::from_sec1_der(der) {
                    return Ok(Key::P384(key.into()));
                }
                Err(unsupported_key())
            }
            PrivateKeyDer::Pkcs8(der) => Key::from_pkcs8(der.secret_pkcs8_der()),
            _ => Err(unsupported_key()),
        }
    }

    /// PKCS#8, by the algorithm it names.
    fn from_pkcs8(der: &[u8]) -> Result<Key, Error> {
        let info = rsa::pkcs8::PrivateKeyInfo::try_from(der)
            .map_err(|e| Error::General(format!("the private key is not valid PKCS#8: {e}")))?;
        let algorithm = info.algorithm.oid;
        if algorithm == rsa::pkcs1::ALGORITHM_OID {
            return Key::rsa(rsa::RsaPrivateKey::from_pkcs8_der(der));
        }
        if algorithm == p256::elliptic_curve::ALGORITHM_OID {
            if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
                return Ok(Key::P256(key));
            }
            if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
                return Ok(Key::P384(key));
            }
        }
        if algorithm == ed25519_dalek::pkcs8::ALGORITHM_OID {
            return ed25519_dalek::SigningKey::from_pkcs8_der(der)
                .map(Key::Ed25519)
                .map_err(|e| Error::General(format!("cannot load the Ed25519 private key: {e}")));
        }
        Err(unsupported_key())
    }

    /// An RSA key in the sizes ring took, so that what loaded before loads
    /// now and nothing more: at least 2048 bits, counted in whole bytes as
    /// ring counts them, and at most 4096.
    fn rsa(key: Result<rsa::RsaPrivateKey, impl fmt::Display>) -> Result<Key, Error> {
        let key =
            key.map_err(|e| Error::General(format!("cannot load the RSA private key: {e}")))?;
        let bits = key.n().bits();
        if bits.div_ceil(8) * 8 < 2048 || bits > 4096 {
            return Err(Error::General(format!(
                "the RSA private key has {bits} bits; this build takes {SUPPORTED_KEYS}"
            )));
        }
        Ok(Key::Rsa(key))
    }

    /// The schemes it signs TLS handshakes with, most preferred first.
    fn schemes(&self) -> &'static [SignatureScheme] {
        match self {
            Key::P256(_) => &[SignatureScheme::ECDSA_NISTP256_SHA256],
            Key::P384(_) => &[SignatureScheme::ECDSA_NISTP384_SHA384],
            Key::Ed25519(_) => &[SignatureScheme::ED25519],
            Key::Rsa(_) => TLS12_RSA_SCHEMES,
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            Key::P256(_) | Key::P384(_) => SignatureAlgorithm::ECDSA,
            Key::Ed25519(_) => SignatureAlgorithm::ED25519,
            Key::Rsa(_) => SignatureAlgorithm::RSA,
        }
    }

    /// Its public key as a certificate holds it, `SubjectPublicKeyInfo` DER:
    /// rustls compares the two to tell a key from another certificate's.
    fn spki(&self) -> Result<Vec<u8>, Error> {
        let spki = match self {
            Key::P256(key) => key.verifying_key().to_public_key_der(),
            Key::P384(key) => key.verifying_key().to_public_key_der(),
            Key::Ed25519(key) => key.verifying_key().to_public_key_der(),
            Key::Rsa(key) => key.to_public_key().to_public_key_der(),
        };
        spki.map(|der| der.into_vec())
            .map_err(|e| Error::General(format!("cannot encode the public key: {e}")))
    }

    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, Error> {
        let signed = match (self, scheme) {
            (Key::P256(key), SignatureScheme::ECDSA_NISTP256_SHA256) => key
                .try_sign(message)
                .map(|s: p256::ecdsa::DerSignature| s.as_bytes().to_vec())
                .map_err(|e| e.to_string()),
            (Key::P384(key), SignatureScheme::ECDSA_NISTP384_SHA384) => key
                .try_sign(message)
                .map(|s: p384::ecdsa::DerSignature| s.as_bytes().to_vec())
                .map_err(|e| e.to_string()),
            (Key::Ed25519(key), SignatureScheme::ED25519) => key
                .try_sign(message)
                .map(|s| s.to_bytes().to_vec())
                .map_err(|e| e.to_string()),
            (Key::Rsa(key), SignatureScheme::RSA_PSS_SHA256) => {
                rsa_sign_pss::<Sha256>(key, message)
            }
            (Key::Rsa(key), SignatureScheme::RSA_PSS_SHA384) => {
                rsa_sign_pss::<Sha384>(key, message)
            }
            (Key::Rsa(key), SignatureScheme::RSA_PSS_SHA512) => {
                rsa_sign_pss::<Sha512>(key, message)
            }
            (Key::Rsa(key), SignatureScheme::RSA_PKCS1_SHA256) => {
                rsa_sign_pkcs1::<Sha256>(key, message)
            }
            (Key::Rsa(key), SignatureScheme::RSA_PKCS1_SHA384) => {
                rsa_sign_pkcs1::<Sha384>(key, message)
            }
            (Key::Rsa(key), SignatureScheme::RSA_PKCS1_SHA512) => {
                rsa_sign_pkcs1::<Sha512>(key, message)
            }
            _ => Err(format!("this key does not sign with {scheme:?}")),
        };
        signed.map_err(|e| Error::General(format!("signing failed: {e}")))
    }
}

/// Blinded RSASSA-PSS, a salt as long as the hash.
fn rsa_sign_pss<D>(key: &rsa::RsaPrivateKey, message: &[u8]) -> Result<Vec<u8>, String>
where
    D: 'static + Digest + DynDigest + Send + Sync,
{
    key.sign_with_rng(
        &mut OsRng,
        rsa::Pss::new_blinded::<D>(),
        &D::digest(message),
    )
    .map_err(|e| e.to_string())
}

/// Blinded RSASSA-PKCS1-v1_5: `sign_with_rng` blinds whenever it has an RNG.
fn rsa_sign_pkcs1<D>(key: &rsa::RsaPrivateKey, message: &[u8]) -> Result<Vec<u8>, String>
where
    D: Digest + AssociatedOid,
{
    key.sign_with_rng(
        &mut OsRng,
        rsa::Pkcs1v15Sign::new::<D>(),
        &D::digest(message),
    )
    .map_err(|e| e.to_string())
}

fn unsupported_key() -> Error {
    Error::General(format!(
        "the private key is not of a kind this build can use; it takes {SUPPORTED_KEYS}"
    ))
}

/// A loaded key, as rustls holds it.
struct PrivateKey {
    key: Arc<Key>,
    spki: Vec<u8>,
}

impl PrivateKey {
    fn load(der: &PrivateKeyDer<'_>) -> Result<PrivateKey, Error> {
        let key = Key::from_der(der)?;
        let spki = key.spki()?;
        Ok(PrivateKey {
            key: Arc::new(key),
            spki,
        })
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("algorithm", &self.key.algorithm())
            .finish_non_exhaustive()
    }
}

impl SigningKey for PrivateKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = *self.key.schemes().iter().find(|s| offered.contains(s))?;
        Some(Box::new(KeySigner {
            key: self.key.clone(),
            scheme,
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.spki.as_slice()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.key.algorithm()
    }
}

struct KeySigner {
    key: Arc<Key>,
    scheme: SignatureScheme,
}

impl fmt::Debug for KeySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySigner")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl Signer for KeySigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key.sign(self.scheme, message)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// A new ECDSA P-256 private key, as PKCS#8 DER and as PEM.
pub fn generate_p256() -> Result<(PrivateKeyDer<'static>, String), Error> {
    let key = p256::SecretKey::random(&mut OsRng);
    let failed = |e: p256::pkcs8::Error| Error::General(format!("cannot encode a new key: {e}"));
    let der = key.to_pkcs8_der().map_err(failed)?;
    let pem = key.to_pkcs8_pem(LineEnding::LF).map_err(failed)?;
    Ok((
        PrivatePkcs8KeyDer::from(der.as_bytes().to_vec()).into(),
        pem.as_str().to_owned(),
    ))
}

/// A private key rcgen signs a certificate with, through this provider's own
/// signing, so a certificate made with it is one [`provider`] serves. X.509
/// signs as TLS does for these keys: DER ECDSA, plain Ed25519, and RSA
/// PKCS#1 v1.5 with SHA-256.
pub struct CertSigner {
    key: Arc<Key>,
    scheme: SignatureScheme,
    algorithm: &'static rcgen::SignatureAlgorithm,
    /// The `subjectPublicKey` bits.
    public_key: Vec<u8>,
}

impl CertSigner {
    pub fn new(der: &PrivateKeyDer<'_>) -> Result<CertSigner, Error> {
        let PrivateKey { key, spki } = PrivateKey::load(der)?;
        let (scheme, algorithm) = match &*key {
            Key::P256(_) => (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                &rcgen::PKCS_ECDSA_P256_SHA256,
            ),
            Key::P384(_) => (
                SignatureScheme::ECDSA_NISTP384_SHA384,
                &rcgen::PKCS_ECDSA_P384_SHA384,
            ),
            Key::Ed25519(_) => (SignatureScheme::ED25519, &rcgen::PKCS_ED25519),
            Key::Rsa(_) => (SignatureScheme::RSA_PKCS1_SHA256, &rcgen::PKCS_RSA_SHA256),
        };
        let public_key = SubjectPublicKeyInfoRef::try_from(spki.as_slice())
            .map_err(|e| Error::General(format!("cannot read the public key: {e}")))?
            .subject_public_key
            .raw_bytes()
            .to_vec();
        Ok(CertSigner {
            key,
            scheme,
            algorithm,
            public_key,
        })
    }
}

impl rcgen::PublicKeyData for CertSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.algorithm
    }
}

impl rcgen::SigningKey for CertSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.key
            .sign(self.scheme, message)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}
