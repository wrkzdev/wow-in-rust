//! [`provider`]'s tests: a handshake and an exchange of application data for
//! every suite with every kind of key it can be signed with and for every key
//! exchange group, the key formats it loads, RSA signing with every scheme,
//! the pairs `rpc::tls` serves, and known answers for record protection.

use std::io::{Read, Write};
use std::sync::OnceLock;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{OsRng, RngCore};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::crypto::cipher::{AeadKey, InboundOpaqueMessage, Iv, OutboundPlainMessage};
use rustls::crypto::SupportedKxGroup;
use rustls::pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, ContentType, ProtocolVersion,
    SupportedCipherSuite, SupportedProtocolVersion,
};

use super::provider::{self, CertSigner};
use super::*;

const REQUEST: &[u8] = b"POST /get_height HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
const ANSWER: &[u8] = b"HTTP/1.1 200 Ok\r\nContent-Length: 13\r\n\r\n{\"height\":1}\n";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    P256,
    P384,
    Ed25519,
    Rsa,
}

use Kind::{Ed25519, Rsa, P256, P384};

/// One RSA-2048 key for all the tests: finding primes is slow.
fn rsa_key() -> &'static rsa::RsaPrivateKey {
    static KEY: OnceLock<rsa::RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap())
}

/// A private key of `kind` as PKCS#8, fresh except for RSA.
fn pkcs8(kind: Kind) -> PrivateKeyDer<'static> {
    let der = match kind {
        P256 => p256::SecretKey::random(&mut OsRng).to_pkcs8_der(),
        P384 => p384::SecretKey::random(&mut OsRng).to_pkcs8_der(),
        Ed25519 => {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            ed25519_dalek::SigningKey::from_bytes(&seed).to_pkcs8_der()
        }
        Rsa => rsa_key().to_pkcs8_der(),
    };
    PrivatePkcs8KeyDer::from(der.unwrap().as_bytes().to_vec()).into()
}

/// A self-signed certificate for `localhost` on `key`. rcgen without a crypto
/// backend of its own draws no serial number, so one is given.
fn certificate(key: &PrivateKeyDer<'_>) -> CertificateDer<'static> {
    let signer = CertSigner::new(key).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.serial_number = Some(rcgen::SerialNumber::from(OsRng.next_u64()));
    params.self_signed(&signer).unwrap().der().clone()
}

/// The provider cut down to one suite and one group, so that is what is
/// negotiated.
fn only(suite: SupportedCipherSuite, group: &'static dyn SupportedKxGroup) -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        cipher_suites: vec![suite],
        kx_groups: vec![group],
        ..provider::provider()
    })
}

fn server(
    provider: &Arc<CryptoProvider>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Arc<ServerConfig> {
    let config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    Arc::new(config)
}

/// A client that trusts `root` and checks the server's certificate against it
/// as webpki does: the certificate's own signature, its name, its dates.
fn client(
    provider: &Arc<CryptoProvider>,
    version: &'static SupportedProtocolVersion,
    root: &CertificateDer<'static>,
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// Accepts any certificate, but checks the handshake signature made with it:
/// for the generated certificate, which names no host.
#[derive(Debug)]
struct AnyCertificate(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

fn any_certificate_client(version: &'static SupportedProtocolVersion) -> Arc<ClientConfig> {
    let provider = Arc::new(provider::provider());
    let verifier = Arc::new(AnyCertificate(provider.signature_verification_algorithms));
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Arc::new(config)
}

/// Hand what `from` has written to `to`; whether there was anything.
fn send<A, B>(from: &mut ConnectionCommon<A>, to: &mut ConnectionCommon<B>) -> bool {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire).unwrap();
    }
    let mut rest = &wire[..];
    while !rest.is_empty() {
        to.read_tls(&mut rest).unwrap();
        to.process_new_packets().expect("the records are accepted");
    }
    !wire.is_empty()
}

/// Pass records both ways until neither side has more to say.
fn exchange(client: &mut ClientConnection, server: &mut ServerConnection) {
    for _ in 0..16 {
        let sent = send(client, server);
        let answered = send(server, client);
        if !sent && !answered {
            return;
        }
    }
    panic!("the conversation does not settle");
}

/// A handshake, then a request and its answer, as the RPC server has them.
fn round_trip(
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
) -> (ClientConnection, ServerConnection) {
    let mut c = ClientConnection::new(client, "localhost".try_into().unwrap()).unwrap();
    let mut s = ServerConnection::new(server).unwrap();
    c.writer().write_all(REQUEST).unwrap();
    exchange(&mut c, &mut s);
    assert!(!c.is_handshaking() && !s.is_handshaking());
    let mut got = vec![0; REQUEST.len()];
    s.reader().read_exact(&mut got).unwrap();
    assert_eq!(got, REQUEST);

    s.writer().write_all(ANSWER).unwrap();
    exchange(&mut c, &mut s);
    let mut got = vec![0; ANSWER.len()];
    c.reader().read_exact(&mut got).unwrap();
    assert_eq!(got, ANSWER);
    (c, s)
}

/// The TLS 1.3 scheme a key of `kind` signs a handshake with, when offered
/// everything; RSA's is PSS, as TLS 1.3 requires.
fn tls13_scheme(kind: Kind) -> SignatureScheme {
    match kind {
        P256 => SignatureScheme::ECDSA_NISTP256_SHA256,
        P384 => SignatureScheme::ECDSA_NISTP384_SHA384,
        Ed25519 => SignatureScheme::ED25519,
        Rsa => SignatureScheme::RSA_PSS_SHA512,
    }
}

/// Whether `signature` checks out with the first algorithm the provider maps
/// `scheme` to, the one TLS 1.3 uses.
fn verifies(scheme: SignatureScheme, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let algorithms = provider::provider().signature_verification_algorithms;
    let (_, candidates) = algorithms
        .mapping
        .iter()
        .find(|(s, _)| *s == scheme)
        .expect("a mapped scheme");
    candidates[0]
        .verify_signature(public_key, message, signature)
        .is_ok()
}

/// **Every suite**, with every kind of key it can be signed with -- TLS 1.3
/// with any, TLS 1.2's ECDHE_ECDSA with ECDSA or Ed25519, ECDHE_RSA with RSA --
/// hands a request and its answer across, and negotiates what it was given.
#[test]
fn every_suite_carries_data_with_every_kind_of_key() {
    const ANY: &[Kind] = &[P256, P384, Ed25519, Rsa];
    const ECDSA: &[Kind] = &[P256, P384, Ed25519];
    const RSA: &[Kind] = &[Rsa];
    let cases: &[(SupportedCipherSuite, &[Kind])] = &[
        (provider::TLS13_AES_128_GCM_SHA256, ANY),
        (provider::TLS13_AES_256_GCM_SHA384, ANY),
        (provider::TLS13_CHACHA20_POLY1305_SHA256, ANY),
        (provider::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ECDSA),
        (provider::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, ECDSA),
        (
            provider::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ECDSA,
        ),
        (provider::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, RSA),
        (provider::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, RSA),
        (provider::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, RSA),
    ];
    assert_eq!(cases.len(), provider::CIPHER_SUITES.len());
    assert!(provider::CIPHER_SUITES
        .iter()
        .all(|s| cases.iter().any(|(c, _)| c == s)));

    for (suite, kinds) in cases {
        for kind in *kinds {
            let key = pkcs8(*kind);
            let cert = certificate(&key);
            let provider = only(*suite, provider::X25519);
            let version = suite.version();
            let (c, s) = round_trip(
                server(&provider, cert.clone(), key),
                client(&provider, version, &cert),
            );
            let what = format!("{:?} with {kind:?}", suite.suite());
            assert_eq!(c.negotiated_cipher_suite(), Some(*suite), "{what}");
            assert_eq!(s.negotiated_cipher_suite(), Some(*suite), "{what}");
            assert_eq!(c.protocol_version(), Some(version.version), "{what}");
            assert_eq!(c.peer_certificates().unwrap()[0], cert, "{what}");
        }
    }
}

/// **Every key exchange group**, over TLS 1.3 and TLS 1.2.
#[test]
fn every_group_agrees_a_key_in_either_version() {
    let key = pkcs8(P256);
    let cert = certificate(&key);
    for group in provider::KX_GROUPS {
        for suite in [
            provider::TLS13_AES_128_GCM_SHA256,
            provider::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ] {
            let provider = only(suite, *group);
            let (c, s) = round_trip(
                server(&provider, cert.clone(), key.clone_key()),
                client(&provider, suite.version(), &cert),
            );
            for negotiated in [
                c.negotiated_key_exchange_group(),
                s.negotiated_key_exchange_group(),
            ] {
                assert_eq!(
                    negotiated.map(|g| g.name()),
                    Some(group.name()),
                    "{:?}",
                    suite.suite()
                );
            }
        }
    }
}

/// **The full provider**, as the server runs it, against a client offering
/// everything: TLS 1.3, X25519 and the most preferred suite.
#[test]
fn the_whole_provider_prefers_tls13_x25519_and_aes_256() {
    for kind in [P256, Rsa] {
        let key = pkcs8(kind);
        let cert = certificate(&key);
        let provider = Arc::new(provider::provider());
        let (c, _) = round_trip(
            server(&provider, cert.clone(), key),
            client(&provider, &rustls::version::TLS13, &cert),
        );
        assert_eq!(
            c.negotiated_cipher_suite(),
            Some(provider::TLS13_AES_256_GCM_SHA384)
        );
        assert_eq!(
            c.negotiated_key_exchange_group().map(|g| g.name()),
            Some(rustls::NamedGroup::X25519)
        );
    }
}

/// **The generated certificate**, over TLS 1.3 and TLS 1.2: an ECDSA P-256
/// pair, served with the fingerprint of what was written.
#[test]
fn the_generated_pair_is_p256_and_serves_both_versions() {
    let dir = scratch("generated");
    let tls = Tls::from_config(&Config::default(), &dir).unwrap().unwrap();
    let crt = CertificateDer::from_pem_file(dir.join("rpc_ssl.crt")).unwrap();
    let key = PrivateKeyDer::from_pem_file(dir.join("rpc_ssl.key")).unwrap();
    assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    let key = provider::provider()
        .key_provider
        .load_private_key(key)
        .unwrap();
    assert_eq!(key.algorithm(), SignatureAlgorithm::ECDSA);
    assert_eq!(tls.fingerprint(), fingerprint(&crt));

    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let (c, _) = round_trip(tls.config.clone(), any_certificate_client(version));
        assert_eq!(c.protocol_version(), Some(version.version));
        assert_eq!(c.peer_certificates().unwrap()[0], crt);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// **A pair the C++ left**: an RSA key as PKCS#8 PEM (`PEM_write_PrivateKey`)
/// with a serial-1, empty-subject certificate signed SHA-256, in the data
/// directory. It is served as it is, over TLS 1.3 and TLS 1.2's ECDHE_RSA
/// suites, and nothing is generated over it.
#[test]
fn a_cpp_rsa_pair_in_the_data_directory_is_served_as_it_is() {
    let dir = scratch("cpp");
    let key_pem = rsa_key().to_pkcs8_pem(LineEnding::LF).unwrap();
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serial_number = Some(rcgen::SerialNumber::from(1u64));
    let cert = params.self_signed(&CertSigner::new(&key).unwrap()).unwrap();
    std::fs::write(dir.join("rpc_ssl.key"), key_pem.as_bytes()).unwrap();
    std::fs::write(dir.join("rpc_ssl.crt"), cert.pem()).unwrap();

    let tls = Tls::from_config(&Config::default(), &dir).unwrap().unwrap();
    assert_eq!(tls.fingerprint(), fingerprint(cert.der()));
    assert_eq!(
        std::fs::read(dir.join("rpc_ssl.key")).unwrap(),
        key_pem.as_bytes(),
        "the key is left as it was"
    );
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let (c, _) = round_trip(tls.config.clone(), any_certificate_client(version));
        assert_eq!(c.protocol_version(), Some(version.version));
        assert_eq!(&c.peer_certificates().unwrap()[0], cert.der());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// **RSA keys**, PKCS#8 as the C++ and `wownero-gen-ssl-cert` write them and
/// PKCS#1 as older `openssl genrsa` does, load and sign with every scheme
/// rustls may ask for, each signature checking out and failing on another
/// message.
#[test]
fn an_rsa_key_loads_and_signs_with_every_scheme() {
    let pkcs1: PrivateKeyDer<'static> =
        PrivatePkcs1KeyDer::from(rsa_key().to_pkcs1_der().unwrap().as_bytes().to_vec()).into();
    for der in [pkcs8(Rsa), pkcs1] {
        let key = provider::provider()
            .key_provider
            .load_private_key(der.clone_key())
            .unwrap();
        assert_eq!(key.algorithm(), SignatureAlgorithm::RSA);
        let public_key = rcgen::PublicKeyData::der_bytes(&CertSigner::new(&der).unwrap()).to_vec();
        for scheme in [
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ] {
            let signer = key.choose_scheme(&[scheme]).expect("RSA signs with it");
            assert_eq!(signer.scheme(), scheme);
            let signature = signer.sign(REQUEST).unwrap();
            assert_eq!(signature.len(), 256, "{scheme:?}");
            assert!(
                verifies(scheme, &public_key, REQUEST, &signature),
                "{scheme:?}"
            );
            assert!(
                !verifies(scheme, &public_key, ANSWER, &signature),
                "{scheme:?}"
            );
        }
        assert!(key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .is_none());
    }
}

/// **ECDSA and Ed25519 keys**: P-256 and P-384 as PKCS#8 and SEC1, Ed25519 as
/// PKCS#8, each loading as its kind and signing with its one scheme.
#[test]
fn ecdsa_and_ed25519_keys_load_and_sign() {
    let p256 = p256::SecretKey::random(&mut OsRng);
    let p384 = p384::SecretKey::random(&mut OsRng);
    let pkcs8_of =
        |der: Vec<u8>| -> PrivateKeyDer<'static> { PrivatePkcs8KeyDer::from(der).into() };
    let sec1_of = |der: Vec<u8>| -> PrivateKeyDer<'static> { PrivateSec1KeyDer::from(der).into() };
    let cases = [
        (
            pkcs8_of(p256.to_pkcs8_der().unwrap().as_bytes().to_vec()),
            P256,
        ),
        (sec1_of(p256.to_sec1_der().unwrap().to_vec()), P256),
        (
            pkcs8_of(p384.to_pkcs8_der().unwrap().as_bytes().to_vec()),
            P384,
        ),
        (sec1_of(p384.to_sec1_der().unwrap().to_vec()), P384),
        (pkcs8(Ed25519), Ed25519),
    ];
    for (der, kind) in cases {
        let key = provider::provider()
            .key_provider
            .load_private_key(der.clone_key())
            .unwrap();
        let algorithm = match kind {
            Ed25519 => SignatureAlgorithm::ED25519,
            _ => SignatureAlgorithm::ECDSA,
        };
        assert_eq!(key.algorithm(), algorithm, "{kind:?}");
        let scheme = tls13_scheme(kind);
        let public_key = rcgen::PublicKeyData::der_bytes(&CertSigner::new(&der).unwrap()).to_vec();
        let signature = key.choose_scheme(&[scheme]).unwrap().sign(REQUEST).unwrap();
        assert!(
            verifies(scheme, &public_key, REQUEST, &signature),
            "{kind:?}"
        );
        assert!(
            !verifies(scheme, &public_key, ANSWER, &signature),
            "{kind:?}"
        );
        assert!(key
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .is_none());
    }
}

/// **A key the ring build generated**: ring writes P-256 PKCS#8 with the
/// public key but without the curve inside its ECPrivateKey. An `rpc_ssl.key`
/// kept by the build before this one loads, and matches its certificate.
#[test]
fn a_p256_key_in_rings_pkcs8_layout_loads() {
    let secret = p256::SecretKey::random(&mut OsRng);
    let public = secret.public_key().to_encoded_point(false);
    // ring's `ecPublicKey_p256_pkcs8_v1_template.der`, then the key.
    let mut der = vec![
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    der.extend_from_slice(&secret.to_bytes());
    der.extend_from_slice(&[0xa1, 0x44, 0x03, 0x42, 0x00]);
    der.extend_from_slice(public.as_bytes());
    let key: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(der).into();

    let cert = certificate(&key);
    let provider = Arc::new(provider::provider());
    round_trip(
        server(&provider, cert.clone(), key),
        client(&provider, &rustls::version::TLS13, &cert),
    );
}

/// A key that is not its certificate's is refused, as rustls did with ring,
/// whatever the kinds.
#[test]
fn a_key_that_is_not_the_certificates_is_refused() {
    for (cert_kind, key_kind) in [(P256, P256), (Ed25519, P384), (Rsa, P256), (P256, Rsa)] {
        let cert = certificate(&pkcs8(cert_kind));
        let e = ServerConfig::builder_with_provider(Arc::new(provider::provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], pkcs8(key_kind))
            .unwrap_err();
        assert!(
            matches!(
                e,
                rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch)
            ),
            "{cert_kind:?} and {key_kind:?}: {e:?}"
        );
    }
}

/// A key of a kind the provider has no signer for is refused, and the message
/// says what it takes: here X25519's PKCS#8 (RFC 8410), a key for agreement.
#[test]
fn an_unusable_key_is_refused_naming_the_kinds_taken() {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[7; 32]);
    let e = provider::provider()
        .key_provider
        .load_private_key(PrivatePkcs8KeyDer::from(der).into())
        .unwrap_err()
        .to_string();
    assert!(e.contains(provider::SUPPORTED_KEYS), "{e}");

    let e = provider::provider()
        .key_provider
        .load_private_key(PrivatePkcs8KeyDer::from(vec![0x30, 0x00]).into())
        .unwrap_err()
        .to_string();
    assert!(e.contains("not valid PKCS#8"), "{e}");
}

/// RSA keys load in the sizes ring took, 2048 to 4096 bits: an RSA-1024 key,
/// which ring refused, is refused in either encoding, saying why.
#[test]
fn an_rsa_key_smaller_than_ring_took_is_refused() {
    let small = rsa::RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
    let pkcs8 = PrivatePkcs8KeyDer::from(small.to_pkcs8_der().unwrap().as_bytes().to_vec());
    let pkcs1 = PrivatePkcs1KeyDer::from(small.to_pkcs1_der().unwrap().as_bytes().to_vec());
    for der in [PrivateKeyDer::from(pkcs8), PrivateKeyDer::from(pkcs1)] {
        let e = provider::provider()
            .key_provider
            .load_private_key(der)
            .unwrap_err()
            .to_string();
        assert!(e.contains("has 1024 bits"), "{e}");
        assert!(e.contains(provider::SUPPORTED_KEYS), "{e}");
    }
}

fn hex(text: &str) -> Vec<u8> {
    wow_crypto::hex::decode(text).unwrap()
}

/// **Known answers for record protection**, computed with pyca/cryptography
/// (OpenSSL's AEADs) from RFC 8446 §5.2 and RFC 5246 §6.2.3.3 as written, not
/// with the crates under test: a TLS 1.3 ChaCha20-Poly1305 record and a
/// TLS 1.2 AES-256-GCM record carrying its explicit nonce. Each is sealed to
/// the byte, opened again, and refused once altered.
#[test]
fn records_match_known_answers() {
    const PLAINTEXT: &[u8] = b"POST /get_height HTTP/1.1";

    // TLS 1.3: key 00..1f, IV a0..ab, sequence number 0x0102030405060708.
    let SupportedCipherSuite::Tls13(suite) = provider::TLS13_CHACHA20_POLY1305_SHA256 else {
        unreachable!()
    };
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let iv: [u8; 12] = std::array::from_fn(|i| 0xa0 + i as u8);
    let seq = 0x0102_0304_0506_0708;
    let record = hex(
        "170303002af6b01702f3a459f3c1a3843f3a802c125558df0d395f46a8243ae7631c3ef6395196f4c17f\
         6e418aad17",
    );
    let sealed = suite
        .aead_alg
        .encrypter(AeadKey::from(key), Iv::new(iv))
        .encrypt(
            OutboundPlainMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_3,
                payload: PLAINTEXT.into(),
            },
            seq,
        )
        .unwrap()
        .encode();
    assert_eq!(sealed, record);
    let mut decrypter = suite.aead_alg.decrypter(AeadKey::from(key), Iv::new(iv));
    let mut body = record[5..].to_vec();
    let opened = decrypter
        .decrypt(
            InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut body,
            ),
            seq,
        )
        .unwrap();
    assert_eq!(opened.typ, ContentType::ApplicationData);
    assert_eq!(opened.payload, PLAINTEXT);
    let mut altered = record[5..].to_vec();
    altered[3] ^= 1;
    assert!(decrypter
        .decrypt(
            InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut altered,
            ),
            seq,
        )
        .is_err());

    // TLS 1.2: key 40..5f, fixed IV c0c1c2c3, explicit part d0..d7, sequence
    // number 2.
    let SupportedCipherSuite::Tls12(suite) = provider::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 else {
        unreachable!()
    };
    let key: [u8; 32] = std::array::from_fn(|i| 0x40 + i as u8);
    let fixed = [0xc0, 0xc1, 0xc2, 0xc3];
    let explicit = [0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7];
    let record = hex(
        "1703030031d0d1d2d3d4d5d6d50f6fe878817e6399f81b407bd0f25162a9f413dba0f91619773074959b\
         8262bce96c4a5e529a66c49e",
    );
    let sealed = suite
        .aead_alg
        .encrypter(AeadKey::from(key), &fixed, &explicit)
        .encrypt(
            OutboundPlainMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload: PLAINTEXT.into(),
            },
            2,
        )
        .unwrap()
        .encode();
    assert_eq!(sealed, record);
    let mut decrypter = suite.aead_alg.decrypter(AeadKey::from(key), &fixed);
    let mut body = record[5..].to_vec();
    let opened = decrypter
        .decrypt(
            InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut body,
            ),
            2,
        )
        .unwrap();
    assert_eq!(opened.payload, PLAINTEXT);
    let mut altered = record[5..].to_vec();
    altered[0] ^= 1;
    assert!(decrypter
        .decrypt(
            InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut altered,
            ),
            2,
        )
        .is_err());
}

fn scratch(tag: &str) -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("wownerod-tlsprov-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}
