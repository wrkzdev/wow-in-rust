//! The files a watch-only wallet and a cold wallet exchange (`specs/12` §6).
//!
//! Cold signing splits one wallet in two. The **watch-only** half has the view
//! key, sees the chain, and can plan a transaction but not sign it. The
//! **cold** half has the spend key and never touches a network. Four files
//! cross between them:
//!
//! | File | Written by | Read by | Magic |
//! |---|---|---|---|
//! | outputs | cold | watch-only | `Wownero output export\4` |
//! | key images | cold | watch-only | `Wownero key image export\3` |
//! | unsigned tx set | watch-only | cold | `Wownero unsigned tx set\5` |
//! | signed tx set | cold | watch-only | `Wownero signed tx set\5` |
//!
//! The whole point is that the two halves can be a `wownero-wallet-cli` and
//! this one, in either arrangement, so every byte here is the C++'s.
//!
//! # These are `binary_archive`, not Boost
//!
//! This is worth stating plainly, because the repository's note on the wallet
//! cache (`crate` docs, `specs/12` §2.2) says the cache *is* a Boost portable
//! binary archive and is therefore not reproduced. These four files were the
//! same until Monero 0.18 / Wownero 0.11: the version bytes in the magic
//! strings above were `\3` and `\4`, and the payload was
//! `boost::archive::portable_binary_{i,o}archive`.
//!
//! The current versions are not. `wallet2::dump_tx_to_str`,
//! `sign_tx_dump_to_str`, `export_outputs_to_str` and `export_key_images` all
//! write through `binary_archive<true>` — Monero's own archive, the one that
//! carries consensus blobs ([`wow_serialize::binary`]) — and only the *read*
//! paths still have a Boost branch, guarded by `m_load_deprecated_formats`.
//! So the formats here are byte-reproducible, and are reproduced.
//!
//! What this build will not do is read the deprecated Boost versions: a `\3`
//! or `\4` transfer set is refused by version with a reason
//! ([`ColdError::DeprecatedFormat`]), which is what the C++ itself does unless
//! it is asked for them. A wallet that writes those has been out of date since
//! 2022.
//!
//! # The archive, in one table
//!
//! Every rule below comes from `src/serialization/`, and getting any of them
//! wrong produces a file the C++ rejects:
//!
//! | C++ | Bytes |
//! |---|---|
//! | `FIELD(uint64_t)` | **8, little-endian** — not a varint |
//! | `VARINT_FIELD(x)` | base-128 varint |
//! | `VERSION_FIELD(n)` | varint of `n` |
//! | `FIELD(bool)` | one byte |
//! | `FIELD(crypto::hash)` and friends | raw bytes, no length (`BLOB_SERIALIZER`) |
//! | `FIELD(std::string)`, `FIELD(std::vector<uint8_t>)` | varint length, then bytes |
//! | `FIELD(std::vector<T>)` | varint count, then each element |
//! | a container element of unsigned integral type wider than a byte | varint |
//! | `std::pair` | **varint 2**, then both elements |
//! | `std::tuple` of three | **varint 3**, then all three |
//!
//! The two surprising ones are the last two: `begin_array(s)` writes a varint
//! of `s` even for a pair or a tuple, whose size is fixed and known, so a
//! literal `2` or `3` sits in the middle of the blob
//! (`binary_archive<true>::begin_array`). And `serialize_pair_element` /
//! `serialize_tuple_element` promote a `uint64_t` to a varint where
//! `FIELD` would not.
//!
//! # Encryption
//!
//! All four payloads are sealed with the **view** secret key, not the password:
//! `wallet2::encrypt`, as
//!
//! ```text
//! iv(8) || chacha20(plaintext, cn_slow_hash(view_secret_key), iv) || sig(64)
//! ```
//!
//! where the signature is a CryptoNote Schnorr signature over
//! `cn_fast_hash(everything before it)` under the view key. It is
//! authentication, not secrecy from the other half — both halves have the view
//! key, and that is the point: the watch-only half can read what the cold half
//! sent and nobody who intercepted the file can.

use wow_crypto::random::Rng;
use wow_crypto::types::{
    AccountPublicAddress, Hash256, KeyImage, PublicKey, SecretKey, Signature, SubaddressIndex,
};
use wow_serialize::binary::{Reader, Writer};
use wow_types::tx::Transaction;

use crate::chacha;

/// `KEY_IMAGE_EXPORT_FILE_MAGIC`. The version byte is inside the magic here,
/// and is compared with it.
pub const KEY_IMAGE_EXPORT_MAGIC: &[u8] = b"Wownero key image export\x03";

/// `OUTPUT_EXPORT_FILE_MAGIC`. Version byte inside, as above.
pub const OUTPUT_EXPORT_MAGIC: &[u8] = b"Wownero output export\x04";

/// `UNSIGNED_TX_PREFIX` without its version byte: the reference compares
/// `strlen(UNSIGNED_TX_PREFIX) - 1` bytes and then reads the version.
pub const UNSIGNED_TX_MAGIC: &[u8] = b"Wownero unsigned tx set";

/// `SIGNED_TX_PREFIX` without its version byte.
pub const SIGNED_TX_MAGIC: &[u8] = b"Wownero signed tx set";

/// The `\005` of `UNSIGNED_TX_PREFIX` and `SIGNED_TX_PREFIX`: the
/// `binary_archive` payload. `\003` and `\004` are the Boost ones.
pub const TX_SET_VERSION: u8 = 5;

/// How many outputs or transactions one file may carry.
///
/// Not a C++ limit — the C++ trusts the archive and its own `resize` — but a
/// parser reading a file from another machine sizes allocations from it, and
/// `Reader::read_len` wants a cap. Chosen well above any real wallet.
const MAX_ENTRIES: usize = 1_000_000;

/// How long a `std::string` field may be.
const MAX_STRING: usize = 1_000_000;

/// `rct::identity()`, which is what `import_outputs` puts in `m_mask`.
///
/// The field is a scalar and this is the encoding of the identity *point*,
/// which read as a scalar is one. It is a placeholder either way: the mask an
/// output really has reaches the cold wallet in the `tx_source_entry` of an
/// unsigned transfer, not here, because `exported_transfer_details` has no
/// field for it.
pub const IDENTITY_MASK: [u8; 32] = {
    let mut m = [0u8; 32];
    m[0] = 1;
    m
};

#[derive(Debug, thiserror::Error)]
pub enum ColdError {
    #[error("this is not a {0} file: the magic does not match")]
    BadMagic(&'static str),
    #[error(
        "a {what} of version {version} is the deprecated Boost format; this build reads version \
         {expected}, which is what Wownero has written since 0.11. Re-export it from a current \
         wallet"
    )]
    DeprecatedFormat {
        what: &'static str,
        version: u8,
        expected: u8,
    },
    #[error("unsupported version {version} in a {what}")]
    UnsupportedVersion { what: &'static str, version: u64 },
    #[error("unexpected ciphertext size")]
    ShortCiphertext,
    #[error("failed to authenticate ciphertext")]
    NotAuthenticated,
    #[error("that file is for a different account")]
    WrongAccount,
    #[error("bad data size for a {0}")]
    BadSize(&'static str),
    #[error("{0} in the file's data")]
    Parse(wow_serialize::Error),
    #[error("{0} bytes are left over after the data; this is not the format it claims to be")]
    Trailing(usize),
    #[error("a key in the file does not decode")]
    BadKey,
}

impl From<wow_serialize::Error> for ColdError {
    fn from(e: wow_serialize::Error) -> ColdError {
        ColdError::Parse(e)
    }
}

type Result<T> = std::result::Result<T, ColdError>;

// -- encryption ------------------------------------------------------------

/// `wallet2::encrypt(plaintext, skey, authenticated)`.
///
/// `rng` supplies the IV, as `crypto::rand<crypto::chacha_iv>()` does, and the
/// signature's nonce. It is the caller's so that there is exactly one entropy
/// source per operation and a test can fix it: a Schnorr signature with a
/// predictable nonce over two different messages gives up the key it signs
/// with, so this must never fall back to a constant.
pub fn encrypt(
    plaintext: &[u8],
    skey: &SecretKey,
    authenticated: bool,
    rng: &mut Rng,
) -> Result<Vec<u8>> {
    let mut iv = [0u8; chacha::IV_SIZE];
    rng.fill(&mut iv);
    encrypt_with_iv(plaintext, skey, authenticated, iv, rng)
}

/// [`encrypt`] with the IV given, so that a test can pin the ciphertext.
pub fn encrypt_with_iv(
    plaintext: &[u8],
    skey: &SecretKey,
    authenticated: bool,
    iv: chacha::Iv,
    rng: &mut Rng,
) -> Result<Vec<u8>> {
    // The key is CryptoNight over the 32 secret-key bytes, `kdf_rounds` times.
    // `kdf_rounds` is the wallet's, and it is 1 for every wallet the CLI
    // writes; a wallet opened with a different one cannot exchange these files
    // with one that was not, which is true of the C++ too.
    let key = chacha::generate_chacha_key(&skey.0, 1);

    let mut out = Vec::with_capacity(plaintext.len() + chacha::IV_SIZE + Signature::LEN);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&chacha::chacha20(plaintext, &key, &iv));
    if authenticated {
        let hash = wow_crypto::cn_fast_hash(&out);
        let pkey = wow_crypto::secret_key_to_public_key(skey).ok_or(ColdError::BadKey)?;
        let sig =
            wow_crypto::generate_signature(rng, &hash, &pkey, skey).ok_or(ColdError::BadKey)?;
        out.extend_from_slice(&sig.to_bytes());
    }
    Ok(out)
}

/// `wallet2::decrypt(ciphertext, skey, authenticated)`.
pub fn decrypt(ciphertext: &[u8], skey: &SecretKey, authenticated: bool) -> Result<Vec<u8>> {
    let prefix = chacha::IV_SIZE + if authenticated { Signature::LEN } else { 0 };
    if ciphertext.len() < prefix {
        return Err(ColdError::ShortCiphertext);
    }
    let key = chacha::generate_chacha_key(&skey.0, 1);
    let iv: chacha::Iv = ciphertext[..chacha::IV_SIZE]
        .try_into()
        .expect("IV_SIZE bytes");

    if authenticated {
        let split = ciphertext.len() - Signature::LEN;
        let hash = wow_crypto::cn_fast_hash(&ciphertext[..split]);
        let pkey = wow_crypto::secret_key_to_public_key(skey).ok_or(ColdError::BadKey)?;
        let sig = Signature::from_slice(&ciphertext[split..]).ok_or(ColdError::BadKey)?;
        if !wow_crypto::check_signature(&hash, &pkey, &sig) {
            return Err(ColdError::NotAuthenticated);
        }
    }

    let body = &ciphertext[chacha::IV_SIZE..ciphertext.len() - (prefix - chacha::IV_SIZE)];
    Ok(chacha::chacha20(body, &key, &iv))
}

/// The two public keys every export carries so the other half can tell the
/// file is its own: `m_spend_public_key` then `m_view_public_key`, raw.
fn account_header(address: &AccountPublicAddress) -> [u8; 64] {
    address.to_bytes()
}

/// Check and strip an account header, refusing a file for another wallet as
/// `import_outputs_from_str` and `import_key_images` do.
fn take_account_header<'a>(
    data: &'a [u8],
    ours: &AccountPublicAddress,
    what: &'static str,
) -> Result<&'a [u8]> {
    if data.len() < AccountPublicAddress::LEN {
        return Err(ColdError::BadSize(what));
    }
    let (head, rest) = data.split_at(AccountPublicAddress::LEN);
    let mut bytes = [0u8; AccountPublicAddress::LEN];
    bytes.copy_from_slice(head);
    if AccountPublicAddress::from_bytes(&bytes) != *ours {
        return Err(ColdError::WrongAccount);
    }
    Ok(rest)
}

// -- key images ------------------------------------------------------------

/// One exported key image and the signature that proves the exporter held the
/// output's secret key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedKeyImage {
    pub key_image: KeyImage,
    pub signature: Signature,
}

/// `export_key_images`' payload: where in the exporter's output list these
/// start, and the images themselves.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportedKeyImages {
    /// `ski.first`: the index of the first output described. Everything below
    /// it the importer is expected to know already.
    pub offset: u32,
    pub images: Vec<SignedKeyImage>,
}

impl ExportedKeyImages {
    /// The file `export_key_images` writes: the magic in the clear, and
    /// everything else sealed under the view key.
    pub fn to_file(
        &self,
        address: &AccountPublicAddress,
        view_secret_key: &SecretKey,
        rng: &mut Rng,
    ) -> Result<Vec<u8>> {
        // "data.resize(4); data[0] = offset & 0xff; ..." -- four bytes,
        // little-endian, and then the account, and then the records. Note this
        // is a hand-rolled blob, not an archive: no varints anywhere.
        let mut data = Vec::with_capacity(4 + 64 + self.images.len() * 96);
        data.extend_from_slice(&self.offset.to_le_bytes());
        data.extend_from_slice(&account_header(address));
        for i in &self.images {
            data.extend_from_slice(&i.key_image.0);
            data.extend_from_slice(&i.signature.to_bytes());
        }

        let mut out = KEY_IMAGE_EXPORT_MAGIC.to_vec();
        out.extend_from_slice(&encrypt(&data, view_secret_key, true, rng)?);
        Ok(out)
    }

    /// `wallet2::import_key_images(filename, ...)`' parsing half.
    pub fn from_file(
        blob: &[u8],
        address: &AccountPublicAddress,
        view_secret_key: &SecretKey,
    ) -> Result<ExportedKeyImages> {
        let body = strip_magic(blob, KEY_IMAGE_EXPORT_MAGIC, "key image export")?;
        let data = decrypt(body, view_secret_key, true)?;

        if data.len() < 4 {
            return Err(ColdError::BadSize("key image export"));
        }
        let offset = u32::from_le_bytes(data[..4].try_into().expect("4 bytes"));
        let rest = take_account_header(&data[4..], address, "key image export")?;

        // "Bad data size from file": the records are fixed width, so a length
        // that is not a multiple of one is a corrupt file rather than a short
        // last record.
        const RECORD: usize = KeyImage::LEN + Signature::LEN;
        if rest.len() % RECORD != 0 {
            return Err(ColdError::BadSize("key image export"));
        }
        let images = rest
            .chunks_exact(RECORD)
            .map(|c| SignedKeyImage {
                key_image: KeyImage(c[..32].try_into().expect("32 bytes")),
                signature: Signature::from_slice(&c[32..]).expect("64 bytes"),
            })
            .collect();
        Ok(ExportedKeyImages { offset, images })
    }
}

/// Whether a key image's signature is the one `export_key_images` makes:
/// a one-member ring signature over the key image itself, under the output's
/// one-time public key.
///
/// `import_key_images` verifies exactly this, and the message being the key
/// image is not a typo in the reference — `generate_ring_signature((const
/// crypto::hash&)td.m_key_image, td.m_key_image, {&pkey}, ...)` passes the key
/// image as both the prefix hash and the image.
pub fn check_key_image_signature(
    key_image: &KeyImage,
    output_public_key: &PublicKey,
    signature: &Signature,
) -> bool {
    wow_crypto::check_ring_signature(
        &key_image.0,
        key_image,
        std::slice::from_ref(output_public_key),
        std::slice::from_ref(signature),
    )
}

/// The signature `export_key_images` writes for one output.
pub fn sign_key_image(
    rng: &mut Rng,
    key_image: &KeyImage,
    output_public_key: &PublicKey,
    output_secret_key: &SecretKey,
) -> Option<Signature> {
    let sigs = wow_crypto::generate_ring_signature(
        rng,
        &key_image.0,
        key_image,
        std::slice::from_ref(output_public_key),
        output_secret_key,
        0,
    )?;
    sigs.into_iter().next()
}

// -- outputs ---------------------------------------------------------------

/// `wallet2::exported_transfer_details`: one output, as much of it as a cold
/// wallet needs to recognise and later sign for.
///
/// Notably **not** the commitment mask: `import_outputs` sets
/// `td.m_mask = rct::identity()` and the real mask reaches the cold half in
/// the `tx_source_entry` of an unsigned transfer instead.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportedTransferDetails {
    /// The one-time public key on chain.
    pub public_key: PublicKey,
    pub internal_output_index: u64,
    pub global_output_index: u64,
    /// The transaction public key the output was derived from.
    pub tx_public_key: PublicKey,
    /// `m_flags.flags`, the packed bitfield. See [`flags`].
    pub flags: u8,
    pub amount: u64,
    pub additional_tx_keys: Vec<PublicKey>,
    pub subaddress: SubaddressIndex,
}

/// The bits of [`ExportedTransferDetails::flags`].
///
/// C++ declares them as a `uint8_t m_spent: 1, m_frozen: 1, ...` bitfield in a
/// union with a plain `uint8_t flags`, and serializes the `uint8_t`. Bitfield
/// layout is implementation-defined in the standard; every compiler Wownero is
/// built with puts the first declared bit in the least significant position on
/// a little-endian target, so that is the layout, and the order below is the
/// declaration order in `wallet2.h`.
pub mod flags {
    pub const SPENT: u8 = 1 << 0;
    pub const FROZEN: u8 = 1 << 1;
    pub const RCT: u8 = 1 << 2;
    pub const KEY_IMAGE_KNOWN: u8 = 1 << 3;
    pub const KEY_IMAGE_REQUEST: u8 = 1 << 4;
    pub const KEY_IMAGE_PARTIAL: u8 = 1 << 5;
}

impl ExportedTransferDetails {
    /// `VERSION_FIELD(1)`: the only version this type has ever had, and
    /// `version < 1` is refused by the reference itself.
    const VERSION: u64 = 1;

    pub fn write(&self, w: &mut Writer) {
        w.write_varint(Self::VERSION);
        w.write_bytes(&self.public_key.0);
        w.write_varint(self.internal_output_index);
        w.write_varint(self.global_output_index);
        w.write_bytes(&self.tx_public_key.0);
        w.write_u8(self.flags);
        w.write_varint(self.amount);
        w.write_varint(self.additional_tx_keys.len() as u64);
        for k in &self.additional_tx_keys {
            w.write_bytes(&k.0);
        }
        w.write_varint(u64::from(self.subaddress.major));
        w.write_varint(u64::from(self.subaddress.minor));
    }

    pub fn read(r: &mut Reader<'_>) -> Result<ExportedTransferDetails> {
        // "VERSION_FIELD(1); if (version < 1) return false;" -- a later
        // version is read as this one, exactly as the reference reads it.
        let version = r.read_varint()?;
        if version < Self::VERSION {
            return Err(ColdError::UnsupportedVersion {
                what: "exported output",
                version,
            });
        }
        let public_key = PublicKey(r.read_array::<32>()?);
        let internal_output_index = r.read_varint()?;
        let global_output_index = r.read_varint()?;
        let tx_public_key = PublicKey(r.read_array::<32>()?);
        let flags = r.read_u8()?;
        let amount = r.read_varint()?;
        let n = r.read_len(MAX_ENTRIES, "additional tx keys")?;
        let mut additional_tx_keys = Vec::with_capacity(n);
        for _ in 0..n {
            additional_tx_keys.push(PublicKey(r.read_array::<32>()?));
        }
        let major = r.read_varint_u32()?;
        let minor = r.read_varint_u32()?;
        Ok(ExportedTransferDetails {
            public_key,
            internal_output_index,
            global_output_index,
            tx_public_key,
            flags,
            amount,
            additional_tx_keys,
            subaddress: SubaddressIndex::new(major, minor),
        })
    }
}

/// `export_outputs`' payload: `std::tuple<uint64_t, uint64_t,
/// std::vector<exported_transfer_details>>`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportedOutputs {
    /// Where in the exporter's output list `outputs` begins.
    pub offset: u64,
    /// How many outputs the exporter has in total, which is how the importer
    /// knows to trim its own list.
    pub total: u64,
    pub outputs: Vec<ExportedTransferDetails>,
}

impl ExportedOutputs {
    pub fn write(&self, w: &mut Writer) {
        // `begin_array(3)` for the tuple: a literal varint 3.
        w.write_varint(3);
        // `serialize_tuple_element` promotes a `uint64_t` to a varint.
        w.write_varint(self.offset);
        w.write_varint(self.total);
        w.write_varint(self.outputs.len() as u64);
        for o in &self.outputs {
            o.write(w);
        }
    }

    pub fn read(r: &mut Reader<'_>) -> Result<ExportedOutputs> {
        let arity = r.read_varint()?;
        if arity != 3 {
            return Err(ColdError::Parse(wow_serialize::Error::InvalidValue(
                "an exported output set is a tuple of three",
            )));
        }
        let offset = r.read_varint()?;
        let total = r.read_varint()?;
        let n = r.read_len(MAX_ENTRIES, "exported outputs")?;
        let mut outputs = Vec::with_capacity(n);
        for _ in 0..n {
            outputs.push(ExportedTransferDetails::read(r)?);
        }
        Ok(ExportedOutputs {
            offset,
            total,
            outputs,
        })
    }

    /// The file `export_outputs_to_str` writes.
    pub fn to_file(
        &self,
        address: &AccountPublicAddress,
        view_secret_key: &SecretKey,
        rng: &mut Rng,
    ) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        self.write(&mut w);
        let mut data = account_header(address).to_vec();
        data.extend_from_slice(&w.into_vec());

        let mut out = OUTPUT_EXPORT_MAGIC.to_vec();
        out.extend_from_slice(&encrypt(&data, view_secret_key, true, rng)?);
        Ok(out)
    }

    /// `import_outputs_from_str`' parsing half.
    ///
    /// The reference tries `exported_transfer_details` first, then the older
    /// whole `transfer_details`, then Boost. Only the first is read here: the
    /// second carries a whole `transaction_prefix` per output and has not been
    /// written since 0.17, and the third needs Boost.
    pub fn from_file(
        blob: &[u8],
        address: &AccountPublicAddress,
        view_secret_key: &SecretKey,
    ) -> Result<ExportedOutputs> {
        let body = strip_magic(blob, OUTPUT_EXPORT_MAGIC, "output export")?;
        let data = decrypt(body, view_secret_key, true)?;
        let body = take_account_header(&data, address, "output export")?;

        let mut r = Reader::new(body);
        let outputs = ExportedOutputs::read(&mut r)?;
        // `check_stream_state(ar)` with `noeof == false`: the whole blob must
        // have been consumed, which is what tells the reference it guessed the
        // right one of the three shapes.
        if !r.is_empty() {
            return Err(ColdError::Trailing(r.remaining()));
        }
        Ok(outputs)
    }
}

// -- destinations and sources ----------------------------------------------

/// `cryptonote::tx_destination_entry`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxDestinationEntry {
    /// The address as the user typed it, kept so `describe_transfer` can show
    /// an integrated address back rather than the plain one inside it. Empty
    /// for change and for anything built without a typed address.
    pub original: String,
    pub amount: u64,
    pub address: AccountPublicAddress,
    pub is_subaddress: bool,
    pub is_integrated: bool,
}

impl TxDestinationEntry {
    pub fn write(&self, w: &mut Writer) {
        w.write_bytes_prefixed(self.original.as_bytes());
        w.write_varint(self.amount);
        w.write_bytes(&self.address.to_bytes());
        w.write_u8(u8::from(self.is_subaddress));
        w.write_u8(u8::from(self.is_integrated));
    }

    pub fn read(r: &mut Reader<'_>) -> Result<TxDestinationEntry> {
        let original = r.read_bytes_prefixed(MAX_STRING, "destination address")?;
        // `std::string` is bytes; a wallet only ever puts an address there, so
        // anything that is not UTF-8 is a file to refuse rather than to guess
        // at.
        let original = std::str::from_utf8(original)
            .map_err(|_| wow_serialize::Error::InvalidValue("a destination address is not text"))?
            .to_string();
        let amount = r.read_varint()?;
        let address = AccountPublicAddress::from_bytes(&r.read_array::<64>()?);
        let is_subaddress = r.read_u8()? != 0;
        let is_integrated = r.read_u8()? != 0;
        Ok(TxDestinationEntry {
            original,
            amount,
            address,
            is_subaddress,
            is_integrated,
        })
    }
}

/// One ring member as a source carries it: its global index, its one-time
/// public key and its commitment. `cryptonote::tx_source_entry::output_entry`,
/// which is `std::pair<uint64_t, rct::ctkey>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RingEntry {
    /// **Absolute**, not the relative offset the wire form of an input uses.
    pub global_index: u64,
    pub public_key: PublicKey,
    /// The output's commitment, whole (not divided by eight).
    pub commitment: wow_crypto::types::EcPoint,
}

impl RingEntry {
    fn write(&self, w: &mut Writer) {
        // A pair writes its own arity first.
        w.write_varint(2);
        // `serialize_pair_element` promotes the `uint64_t` to a varint.
        w.write_varint(self.global_index);
        // `rct::ctkey` is a `BLOB_SERIALIZER` type: 64 raw bytes, dest then
        // mask, with no framing of its own.
        w.write_bytes(&self.public_key.0);
        w.write_bytes(&self.commitment.0);
    }

    fn read(r: &mut Reader<'_>) -> Result<RingEntry> {
        let arity = r.read_varint()?;
        if arity != 2 {
            return Err(ColdError::Parse(wow_serialize::Error::InvalidValue(
                "a ring entry is a pair",
            )));
        }
        let global_index = r.read_varint()?;
        let public_key = PublicKey(r.read_array::<32>()?);
        let commitment = wow_crypto::types::EcPoint(r.read_array::<32>()?);
        Ok(RingEntry {
            global_index,
            public_key,
            commitment,
        })
    }
}

/// `cryptonote::tx_source_entry`: one input, with its ring and everything the
/// signer needs to derive the key for the real member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxSourceEntry {
    /// The ring, in wire order (ascending global index).
    pub outputs: Vec<RingEntry>,
    /// Which entry of `outputs` is really ours.
    pub real_output: u64,
    /// The transaction public key of the transaction that paid us.
    pub real_out_tx_key: PublicKey,
    pub real_out_additional_tx_keys: Vec<PublicKey>,
    /// Our output's index within that transaction.
    pub real_output_in_tx_index: u64,
    pub amount: u64,
    pub rct: bool,
    /// Our output's commitment mask — the one thing `export_outputs` leaves
    /// out and a signer cannot do without.
    pub mask: [u8; 32],
    /// `multisig_kLRki`: four keys, zero for a non-multisig wallet, written
    /// because the format has the field.
    pub multisig_klrki: [u8; 128],
}

/// Hand-written because `[u8; 128]` is not `Default` — the standard library's
/// array impls stop at 32.
impl Default for TxSourceEntry {
    fn default() -> TxSourceEntry {
        TxSourceEntry {
            outputs: Vec::new(),
            real_output: 0,
            real_out_tx_key: PublicKey::ZERO,
            real_out_additional_tx_keys: Vec::new(),
            real_output_in_tx_index: 0,
            amount: 0,
            rct: true,
            mask: [0u8; 32],
            multisig_klrki: [0u8; 128],
        }
    }
}

impl TxSourceEntry {
    pub fn write(&self, w: &mut Writer) {
        w.write_varint(self.outputs.len() as u64);
        for o in &self.outputs {
            o.write(w);
        }
        // `FIELD(uint64_t)`, so eight little-endian bytes and not a varint.
        w.write_u64_le(self.real_output);
        w.write_bytes(&self.real_out_tx_key.0);
        w.write_varint(self.real_out_additional_tx_keys.len() as u64);
        for k in &self.real_out_additional_tx_keys {
            w.write_bytes(&k.0);
        }
        w.write_u64_le(self.real_output_in_tx_index);
        w.write_u64_le(self.amount);
        w.write_u8(u8::from(self.rct));
        w.write_bytes(&self.mask);
        w.write_bytes(&self.multisig_klrki);
    }

    pub fn read(r: &mut Reader<'_>) -> Result<TxSourceEntry> {
        let n = r.read_len(MAX_ENTRIES, "ring members")?;
        let mut outputs = Vec::with_capacity(n);
        for _ in 0..n {
            outputs.push(RingEntry::read(r)?);
        }
        let real_output = r.read_u64_le()?;
        let real_out_tx_key = PublicKey(r.read_array::<32>()?);
        let n = r.read_len(MAX_ENTRIES, "additional tx keys")?;
        let mut real_out_additional_tx_keys = Vec::with_capacity(n);
        for _ in 0..n {
            real_out_additional_tx_keys.push(PublicKey(r.read_array::<32>()?));
        }
        let real_output_in_tx_index = r.read_u64_le()?;
        let amount = r.read_u64_le()?;
        let rct = r.read_u8()? != 0;
        let mask = r.read_array::<32>()?;
        let multisig_klrki = r.read_array::<128>()?;

        // The reference's own last line: "if (real_output >= outputs.size())
        // return false". A source whose real member is outside its ring cannot
        // be signed.
        if real_output >= outputs.len() as u64 {
            return Err(ColdError::Parse(wow_serialize::Error::InvalidValue(
                "an input's real output is outside its ring",
            )));
        }
        Ok(TxSourceEntry {
            outputs,
            real_output,
            real_out_tx_key,
            real_out_additional_tx_keys,
            real_output_in_tx_index,
            amount,
            rct,
            mask,
            multisig_klrki,
        })
    }
}

/// `rct::RCTConfig`. The wallet writes one shape and one only, and a file that
/// asks for another is refused rather than signed into something else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RctConfig {
    /// `rct::RangeProofPaddedBulletproof` is 3.
    pub range_proof_type: u64,
    /// 4 from the Bulletproof+ fork, 3 before it.
    pub bp_version: u64,
}

impl Default for RctConfig {
    /// What `create_transactions_2` sets on this chain: `{
    /// RangeProofPaddedBulletproof, 4 }`.
    fn default() -> RctConfig {
        RctConfig {
            range_proof_type: RctConfig::PADDED_BULLETPROOF,
            bp_version: 4,
        }
    }
}

impl RctConfig {
    pub const PADDED_BULLETPROOF: u64 = 3;

    pub fn write(&self, w: &mut Writer) {
        w.write_varint(0); // VERSION_FIELD(0)
        w.write_varint(self.range_proof_type);
        w.write_varint(self.bp_version);
    }

    pub fn read(r: &mut Reader<'_>) -> Result<RctConfig> {
        // `VERSION_FIELD(0)` and nothing conditional on it: the reference
        // reads the varint and carries on whatever it says, so this does too.
        // Refusing a version it accepts would refuse a file it can produce.
        let _version = r.read_varint()?;
        Ok(RctConfig {
            range_proof_type: r.read_varint()?,
            bp_version: r.read_varint()?,
        })
    }
}

/// `wallet2::tx_construction_data`: everything needed to build and sign one
/// transaction, and nothing secret.
///
/// This is what a watch-only wallet can produce and a cold wallet turns into a
/// signed transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxConstructionData {
    pub sources: Vec<TxSourceEntry>,
    /// The change output. Its address is a throwaway one when the amount is
    /// zero, as `transfer_selected_rct` makes it.
    pub change_dts: TxDestinationEntry,
    /// Every output, change included.
    pub splitted_dsts: Vec<TxDestinationEntry>,
    /// Indices into the exporting wallet's output list, one per source, in
    /// input order.
    pub selected_transfers: Vec<u64>,
    /// `tx_extra` as the watch-only half laid it out, with the payment id
    /// **decrypted** (`get_construction_data_with_decrypted_short_payment_id`)
    /// because the signer makes a new transaction key and has to encrypt it
    /// again.
    pub extra: Vec<u8>,
    /// Must be zero: Wownero does not relay anything else (`specs/06` §6.3),
    /// and `sign_tx` throws `nonzero_unlock_time` on one.
    pub unlock_time: u64,
    pub use_rct: bool,
    pub use_view_tags: bool,
    pub rct_config: RctConfig,
    /// The destinations as asked for, change left out.
    pub dests: Vec<TxDestinationEntry>,
    pub subaddr_account: u32,
    /// The minor indices the inputs came from, ascending and unique — it is a
    /// `std::set` in C++.
    pub subaddr_indices: Vec<u32>,
}

/// `tx_construction_data::construction_flags_`.
pub mod construction_flags {
    pub const USE_RCT: u8 = 1 << 0;
    pub const USE_VIEW_TAGS: u8 = 1 << 1;
}

impl TxConstructionData {
    pub fn write(&self, w: &mut Writer) {
        w.write_varint(self.sources.len() as u64);
        for s in &self.sources {
            s.write(w);
        }
        self.change_dts.write(w);
        w.write_varint(self.splitted_dsts.len() as u64);
        for d in &self.splitted_dsts {
            d.write(w);
        }
        w.write_varint(self.selected_transfers.len() as u64);
        for &i in &self.selected_transfers {
            // `std::vector<size_t>`: a container element of unsigned integral
            // type wider than a byte, so a varint.
            w.write_varint(i);
        }
        // `std::vector<uint8_t>`: a varint count and then the bytes, which is
        // the same shape a length-prefixed blob has.
        w.write_bytes_prefixed(&self.extra);
        w.write_u64_le(self.unlock_time);
        // The field is still tagged "use_rct" but carries the flags: "converted
        // `use_rct` field into construction_flags when view tags were
        // introduced to maintain backwards compatibility".
        let mut construction = 0u8;
        if self.use_rct {
            construction ^= construction_flags::USE_RCT;
        }
        if self.use_view_tags {
            construction ^= construction_flags::USE_VIEW_TAGS;
        }
        w.write_u8(construction);
        self.rct_config.write(w);
        w.write_varint(self.dests.len() as u64);
        for d in &self.dests {
            d.write(w);
        }
        w.write_u32_le(self.subaddr_account);
        w.write_varint(self.subaddr_indices.len() as u64);
        for &i in &self.subaddr_indices {
            w.write_varint(u64::from(i));
        }
    }

    pub fn read(r: &mut Reader<'_>) -> Result<TxConstructionData> {
        let n = r.read_len(MAX_ENTRIES, "inputs")?;
        let mut sources = Vec::with_capacity(n);
        for _ in 0..n {
            sources.push(TxSourceEntry::read(r)?);
        }
        let change_dts = TxDestinationEntry::read(r)?;
        let n = r.read_len(MAX_ENTRIES, "outputs")?;
        let mut splitted_dsts = Vec::with_capacity(n);
        for _ in 0..n {
            splitted_dsts.push(TxDestinationEntry::read(r)?);
        }
        let n = r.read_len(MAX_ENTRIES, "selected transfers")?;
        let mut selected_transfers = Vec::with_capacity(n);
        for _ in 0..n {
            selected_transfers.push(r.read_varint()?);
        }
        let extra = r.read_bytes_prefixed(MAX_STRING, "tx_extra")?.to_vec();
        let unlock_time = r.read_u64_le()?;
        let construction = r.read_u8()?;
        let rct_config = RctConfig::read(r)?;
        let n = r.read_len(MAX_ENTRIES, "destinations")?;
        let mut dests = Vec::with_capacity(n);
        for _ in 0..n {
            dests.push(TxDestinationEntry::read(r)?);
        }
        let subaddr_account = r.read_u32_le()?;
        let n = r.read_len(MAX_ENTRIES, "subaddress indices")?;
        let mut subaddr_indices = Vec::with_capacity(n);
        for _ in 0..n {
            subaddr_indices.push(r.read_varint_u32()?);
        }
        Ok(TxConstructionData {
            sources,
            change_dts,
            splitted_dsts,
            selected_transfers,
            extra,
            unlock_time,
            use_rct: construction & construction_flags::USE_RCT != 0,
            use_view_tags: construction & construction_flags::USE_VIEW_TAGS != 0,
            rct_config,
            dests,
            subaddr_account,
            subaddr_indices,
        })
    }

    /// The fee: what the inputs hold, less what the outputs do.
    pub fn fee(&self) -> u64 {
        let inputs: u128 = self.sources.iter().map(|s| u128::from(s.amount)).sum();
        let outputs: u128 = self
            .splitted_dsts
            .iter()
            .map(|d| u128::from(d.amount))
            .sum();
        u64::try_from(inputs.saturating_sub(outputs)).unwrap_or(u64::MAX)
    }
}

/// `wallet2::pending_tx`: a signed transaction and what the wallet that signed
/// it knows about it.
#[derive(Clone, Debug, Default)]
pub struct PendingTx {
    pub tx: Transaction,
    pub dust: u64,
    pub fee: u64,
    pub dust_added_to_fee: bool,
    pub change_dts: TxDestinationEntry,
    pub selected_transfers: Vec<u64>,
    /// The key images as text, space-separated with a trailing space, which is
    /// how `boost::to_string(in.k_image) + " "` builds it. Kept as the C++
    /// keeps it so the field round-trips.
    pub key_images: String,
    /// **Zero in a signed set.** `sign_tx` sets `ptx.tx_key =
    /// rct::rct2sk(rct::identity())` with the comment "don't send it back to
    /// the untrusted view wallet": the transaction key would let the watch-only
    /// half prove the payment, and the watch-only half is the compromised one.
    pub tx_key: SecretKey,
    pub additional_tx_keys: Vec<SecretKey>,
    pub dests: Vec<TxDestinationEntry>,
    pub construction_data: TxConstructionData,
    /// Multisig only, and always zero here.
    pub multisig_tx_key_entropy: SecretKey,
}

impl PendingTx {
    const VERSION: u64 = 1;

    pub fn write(&self, w: &mut Writer) {
        w.write_varint(Self::VERSION);
        self.tx.write(w);
        w.write_u64_le(self.dust);
        w.write_u64_le(self.fee);
        w.write_u8(u8::from(self.dust_added_to_fee));
        self.change_dts.write(w);
        w.write_varint(self.selected_transfers.len() as u64);
        for &i in &self.selected_transfers {
            w.write_varint(i);
        }
        w.write_bytes_prefixed(self.key_images.as_bytes());
        w.write_bytes(&self.tx_key.0);
        w.write_varint(self.additional_tx_keys.len() as u64);
        for k in &self.additional_tx_keys {
            w.write_bytes(&k.0);
        }
        w.write_varint(self.dests.len() as u64);
        for d in &self.dests {
            d.write(w);
        }
        self.construction_data.write(w);
        // `multisig_sigs`: none, and this build refuses a set that has any.
        w.write_varint(0);
        w.write_bytes(&self.multisig_tx_key_entropy.0);
    }

    pub fn read(r: &mut Reader<'_>) -> Result<PendingTx> {
        // `VERSION_FIELD(1)` with only a `version < 1` branch: a later version
        // is read as this one, which is what the reference does.
        let version = r.read_varint()?;
        let tx = Transaction::read(r)?;
        let dust = r.read_u64_le()?;
        let fee = r.read_u64_le()?;
        let dust_added_to_fee = r.read_u8()? != 0;
        let change_dts = TxDestinationEntry::read(r)?;
        let n = r.read_len(MAX_ENTRIES, "selected transfers")?;
        let mut selected_transfers = Vec::with_capacity(n);
        for _ in 0..n {
            selected_transfers.push(r.read_varint()?);
        }
        let key_images = r.read_bytes_prefixed(MAX_STRING, "key images")?;
        let key_images = std::str::from_utf8(key_images)
            .map_err(|_| wow_serialize::Error::InvalidValue("the key image list is not text"))?
            .to_string();
        let tx_key = SecretKey(r.read_array::<32>()?);
        let n = r.read_len(MAX_ENTRIES, "additional tx keys")?;
        let mut additional_tx_keys = Vec::with_capacity(n);
        for _ in 0..n {
            additional_tx_keys.push(SecretKey(r.read_array::<32>()?));
        }
        let n = r.read_len(MAX_ENTRIES, "destinations")?;
        let mut dests = Vec::with_capacity(n);
        for _ in 0..n {
            dests.push(TxDestinationEntry::read(r)?);
        }
        let construction_data = TxConstructionData::read(r)?;
        let multisig = r.read_len(MAX_ENTRIES, "multisig signatures")?;
        if multisig != 0 {
            return Err(ColdError::Parse(wow_serialize::Error::InvalidValue(
                "a multisig transaction; this build does not do multisig",
            )));
        }
        // "if (version < 1) { multisig_tx_key_entropy = null; return true; }"
        let multisig_tx_key_entropy = if version < 1 {
            SecretKey::ZERO
        } else {
            SecretKey(r.read_array::<32>()?)
        };
        Ok(PendingTx {
            tx,
            dust,
            fee,
            dust_added_to_fee,
            change_dts,
            selected_transfers,
            key_images,
            tx_key,
            additional_tx_keys,
            dests,
            construction_data,
            multisig_tx_key_entropy,
        })
    }
}

/// `wallet2::unsigned_tx_set`: what a watch-only wallet hands to a cold one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnsignedTxSet {
    pub txes: Vec<TxConstructionData>,
    /// The exporter's outputs, so the cold wallet can fill in the indices
    /// `selected_transfers` refers to. `sign_tx` imports these first.
    pub new_transfers: ExportedOutputs,
}

impl UnsignedTxSet {
    /// `VERSION_FIELD(2)`: versions 0 and 1 carried a `std::pair` rather than
    /// the triple, and are Boost-era.
    const VERSION: u64 = 2;

    pub fn write(&self, w: &mut Writer) {
        w.write_varint(Self::VERSION);
        w.write_varint(self.txes.len() as u64);
        for t in &self.txes {
            t.write(w);
        }
        self.new_transfers.write(w);
    }

    pub fn read(r: &mut Reader<'_>) -> Result<UnsignedTxSet> {
        // Versions 0 and 1 put a `std::pair` where the triple is and then
        // return, so they cannot be read as this one. They were only ever
        // written through Boost, so a `\005` file cannot carry them.
        let version = r.read_varint()?;
        if version < Self::VERSION {
            return Err(ColdError::UnsupportedVersion {
                what: "unsigned transfer set",
                version,
            });
        }
        let n = r.read_len(MAX_ENTRIES, "transactions")?;
        let mut txes = Vec::with_capacity(n);
        for _ in 0..n {
            txes.push(TxConstructionData::read(r)?);
        }
        let new_transfers = ExportedOutputs::read(r)?;
        Ok(UnsignedTxSet {
            txes,
            new_transfers,
        })
    }

    /// The file `dump_tx_to_str` writes: the magic and version in the clear,
    /// the rest sealed under the view key.
    pub fn to_file(&self, view_secret_key: &SecretKey, rng: &mut Rng) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        self.write(&mut w);
        let mut out = UNSIGNED_TX_MAGIC.to_vec();
        out.push(TX_SET_VERSION);
        out.extend_from_slice(&encrypt(&w.into_vec(), view_secret_key, true, rng)?);
        Ok(out)
    }

    /// `parse_unsigned_tx_from_str`.
    pub fn from_file(blob: &[u8], view_secret_key: &SecretKey) -> Result<UnsignedTxSet> {
        let body = strip_versioned_magic(
            blob,
            UNSIGNED_TX_MAGIC,
            "unsigned transfer set",
            TX_SET_VERSION,
        )?;
        let data = decrypt(body, view_secret_key, true)?;
        let mut r = Reader::new(&data);
        let set = UnsignedTxSet::read(&mut r)?;
        if !r.is_empty() {
            return Err(ColdError::Trailing(r.remaining()));
        }
        Ok(set)
    }
}

/// `wallet2::signed_tx_set`: what a cold wallet hands back.
#[derive(Clone, Debug, Default)]
pub struct SignedTxSet {
    pub ptx: Vec<PendingTx>,
    /// Every key image the signing wallet knows, in its own output order, so
    /// the watch-only half can learn them all at once.
    pub key_images: Vec<KeyImage>,
    /// Output public key → key image, for the outputs of these very
    /// transactions: the change coming back, whose key image the watch-only
    /// half could not compute.
    pub tx_key_images: Vec<(PublicKey, KeyImage)>,
}

impl SignedTxSet {
    pub fn write(&self, w: &mut Writer) {
        w.write_varint(0); // VERSION_FIELD(0)
        w.write_varint(self.ptx.len() as u64);
        for p in &self.ptx {
            p.write(w);
        }
        w.write_varint(self.key_images.len() as u64);
        for k in &self.key_images {
            w.write_bytes(&k.0);
        }
        // `serializable_unordered_map`: a container of pairs, so each entry
        // writes its own arity 2 first. The C++ iterates an unordered_map, so
        // the order on the wire is whatever its buckets give; nothing reads it
        // in order.
        w.write_varint(self.tx_key_images.len() as u64);
        for (pk, ki) in &self.tx_key_images {
            w.write_varint(2);
            w.write_bytes(&pk.0);
            w.write_bytes(&ki.0);
        }
    }

    pub fn read(r: &mut Reader<'_>) -> Result<SignedTxSet> {
        // `VERSION_FIELD(0)` with no branch on it, as above.
        let _version = r.read_varint()?;
        let n = r.read_len(MAX_ENTRIES, "transactions")?;
        let mut ptx = Vec::with_capacity(n);
        for _ in 0..n {
            ptx.push(PendingTx::read(r)?);
        }
        let n = r.read_len(MAX_ENTRIES, "key images")?;
        let mut key_images = Vec::with_capacity(n);
        for _ in 0..n {
            key_images.push(KeyImage(r.read_array::<32>()?));
        }
        let n = r.read_len(MAX_ENTRIES, "output key images")?;
        let mut tx_key_images = Vec::with_capacity(n);
        for _ in 0..n {
            let arity = r.read_varint()?;
            if arity != 2 {
                return Err(ColdError::Parse(wow_serialize::Error::InvalidValue(
                    "an output key image is a pair",
                )));
            }
            let pk = PublicKey(r.read_array::<32>()?);
            let ki = KeyImage(r.read_array::<32>()?);
            tx_key_images.push((pk, ki));
        }
        Ok(SignedTxSet {
            ptx,
            key_images,
            tx_key_images,
        })
    }

    /// The file `sign_tx_dump_to_str` writes.
    pub fn to_file(&self, view_secret_key: &SecretKey, rng: &mut Rng) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        self.write(&mut w);
        let mut out = SIGNED_TX_MAGIC.to_vec();
        out.push(TX_SET_VERSION);
        out.extend_from_slice(&encrypt(&w.into_vec(), view_secret_key, true, rng)?);
        Ok(out)
    }

    /// `parse_tx_from_str`.
    pub fn from_file(blob: &[u8], view_secret_key: &SecretKey) -> Result<SignedTxSet> {
        let body =
            strip_versioned_magic(blob, SIGNED_TX_MAGIC, "signed transfer set", TX_SET_VERSION)?;
        let data = decrypt(body, view_secret_key, true)?;
        let mut r = Reader::new(&data);
        let set = SignedTxSet::read(&mut r)?;
        if !r.is_empty() {
            return Err(ColdError::Trailing(r.remaining()));
        }
        Ok(set)
    }
}

/// The key image list `pending_tx::key_images` holds, built as
/// `boost::to_string(in.k_image) + " "` builds it: lower-case hex, each
/// followed by a space.
pub fn key_image_list(images: &[KeyImage]) -> String {
    let mut s = String::with_capacity(images.len() * 65);
    for k in images {
        s.push_str(&wow_crypto::hex::encode(&k.0));
        s.push(' ');
    }
    s
}

/// The transaction ids of the transactions in a signed set.
pub fn signed_txids(set: &SignedTxSet) -> Vec<Hash256> {
    set.ptx
        .iter()
        .map(|p| crate::transfer::transaction_hash(&p.tx))
        .collect()
}

fn strip_magic<'a>(blob: &'a [u8], magic: &[u8], what: &'static str) -> Result<&'a [u8]> {
    if blob.len() < magic.len() || &blob[..magic.len()] != magic {
        return Err(ColdError::BadMagic(what));
    }
    Ok(&blob[magic.len()..])
}

/// A magic string whose version byte follows it rather than being part of it,
/// as the two transfer sets have.
fn strip_versioned_magic<'a>(
    blob: &'a [u8],
    magic: &[u8],
    what: &'static str,
    expected: u8,
) -> Result<&'a [u8]> {
    let rest = strip_magic(blob, magic, what)?;
    let (&version, rest) = rest.split_first().ok_or(ColdError::BadMagic(what))?;
    if version != expected {
        // 3 and 4 are the Boost formats, and saying so is more useful than
        // "unsupported version": it tells the user what to do about it.
        return Err(if version == 3 || version == 4 {
            ColdError::DeprecatedFormat {
                what,
                version,
                expected,
            }
        } else {
            ColdError::UnsupportedVersion {
                what,
                version: u64::from(version),
            }
        });
    }
    Ok(rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wow_crypto::hex;

    fn rng() -> Rng {
        Rng::deterministic_test_seed()
    }

    fn view_key() -> SecretKey {
        SecretKey(wow_crypto::ops::sc_reduce32(&[7u8; 32]))
    }

    fn address() -> AccountPublicAddress {
        let spend = SecretKey(wow_crypto::ops::sc_reduce32(&[9u8; 32]));
        AccountPublicAddress {
            spend_public_key: wow_crypto::secret_key_to_public_key(&spend).expect("spend"),
            view_public_key: wow_crypto::secret_key_to_public_key(&view_key()).expect("view"),
        }
    }

    /// A transaction that survives a write and a read: version 2, no inputs,
    /// so no RingCT half. `Transaction::default()` is version 0, which the
    /// prefix parser refuses.
    fn empty_tx() -> Transaction {
        Transaction {
            prefix: wow_types::tx::TransactionPrefix {
                version: 2,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Encryption is a stream xor with an eight-byte IV in front and a
    /// signature behind, and it round-trips.
    #[test]
    fn a_blob_round_trips_through_the_view_key() {
        let key = view_key();
        let msg = b"the spend key never sees a network".to_vec();
        let sealed = encrypt_with_iv(&msg, &key, true, [3u8; 8], &mut rng()).expect("encrypt");
        assert_eq!(sealed.len(), msg.len() + 8 + 64);
        assert_eq!(&sealed[..8], &[3u8; 8]);
        assert_ne!(&sealed[8..8 + msg.len()], &msg[..]);
        assert_eq!(decrypt(&sealed, &key, true).expect("decrypt"), msg);

        // Unauthenticated leaves the signature off entirely, and the body is
        // the same bytes: the signature is over the ciphertext, not part of it.
        let plain = encrypt_with_iv(&msg, &key, false, [3u8; 8], &mut rng()).expect("encrypt");
        assert_eq!(plain.len(), msg.len() + 8);
        assert_eq!(&plain[8..], &sealed[8..8 + msg.len()]);
        assert_eq!(decrypt(&plain, &key, false).expect("decrypt"), msg);
    }

    /// A tampered blob does not decrypt: that is what the trailing signature
    /// is for.
    #[test]
    fn a_tampered_blob_is_refused() {
        let key = view_key();
        let mut sealed = encrypt(b"pay me", &key, true, &mut rng()).expect("encrypt");
        sealed[10] ^= 1;
        assert!(matches!(
            decrypt(&sealed, &key, true),
            Err(ColdError::NotAuthenticated)
        ));

        // And so is one that is too short to hold its own framing.
        assert!(matches!(
            decrypt(&[0u8; 40], &key, true),
            Err(ColdError::ShortCiphertext)
        ));
    }

    /// Another wallet's view key does not open it.
    #[test]
    fn another_wallets_key_does_not_open_it() {
        let sealed = encrypt(b"pay me", &view_key(), true, &mut rng()).expect("encrypt");
        let other = SecretKey(wow_crypto::ops::sc_reduce32(&[8u8; 32]));
        assert!(matches!(
            decrypt(&sealed, &other, true),
            Err(ColdError::NotAuthenticated)
        ));
    }

    fn sample_output(n: u8) -> ExportedTransferDetails {
        ExportedTransferDetails {
            public_key: PublicKey([n; 32]),
            internal_output_index: u64::from(n),
            global_output_index: 1_000 + u64::from(n),
            tx_public_key: PublicKey([n.wrapping_add(1); 32]),
            flags: flags::RCT | flags::KEY_IMAGE_KNOWN,
            amount: 123_456_789,
            additional_tx_keys: vec![PublicKey([n.wrapping_add(2); 32])],
            subaddress: SubaddressIndex::new(1, 2),
        }
    }

    /// The bytes of one exported output, field by field, because nothing here
    /// can be checked against the C++ locally and the layout is the contract.
    #[test]
    fn an_exported_output_has_the_documented_layout() {
        let o = ExportedTransferDetails {
            public_key: PublicKey([0xaa; 32]),
            internal_output_index: 1,
            global_output_index: 300,
            tx_public_key: PublicKey([0xbb; 32]),
            flags: 0x0c,
            amount: 128,
            additional_tx_keys: Vec::new(),
            subaddress: SubaddressIndex::new(0, 5),
        };
        let mut w = Writer::new();
        o.write(&mut w);
        let bytes = w.into_vec();
        // version, pubkey, internal index, global index (300 = 0xac 0x02), tx
        // pubkey, flags, amount (128 = 0x80 0x01), no additional keys, major,
        // minor.
        let expected = format!(
            "01{}01ac02{}0c8001000005",
            "aa".repeat(32),
            "bb".repeat(32)
        );
        assert_eq!(hex::encode(&bytes), expected);

        let mut r = Reader::new(&bytes);
        assert_eq!(ExportedTransferDetails::read(&mut r).expect("read"), o);
        assert!(r.is_empty());
    }

    /// An exported output set is a tuple, and a tuple writes its own arity.
    #[test]
    fn an_output_set_writes_its_tuple_arity() {
        let set = ExportedOutputs {
            offset: 2,
            total: 9,
            outputs: vec![sample_output(1), sample_output(2)],
        };
        let mut w = Writer::new();
        set.write(&mut w);
        let bytes = w.into_vec();
        assert_eq!(&bytes[..4], &[3, 2, 9, 2], "arity, offset, total, count");

        let mut r = Reader::new(&bytes);
        assert_eq!(ExportedOutputs::read(&mut r).expect("read"), set);
        assert!(r.is_empty());
    }

    /// Export then import, through the file form: the magic is in the clear,
    /// the rest is not, and the account header has to match.
    #[test]
    fn an_output_file_round_trips() {
        let set = ExportedOutputs {
            offset: 0,
            total: 3,
            outputs: vec![sample_output(1), sample_output(2), sample_output(3)],
        };
        let file = set
            .to_file(&address(), &view_key(), &mut rng())
            .expect("export");
        assert!(file.starts_with(OUTPUT_EXPORT_MAGIC));
        assert_eq!(
            ExportedOutputs::from_file(&file, &address(), &view_key()).expect("import"),
            set
        );

        // Another account's file is refused before anything is parsed.
        let other = AccountPublicAddress {
            spend_public_key: PublicKey([1; 32]),
            view_public_key: address().view_public_key,
        };
        assert!(matches!(
            ExportedOutputs::from_file(&file, &other, &view_key()),
            Err(ColdError::WrongAccount)
        ));

        // And so is one with the wrong magic.
        let mut wrong = file.clone();
        wrong[0] = b'X';
        assert!(matches!(
            ExportedOutputs::from_file(&wrong, &address(), &view_key()),
            Err(ColdError::BadMagic(_))
        ));
    }

    /// The key image file is hand-rolled, not an archive: a four-byte
    /// little-endian offset, the account, and fixed-width records.
    #[test]
    fn a_key_image_file_round_trips() {
        let set = ExportedKeyImages {
            offset: 0x0102_0304,
            images: vec![
                SignedKeyImage {
                    key_image: KeyImage([1; 32]),
                    signature: Signature::from_bytes(&[2; 64]),
                },
                SignedKeyImage {
                    key_image: KeyImage([3; 32]),
                    signature: Signature::from_bytes(&[4; 64]),
                },
            ],
        };
        let file = set
            .to_file(&address(), &view_key(), &mut rng())
            .expect("export");
        assert!(file.starts_with(KEY_IMAGE_EXPORT_MAGIC));

        let data =
            decrypt(&file[KEY_IMAGE_EXPORT_MAGIC.len()..], &view_key(), true).expect("decrypt");
        assert_eq!(&data[..4], &[0x04, 0x03, 0x02, 0x01], "little-endian offset");
        assert_eq!(data.len(), 4 + 64 + 2 * 96);

        assert_eq!(
            ExportedKeyImages::from_file(&file, &address(), &view_key()).expect("import"),
            set
        );
    }

    /// A key image file whose records do not divide evenly is refused rather
    /// than half-read.
    #[test]
    fn a_truncated_key_image_file_is_refused() {
        let image = SignedKeyImage {
            key_image: KeyImage([1; 32]),
            signature: Signature::from_bytes(&[2; 64]),
        };
        // Build the plaintext one byte short and seal it.
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&address().to_bytes());
        data.extend_from_slice(&image.key_image.0);
        data.extend_from_slice(&image.signature.to_bytes()[..63]);
        let mut file = KEY_IMAGE_EXPORT_MAGIC.to_vec();
        file.extend_from_slice(&encrypt(&data, &view_key(), true, &mut rng()).expect("encrypt"));
        assert!(matches!(
            ExportedKeyImages::from_file(&file, &address(), &view_key()),
            Err(ColdError::BadSize(_))
        ));
    }

    /// A key image signature verifies under the output's public key, and not
    /// under another one.
    #[test]
    fn a_key_image_signature_verifies() {
        let mut rng = rng();
        let secret = SecretKey(rng.random_scalar());
        let public = wow_crypto::secret_key_to_public_key(&secret).expect("public");
        let key_image = wow_crypto::generate_key_image(&public, &secret).expect("image");

        let sig = sign_key_image(&mut rng, &key_image, &public, &secret).expect("sign");
        assert!(check_key_image_signature(&key_image, &public, &sig));

        let other =
            wow_crypto::secret_key_to_public_key(&SecretKey(rng.random_scalar())).expect("other");
        assert!(!check_key_image_signature(&key_image, &other, &sig));
    }

    fn sample_source() -> TxSourceEntry {
        TxSourceEntry {
            outputs: vec![
                RingEntry {
                    global_index: 5,
                    public_key: PublicKey([1; 32]),
                    commitment: wow_crypto::types::EcPoint([2; 32]),
                },
                RingEntry {
                    global_index: 11,
                    public_key: PublicKey([3; 32]),
                    commitment: wow_crypto::types::EcPoint([4; 32]),
                },
            ],
            real_output: 1,
            real_out_tx_key: PublicKey([5; 32]),
            real_out_additional_tx_keys: vec![PublicKey([6; 32])],
            real_output_in_tx_index: 2,
            amount: 1_000_000,
            rct: true,
            mask: [7; 32],
            multisig_klrki: [0; 128],
        }
    }

    fn sample_destination(amount: u64) -> TxDestinationEntry {
        TxDestinationEntry {
            original: "Wo1abc".to_string(),
            amount,
            address: address(),
            is_subaddress: true,
            is_integrated: false,
        }
    }

    fn sample_construction() -> TxConstructionData {
        TxConstructionData {
            sources: vec![sample_source()],
            change_dts: sample_destination(400_000),
            splitted_dsts: vec![sample_destination(500_000), sample_destination(400_000)],
            selected_transfers: vec![3],
            extra: vec![0x01, 0x02, 0x03],
            unlock_time: 0,
            use_rct: true,
            use_view_tags: true,
            rct_config: RctConfig::default(),
            dests: vec![sample_destination(500_000)],
            subaddr_account: 1,
            subaddr_indices: vec![0, 2],
        }
    }

    /// A pair writes its arity, and `real_output` is eight fixed bytes rather
    /// than a varint. Both are easy to get wrong and both are checked here.
    #[test]
    fn a_source_writes_pairs_and_fixed_width_integers() {
        let s = sample_source();
        let mut w = Writer::new();
        s.write(&mut w);
        let bytes = w.into_vec();
        // count, then (arity 2, index 5, 64 bytes), then (arity 2, index 11,
        // 64 bytes), then `real_output` as eight bytes.
        assert_eq!(&bytes[..3], &[2, 2, 5]);
        assert_eq!(&bytes[67..69], &[2, 11]);
        let after_ring = 1 + 2 * (1 + 1 + 64);
        assert_eq!(
            &bytes[after_ring..after_ring + 8],
            &[1, 0, 0, 0, 0, 0, 0, 0],
            "real_output is FIELD(uint64_t), so eight little-endian bytes"
        );

        let mut r = Reader::new(&bytes);
        assert_eq!(TxSourceEntry::read(&mut r).expect("read"), s);
        assert!(r.is_empty());
    }

    /// A source whose real member is outside its ring cannot be signed, and
    /// the reference refuses it in `END_SERIALIZE`.
    #[test]
    fn a_source_with_a_bad_real_index_is_refused() {
        let mut s = sample_source();
        s.real_output = 2;
        let mut w = Writer::new();
        s.write(&mut w);
        let bytes = w.into_vec();
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            TxSourceEntry::read(&mut r),
            Err(ColdError::Parse(wow_serialize::Error::InvalidValue(_)))
        ));
    }

    /// The construction data round-trips, flags and all.
    #[test]
    fn construction_data_round_trips() {
        let cd = sample_construction();
        let mut w = Writer::new();
        cd.write(&mut w);
        let bytes = w.into_vec();
        let mut r = Reader::new(&bytes);
        assert_eq!(TxConstructionData::read(&mut r).expect("read"), cd);
        assert!(r.is_empty());

        assert_eq!(cd.fee(), 1_000_000 - 900_000);

        // The flags byte is `use_rct | use_view_tags`, and each bit survives
        // on its own.
        let mut off = cd.clone();
        off.use_view_tags = false;
        let mut w = Writer::new();
        off.write(&mut w);
        let bytes = w.into_vec();
        let mut r = Reader::new(&bytes);
        let back = TxConstructionData::read(&mut r).expect("read");
        assert!(back.use_rct && !back.use_view_tags);
    }

    /// An unsigned set round-trips through its file form, and a version 4 file
    /// -- the Boost one -- is refused by name rather than mis-parsed.
    #[test]
    fn an_unsigned_set_round_trips() {
        let set = UnsignedTxSet {
            txes: vec![sample_construction()],
            new_transfers: ExportedOutputs {
                offset: 0,
                total: 4,
                outputs: vec![sample_output(1)],
            },
        };
        let file = set.to_file(&view_key(), &mut rng()).expect("write");
        assert!(file.starts_with(UNSIGNED_TX_MAGIC));
        assert_eq!(file[UNSIGNED_TX_MAGIC.len()], TX_SET_VERSION);
        assert_eq!(
            UnsignedTxSet::from_file(&file, &view_key()).expect("parse"),
            set
        );

        let mut old = file.clone();
        old[UNSIGNED_TX_MAGIC.len()] = 4;
        assert!(matches!(
            UnsignedTxSet::from_file(&old, &view_key()),
            Err(ColdError::DeprecatedFormat { version: 4, .. })
        ));

        let mut future = file.clone();
        future[UNSIGNED_TX_MAGIC.len()] = 9;
        assert!(matches!(
            UnsignedTxSet::from_file(&future, &view_key()),
            Err(ColdError::UnsupportedVersion { version: 9, .. })
        ));
    }

    /// A signed set round-trips, including the transaction inside it.
    #[test]
    fn a_signed_set_round_trips() {
        let ptx = PendingTx {
            tx: empty_tx(),
            dust: 0,
            fee: 100_000,
            dust_added_to_fee: false,
            change_dts: sample_destination(400_000),
            selected_transfers: vec![3],
            key_images: key_image_list(&[KeyImage([1; 32])]),
            tx_key: SecretKey::ZERO,
            additional_tx_keys: Vec::new(),
            dests: vec![sample_destination(500_000)],
            construction_data: sample_construction(),
            multisig_tx_key_entropy: SecretKey::ZERO,
        };
        let set = SignedTxSet {
            ptx: vec![ptx],
            key_images: vec![KeyImage([1; 32]), KeyImage([2; 32])],
            tx_key_images: vec![(PublicKey([3; 32]), KeyImage([4; 32]))],
        };
        let file = set.to_file(&view_key(), &mut rng()).expect("write");
        assert!(file.starts_with(SIGNED_TX_MAGIC));

        let back = SignedTxSet::from_file(&file, &view_key()).expect("parse");
        assert_eq!(back.ptx.len(), 1);
        assert_eq!(back.key_images, set.key_images);
        assert_eq!(back.tx_key_images, set.tx_key_images);
        assert_eq!(back.ptx[0].fee, 100_000);
        assert_eq!(back.ptx[0].construction_data, set.ptx[0].construction_data);
        assert_eq!(back.ptx[0].tx.prefix, set.ptx[0].tx.prefix);
        assert_eq!(back.ptx[0].key_images, format!("{} ", "01".repeat(32)));
    }

    /// A signed set that carries multisig signatures is refused: this build
    /// does not do multisig, and signing one halfway would be worse.
    #[test]
    fn a_multisig_signed_set_is_refused() {
        // Hand-build a `pending_tx` whose `multisig_sigs` count is one.
        let mut w = Writer::new();
        w.write_varint(1); // version
        empty_tx().write(&mut w);
        w.write_u64_le(0); // dust
        w.write_u64_le(0); // fee
        w.write_u8(0); // dust_added_to_fee
        TxDestinationEntry::default().write(&mut w);
        w.write_varint(0); // selected_transfers
        w.write_bytes_prefixed(b""); // key_images
        w.write_bytes(&[0u8; 32]); // tx_key
        w.write_varint(0); // additional_tx_keys
        w.write_varint(0); // dests
        TxConstructionData::default().write(&mut w);
        w.write_varint(1); // one multisig_sig
        let bytes = w.into_vec();

        let mut r = Reader::new(&bytes);
        assert!(matches!(
            PendingTx::read(&mut r),
            Err(ColdError::Parse(wow_serialize::Error::InvalidValue(_)))
        ));
    }

    /// The key image list is hex with a trailing space per entry, as
    /// `boost::to_string(k) + " "` builds it.
    #[test]
    fn the_key_image_list_is_space_terminated_hex() {
        assert_eq!(key_image_list(&[]), "");
        let s = key_image_list(&[KeyImage([0xab; 32]), KeyImage([0xcd; 32])]);
        assert_eq!(s, format!("{} {} ", "ab".repeat(32), "cd".repeat(32)));
        assert!(s.ends_with(' '));
    }
}
