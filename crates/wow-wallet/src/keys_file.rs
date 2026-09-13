//! The `<name>.keys` file: read and write it the way the C++ wallet does.
//!
//! `wallet2::get_keys_file_data` and `wallet2::load_keys_buf`. `specs/12` §2.1.
//!
//! This is the one wallet file that **must** be byte-compatible — the cache can
//! be rebuilt from the chain, but the keys file is where the money is.
//!
//! ```text
//! <name>.keys        binary archive:  [8] iv | varint len | [len] ciphertext
//!   decrypts to      JSON:            { "key_data": <epee blob>, ...settings }
//!     key_data       epee storage:    { m_keys: {...}, m_creation_timestamp }
//!       secret keys  xored with a ChaCha20 stream under a second derived key
//! ```
//!
//! # The JSON is not UTF-8
//!
//! `key_data` is a binary blob stored as a JSON *string*. The reference writes
//! it with rapidjson, which escapes only the control characters, `"` and `\`,
//! and passes bytes `0x80`–`0xff` through raw — so the file contains byte
//! sequences that are not valid UTF-8, and `String::from_utf8` on it fails.
//!
//! Both directions therefore transcode Latin-1: byte `n` is `char n`, and back.
//! Since every escape either side produces is ASCII, and every character in the
//! document is below `U+0100` by construction, the round trip is exact. Using a
//! UTF-8 reader here does not fail loudly — it replaces the high bytes and
//! silently corrupts the key material.
//!
//! # What is not handled
//!
//! * The pre-2017 ChaCha8 format and the pre-JSON format before it. Both are
//!   detected and reported rather than guessed at.
//! * Background-sync keys files, which are keyed differently.
//! * Multisig, which needs the `multisig_signers` blobs.

use serde_json::{Map, Value as Json};
use wow_serialize::binary::{Reader, Writer};
use wow_types::address::Network;

use crate::account::{AccountBase, AccountError};
use crate::chacha::{self, Iv, Key};

/// A keys file's ciphertext cannot plausibly exceed this. The reference has no
/// limit; this one exists so a corrupt length is an error and not an
/// allocation.
const MAX_ACCOUNT_DATA: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum KeysFileError {
    #[error("the outer container is malformed: {0}")]
    Container(#[from] wow_serialize::Error),
    #[error("the decrypted keys file is not JSON — wrong password, or a format this reader does not handle (pre-2017 ChaCha8, pre-JSON, or a background-sync keys file)")]
    NotJson,
    #[error("the keys file JSON has no `key_data`")]
    NoKeyData,
    #[error(transparent)]
    Account(#[from] AccountError),
    #[error("the keys file is multisig, which is not implemented")]
    Multisig,
    #[error("`{0}` has the wrong JSON type")]
    BadField(&'static str),
}

type Result<T> = std::result::Result<T, KeysFileError>;

/// `wallet2::AskPasswordType`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AskPassword {
    Never,
    OnAction,
    /// The interesting one: the spend key stays encrypted in memory and only
    /// the view key is decrypted, so the wallet can scan without the password.
    ToDecrypt,
}

impl AskPassword {
    fn from_i64(v: i64) -> AskPassword {
        match v {
            0 => AskPassword::Never,
            2 => AskPassword::ToDecrypt,
            _ => AskPassword::OnAction,
        }
    }
}

/// An opened keys file.
///
/// The settings are kept as the JSON they were read from rather than as a
/// struct of every member. `wallet2` writes about fifty, most of which are UI
/// preferences this implementation has no opinion about, and dropping them on
/// rewrite would quietly reset someone's wallet. Typed accessors cover the ones
/// that change behaviour.
#[derive(Clone, Debug)]
pub struct KeysFile {
    /// The keys, decrypted.
    pub account: AccountBase,
    /// Every JSON member except `key_data`, exactly as read.
    pub settings: Map<String, Json>,
}

impl KeysFile {
    /// Read and decrypt a keys file.
    ///
    /// `kdf_rounds` must match what wrote the file; the CLI uses 1.
    pub fn open(blob: &[u8], password: &[u8], kdf_rounds: u64) -> Result<KeysFile> {
        let (iv, ciphertext) = parse_container(blob)?;
        let key = chacha::generate_chacha_key(password, kdf_rounds);
        let plaintext = chacha::chacha20(ciphertext, &key, &iv);

        let mut settings = parse_json(&plaintext).ok_or(KeysFileError::NotJson)?;

        let key_data = match settings.remove("key_data") {
            Some(Json::String(s)) => latin1_to_bytes(&s),
            _ => return Err(KeysFileError::NoKeyData),
        };

        if bool_member(&settings, "multisig").unwrap_or(false) {
            return Err(KeysFileError::Multisig);
        }

        let mut account = AccountBase::from_key_data(&key_data)?;
        // `encrypted_secret_keys` is written as 1 by every current writer, but
        // a file old enough to lack it holds the keys in the clear.
        if u64_member(&settings, "encrypted_secret_keys").unwrap_or(0) != 0 {
            account.keys.decrypt(&key);
        }
        account.keys.verify()?;

        Ok(KeysFile { account, settings })
    }

    /// Encrypt and serialize, ready to write to disk.
    ///
    /// `iv` and `key_iv` are the two nonces the reference draws at random — the
    /// outer one for the JSON and the inner one for the secret keys. They are
    /// parameters rather than generated here so a test can pin them; callers
    /// pass fresh random bytes.
    pub fn to_blob(&self, password: &[u8], kdf_rounds: u64, iv: Iv, key_iv: Iv) -> Result<Vec<u8>> {
        let key = chacha::generate_chacha_key(password, kdf_rounds);

        let mut account = self.account.clone();
        account.keys.encrypt(&key, key_iv);
        let key_data = account.to_key_data()?;

        let mut json = self.settings.clone();
        json.insert("key_data".into(), Json::String(bytes_to_latin1(&key_data)));
        // Whatever the file said before, what we just wrote is encrypted.
        json.insert("encrypted_secret_keys".into(), Json::from(1u64));

        let text = serde_json::to_string(&Json::Object(json)).expect("a JSON object serializes");
        let plaintext = latin1_to_bytes(&text);
        let ciphertext = chacha::chacha20(&plaintext, &key, &iv);

        let mut w = Writer::new();
        w.write_bytes(&iv);
        w.write_bytes_prefixed(&ciphertext);
        Ok(w.into_vec())
    }

    /// Build the settings a freshly created wallet gets, matching the
    /// reference's defaults for the members that change behaviour.
    pub fn new(account: AccountBase, network: Network, seed_language: &str) -> KeysFile {
        let mut settings = Map::new();
        settings.insert("seed_language".into(), Json::from(seed_language));
        settings.insert("nettype".into(), Json::from(nettype_of(network)));
        settings.insert("watch_only".into(), Json::from(0));
        settings.insert("multisig".into(), Json::from(0));
        settings.insert("multisig_threshold".into(), Json::from(0));
        settings.insert("encrypted_secret_keys".into(), Json::from(1));
        settings.insert("key_on_device".into(), Json::from(0));
        settings.insert("ask_password".into(), Json::from(1));
        settings.insert("refresh_height".into(), Json::from(0));
        settings.insert("skip_to_height".into(), Json::from(0));
        settings.insert("subaddress_lookahead_major".into(), Json::from(50));
        settings.insert("subaddress_lookahead_minor".into(), Json::from(200));
        settings.insert("auto_refresh".into(), Json::from(1));
        settings.insert("store_tx_info".into(), Json::from(1));
        settings.insert("device_name".into(), Json::from(""));
        settings.insert("device_derivation_path".into(), Json::from(""));
        KeysFile { account, settings }
    }

    /// `nettype`. A keys file that says mainnet must not be opened as testnet:
    /// the addresses would be re-encoded under the wrong prefix.
    pub fn network(&self) -> Network {
        match u64_member(&self.settings, "nettype") {
            Some(1) => Network::Testnet,
            Some(2) => Network::Stagenet,
            Some(3) => Network::Fakechain,
            _ => Network::Mainnet,
        }
    }

    /// `watch_only`. A watch-only wallet can scan and nothing else.
    pub fn is_watch_only(&self) -> bool {
        bool_member(&self.settings, "watch_only").unwrap_or(false)
            || self.account.keys.is_view_only()
    }

    pub fn ask_password(&self) -> AskPassword {
        AskPassword::from_i64(u64_member(&self.settings, "ask_password").unwrap_or(1) as i64)
    }

    /// `refresh_height` — where scanning starts. Zero means genesis, which for
    /// a restored wallet means a very long refresh.
    pub fn refresh_height(&self) -> u64 {
        u64_member(&self.settings, "refresh_height").unwrap_or(0)
    }

    pub fn set_refresh_height(&mut self, h: u64) {
        self.settings.insert("refresh_height".into(), Json::from(h));
    }

    pub fn seed_language(&self) -> Option<&str> {
        self.settings.get("seed_language")?.as_str()
    }

    /// `(major, minor)` lookahead — how many unused subaddresses to precompute.
    pub fn subaddress_lookahead(&self) -> (u32, u32) {
        (
            u64_member(&self.settings, "subaddress_lookahead_major").unwrap_or(50) as u32,
            u64_member(&self.settings, "subaddress_lookahead_minor").unwrap_or(200) as u32,
        )
    }

    /// The cache key, `derive_cache_key(keys_key, HASH_KEY_WALLET_CACHE)`.
    /// Needed to read a C++ cache file's container even though its contents are
    /// a Boost archive we do not parse.
    pub fn cache_key(password: &[u8], kdf_rounds: u64) -> Key {
        let key = chacha::generate_chacha_key(password, kdf_rounds);
        chacha::derive_cache_key(&key, chacha::HASH_KEY_WALLET_CACHE)
    }
}

fn nettype_of(n: Network) -> u64 {
    match n {
        Network::Mainnet => 0,
        Network::Testnet => 1,
        Network::Stagenet => 2,
        Network::Fakechain => 3,
    }
}

/// `keys_file_data`: a POD `iv` field then a length-prefixed string.
fn parse_container(blob: &[u8]) -> Result<(Iv, &[u8])> {
    let mut r = Reader::new(blob);
    let iv: Iv = r.read_array()?;
    let data = r.read_bytes_prefixed(MAX_ACCOUNT_DATA, "keys file account_data")?;
    Ok((iv, data))
}

/// Parse the decrypted JSON, stopping at a NUL the way `c_str()` does.
fn parse_json(plaintext: &[u8]) -> Option<Map<String, Json>> {
    let end = plaintext
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(plaintext.len());
    let text = bytes_to_latin1(&plaintext[..end]);
    match serde_json::from_str(&text) {
        Ok(Json::Object(m)) => Some(m),
        _ => None,
    }
}

/// Every byte becomes the character with that code point.
fn bytes_to_latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// The inverse. Characters above `U+00ff` cannot occur in a document built by
/// [`bytes_to_latin1`], and are truncated rather than expanded if they somehow
/// do — which would be a bug here, not in the file.
fn latin1_to_bytes(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u32 as u8).collect()
}

/// Numbers in this JSON are integers even where they mean booleans, and a few
/// are written as floats. Accept whichever.
fn u64_member(m: &Map<String, Json>, name: &str) -> Option<u64> {
    let v = m.get(name)?;
    v.as_u64().or_else(|| v.as_i64().map(|i| i as u64))
}

fn bool_member(m: &Map<String, Json>, name: &str) -> Option<bool> {
    let v = m.get(name)?;
    // The reference writes 0/1, but tolerate a real JSON boolean.
    v.as_bool().or_else(|| Some(u64_member(m, name)? != 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wow_crypto::types::SecretKey;

    fn account() -> AccountBase {
        let spend = SecretKey(
            wow_crypto::hex::decode(
                "3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109",
            )
            .expect("hex")
            .try_into()
            .expect("32 bytes"),
        );
        AccountBase::from_spend_key(spend, 1_700_000_000).expect("a valid key")
    }

    /// Write a keys file and read it back.
    #[test]
    fn it_round_trips() {
        let kf = KeysFile::new(account(), Network::Mainnet, "English");
        let blob = kf
            .to_blob(b"correct horse", 1, [1; 8], [2; 8])
            .expect("write");

        let back = KeysFile::open(&blob, b"correct horse", 1).expect("read");
        assert_eq!(
            back.account.keys.spend_secret_key,
            kf.account.keys.spend_secret_key
        );
        assert_eq!(
            back.account.keys.view_secret_key,
            kf.account.keys.view_secret_key
        );
        assert_eq!(
            back.account.keys.account_address,
            kf.account.keys.account_address
        );
        assert_eq!(
            back.account.creation_timestamp,
            kf.account.creation_timestamp
        );
        assert_eq!(back.network(), Network::Mainnet);
        assert_eq!(back.seed_language(), Some("English"));
        assert_eq!(back.subaddress_lookahead(), (50, 200));
    }

    /// A wrong password does not open the wallet. It cannot fail at the
    /// ChaCha20 step — a stream cipher decrypts anything — so it has to fail at
    /// the JSON, and if it ever got past that, at `verify`.
    #[test]
    fn a_wrong_password_is_rejected() {
        let kf = KeysFile::new(account(), Network::Mainnet, "English");
        let blob = kf.to_blob(b"right", 1, [1; 8], [2; 8]).expect("write");

        let err = KeysFile::open(&blob, b"wrong", 1).expect_err("must not open");
        assert!(matches!(err, KeysFileError::NotJson), "got {err:?}");
    }

    /// The kdf_rounds count is part of the key. Opening with a different count
    /// is the same as a wrong password.
    #[test]
    fn the_kdf_rounds_must_match() {
        let kf = KeysFile::new(account(), Network::Mainnet, "English");
        let blob = kf.to_blob(b"pw", 1, [1; 8], [2; 8]).expect("write");
        assert!(KeysFile::open(&blob, b"pw", 2).is_err());
    }

    /// `key_data` is binary and the JSON carries it raw, so the decrypted file
    /// is not valid UTF-8. This is the property the Latin-1 transcode exists
    /// for; if it ever becomes false, the transcode can go.
    #[test]
    fn the_decrypted_json_is_not_utf8() {
        let kf = KeysFile::new(account(), Network::Mainnet, "English");
        let blob = kf.to_blob(b"pw", 1, [1; 8], [2; 8]).expect("write");

        let (iv, ct) = parse_container(&blob).expect("container");
        let key = chacha::generate_chacha_key(b"pw", 1);
        let plaintext = chacha::chacha20(ct, &key, &iv);

        assert!(
            String::from_utf8(plaintext.clone()).is_err(),
            "expected raw high bytes in key_data"
        );
        // And the transcode is exact both ways.
        assert_eq!(latin1_to_bytes(&bytes_to_latin1(&plaintext)), plaintext);
    }

    /// Settings this implementation does not model survive a rewrite. Losing
    /// them would silently reset someone's wallet preferences.
    #[test]
    fn unknown_settings_survive_a_rewrite() {
        let mut kf = KeysFile::new(account(), Network::Testnet, "Deutsch");
        kf.settings
            .insert("some_future_option".into(), Json::from(42));
        kf.settings
            .insert("confirm_backlog_threshold".into(), Json::from(7));

        let blob = kf.to_blob(b"pw", 1, [5; 8], [6; 8]).expect("write");
        let back = KeysFile::open(&blob, b"pw", 1).expect("read");

        assert_eq!(u64_member(&back.settings, "some_future_option"), Some(42));
        assert_eq!(
            u64_member(&back.settings, "confirm_backlog_threshold"),
            Some(7)
        );
        assert_eq!(back.network(), Network::Testnet);
    }

    /// A watch-only wallet has no spend key, and still opens.
    #[test]
    fn a_watch_only_wallet_opens() {
        let mut a = account();
        a.forget_spend_key();
        let mut kf = KeysFile::new(a, Network::Mainnet, "English");
        kf.settings.insert("watch_only".into(), Json::from(1));

        let blob = kf.to_blob(b"pw", 1, [1; 8], [2; 8]).expect("write");
        let back = KeysFile::open(&blob, b"pw", 1).expect("read");
        assert!(back.is_watch_only());
        assert!(back.account.keys.is_view_only());
    }

    /// Truncation is an error, not a panic.
    #[test]
    fn a_truncated_file_is_an_error() {
        let kf = KeysFile::new(account(), Network::Mainnet, "English");
        let blob = kf.to_blob(b"pw", 1, [1; 8], [2; 8]).expect("write");
        for n in [0usize, 1, 7, 8, 9, 20, blob.len() - 1] {
            assert!(KeysFile::open(&blob[..n], b"pw", 1).is_err(), "len {n}");
        }
    }

    /// The cache key is derived from the password key, not equal to it.
    #[test]
    fn the_cache_key_is_derived() {
        let keys_key = chacha::generate_chacha_key(b"pw", 1);
        let cache = KeysFile::cache_key(b"pw", 1);
        assert_ne!(cache, keys_key);
        assert_eq!(
            cache,
            chacha::derive_cache_key(&keys_key, chacha::HASH_KEY_WALLET_CACHE)
        );
    }
}
