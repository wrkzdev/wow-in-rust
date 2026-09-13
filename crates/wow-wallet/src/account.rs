//! `account_base` — the key material, and the `key_data` blob inside a keys
//! file.
//!
//! `src/cryptonote_basic/account.h`, `account.cpp`.
//!
//! # `key_data` is epee portable storage
//!
//! `specs/12` §2.1.1 describes `key_data` as "the binary-archive serialization
//! of `account_base`" with a flat layout. It is not: the writer is
//! `epee::serialization::store_t_to_binary`, so `key_data` is an **epee
//! portable-storage** blob driven by the `BEGIN_KV_SERIALIZE_MAP` in
//! `account.h`, with named members and a nested section. The spec also omits
//! `m_encryption_iv`, which is a member and is what the secret keys are
//! encrypted under. See `docs/spec-deltas.md`.
//!
//! # The secret keys are encrypted under a second key
//!
//! When `encrypted_secret_keys` is set — it always is, for anything the current
//! writer produces — the spend and view keys inside `key_data` are xored with a
//! ChaCha20 key stream. That stream is **not** keyed by the password key
//! directly: `account.cpp`'s `derive_key` runs CryptoNight again over the key
//! plus `'k'`. So opening a wallet costs two CryptoNight evaluations, and a
//! reader that uses the password key directly gets plausible-looking garbage
//! rather than an error.

use wow_crypto::types::{AccountPublicAddress, PublicKey, SecretKey};
use wow_serialize::epee::{self, Section, Value};

use crate::chacha::{self, Iv, Key};

/// `crypto::secret_key` is 32 bytes, and the key stream is laid out in
/// multiples of it.
const SECRET_KEY_LEN: usize = 32;

/// The key material a wallet holds. `cryptonote::account_keys`.
///
/// The reference's `m_device_derivation_path` is **not** here: it lives in the
/// keys file's JSON, not in `account_keys`, despite `specs/12` §1.1 listing it
/// on this struct.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountKeys {
    pub account_address: AccountPublicAddress,
    /// Zero for a view-only wallet.
    pub spend_secret_key: SecretKey,
    pub view_secret_key: SecretKey,
    pub multisig_keys: Vec<SecretKey>,
    /// `m_encryption_iv`. Randomised on every encrypt, stored in `key_data`,
    /// and defaulting to all-zero when the member is absent.
    pub encryption_iv: Iv,
}

/// `cryptonote::account_base`: the keys plus when they were made.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountBase {
    pub keys: AccountKeys,
    pub creation_timestamp: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("key_data is not valid epee portable storage: {0}")]
    Epee(#[from] wow_serialize::Error),
    #[error("key_data is missing `{0}`")]
    Missing(&'static str),
    #[error("key_data field `{field}` is {got} bytes, expected {want}")]
    BadLength {
        field: &'static str,
        got: usize,
        want: usize,
    },
    #[error("the {which} key does not match its public key")]
    KeyMismatch { which: &'static str },
}

type Result<T> = std::result::Result<T, AccountError>;

impl AccountKeys {
    /// A view-only wallet has no spend key, which the reference represents as
    /// all zeros rather than as an absent member.
    pub fn is_view_only(&self) -> bool {
        self.spend_secret_key == SecretKey::ZERO
    }

    /// `is_deterministic()`: the view key is `sc_reduce32(keccak(spend))`, so
    /// the whole wallet follows from the spend key and a 25-word seed can
    /// represent it (`specs/12` §1.2).
    pub fn is_deterministic(&self) -> bool {
        !self.is_view_only()
            && self.view_secret_key == wow_crypto::view_key_from_spend_key(&self.spend_secret_key)
    }

    /// Check each secret key against the public key stored beside it.
    ///
    /// This is `hwdev.verify_keys`, and it is what turns a wrong password from
    /// "opened a wallet full of noise" into an error. The spend key is skipped
    /// for a view-only wallet, exactly as the reference skips it.
    pub fn verify(&self) -> Result<()> {
        let view = wow_crypto::secret_key_to_public_key(&self.view_secret_key);
        if view != Some(self.account_address.view_public_key) {
            return Err(AccountError::KeyMismatch { which: "view" });
        }
        if !self.is_view_only() {
            let spend = wow_crypto::secret_key_to_public_key(&self.spend_secret_key);
            if spend != Some(self.account_address.spend_public_key) {
                return Err(AccountError::KeyMismatch { which: "spend" });
            }
        }
        Ok(())
    }

    /// `account_keys::xor_with_key_stream`. Its own inverse, which is why the
    /// reference implements `decrypt` as a second call to `encrypt`.
    ///
    /// The stream covers the spend key, the view key, and every multisig key,
    /// in that order.
    fn xor_with_key_stream(&mut self, key: &Key) {
        let n = SECRET_KEY_LEN * (2 + self.multisig_keys.len());
        let stream = chacha::key_stream(key, &self.encryption_iv, n);

        let mut at = 0usize;
        let mut apply = |k: &mut SecretKey| {
            for (b, s) in k.0.iter_mut().zip(&stream[at..at + SECRET_KEY_LEN]) {
                *b ^= s;
            }
            at += SECRET_KEY_LEN;
        };
        apply(&mut self.spend_secret_key);
        apply(&mut self.view_secret_key);
        for k in self.multisig_keys.iter_mut() {
            apply(k);
        }
    }

    /// `account_keys::encrypt`. Picks a fresh IV, then xors.
    pub fn encrypt(&mut self, key: &Key, iv: Iv) {
        self.encryption_iv = iv;
        self.xor_with_key_stream(key);
    }

    /// `account_keys::decrypt`. The same xor under the stored IV.
    pub fn decrypt(&mut self, key: &Key) {
        self.xor_with_key_stream(key);
    }

    /// `account_keys::encrypt_viewkey`, which is also `decrypt_viewkey`.
    ///
    /// It takes the **second** 32 bytes of the stream — the slot the view key
    /// occupies — so it leaves the spend key alone. This is how a wallet with
    /// `ask_password == AskPasswordToDecrypt` keeps scanning without the
    /// password while the spend key stays encrypted.
    pub fn encrypt_viewkey(&mut self, key: &Key) {
        let stream = chacha::key_stream(key, &self.encryption_iv, SECRET_KEY_LEN * 2);
        for (b, s) in self
            .view_secret_key
            .0
            .iter_mut()
            .zip(&stream[SECRET_KEY_LEN..])
        {
            *b ^= s;
        }
    }
}

impl AccountBase {
    /// Build a wallet from a spend key, deriving the view key from it — the
    /// deterministic case, which is the only one with a seed phrase.
    pub fn from_spend_key(spend_secret_key: SecretKey, creation_timestamp: u64) -> Option<Self> {
        let view_secret_key = wow_crypto::view_key_from_spend_key(&spend_secret_key);
        Self::from_keys(spend_secret_key, view_secret_key, creation_timestamp)
    }

    /// Build a wallet from both secret keys. Non-deterministic unless they
    /// happen to satisfy the relation.
    pub fn from_keys(
        spend_secret_key: SecretKey,
        view_secret_key: SecretKey,
        creation_timestamp: u64,
    ) -> Option<Self> {
        let spend_public_key = wow_crypto::secret_key_to_public_key(&spend_secret_key)?;
        let view_public_key = wow_crypto::secret_key_to_public_key(&view_secret_key)?;
        Some(AccountBase {
            keys: AccountKeys {
                account_address: AccountPublicAddress {
                    spend_public_key,
                    view_public_key,
                },
                spend_secret_key,
                view_secret_key,
                multisig_keys: Vec::new(),
                encryption_iv: [0u8; chacha::IV_SIZE],
            },
            creation_timestamp,
        })
    }

    /// Build a view-only wallet: the address plus the view key, no spend key.
    pub fn view_only(
        account_address: AccountPublicAddress,
        view_secret_key: SecretKey,
        creation_timestamp: u64,
    ) -> Self {
        AccountBase {
            keys: AccountKeys {
                account_address,
                spend_secret_key: SecretKey::ZERO,
                view_secret_key,
                multisig_keys: Vec::new(),
                encryption_iv: [0u8; chacha::IV_SIZE],
            },
            creation_timestamp,
        }
    }

    /// `account_base::forget_spend_key`, which is what turns a wallet into a
    /// watch-only one on the way to a keys file.
    pub fn forget_spend_key(&mut self) {
        self.keys.spend_secret_key = SecretKey::ZERO;
    }

    /// Serialize to the `key_data` blob: epee portable storage of the
    /// `BEGIN_KV_SERIALIZE_MAP` in `account.h`.
    pub fn to_key_data(&self) -> Result<Vec<u8>> {
        let mut address = Section::new();
        address.insert(
            "m_spend_public_key".into(),
            Value::String(self.keys.account_address.spend_public_key.0.to_vec()),
        );
        address.insert(
            "m_view_public_key".into(),
            Value::String(self.keys.account_address.view_public_key.0.to_vec()),
        );

        let mut keys = Section::new();
        keys.insert("m_account_address".into(), Value::Object(address));
        keys.insert(
            "m_spend_secret_key".into(),
            Value::String(self.keys.spend_secret_key.0.to_vec()),
        );
        keys.insert(
            "m_view_secret_key".into(),
            Value::String(self.keys.view_secret_key.0.to_vec()),
        );
        // `KV_SERIALIZE_CONTAINER_POD_AS_BLOB`: every element concatenated into
        // one string, not an array.
        keys.insert(
            "m_multisig_keys".into(),
            Value::String(
                self.keys
                    .multisig_keys
                    .iter()
                    .flat_map(|k| k.0)
                    .collect::<Vec<u8>>(),
            ),
        );
        keys.insert(
            "m_encryption_iv".into(),
            Value::String(self.keys.encryption_iv.to_vec()),
        );

        let mut root = Section::new();
        root.insert("m_keys".into(), Value::Object(keys));
        root.insert(
            "m_creation_timestamp".into(),
            Value::U64(self.creation_timestamp),
        );
        Ok(epee::to_bytes(&root)?)
    }

    /// Parse a `key_data` blob.
    ///
    /// Every member except the address and the two secret keys is optional, as
    /// the reference's `KV_SERIALIZE_*_OPT` forms are — an older wallet has no
    /// `m_encryption_iv` and means all-zero by it.
    pub fn from_key_data(blob: &[u8]) -> Result<Self> {
        let root = epee::from_bytes(blob)?;
        let keys = root
            .get("m_keys")
            .and_then(Value::as_object)
            .ok_or(AccountError::Missing("m_keys"))?;
        let address = keys
            .get("m_account_address")
            .and_then(Value::as_object)
            .ok_or(AccountError::Missing("m_account_address"))?;

        let spend_public_key = PublicKey(fixed(address, "m_spend_public_key")?);
        let view_public_key = PublicKey(fixed(address, "m_view_public_key")?);
        let spend_secret_key = SecretKey(fixed(keys, "m_spend_secret_key")?);
        let view_secret_key = SecretKey(fixed(keys, "m_view_secret_key")?);

        let multisig_keys = match keys.get("m_multisig_keys").and_then(Value::as_bytes) {
            None => Vec::new(),
            Some(b) if b.len() % SECRET_KEY_LEN == 0 => b
                .chunks_exact(SECRET_KEY_LEN)
                .map(|c| SecretKey(c.try_into().expect("32 bytes")))
                .collect(),
            Some(b) => {
                return Err(AccountError::BadLength {
                    field: "m_multisig_keys",
                    got: b.len(),
                    want: SECRET_KEY_LEN,
                })
            }
        };

        let encryption_iv = match keys.get("m_encryption_iv").and_then(Value::as_bytes) {
            None => [0u8; chacha::IV_SIZE],
            Some(b) => b.try_into().map_err(|_| AccountError::BadLength {
                field: "m_encryption_iv",
                got: b.len(),
                want: chacha::IV_SIZE,
            })?,
        };

        Ok(AccountBase {
            keys: AccountKeys {
                account_address: AccountPublicAddress {
                    spend_public_key,
                    view_public_key,
                },
                spend_secret_key,
                view_secret_key,
                multisig_keys,
                encryption_iv,
            },
            creation_timestamp: root
                .get("m_creation_timestamp")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        })
    }
}

fn fixed<const N: usize>(s: &Section, field: &'static str) -> Result<[u8; N]> {
    let b = s
        .get(field)
        .and_then(Value::as_bytes)
        .ok_or(AccountError::Missing(field))?;
    b.try_into().map_err(|_| AccountError::BadLength {
        field,
        got: b.len(),
        want: N,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A spend key with a known public key, from the reference vectors' shape.
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

    /// A round trip through the epee blob preserves everything, including the
    /// IV and the timestamp.
    #[test]
    fn key_data_round_trips() {
        let mut a = account();
        a.keys.encryption_iv = [1, 2, 3, 4, 5, 6, 7, 8];
        let blob = a.to_key_data().expect("serialize");
        assert_eq!(AccountBase::from_key_data(&blob).expect("parse"), a);
    }

    /// An older keys file has no `m_encryption_iv`, and means all-zero by it.
    #[test]
    fn a_missing_iv_defaults_to_zero() {
        let a = account();
        let blob = a.to_key_data().expect("serialize");

        let mut root = epee::from_bytes(&blob).expect("parse");
        let keys = match root.get_mut("m_keys") {
            Some(Value::Object(s)) => s,
            _ => panic!("m_keys is a section"),
        };
        keys.remove("m_encryption_iv");
        keys.remove("m_multisig_keys");
        let trimmed = epee::to_bytes(&root).expect("serialize");

        let back = AccountBase::from_key_data(&trimmed).expect("parse");
        assert_eq!(back.keys.encryption_iv, [0u8; 8]);
        assert!(back.keys.multisig_keys.is_empty());
    }

    /// Encryption is its own inverse, and it moves both secret keys but
    /// neither public one.
    #[test]
    fn encrypt_is_its_own_inverse() {
        let a = account();
        let key = crate::chacha::generate_chacha_key(b"a password", 1);

        let mut enc = a.clone();
        enc.keys.encrypt(&key, [9, 9, 9, 9, 9, 9, 9, 9]);
        assert_ne!(enc.keys.spend_secret_key, a.keys.spend_secret_key);
        assert_ne!(enc.keys.view_secret_key, a.keys.view_secret_key);
        assert_eq!(enc.keys.account_address, a.keys.account_address);

        enc.keys.decrypt(&key);
        assert_eq!(enc.keys.spend_secret_key, a.keys.spend_secret_key);
        assert_eq!(enc.keys.view_secret_key, a.keys.view_secret_key);
    }

    /// `encrypt_viewkey` uses the stream's second slot, so it agrees with the
    /// view-key half of a full `encrypt` and leaves the spend key untouched.
    #[test]
    fn the_viewkey_slot_is_the_second_one() {
        let a = account();
        let key = crate::chacha::generate_chacha_key(b"a password", 1);
        let iv = [4u8, 4, 4, 4, 4, 4, 4, 4];

        let mut full = a.clone();
        full.keys.encrypt(&key, iv);

        let mut view = a.clone();
        view.keys.encryption_iv = iv;
        view.keys.encrypt_viewkey(&key);

        assert_eq!(view.keys.view_secret_key, full.keys.view_secret_key);
        assert_eq!(view.keys.spend_secret_key, a.keys.spend_secret_key);
    }

    /// A wallet built from a spend key alone is deterministic; one built from
    /// two unrelated keys is not, and so has no seed phrase.
    #[test]
    fn determinism_is_the_view_key_relation() {
        let a = account();
        assert!(a.keys.is_deterministic());
        assert!(!a.keys.is_view_only());

        let other = SecretKey(
            wow_crypto::hex::decode(
                "c8e8c6ccd6a7dc99a80e3e69dd9d4e6f8e1e50cbf2ca7ad7cfd9f0a8b0f8ba0d",
            )
            .expect("hex")
            .try_into()
            .expect("32 bytes"),
        );
        let b = AccountBase::from_keys(a.keys.spend_secret_key, other, 0).expect("valid keys");
        assert!(!b.keys.is_deterministic());
    }

    /// A view-only wallet verifies without a spend key, and the full wallet
    /// verifies with one. A wrong password shows up here rather than as silent
    /// nonsense.
    #[test]
    fn verify_catches_a_wrong_key() {
        let a = account();
        a.keys.verify().expect("the real keys verify");

        let mut v = a.clone();
        v.forget_spend_key();
        assert!(v.keys.is_view_only());
        v.keys.verify().expect("a view-only wallet verifies");

        // Still encrypted: what a reader sees if it uses the wrong password,
        // or forgets that `encrypted_secret_keys` was set.
        let mut enc = a.clone();
        enc.keys
            .encrypt(&crate::chacha::generate_chacha_key(b"pw", 1), [1; 8]);
        assert!(enc.keys.verify().is_err());
    }
}

#[cfg(test)]
mod golden {
    use super::*;

    /// The `key_data` byte layout, pinned.
    ///
    /// Member names, types and nesting are what the C++ reader looks for. A
    /// change to any of them produces a file that round-trips here and does not
    /// open there, which no other test in this module would catch — so this one
    /// asserts the bytes.
    ///
    /// Decoded, against `specs/04` §2: the nine-byte epee header, then two
    /// root entries (`m_creation_timestamp` as UINT64 and `m_keys` as a
    /// section), and inside `m_keys` five entries with `m_account_address`
    /// itself a section of two STRINGs. Entry order is lexicographic because
    /// that is how this workspace's epee writer orders sections; the reference
    /// reader looks entries up by name.
    #[test]
    fn the_key_data_layout() {
        let a = AccountBase {
            keys: AccountKeys {
                account_address: AccountPublicAddress {
                    spend_public_key: PublicKey([0x33u8; 32]),
                    view_public_key: PublicKey([0x44u8; 32]),
                },
                spend_secret_key: SecretKey([0x11u8; 32]),
                view_secret_key: SecretKey([0x22u8; 32]),
                multisig_keys: Vec::new(),
                encryption_iv: [0x55u8; 8],
            },
            creation_timestamp: 0x0102_0304_0506_0708,
        };
        let blob = a.to_key_data().expect("serialize");
        assert_eq!(
            wow_crypto::hex::encode(&blob),
            concat!(
                // Signature 0x01011101, 0x01020101, version 1.
                "011101010101020101",
                "08", // two root entries
                "14",
                "6d5f6372656174696f6e5f74696d657374616d70", // "m_creation_timestamp"
                "05",
                "0807060504030201", // UINT64, little-endian
                "06",
                "6d5f6b657973", // "m_keys"
                "0c",
                "14", // a section of five entries
                "11",
                "6d5f6163636f756e745f61646472657373", // "m_account_address"
                "0c",
                "08", // a section of two entries
                "12",
                "6d5f7370656e645f7075626c69635f6b6579", // "m_spend_public_key"
                "0a",
                "80", // STRING, 32 bytes
                "3333333333333333333333333333333333333333333333333333333333333333",
                "11",
                "6d5f766965775f7075626c69635f6b6579", // "m_view_public_key"
                "0a",
                "80",
                "4444444444444444444444444444444444444444444444444444444444444444",
                "0f",
                "6d5f656e6372797074696f6e5f6976", // "m_encryption_iv"
                "0a",
                "20", // STRING, 8 bytes
                "5555555555555555",
                "0f",
                "6d5f6d756c74697369675f6b657973", // "m_multisig_keys"
                "0a",
                "00", // STRING, empty — written even when there are none
                "12",
                "6d5f7370656e645f7365637265745f6b6579", // "m_spend_secret_key"
                "0a",
                "80",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "11",
                "6d5f766965775f7365637265745f6b6579", // "m_view_secret_key"
                "0a",
                "80",
                "2222222222222222222222222222222222222222222222222222222222222222",
            )
        );
    }
}
