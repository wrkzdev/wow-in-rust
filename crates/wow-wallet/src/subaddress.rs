//! The subaddress table: the map scanning looks every output up in.
//!
//! `specs/12` §1.3. `wallet2::m_subaddresses`.
//!
//! Scanning asks one question per output — "is this spend key one of mine?" —
//! several million times over a full refresh, so the answer has to be a hash
//! lookup rather than a derivation. The table is precomputed up to a
//! *lookahead* and extended whenever a hit lands near its edge.
//!
//! Index `(0, 0)` is the main address and is **not** derived: the C returns the
//! account's own keys for it unchanged, and deriving would give a different
//! address.

use std::collections::HashMap;

use wow_crypto::types::{AccountPublicAddress, PublicKey, SecretKey, SubaddressIndex};

/// `subaddress_lookahead_major` — how many accounts to precompute.
pub const DEFAULT_LOOKAHEAD_MAJOR: u32 = 50;
/// `subaddress_lookahead_minor` — how many addresses per account.
pub const DEFAULT_LOOKAHEAD_MINOR: u32 = 200;

/// Spend public key → `(major, minor)`.
#[derive(Clone, Debug, Default)]
pub struct SubaddressTable {
    by_spend_key: HashMap<PublicKey, SubaddressIndex>,
    /// How far each account has been expanded, so `extend` is incremental.
    filled: Vec<u32>,
}

impl SubaddressTable {
    /// Build the table for `(0..major, 0..minor)`.
    pub fn new(
        address: &AccountPublicAddress,
        view_secret: &SecretKey,
        major: u32,
        minor: u32,
    ) -> SubaddressTable {
        let mut t = SubaddressTable::default();
        t.extend(address, view_secret, major, minor);
        t
    }

    /// Grow the table so every account below `major` is filled to `minor`.
    ///
    /// Already-filled entries are skipped, so calling this repeatedly as
    /// scanning approaches the edge costs only the new rows.
    pub fn extend(
        &mut self,
        address: &AccountPublicAddress,
        view_secret: &SecretKey,
        major: u32,
        minor: u32,
    ) {
        if self.filled.len() < major as usize {
            self.filled.resize(major as usize, 0);
        }
        for m in 0..major {
            let from = self.filled[m as usize];
            if from >= minor {
                continue;
            }
            for n in from..minor {
                let index = SubaddressIndex::new(m, n);
                if let Some(sub) = wow_crypto::get_subaddress(address, view_secret, index) {
                    self.by_spend_key.insert(sub.spend_public_key, index);
                }
            }
            self.filled[m as usize] = minor;
        }
    }

    /// The lookup scanning does per output.
    pub fn get(&self, spend_key: &PublicKey) -> Option<SubaddressIndex> {
        self.by_spend_key.get(spend_key).copied()
    }

    pub fn len(&self) -> usize {
        self.by_spend_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_spend_key.is_empty()
    }

    /// How far account `major` has been filled, which is what decides whether a
    /// hit near the edge should trigger an [`extend`](Self::extend).
    pub fn filled_minor(&self, major: u32) -> u32 {
        self.filled.get(major as usize).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (AccountPublicAddress, SecretKey) {
        let spend = SecretKey(
            wow_crypto::hex::decode(
                "3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109",
            )
            .expect("hex")
            .try_into()
            .expect("32 bytes"),
        );
        let view = wow_crypto::view_key_from_spend_key(&spend);
        let address = AccountPublicAddress {
            spend_public_key: wow_crypto::secret_key_to_public_key(&spend).expect("valid"),
            view_public_key: wow_crypto::secret_key_to_public_key(&view).expect("valid"),
        };
        (address, view)
    }

    /// The main address is in the table under the account's own spend key, not
    /// under a derived one.
    #[test]
    fn the_main_address_is_not_derived() {
        let (address, view) = keys();
        let t = SubaddressTable::new(&address, &view, 1, 1);
        assert_eq!(
            t.get(&address.spend_public_key),
            Some(SubaddressIndex::MAIN)
        );
        assert_eq!(t.len(), 1);
    }

    /// Every precomputed index is present and distinct.
    #[test]
    fn it_covers_the_lookahead() {
        let (address, view) = keys();
        let t = SubaddressTable::new(&address, &view, 2, 3);
        assert_eq!(t.len(), 6, "no two subaddresses collide");

        for m in 0..2 {
            for n in 0..3 {
                let i = SubaddressIndex::new(m, n);
                let sub = wow_crypto::get_subaddress(&address, &view, i).expect("derivable");
                assert_eq!(t.get(&sub.spend_public_key), Some(i), "{i:?}");
            }
        }
        // Just past the edge is absent.
        let past = wow_crypto::get_subaddress(&address, &view, SubaddressIndex::new(0, 3))
            .expect("derivable");
        assert_eq!(t.get(&past.spend_public_key), None);
    }

    /// Extending is incremental and idempotent: the same table results whether
    /// it was built in one step or three.
    #[test]
    fn extending_is_incremental() {
        let (address, view) = keys();

        let one = SubaddressTable::new(&address, &view, 3, 4);

        let mut many = SubaddressTable::new(&address, &view, 1, 2);
        many.extend(&address, &view, 3, 2);
        many.extend(&address, &view, 3, 4);
        many.extend(&address, &view, 3, 4); // a no-op

        assert_eq!(one.len(), many.len());
        assert_eq!(many.filled_minor(2), 4);
        for m in 0..3 {
            for n in 0..4 {
                let i = SubaddressIndex::new(m, n);
                let sub = wow_crypto::get_subaddress(&address, &view, i).expect("derivable");
                assert_eq!(
                    many.get(&sub.spend_public_key),
                    one.get(&sub.spend_public_key)
                );
                assert_eq!(many.get(&sub.spend_public_key), Some(i));
            }
        }
    }

    /// Shrinking is not a thing: a smaller extend leaves the table alone.
    #[test]
    fn a_smaller_extend_does_not_shrink() {
        let (address, view) = keys();
        let mut t = SubaddressTable::new(&address, &view, 2, 5);
        let before = t.len();
        t.extend(&address, &view, 1, 1);
        assert_eq!(t.len(), before);
        assert_eq!(t.filled_minor(0), 5);
    }
}
