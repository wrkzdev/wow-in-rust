//! The rings this wallet has spent its outputs with: `ringdb`.
//!
//! `wallet/ringdb.cpp` and the ring functions in `wallet2.cpp`.
//!
//! # Why a wallet remembers rings
//!
//! A key image can be spent on two chains: this one and a fork of it, or the
//! same chain before and after a reorganisation. Each spend has a ring, and
//! the real output is in both. Two different rings for one key image
//! intersect, and the intersection is the real output; after a few such
//! spends nothing is left of the anonymity a ring is for. So `wallet2` keeps
//! every ring it has chosen, and every ring of its own spends it finds on
//! chain, and spends a key image again with the ring it used before
//! (`get_outs`, 9381-9398 and 9541-9582).
//!
//! # Where it is kept
//!
//! In the wallet's cache, which is sealed under the wallet's key
//! ([`crate::files::cache`]), rather than in the C++'s database of rings
//! shared by every wallet on the machine. The C++ encrypts each entry
//! because that database is shared and unsealed; the cache is neither.
//! Nor is there a blackball list of outputs known to be spent, which lives in
//! the same shared database and which this wallet does not keep.
//!
//! Rings are kept as absolute global indices, ascending, which is what the
//! C++ reads back out of its relative form.

use std::collections::BTreeMap;

use wow_crypto::types::KeyImage;
use wow_types::tx::{TransactionPrefix, TxIn};

/// Key image to ring, as absolute global indices in ascending order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RingDb {
    rings: BTreeMap<KeyImage, Vec<u64>>,
}

/// `relative_output_offsets_to_absolute`: the running sum, unsigned, as the
/// C++ sums it.
pub fn relative_to_absolute(relative: &[u64]) -> Vec<u64> {
    let mut sum = 0u64;
    relative
        .iter()
        .map(|o| {
            sum = sum.wrapping_add(*o);
            sum
        })
        .collect()
}

impl RingDb {
    /// `ringdb::get_ring`.
    pub fn get(&self, key_image: &KeyImage) -> Option<&[u64]> {
        self.rings.get(key_image).map(Vec::as_slice)
    }

    /// `ringdb::get_rings`: a ring for every key image, or `None` if any one
    /// of them has none.
    ///
    /// All or nothing, as the C++ answers, which is why `get_outs` reuses
    /// known rings only when every input of a transaction has one.
    pub fn get_rings(&self, key_images: &[KeyImage]) -> Option<Vec<Vec<u64>>> {
        key_images
            .iter()
            .map(|k| self.rings.get(k).cloned())
            .collect()
    }

    /// `ringdb::set_ring`: keep `outs` as the ring for `key_image`, replacing
    /// any ring it had.
    ///
    /// Relative offsets are summed, and absolute ones sorted, which is the
    /// order `absolute_output_offsets_to_relative` puts them in.
    pub fn set_ring(&mut self, key_image: KeyImage, outs: &[u64], relative: bool) {
        let mut ring = if relative {
            relative_to_absolute(outs)
        } else {
            outs.to_vec()
        };
        ring.sort_unstable();
        self.rings.insert(key_image, ring);
    }

    /// `ringdb::set_rings`, for absolute rings.
    pub fn set_rings<'a>(&mut self, rings: impl IntoIterator<Item = (KeyImage, &'a [u64])>) {
        for (key_image, ring) in rings {
            self.set_ring(key_image, ring, false);
        }
    }

    /// `ringdb::remove_rings`: forget the rings of `key_images`. Returns how
    /// many there were.
    pub fn unset(&mut self, key_images: &[KeyImage]) -> usize {
        key_images
            .iter()
            .filter(|k| self.rings.remove(*k).is_some())
            .count()
    }

    /// `ringdb::add_rings`: keep the ring of every input of `tx`, which is a
    /// transaction spending this wallet's outputs found in a block
    /// (`process_outgoing`). An input of one member has no ring to keep.
    pub fn add_rings(&mut self, tx: &TransactionPrefix) {
        for input in &tx.vin {
            if let TxIn::ToKey {
                key_offsets,
                k_image,
                ..
            } = input
            {
                if key_offsets.len() > 1 {
                    self.set_ring(*k_image, key_offsets, true);
                }
            }
        }
    }

    /// Every ring kept, by key image.
    pub fn iter(&self) -> impl Iterator<Item = (&KeyImage, &Vec<u64>)> {
        self.rings.iter()
    }

    pub fn len(&self) -> usize {
        self.rings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(n: u8) -> KeyImage {
        KeyImage([n; 32])
    }

    /// A ring given either way comes back absolute and ascending.
    #[test]
    fn a_ring_is_kept_absolute() {
        let mut db = RingDb::default();
        db.set_ring(image(1), &[10, 5, 1, 20], true);
        assert_eq!(db.get(&image(1)), Some(&[10u64, 15, 16, 36][..]));

        db.set_ring(image(2), &[36, 10, 16, 15], false);
        assert_eq!(db.get(&image(2)), Some(&[10u64, 15, 16, 36][..]));

        // A new ring for the same key image replaces the old.
        db.set_ring(image(2), &[1, 2], false);
        assert_eq!(db.get(&image(2)), Some(&[1u64, 2][..]));
        assert_eq!(db.len(), 2);
    }

    /// Rings for several key images come back only if every one has one.
    #[test]
    fn rings_are_all_or_nothing() {
        let mut db = RingDb::default();
        db.set_rings([(image(1), &[1u64, 2][..]), (image(2), &[3u64, 4][..])]);
        assert_eq!(
            db.get_rings(&[image(2), image(1)]),
            Some(vec![vec![3, 4], vec![1, 2]])
        );
        assert_eq!(db.get_rings(&[image(1), image(3)]), None);

        assert_eq!(db.unset(&[image(1), image(3)]), 1);
        assert_eq!(db.get(&image(1)), None);
        assert!(db.get(&image(2)).is_some());
    }

    /// A transaction's rings are kept from its inputs, and an input of a
    /// single member is not a ring.
    #[test]
    fn a_transactions_rings_are_kept_from_its_inputs() {
        let tx = TransactionPrefix {
            version: 2,
            unlock_time: 0,
            vin: vec![
                TxIn::ToKey {
                    amount: 0,
                    key_offsets: vec![100, 3, 7],
                    k_image: image(1),
                },
                TxIn::ToKey {
                    amount: 0,
                    key_offsets: vec![42],
                    k_image: image(2),
                },
            ],
            vout: Vec::new(),
            extra: Vec::new(),
        };
        let mut db = RingDb::default();
        db.add_rings(&tx);
        assert_eq!(db.get(&image(1)), Some(&[100u64, 103, 110][..]));
        assert_eq!(db.get(&image(2)), None);
    }
}
