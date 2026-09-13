//! `cn_fast_hash` and `tree_hash`.
//!
//! `specs/02-crypto.md` §1.

use crate::keccak::keccak256;
use crate::types::Hash256;

/// The all-zero hash. `crypto::null_hash`.
pub const NULL_HASH: Hash256 = [0u8; 32];

/// `cn_fast_hash` — Keccak-256 with the original padding.
///
/// `specs/02-crypto.md` §1.1. **Not** SHA3-256.
#[inline]
pub fn cn_fast_hash(data: &[u8]) -> Hash256 {
    keccak256(data)
}

/// `get_blob_hash(blob)`. An alias kept for readability at call sites that
/// mirror the C.
#[inline]
pub fn get_blob_hash(blob: &[u8]) -> Hash256 {
    cn_fast_hash(blob)
}

/// `tree_hash_cnt(count)` = `1 << floor(log2(count))`, for `count >= 3`.
///
/// `src/crypto/tree-hash.c`.
pub fn tree_hash_cnt(count: usize) -> usize {
    debug_assert!(count >= 3);
    debug_assert!(count <= 0x1000_0000);
    let mut pow = 2usize;
    while pow < count {
        pow <<= 1;
    }
    pow >> 1
}

/// The maximum number of leaves `tree_hash` accepts.
///
/// `CRYPTONOTE_MAX_TX_PER_BLOCK` (`specs/01-constants.md` §4); the C asserts it
/// upstream and `specs/02` §1.4 says to reject larger.
pub const TREE_HASH_MAX_COUNT: usize = 0x1000_0000;

/// The transaction Merkle root. `specs/02-crypto.md` §1.4.
///
/// This is **not** a standard binary Merkle tree: the first `2*cnt - count`
/// leaves are copied verbatim into a zero-initialised buffer of `cnt` slots and
/// only the remainder are paired, before the usual pairwise reduction.
///
/// Returns `None` for an empty input or for more than
/// [`TREE_HASH_MAX_COUNT`] leaves — a validation failure, never a panic
/// (`specs/04-serialization.md` §1.6).
pub fn tree_hash(hashes: &[Hash256]) -> Option<Hash256> {
    match hashes.len() {
        0 => None,
        _ if hashes.len() > TREE_HASH_MAX_COUNT => None,
        1 => Some(hashes[0]),
        2 => Some(hash_pair(&hashes[0], &hashes[1])),
        count => {
            let cnt = tree_hash_cnt(count);
            let mut ints = vec![NULL_HASH; cnt];

            // The first (2*cnt - count) hashes are copied verbatim.
            let k = 2 * cnt - count;
            ints[..k].copy_from_slice(&hashes[..k]);

            // The remainder are paired and hashed.
            let mut i = k;
            for slot in ints.iter_mut().take(cnt).skip(k) {
                *slot = hash_pair(&hashes[i], &hashes[i + 1]);
                i += 2;
            }
            debug_assert_eq!(i, count);

            // Standard pairwise reduction.
            let mut cnt = cnt;
            while cnt > 2 {
                cnt >>= 1;
                for j in 0..cnt {
                    ints[j] = hash_pair(&ints[2 * j], &ints[2 * j + 1]);
                }
            }
            Some(hash_pair(&ints[0], &ints[1]))
        }
    }
}

#[inline]
fn hash_pair(a: &Hash256, b: &Hash256) -> Hash256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    cn_fast_hash(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Hash256 {
        [n; 32]
    }

    #[test]
    fn spec_vectors() {
        assert_eq!(
            crate::hex::encode(&cn_fast_hash(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            crate::hex::encode(&cn_fast_hash(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn tree_hash_cnt_table() {
        assert_eq!(tree_hash_cnt(3), 2);
        assert_eq!(tree_hash_cnt(4), 2);
        assert_eq!(tree_hash_cnt(5), 4);
        assert_eq!(tree_hash_cnt(8), 4);
        assert_eq!(tree_hash_cnt(9), 8);
        assert_eq!(tree_hash_cnt(16), 8);
        assert_eq!(tree_hash_cnt(17), 16);
        // Monero block 202,612 had 514 transactions -> 515 leaves.
        assert_eq!(tree_hash_cnt(515), 512);
    }

    #[test]
    fn degenerate_inputs() {
        assert_eq!(tree_hash(&[]), None);
        assert_eq!(tree_hash(&[h(1)]), Some(h(1)));
        assert_eq!(tree_hash(&[h(1), h(2)]), Some(hash_pair(&h(1), &h(2))));
    }

    /// Three leaves is the smallest case that exercises the copy-then-pair
    /// structure: `cnt = 2`, `k = 2*2 - 3 = 1`, so leaf 0 is copied and leaves
    /// 1 and 2 are paired.
    #[test]
    fn three_leaves_uses_copy_then_pair() {
        let got = tree_hash(&[h(1), h(2), h(3)]).unwrap();
        let expect = hash_pair(&h(1), &hash_pair(&h(2), &h(3)));
        assert_eq!(got, expect);
    }

    /// Four leaves is a perfect tree: `cnt = 2`, `k = 0`, so both slots pair.
    #[test]
    fn four_leaves_is_a_balanced_tree() {
        let got = tree_hash(&[h(1), h(2), h(3), h(4)]).unwrap();
        let expect = hash_pair(&hash_pair(&h(1), &h(2)), &hash_pair(&h(3), &h(4)));
        assert_eq!(got, expect);
    }

    /// Five leaves: `cnt = 4`, `k = 3`. Leaves 0..3 copy through, leaves 3 and
    /// 4 pair into slot 3. A "clean" implementation that padded instead would
    /// give a different root.
    #[test]
    fn five_leaves_matches_the_c_structure() {
        let got = tree_hash(&[h(1), h(2), h(3), h(4), h(5)]).unwrap();
        let s3 = hash_pair(&h(4), &h(5));
        let expect = hash_pair(&hash_pair(&h(1), &h(2)), &hash_pair(&h(3), &s3));
        assert_eq!(got, expect);
    }

    /// `CRYPTONOTE_MAX_TX_PER_BLOCK`. Allocating 2^28 + 1 hashes to test the
    /// rejection is not practical, so the constant itself is pinned.
    const _: () = assert!(TREE_HASH_MAX_COUNT == 0x1000_0000);

    #[test]
    fn all_sizes_up_to_64_are_deterministic_and_distinct() {
        let leaves: Vec<Hash256> = (0u8..64).map(h).collect();
        let mut seen = std::collections::HashSet::new();
        for n in 1..=64usize {
            let root = tree_hash(&leaves[..n]).unwrap();
            assert_eq!(tree_hash(&leaves[..n]).unwrap(), root, "not deterministic");
            assert!(seen.insert(root), "collision at n = {n}");
        }
    }
}
