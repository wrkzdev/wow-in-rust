//! Difficulty as a 128-bit integer, and the proof-of-work check.
//!
//! `specs/03-pow.md` §4. Difficulty is `boost::multiprecision::uint128_t` in
//! the C, so `u128` here; intermediate products need 256 bits.

use wow_crypto::types::Hash256;

/// A difficulty value.
pub type Difficulty = u128;

/// `check_hash(hash, difficulty)`.
///
/// A hash passes iff, treating the 32 bytes as a **little-endian** 256-bit
/// integer, `hash * difficulty` fits in 256 bits — i.e. the 320-bit product has
/// no high part.
///
/// The C has two implementations (`check_hash_64` for `difficulty <= u64::MAX`
/// and `check_hash_128` above it) which are equivalent to this one statement.
///
/// A difficulty of 0 is a **validation failure**, not "any hash passes"
/// (`specs/03` §4): `next_difficulty*` can return 0 on overflow and the C then
/// errors with "difficulty overhead".
pub fn check_hash(hash: &Hash256, difficulty: Difficulty) -> bool {
    if difficulty == 0 {
        return false;
    }
    mul_256_by_128_fits(hash, difficulty)
}

/// Multiply the little-endian 256-bit `hash` by `difficulty` and report whether
/// the product fits in 256 bits.
///
/// Done with 64-bit limbs and explicit carries rather than a bignum type, so
/// there is no dependency and no ambiguity about the overflow condition.
fn mul_256_by_128_fits(hash: &Hash256, difficulty: u128) -> bool {
    // hash as four little-endian u64 limbs.
    let mut h = [0u64; 4];
    for (i, limb) in h.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(hash[i * 8..i * 8 + 8].try_into().unwrap());
    }
    // difficulty as two u64 limbs.
    let d = [difficulty as u64, (difficulty >> 64) as u64];

    // Schoolbook multiply into six limbs; anything set above limb 3 overflows.
    let mut prod = [0u64; 6];
    for (i, &di) in d.iter().enumerate() {
        if di == 0 {
            continue;
        }
        let mut carry: u128 = 0;
        for (j, &hj) in h.iter().enumerate() {
            let cur = prod[i + j] as u128 + (hj as u128) * (di as u128) + carry;
            prod[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut k = i + h.len();
        while carry != 0 && k < prod.len() {
            let cur = prod[k] as u128 + carry;
            prod[k] = cur as u64;
            carry = cur >> 64;
            k += 1;
        }
        if carry != 0 {
            return false;
        }
    }
    prod[4] == 0 && prod[5] == 0
}

/// `cumulative_difficulty[h] = cumulative_difficulty[h-1] + difficulty[h]`,
/// with `cumulative_difficulty[0] = difficulty[0]` (`specs/07` §6).
///
/// Returns `None` on overflow, which `recalculate_difficulties` treats as
/// fatal.
pub fn accumulate(cumulative: Difficulty, next: Difficulty) -> Option<Difficulty> {
    cumulative.checked_add(next)
}

/// Split a `u128` difficulty into the `(low, high)` pair the storage records
/// and the RPC use (`specs/10` §4.2, `specs/11` §2.1).
pub fn split(d: Difficulty) -> (u64, u64) {
    (d as u64, (d >> 64) as u64)
}

/// Reassemble a `u128` from the `(low, high)` pair.
pub fn join(lo: u64, hi: u64) -> Difficulty {
    (u128::from(hi) << 64) | u128::from(lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(v: u128) -> Hash256 {
        let mut h = [0u8; 32];
        h[..16].copy_from_slice(&v.to_le_bytes());
        h
    }

    #[test]
    fn difficulty_one_accepts_everything() {
        assert!(check_hash(&[0xff; 32], 1));
        assert!(check_hash(&[0x00; 32], 1));
    }

    /// A difficulty of 0 fails the block rather than passing every hash.
    #[test]
    fn difficulty_zero_always_fails() {
        assert!(!check_hash(&[0x00; 32], 0));
        assert!(!check_hash(&[0xff; 32], 0));
    }

    #[test]
    fn the_hash_is_little_endian() {
        // A hash with only the *last* byte set is a huge number; with only the
        // first byte set it is tiny. Reading big-endian would invert this.
        let mut small = [0u8; 32];
        small[0] = 1;
        let mut huge = [0u8; 32];
        huge[31] = 0x80;
        assert!(check_hash(&small, 1_000_000));
        assert!(!check_hash(&huge, 4));
    }

    #[test]
    fn boundary_at_exactly_two_to_the_256() {
        // hash = 2^255, difficulty = 2 -> product is exactly 2^256, which does
        // NOT fit; difficulty 1 does.
        let mut h = [0u8; 32];
        h[31] = 0x80;
        assert!(check_hash(&h, 1));
        assert!(!check_hash(&h, 2));

        // hash = 2^255 - 1, difficulty 2 -> 2^256 - 2, which fits.
        let mut h = [0xffu8; 32];
        h[31] = 0x7f;
        assert!(check_hash(&h, 2));
        assert!(!check_hash(&h, 3));
    }

    #[test]
    fn agrees_with_the_reference_statement() {
        // For every case, `check_hash` must equal `h * d < 2^256`, computed
        // here with arbitrary precision via u128 pieces.
        for d in [1u128, 2, 3, 1000, u64::MAX as u128, (u64::MAX as u128) + 1] {
            for v in [0u128, 1, 2, 1 << 100, u128::MAX] {
                let h = le(v);
                // v * d as a 256-bit value: since v < 2^128 and d < 2^128,
                // the product is < 2^256 iff it fits.
                let expect = v.checked_mul(d).is_some() || {
                    // Compute the wide product to decide.
                    let (lo, hi) = wide_mul(v, d);
                    let _ = lo;
                    hi < u128::MAX // always representable in 256 bits
                };
                assert_eq!(check_hash(&h, d), expect && d != 0, "v={v} d={d}");
            }
        }
    }

    fn wide_mul(a: u128, b: u128) -> (u128, u128) {
        let (a_lo, a_hi) = (a as u64 as u128, a >> 64);
        let (b_lo, b_hi) = (b as u64 as u128, b >> 64);
        let ll = a_lo * b_lo;
        let lh = a_lo * b_hi;
        let hl = a_hi * b_lo;
        let hh = a_hi * b_hi;
        let mid = (ll >> 64) + (lh & 0xffff_ffff_ffff_ffff) + (hl & 0xffff_ffff_ffff_ffff);
        let lo = (ll & 0xffff_ffff_ffff_ffff) | (mid << 64);
        let hi = hh + (lh >> 64) + (hl >> 64) + (mid >> 64);
        (lo, hi)
    }

    /// A 128-bit difficulty must actually use both limbs.
    #[test]
    fn difficulty_above_u64_max_works() {
        let d = (1u128 << 64) + 1;
        let mut h = [0u8; 32];
        h[0] = 1; // hash = 1
        assert!(check_hash(&h, d));
        // hash = 2^192, difficulty = 2^64 -> 2^256, does not fit.
        let mut h = [0u8; 32];
        h[24] = 1;
        assert!(!check_hash(&h, 1u128 << 64));
        assert!(check_hash(&h, (1u128 << 64) - 1));
    }

    #[test]
    fn split_and_join_roundtrip() {
        for d in [
            0u128,
            1,
            u64::MAX as u128,
            (u64::MAX as u128) + 1,
            u128::MAX,
        ] {
            let (lo, hi) = split(d);
            assert_eq!(join(lo, hi), d);
        }
        assert_eq!(
            split(0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00),
            (0x99aa_bbcc_ddee_ff00, 0x1122_3344_5566_7788)
        );
    }

    #[test]
    fn accumulate_reports_overflow() {
        assert_eq!(accumulate(1, 2), Some(3));
        assert_eq!(accumulate(u128::MAX, 1), None);
        assert_eq!(accumulate(u128::MAX, 0), Some(u128::MAX));
    }
}
