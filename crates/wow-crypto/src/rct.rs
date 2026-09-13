//! RingCT primitives: the `H` generator and Pedersen commitments.
//!
//! `src/ringct/rctOps.cpp`, `src/ringct/rctTypes.h`.
//!
//! # `H` is a literal, not a derivation
//!
//! `rctTypes.h` comments that `H = toPoint(cn_fast_hash(G))`, and
//! `specs/02` §2 repeats it. **It does not reproduce.** `rctOps.cpp: hash_to_p3`
//! is byte-for-byte `crypto::hash_to_ec`, and applying it to the basepoint
//! encoding gives a different point. The folklore is upstream, not introduced
//! here — see `docs/spec-deltas.md` §4.
//!
//! So [`H`] is the literal from `rctTypes.h:653`. [`tests`] asserts it decodes,
//! lies in the prime-order subgroup, and is not the basepoint; it does **not**
//! assert a derivation that does not hold.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use crate::ops::decode_point;
use crate::types::{EcPoint, EcScalar};

/// The second generator `H`, hard-coded in `rctTypes.h:653`.
///
/// Used for the amount term of every Pedersen commitment and by
/// Bulletproofs(+).
pub const H: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

/// `H` as a curve point.
///
/// Decoding is infallible — the literal is a valid encoding — but the check is
/// done once here rather than asserted at every call site.
pub fn h_point() -> EdwardsPoint {
    decode_point(&H).expect("the H literal from rctTypes.h decodes")
}

/// `d2h(amount)` — an amount as a scalar: eight bytes little-endian, zero above.
///
/// Every `u64` is far below the group order, so this is always canonical and
/// needs no reduction.
pub fn amount_to_scalar(amount: u64) -> Scalar {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&amount.to_le_bytes());
    Scalar::from_bytes_mod_order(b)
}

/// `scalarmultH(a)` — `a * H`.
pub fn scalarmult_h(a: &Scalar) -> EdwardsPoint {
    a * h_point()
}

/// `rct::zeroCommit(amount)` — the commitment to `amount` with an **identity
/// mask**: `G + amount * H`.
///
/// This is the commitment a v2 coinbase output is stored with (`specs/10` §5.2)
/// and the one `get_output_key` synthesises for a pre-RingCT output when the
/// caller asks for a commitment (`specs/10` §4.5).
///
/// The C++ consults a lookup table of precomputed commitments for common
/// amounts first. That is a cache: the table holds exactly what this computes,
/// so the result is identical and the table is not reproduced here.
pub fn zero_commit(amount: u64) -> EcPoint {
    let c = ED25519_BASEPOINT_POINT + scalarmult_h(&amount_to_scalar(amount));
    EcPoint(c.compress().to_bytes())
}

/// `rct::commit(amount, mask)` — `mask * G + amount * H`, the ordinary Pedersen
/// commitment.
pub fn commit(amount: u64, mask: &Scalar) -> EcPoint {
    let c = mask * ED25519_BASEPOINT_POINT + scalarmult_h(&amount_to_scalar(amount));
    EcPoint(c.compress().to_bytes())
}

/// `rct::scalarmultKey(P, INV_EIGHT)` — `P / 8`.
///
/// The inverse of [`scalarmult8`], and what reconstructs a Bulletproof(+)'s
/// `V` from `outPk.mask` when the mask holds the full commitment
/// (`specs/02` §4.4). A proof's `V` is always `C / 8`; what differs by RCT type
/// is whether the mask already is.
pub fn div8(p: &EcPoint) -> Option<EcPoint> {
    let point = decode_point(&p.0)?;
    let inv8 = Scalar::from(8u8).invert();
    Some(EcPoint((inv8 * point).compress().to_bytes()))
}

/// `rct::scalarmult8(P)` — `8 * P`, used to recover a full commitment from the
/// `C/8` form that RCT type 8 serialises (`specs/02` §4.4).
///
/// Returns `None` when `P` does not decode, which the C++ turns into a thrown
/// exception.
pub fn scalarmult8(p: &EcPoint) -> Option<EcPoint> {
    let point = decode_point(&p.0)?;
    Some(EcPoint(crate::ops::mul8(&point).compress().to_bytes()))
}

/// The domain string for the blinding factor. **15 bytes, no trailing NUL.**
const COMMITMENT_MASK: &[u8] = b"commitment_mask";
/// The domain string for the amount pad. **6 bytes, no trailing NUL.**
const AMOUNT: &[u8] = b"amount";

/// `genCommitmentMask(shared_sec)` — the blinding factor of an output the
/// sender never transmits, because the receiver recomputes it.
///
/// `specs/02` §4.5. The domain strings are C string literals in the reference
/// and are hashed **without** their terminating NUL, so the buffers are 47 and
/// 38 bytes.
pub fn commitment_mask(shared_sec: &EcScalar) -> Scalar {
    let mut buf = [0u8; 15 + 32];
    buf[..15].copy_from_slice(COMMITMENT_MASK);
    buf[15..].copy_from_slice(&shared_sec.0);
    crate::ops::hash_to_scalar_dalek(&buf)
}

/// `ecdhHash(shared_sec)` — the eight-byte pad the amount is xored with.
///
/// The hash is 32 bytes and only the first 8 are used.
pub fn amount_pad(shared_sec: &EcScalar) -> [u8; 8] {
    let mut buf = [0u8; 6 + 32];
    buf[..6].copy_from_slice(AMOUNT);
    buf[6..].copy_from_slice(&shared_sec.0);
    crate::cn_fast_hash(&buf)[..8].try_into().expect("8 bytes")
}

/// `ecdhDecode` in its **short** form — RCT types 6 and up (`Bulletproof2`,
/// `CLSAG`, `BulletproofPlus`).
///
/// Only eight bytes of `ecdhInfo[i].amount` are on the wire and the mask is not
/// there at all, so both come back from `shared_sec`.
pub fn ecdh_decode_short(amount_field: &EcScalar, shared_sec: &EcScalar) -> (u64, Scalar) {
    let pad = amount_pad(shared_sec);
    let mut a = [0u8; 8];
    for (o, (b, p)) in a.iter_mut().zip(amount_field.0[..8].iter().zip(pad.iter())) {
        *o = b ^ p;
    }
    (u64::from_le_bytes(a), commitment_mask(shared_sec))
}

/// `ecdhDecode` in its **legacy** form — RCT types 1 to 5.
///
/// Both fields are on the wire as full scalars, and each has a hash subtracted
/// rather than being xored: `s1 = Hs(shared)`, `s2 = Hs(s1)`.
///
/// The decoded amount is the low 8 bytes of the scalar; the reference reads it
/// back as a `u64` the same way (`h2d`).
pub fn ecdh_decode_legacy(
    mask_field: &EcScalar,
    amount_field: &EcScalar,
    shared_sec: &EcScalar,
) -> Option<(u64, Scalar)> {
    let s1 = crate::ops::hash_to_scalar_dalek(&shared_sec.0);
    let s2 = crate::ops::hash_to_scalar_dalek(&s1.to_bytes());

    let mask = Option::<Scalar>::from(Scalar::from_canonical_bytes(mask_field.0))? - s1;
    let amount = Option::<Scalar>::from(Scalar::from_canonical_bytes(amount_field.0))? - s2;

    let b = amount.to_bytes();
    // The reference reads the amount out of the low eight bytes and ignores the
    // rest; a sender that put anything above them made an invalid output, which
    // the commitment check below catches.
    Some((
        u64::from_le_bytes(b[..8].try_into().expect("8 bytes")),
        mask,
    ))
}

/// Does `mask * G + amount * H` equal the commitment the transaction carries?
///
/// This is what turns a decode into proof that the output is really worth what
/// it says. `outPk.mask` is the full commitment for every type except 8, where
/// the wire form is `C/8` and the caller must multiply first.
pub fn commitment_matches(amount: u64, mask: &Scalar, out_pk: &EcPoint) -> bool {
    commit(amount, mask) == *out_pk
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What is actually true about `H`, as opposed to what the comment claims.
    #[test]
    fn h_is_a_valid_prime_order_point() {
        let h = h_point();
        assert!(h.is_torsion_free(), "H must be in the prime-order subgroup");
        assert_ne!(h.compress().to_bytes(), [0u8; 32], "not the identity");
        assert_ne!(h, ED25519_BASEPOINT_POINT, "H is a *second* generator");

        // It re-encodes to the literal, so the literal is canonical.
        assert_eq!(h.compress().to_bytes(), H);
    }

    /// `docs/spec-deltas.md` §4: the documented derivation does not reproduce
    /// the literal. Recorded here so nobody "fixes" the constant by computing
    /// it.
    #[test]
    fn h_is_not_the_documented_derivation() {
        // hash_to_ec of the basepoint encoding -- what the comment says H is.
        let derived = crate::ops::hash_to_ec_point(&ED25519_BASEPOINT_POINT.compress().to_bytes())
            .expect("the basepoint encoding decodes");
        assert_ne!(
            derived.compress().to_bytes(),
            H,
            "if this ever passes, the comment in rctTypes.h became true and \
             docs/spec-deltas.md §4 should be revisited"
        );
    }

    /// `zero_commit(0)` is the basepoint alone: `G + 0*H == G`.
    #[test]
    fn zero_commit_of_zero_is_the_basepoint() {
        assert_eq!(
            zero_commit(0).0,
            ED25519_BASEPOINT_POINT.compress().to_bytes()
        );
    }

    /// The commitment is additively homomorphic in the amount, which is the
    /// property the whole scheme rests on: `zeroCommit(a) + zeroCommit(b)` is
    /// `zeroCommit(a + b)` plus one extra `G`.
    #[test]
    fn zero_commit_is_homomorphic_in_the_amount() {
        let a = 1_234_567u64;
        let b = 7_654_321u64;

        let ca = decode_point(&zero_commit(a).0).unwrap();
        let cb = decode_point(&zero_commit(b).0).unwrap();
        let cab = decode_point(&zero_commit(a + b).0).unwrap();

        // (G + aH) + (G + bH) == (G + (a+b)H) + G
        assert_eq!(ca + cb, cab + ED25519_BASEPOINT_POINT);
    }

    /// `zero_commit` is `commit` with a mask of 1 — the "identity mask" the
    /// spec names.
    #[test]
    fn zero_commit_is_commit_with_an_identity_mask() {
        for amount in [0u64, 1, 12_345, u64::MAX] {
            assert_eq!(zero_commit(amount), commit(amount, &Scalar::ONE));
        }
    }

    /// Distinct amounts give distinct commitments, including at the extremes.
    #[test]
    fn distinct_amounts_commit_distinctly() {
        let mut seen = std::collections::BTreeSet::new();
        for amount in [0u64, 1, 2, 1_000, u64::MAX / 2, u64::MAX] {
            assert!(seen.insert(zero_commit(amount).0), "collision at {amount}");
        }
    }

    /// `amount_to_scalar` is little-endian in the low eight bytes, with nothing
    /// above — a big-endian reading would commit to a different amount.
    #[test]
    fn the_amount_scalar_is_little_endian() {
        let s = amount_to_scalar(1);
        let mut want = [0u8; 32];
        want[0] = 1;
        assert_eq!(s.to_bytes(), want);

        let s = amount_to_scalar(0x0102_0304_0506_0708);
        let b = s.to_bytes();
        assert_eq!(&b[..8], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&b[8..], &[0u8; 24], "nothing above the low eight bytes");

        // u64::MAX is still far below the group order, so no reduction happens.
        let b = amount_to_scalar(u64::MAX).to_bytes();
        assert_eq!(&b[..8], &[0xff; 8]);
        assert_eq!(&b[8..], &[0u8; 24]);
    }

    /// `scalarmult8` clears the cofactor, and round-trips a commitment stored
    /// in the `C/8` form RCT type 8 uses.
    #[test]
    fn scalarmult8_multiplies_by_eight() {
        let p = h_point();
        let got = scalarmult8(&EcPoint(p.compress().to_bytes())).unwrap();
        let want = (p * Scalar::from(8u8)).compress().to_bytes();
        assert_eq!(got.0, want);

        // A point that does not decode is an error, not a panic.
        assert!(scalarmult8(&EcPoint([0xff; 32])).is_none());
    }
}
