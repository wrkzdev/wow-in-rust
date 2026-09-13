//! ed25519 group and scalar operations with Monero's conventions.
//!
//! `specs/02-crypto.md` §2. The points where a standard ed25519 library will
//! *not* match are called out inline; the most important is that point decoding
//! must be as permissive as `ge_frombytes_vartime` — small-order and
//! non-canonical `y` encodings are accepted.

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use crate::field::{consts, divpowm1, Fe};
use crate::hash::cn_fast_hash;
use crate::types::{EcPoint, EcScalar, KeyImage, PublicKey, SecretKey};

/// `p - 1`, little-endian: the largest canonical `y`.
const P_MINUS_1: [u8; 32] = [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// `ge_frombytes_vartime`: Monero's point decoding.
///
/// Accepts **small-order and torsioned points**, which a strict ed25519
/// library rejects and which appear on chain — so no `is_torsion_free()` check
/// belongs here.
///
/// It is *not* permissive about everything, though. Two rejections that
/// `curve25519-dalek`'s `decompress` does not make are consensus:
///
/// 1. **A non-canonical `y`.** The C opens with a limb-wise comparison
///    (`h9 == 33554428 && ... && h0 >= 4294967277`) that is exactly
///    `y >= p` after bit 255 is masked off, and returns `-1`.
/// 2. **`x == 0` with the sign bit set.** "If x = 0, the sign must be
///    positive". Since the curve forces `x == 0` exactly when `y^2 == 1`, this
///    is the check `y in {1, p-1}` below.
///
/// Note `specs/02-crypto.md` §2 item 1 says decoding "does not reject
/// non-canonical `y` encodings"; that describes the `fe_frombytes` used by
/// `ge_fromfe_frombytes_vartime`, not this function. 26 of the 372 `check_key`
/// reference vectors fail without these two rejections.
#[inline]
pub fn decode_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let mut y = *bytes;
    let negative = y[31] & 0x80 != 0;
    y[31] &= 0x7f;

    // (1) y must be canonical: y < p. Compare little-endian, high byte first.
    let mut canonical = false;
    for i in (0..32).rev() {
        if y[i] != P_MINUS_1[i] {
            canonical = y[i] < P_MINUS_1[i];
            break;
        }
    }
    // The loop leaves `canonical` false when y == p - 1, which *is* canonical.
    if !canonical && y != P_MINUS_1 {
        return None;
    }

    // (2) x == 0 (i.e. y == 1 or y == p - 1) forbids a set sign bit.
    if negative && (y == ONE_LE || y == P_MINUS_1) {
        return None;
    }

    CompressedEdwardsY(*bytes).decompress()
}

/// `1`, little-endian.
const ONE_LE: [u8; 32] = {
    let mut a = [0u8; 32];
    a[0] = 1;
    a
};

/// `ge_p3_tobytes` / `ge_tobytes`: compress a point.
#[inline]
pub fn encode_point(p: &EdwardsPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

/// `sc_check`: is the scalar canonical (`< l`)?
#[inline]
pub fn sc_check(bytes: &[u8; 32]) -> bool {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes)).is_some()
}

/// `sc_reduce32`: reduce a 32-byte little-endian value mod `l`.
#[inline]
pub fn sc_reduce32(bytes: &[u8; 32]) -> [u8; 32] {
    Scalar::from_bytes_mod_order(*bytes).to_bytes()
}

/// `sc_isnonzero`.
#[inline]
pub fn sc_is_nonzero(bytes: &[u8; 32]) -> bool {
    *bytes != [0u8; 32]
}

/// Decode a scalar, requiring canonicality as `sc_check` does.
#[inline]
pub fn decode_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(*bytes).into()
}

/// Decode a scalar the way `ge_scalarmult` treats its argument: the raw bits.
///
/// The C asserts `sc_check` at the call sites, so in practice the value is
/// canonical; this is the fallback for inputs that reach us unvalidated.
#[inline]
pub fn decode_scalar_unreduced(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

/// `sc_add`.
#[inline]
pub fn sc_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    (decode_scalar_unreduced(a) + decode_scalar_unreduced(b)).to_bytes()
}

/// `sc_sub`.
#[inline]
pub fn sc_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    (decode_scalar_unreduced(a) - decode_scalar_unreduced(b)).to_bytes()
}

/// `sc_mulsub(r, a, b, c)` = `c - a*b  (mod l)`.
#[inline]
pub fn sc_mulsub(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    (decode_scalar_unreduced(c) - decode_scalar_unreduced(a) * decode_scalar_unreduced(b))
        .to_bytes()
}

/// `ge_scalarmult_base`: `s * G`.
#[inline]
pub fn scalarmult_base(s: &Scalar) -> EdwardsPoint {
    ED25519_BASEPOINT_TABLE * s
}

/// `ge_double_scalarmult_base_vartime(r, a, A, b)` = `a*A + b*G`.
#[inline]
pub fn double_scalarmult_base_vartime(
    a: &Scalar,
    big_a: &EdwardsPoint,
    b: &Scalar,
) -> EdwardsPoint {
    EdwardsPoint::vartime_double_scalar_mul_basepoint(a, big_a, b)
}

/// `ge_double_scalarmult_precomp_vartime(r, a, A, b, Bi)` = `a*A + b*B`.
#[inline]
pub fn double_scalarmult_vartime(
    a: &Scalar,
    big_a: &EdwardsPoint,
    b: &Scalar,
    big_b: &EdwardsPoint,
) -> EdwardsPoint {
    EdwardsPoint::vartime_multiscalar_mul([a, b], [big_a, big_b])
}

/// `ge_mul8` / `scalarmult8`: `8 * P`, clearing the cofactor.
#[inline]
pub fn mul8(p: &EdwardsPoint) -> EdwardsPoint {
    p.mul_by_cofactor()
}

/// `check_key`: does this 32-byte value decode to a curve point?
///
/// `src/crypto/crypto.cpp: crypto_ops::check_key`.
#[inline]
pub fn check_key(key: &PublicKey) -> bool {
    decode_point(&key.0).is_some()
}

/// `secret_key_to_public_key`: `A = a*G`, rejecting a non-canonical `a`.
///
/// Returns `None` exactly when the C returns `false` (i.e. `sc_check` fails).
pub fn secret_key_to_public_key(sec: &SecretKey) -> Option<PublicKey> {
    let s = decode_scalar(&sec.0)?;
    Some(PublicKey(encode_point(&scalarmult_base(&s))))
}

/// `hash_to_scalar(data)` = `sc_reduce32(cn_fast_hash(data))`.
///
/// `specs/02-crypto.md` §1.2.
#[inline]
pub fn hash_to_scalar(data: &[u8]) -> EcScalar {
    EcScalar(sc_reduce32(&cn_fast_hash(data)))
}

/// The same, returned as a dalek `Scalar` (already reduced, so infallible).
#[inline]
pub fn hash_to_scalar_dalek(data: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order(cn_fast_hash(data))
}

/// `ge_fromfe_frombytes_vartime`, returning the **compressed** `ge_p2`.
///
/// A literal port of `src/crypto/crypto-ops.c`. This is the CryptoNote
/// Shallue--van de Woestijne-ish map; it is **not** any standard hash-to-curve
/// (`specs/02-crypto.md` §1.3). The C's control flow — including the
/// `negative:` branch and the `setsign:` sign fixup — is reproduced statement
/// for statement.
///
/// Corresponds to `hash_to_point` in `tests/crypto/crypto.cpp`, which encodes
/// the resulting `ge_p2` with `ge_tobytes`.
pub fn ge_fromfe_frombytes_vartime(s: &[u8; 32]) -> EcPoint {
    // NOT `Fe::from_bytes`: the loader inlined into this function has no
    // bit-255 mask, so the full 256-bit value is reduced mod p rather than
    // truncated. Half of all Keccak outputs have that bit set.
    let u = Fe::from_bytes_unmasked(s);

    let v = u.square2(); // 2 * u^2
    let w = v + Fe::ONE; // w = 2*u^2 + 1
    let mut x = w.square(); // w^2
    let y = consts::ma2() * v; // -2 * A^2 * u^2
    x = x + y; // x = w^2 - 2*A^2*u^2

    let mut rx = divpowm1(w, x); // (w/x)^(m+1)
    let y2 = rx.square();
    let xx = y2 * x;
    let diff = w - xx;
    let mut z = consts::ma();
    let sign: u8;

    if diff.is_nonzero() {
        let sum = w + xx;
        if sum.is_nonzero() {
            // ---- `negative:` ----
            let xneg = xx * consts::sqrtm1();
            let dneg = w - xneg;
            if dneg.is_nonzero() {
                debug_assert!(!(w + xneg).is_nonzero());
                rx = rx * consts::fffb3();
            } else {
                rx = rx * consts::fffb4();
            }
            // rx = sqrt(A * (A+2) * w / x); z stays -A.
            sign = 1;
        } else {
            rx = rx * consts::fffb1();
            rx = rx * u; // u * sqrt(2*A*(A+2)*w/x)
            z = z * v; // -2*A*u^2
            sign = 0;
        }
    } else {
        rx = rx * consts::fffb2();
        rx = rx * u;
        z = z * v;
        sign = 0;
    }

    // ---- `setsign:` ----
    if u8::from(rx.is_negative()) != sign {
        debug_assert!(rx.is_nonzero());
        rx = -rx;
    }

    let rz = z + w;
    let ry = z - w;
    let rx = rx * rz;

    // `ge_tobytes`: x = X/Z, y = Y/Z; encode y, with the sign bit from x.
    let recip = rz.invert();
    let ax = rx * recip;
    let ay = ry * recip;
    let mut out = ay.to_bytes();
    out[31] ^= u8::from(ax.is_negative()) << 7;
    EcPoint(out)
}

/// `hash_to_point(h)` from `tests/crypto/crypto.cpp`: the map above applied to
/// a raw 32-byte hash, with **no** multiplication by 8.
#[inline]
pub fn hash_to_point(h: &[u8; 32]) -> EcPoint {
    ge_fromfe_frombytes_vartime(h)
}

/// `hash_to_ec(key)`: `8 * ge_fromfe_frombytes_vartime(cn_fast_hash(key))`.
///
/// `specs/02-crypto.md` §1.3. Used for key images and CLSAG.
///
/// Returns `None` only if the map produced a point that does not decode, which
/// cannot happen for a well-formed field element — the C's `NDEBUG` assertion
/// checks the same curve equation.
pub fn hash_to_ec_point(key: &[u8; 32]) -> Option<EdwardsPoint> {
    let h = cn_fast_hash(key);
    let p2 = ge_fromfe_frombytes_vartime(&h);
    let p = decode_point(&p2.0)?;
    Some(mul8(&p))
}

/// The compressed form of [`hash_to_ec_point`]. `Hp(P)` in the CLSAG notation.
pub fn hash_to_ec(key: &[u8; 32]) -> Option<EcPoint> {
    hash_to_ec_point(key).map(|p| EcPoint(encode_point(&p)))
}

/// `generate_key_image(P, x)` = `x * Hp(P)`.
///
/// `specs/02-crypto.md` §3.6. The C asserts `sc_check(sec)`; we require it,
/// returning `None` instead of invoking undefined behaviour.
pub fn generate_key_image(pub_key: &PublicKey, sec: &SecretKey) -> Option<KeyImage> {
    let s = decode_scalar(&sec.0)?;
    let point = hash_to_ec_point(&pub_key.0)?;
    Some(KeyImage(encode_point(&(s * point))))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `hash_to_ec` multiplies by 8, so its output is always in the
    /// prime-order subgroup -- which is what makes a key image bind to the
    /// one-time key rather than to a torsion coset.
    ///
    /// (`specs/02` §2 item 4 also states `H = 8 * to_point(cn_fast_hash(G))`
    /// for the second generator hard-coded in `rctTypes.h`. Applying
    /// `hash_to_ec` to the basepoint encoding does *not* reproduce that
    /// literal, and `rctOps.cpp: hash_to_p3` is byte-for-byte the same
    /// function as `hash_to_ec` -- so the documented derivation of `H` does not
    /// hold as written. `H` is only needed for commitments and Bulletproofs+,
    /// which are M2 work; take the literal from `rctTypes.h` there rather than
    /// deriving it.)
    #[test]
    fn hash_to_ec_lands_in_the_prime_order_subgroup() {
        for i in 0u8..16 {
            let p = hash_to_ec_point(&[i; 32]).expect("map always yields a point");
            assert!(p.is_torsion_free(), "hash_to_ec output has torsion");
            assert_ne!(p, EdwardsPoint::default(), "hash_to_ec produced identity");
        }
    }

    #[test]
    fn sc_check_boundary() {
        // l = 2^252 + 27742317777372353535851937790883648493
        let l = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        assert!(!sc_check(&l), "l itself is not canonical");
        let mut lm1 = l;
        lm1[0] -= 1;
        assert!(sc_check(&lm1), "l-1 is canonical");
        assert!(sc_check(&[0u8; 32]), "zero is canonical");
    }

    #[test]
    fn decoding_accepts_small_order_points() {
        // The order-8 point 0x26e8...  and the identity must both decode, as
        // ge_frombytes_vartime accepts them. A strict ed25519 library would
        // reject these, and rejecting them here would fork the chain.
        let identity = [
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert!(decode_point(&identity).is_some());
        let order2 = [
            0xecu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        assert!(decode_point(&order2).is_some());
    }

    #[test]
    fn mul8_is_multiplication_by_eight() {
        let p = scalarmult_base(&Scalar::from(7u64));
        assert_eq!(mul8(&p), p * Scalar::from(8u64));
    }

    #[test]
    fn sc_mulsub_matches_definition() {
        let a = sc_reduce32(&[3u8; 32]);
        let b = sc_reduce32(&[5u8; 32]);
        let c = sc_reduce32(&[7u8; 32]);
        let lhs = sc_mulsub(&a, &b, &c);
        let rhs = (decode_scalar_unreduced(&c)
            - decode_scalar_unreduced(&a) * decode_scalar_unreduced(&b))
        .to_bytes();
        assert_eq!(lhs, rhs);
    }
}
