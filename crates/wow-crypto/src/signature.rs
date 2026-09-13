//! The CryptoNote Schnorr signature and the v1 ring signature.
//!
//! `specs/02-crypto.md` §3.9. This is **not** standard ed25519: the challenge
//! is `hash_to_scalar` over a packed 96-byte `s_comm`, and the verifier has two
//! extra rejections the C is explicit about.
//!
//! The same scheme carries the **HF 18 block-header miner signature**
//! (`specs/06-consensus-rules.md` §4), which is what makes Wownero solo-mining
//! only — so a bug here is a consensus bug, not just a wallet one.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use crate::ops::{
    decode_point, double_scalarmult_base_vartime, double_scalarmult_vartime, encode_point,
    hash_to_ec_point, hash_to_scalar, sc_check, sc_is_nonzero, sc_mulsub, scalarmult_base,
};
use crate::random::Rng;
use crate::types::{EcScalar, Hash256, KeyImage, PublicKey, SecretKey, Signature};

/// The encoded identity point, `{1, 0, 0, ...}`.
///
/// `check_signature` rejects a commitment equal to this literal. Note it
/// compares the *encoding*, so only this one of the several byte strings that
/// decode to the identity is caught — reproduce the literal comparison.
const ENCODED_IDENTITY: [u8; 32] = {
    let mut a = [0u8; 32];
    a[0] = 1;
    a
};

/// `struct s_comm { hash h; ec_point key; ec_point comm; }` — 96 bytes, packed.
#[inline]
fn s_comm(msg: &Hash256, key: &[u8; 32], comm: &[u8; 32]) -> [u8; 96] {
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(msg);
    buf[32..64].copy_from_slice(key);
    buf[64..].copy_from_slice(comm);
    buf
}

/// `generate_signature(prefix_hash, pub, sec, sig)`.
///
/// ```text
/// loop {
///     k = random_scalar()
///     comm = k*G
///     c = hash_to_scalar(s_comm{ h: m, key: A, comm })
///     if c == 0 { continue }
///     r = k - c*a   (mod l)
///     if r == 0 { continue }
///     return (c, r)
/// }
/// ```
///
/// The retry loop is not decoration: it consumes an extra draw from the PRNG
/// when it fires, which the reference vectors depend on.
///
/// Returns `None` if `sec` is not canonical (the C asserts it).
pub fn generate_signature(
    rng: &mut Rng,
    prefix_hash: &Hash256,
    pub_key: &PublicKey,
    sec: &SecretKey,
) -> Option<Signature> {
    if !sc_check(&sec.0) {
        return None;
    }
    loop {
        let k = rng.random_scalar();
        let k_scalar = Scalar::from_bytes_mod_order(k);
        let comm = encode_point(&scalarmult_base(&k_scalar));
        let c = hash_to_scalar(&s_comm(prefix_hash, &pub_key.0, &comm));
        if !sc_is_nonzero(&c.0) {
            continue;
        }
        let r = sc_mulsub(&c.0, &sec.0, &k);
        if !sc_is_nonzero(&r) {
            continue;
        }
        return Some(Signature { c, r: EcScalar(r) });
    }
}

/// `check_signature(prefix_hash, pub, sig)`.
///
/// Rejects, in the C's order:
/// 1. a public key that does not decode,
/// 2. a non-canonical `c` or `r` (`sc_check`),
/// 3. `c == 0`,
/// 4. a commitment equal to the encoded identity,
/// 5. a challenge that does not reproduce `c`.
///
/// Steps 3 and 4 are easy to omit and `specs/02` §9 calls both out.
pub fn check_signature(prefix_hash: &Hash256, pub_key: &PublicKey, sig: &Signature) -> bool {
    let Some(a) = decode_point(&pub_key.0) else {
        return false;
    };
    if !sc_check(&sig.c.0) || !sc_check(&sig.r.0) || !sc_is_nonzero(&sig.c.0) {
        return false;
    }
    let c = Scalar::from_bytes_mod_order(sig.c.0);
    let r = Scalar::from_bytes_mod_order(sig.r.0);
    // ge_double_scalarmult_base_vartime(&tmp2, &sig.c, &tmp3, &sig.r)
    let comm = encode_point(&double_scalarmult_base_vartime(&c, &a, &r));
    if comm == ENCODED_IDENTITY {
        return false;
    }
    let c2 = hash_to_scalar(&s_comm(prefix_hash, &pub_key.0, &comm));
    c2.0 == sig.c.0
}

/// `rs_comm`: `hash h` followed by `pubs_count` pairs of `ec_point`.
///
/// The C `malloc`s `sizeof(rs_comm) + n * sizeof(ec_point_pair)` and hashes
/// exactly that many bytes — `32 + 64 * n`.
fn rs_comm_buf(prefix_hash: &Hash256, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; 32 + 64 * n];
    buf[..32].copy_from_slice(prefix_hash);
    buf
}

#[inline]
fn rs_comm_set(buf: &mut [u8], i: usize, a: &[u8; 32], b: &[u8; 32]) {
    let off = 32 + 64 * i;
    buf[off..off + 32].copy_from_slice(a);
    buf[off + 32..off + 64].copy_from_slice(b);
}

/// `generate_ring_signature(prefix_hash, image, pubs, n, sec, sec_index, sig)`.
///
/// The v1 (pre-RingCT) ring signature. Only needed to *verify* historical
/// transactions — no v1 transaction can be created at HF >= 6
/// (`specs/06` §5.4) — but it is a large slice of the reference vectors, so it
/// is implemented in full.
///
/// Returns `None` if `sec_index` is out of range, the key image does not
/// decode, `sec` is not canonical, or any ring member fails to decode.
pub fn generate_ring_signature(
    rng: &mut Rng,
    prefix_hash: &Hash256,
    image: &KeyImage,
    pubs: &[PublicKey],
    sec: &SecretKey,
    sec_index: usize,
) -> Option<Vec<Signature>> {
    if sec_index >= pubs.len() || !sc_check(&sec.0) {
        return None;
    }
    let image_point = decode_point(&image.0)?;

    let mut buf = rs_comm_buf(prefix_hash, pubs.len());
    let mut sig = vec![Signature::ZERO; pubs.len()];
    let mut sum = Scalar::ZERO;
    let mut k = [0u8; 32];

    for (i, p) in pubs.iter().enumerate() {
        if i == sec_index {
            k = rng.random_scalar();
            let k_s = Scalar::from_bytes_mod_order(k);
            let a = encode_point(&scalarmult_base(&k_s));
            let hp = hash_to_ec_point(&p.0)?;
            let b = encode_point(&(k_s * hp));
            rs_comm_set(&mut buf, i, &a, &b);
        } else {
            sig[i].c = EcScalar(rng.random_scalar());
            sig[i].r = EcScalar(rng.random_scalar());
            let point = decode_point(&p.0)?;
            let ci = Scalar::from_bytes_mod_order(sig[i].c.0);
            let ri = Scalar::from_bytes_mod_order(sig[i].r.0);
            let a = encode_point(&double_scalarmult_base_vartime(&ci, &point, &ri));
            let hp = hash_to_ec_point(&p.0)?;
            let b = encode_point(&double_scalarmult_vartime(&ri, &hp, &ci, &image_point));
            rs_comm_set(&mut buf, i, &a, &b);
            sum += ci;
        }
    }

    let h = hash_to_scalar(&buf);
    let c = Scalar::from_bytes_mod_order(h.0) - sum;
    sig[sec_index].c = EcScalar(c.to_bytes());
    sig[sec_index].r = EcScalar(sc_mulsub(&sig[sec_index].c.0, &sec.0, &k));
    Some(sig)
}

/// `check_ring_signature(prefix_hash, image, pubs, n, sig)`.
pub fn check_ring_signature(
    prefix_hash: &Hash256,
    image: &KeyImage,
    pubs: &[PublicKey],
    sigs: &[Signature],
) -> bool {
    if pubs.len() != sigs.len() {
        return false;
    }
    let Some(image_point) = decode_point(&image.0) else {
        return false;
    };

    let mut buf = rs_comm_buf(prefix_hash, pubs.len());
    let mut sum = Scalar::ZERO;

    for (i, p) in pubs.iter().enumerate() {
        if !sc_check(&sigs[i].c.0) || !sc_check(&sigs[i].r.0) {
            return false;
        }
        let Some(point) = decode_point(&p.0) else {
            return false;
        };
        let ci = Scalar::from_bytes_mod_order(sigs[i].c.0);
        let ri = Scalar::from_bytes_mod_order(sigs[i].r.0);
        let a = encode_point(&double_scalarmult_base_vartime(&ci, &point, &ri));
        let Some(hp) = hash_to_ec_point(&p.0) else {
            return false;
        };
        let b = encode_point(&double_scalarmult_vartime(&ri, &hp, &ci, &image_point));
        rs_comm_set(&mut buf, i, &a, &b);
        sum += ci;
    }

    let h = hash_to_scalar(&buf);
    let diff = Scalar::from_bytes_mod_order(h.0) - sum;
    diff == Scalar::ZERO
}

/// Whether a decoded point is the identity, using the *correct* test rather
/// than the field-representation one.
///
/// `tests/crypto/tests.txt` has six `check_ge_p3_identity` vectors that compare
/// a buggy limb-wise test (`X == 0 && Y == Z` on unreduced limbs) against the
/// fixed one. Only the fixed function is used by consensus code
/// (`ge_p3_is_point_at_infinity_vartime`), so only it is provided here; the
/// buggy variant tests a C-specific representation that this implementation
/// does not have.
#[inline]
pub fn is_point_at_infinity(p: &EdwardsPoint) -> bool {
    p == &EdwardsPoint::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::generate_key_image;

    fn keypair(rng: &mut Rng) -> (PublicKey, SecretKey) {
        rng.generate_keys()
    }

    #[test]
    fn sign_then_verify() {
        let mut rng = Rng::deterministic_test_seed();
        for i in 0..16u8 {
            let (p, s) = keypair(&mut rng);
            let msg = crate::hash::cn_fast_hash(&[i; 8]);
            let sig = generate_signature(&mut rng, &msg, &p, &s).unwrap();
            assert!(check_signature(&msg, &p, &sig));
        }
    }

    #[test]
    fn verification_rejects_tampering() {
        let mut rng = Rng::deterministic_test_seed();
        let (p, s) = keypair(&mut rng);
        let (p2, _) = keypair(&mut rng);
        let msg = crate::hash::cn_fast_hash(b"message");
        let other = crate::hash::cn_fast_hash(b"other");
        let sig = generate_signature(&mut rng, &msg, &p, &s).unwrap();

        assert!(check_signature(&msg, &p, &sig));
        assert!(!check_signature(&other, &p, &sig), "wrong message");
        assert!(!check_signature(&msg, &p2, &sig), "wrong key");

        let mut bad = sig;
        bad.c.0[0] ^= 1;
        assert!(!check_signature(&msg, &p, &bad), "tampered c");
        let mut bad = sig;
        bad.r.0[0] ^= 1;
        assert!(!check_signature(&msg, &p, &bad), "tampered r");
    }

    /// `specs/02` §9: the verifier MUST reject `c == 0` and non-canonical
    /// scalars. Both are easy to leave out and neither is caught by a
    /// round-trip test.
    #[test]
    fn verifier_rejects_zero_c_and_non_canonical_scalars() {
        let mut rng = Rng::deterministic_test_seed();
        let (p, _s) = keypair(&mut rng);
        let msg = crate::hash::cn_fast_hash(b"m");

        let zero_c = Signature {
            c: EcScalar::ZERO,
            r: EcScalar([1u8; 32]),
        };
        assert!(!check_signature(&msg, &p, &zero_c));

        // l itself is not a canonical scalar.
        let l = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        assert!(!check_signature(
            &msg,
            &p,
            &Signature {
                c: EcScalar(l),
                r: EcScalar([1u8; 32])
            }
        ));
        assert!(!check_signature(
            &msg,
            &p,
            &Signature {
                c: EcScalar([1u8; 32]),
                r: EcScalar(l)
            }
        ));
    }

    #[test]
    fn verifier_rejects_an_undecodable_key() {
        let msg = crate::hash::cn_fast_hash(b"m");
        let sig = Signature {
            c: EcScalar([1u8; 32]),
            r: EcScalar([1u8; 32]),
        };
        assert!(!check_signature(&msg, &PublicKey([0xffu8; 32]), &sig));
    }

    #[test]
    fn ring_signature_roundtrip() {
        let mut rng = Rng::deterministic_test_seed();
        for n in [1usize, 2, 3, 8, 22] {
            let mut pubs = Vec::new();
            let mut secs = Vec::new();
            for _ in 0..n {
                let (p, s) = keypair(&mut rng);
                pubs.push(p);
                secs.push(s);
            }
            let idx = n / 2;
            let image = generate_key_image(&pubs[idx], &secs[idx]).unwrap();
            let msg = crate::hash::cn_fast_hash(&[n as u8; 4]);

            let sigs =
                generate_ring_signature(&mut rng, &msg, &image, &pubs, &secs[idx], idx).unwrap();
            assert_eq!(sigs.len(), n);
            assert!(check_ring_signature(&msg, &image, &pubs, &sigs));

            // Any tampering breaks it.
            let mut bad = sigs.clone();
            bad[0].r.0[0] ^= 1;
            assert!(!check_ring_signature(&msg, &image, &pubs, &bad));
            let other = crate::hash::cn_fast_hash(b"other");
            assert!(!check_ring_signature(&other, &image, &pubs, &sigs));
        }
    }

    #[test]
    fn ring_signature_rejects_a_length_mismatch() {
        let mut rng = Rng::deterministic_test_seed();
        let (p, s) = keypair(&mut rng);
        let image = generate_key_image(&p, &s).unwrap();
        let msg = crate::hash::cn_fast_hash(b"m");
        let sigs = generate_ring_signature(&mut rng, &msg, &image, &[p], &s, 0).unwrap();
        assert!(!check_ring_signature(&msg, &image, &[p, p], &sigs));
    }

    #[test]
    fn key_image_is_deterministic_and_binds_the_key() {
        let mut rng = Rng::deterministic_test_seed();
        let (p, s) = keypair(&mut rng);
        let (p2, s2) = keypair(&mut rng);
        assert_eq!(
            generate_key_image(&p, &s).unwrap(),
            generate_key_image(&p, &s).unwrap()
        );
        assert_ne!(
            generate_key_image(&p, &s).unwrap(),
            generate_key_image(&p2, &s2).unwrap()
        );
    }

    /// The C compares the *encoding* against the literal `{1, 0, ...}`, so the
    /// constant must be exactly that.
    #[test]
    fn encoded_identity_literal() {
        assert_eq!(ENCODED_IDENTITY[0], 1);
        assert!(ENCODED_IDENTITY[1..].iter().all(|b| *b == 0));
        assert_eq!(encode_point(&EdwardsPoint::default()), ENCODED_IDENTITY);
    }

    #[test]
    fn signature_wire_layout_is_c_then_r() {
        let sig = Signature {
            c: EcScalar([0xaa; 32]),
            r: EcScalar([0xbb; 32]),
        };
        let b = sig.to_bytes();
        assert!(b[..32].iter().all(|x| *x == 0xaa));
        assert!(b[32..].iter().all(|x| *x == 0xbb));
        assert_eq!(Signature::from_bytes(&b), sig);
    }
}
