//! CLSAG: the ring signature every RingCT input carries from HF 13 onward.
//!
//! `src/ringct/rctSigs.cpp`: `CLSAG_Gen`, `verRctCLSAGSimple`, plus
//! `device_default.cpp`'s `clsag_prepare`, `clsag_hash` and `clsag_sign`.
//! `specs/02` §4.3.
//!
//! # The domain separators are 32-byte blocks, not strings
//!
//! `specs/02` §4.3 writes the hashes as
//! `hash_to_scalar("CLSAG_agg_0" || P_0..)`, which reads as an 11-byte prefix.
//! The C builds a **vector of 32-byte keys** and writes the string into the
//! first one over zeros:
//!
//! ```c
//! sc_0(mu_P_to_hash[0].bytes);
//! memcpy(mu_P_to_hash[0].bytes, config::HASH_KEY_CLSAG_AGG_0,
//!        sizeof(config::HASH_KEY_CLSAG_AGG_0) - 1);
//! ```
//!
//! So the hashed prefix is `"CLSAG_agg_0"` followed by **21 zero bytes**, and
//! the same for the other two. The `- 1` drops the terminating NUL, so the
//! string itself is not NUL-terminated inside the block. Getting this wrong
//! produces signatures that verify against themselves and against nothing else.
//!
//! # What is signed
//!
//! One CLSAG per input. The ring is `n` pairs `(P_i, C_i)` — a one-time output
//! key and its amount commitment — and the signer knows `p` with `P_l = p*G`
//! and `z` with `C_l - C_offset = z*G`. `C_offset` is the pseudo-output
//! commitment for that input, which is what makes the amounts balance without
//! revealing them.
//!
//! The key image `I = p * Hp(P_l)` is **not** serialized — it comes from the
//! input's `k_image` field. The auxiliary image `D` is serialized, and in its
//! `D/8` form.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::ops::{decode_point, decode_scalar, encode_point, hash_to_ec_point, mul8};
use crate::types::{EcPoint, EcScalar, KeyImage, PublicKey};

/// `config::HASH_KEY_CLSAG_ROUND`.
const DOMAIN_ROUND: &[u8] = b"CLSAG_round";
/// `config::HASH_KEY_CLSAG_AGG_0`.
const DOMAIN_AGG_0: &[u8] = b"CLSAG_agg_0";
/// `config::HASH_KEY_CLSAG_AGG_1`.
const DOMAIN_AGG_1: &[u8] = b"CLSAG_agg_1";

/// `INV_EIGHT`, the inverse of 8 modulo the group order.
fn inv_eight() -> Scalar {
    Scalar::from(8u8).invert()
}

/// A CLSAG signature as it appears on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Clsag {
    /// One scalar per ring member.
    pub s: Vec<EcScalar>,
    /// The challenge that closes the ring.
    pub c1: EcScalar,
    /// The auxiliary key image, stored as `D / 8`.
    pub d: EcPoint,
    /// `I`. Not serialized as part of the signature — it is the input's
    /// `k_image` — but carried here because signing produces it and
    /// verification needs it.
    pub i: KeyImage,
}

/// One ring member: the output key and its commitment, both as they appear in
/// the chain (`C_nonzero`, before `C_offset` is subtracted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingMember {
    pub dest: PublicKey,
    pub mask: EcPoint,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClsagError {
    #[error("the ring is empty")]
    EmptyRing,
    #[error("the signing index {index} is outside a ring of {ring_size}")]
    IndexOutOfRange { index: usize, ring_size: usize },
    #[error("the signature has {got} scalars for a ring of {want}")]
    WrongScalarCount { got: usize, want: usize },
    #[error("a signature scalar is not canonical")]
    NonCanonicalScalar,
    #[error("the key image is the identity")]
    IdentityKeyImage,
    #[error("a point in the ring does not decode")]
    BadPoint,
    #[error("the ring does not close")]
    BadSignature,
}

type Result<T> = std::result::Result<T, ClsagError>;

/// A 32-byte block holding `domain` at its start and zeros after it.
fn domain_block(domain: &[u8]) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..domain.len()].copy_from_slice(domain);
    b
}

/// The two aggregation scalars.
///
/// Both hash the same tail; only the leading domain block differs, which is
/// what makes `mu_P` and `mu_C` independent.
fn aggregation_hashes(
    ring: &[RingMember],
    key_image: &KeyImage,
    d8: &EcPoint,
    c_offset: &EcPoint,
) -> (Scalar, Scalar) {
    let n = ring.len();
    // domain, n dests, n masks, I, D/8, C_offset.
    let mut tail = Vec::with_capacity((2 * n + 3) * 32);
    for m in ring {
        tail.extend_from_slice(&m.dest.0);
    }
    for m in ring {
        tail.extend_from_slice(&m.mask.0);
    }
    tail.extend_from_slice(&key_image.0);
    tail.extend_from_slice(&d8.0);
    tail.extend_from_slice(&c_offset.0);

    let mut buf = Vec::with_capacity(32 + tail.len());
    buf.extend_from_slice(&domain_block(DOMAIN_AGG_0));
    buf.extend_from_slice(&tail);
    let mu_p = crate::ops::hash_to_scalar_dalek(&buf);

    buf[..32].copy_from_slice(&domain_block(DOMAIN_AGG_1));
    let mu_c = crate::ops::hash_to_scalar_dalek(&buf);

    (mu_p, mu_c)
}

/// The fixed part of the round hash: everything before `L` and `R`.
fn round_prefix(ring: &[RingMember], c_offset: &EcPoint, message: &[u8; 32]) -> Vec<u8> {
    let n = ring.len();
    let mut buf = Vec::with_capacity((2 * n + 5) * 32);
    buf.extend_from_slice(&domain_block(DOMAIN_ROUND));
    for m in ring {
        buf.extend_from_slice(&m.dest.0);
    }
    for m in ring {
        buf.extend_from_slice(&m.mask.0);
    }
    buf.extend_from_slice(&c_offset.0);
    buf.extend_from_slice(message);
    buf
}

/// `c_{i+1} = Hs(prefix || L || R)`.
fn round_hash(prefix: &[u8], l: &EdwardsPoint, r: &EdwardsPoint) -> Scalar {
    let mut buf = Vec::with_capacity(prefix.len() + 64);
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(&encode_point(l));
    buf.extend_from_slice(&encode_point(r));
    crate::ops::hash_to_scalar_dalek(&buf)
}

/// The decoded ring, computed once for both signing and verification.
struct DecodedRing {
    dest: Vec<EdwardsPoint>,
    /// `C_i - C_offset`.
    mask_less_offset: Vec<EdwardsPoint>,
    /// `Hp(P_i)`.
    hp: Vec<EdwardsPoint>,
}

fn decode_ring(ring: &[RingMember], c_offset: &EdwardsPoint) -> Result<DecodedRing> {
    let mut out = DecodedRing {
        dest: Vec::with_capacity(ring.len()),
        mask_less_offset: Vec::with_capacity(ring.len()),
        hp: Vec::with_capacity(ring.len()),
    };
    for m in ring {
        let p = decode_point(&m.dest.0).ok_or(ClsagError::BadPoint)?;
        let c = decode_point(&m.mask.0).ok_or(ClsagError::BadPoint)?;
        out.hp
            .push(hash_to_ec_point(&m.dest.0).ok_or(ClsagError::BadPoint)?);
        out.dest.push(p);
        out.mask_less_offset.push(c - c_offset);
    }
    Ok(out)
}

/// Sign `message` over `ring`, knowing the secrets at `index`.
///
/// * `p` — the one-time output secret key, `P_l = p*G`.
/// * `z` — the difference of blinding factors, `C_l - C_offset = z*G`.
/// * `alpha` and `fake_s` are the random values the reference draws inside;
///   they are parameters so a test can pin a signature. Callers pass fresh
///   randomness, and **reusing `alpha` across two signatures leaks `p`** in
///   exactly the way a reused Schnorr nonce does.
#[allow(clippy::too_many_arguments, reason = "CLSAG_Gen takes them")]
pub fn sign(
    message: &[u8; 32],
    ring: &[RingMember],
    index: usize,
    p: &Scalar,
    z: &Scalar,
    c_offset: &EcPoint,
    alpha: &Scalar,
    fake_s: &[Scalar],
) -> Result<Clsag> {
    let n = ring.len();
    if n == 0 {
        return Err(ClsagError::EmptyRing);
    }
    if index >= n {
        return Err(ClsagError::IndexOutOfRange {
            index,
            ring_size: n,
        });
    }
    if fake_s.len() != n {
        return Err(ClsagError::WrongScalarCount {
            got: fake_s.len(),
            want: n,
        });
    }

    let offset_point = decode_point(&c_offset.0).ok_or(ClsagError::BadPoint)?;
    let decoded = decode_ring(ring, &offset_point)?;

    // `clsag_prepare`: the two key images and the commitment to `alpha`.
    let h = decoded.hp[index];
    let key_image = KeyImage(encode_point(&(p * h)));
    let d_point = z * h;
    let d8 = EcPoint(encode_point(&(inv_eight() * d_point)));

    let a_g = alpha * ED25519_BASEPOINT_POINT;
    let a_h = alpha * h;

    let (mu_p, mu_c) = aggregation_hashes(ring, &key_image, &d8, c_offset);
    let prefix = round_prefix(ring, c_offset, message);

    let i_point = decode_point(&key_image.0).ok_or(ClsagError::BadPoint)?;

    // The ring starts closed at `index` and is walked forward.
    let mut c = round_hash(&prefix, &a_g, &a_h);
    let mut s = vec![Scalar::ZERO; n];
    let mut c1 = Scalar::ZERO;

    let mut i = (index + 1) % n;
    if i == 0 {
        c1 = c;
    }
    while i != index {
        s[i] = fake_s[i];
        let c_p = mu_p * c;
        let c_c = mu_c * c;

        let l = s[i] * ED25519_BASEPOINT_POINT
            + c_p * decoded.dest[i]
            + c_c * decoded.mask_less_offset[i];
        let r = s[i] * decoded.hp[i] + c_p * i_point + c_c * d_point;

        c = round_hash(&prefix, &l, &r);
        i = (i + 1) % n;
        if i == 0 {
            c1 = c;
        }
    }

    // `clsag_sign`: s_l = alpha - c * (mu_P * p + mu_C * z).
    s[index] = alpha - c * (mu_p * p + mu_c * z);

    Ok(Clsag {
        s: s.into_iter().map(|x| EcScalar(x.to_bytes())).collect(),
        c1: EcScalar(c1.to_bytes()),
        d: d8,
        i: key_image,
    })
}

/// `verRctCLSAGSimple`.
///
/// The key image is passed separately because on the wire it lives in the
/// input's `k_image` field, not in the signature.
pub fn verify(
    message: &[u8; 32],
    sig: &Clsag,
    key_image: &KeyImage,
    ring: &[RingMember],
    c_offset: &EcPoint,
) -> Result<()> {
    let n = ring.len();
    if n == 0 {
        return Err(ClsagError::EmptyRing);
    }
    if sig.s.len() != n {
        return Err(ClsagError::WrongScalarCount {
            got: sig.s.len(),
            want: n,
        });
    }

    // Every scalar must be canonical. The C checks this explicitly, and it
    // matters: a non-canonical scalar has more than one encoding, so accepting
    // one would let the same signature be rewritten.
    let mut s = Vec::with_capacity(n);
    for x in &sig.s {
        s.push(decode_scalar(&x.0).ok_or(ClsagError::NonCanonicalScalar)?);
    }
    let c1 = decode_scalar(&sig.c1.0).ok_or(ClsagError::NonCanonicalScalar)?;

    let i_point = decode_point(&key_image.0).ok_or(ClsagError::BadPoint)?;
    if i_point == EdwardsPoint::identity() {
        return Err(ClsagError::IdentityKeyImage);
    }

    // `D` is stored divided by eight, so multiplying by eight both recovers it
    // and clears any torsion the sender may have added.
    let d_point = mul8(&decode_point(&sig.d.0).ok_or(ClsagError::BadPoint)?);
    if d_point == EdwardsPoint::identity() {
        return Err(ClsagError::IdentityKeyImage);
    }

    let offset_point = decode_point(&c_offset.0).ok_or(ClsagError::BadPoint)?;
    let decoded = decode_ring(ring, &offset_point)?;

    let (mu_p, mu_c) = aggregation_hashes(ring, key_image, &sig.d, c_offset);
    let prefix = round_prefix(ring, c_offset, message);

    let mut c = c1;
    for (i, si) in s.iter().enumerate().take(n) {
        let c_p = mu_p * c;
        let c_c = mu_c * c;

        let l = si * ED25519_BASEPOINT_POINT
            + c_p * decoded.dest[i]
            + c_c * decoded.mask_less_offset[i];
        let r = si * decoded.hp[i] + c_p * i_point + c_c * d_point;

        c = round_hash(&prefix, &l, &r);
        if c == Scalar::ZERO {
            return Err(ClsagError::BadSignature);
        }
    }

    if c == c1 {
        Ok(())
    } else {
        Err(ClsagError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic scalar, so the tests are reproducible.
    fn scalar(seed: u8, tweak: u8) -> Scalar {
        let mut b = [seed; 32];
        b[31] = tweak;
        Scalar::from_bytes_mod_order(b)
    }

    fn point(s: &Scalar) -> EcPoint {
        EcPoint(encode_point(&(s * ED25519_BASEPOINT_POINT)))
    }

    /// A ring of `n` members with a real spend at `index`.
    ///
    /// The signer knows `p` (the output secret key) and `z`, where
    /// `C_index - C_offset = z*G`. The decoys are unrelated points, which is
    /// what they are on the chain too.
    struct Setup {
        ring: Vec<RingMember>,
        index: usize,
        p: Scalar,
        z: Scalar,
        c_offset: EcPoint,
        alpha: Scalar,
        fake_s: Vec<Scalar>,
        message: [u8; 32],
    }

    fn setup(n: usize, index: usize) -> Setup {
        let p = scalar(1, 7);
        let z = scalar(2, 9);

        // The pseudo-output commitment, and the real member's commitment
        // sitting z*G above it.
        let offset_scalar = scalar(3, 11);
        let c_offset = point(&offset_scalar);
        let real_mask = EcPoint(encode_point(
            &((offset_scalar + z) * ED25519_BASEPOINT_POINT),
        ));

        let mut ring = Vec::with_capacity(n);
        for i in 0..n {
            if i == index {
                ring.push(RingMember {
                    dest: PublicKey(point(&p).0),
                    mask: real_mask,
                });
            } else {
                ring.push(RingMember {
                    dest: PublicKey(point(&scalar(20 + i as u8, 3)).0),
                    mask: point(&scalar(60 + i as u8, 5)),
                });
            }
        }

        Setup {
            ring,
            index,
            p,
            z,
            c_offset,
            alpha: scalar(4, 13),
            fake_s: (0..n).map(|i| scalar(100 + i as u8, 17)).collect(),
            message: [0x5a; 32],
        }
    }

    impl Setup {
        fn sign(&self) -> Clsag {
            sign(
                &self.message,
                &self.ring,
                self.index,
                &self.p,
                &self.z,
                &self.c_offset,
                &self.alpha,
                &self.fake_s,
            )
            .expect("signing succeeds")
        }

        fn verify(&self, sig: &Clsag) -> Result<()> {
            verify(&self.message, sig, &sig.i, &self.ring, &self.c_offset)
        }
    }

    /// The basic claim: a signature made over a ring verifies against it.
    ///
    /// Checked at Wownero's real ring size of 22, and at the edges.
    #[test]
    fn a_signature_verifies() {
        for (n, index) in [
            (1usize, 0usize),
            (2, 0),
            (2, 1),
            (22, 0),
            (22, 11),
            (22, 21),
        ] {
            let s = setup(n, index);
            let sig = s.sign();
            assert_eq!(sig.s.len(), n, "n={n}");
            s.verify(&sig)
                .unwrap_or_else(|e| panic!("n={n} index={index}: {e}"));
        }
    }

    /// The key image depends only on the spent output and its secret key, so
    /// the same output spent into two different rings gives the same image.
    /// That is what makes double-spend detection work.
    #[test]
    fn the_key_image_does_not_depend_on_the_ring() {
        let a = setup(22, 3);
        let b = setup(11, 7);
        assert_eq!(a.sign().i, b.sign().i);

        // And it is the image the standalone function computes.
        let expected = crate::generate_key_image(
            &a.ring[a.index].dest,
            &crate::types::SecretKey(a.p.to_bytes()),
        );
        assert_eq!(Some(a.sign().i), expected);
    }

    /// Changing the message invalidates the signature. Without this the
    /// signature would not bind the transaction at all.
    #[test]
    fn a_different_message_fails() {
        let s = setup(11, 5);
        let sig = s.sign();
        let mut other = s.message;
        other[0] ^= 1;
        assert_eq!(
            verify(&other, &sig, &sig.i, &s.ring, &s.c_offset),
            Err(ClsagError::BadSignature)
        );
    }

    /// Substituting a ring member invalidates the signature — including
    /// replacing a decoy, since every member is hashed into every round.
    #[test]
    fn a_tampered_ring_fails() {
        let s = setup(11, 5);
        let sig = s.sign();

        let mut ring = s.ring.clone();
        ring[0].dest = PublicKey(point(&scalar(99, 1)).0);
        assert_eq!(
            verify(&s.message, &sig, &sig.i, &ring, &s.c_offset),
            Err(ClsagError::BadSignature)
        );

        let mut ring = s.ring.clone();
        ring[2].mask = point(&scalar(98, 1));
        assert_eq!(
            verify(&s.message, &sig, &sig.i, &ring, &s.c_offset),
            Err(ClsagError::BadSignature)
        );
    }

    /// The commitment offset is bound too. This is the link between the ring
    /// signature and the amount balance: swapping in a different pseudo-output
    /// would otherwise let an input claim a different value.
    #[test]
    fn a_different_commitment_offset_fails() {
        let s = setup(11, 5);
        let sig = s.sign();
        let other = point(&scalar(77, 3));
        assert_eq!(
            verify(&s.message, &sig, &sig.i, &s.ring, &other),
            Err(ClsagError::BadSignature)
        );
    }

    /// A wrong key image fails. The image is not in the signature, so a
    /// verifier that took it on trust would accept a spend of an output whose
    /// image had already been seen.
    #[test]
    fn a_substituted_key_image_fails() {
        let s = setup(11, 5);
        let sig = s.sign();
        let other = crate::generate_key_image(
            &s.ring[0].dest,
            &crate::types::SecretKey(scalar(55, 1).to_bytes()),
        )
        .expect("an image");
        assert_eq!(
            verify(&s.message, &sig, &other, &s.ring, &s.c_offset),
            Err(ClsagError::BadSignature)
        );
    }

    /// Tampering with any scalar fails, wherever it sits in the ring.
    #[test]
    fn a_tampered_scalar_fails() {
        let s = setup(11, 5);
        for i in [0usize, 5, 10] {
            let mut sig = s.sign();
            sig.s[i].0[0] ^= 1;
            assert_eq!(s.verify(&sig), Err(ClsagError::BadSignature), "s[{i}]");
        }
        let mut sig = s.sign();
        sig.c1.0[0] ^= 1;
        assert!(s.verify(&sig).is_err());
    }

    /// `D` is stored divided by eight, so a verifier that forgets to multiply
    /// sees a different point and rejects.
    #[test]
    fn the_auxiliary_image_is_divided_by_eight() {
        let s = setup(11, 5);
        let sig = s.sign();

        // What the signature stores is D/8; D itself is 8 times that, and the
        // two are different points.
        let stored = decode_point(&sig.d.0).expect("decodes");
        assert_ne!(encode_point(&mul8(&stored)), sig.d.0);

        // Storing D rather than D/8 does not verify.
        let mut wrong = sig.clone();
        wrong.d = EcPoint(encode_point(&mul8(&stored)));
        assert!(s.verify(&wrong).is_err());
    }

    /// Structural errors are reported rather than silently accepted.
    #[test]
    fn malformed_input_is_rejected() {
        let s = setup(11, 5);
        let sig = s.sign();

        assert_eq!(
            verify(&s.message, &sig, &sig.i, &[], &s.c_offset),
            Err(ClsagError::EmptyRing)
        );

        let mut short = sig.clone();
        short.s.pop();
        assert_eq!(
            s.verify(&short),
            Err(ClsagError::WrongScalarCount { got: 10, want: 11 })
        );

        // A non-canonical scalar: the group order itself plus one is not a
        // valid encoding, and must not be accepted as an alternative form.
        let mut bad = sig.clone();
        bad.s[0] = EcScalar([0xff; 32]);
        assert_eq!(s.verify(&bad), Err(ClsagError::NonCanonicalScalar));

        // The identity as a key image is rejected outright.
        let identity = KeyImage(encode_point(&EdwardsPoint::identity()));
        assert_eq!(
            verify(&s.message, &sig, &identity, &s.ring, &s.c_offset),
            Err(ClsagError::IdentityKeyImage)
        );
    }

    /// Signing with the wrong secret key is caught by verification rather than
    /// producing a signature that passes.
    #[test]
    fn signing_with_the_wrong_key_does_not_verify() {
        let mut s = setup(11, 5);
        s.p = scalar(1, 8); // one bit off the key that matches ring[5].dest
        let sig = s.sign();
        assert!(s.verify(&sig).is_err());
    }

    /// The signing index is bounds-checked.
    #[test]
    fn an_out_of_range_index_is_an_error() {
        let s = setup(4, 0);
        let e = sign(
            &s.message,
            &s.ring,
            4,
            &s.p,
            &s.z,
            &s.c_offset,
            &s.alpha,
            &s.fake_s,
        );
        assert_eq!(
            e,
            Err(ClsagError::IndexOutOfRange {
                index: 4,
                ring_size: 4
            })
        );
    }

    /// The domain blocks are the string followed by zeros, to 32 bytes.
    #[test]
    fn the_domain_blocks_are_padded() {
        let b = domain_block(DOMAIN_AGG_0);
        assert_eq!(&b[..11], b"CLSAG_agg_0");
        assert_eq!(&b[11..], &[0u8; 21]);
        assert_eq!(
            domain_block(DOMAIN_ROUND)[..11].to_vec(),
            b"CLSAG_round".to_vec()
        );
        // The three are distinct, which is the point of having them.
        assert_ne!(domain_block(DOMAIN_AGG_0), domain_block(DOMAIN_AGG_1));
        assert_ne!(domain_block(DOMAIN_AGG_0), domain_block(DOMAIN_ROUND));
    }

    /// `mu_P` and `mu_C` differ only by the domain block, and must not be
    /// equal — if they were, the key and commitment terms would collapse into
    /// one and the amount would no longer be bound.
    #[test]
    fn the_two_aggregation_scalars_differ() {
        let s = setup(11, 5);
        let sig = s.sign();
        let (mu_p, mu_c) = aggregation_hashes(&s.ring, &sig.i, &sig.d, &s.c_offset);
        assert_ne!(mu_p, mu_c);
        assert_ne!(mu_p, Scalar::ZERO);
        assert_ne!(mu_c, Scalar::ZERO);
    }

    /// Signing is deterministic given the same randomness, which is what lets
    /// these tests pin a signature at all.
    #[test]
    fn signing_is_deterministic_in_its_randomness() {
        let s = setup(11, 5);
        assert_eq!(s.sign(), s.sign());

        let mut other = setup(11, 5);
        other.alpha = scalar(4, 14);
        assert_ne!(s.sign(), other.sign());
        // ...and both still verify.
        other.verify(&other.sign()).expect("still valid");
    }
}
