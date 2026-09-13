//! Bulletproofs+: the range proof every RingCT output carries from HF 15
//! onward.
//!
//! `src/ringct/bulletproofs_plus.cc`, preprint <https://eprint.iacr.org/2020/735>.
//! `specs/02` §4.4.
//!
//! # `g` and `h` are swapped relative to the paper
//!
//! The reference says so at the top of the file and it is worth repeating,
//! because reading the preprint alongside this code is otherwise confusing:
//!
//! > In the signature constructions used in Monero, commitments to zero are
//! > treated as public keys against the curve group generator `G`. This means
//! > that amount commitments must use another generator `H` for values in order
//! > to show balance. The result is that the roles of `g` and `h` in the
//! > preprint are effectively swapped in this code, taking on the roles of `H`
//! > and `G`, respectively.
//!
//! # Everything is offset by 1/8
//!
//! Group elements are stored multiplied by `8^-1`, so the verifier can multiply
//! by 8 and land in the prime-order subgroup without a much costlier
//! multiplication by the group order. `V`, `A`, `A1`, `B`, `L` and `R` are all
//! stored that way. This is the same convention as `outPk.mask` under RCT type
//! 8 (`specs/02` §4.4), and forgetting it in one place produces a proof that
//! verifies nowhere.
//!
//! # Batching is not implemented
//!
//! The reference verifies a batch of proofs under random weights, collapsing
//! them into one multiscalar multiplication. That is worth doing when the
//! multiexp is Straus or Pippenger; here it is a plain sum, so a batch of `n`
//! costs the same either way and single-proof verification is what this
//! provides. The weight in the reference's equation is fixed at 1 below, which
//! is what a batch of one reduces to.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use std::sync::OnceLock;

use crate::ops::{decode_point, decode_scalar, encode_point, hash_to_ec_point, mul8};
use crate::types::{EcPoint, EcScalar};

/// Bits in each range. `N` in the reference.
const N: usize = 64;
/// `logN`.
const LOG_N: usize = 6;
/// `BULLETPROOF_PLUS_MAX_OUTPUTS`. Proofs aggregate up to this many values.
pub const MAX_OUTPUTS: usize = 16;
/// `maxN * maxM` — the number of each kind of generator.
const MAX_MN: usize = N * MAX_OUTPUTS;

/// `config::HASH_KEY_BULLETPROOF_PLUS_EXPONENT`.
const DOMAIN_EXPONENT: &[u8] = b"bulletproof_plus";
/// `config::HASH_KEY_BULLETPROOF_PLUS_TRANSCRIPT`.
const DOMAIN_TRANSCRIPT: &[u8] = b"bulletproof_plus_transcript";

/// A Bulletproof+ range proof.
///
/// `V` is **not** serialized on the wire — it is reconstructed from
/// `outPk.mask` — but it is part of the proof for every other purpose, so it
/// lives here.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BulletproofPlus {
    pub v: Vec<EcPoint>,
    pub a: EcPoint,
    pub a1: EcPoint,
    pub b: EcPoint,
    pub r1: EcScalar,
    pub s1: EcScalar,
    pub d1: EcScalar,
    pub l: Vec<EcPoint>,
    pub r: Vec<EcPoint>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BppError {
    #[error("no values to prove")]
    Empty,
    #[error("{0} values is more than the aggregation limit of {MAX_OUTPUTS}")]
    TooManyValues(usize),
    #[error("the value and mask vectors have different lengths")]
    LengthMismatch,
    #[error("a scalar is not canonical")]
    NonCanonicalScalar,
    #[error("a point in the proof does not decode")]
    BadPoint,
    #[error("L has {l} entries and R has {r}")]
    MismatchedRounds { l: usize, r: usize },
    #[error("a proof with {v} commitments should have {want} rounds, not {got}")]
    WrongProofSize { v: usize, want: usize, got: usize },
    #[error("a Fiat-Shamir challenge came out zero")]
    ZeroChallenge,
    #[error("the proof does not verify")]
    BadProof,
}

type Result<T> = std::result::Result<T, BppError>;

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

struct Generators {
    gi: Vec<EdwardsPoint>,
    hi: Vec<EdwardsPoint>,
    /// `initial_transcript`, the constant the Fiat-Shamir chain starts from.
    initial_transcript: [u8; 32],
}

fn generators() -> &'static Generators {
    static GENERATORS: OnceLock<Generators> = OnceLock::new();
    GENERATORS.get_or_init(|| {
        let mut gi = Vec::with_capacity(MAX_MN);
        let mut hi = Vec::with_capacity(MAX_MN);
        for i in 0..MAX_MN {
            hi.push(exponent(i * 2));
            gi.push(exponent(i * 2 + 1));
        }

        // The initial transcript is a *point*, used as 32 bytes of input.
        let h = crate::cn_fast_hash(DOMAIN_TRANSCRIPT);
        let p = hash_to_ec_point(&h).expect("the transcript domain hashes to a point");

        Generators {
            gi,
            hi,
            initial_transcript: encode_point(&p),
        }
    })
}

/// `get_exponent(H, idx)`.
///
/// Two hashes deep: the string is hashed to 32 bytes, and `hash_to_p3` hashes
/// *those* again before the curve map. Collapsing it to one would give valid
/// generators that agree with nothing.
fn exponent(idx: usize) -> EdwardsPoint {
    let mut buf = Vec::with_capacity(32 + DOMAIN_EXPONENT.len() + 10);
    buf.extend_from_slice(&crate::rct::H);
    buf.extend_from_slice(DOMAIN_EXPONENT);
    wow_serialize::varint::write_varint(&mut buf, idx as u64);

    let h = crate::cn_fast_hash(&buf);
    let p = hash_to_ec_point(&h).expect("a generator hashes to a point");
    assert!(
        p != EdwardsPoint::identity(),
        "exponent {idx} is the point at infinity"
    );
    p
}

// ---------------------------------------------------------------------------
// Scalar helpers
// ---------------------------------------------------------------------------

fn inv_eight() -> Scalar {
    Scalar::from(8u8).invert()
}

/// `transcript_update(t, x)` and its two-argument form.
fn transcript_update(transcript: &mut [u8; 32], parts: &[&[u8; 32]]) -> Scalar {
    let mut buf = Vec::with_capacity(32 * (1 + parts.len()));
    buf.extend_from_slice(transcript);
    for p in parts {
        buf.extend_from_slice(*p);
    }
    let s = crate::ops::hash_to_scalar_dalek(&buf);
    *transcript = s.to_bytes();
    s
}

/// `vector_of_scalar_powers(x, n)` = `(1, x, x^2, ..., x^{n-1})`.
fn scalar_powers(x: &Scalar, n: usize) -> Vec<Scalar> {
    let mut v = Vec::with_capacity(n);
    v.push(Scalar::ONE);
    for i in 1..n {
        v.push(if i == 1 { *x } else { v[i - 1] * x });
    }
    v
}

/// `sum_of_even_powers(x, n)` = `x^2 + x^4 + ... + x^n`, `n` a power of two.
fn sum_of_even_powers(x: &Scalar, n: usize) -> Scalar {
    debug_assert!(n > 0 && n.is_power_of_two());
    let mut x1 = x * x;
    let mut res = x1;
    let mut n = n;
    while n > 2 {
        res = x1 * res + res;
        x1 = x1 * x1;
        n /= 2;
    }
    res
}

/// `sum_of_scalar_powers(x, n)` = `x + x^2 + ... + x^n`.
fn sum_of_scalar_powers(x: &Scalar, n: usize) -> Scalar {
    debug_assert!(n > 0);
    if n == 1 {
        return *x;
    }
    let mut res = Scalar::ONE;
    let mut prev = *x;
    for i in 1..=n {
        if i > 1 {
            prev *= x;
        }
        res += prev;
    }
    res - Scalar::ONE
}

/// `weighted_inner_product(a, b, y)` = `sum a_i * b_i * y^{i+1}`.
fn weighted_inner_product(a: &[Scalar], b: &[Scalar], y: &Scalar) -> Scalar {
    debug_assert_eq!(a.len(), b.len());
    let mut res = Scalar::ZERO;
    let mut y_power = Scalar::ONE;
    for (ai, bi) in a.iter().zip(b.iter()) {
        y_power *= y;
        res += ai * bi * y_power;
    }
    res
}

/// `hadamard_fold(v, a, b)`: `v[n] = a*v[n] + b*v[sz+n]`, halving the vector.
fn hadamard_fold(v: &mut Vec<EdwardsPoint>, a: &Scalar, b: &Scalar) {
    debug_assert_eq!(v.len() % 2, 0);
    let sz = v.len() / 2;
    for n in 0..sz {
        v[n] = a * v[n] + b * v[sz + n];
    }
    v.truncate(sz);
}

/// The number of aggregated slots: the first power of two at or above `count`.
fn padded_count(count: usize) -> Result<(usize, usize)> {
    if count == 0 {
        return Err(BppError::Empty);
    }
    let mut log_m = 0usize;
    let mut m = 1usize;
    while m <= MAX_OUTPUTS && m < count {
        log_m += 1;
        m = 1 << log_m;
    }
    if m > MAX_OUTPUTS {
        return Err(BppError::TooManyValues(count));
    }
    Ok((m, log_m))
}

// ---------------------------------------------------------------------------
// Proving
// ---------------------------------------------------------------------------

/// Prove that each of `values` lies in `[0, 2^64)`, hiding them behind
/// `masks`.
///
/// `rand` supplies the proof's randomness. The reference draws it internally;
/// here it is a parameter so a test can pin a proof. Callers pass a
/// cryptographically secure source — **the blinding values are what hide the
/// amounts**, and a predictable `rand` reveals every one of them.
pub fn prove(
    values: &[u64],
    masks: &[Scalar],
    rand: &mut dyn FnMut() -> Scalar,
) -> Result<BulletproofPlus> {
    if values.len() != masks.len() {
        return Err(BppError::LengthMismatch);
    }
    let (m, log_m) = padded_count(values.len())?;
    let mn = m * N;
    let log_mn = log_m + LOG_N;

    let gens = generators();
    let h_point = crate::rct::h_point();
    let inv8 = inv_eight();

    // V_j = (gamma_j/8)*G + (v_j/8)*H.
    let v: Vec<EdwardsPoint> = values
        .iter()
        .zip(masks.iter())
        .map(|(val, gamma)| {
            (gamma * inv8) * ED25519_BASEPOINT_POINT + (Scalar::from(*val) * inv8) * h_point
        })
        .collect();
    let v_bytes: Vec<[u8; 32]> = v.iter().map(encode_point).collect();

    // Bit decomposition, padded to MN. aL is the bit, aR is the bit minus one.
    let minus_one = -Scalar::ONE;
    let minus_inv8 = -inv8;
    let mut a_l = vec![Scalar::ZERO; mn];
    let mut a_r = vec![Scalar::ZERO; mn];
    let mut a_l8 = vec![Scalar::ZERO; mn];
    let mut a_r8 = vec![Scalar::ZERO; mn];
    for j in 0..m {
        for i in 0..N {
            let bit = j < values.len() && (values[j] >> i) & 1 == 1;
            if bit {
                a_l[j * N + i] = Scalar::ONE;
                a_l8[j * N + i] = inv8;
            } else {
                a_r[j * N + i] = minus_one;
                a_r8[j * N + i] = minus_inv8;
            }
        }
    }

    // The reference restarts with fresh randomness if a challenge comes out
    // zero. That has probability about 2^-252 per draw, so the bound is
    // generous; it exists so a broken `rand` cannot spin forever.
    for _ in 0..8 {
        match attempt(
            &v,
            &v_bytes,
            &a_l,
            &a_r,
            &a_l8,
            &a_r8,
            masks,
            values.len(),
            m,
            mn,
            log_mn,
            gens,
            &h_point,
            rand,
        ) {
            Err(BppError::ZeroChallenge) => continue,
            other => return other,
        }
    }
    Err(BppError::ZeroChallenge)
}

#[allow(
    clippy::too_many_arguments,
    reason = "one attempt of bulletproof_plus_PROVE"
)]
fn attempt(
    v: &[EdwardsPoint],
    v_bytes: &[[u8; 32]],
    a_l: &[Scalar],
    a_r: &[Scalar],
    a_l8: &[Scalar],
    a_r8: &[Scalar],
    masks: &[Scalar],
    n_values: usize,
    m: usize,
    mn: usize,
    log_mn: usize,
    gens: &Generators,
    h_point: &EdwardsPoint,
    rand: &mut dyn FnMut() -> Scalar,
) -> Result<BulletproofPlus> {
    let inv8 = inv_eight();

    let mut transcript = gens.initial_transcript;
    let v_hash = {
        let mut buf = Vec::with_capacity(v_bytes.len() * 32);
        for b in v_bytes {
            buf.extend_from_slice(b);
        }
        crate::ops::hash_to_scalar_dalek(&buf).to_bytes()
    };
    transcript_update(&mut transcript, &[&v_hash]);

    // A, the commitment to the bit vectors.
    let alpha = rand();
    let mut pre_a = EdwardsPoint::identity();
    for i in 0..mn {
        pre_a += a_l8[i] * gens.gi[i] + a_r8[i] * gens.hi[i];
    }
    let a_point = pre_a + (alpha * inv8) * ED25519_BASEPOINT_POINT;
    let a_bytes = encode_point(&a_point);

    let y = transcript_update(&mut transcript, &[&a_bytes]);
    if y == Scalar::ZERO {
        return Err(BppError::ZeroChallenge);
    }
    // z is hash_to_scalar(y), and it *replaces* the transcript rather than
    // extending it.
    let z = crate::ops::hash_to_scalar_dalek(&y.to_bytes());
    if z == Scalar::ZERO {
        return Err(BppError::ZeroChallenge);
    }
    transcript = z.to_bytes();
    let z_squared = z * z;

    // d[j*N+i] = z^(2(j+1)) * 2^i.
    let two = Scalar::from(2u8);
    let mut d = vec![Scalar::ZERO; mn];
    d[0] = z_squared;
    for i in 1..N {
        d[i] = d[i - 1] * two;
    }
    for j in 1..m {
        for i in 0..N {
            d[j * N + i] = d[(j - 1) * N + i] * z_squared;
        }
    }

    let y_powers = scalar_powers(&y, mn + 2);

    // The inner-product inputs.
    let mut aprime: Vec<Scalar> = a_l.iter().map(|x| x - z).collect();
    let mut bprime: Vec<Scalar> = (0..mn)
        .map(|i| a_r[i] + z + d[i] * y_powers[mn - i])
        .collect();

    let mut alpha1 = alpha;
    let mut temp = Scalar::ONE;
    for gamma in masks.iter().take(n_values) {
        temp *= z_squared;
        alpha1 += y_powers[mn + 1] * temp * gamma;
    }

    let mut gprime: Vec<EdwardsPoint> = gens.gi[..mn].to_vec();
    let mut hprime: Vec<EdwardsPoint> = gens.hi[..mn].to_vec();

    let yinv = y.invert();
    let mut yinvpow = vec![Scalar::ONE; mn];
    for i in 1..mn {
        yinvpow[i] = yinvpow[i - 1] * yinv;
    }

    let mut l_vec = Vec::with_capacity(log_mn);
    let mut r_vec = Vec::with_capacity(log_mn);
    let mut nprime = mn;

    while nprime > 1 {
        nprime /= 2;

        let c_l = weighted_inner_product(&aprime[..nprime], &bprime[nprime..], &y);
        let scaled: Vec<Scalar> = aprime[nprime..]
            .iter()
            .map(|a| a * y_powers[nprime])
            .collect();
        let c_r = weighted_inner_product(&scaled, &bprime[..nprime], &y);

        let d_l = rand();
        let d_r = rand();

        let l = compute_lr(
            nprime,
            &yinvpow[nprime],
            &gprime[nprime..],
            &hprime[..nprime],
            &aprime[..nprime],
            &bprime[nprime..],
            &c_l,
            &d_l,
            h_point,
        );
        let r = compute_lr(
            nprime,
            &y_powers[nprime],
            &gprime[..nprime],
            &hprime[nprime..],
            &aprime[nprime..],
            &bprime[..nprime],
            &c_r,
            &d_r,
            h_point,
        );
        let l_bytes = encode_point(&l);
        let r_bytes = encode_point(&r);
        l_vec.push(l);
        r_vec.push(r);

        let challenge = transcript_update(&mut transcript, &[&l_bytes, &r_bytes]);
        if challenge == Scalar::ZERO {
            return Err(BppError::ZeroChallenge);
        }
        let challenge_inv = challenge.invert();

        hadamard_fold(&mut gprime, &challenge_inv, &(yinvpow[nprime] * challenge));
        hadamard_fold(&mut hprime, &challenge, &challenge_inv);

        let t = challenge_inv * y_powers[nprime];
        aprime = (0..nprime)
            .map(|i| aprime[i] * challenge + aprime[nprime + i] * t)
            .collect();
        bprime = (0..nprime)
            .map(|i| bprime[i] * challenge_inv + bprime[nprime + i] * challenge)
            .collect();

        alpha1 += d_l * (challenge * challenge) + d_r * (challenge_inv * challenge_inv);
    }

    // The final round.
    let r_s = rand();
    let s_s = rand();
    let d_s = rand();
    let eta = rand();

    let a1 = (r_s * inv8) * gprime[0]
        + (s_s * inv8) * hprime[0]
        + (d_s * inv8) * ED25519_BASEPOINT_POINT
        + ((r_s * y * bprime[0] + s_s * y * aprime[0]) * inv8) * h_point;

    let b_point = (eta * inv8) * ED25519_BASEPOINT_POINT + (r_s * y * s_s * inv8) * h_point;

    let a1_bytes = encode_point(&a1);
    let b_bytes = encode_point(&b_point);
    let e = transcript_update(&mut transcript, &[&a1_bytes, &b_bytes]);
    if e == Scalar::ZERO {
        return Err(BppError::ZeroChallenge);
    }

    let r1 = aprime[0] * e + r_s;
    let s1 = bprime[0] * e + s_s;
    let d1 = d_s * e + eta + alpha1 * (e * e);

    Ok(BulletproofPlus {
        v: v.iter().map(|p| EcPoint(encode_point(p))).collect(),
        a: EcPoint(a_bytes),
        a1: EcPoint(a1_bytes),
        b: EcPoint(b_bytes),
        r1: EcScalar(r1.to_bytes()),
        s1: EcScalar(s1.to_bytes()),
        d1: EcScalar(d1.to_bytes()),
        l: l_vec.iter().map(|p| EcPoint(encode_point(p))).collect(),
        r: r_vec.iter().map(|p| EcPoint(encode_point(p))).collect(),
    })
}

/// `compute_LR`. Every scalar is offset by `1/8`, like the elements it builds.
#[allow(clippy::too_many_arguments, reason = "compute_LR takes them")]
fn compute_lr(
    size: usize,
    y: &Scalar,
    g: &[EdwardsPoint],
    h: &[EdwardsPoint],
    a: &[Scalar],
    b: &[Scalar],
    c: &Scalar,
    d: &Scalar,
    h_point: &EdwardsPoint,
) -> EdwardsPoint {
    let inv8 = inv_eight();
    let mut acc = EdwardsPoint::identity();
    for i in 0..size {
        acc += (a[i] * y * inv8) * g[i];
        acc += (b[i] * inv8) * h[i];
    }
    acc += (c * inv8) * h_point;
    acc += (d * inv8) * ED25519_BASEPOINT_POINT;
    acc
}

// ---------------------------------------------------------------------------
// Verifying
// ---------------------------------------------------------------------------

/// Verify one proof.
pub fn verify(proof: &BulletproofPlus) -> Result<()> {
    let gens = generators();
    let h_point = crate::rct::h_point();

    let r1 = decode_scalar(&proof.r1.0).ok_or(BppError::NonCanonicalScalar)?;
    let s1 = decode_scalar(&proof.s1.0).ok_or(BppError::NonCanonicalScalar)?;
    let d1 = decode_scalar(&proof.d1.0).ok_or(BppError::NonCanonicalScalar)?;

    if proof.v.is_empty() {
        return Err(BppError::Empty);
    }
    if proof.l.len() != proof.r.len() {
        return Err(BppError::MismatchedRounds {
            l: proof.l.len(),
            r: proof.r.len(),
        });
    }
    if proof.l.is_empty() {
        return Err(BppError::Empty);
    }

    // Re-derive the challenges.
    let mut transcript = gens.initial_transcript;
    let v_hash = {
        let mut buf = Vec::with_capacity(proof.v.len() * 32);
        for p in &proof.v {
            buf.extend_from_slice(&p.0);
        }
        crate::ops::hash_to_scalar_dalek(&buf).to_bytes()
    };
    transcript_update(&mut transcript, &[&v_hash]);

    let y = transcript_update(&mut transcript, &[&proof.a.0]);
    if y == Scalar::ZERO {
        return Err(BppError::ZeroChallenge);
    }
    let z = crate::ops::hash_to_scalar_dalek(&y.to_bytes());
    if z == Scalar::ZERO {
        return Err(BppError::ZeroChallenge);
    }
    transcript = z.to_bytes();

    let (m, log_m) = padded_count(proof.v.len())?;
    let rounds = log_m + LOG_N;
    if proof.l.len() != rounds {
        return Err(BppError::WrongProofSize {
            v: proof.v.len(),
            want: rounds,
            got: proof.l.len(),
        });
    }
    let mn = m * N;

    let mut challenges = Vec::with_capacity(rounds);
    for j in 0..rounds {
        let c = transcript_update(&mut transcript, &[&proof.l[j].0, &proof.r[j].0]);
        if c == Scalar::ZERO {
            return Err(BppError::ZeroChallenge);
        }
        challenges.push(c);
    }
    let e = transcript_update(&mut transcript, &[&proof.a1.0, &proof.b.0]);
    if e == Scalar::ZERO {
        return Err(BppError::ZeroChallenge);
    }

    let challenges_inv: Vec<Scalar> = challenges.iter().map(|c| c.invert()).collect();
    let yinv = y.invert();

    // Rescale the stored elements into the prime-order subgroup.
    let mul8_of = |p: &EcPoint| -> Result<EdwardsPoint> {
        Ok(mul8(&decode_point(&p.0).ok_or(BppError::BadPoint)?))
    };
    let v8: Vec<EdwardsPoint> = proof.v.iter().map(mul8_of).collect::<Result<_>>()?;
    let l8: Vec<EdwardsPoint> = proof.l.iter().map(mul8_of).collect::<Result<_>>()?;
    let r8: Vec<EdwardsPoint> = proof.r.iter().map(mul8_of).collect::<Result<_>>()?;
    let a8 = mul8_of(&proof.a)?;
    let a1_8 = mul8_of(&proof.a1)?;
    let b8 = mul8_of(&proof.b)?;

    // y^MN and y^(MN+1).
    let mut y_mn = y;
    let mut t = mn;
    while t > 1 {
        y_mn = y_mn * y_mn;
        t /= 2;
    }
    let y_mn_1 = y_mn * y;

    let e_squared = e * e;
    let z_squared = z * z;

    // The single multiscalar multiplication, accumulated directly.
    let mut acc = EdwardsPoint::identity();

    // V_j: -e^2 * y^(MN+1) * z^(2(j+1))
    let mut temp = -e_squared * y_mn_1;
    for vj in &v8 {
        temp *= z_squared;
        acc += temp * vj;
    }

    // B: -1;  A1: -e;  A: -e^2
    acc += -Scalar::ONE * b8;
    acc += -e * a1_8;
    let minus_e_squared = -e_squared;
    acc += minus_e_squared * a8;

    // G: d1
    acc += d1 * ED25519_BASEPOINT_POINT;

    // d[j*N+i] = z^(2(j+1)) * 2^i
    let mut d = vec![Scalar::ZERO; mn];
    d[0] = z_squared;
    for i in 1..N {
        d[i] = d[i - 1] + d[i - 1];
    }
    for j in 1..m {
        for i in 0..N {
            d[j * N + i] = d[(j - 1) * N + i] * z_squared;
        }
    }

    // H: r1*y*s1 + e^2*( y^(MN+1)*z*sum(d) + (z^2-z)*sum(y) )
    let two_sixty_four_minus_one = {
        let mut x = Scalar::from(2u8);
        for _ in 0..6 {
            x = x * x;
        }
        x - Scalar::ONE
    };
    let sum_d = two_sixty_four_minus_one * sum_of_even_powers(&z, 2 * m);
    let sum_y = sum_of_scalar_powers(&y, mn);
    let h_scalar = r1 * y * s1 + e_squared * (y_mn_1 * z * sum_d + (z_squared - z) * sum_y);
    acc += h_scalar * h_point;

    // The challenge products, indexed by the binary decomposition of i.
    let mut cache = vec![Scalar::ZERO; 1 << rounds];
    cache[0] = challenges_inv[0];
    cache[1] = challenges[0];
    for j in 1..rounds {
        let slots = 1usize << (j + 1);
        // Downward in steps of two, because each pair reads `cache[s / 2]`
        // before either half of it is overwritten.
        let mut s = slots;
        while s > 0 {
            s -= 1;
            cache[s] = cache[s / 2] * challenges[j];
            cache[s - 1] = cache[s / 2] * challenges_inv[j];
            s -= 1;
        }
    }

    let mut e_r1_y = e * r1;
    let e_s1 = e * s1;
    let e_squared_z = e_squared * z;
    let minus_e_squared_z = -e_squared_z;
    let mut minus_e_squared_y = -e_squared * y_mn;

    for i in 0..mn {
        let g_scalar = e_r1_y * cache[i] + e_squared_z;
        let mut h_scalar = e_s1 * cache[(!i) & (mn - 1)] + minus_e_squared_z;
        h_scalar += minus_e_squared_y * d[i];

        acc += g_scalar * gens.gi[i];
        acc += h_scalar * gens.hi[i];

        e_r1_y *= yinv;
        minus_e_squared_y *= yinv;
    }

    // L_j: -e^2 * c_j^2;  R_j: -e^2 * c_j^-2
    for j in 0..rounds {
        acc += (challenges[j] * challenges[j] * minus_e_squared) * l8[j];
        acc += (challenges_inv[j] * challenges_inv[j] * minus_e_squared) * r8[j];
    }

    if acc == EdwardsPoint::identity() {
        Ok(())
    } else {
        Err(BppError::BadProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic stand-in for `skGen`, so a proof can be reproduced.
    ///
    /// This is emphatically not what a caller should pass: the blinding values
    /// are what hide the amounts.
    fn counter_rand(seed: u64) -> impl FnMut() -> Scalar {
        let mut n = seed;
        move || {
            n = n
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&n.to_le_bytes());
            b[8..16].copy_from_slice(&n.rotate_left(17).to_le_bytes());
            b[16..24].copy_from_slice(&n.rotate_left(33).to_le_bytes());
            Scalar::from_bytes_mod_order(b)
        }
    }

    fn masks(n: usize, seed: u64) -> Vec<Scalar> {
        let mut r = counter_rand(seed);
        (0..n).map(|_| r()).collect()
    }

    /// The claim that matters: a proof of a valid range verifies.
    #[test]
    fn a_proof_verifies() {
        let values = [1_000_000u64];
        let gamma = masks(1, 99);
        let mut r = counter_rand(1);
        let proof = prove(&values, &gamma, &mut r).expect("prove");
        verify(&proof).expect("verify");

        assert_eq!(proof.l.len(), 6, "one value needs logN rounds");
        assert_eq!(proof.r.len(), 6);
        assert_eq!(proof.v.len(), 1);
    }

    /// The edges of the range, which is what the proof is about.
    #[test]
    fn the_range_endpoints_prove() {
        for v in [0u64, 1, 2, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let gamma = masks(1, 7);
            let mut r = counter_rand(v ^ 0x5a5a);
            let proof = prove(&[v], &gamma, &mut r).unwrap_or_else(|e| panic!("prove {v}: {e}"));
            verify(&proof).unwrap_or_else(|e| panic!("verify {v}: {e}"));
        }
    }

    /// Aggregation: two, three and sixteen values in one proof. A
    /// non-power-of-two count pads up, which is why three costs the same
    /// rounds as four.
    #[test]
    fn it_aggregates() {
        for n in [1usize, 2, 3, 4, 8, 16] {
            let values: Vec<u64> = (0..n).map(|i| (i as u64 + 1) * 1_000).collect();
            let gamma = masks(n, 40 + n as u64);
            let mut r = counter_rand(n as u64);
            let proof =
                prove(&values, &gamma, &mut r).unwrap_or_else(|e| panic!("prove n={n}: {e}"));
            verify(&proof).unwrap_or_else(|e| panic!("verify n={n}: {e}"));

            let log_m = n.next_power_of_two().trailing_zeros() as usize;
            assert_eq!(proof.l.len(), 6 + log_m, "n={n}");
            assert_eq!(proof.v.len(), n, "n={n}");
        }
    }

    /// Seventeen values is past the aggregation limit.
    #[test]
    fn it_refuses_too_many_values() {
        let values = vec![1u64; 17];
        let gamma = masks(17, 3);
        let mut r = counter_rand(3);
        assert_eq!(
            prove(&values, &gamma, &mut r),
            Err(BppError::TooManyValues(17))
        );
    }

    /// The commitments the proof carries are the ones the amounts imply, so a
    /// verifier can tie the proof to `outPk.mask`. `V` is stored as `C/8`.
    #[test]
    fn the_commitments_are_the_amounts() {
        let values = [42u64, 7];
        let gamma = masks(2, 11);
        let mut r = counter_rand(5);
        let proof = prove(&values, &gamma, &mut r).expect("prove");

        for (i, v) in values.iter().enumerate() {
            // 8 * V[i] is the ordinary Pedersen commitment.
            let stored = decode_point(&proof.v[i].0).expect("decodes");
            let full = EcPoint(encode_point(&mul8(&stored)));
            assert_eq!(full, crate::rct::commit(*v, &gamma[i]), "output {i}");
        }
    }

    /// Tampering with any element of the proof breaks it. These are the checks
    /// that stand between the chain and an inflated output.
    #[test]
    fn a_tampered_proof_fails() {
        let gamma = masks(1, 13);
        let mut r = counter_rand(21);
        let proof = prove(&[500u64], &gamma, &mut r).expect("prove");
        verify(&proof).expect("the untampered proof verifies");

        let mut p = proof.clone();
        p.r1.0[0] ^= 1;
        assert_eq!(verify(&p), Err(BppError::BadProof), "r1");

        let mut p = proof.clone();
        p.s1.0[0] ^= 1;
        assert_eq!(verify(&p), Err(BppError::BadProof), "s1");

        let mut p = proof.clone();
        p.d1.0[0] ^= 1;
        assert_eq!(verify(&p), Err(BppError::BadProof), "d1");

        // A, A1 and B all feed the transcript, so a change there moves every
        // later challenge as well.
        for field in 0..3 {
            let mut p = proof.clone();
            match field {
                0 => p.a = flip(&p.a),
                1 => p.a1 = flip(&p.a1),
                _ => p.b = flip(&p.b),
            }
            assert!(verify(&p).is_err(), "point field {field}");
        }

        for j in 0..proof.l.len() {
            let mut p = proof.clone();
            p.l[j] = flip(&p.l[j]);
            assert!(verify(&p).is_err(), "L[{j}]");

            let mut p = proof.clone();
            p.r[j] = flip(&p.r[j]);
            assert!(verify(&p).is_err(), "R[{j}]");
        }
    }

    /// Replace a point with a different valid one, rather than corrupting the
    /// encoding, so the failure is the proof and not the decoding.
    fn flip(p: &EcPoint) -> EcPoint {
        let q = decode_point(&p.0).expect("decodes") + ED25519_BASEPOINT_POINT;
        EcPoint(encode_point(&q))
    }

    /// Substituting the commitment invalidates the proof. Without this a proof
    /// of one amount could be presented for another.
    #[test]
    fn a_substituted_commitment_fails() {
        let gamma = masks(1, 17);
        let mut r = counter_rand(23);
        let mut proof = prove(&[1_000u64], &gamma, &mut r).expect("prove");

        let other = crate::rct::commit(2_000, &gamma[0]);
        let eighth = Scalar::from(8u8).invert() * decode_point(&other.0).expect("decodes");
        proof.v[0] = EcPoint(encode_point(&eighth));
        assert!(verify(&proof).is_err());
    }

    /// A proof with the wrong number of rounds for its commitment count is
    /// rejected on shape, before any arithmetic.
    #[test]
    fn the_proof_shape_is_checked() {
        let gamma = masks(1, 29);
        let mut r = counter_rand(31);
        let proof = prove(&[9u64], &gamma, &mut r).expect("prove");

        let mut p = proof.clone();
        p.l.pop();
        assert_eq!(verify(&p), Err(BppError::MismatchedRounds { l: 5, r: 6 }));

        let mut p = proof.clone();
        p.l.pop();
        p.r.pop();
        assert_eq!(
            verify(&p),
            Err(BppError::WrongProofSize {
                v: 1,
                want: 6,
                got: 5
            })
        );

        let mut p = proof.clone();
        p.v.clear();
        assert_eq!(verify(&p), Err(BppError::Empty));

        let mut p = proof;
        p.r1 = EcScalar([0xff; 32]);
        assert_eq!(verify(&p), Err(BppError::NonCanonicalScalar));
    }

    /// Different randomness gives a different proof, and both verify. Same
    /// randomness gives the same proof, which is what makes these tests
    /// reproducible.
    #[test]
    fn proving_is_deterministic_in_its_randomness() {
        let gamma = masks(1, 37);
        let a = prove(&[77u64], &gamma, &mut counter_rand(1)).expect("prove");
        let b = prove(&[77u64], &gamma, &mut counter_rand(1)).expect("prove");
        let c = prove(&[77u64], &gamma, &mut counter_rand(2)).expect("prove");

        assert_eq!(a, b);
        assert_ne!(a, c);
        verify(&c).expect("the other proof verifies too");
    }

    /// Proofs do not transplant: swapping halves of two proofs of the same
    /// shape fails.
    #[test]
    fn proofs_do_not_mix() {
        let g1 = masks(1, 41);
        let g2 = masks(1, 43);
        let p1 = prove(&[1u64], &g1, &mut counter_rand(51)).expect("prove");
        let p2 = prove(&[2u64], &g2, &mut counter_rand(53)).expect("prove");

        let mut mixed = p1.clone();
        mixed.v = p2.v.clone();
        assert!(verify(&mixed).is_err());

        let mut mixed = p1;
        mixed.l = p2.l.clone();
        mixed.r = p2.r;
        assert!(verify(&mixed).is_err());
    }

    /// The generators are distinct, non-identity, and derived the two-hash way.
    /// A single hash would give valid-looking generators that agree with
    /// nothing.
    #[test]
    fn the_generators_are_derived_twice() {
        let g = generators();
        assert_eq!(g.gi.len(), MAX_MN);
        assert_eq!(g.hi.len(), MAX_MN);
        assert_ne!(g.gi[0], g.hi[0]);
        assert_ne!(g.gi[0], g.gi[1]);

        // Hi[0] is exponent(0): hash the string, then hash again inside
        // hash_to_ec.
        let mut buf = Vec::new();
        buf.extend_from_slice(&crate::rct::H);
        buf.extend_from_slice(b"bulletproof_plus");
        wow_serialize::varint::write_varint(&mut buf, 0);
        let once = crate::cn_fast_hash(&buf);
        assert_eq!(g.hi[0], hash_to_ec_point(&once).expect("a point"));
        // And the single-hash version is a different point.
        assert_ne!(
            g.hi[0],
            decode_point(&crate::ops::hash_to_point(&once).0).expect("decodes")
        );
    }

    /// The scalar helpers, against direct summation.
    #[test]
    fn the_scalar_helpers() {
        let x = Scalar::from(3u8);

        // x^2 + x^4 = 9 + 81 = 90
        assert_eq!(sum_of_even_powers(&x, 4), Scalar::from(90u8));
        assert_eq!(sum_of_even_powers(&x, 2), Scalar::from(9u8));

        // x + x^2 + x^3 = 3 + 9 + 27 = 39
        assert_eq!(sum_of_scalar_powers(&x, 3), Scalar::from(39u8));
        assert_eq!(sum_of_scalar_powers(&x, 1), x);

        // Against a direct sum, at the sizes the verifier actually uses.
        for n in [64usize, 128, 256] {
            let mut want = Scalar::ZERO;
            let mut p = Scalar::ONE;
            for _ in 0..n {
                p *= x;
                want += p;
            }
            assert_eq!(sum_of_scalar_powers(&x, n), want, "n={n}");
        }

        let p = scalar_powers(&x, 5);
        assert_eq!(p[0], Scalar::ONE);
        assert_eq!(p[4], Scalar::from(81u8));

        assert_eq!(
            weighted_inner_product(
                &[Scalar::from(2u8), Scalar::from(3u8)],
                &[Scalar::from(5u8), Scalar::from(7u8)],
                &Scalar::from(10u8)
            ),
            // 2*5*10 + 3*7*100 = 100 + 2100
            Scalar::from(2200u32)
        );
    }

    /// The padding rule: a count pads up to the next power of two, capped at
    /// the aggregation limit.
    #[test]
    fn the_padding_rule() {
        assert_eq!(padded_count(1), Ok((1, 0)));
        assert_eq!(padded_count(2), Ok((2, 1)));
        assert_eq!(padded_count(3), Ok((4, 2)));
        assert_eq!(padded_count(16), Ok((16, 4)));
        assert_eq!(padded_count(17), Err(BppError::TooManyValues(17)));
        assert_eq!(padded_count(0), Err(BppError::Empty));
    }
}
