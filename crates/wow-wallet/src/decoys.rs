//! Decoy selection: choosing the ring members that hide a real spend.
//!
//! `specs/12` §4.3, `gamma_picker` in `wallet2.cpp`.
//!
//! # This is a privacy mechanism, not a consensus rule
//!
//! A node accepts any ring of the right size. Nothing here can make a
//! transaction invalid, and that is exactly what makes it dangerous: a wallet
//! that picks decoys from the wrong distribution produces transactions that
//! work perfectly and are distinguishable from every other wallet's, which
//! deanonymises its user and everyone who happens to be in a ring with them.
//!
//! # The constants are not Monero's
//!
//! The shape and scale are, but three derived values are not, because
//! `DIFFICULTY_TARGET_V2` is 300 seconds here and 120 on Monero:
//!
//! | | Wownero | Monero |
//! |---|---|---|
//! | `DEFAULT_UNLOCK_TIME` = 4 × target | 1,200 s | 480 s |
//! | `RECENT_SPEND_WINDOW` = 15 × target | 4,500 s | 1,800 s |
//! | `blocks_in_a_year` = 86400 × 365 ÷ target | 105,120 | 262,800 |
//!
//! `specs/12` §4.3 calls this out and it is worth repeating: using Monero's
//! numbers would make this wallet's output ages visibly wrong.
//!
//! # Where the randomness comes from
//!
//! [`RandomSource`] is a trait so the tests can be deterministic, and because a
//! library has no business deciding where a user's entropy comes from. The
//! binaries seed [`wow_crypto::random::Rng`] from the OS. Passing something
//! predictable here does not produce an invalid transaction — it produces a
//! valid one whose real spend can be picked out.

/// `GAMMA_SHAPE`.
pub const GAMMA_SHAPE: f64 = 19.28;
/// `GAMMA_SCALE`, as the reference writes it: `1 / 1.61`.
pub const GAMMA_SCALE: f64 = 1.0 / 1.61;

/// `DIFFICULTY_TARGET_V2`. 300 seconds, not Monero's 120.
pub const DIFFICULTY_TARGET: u64 = 300;
/// `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`.
pub const SPENDABLE_AGE: u64 = 4;
/// `DEFAULT_UNLOCK_TIME` = 4 × 300.
pub const DEFAULT_UNLOCK_TIME: f64 = (SPENDABLE_AGE * DIFFICULTY_TARGET) as f64;
/// `RECENT_SPEND_WINDOW` = 15 × 300.
pub const RECENT_SPEND_WINDOW: u64 = 15 * DIFFICULTY_TARGET;
/// `blocks_in_a_year` = 86400 × 365 ÷ 300.
pub const BLOCKS_IN_A_YEAR: usize = (86_400 * 365 / DIFFICULTY_TARGET) as usize;

/// The ring size from HF 9, enforced **exactly** from HF 15 (`specs/12` §4.3).
pub const RING_SIZE: usize = 22;

/// Where random numbers come from.
pub trait RandomSource {
    /// A uniform 64-bit value.
    fn next_u64(&mut self) -> u64;

    /// `crypto::rand_idx(n)`: uniform below `n`.
    ///
    /// The reference takes a plain modulo, and so does this. The bias that
    /// introduces is on the order of `n / 2^64` — for the millions of outputs
    /// this is called with, around one part in a trillion, which is not
    /// something an observer can see. Diverging here would buy nothing and
    /// cost the ability to say this matches.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next_u64() % n
    }

    /// A uniform double in `(0, 1)`.
    ///
    /// Open at **both** ends, which takes a little care: `ln(0)` is `-inf` and
    /// the gamma sampler takes logarithms.
    ///
    /// 52 bits rather than the 53 an `f64` mantissa holds. With 53, the top
    /// value is `(2^53 - 1 + 0.5) / 2^53`, and the numerator needs a 54th bit
    /// — so it rounds up and the quotient is exactly `1.0`. At 52 bits the
    /// `+ 0.5` is exact and the result stays strictly below one.
    fn unit(&mut self) -> f64 {
        const SCALE: f64 = 4_503_599_627_370_496.0; // 2^52
        let bits = (self.next_u64() >> 12) as f64;
        (bits + 0.5) / SCALE
    }
}

impl RandomSource for wow_crypto::random::Rng {
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_le_bytes(b)
    }
}

/// A standard normal, by Box–Muller.
fn normal(rng: &mut dyn RandomSource) -> f64 {
    let u1 = rng.unit();
    let u2 = rng.unit();
    (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
}

/// A gamma variate, by Marsaglia–Tsang.
///
/// `std::gamma_distribution<double>(shape, scale)` in the reference. The exact
/// samples cannot match — they are random — but the distribution must, which is
/// the only thing that matters for indistinguishability.
///
/// Valid for `shape >= 1`, which 19.28 is.
fn gamma(rng: &mut dyn RandomSource, shape: f64, scale: f64) -> f64 {
    debug_assert!(shape >= 1.0, "Marsaglia-Tsang needs shape >= 1");
    let d = shape - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();

    loop {
        let x = normal(rng);
        let v = (1.0 + c * x).powi(3);
        if v <= 0.0 {
            continue;
        }
        let u = rng.unit();
        let x2 = x * x;
        if u < 1.0 - 0.033_1 * x2 * x2 {
            return d * v * scale;
        }
        if u.ln() < 0.5 * x2 + d * (1.0 - v + v.ln()) {
            return d * v * scale;
        }
    }
}

/// The gamma picker: chooses a global output index weighted by how old the
/// output is.
#[derive(Debug)]
pub struct GammaPicker<'a> {
    /// `rct_offsets`: the cumulative count of RingCT outputs per block, from
    /// `get_output_distribution`.
    offsets: &'a [u64],
    /// One past the newest block considered: the three youngest are dropped,
    /// because an output there is not spendable yet.
    end: usize,
    num_rct_outputs: u64,
    average_output_time: f64,
    shape: f64,
    scale: f64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecoyError {
    #[error("the output distribution has {0} blocks, too few to pick from")]
    NotEnoughBlocks(usize),
    #[error("the chain has no RingCT outputs to pick from")]
    NoOutputs,
    #[error("could not find {wanted} distinct decoys in {tries} tries")]
    NotEnoughDecoys { wanted: usize, tries: usize },
    #[error("the real output at index {0} is not in the distribution")]
    RealOutputNotFound(u64),
}

impl<'a> GammaPicker<'a> {
    /// `offsets[i]` is the number of RingCT outputs in blocks `0..=i`.
    pub fn new(offsets: &'a [u64]) -> Result<GammaPicker<'a>, DecoyError> {
        Self::with_parameters(offsets, GAMMA_SHAPE, GAMMA_SCALE)
    }

    pub fn with_parameters(
        offsets: &'a [u64],
        shape: f64,
        scale: f64,
    ) -> Result<GammaPicker<'a>, DecoyError> {
        if offsets.len() <= SPENDABLE_AGE as usize {
            return Err(DecoyError::NotEnoughBlocks(offsets.len()));
        }

        let blocks_to_consider = offsets.len().min(BLOCKS_IN_A_YEAR);
        let outputs_to_consider = offsets[offsets.len() - 1]
            - if blocks_to_consider < offsets.len() {
                offsets[offsets.len() - blocks_to_consider - 1]
            } else {
                0
            };

        // `end` drops the three youngest blocks: `max(1, SPENDABLE_AGE) - 1`.
        let end = offsets.len() - (SPENDABLE_AGE.max(1) as usize - 1);
        let num_rct_outputs = offsets[end - 1];
        if num_rct_outputs == 0 || outputs_to_consider == 0 {
            return Err(DecoyError::NoOutputs);
        }

        Ok(GammaPicker {
            offsets,
            end,
            num_rct_outputs,
            // Seconds per output, assuming a constant target over the range —
            // which the reference also assumes, and says so.
            average_output_time: (DIFFICULTY_TARGET * blocks_to_consider as u64) as f64
                / outputs_to_consider as f64,
            shape,
            scale,
        })
    }

    pub fn num_rct_outputs(&self) -> u64 {
        self.num_rct_outputs
    }

    pub fn average_output_time(&self) -> f64 {
        self.average_output_time
    }

    /// One pick, or `None` for a pick that landed outside the chain.
    ///
    /// The reference returns `uint64_t::max()` for this and the caller retries.
    /// A failed pick is normal, not an error: the gamma has a long tail and the
    /// chain does not.
    pub fn pick(&self, rng: &mut dyn RandomSource) -> Option<u64> {
        let mut x = gamma(rng, self.shape, self.scale).exp();

        if x > DEFAULT_UNLOCK_TIME {
            // The gamma was fitted before lock times were enforced, so it is
            // measuring from the chain tip while the outputs on offer start
            // four blocks back. Shifting by the unlock time lines the two up.
            x -= DEFAULT_UNLOCK_TIME;
        } else {
            // A suggestion younger than the unlock time is not spendable at
            // all. The reference assumes such an output would be spent soon
            // after it became allowed, and picks uniformly in that window.
            x = rng.below(RECENT_SPEND_WINDOW) as f64;
        }

        // `as u64` saturates rather than wrapping, so an absurd tail sample
        // becomes a failed pick instead of a small index.
        let age_in_outputs = (x / self.average_output_time) as u64;
        if age_in_outputs >= self.num_rct_outputs {
            return None;
        }
        let target = self.num_rct_outputs - 1 - age_in_outputs;

        // The block that output falls in: the first cumulative count at or
        // above it.
        let index = lower_bound(&self.offsets[..self.end], target)?;
        let first_rct = if index == 0 {
            0
        } else {
            self.offsets[index - 1]
        };
        let n_rct = self.offsets[index] - first_rct;
        if n_rct == 0 {
            return None;
        }
        // Then uniformly within the block, so the block is what the
        // distribution chooses and the output within it is not.
        Some(first_rct + rng.below(n_rct))
    }

    /// Pick `count` distinct indices, excluding `exclude`.
    pub fn pick_distinct(
        &self,
        rng: &mut dyn RandomSource,
        count: usize,
        exclude: u64,
        max_tries: usize,
    ) -> Result<Vec<u64>, DecoyError> {
        let mut picked: Vec<u64> = Vec::with_capacity(count);
        let mut tries = 0usize;
        while picked.len() < count {
            tries += 1;
            if tries > max_tries {
                return Err(DecoyError::NotEnoughDecoys {
                    wanted: count,
                    tries: max_tries,
                });
            }
            if let Some(i) = self.pick(rng) {
                if i != exclude && !picked.contains(&i) {
                    picked.push(i);
                }
            }
        }
        Ok(picked)
    }
}

/// `std::lower_bound`: the first position whose value is `>= target`, or `None`
/// past the end.
fn lower_bound(slice: &[u64], target: u64) -> Option<usize> {
    let mut lo = 0usize;
    let mut hi = slice.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if slice[mid] < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo < slice.len() {
        Some(lo)
    } else {
        None
    }
}

/// A ring: the global indices to reference, and where the real one sits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ring {
    /// Ascending, as the wire form requires.
    pub indices: Vec<u64>,
    /// The position of the real output within [`indices`](Self::indices).
    pub real_index: usize,
}

/// Build a ring of `ring_size` around the real output at `real`.
///
/// The result is **sorted ascending**, which is what the reference does and
/// what the relative-offset encoding needs. `specs/12` §4.3 says the real spend
/// is "placed at a uniformly random position in the sorted ring", which reads
/// as an extra shuffle; there is none. The real output lands wherever its index
/// sorts to, and that position is already unpredictable because the decoys
/// around it were drawn from the gamma. See `docs/spec-deltas.md`.
pub fn select_ring(
    picker: &GammaPicker<'_>,
    rng: &mut dyn RandomSource,
    real: u64,
    ring_size: usize,
) -> Result<Ring, DecoyError> {
    if real >= picker.num_rct_outputs() {
        return Err(DecoyError::RealOutputNotFound(real));
    }
    let decoys = picker.pick_distinct(rng, ring_size - 1, real, ring_size * 200)?;

    let mut indices = decoys;
    indices.push(real);
    indices.sort_unstable();

    let real_index = indices
        .iter()
        .position(|&i| i == real)
        .ok_or(DecoyError::RealOutputNotFound(real))?;

    Ok(Ring {
        indices,
        real_index,
    })
}

/// A ring's members, once a daemon has been asked what keys they hold.
#[derive(Clone, Debug)]
pub struct RingKeys {
    pub members: Vec<wow_crypto::clsag::RingMember>,
    pub indices: Vec<u64>,
    pub real_index: usize,
}

/// Turn a daemon's `get_outs` answer into ring members.
///
/// The real output's key must be the one the wallet already holds: a daemon
/// that returned something else for that slot would produce a signature over a
/// key the wallet cannot sign for, and failing here says so plainly.
pub fn assemble_ring(
    ring: &Ring,
    keys: &[([u8; 32], [u8; 32])],
    real_public_key: &wow_crypto::types::PublicKey,
    real_commitment: &wow_crypto::types::EcPoint,
) -> Result<RingKeys, DecoyError> {
    if keys.len() != ring.indices.len() {
        return Err(DecoyError::NotEnoughDecoys {
            wanted: ring.indices.len(),
            tries: keys.len(),
        });
    }

    let (got_key, got_mask) = keys[ring.real_index];
    if got_key != real_public_key.0 || got_mask != real_commitment.0 {
        return Err(DecoyError::RealOutputNotFound(
            ring.indices[ring.real_index],
        ));
    }

    Ok(RingKeys {
        members: keys
            .iter()
            .map(|(k, m)| wow_crypto::clsag::RingMember {
                dest: wow_crypto::types::PublicKey(*k),
                mask: wow_crypto::types::EcPoint(*m),
            })
            .collect(),
        indices: ring.indices.clone(),
        real_index: ring.real_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic source, so a failure can be reproduced. Not a CSPRNG,
    /// and not what a caller passes.
    struct Lcg(u64);

    impl RandomSource for Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // The low bits of an LCG are famously poor; use the high ones.
            self.0 ^ (self.0 >> 31)
        }
    }

    /// A chain with `blocks` blocks and `per_block` outputs in each.
    fn offsets(blocks: usize, per_block: u64) -> Vec<u64> {
        (1..=blocks as u64).map(|i| i * per_block).collect()
    }

    /// The derived constants are Wownero's, not Monero's. This is the one
    /// thing in this module that a reader can check against the spec by eye,
    /// and getting it wrong is invisible at runtime.
    #[test]
    fn the_constants_are_wowneros() {
        assert_eq!(DIFFICULTY_TARGET, 300);
        assert_eq!(DEFAULT_UNLOCK_TIME, 1_200.0);
        assert_eq!(RECENT_SPEND_WINDOW, 4_500);
        assert_eq!(BLOCKS_IN_A_YEAR, 105_120);
        assert_eq!(RING_SIZE, 22);

        // Monero's values, which must not appear.
        assert_ne!(DEFAULT_UNLOCK_TIME, 480.0);
        assert_ne!(RECENT_SPEND_WINDOW, 1_800);
        assert_ne!(BLOCKS_IN_A_YEAR, 262_800);
    }

    /// The setup arithmetic, on numbers small enough to check by hand.
    #[test]
    fn the_picker_setup() {
        // 10 blocks, 5 outputs each: 50 outputs, cumulative 5,10,...,50.
        let o = offsets(10, 5);
        let p = GammaPicker::new(&o).expect("a picker");

        // `end` drops the three youngest blocks, so the newest considered is
        // block 6 (0-based), holding cumulative 35.
        assert_eq!(p.num_rct_outputs(), 35);

        // The whole chain is inside a year, so every block counts:
        // 300 * 10 / 50 = 60 seconds per output.
        assert!((p.average_output_time() - 60.0).abs() < 1e-9);
    }

    /// Too short a chain, or an empty one, is an error rather than a panic.
    #[test]
    fn a_chain_too_short_to_pick_from_is_an_error() {
        assert_eq!(
            GammaPicker::new(&[]).unwrap_err(),
            DecoyError::NotEnoughBlocks(0)
        );
        assert_eq!(
            GammaPicker::new(&[1, 2, 3, 4]).unwrap_err(),
            DecoyError::NotEnoughBlocks(4)
        );
        // Long enough, but with no outputs in it.
        assert_eq!(
            GammaPicker::new(&[0, 0, 0, 0, 0, 0]).unwrap_err(),
            DecoyError::NoOutputs
        );
    }

    /// Every pick is a real output index, inside the spendable range.
    #[test]
    fn every_pick_is_in_range() {
        let o = offsets(5_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let mut rng = Lcg(12345);

        let mut picks = 0;
        for _ in 0..5_000 {
            if let Some(i) = p.pick(&mut rng) {
                assert!(i < p.num_rct_outputs(), "{i} is past the spendable range");
                picks += 1;
            }
        }
        assert!(picks > 4_000, "most picks land on the chain: {picks}/5000");
    }

    /// The distribution favours recent outputs, which is the entire point:
    /// most spends are of recently received coins.
    #[test]
    fn picks_skew_recent() {
        let o = offsets(20_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let mut rng = Lcg(99);

        let total = p.num_rct_outputs();
        let mut newest_tenth = 0usize;
        let mut samples = 0usize;
        for _ in 0..20_000 {
            if let Some(i) = p.pick(&mut rng) {
                samples += 1;
                if i >= total - total / 10 {
                    newest_tenth += 1;
                }
            }
        }
        let share = newest_tenth as f64 / samples as f64;
        // A uniform picker would give 0.10. The gamma gives far more.
        assert!(
            share > 0.25,
            "the newest tenth should be over-represented, got {share:.3}"
        );
    }

    /// The gamma sampler has the right mean and variance.
    ///
    /// `Gamma(shape, scale)` has mean `shape * scale` and variance
    /// `shape * scale^2`. For 19.28 and 1/1.61 that is 11.975 and 7.438. The
    /// exact samples cannot match the C++, but the distribution must, and a
    /// sampler that is subtly wrong produces a wallet that is distinguishable
    /// while working perfectly.
    #[test]
    fn the_gamma_sampler_has_the_right_moments() {
        let mut rng = Lcg(7);
        const N: usize = 200_000;

        let mut sum = 0.0f64;
        let mut sum_sq = 0.0f64;
        for _ in 0..N {
            let g = gamma(&mut rng, GAMMA_SHAPE, GAMMA_SCALE);
            assert!(g > 0.0, "a gamma variate is positive");
            sum += g;
            sum_sq += g * g;
        }
        let mean = sum / N as f64;
        let var = sum_sq / N as f64 - mean * mean;

        let want_mean = GAMMA_SHAPE * GAMMA_SCALE;
        let want_var = GAMMA_SHAPE * GAMMA_SCALE * GAMMA_SCALE;
        assert!(
            (mean - want_mean).abs() < 0.05,
            "mean {mean:.4}, want {want_mean:.4}"
        );
        assert!(
            (var - want_var).abs() < 0.15,
            "variance {var:.4}, want {want_var:.4}"
        );
    }

    /// The normal sampler underneath it is standard: mean 0, variance 1.
    #[test]
    fn the_normal_sampler_is_standard() {
        let mut rng = Lcg(3);
        const N: usize = 200_000;
        let mut sum = 0.0f64;
        let mut sum_sq = 0.0f64;
        for _ in 0..N {
            let x = normal(&mut rng);
            sum += x;
            sum_sq += x * x;
        }
        let mean = sum / N as f64;
        let var = sum_sq / N as f64 - mean * mean;
        assert!(mean.abs() < 0.02, "mean {mean:.4}");
        assert!((var - 1.0).abs() < 0.03, "variance {var:.4}");
    }

    /// `unit()` stays strictly inside `(0, 1)`, because the gamma sampler takes
    /// its logarithm.
    #[test]
    fn the_unit_sampler_is_open_at_both_ends() {
        // The extremes of the underlying u64, which are what would land on a
        // boundary if the mapping were closed.
        struct Fixed(u64);
        impl RandomSource for Fixed {
            fn next_u64(&mut self) -> u64 {
                self.0
            }
        }
        for v in [0u64, 1, u64::MAX, u64::MAX - 1] {
            let u = Fixed(v).unit();
            assert!(u > 0.0 && u < 1.0, "unit() gave {u} for {v}");
            assert!(u.ln().is_finite(), "ln({u}) is not finite");
        }
    }

    /// `lower_bound` is `std::lower_bound`: the first element at or above the
    /// target.
    #[test]
    fn the_lower_bound() {
        let v = [10u64, 20, 30, 40];
        assert_eq!(lower_bound(&v, 0), Some(0));
        assert_eq!(lower_bound(&v, 10), Some(0));
        assert_eq!(lower_bound(&v, 11), Some(1));
        assert_eq!(lower_bound(&v, 30), Some(2));
        assert_eq!(lower_bound(&v, 40), Some(3));
        assert_eq!(lower_bound(&v, 41), None);
        assert_eq!(lower_bound(&[], 1), None);
    }

    /// A ring is the right size, sorted, distinct, and contains the real
    /// output at the reported position.
    #[test]
    fn a_ring_is_well_formed() {
        let o = offsets(10_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let mut rng = Lcg(2024);

        for real in [0u64, 1, 5_000, p.num_rct_outputs() - 1] {
            let ring = select_ring(&p, &mut rng, real, RING_SIZE).expect("a ring");

            assert_eq!(ring.indices.len(), RING_SIZE);
            assert_eq!(ring.indices[ring.real_index], real, "the real one is there");

            let mut sorted = ring.indices.clone();
            sorted.sort_unstable();
            assert_eq!(ring.indices, sorted, "ascending, as the wire form needs");

            sorted.dedup();
            assert_eq!(sorted.len(), RING_SIZE, "no repeats");
        }
    }

    /// A real output past the end of the chain is refused rather than signed
    /// over.
    #[test]
    fn a_real_output_off_the_chain_is_refused() {
        let o = offsets(1_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let mut rng = Lcg(1);
        let past = p.num_rct_outputs();
        assert_eq!(
            select_ring(&p, &mut rng, past, RING_SIZE),
            Err(DecoyError::RealOutputNotFound(past))
        );
    }

    /// Two rings for the same output differ. A wallet that produced the same
    /// ring twice would link its own spends.
    #[test]
    fn two_rings_for_the_same_output_differ() {
        let o = offsets(50_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");

        let a = select_ring(&p, &mut Lcg(11), 100_000, RING_SIZE).expect("a ring");
        let b = select_ring(&p, &mut Lcg(22), 100_000, RING_SIZE).expect("a ring");
        assert_ne!(a.indices, b.indices);
    }

    /// A chain too small to hold a whole ring fails with a clear error rather
    /// than looping forever.
    #[test]
    fn a_chain_too_small_for_a_ring_gives_up() {
        // Five blocks, one output each: two usable outputs after the
        // spendable-age cut, which cannot fill a ring of 22.
        let o = offsets(5, 1);
        let p = GammaPicker::new(&o).expect("a picker");
        let mut rng = Lcg(5);
        let e = select_ring(&p, &mut rng, 0, RING_SIZE).expect_err("cannot fill");
        assert!(matches!(e, DecoyError::NotEnoughDecoys { .. }), "{e}");
    }

    /// Assembling a ring checks that the daemon returned the wallet's own key
    /// in the real slot.
    #[test]
    fn assembling_checks_the_real_member() {
        let o = offsets(1_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let mut rng = Lcg(8);
        let ring = select_ring(&p, &mut rng, 500, 4).expect("a ring");

        let real_key = wow_crypto::types::PublicKey([9u8; 32]);
        let real_mask = wow_crypto::types::EcPoint([8u8; 32]);

        let mut keys: Vec<([u8; 32], [u8; 32])> =
            (0..4).map(|i| ([i as u8; 32], [i as u8; 32])).collect();
        keys[ring.real_index] = (real_key.0, real_mask.0);

        let assembled = assemble_ring(&ring, &keys, &real_key, &real_mask).expect("assembles");
        assert_eq!(assembled.members.len(), 4);
        assert_eq!(assembled.real_index, ring.real_index);

        // A daemon that returned somebody else's key for our slot is caught.
        let mut wrong = keys.clone();
        wrong[ring.real_index] = ([0xff; 32], real_mask.0);
        assert!(assemble_ring(&ring, &wrong, &real_key, &real_mask).is_err());

        // And so is a wrong count.
        assert!(assemble_ring(&ring, &keys[..3], &real_key, &real_mask).is_err());
    }
}
