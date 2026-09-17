//! Decoy selection: choosing the ring members that hide a real spend.
//!
//! `specs/12` §4.3, `gamma_picker` in `wallet2.cpp`.
//!
//! # A privacy mechanism, with one consensus rule in it
//!
//! A node accepts any ring of the right size whose members are all unlocked.
//! Which unlocked outputs are chosen cannot make a transaction invalid, and
//! that is exactly what makes it dangerous: a wallet that picks decoys from the
//! wrong distribution produces transactions that work perfectly and are
//! distinguishable from every other wallet's, which deanonymises its user and
//! everyone who happens to be in a ring with them.
//!
//! The one rule is the lock, and the picker cannot see it: a lock belongs to
//! the output, not to where it sits in the distribution. [`get_outs`] asks a
//! daemon about far more candidates than a ring needs and keeps the unlocked
//! ones, as `wallet2::get_outs` does.
//!
//! # What the daemon sees
//!
//! Every input's candidates go to the node in one request, the same number
//! for every input, each input's share sorted. A wallet that asked again for
//! a few more whenever some came back locked would tell the node that what it
//! asked for later was a decoy, since the real output is always in the first
//! request. So the shape of the request is `wallet2`'s, number for number.
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

use std::collections::{BTreeSet, HashSet};

/// `wallet2`'s log category, so one `--log-level` means the same to both.
const LOG: &str = "wallet.wallet2";

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
    #[error("the daemon could not say what the ring members are: {0}")]
    Fetch(String),
    #[error(
        "the daemon's answer did not include the output being spent, at index {0}, unlocked and \
         with its own key and commitment"
    )]
    RealOutputNotReturned(u64),
    #[error("found only {found} usable ring members of the {wanted} a ring needs")]
    TooFewUnlocked { wanted: usize, found: usize },
    #[error(
        "an output in this transaction was previously spent on another chain with ring size \
         {size}; it cannot be spent now with ring size {ring_size}, which is smaller"
    )]
    KnownRingTooLarge { size: usize, ring_size: usize },
    #[error("the known ring member at index {0} is not in the daemon's answer")]
    KnownRingMemberMissing(u64),
    #[error("the rings failed the transaction sanity check {0} times")]
    SanityCheckFailed(usize),
    #[error("the output distribution cannot be used: {0}")]
    Distribution(String),
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

/// `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_V2`: how long a coinbase output stays
/// locked.
pub const MINED_MONEY_UNLOCK_WINDOW: u64 = 288;

/// How many ring members one `/get_outs.bin` call asks about: the chunk size
/// `wallet2::get_outs` splits a large request into, so the answer stays under
/// a node's anti-DoS limits.
pub const GET_OUTS_CHUNK: usize = 1_000;

/// How many times rings are picked before a transaction that keeps failing
/// [`tx_sanity_check`] is given up on: `wallet2::get_outs`'s `attempts`.
pub const SANITY_CHECK_ATTEMPTS: usize = 3;

/// How many candidates `wallet2::get_outs` asks the daemon about for each
/// input: `(ring_size * 1.5) + 1`, "to have spares if some outputs are still
/// locked", and for a RingCT output as many again as a coinbase stays locked
/// past the spendable age, "since they're locked for longer".
///
/// At ring size 22 that is 34 + 284 = 318, the same for every input, whether
/// or not any of them turn out to be locked.
pub fn requested_outputs_count(ring_size: usize) -> usize {
    let base = (ring_size as f64 * 1.5 + 1.0) as usize;
    base + (MINED_MONEY_UNLOCK_WINDOW - SPENDABLE_AGE) as usize
}

/// An output being spent, as [`get_outs`] needs to know it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealOutput {
    pub global_index: u64,
    /// Its one-time public key.
    pub public_key: [u8; 32],
    /// Its commitment, `rct::commit(amount, mask)`.
    pub commitment: [u8; 32],
}

/// A ring member as a daemon describes it in `get_outs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    pub key: [u8; 32],
    pub mask: [u8; 32],
    /// Whether the chain lets it be spent yet: `is_tx_spendtime_unlocked`.
    pub unlocked: bool,
}

/// A ring's members as `(key, mask)`, in ring order: what [`assemble_ring`]
/// takes.
pub type MemberKeys = Vec<([u8; 32], [u8; 32])>;

/// `rct::isInMainSubgroup`: the bytes decode as a point, and that point times
/// the group order is the identity.
pub fn in_main_subgroup(bytes: &[u8; 32]) -> bool {
    wow_crypto::ops::decode_point(bytes).is_some_and(|p| p.is_torsion_free())
}

/// `wallet2::get_outs`, for RingCT inputs: a ring for each of `reals`, every
/// member one the daemon says is unlocked, with each member's `(key, mask)`
/// in ring order.
///
/// # The request
///
/// For each input, [`requested_outputs_count`] indices: the members of a
/// `known` ring first, if there is one, then the real output unless that ring
/// already named something, then gamma picks until there are enough, and each
/// input's share sorted before it is sent, "to ensure the daemon doesn't know
/// which output is ours". A chain with too few outputs to pick that many from
/// is asked about every one of them, the last repeated to make up the number.
/// All of it goes in [`GET_OUTS_CHUNK`]s, which for fewer than four inputs is
/// one call. `fetch` is given the indices of one chunk and answers one
/// [`Member`] for each, in that order.
///
/// # The answer
///
/// Checked before it is used, as `wallet2` checks it: the real output must be
/// in it with the key and commitment this wallet holds for it, and unlocked,
/// or a node could send dummy data for every output and tell the real one
/// from the difference; every member must be unlocked, not a repeat, and have
/// a key and a commitment in the prime-order subgroup (`tx_add_fake_output`).
/// Members are then taken in the order they were picked, not the order they
/// were sent in, because each later pick from a finite set is a little less
/// independent than the one before.
///
/// `known` gives, per input, a ring this wallet used before for that key
/// image. Its members are kept, so a key image spent again on another chain
/// is spent with the same ring rather than one an observer can intersect
/// with the first.
pub fn get_outs<F>(
    picker: &GammaPicker<'_>,
    rng: &mut dyn RandomSource,
    reals: &[RealOutput],
    ring_size: usize,
    known: Option<&[Vec<u64>]>,
    fetch: &mut F,
) -> Result<Vec<(Ring, MemberKeys)>, DecoyError>
where
    F: FnMut(&[u64]) -> Result<Vec<Member>, String>,
{
    let requested = requested_outputs_count(ring_size);
    // "the base offset of the first rct output in the first unlocked block"
    let num_outs = picker.num_rct_outputs();
    if num_outs == 0 {
        return Err(DecoyError::NoOutputs);
    }

    // What goes to the node, and the same indices in the order they were
    // picked. `sections[n]` is where input `n`'s share of both lies.
    let mut request: Vec<u64> = Vec::with_capacity(reals.len() * requested);
    let mut picking_order: Vec<u64> = Vec::with_capacity(reals.len() * requested);
    let mut sections: Vec<(usize, usize)> = Vec::with_capacity(reals.len());

    for (n, real) in reals.iter().enumerate() {
        let start = request.len();
        let mut add = |i: u64| {
            request.push(i);
            picking_order.push(i);
        };
        let mut seen: HashSet<u64> = HashSet::new();
        let mut num_found = 0usize;

        if let Some(ring) = known.and_then(|k| k.get(n)) {
            if ring.len() > ring_size {
                return Err(DecoyError::KnownRingTooLarge {
                    size: ring.len(),
                    ring_size,
                });
            }
            let mut own_found = false;
            for &out in ring {
                // Anything newer than the picker's range is too recent to be
                // asked about.
                if out < num_outs {
                    add(out);
                    num_found += 1;
                    seen.insert(out);
                    own_found |= out == real.global_index;
                }
            }
            if !own_found {
                wow_log::warn!(
                    LOG,
                    "Known ring does not include the spent output: {}, there may have been a \
                     reorg that moved the spent output's position in the chain",
                    real.global_index
                );
            }
        }

        if num_outs <= requested as u64 {
            // Every output there is, and the last one again to make up the
            // count: the shortfall is caught once the answer says which are
            // unlocked.
            for i in 0..num_outs {
                add(i);
            }
            for _ in num_outs..requested as u64 {
                add(num_outs - 1);
            }
        } else {
            // Start with the real one.
            if num_found == 0 {
                num_found = 1;
                seen.insert(real.global_index);
                add(real.global_index);
            }
            // `wallet2` has two passes here, the first leaving out outputs its
            // shared database marks as spent. This wallet keeps no such marks,
            // so both passes see every output, and the second ends the picking
            // once every one has been seen.
            let mut allow_blackballed = false;
            // Not in the reference, which picks until it has enough. A chain
            // whose old outputs the gamma almost never reaches could keep it
            // picking for a very long time; this stops, and the rings are
            // judged on what was found.
            let mut picks_left = requested.saturating_mul(1_000);
            while num_found < requested {
                if seen.len() as u64 == num_outs {
                    if allow_blackballed {
                        break;
                    }
                    allow_blackballed = true;
                }
                // `do i = gamma->pick(); while (i >= num_outs);`, where a pick
                // off the chain is `None`. A repeat is picked again too.
                match picker.pick(rng).filter(|i| *i < num_outs) {
                    Some(i) if seen.insert(i) => {
                        add(i);
                        num_found += 1;
                    }
                    _ => {
                        if picks_left == 0 {
                            break;
                        }
                        picks_left -= 1;
                    }
                }
            }
            // "stuff with one to keep counts good, and we'll error out later"
            while num_found < requested {
                add(0);
                num_found += 1;
            }
        }

        // Sorted, so the node cannot tell which is ours from where it sits.
        request[start..].sort_unstable();
        sections.push((start, request.len()));
    }

    let mut answer: Vec<Member> = Vec::with_capacity(request.len());
    for chunk in request.chunks(GET_OUTS_CHUNK) {
        let got = fetch(chunk).map_err(DecoyError::Fetch)?;
        if got.len() != chunk.len() {
            return Err(DecoyError::Fetch(format!(
                "daemon returned wrong response for get_outs.bin, wrong amounts count = {}, \
                 expected {}",
                got.len(),
                chunk.len()
            )));
        }
        answer.extend(got);
    }

    let mut valid_keys: HashSet<[u8; 32]> = HashSet::new();
    let mut rings = Vec::with_capacity(reals.len());
    for (n, real) in reals.iter().enumerate() {
        let (start, end) = sections[n];
        let asked = &request[start..end];
        let told = &answer[start..end];

        // "this guards against an active attack where the node sends dummy
        // data for all outputs, and we then send the real one, which the node
        // can then tell from the fake outputs"
        let real_out_found = asked.iter().zip(told).any(|(i, m)| {
            *i == real.global_index
                && m.key == real.public_key
                && m.mask == real.commitment
                && m.unlocked
        });
        if !real_out_found {
            return Err(DecoyError::RealOutputNotReturned(real.global_index));
        }

        let mut outs: Vec<(u64, [u8; 32], [u8; 32])> =
            vec![(real.global_index, real.public_key, real.commitment)];

        if let Some(ring) = known.and_then(|k| k.get(n)) {
            for &out in ring {
                if out < num_outs && out != real.global_index {
                    let at = asked
                        .iter()
                        .position(|i| *i == out)
                        .ok_or(DecoyError::KnownRingMemberMissing(out))?;
                    add_fake_output(&mut outs, out, &told[at], real, &mut valid_keys);
                }
            }
        }

        // "While we are still lacking outputs in this result ring, in our
        // secret pick order..."
        for &picked in &picking_order[start..end] {
            if outs.len() >= ring_size {
                break;
            }
            let at = asked
                .iter()
                .position(|i| *i == picked)
                .ok_or(DecoyError::RealOutputNotFound(picked))?;
            add_fake_output(&mut outs, picked, &told[at], real, &mut valid_keys);
        }
        if outs.len() < ring_size {
            return Err(DecoyError::TooFewUnlocked {
                wanted: ring_size,
                found: outs.len(),
            });
        }

        outs.sort_by_key(|o| o.0);
        let indices: Vec<u64> = outs.iter().map(|o| o.0).collect();
        let real_index = indices
            .iter()
            .position(|&i| i == real.global_index)
            .ok_or(DecoyError::RealOutputNotFound(real.global_index))?;
        let keys = outs.iter().map(|o| (o.1, o.2)).collect();
        rings.push((
            Ring {
                indices,
                real_index,
            },
            keys,
        ));
    }
    Ok(rings)
}

/// `wallet2::tx_add_fake_output`: take a member the daemon described, if it
/// can go in a ring.
///
/// Not if it is locked, is the real output, or is already in the ring. Nor if
/// its key or its commitment is outside the prime-order subgroup: a node that
/// handed out such a point could recognise it in a ring later. `valid` holds
/// the points already found good, so each is checked once.
fn add_fake_output(
    outs: &mut Vec<(u64, [u8; 32], [u8; 32])>,
    index: u64,
    member: &Member,
    real: &RealOutput,
    valid: &mut HashSet<[u8; 32]>,
) -> bool {
    if !member.unlocked || index == real.global_index {
        return false;
    }
    let item = (index, member.key, member.mask);
    if outs.contains(&item) {
        return false;
    }
    if !valid.contains(&member.key) && !in_main_subgroup(&member.key) {
        wow_log::warn!(
            LOG,
            "Key {} at index {index} is not in the main subgroup",
            wow_crypto::hex::encode(&member.key)
        );
        return false;
    }
    valid.insert(member.key);
    if !valid.contains(&member.mask) && !in_main_subgroup(&member.mask) {
        wow_log::warn!(
            LOG,
            "Commitment {} at index {index} is not in the main subgroup",
            wow_crypto::hex::encode(&member.mask)
        );
        return false;
    }
    valid.insert(member.mask);
    outs.push(item);
    true
}

/// `tx_sanity_check` (`cryptonote_core/tx_sanity_check.cpp`), over the set of
/// every ring member's index, how many members there are in all, and how many
/// RingCT outputs the chain has.
///
/// A transaction whose rings are mostly repeats, or mostly old, looks like
/// nobody else's, and a node that fed a wallet a skewed distribution would get
/// exactly that. At least 80% of the members must be distinct, and their
/// median must be at least 60% of the way up the chain. Too few members, or
/// too young a chain, to judge by passes.
pub fn tx_sanity_check(
    rct_indices: &BTreeSet<u64>,
    n_indices: usize,
    rct_outs_available: u64,
) -> bool {
    if n_indices <= 10 {
        return true;
    }
    if rct_outs_available < 10_000 {
        return true;
    }
    if rct_indices.len() < n_indices * 8 / 10 {
        wow_log::error!(
            "verify",
            "amount of unique indices is too low (amount of rct indices is {}, out of total {} \
             indices.",
            rct_indices.len(),
            n_indices
        );
        return false;
    }
    let offsets: Vec<u64> = rct_indices.iter().copied().collect();
    let median = median(&offsets);
    if median < rct_outs_available.wrapping_mul(6) / 10 {
        wow_log::error!(
            "verify",
            "median offset index is too low (median is {median} out of total \
             {rct_outs_available} offsets). Transactions should contain a higher fraction of \
             recent outputs."
        );
        return false;
    }
    true
}

/// `epee::misc_utils::median` of an ascending slice: the middle element, or
/// the mean of the middle two taken without overflowing (`get_mid`).
fn median(sorted: &[u64]) -> u64 {
    match sorted.len() {
        0 => 0,
        1 => sorted[0],
        n if n % 2 == 1 => sorted[n / 2],
        n => {
            let (a, b) = (sorted[n / 2 - 1], sorted[n / 2]);
            a / 2 + b / 2 + (a % 2 + b % 2) / 2
        }
    }
}

/// The outer `wallet2::get_outs`: rings from [`get_outs`], judged by
/// [`tx_sanity_check`] over every member of every ring, and picked again up to
/// [`SANITY_CHECK_ATTEMPTS`] times while they fail.
///
/// The reference judges the rings, not the built transaction, and so does
/// this: they are the same indices, and judging them first means a
/// transaction that would fail is never built and signed.
///
/// `offsets` is the distribution `picker` was built from, whose last entry is
/// how many RingCT outputs the chain has.
pub fn select_rings<F>(
    offsets: &[u64],
    picker: &GammaPicker<'_>,
    rng: &mut dyn RandomSource,
    reals: &[RealOutput],
    ring_size: usize,
    known: Option<&[Vec<u64>]>,
    mut fetch: F,
) -> Result<Vec<(Ring, MemberKeys)>, DecoyError>
where
    F: FnMut(&[u64]) -> Result<Vec<Member>, String>,
{
    let available = offsets.last().copied().unwrap_or(0);
    for _ in 0..SANITY_CHECK_ATTEMPTS {
        let rings = get_outs(picker, rng, reals, ring_size, known, &mut fetch)?;
        let unique: BTreeSet<u64> = rings
            .iter()
            .flat_map(|(r, _)| r.indices.iter().copied())
            .collect();
        let total = rings.iter().map(|(r, _)| r.indices.len()).sum();
        if tx_sanity_check(&unique, total, available) {
            return Ok(rings);
        }
    }
    Err(DecoyError::SanityCheckFailed(SANITY_CHECK_ATTEMPTS))
}

/// [`Member`]s from a daemon's `/get_outs.bin`, for [`get_outs`].
pub fn fetch_members(
    client: &wow_daemon_client::DaemonClient,
    indices: &[u64],
) -> Result<Vec<Member>, String> {
    let wanted: Vec<(u64, u64)> = indices.iter().map(|i| (0u64, *i)).collect();
    let outs = client.get_outs(&wanted, false).map_err(|e| e.to_string())?;
    Ok(outs
        .iter()
        .map(|o| Member {
            key: o.key,
            mask: o.mask,
            unlocked: o.unlocked,
        })
        .collect())
}

/// The RingCT output distribution a transaction's rings are picked from:
/// what `wallet2::get_rct_distribution` hands `get_outs`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RctDistribution {
    /// The height `offsets[0]` is for, as the node said.
    ///
    /// `wallet2` reads it and uses it for nothing, and neither does this: the
    /// offsets go to the picker as they are. A C++ node starts them at height
    /// 1, where RingCT outputs begin on mainnet, so `offsets[i]` is the block
    /// `i + 1`. That shifts no pick: the picker finds a block by its running
    /// total and takes the output within it from the totals alone, and the
    /// only thing a block's position feeds is how many blocks a young chain
    /// spans, which mainnet is long past. Lining the array up by prepending
    /// the missing blocks would make this wallet's picker the one that
    /// differs.
    pub start_height: u64,
    /// Running totals of RingCT outputs, one per block from `start_height`.
    pub offsets: Vec<u64>,
}

/// `wallet2::get_rct_distribution`: the whole RingCT distribution, asked for
/// exactly as the reference wallet asks.
///
/// Amount 0 only, from height 0, per-block counts rather than running totals,
/// compressed, and to the node's own tip -- not the height this wallet has
/// scanned to, which may be behind it. The node sees the same request from
/// this wallet as from the C++ one, every transaction.
///
/// Nothing is kept between sends. A cache that asked only for the blocks since
/// the last send would be a request no other wallet makes; the one this
/// replaces also counted every output below the window twice once it had
/// something to append to.
pub fn rct_distribution(
    client: &wow_daemon_client::DaemonClient,
) -> Result<RctDistribution, DecoyError> {
    let answer = client
        .get_output_distribution(&[0], 0, 0, false, true)
        .map_err(|e| DecoyError::Fetch(e.to_string()))?;
    rct_distribution_from(answer)
}

/// The checks and the sum in `wallet2::get_rct_distribution`, on an answer
/// already fetched.
///
/// The answer must be exactly one distribution, for amount 0; anything else
/// is refused rather than guessed at. The per-block counts are then summed in
/// place into running totals. `base` is not added: the reference does not add
/// it, and a node counts no RingCT outputs below where it starts.
pub fn rct_distribution_from(
    mut answer: Vec<wow_daemon_client::OutputDistribution>,
) -> Result<RctDistribution, DecoyError> {
    if answer.len() != 1 {
        return Err(DecoyError::Distribution(format!(
            "not the expected single result, but {}",
            answer.len()
        )));
    }
    let d = answer.remove(0);
    if d.amount != 0 {
        return Err(DecoyError::Distribution(
            "the result is not for amount 0".into(),
        ));
    }
    let mut offsets = d.distribution;
    for i in 1..offsets.len() {
        offsets[i] = offsets[i].wrapping_add(offsets[i - 1]);
    }
    Ok(RctDistribution {
        start_height: d.start_height,
        offsets,
    })
}

/// The checks `wallet2::get_outs` makes of a distribution before picking from
/// it.
///
/// Too few blocks to leave the spendable age out of is "Not enough rct
/// outputs". And a chain whose last running total does not reach past every
/// output being spent cannot be the chain those outputs are on: "Daemon
/// reports suspicious number of rct outputs". A node that answered short would
/// otherwise have every ring picked from the part of the chain it chose to
/// show.
pub fn check_distribution(offsets: &[u64], max_real_index: u64) -> Result<(), DecoyError> {
    if offsets.len() <= SPENDABLE_AGE as usize {
        return Err(DecoyError::Distribution("not enough rct outputs".into()));
    }
    if offsets.last().is_none_or(|last| *last <= max_real_index) {
        return Err(DecoyError::Distribution(
            "the daemon reports a suspicious number of rct outputs".into(),
        ));
    }
    Ok(())
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

    /// A real point for output `i`, so a member's key passes the subgroup
    /// check the way a key on chain does.
    fn key_of(i: u64) -> [u8; 32] {
        wow_crypto::ops::encode_point(&wow_crypto::ops::scalarmult_base(
            &curve25519_dalek::scalar::Scalar::from(i + 1),
        ))
    }

    /// The commitment every member of the test daemon's answer has.
    fn mask() -> [u8; 32] {
        wow_crypto::ops::encode_point(&curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
    }

    fn real(i: u64) -> RealOutput {
        RealOutput {
            global_index: i,
            public_key: key_of(i),
            commitment: mask(),
        }
    }

    /// A daemon's answer where `locked` says which outputs are still locked.
    fn daemon(
        locked: impl Fn(u64) -> bool,
    ) -> impl FnMut(&[u64]) -> Result<Vec<Member>, String> {
        move |indices| {
            Ok(indices
                .iter()
                .map(|&i| Member {
                    key: key_of(i),
                    mask: mask(),
                    unlocked: !locked(i),
                })
                .collect())
        }
    }

    /// Ring size 22 asks about 34 candidates, and 284 more for how long a
    /// coinbase stays locked past the spendable age.
    #[test]
    fn the_request_count_is_wallet2s() {
        assert_eq!(requested_outputs_count(22), 318);
        assert_eq!(requested_outputs_count(11), 17 + 284);
    }

    /// Every input's candidates go in one request, the same number for each,
    /// each input's share sorted with its real output among them. Nothing is
    /// asked for afterwards, so nothing the node sees marks a decoy.
    #[test]
    fn the_request_has_wallet2s_shape() {
        let o = offsets(10_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let reals = [real(20_000), real(31_337)];
        let mut calls: Vec<Vec<u64>> = Vec::new();
        let mut answer = daemon(|_| false);

        let mut fetch = |indices: &[u64]| {
            calls.push(indices.to_vec());
            answer(indices)
        };
        let rings = get_outs(&p, &mut Lcg(12), &reals, RING_SIZE, None, &mut fetch)
            .expect("rings");

        assert_eq!(calls.len(), 1, "one call, not one per input or per round");
        let n = requested_outputs_count(RING_SIZE);
        assert_eq!(calls[0].len(), 2 * n);
        for (share, r) in calls[0].chunks(n).zip(&reals) {
            let mut sorted = share.to_vec();
            sorted.sort_unstable();
            assert_eq!(share, sorted.as_slice(), "each input's share is sorted");
            assert!(share.contains(&r.global_index), "and holds its real output");
            assert!(share.iter().all(|i| *i < p.num_rct_outputs()));
        }

        for ((ring, keys), r) in rings.iter().zip(&reals) {
            assert_eq!(ring.indices.len(), RING_SIZE);
            assert_eq!(ring.indices[ring.real_index], r.global_index);
            let mut distinct = ring.indices.clone();
            distinct.sort_unstable();
            distinct.dedup();
            assert_eq!(distinct, ring.indices, "ascending and distinct");
            for (i, (key, m)) in ring.indices.iter().zip(keys) {
                assert_eq!((*key, *m), (key_of(*i), mask()), "each key is its index's");
            }
        }
    }

    /// More than a thousand candidates go in chunks of a thousand, as
    /// `wallet2` splits them.
    #[test]
    fn a_large_request_goes_in_chunks_of_a_thousand() {
        let o = offsets(10_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let reals = [real(1_000), real(9_000), real(20_000), real(35_000)];
        let mut sizes = Vec::new();
        let mut answer = daemon(|_| false);
        let mut fetch = |indices: &[u64]| {
            sizes.push(indices.len());
            answer(indices)
        };
        get_outs(&p, &mut Lcg(5), &reals, RING_SIZE, None, &mut fetch).expect("rings");
        assert_eq!(sizes, vec![1_000, 4 * 318 - 1_000]);
    }

    /// An output the daemon says is locked is asked about and left out, and
    /// the ring is filled with unlocked ones. On mainnet the newest outputs
    /// are mostly coinbase, locked for 288 blocks, and a ring picked without
    /// asking held several every time -- which every C++ node refuses.
    #[test]
    fn locked_members_are_left_out() {
        let o = offsets(10_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let newest = p.num_rct_outputs() - p.num_rct_outputs() / 50;
        let locked = move |i: u64| i >= newest;
        let mut answer = daemon(locked);
        let mut asked = Vec::new();

        let mut fetch = |indices: &[u64]| {
            asked.extend_from_slice(indices);
            answer(indices)
        };
        let rings = get_outs(&p, &mut Lcg(77), &[real(20_000)], RING_SIZE, None, &mut fetch)
            .expect("a ring");

        assert!(
            asked.iter().any(|&i| locked(i)),
            "the picker offered locked outputs"
        );
        assert!(
            rings[0].0.indices.iter().all(|&i| !locked(i)),
            "and none is in the ring: {:?}",
            rings[0].0.indices
        );
    }

    /// The output being spent must come back unlocked, with the key and the
    /// commitment this wallet holds for it. A node that answered otherwise
    /// could tell it from the decoys once it was spent.
    #[test]
    fn the_real_output_must_come_back_as_it_is_held() {
        let o = offsets(10_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let r = real(20_000);

        let mut locked = daemon(|i| i == 20_000);
        assert_eq!(
            get_outs(&p, &mut Lcg(3), &[r], RING_SIZE, None, &mut locked),
            Err(DecoyError::RealOutputNotReturned(20_000))
        );

        let mut honest = daemon(|_| false);
        let mut dummy = |indices: &[u64]| -> Result<Vec<Member>, String> {
            let mut members = honest(indices)?;
            for (i, m) in indices.iter().zip(&mut members) {
                if *i == 20_000 {
                    m.key = key_of(1);
                }
            }
            Ok(members)
        };
        assert_eq!(
            get_outs(&p, &mut Lcg(3), &[r], RING_SIZE, None, &mut dummy),
            Err(DecoyError::RealOutputNotReturned(20_000))
        );
    }

    /// A member whose key or commitment is outside the prime-order subgroup
    /// is never put in a ring.
    #[test]
    fn members_outside_the_prime_order_subgroup_are_left_out() {
        // (0, -1): a valid encoding of a point of order two.
        let mut small_order = [0xffu8; 32];
        small_order[0] = 0xec;
        small_order[31] = 0x7f;
        assert!(wow_crypto::ops::decode_point(&small_order).is_some());
        assert!(!in_main_subgroup(&small_order));
        assert!(in_main_subgroup(&key_of(7)));

        let o = offsets(10_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let bad = |i: u64| i != 20_000 && i.is_multiple_of(2);
        let mut honest = daemon(|_| false);
        let mut torsioned = |indices: &[u64]| -> Result<Vec<Member>, String> {
            let mut members = honest(indices)?;
            for (i, m) in indices.iter().zip(&mut members) {
                if bad(*i) && i.is_multiple_of(4) {
                    m.key = small_order;
                } else if bad(*i) {
                    m.mask = small_order;
                }
            }
            Ok(members)
        };
        let rings = get_outs(&p, &mut Lcg(9), &[real(20_000)], RING_SIZE, None, &mut torsioned)
            .expect("a ring of the others");
        assert!(
            rings[0].0.indices.iter().all(|&i| !bad(i)),
            "{:?}",
            rings[0].0.indices
        );
    }

    /// With nothing but the real output unlocked the ring cannot be filled,
    /// and it says so after the one request rather than asking again.
    #[test]
    fn a_chain_with_nothing_unlocked_is_refused_after_one_request() {
        let o = offsets(10_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let mut calls = 0;
        let mut everything_else = daemon(|i| i != 20_000);
        let mut fetch = |indices: &[u64]| {
            calls += 1;
            everything_else(indices)
        };
        let e = get_outs(&p, &mut Lcg(4), &[real(20_000)], RING_SIZE, None, &mut fetch)
            .expect_err("nothing to fill it with");
        assert_eq!(
            e,
            DecoyError::TooFewUnlocked {
                wanted: RING_SIZE,
                found: 1
            }
        );
        assert_eq!(calls, 1);
    }

    /// A chain with fewer outputs than a request asks about is asked about
    /// every one of them, the last repeated to make up the count.
    #[test]
    fn a_small_chain_is_asked_about_every_output() {
        let o = offsets(10, 5);
        let p = GammaPicker::new(&o).expect("a picker");
        let total = p.num_rct_outputs();
        let mut asked = Vec::new();
        let mut answer = daemon(|_| false);
        let mut fetch = |indices: &[u64]| {
            asked.extend_from_slice(indices);
            answer(indices)
        };
        let rings =
            get_outs(&p, &mut Lcg(1), &[real(3)], RING_SIZE, None, &mut fetch).expect("a ring");
        assert_eq!(asked.len(), requested_outputs_count(RING_SIZE));
        assert!((0..total).all(|i| asked.contains(&i)));
        assert!(asked[total as usize..].iter().all(|&i| i == total - 1));
        assert_eq!(rings[0].0.indices.len(), RING_SIZE);
    }

    /// A known ring is used again, member for member.
    #[test]
    fn a_known_ring_is_used_again() {
        let o = offsets(10_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let known: Vec<u64> = (0..RING_SIZE as u64).map(|i| 1_000 + i * 997).collect();
        let r = real(known[5]);
        let mut answer = daemon(|_| false);
        let rings = get_outs(
            &p,
            &mut Lcg(21),
            &[r],
            RING_SIZE,
            Some(std::slice::from_ref(&known)),
            &mut answer,
        )
        .expect("a ring");
        assert_eq!(rings[0].0.indices, known);
        assert_eq!(rings[0].0.real_index, 5);

        let too_large: Vec<u64> = (0..RING_SIZE as u64 + 1).collect();
        assert_eq!(
            get_outs(
                &p,
                &mut Lcg(21),
                &[r],
                RING_SIZE,
                Some(std::slice::from_ref(&too_large)),
                &mut answer,
            ),
            Err(DecoyError::KnownRingTooLarge {
                size: RING_SIZE + 1,
                ring_size: RING_SIZE
            })
        );
    }

    /// `tx_sanity_check`: too few members or too young a chain passes; too
    /// many repeats, or a median too far down the chain, fails.
    #[test]
    fn the_sanity_check_is_the_references() {
        let set = |v: &[u64]| v.iter().copied().collect::<BTreeSet<u64>>();

        assert!(tx_sanity_check(&set(&[1, 2]), 10, 1_000_000), "10 is too few");
        assert!(tx_sanity_check(&set(&[1, 2]), 22, 9_999), "a young chain");

        let recent: Vec<u64> = (0..22).map(|i| 900_000 + i).collect();
        assert!(tx_sanity_check(&set(&recent), 22, 1_000_000));
        assert!(
            !tx_sanity_check(&set(&recent[..16]), 22, 1_000_000),
            "16 distinct of 22 is under 80%, as 22 * 8 / 10 rounds it"
        );
        assert!(tx_sanity_check(&set(&recent[..17]), 22, 1_000_000));

        let old: Vec<u64> = (0..22).map(|i| 500_000 + i).collect();
        assert!(
            !tx_sanity_check(&set(&old), 22, 1_000_000),
            "the median is under 60% of the chain"
        );

        assert_eq!(median(&[]), 0);
        assert_eq!(median(&[7]), 7);
        assert_eq!(median(&[1, 2, 9]), 2);
        assert_eq!(median(&[1, 3, 4, 9]), 3);
        assert_eq!(median(&[u64::MAX, u64::MAX]), u64::MAX, "without overflowing");
    }

    /// Rings that fail the sanity check are picked again, three times in all,
    /// and then the transaction is refused.
    #[test]
    fn rings_that_fail_the_sanity_check_are_picked_again_three_times() {
        // A chain whose last block holds nearly every output, where the picker
        // cannot reach: every ring comes from the bottom half-percent of the
        // chain, and fails.
        let mut o: Vec<u64> = (1..=5_000).collect();
        o.extend([5_000, 5_000, 5_000, 1_000_000]);
        let p = GammaPicker::new(&o).expect("a picker");
        assert_eq!(p.num_rct_outputs(), 5_000);

        let mut calls = 0;
        let mut answer = daemon(|_| false);
        let fetch = |indices: &[u64]| {
            calls += 1;
            answer(indices)
        };
        let e = select_rings(&o, &p, &mut Lcg(8), &[real(4_000)], RING_SIZE, None, fetch)
            .expect_err("fails every time");
        assert_eq!(e, DecoyError::SanityCheckFailed(3));
        assert_eq!(calls, 3, "picked and asked for again each time");

        // And the same rings from an ordinary chain pass the first time.
        let o = offsets(10_000, 4);
        let p = GammaPicker::new(&o).expect("a picker");
        let mut calls = 0;
        let mut answer = daemon(|_| false);
        let fetch = |indices: &[u64]| {
            calls += 1;
            answer(indices)
        };
        select_rings(&o, &p, &mut Lcg(8), &[real(39_000)], RING_SIZE, None, fetch)
            .expect("passes");
        assert_eq!(calls, 1);
    }

    fn answer(
        amount: u64,
        start_height: u64,
        counts: &[u64],
    ) -> wow_daemon_client::OutputDistribution {
        wow_daemon_client::OutputDistribution {
            amount,
            start_height,
            base: 0,
            distribution: counts.to_vec(),
        }
    }

    /// Per-block counts are summed into running totals, as
    /// `wallet2::get_rct_distribution` sums them, and nothing else is added:
    /// not `base`, and not the start height. Asking twice gives the same
    /// array, which is what the cache this replaced got wrong from the second
    /// send on.
    #[test]
    fn a_distribution_is_summed_as_wallet2_sums_it() {
        let got = rct_distribution_from(vec![answer(0, 1, &[2, 0, 3, 5])]).expect("one answer");
        assert_eq!(got.offsets, vec![2, 2, 5, 10]);
        assert_eq!(got.start_height, 1, "kept, and not used to shift anything");
        assert_eq!(
            rct_distribution_from(vec![answer(0, 1, &[2, 0, 3, 5])]),
            Ok(got),
            "the same every time"
        );
    }

    /// Anything but exactly one distribution, for amount 0, is refused.
    #[test]
    fn a_distribution_answer_must_be_one_for_amount_zero() {
        assert!(matches!(
            rct_distribution_from(Vec::new()),
            Err(DecoyError::Distribution(_))
        ));
        assert!(matches!(
            rct_distribution_from(vec![answer(0, 1, &[1]), answer(0, 1, &[1])]),
            Err(DecoyError::Distribution(_))
        ));
        assert!(matches!(
            rct_distribution_from(vec![answer(5, 1, &[1])]),
            Err(DecoyError::Distribution(_))
        ));
    }

    /// The distribution has to leave something past the spendable age, and
    /// reach past every output being spent.
    #[test]
    fn a_distribution_short_of_the_real_outputs_is_refused() {
        let o = offsets(10, 5);
        assert_eq!(check_distribution(&o, 49), Ok(()));
        assert!(matches!(
            check_distribution(&o, 50),
            Err(DecoyError::Distribution(_))
        ));
        assert!(matches!(
            check_distribution(&o[..4], 0),
            Err(DecoyError::Distribution(_))
        ));
    }
}
