//! Block weight limits and the long-term weight model.
//!
//! `specs/06-consensus-rules.md` §3.4.
//!
//! Two different quantities, easily confused:
//!
//! * the **weight median and limit** for the *next* block, updated after each
//!   block by [`update_next_cumulative_weight_limit`];
//! * the **long-term weight stored for a block**, [`next_long_term_block_weight`].
//!
//! The second is a separate database column and **cannot be recomputed from
//! block weights alone** (`specs/06` §3.4, `specs/10` §4.2) — it is a median
//! over previously *stored* long-term weights, so it is self-referential. It
//! must be persisted.
//!
//! ## The two medians are the same function
//!
//! The short-term median goes through `epee::misc_utils::median` (full sort,
//! `get_mid` of the two middles when even). The long-term median goes through
//! `epee::misc_utils::rolling_median_t`, a two-heap structure — a completely
//! different code path, and one that would be easy to assume differs.
//!
//! It does not. `rolling_median_t` caps `maxCt` at `N/2` and `minCt` at
//! `(N-1)/2`, and grows them so that `maxCt == ceil((sz-1)/2)` and
//! `minCt == floor((sz-1)/2)`. Its `median()` returns `data[heap[0]]` — sorted
//! index `maxCt` — and only folds in `heap[-1]` (sorted index `maxCt - 1`) when
//! `minCt < maxCt`, i.e. exactly when `sz` is even. That is
//! `get_mid(v[sz/2 - 1], v[sz/2])` for even `sz` and `v[sz/2]` for odd, which is
//! [`median`] verbatim. So one helper serves both.

use crate::constants::*;
use crate::emission::{get_mid, median};
use crate::hardfork::gates::{HF_VERSION_2021_SCALING, HF_VERSION_LONG_TERM_BLOCK_WEIGHT};

/// The weight state carried between blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WeightLimits {
    /// `m_current_block_cumul_weight_median`.
    pub median: u64,
    /// `m_current_block_cumul_weight_limit` = `median * 2`.
    pub limit: u64,
    /// `m_long_term_effective_median_block_weight`.
    ///
    /// `None` below HF 13: the C++ member is **not assigned** in that branch,
    /// so it keeps whatever a previous call left (0 on a chain synced forward
    /// from genesis). Nothing reads it there — the only consumers are
    /// `check_fee` and `get_dynamic_base_fee_estimate`, both gated on
    /// `version >= HF_VERSION_LONG_TERM_BLOCK_WEIGHT` — so rather than model a
    /// stale member this reports "not set".
    pub long_term_effective_median: Option<u64>,
}

/// `update_next_cumulative_weight_limit`, run after each block.
///
/// `short_term_weights` are the last `CRYPTONOTE_REWARD_BLOCKS_WINDOW` (100)
/// **block** weights; `long_term_median` is the median of the stored
/// **long-term** weights over the trailing
/// `min(LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE, db_height)` blocks.
///
/// ```text
/// if hf < 13:
///     median = median(last 100 block weights)
/// else:
///     ltem = max(300_000, long_term_median)
///     stm  = median(last 100 block weights)
///     effective = if hf >= 20 { min(max(ltem, stm), 50 * ltem) }
///                 else        { min(max(300_000, stm), 50 * ltem) }
///     median = effective
/// median = max(median, 300_000)
/// limit  = median * 2
/// ```
///
/// Note the `hf >= 20` branch takes `max(ltem, stm)` while the earlier one
/// takes `max(300_000, stm)` — the surge floor moves from the constant to the
/// long-term median at HF 20.
pub fn update_next_cumulative_weight_limit(
    hf_version: u8,
    short_term_weights: &mut [u64],
    long_term_median: u64,
) -> WeightLimits {
    let full_reward_zone = get_min_block_weight(hf_version);

    let (mut m, long_term_effective_median) = if hf_version < HF_VERSION_LONG_TERM_BLOCK_WEIGHT {
        (median(short_term_weights), None)
    } else {
        let ltem = BLOCK_GRANTED_FULL_REWARD_ZONE_V5.max(long_term_median);
        let stm = median(short_term_weights);
        let effective = if hf_version >= HF_VERSION_2021_SCALING {
            ltem.max(stm)
                .min(SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * ltem)
        } else {
            BLOCK_GRANTED_FULL_REWARD_ZONE_V5
                .max(stm)
                .min(SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * ltem)
        };
        (effective, Some(ltem))
    };

    if m <= full_reward_zone {
        m = full_reward_zone;
    }
    WeightLimits {
        median: m,
        limit: m * 2,
        long_term_effective_median,
    }
}

/// `get_next_long_term_block_weight(block_weight)` — the value **stored** for
/// this block (`specs/06` §3.4).
///
/// # Which version, and which height
///
/// `specs/06` §3.4 does not say, and the answer takes two hops through the C.
/// For a block at height `h`:
///
/// * `hf_version` is the version of height **`h` itself**, and
/// * `long_term_median` is the median over the stored long-term weights of
///   `[h - min(100_000, h), h)`, i.e. `db_height == h`.
///
/// The version is not obvious. `get_next_long_term_block_weight` runs *before*
/// `m_db->add_block`, and `HardFork::add` — which advances the fork index —
/// runs *inside* `add_block`. So the hard-fork state is one block behind: it
/// last saw block `h - 1`. But `HardFork::add(blk, height)` ends with
/// `get_voted_fork_index(height + 1)`, so after block `h - 1` the index already
/// points at the fork covering height `h`. The two offsets cancel, and
/// `get_current_version()` is the version of `h`.
///
/// [`update_next_cumulative_weight_limit`] runs *after* `add_block` — the C has
/// a comment saying why, "do this after updating the hard fork state since the
/// weight limit may change due to fork" — so it sees the version of `h + 1` and
/// a `db_height` of `h + 1`. That is consistent: it is computing the limit the
/// *next* block must satisfy, using that block's own version.
///
/// [`LongTermWeightWindow`] applies these conventions for you.
///
/// ```text
/// if hf < 13 { return block_weight }
/// ltem = max(300_000, long_term_median)
/// if hf >= 20 { weight = max(block_weight, ltem * 10 / 17)
///               constraint = ltem + ltem * 7 / 10 }        // clamp into [ltem/1.7, ltem*1.7]
/// else        { weight = block_weight
///               constraint = ltem + ltem * 2 / 5 }         // clamp into [0, ltem*1.4]
/// min(weight, constraint)
/// ```
pub fn next_long_term_block_weight(
    hf_version: u8,
    block_weight: u64,
    long_term_median: u64,
) -> u64 {
    if hf_version < HF_VERSION_LONG_TERM_BLOCK_WEIGHT {
        return block_weight;
    }
    let ltem = BLOCK_GRANTED_FULL_REWARD_ZONE_V5.max(long_term_median);

    let (weight, short_term_constraint) = if hf_version >= HF_VERSION_2021_SCALING {
        (block_weight.max(ltem * 10 / 17), ltem + ltem * 7 / 10)
    } else {
        (block_weight, ltem + ltem * 2 / 5)
    };
    weight.min(short_term_constraint)
}

/// How many blocks the long-term median window covers at a given height, and
/// where it starts.
///
/// `nblocks = min(CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE, db_height)`,
/// over `[db_height - nblocks, db_height)` — the **stored** long-term weights,
/// not block weights.
pub fn long_term_window(db_height: u64) -> u64 {
    LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE.min(db_height)
}

/// The range of heights the long-term median covers at `db_height`.
pub fn long_term_window_range(db_height: u64) -> std::ops::Range<u64> {
    let n = long_term_window(db_height);
    (db_height - n)..db_height
}

/// `get_long_term_block_weight_median` — the median of the stored long-term
/// weights. See the module header: the rolling median it uses in C++ is the
/// same function as [`median`].
pub fn long_term_median(stored_long_term_weights: &mut [u64]) -> u64 {
    median(stored_long_term_weights)
}

/// `get_block_weight_limit()` — `median * 2`, the cap a block's cumulative
/// weight must not exceed (`specs/06` §2 step 11).
pub const fn weight_limit(median: u64) -> u64 {
    median * 2
}

/// The sliding window of **stored** long-term weights, with its median.
///
/// This is `Blockchain::m_long_term_block_weights_cache_rolling_median` — the
/// state a node must carry to extend the chain, since the stored long-term
/// weight of a block is a median over the stored long-term weights before it.
///
/// The C uses `epee::misc_utils::rolling_median_t`, a two-heap circular buffer.
/// This is a balanced pair of multisets, which gives the same answer (see the
/// module header for why) with the same eviction order, and does it without
/// `unsafe`. `push` is `O(log n)`; sorting the window per block would be
/// `O(n log n)` and is not viable over a 100,000-block replay.
#[derive(Clone, Debug)]
pub struct LongTermWeightWindow {
    capacity: usize,
    /// Insertion order, so the oldest entry can be evicted.
    order: std::collections::VecDeque<u64>,
    /// The smallest `ceil(len / 2)` values, as value -> count.
    lower: std::collections::BTreeMap<u64, usize>,
    /// The largest `floor(len / 2)` values.
    upper: std::collections::BTreeMap<u64, usize>,
    lower_len: usize,
    upper_len: usize,
}

impl Default for LongTermWeightWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl LongTermWeightWindow {
    /// A window of `CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE` (100,000).
    pub fn new() -> Self {
        Self::with_capacity(LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE as usize)
    }

    /// A window of a chosen size, for tests and for the shorter testnet-style
    /// configurations.
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "a zero-length window has no median");
        Self {
            capacity,
            order: std::collections::VecDeque::with_capacity(capacity.min(4096)),
            lower: std::collections::BTreeMap::new(),
            upper: std::collections::BTreeMap::new(),
            lower_len: 0,
            upper_len: 0,
        }
    }

    /// How many weights the window currently holds.
    pub fn len(&self) -> usize {
        self.lower_len + self.upper_len
    }

    /// Is the window empty? At height 0 it is, and the C would throw on
    /// `count == 0` — but HF 13 is far past genesis, so the caller returns the
    /// raw block weight long before this matters.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append the stored long-term weight of one block, evicting the oldest
    /// once the window is full.
    pub fn push(&mut self, long_term_weight: u64) {
        if self.order.len() == self.capacity {
            let old = self.order.pop_front().expect("non-empty at capacity");
            self.remove(old);
        }
        self.order.push_back(long_term_weight);
        self.insert(long_term_weight);
    }

    /// The median of the window, matching `rolling_median_t::median()`.
    ///
    /// Zero for an empty window, where the C would throw instead.
    pub fn median(&self) -> u64 {
        match (self.max_lower(), self.min_upper()) {
            (None, _) => 0,
            (Some(lo), _) if self.len() % 2 == 1 => lo,
            (Some(lo), Some(hi)) => get_mid(lo, hi),
            (Some(lo), None) => lo,
        }
    }

    /// [`next_long_term_block_weight`] with the window's own median, for the
    /// block at the height this window ends at.
    ///
    /// `hf_version` is the version of the block's **own** height — see that
    /// function's note for why that is not the obvious reading of the C.
    pub fn next_long_term_block_weight(&self, hf_version: u8, block_weight: u64) -> u64 {
        next_long_term_block_weight(hf_version, block_weight, self.median())
    }

    fn max_lower(&self) -> Option<u64> {
        self.lower.keys().next_back().copied()
    }

    fn min_upper(&self) -> Option<u64> {
        self.upper.keys().next().copied()
    }

    fn insert(&mut self, v: u64) {
        match self.max_lower() {
            Some(lo) if v > lo => {
                *self.upper.entry(v).or_insert(0) += 1;
                self.upper_len += 1;
            }
            _ => {
                *self.lower.entry(v).or_insert(0) += 1;
                self.lower_len += 1;
            }
        }
        self.rebalance();
    }

    fn remove(&mut self, v: u64) {
        // If `v` is in both halves it equals `max(lower) == min(upper)`, so
        // taking it from either keeps the partition sorted.
        let from_lower = self.lower.contains_key(&v);
        let (map, len) = if from_lower {
            (&mut self.lower, &mut self.lower_len)
        } else {
            (&mut self.upper, &mut self.upper_len)
        };
        match map.get_mut(&v) {
            Some(c) if *c > 1 => *c -= 1,
            Some(_) => {
                map.remove(&v);
            }
            None => unreachable!("evicting a weight the window never held"),
        }
        *len -= 1;
        self.rebalance();
    }

    /// Keep `lower_len == ceil(len / 2)` and `upper_len == floor(len / 2)`,
    /// which is the split `rolling_median_t` maintains.
    fn rebalance(&mut self) {
        while self.lower_len > self.upper_len + 1 {
            let v = self.max_lower().expect("lower is longer, so non-empty");
            self.shift(v, true);
        }
        while self.upper_len > self.lower_len {
            let v = self.min_upper().expect("upper is longer, so non-empty");
            self.shift(v, false);
        }
    }

    fn shift(&mut self, v: u64, lower_to_upper: bool) {
        let (src, dst, src_len, dst_len) = if lower_to_upper {
            (
                &mut self.lower,
                &mut self.upper,
                &mut self.lower_len,
                &mut self.upper_len,
            )
        } else {
            (
                &mut self.upper,
                &mut self.lower,
                &mut self.upper_len,
                &mut self.lower_len,
            )
        };
        match src.get_mut(&v) {
            Some(c) if *c > 1 => *c -= 1,
            _ => {
                src.remove(&v);
            }
        }
        *src_len -= 1;
        *dst.entry(v).or_insert(0) += 1;
        *dst_len += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Below HF 13 the limit is just the 100-block median, floored at 300,000.
    #[test]
    fn before_long_term_weights() {
        let mut w = vec![1000u64; 100];
        let l = update_next_cumulative_weight_limit(12, &mut w, 0);
        assert_eq!(l.median, 300_000, "floored at the full reward zone");
        assert_eq!(l.limit, 600_000);
        assert_eq!(
            l.long_term_effective_median, None,
            "not assigned below HF 13"
        );

        // A median above the floor is used as-is.
        let mut w = vec![500_000u64; 100];
        let l = update_next_cumulative_weight_limit(12, &mut w, 0);
        assert_eq!(l.median, 500_000);
        assert_eq!(l.limit, 1_000_000);
    }

    /// An empty or small chain still yields the floor, never zero.
    #[test]
    fn the_limit_is_never_below_the_full_reward_zone() {
        for hf in [7u8, 12, 13, 15, 18, 20] {
            let l = update_next_cumulative_weight_limit(hf, &mut [], 0);
            assert_eq!(l.median, 300_000, "hf {hf}");
            assert_eq!(l.limit, 600_000, "hf {hf}");
        }
    }

    /// `specs/06` §3.4: from HF 13 the effective median is the short-term
    /// median clamped by the long-term one, and the surge factor is 50x.
    #[test]
    fn long_term_weights_clamp_the_short_term_median() {
        let ltm = 400_000u64;

        // A short-term median below the floor is raised to it.
        let mut small = vec![1000u64; 100];
        let l = update_next_cumulative_weight_limit(15, &mut small, ltm);
        assert_eq!(l.median, 300_000);
        assert_eq!(l.long_term_effective_median, Some(400_000));

        // A surge is capped at 50x the long-term effective median.
        let mut huge = vec![u64::MAX / 4; 100];
        let l = update_next_cumulative_weight_limit(15, &mut huge, ltm);
        assert_eq!(
            l.median,
            50 * 400_000,
            "the surge factor caps the short-term median"
        );
    }

    /// The HF 20 branch floors at the long-term median rather than at the
    /// constant 300,000 — the one real difference between the two branches.
    #[test]
    fn hf20_floors_at_the_long_term_median() {
        let ltm = 1_000_000u64; // well above the 300,000 constant
        let mut modest = vec![400_000u64; 100]; // below ltm, above the constant

        let before = update_next_cumulative_weight_limit(19, &mut modest.clone(), ltm);
        let after = update_next_cumulative_weight_limit(20, &mut modest, ltm);

        assert_eq!(
            before.median, 400_000,
            "HF 19 takes max(300_000, short-term median)"
        );
        assert_eq!(
            after.median, 1_000_000,
            "HF 20 takes max(long-term median, short-term median)"
        );
        assert_ne!(before.median, after.median, "the branches must differ");
    }

    /// `specs/06` §3.4: the stored long-term weight is a clamp, and the clamp
    /// changes shape at HF 20 — `[ltem/1.7, ltem*1.7]` rather than
    /// `[0, ltem*1.4]`.
    #[test]
    fn stored_long_term_weight_clamps() {
        // Below HF 13 it is the raw block weight.
        assert_eq!(next_long_term_block_weight(12, 123_456, 999_999), 123_456);

        let ltm = 500_000u64;

        // HF 13..19: upper bound only, at ltem * 1.4.
        let upper_old = ltm + ltm * 2 / 5;
        assert_eq!(upper_old, 700_000);
        assert_eq!(
            next_long_term_block_weight(15, 100, ltm),
            100,
            "no lower bound"
        );
        assert_eq!(next_long_term_block_weight(15, 10_000_000, ltm), upper_old);

        // HF 20+: both bounds.
        let lower_new = ltm * 10 / 17;
        let upper_new = ltm + ltm * 7 / 10;
        assert_eq!(upper_new, 850_000);
        assert_eq!(
            next_long_term_block_weight(20, 100, ltm),
            lower_new,
            "a tiny block is raised to ltem / 1.7"
        );
        assert_eq!(next_long_term_block_weight(20, 10_000_000, ltm), upper_new);
        // A weight already inside the band passes through.
        assert_eq!(next_long_term_block_weight(20, 600_000, ltm), 600_000);
    }

    /// The long-term median is floored at 300,000 in both the limit update and
    /// the stored weight, so an early chain behaves sanely.
    #[test]
    fn long_term_median_is_floored() {
        // A long-term median of 0 -- an empty chain -- still gives the floor.
        assert_eq!(
            next_long_term_block_weight(20, 1, 0),
            BLOCK_GRANTED_FULL_REWARD_ZONE_V5 * 10 / 17
        );
        let l = update_next_cumulative_weight_limit(20, &mut [1000; 100], 0);
        assert_eq!(l.long_term_effective_median, Some(300_000));
    }

    #[test]
    fn window_sizes() {
        assert_eq!(long_term_window(0), 0);
        assert_eq!(long_term_window(50_000), 50_000);
        assert_eq!(long_term_window(100_000), 100_000);
        assert_eq!(long_term_window(900_000), 100_000, "capped at the window");
        assert_eq!(LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE, 100_000);
        assert_eq!(SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR, 50);
    }

    #[test]
    fn limit_is_twice_the_median() {
        for m in [300_000u64, 400_000, 1_000_000] {
            assert_eq!(weight_limit(m), 2 * m);
            let l = update_next_cumulative_weight_limit(20, &mut [m; 100], m);
            assert_eq!(l.limit, l.median * 2);
        }
    }

    /// The window must agree with a plain sorted median at every step, for
    /// both parities and with duplicates -- that equivalence is the whole
    /// justification for not reimplementing `rolling_median_t`.
    #[test]
    fn the_window_agrees_with_a_sorted_median() {
        // A cheap deterministic PRNG; no dev-dependency for one test.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for cap in [1usize, 2, 3, 4, 5, 16, 97] {
            let mut w = LongTermWeightWindow::with_capacity(cap);
            let mut naive: Vec<u64> = Vec::new();

            for step in 0..(cap * 4 + 7) {
                // A small value range so duplicates are common.
                let v = next() % 11;
                w.push(v);
                naive.push(v);
                if naive.len() > cap {
                    naive.remove(0);
                }

                assert_eq!(w.len(), naive.len(), "cap {cap} step {step}");
                let mut sorted = naive.clone();
                assert_eq!(
                    w.median(),
                    median(&mut sorted),
                    "cap {cap} step {step}: window {naive:?}"
                );
            }
        }
    }

    /// Large values must not be averaged through an overflowing `(a + b) / 2`;
    /// `get_mid` is the reason they are not.
    #[test]
    fn the_window_median_does_not_overflow() {
        let mut w = LongTermWeightWindow::with_capacity(2);
        w.push(u64::MAX);
        assert_eq!(w.median(), u64::MAX, "one element");
        w.push(u64::MAX - 2);
        assert_eq!(w.median(), get_mid(u64::MAX - 2, u64::MAX));
        assert_eq!(w.median(), u64::MAX - 1);
    }

    /// The window evicts in insertion order, not by value.
    #[test]
    fn the_window_evicts_the_oldest() {
        let mut w = LongTermWeightWindow::with_capacity(3);
        for v in [100u64, 1, 2] {
            w.push(v);
        }
        assert_eq!(w.median(), 2, "sorted [1, 2, 100]");
        w.push(3); // evicts the 100, not the 1
        assert_eq!(w.median(), 2, "sorted [1, 2, 3]");
        w.push(4); // evicts the 1
        assert_eq!(w.median(), 3, "sorted [2, 3, 4]");
    }

    #[test]
    fn an_empty_window_has_no_median() {
        let w = LongTermWeightWindow::new();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
        assert_eq!(w.median(), 0, "the C throws here instead");
        // With a zero median the floor still applies.
        assert_eq!(
            w.next_long_term_block_weight(20, 1),
            BLOCK_GRANTED_FULL_REWARD_ZONE_V5 * 10 / 17
        );
        assert_eq!(w.next_long_term_block_weight(12, 12_345), 12_345);
    }

    #[test]
    fn the_default_window_is_the_consensus_one() {
        assert_eq!(
            LongTermWeightWindow::default().capacity,
            LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE as usize
        );
    }
}
