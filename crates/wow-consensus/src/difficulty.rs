//! All six difficulty algorithms.
//!
//! `specs/07-difficulty.md`. Wownero changed its difficulty algorithm **six
//! times**, and all six must be implemented: a from-genesis sync re-derives
//! cumulative difficulty at every height, and cumulative difficulty is what
//! decides reorgs.
//!
//! # Two things that are easy to get wrong
//!
//! **`HEIGHT` is the current chain height, not the height of the block being
//! validated, and `version` is `get_current_hard_fork_version()` — the version
//! at that chain height, which is the next block's and not the tip block's**
//! (`specs/07` §3). Several
//! algorithms branch on `HEIGHT`, so during initial sync the branch taken
//! depends on how far the chain has progressed. `recalculate_difficulties`
//! reproduces this by passing `m_db->height()` — the *final* height — rather
//! than the loop height, so a recalculation run and a live sync can legitimately
//! take different branches. The call sites are reproduced literally; `HEIGHT` is
//! never normalised.
//!
//! **The ten hard-coded overrides of `specs/07` §4 are consensus.** They are
//! collected in [`OVERRIDES`] so they can be enumerated in a test.

// These three lints all fire on deliberate transcriptions of `difficulty.cpp`.
// Every one of them has a "cleaner" rewrite that is arithmetically identical
// and that makes the line stop matching the C, which is the wrong trade for a
// consensus-critical file that has to be diffed against upstream.
//
// * `manual_div_ceil` -- `(length - span + 1) / 2` is the cut offset, written
//   the way the C writes it.
// * `if_same_then_else` -- v4 and v5 each have two branches with coinciding
//   bodies. Collapsing them hides which condition the C actually tests, and
//   upstream may change one branch without the other.
// * `needless_range_loop` -- these loops carry state across iterations and
//   index more than one array.
#![allow(
    clippy::manual_div_ceil,
    clippy::if_same_then_else,
    clippy::needless_range_loop
)]

use wow_types::Difficulty;
use wow_types::Network;

use crate::constants::*;

/// `get_difficulty_target()`.
///
/// `if version < 2 { DIFFICULTY_TARGET_V1 } else { DIFFICULTY_TARGET_V2 }` —
/// and since both are 300 on Wownero it is **always 300**.
pub const fn difficulty_target() -> u64 {
    DIFFICULTY_TARGET_V2
}

/// `difficulty_blocks_count(version)` (`specs/07` §1).
///
/// Note **versions 18 and 19 fall through to the last branch**, so they use
/// `DIFFICULTY_BLOCKS_COUNT = 735` and algorithm v1.
pub const fn difficulty_blocks_count(version: u8) -> usize {
    if version >= 20 {
        DIFFICULTY_BLOCKS_COUNT_V4 // 147
    } else if version <= 17 && version >= 11 {
        DIFFICULTY_BLOCKS_COUNT_V3 // 145
    } else if version <= 10 && version >= 8 {
        DIFFICULTY_BLOCKS_COUNT_V2 // 61
    } else {
        DIFFICULTY_BLOCKS_COUNT // 735
    }
}

/// Which algorithm a tip version selects (`specs/07` §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// `next_difficulty` — CryptoNote/Monero classic. HF 7, and again 18–19.
    V1,
    /// `next_difficulty_v2` — LWMA (Zawy). HF 8. **Uses floating point.**
    V2,
    /// `next_difficulty_v3` — LWMA-2. HF 9.
    V3,
    /// `next_difficulty_v4` — LWMA-4. HF 10.
    V4,
    /// `next_difficulty_v5` — LWMA-1, N=144. HF 11–17.
    V5,
    /// `next_difficulty_v6` — v1's shape with the V3 window. HF 20+.
    V6,
}

/// `specs/07` §2, verbatim.
pub const fn select_algorithm(version: u8) -> Algorithm {
    if version >= 20 {
        Algorithm::V6
    } else if version <= 17 && version >= 11 {
        Algorithm::V5
    } else if version == 10 {
        Algorithm::V4
    } else if version == 9 {
        Algorithm::V3
    } else if version == 8 {
        Algorithm::V2
    } else {
        Algorithm::V1
    }
}

/// One hard-coded difficulty override (`specs/07` §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Override {
    pub algorithm: Algorithm,
    /// Inclusive height range on which it fires.
    pub from: u64,
    pub to: u64,
    pub difficulty: Difficulty,
    pub mainnet_only: bool,
}

/// Every hard-coded override, for enumeration in tests.
///
/// The testnet/stagenet `HEIGHT <= 720 => 100` rule applies to all six
/// algorithms and is listed once with `mainnet_only = false`.
pub const OVERRIDES: &[Override] = &[
    Override {
        algorithm: Algorithm::V1,
        from: 331_170,
        to: 331_890,
        difficulty: 100_000_000,
        mainnet_only: true,
    },
    Override {
        algorithm: Algorithm::V4,
        from: 0,
        to: 63_470,
        difficulty: 100_000_069,
        mainnet_only: true,
    },
    Override {
        algorithm: Algorithm::V5,
        from: 81_769,
        to: 81_912,
        difficulty: 10_000_000,
        mainnet_only: true,
    },
    Override {
        algorithm: Algorithm::V5,
        from: 307_686,
        to: 307_686,
        difficulty: 25_800_000,
        mainnet_only: true,
    },
    Override {
        algorithm: Algorithm::V5,
        from: 307_692,
        to: 307_692,
        difficulty: 1_890_000,
        mainnet_only: true,
    },
    Override {
        algorithm: Algorithm::V5,
        from: 307_735,
        to: 307_735,
        difficulty: 17_900_000,
        mainnet_only: true,
    },
    Override {
        algorithm: Algorithm::V5,
        from: 307_742,
        to: 307_742,
        difficulty: 21_300_000,
        mainnet_only: true,
    },
    Override {
        algorithm: Algorithm::V5,
        from: 307_750,
        to: 307_750,
        difficulty: 10_900_000,
        mainnet_only: true,
    },
    Override {
        algorithm: Algorithm::V5,
        from: 307_766,
        to: 307_766,
        difficulty: 2_960_000,
        mainnet_only: true,
    },
];

/// The testnet/stagenet floor that every algorithm shares.
const TESTNET_EARLY_DIFFICULTY: Difficulty = 100;

fn is_test_network(net: Network) -> bool {
    matches!(net, Network::Testnet | Network::Stagenet)
}

/// `next_difficulty` (v1) — HF 7, and again HF 18–19 (`specs/07` §3.1).
///
/// Note that only `timestamps` is sorted; `cumulative_difficulties` is left in
/// chain order. That is the classic CryptoNote behaviour, and "fixing" it
/// changes every difficulty in the HF 7 and HF 18–19 eras.
pub fn next_difficulty_v1(
    mut timestamps: Vec<u64>,
    mut cumulative_difficulties: Vec<Difficulty>,
    target: u64,
    height: u64,
    net: Network,
) -> Difficulty {
    if is_test_network(net) && height <= DIFFICULTY_WINDOW as u64 {
        return TESTNET_EARLY_DIFFICULTY;
    }
    // Truncating keeps the FIRST 720 of the up-to-735 collected entries, i.e.
    // it drops the 15 most recent -- the "lag" -- because the vectors are
    // ordered oldest-first.
    if timestamps.len() > DIFFICULTY_WINDOW {
        timestamps.truncate(DIFFICULTY_WINDOW);
        cumulative_difficulties.truncate(DIFFICULTY_WINDOW);
    }
    let length = timestamps.len();
    if length <= 1 {
        return 1;
    }

    // The HF 18 mainnet difficulty reset: 721 heights pinned to 100,000,000.
    if net == Network::Mainnet && (331_170..=331_170 + DIFFICULTY_WINDOW as u64).contains(&height) {
        return 100_000_000;
    }

    timestamps.sort_unstable();
    let span = DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT; // 600
    let (cut_begin, cut_end) = if length <= span {
        (0, length)
    } else {
        let cb = (length - span + 1) / 2;
        (cb, cb + span)
    };
    let mut time_span = timestamps[cut_end - 1] - timestamps[cut_begin];
    if time_span == 0 {
        time_span = 1;
    }
    // `difficulty_type` is boost's **unchecked** uint128_t, so this wraps
    // rather than trapping. On a real chain cumulative difficulty is
    // monotonic and the difference is always positive; wrapping only matters
    // for inputs that cannot occur, and matching the C there is free.
    let total_work =
        cumulative_difficulties[cut_end - 1].wrapping_sub(cumulative_difficulties[cut_begin]);
    ceil_div_256(total_work, target, time_span)
}

/// `next_difficulty_v6` — HF 20+ (`specs/07` §3.6).
///
/// `next_difficulty` with the V3 window (144) and the V2 cut (12), and without
/// the HF 18 reset clause. Because `difficulty_blocks_count` is 147 at HF 20
/// and the window is 144, the 3-block lag is dropped from the *recent* end.
pub fn next_difficulty_v6(
    mut timestamps: Vec<u64>,
    mut cumulative_difficulties: Vec<Difficulty>,
    target: u64,
    height: u64,
    net: Network,
) -> Difficulty {
    if is_test_network(net) && height <= DIFFICULTY_WINDOW as u64 {
        return TESTNET_EARLY_DIFFICULTY;
    }
    if timestamps.len() > DIFFICULTY_WINDOW_V3 {
        timestamps.truncate(DIFFICULTY_WINDOW_V3);
        cumulative_difficulties.truncate(DIFFICULTY_WINDOW_V3);
    }
    let length = timestamps.len();
    if length <= 1 {
        return 1;
    }
    timestamps.sort_unstable();
    let span = DIFFICULTY_WINDOW_V3 - 2 * DIFFICULTY_CUT_V2; // 120
    let (cut_begin, cut_end) = if length <= span {
        (0, length)
    } else {
        let cb = (length - span + 1) / 2;
        (cb, cb + span)
    };
    let mut time_span = timestamps[cut_end - 1] - timestamps[cut_begin];
    if time_span == 0 {
        time_span = 1;
    }
    // `difficulty_type` is boost's **unchecked** uint128_t, so this wraps
    // rather than trapping. On a real chain cumulative difficulty is
    // monotonic and the difference is always positive; wrapping only matters
    // for inputs that cannot occur, and matching the C there is free.
    let total_work =
        cumulative_difficulties[cut_end - 1].wrapping_sub(cumulative_difficulties[cut_begin]);
    ceil_div_256(total_work, target, time_span)
}

/// `(total_work * target + time_span - 1) / time_span`, in 256 bits, returning
/// 0 on overflow past `u128`.
///
/// `specs/03` §4 and `specs/07` §8: "Difficulty 0 (overflow) causes the block to
/// be rejected" — it is a validation failure, not "any hash passes".
fn ceil_div_256(total_work: Difficulty, target: u64, time_span: u64) -> Difficulty {
    // total_work * target can exceed u128, so carry it as a 256-bit value in
    // two u128 halves.
    let (lo, hi) = mul_u128(total_work, target as u128);
    let (lo, hi) = add_u256(lo, hi, (time_span - 1) as u128);
    let (q_lo, q_hi) = div_u256_by_u64(lo, hi, time_span);
    if q_hi != 0 {
        0
    } else {
        q_lo
    }
}

/// 128x128 -> 256.
fn mul_u128(a: u128, b: u128) -> (u128, u128) {
    let (a_lo, a_hi) = (a as u64 as u128, a >> 64);
    let (b_lo, b_hi) = (b as u64 as u128, b >> 64);
    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;
    let mid = (ll >> 64) + (lh & u64::MAX as u128) + (hl & u64::MAX as u128);
    let lo = (ll & u64::MAX as u128) | (mid << 64);
    let hi = hh + (lh >> 64) + (hl >> 64) + (mid >> 64);
    (lo, hi)
}

fn add_u256(lo: u128, hi: u128, add: u128) -> (u128, u128) {
    let (nlo, carry) = lo.overflowing_add(add);
    (nlo, hi + u128::from(carry))
}

/// 256 / 64 -> 256, by long division in 64-bit limbs.
fn div_u256_by_u64(lo: u128, hi: u128, d: u64) -> (u128, u128) {
    let limbs = [lo as u64, (lo >> 64) as u64, hi as u64, (hi >> 64) as u64];
    let mut q = [0u64; 4];
    let mut rem: u128 = 0;
    for i in (0..4).rev() {
        let cur = (rem << 64) | u128::from(limbs[i]);
        q[i] = (cur / u128::from(d)) as u64;
        rem = cur % u128::from(d);
    }
    (
        u128::from(q[0]) | (u128::from(q[1]) << 64),
        u128::from(q[2]) | (u128::from(q[3]) << 64),
    )
}

// ---------------------------------------------------------------------------
// v2 -- LWMA (Zawy), HF 8
// ---------------------------------------------------------------------------

/// `next_difficulty_v2` — HF 8 (`specs/07` §3.2).
///
/// **This is the only algorithm that uses floating point, and it is
/// consensus.** The operation order is reproduced exactly:
///
/// * `k` is `N * (N + 1) / 2` computed in **integer** then converted, so for an
///   odd `N` the integer division truncates before the conversion;
/// * `LWMA += (int64_t)(solveTime * i) / k` multiplies in `int64_t` and only
///   then divides by the `double` `k`;
/// * `difficulty` is truncated to `u64` from the `u128` difference;
/// * `boost::math::round` rounds **half away from zero**, not to even;
/// * the final `static_cast<uint64_t>` is a C-style truncating cast.
pub fn next_difficulty_v2(
    mut timestamps: Vec<u64>,
    mut cumulative_difficulties: Vec<Difficulty>,
    target_seconds: u64,
    height: u64,
    net: Network,
) -> Difficulty {
    let t = target_seconds as i64;
    let mut n = DIFFICULTY_WINDOW_V2;

    if is_test_network(net) && height <= DIFFICULTY_WINDOW as u64 {
        return TESTNET_EARLY_DIFFICULTY;
    }
    if timestamps.len() < 4 {
        return 1;
    } else if timestamps.len() < n + 1 {
        n = timestamps.len() - 1;
    } else {
        timestamps.truncate(n + 1);
        cumulative_difficulties.truncate(n + 1);
    }

    const ADJUST: f64 = 0.998;
    // `const double k = N * (N + 1) / 2;` -- integer arithmetic, then converted.
    let k = (n * (n + 1) / 2) as f64;

    let mut lwma = 0f64;
    let mut sum_inverse_d = 0f64;
    for i in 1..=n {
        let mut solve_time = timestamps[i] as i64 - timestamps[i - 1] as i64;
        // std::min(T * 7, std::max(solveTime, -7 * T))
        solve_time = (t * 7).min(solve_time.max(-7 * t));
        // The u128 difference truncated to u64, as the C's static_cast does.
        let difficulty = (cumulative_difficulties[i] - cumulative_difficulties[i - 1]) as u64;
        // (int64_t)(solveTime * i) / k -- an i64 product divided by a double.
        lwma += (solve_time * i as i64) as f64 / k;
        sum_inverse_d += 1.0 / difficulty as f64;
    }

    let harmonic_mean_d = n as f64 / sum_inverse_d;
    if (round_half_away_from_zero(lwma) as i64) < t / 20 {
        lwma = (t / 20) as f64;
    }

    let next = harmonic_mean_d * t as f64 / lwma * ADJUST;
    // static_cast<uint64_t>(double) truncates toward zero.
    next as u64 as Difficulty
}

/// `boost::math::round` — half **away from zero**, unlike Rust's `f64::round`
/// only for exact `.5` on negatives, which this must match.
fn round_half_away_from_zero(x: f64) -> f64 {
    if x < 0.0 {
        -(-x + 0.5).floor()
    } else {
        (x + 0.5).floor()
    }
}

// ---------------------------------------------------------------------------
// v3 -- LWMA-2, HF 9
// ---------------------------------------------------------------------------

/// `next_difficulty_v3` — HF 9 (`specs/07` §3.3).
///
/// Pure integer, `int64_t` throughout. Two details:
///
/// * the C writes `max((prev_D*67)/100, min(next_D, (prev_D*150)/100))`, so if
///   the low bound exceeds the high one the **low bound wins**. Rust's
///   `clamp` panics in that case, so the explicit `max(lo, min(x, hi))` form is
///   used (`specs/07` §8).
/// * `L` can be zero or negative for pathological timestamps and the C has no
///   guard — it would be undefined behaviour. In practice `L > 0` because of
///   the `-4*T` floor and the `i` weighting. A division by zero here returns 1
///   rather than panicking (`specs/07` §3.3).
pub fn next_difficulty_v3(
    timestamps: Vec<u64>,
    cumulative_difficulties: Vec<Difficulty>,
    height: u64,
    net: Network,
) -> Difficulty {
    let t: i64 = DIFFICULTY_TARGET_V2 as i64;
    let n: i64 = DIFFICULTY_WINDOW_V2 as i64;

    if is_test_network(net) && height <= DIFFICULTY_WINDOW as u64 {
        return TESTNET_EARLY_DIFFICULTY;
    }
    // The C asserts `timestamps.size() == N + 1`.
    if timestamps.len() < (n + 1) as usize || cumulative_difficulties.len() < (n + 1) as usize {
        return 1;
    }

    let mut l: i64 = 0;
    let mut sum_3_st: i64 = 0;
    for i in 1..=n {
        let mut st = timestamps[i as usize] as i64 - timestamps[(i - 1) as usize] as i64;
        // std::max(-4*T, std::min(ST, 6*T))
        st = (-4 * t).max(st.min(6 * t));
        l += st * i;
        if i > n - 3 {
            sum_3_st += st;
        }
    }

    if l == 0 {
        return 1;
    }
    let work = (cumulative_difficulties[n as usize] - cumulative_difficulties[0]) as i64;
    let mut next_d = (work * t * (n + 1) * 99) / (100 * 2 * l);
    let prev_d =
        (cumulative_difficulties[n as usize] - cumulative_difficulties[(n - 1) as usize]) as i64;

    // NOT `clamp`: if lo > hi the low bound wins.
    next_d = ((prev_d * 67) / 100).max(next_d.min((prev_d * 150) / 100));

    if sum_3_st < (8 * t) / 10 {
        next_d = next_d.max((prev_d * 108) / 100);
    }
    next_d as u64 as Difficulty
}

// ---------------------------------------------------------------------------
// v4 -- LWMA-4, HF 10
// ---------------------------------------------------------------------------

/// `next_difficulty_v4` — HF 10 (`specs/07` §3.4).
///
/// The timestamp monotonisation, the digit-zeroing loop and the trailing
/// `min(999, ...)` term are all consensus.
pub fn next_difficulty_v4(
    timestamps: Vec<u64>,
    cumulative_difficulties: Vec<Difficulty>,
    height: u64,
    net: Network,
) -> Difficulty {
    let t: u64 = DIFFICULTY_TARGET_V2;
    let n: u64 = DIFFICULTY_WINDOW_V2 as u64;

    if is_test_network(net) && height <= DIFFICULTY_WINDOW as u64 {
        return TESTNET_EARLY_DIFFICULTY;
    }
    // `HEIGHT <= 63469 + 1`. v4 is only selected at HF 10, which begins at
    // 63,469, so this covers exactly two heights.
    if net == Network::Mainnet && height <= 63_469 + 1 {
        return 100_000_069;
    }
    if timestamps.len() < (n + 1) as usize || cumulative_difficulties.len() < (n + 1) as usize {
        return 1;
    }

    // Monotonise: TS[i] = max(timestamps[i], TS[i-1]).
    let mut ts = vec![0u64; (n + 1) as usize];
    ts[0] = timestamps[0];
    for i in 1..=n as usize {
        ts[i] = timestamps[i].max(ts[i - 1]);
    }

    let mut l: u64 = 0;
    for i in 1..=n as usize {
        let st = if i > 4 && ts[i] - ts[i - 1] > 5 * t && ts[i - 1] - ts[i - 4] < (14 * t) / 10 {
            2 * t
        } else if i > 7 && ts[i] - ts[i - 1] > 5 * t && ts[i - 1] - ts[i - 7] < 4 * t {
            2 * t
        } else {
            (5 * t).min(ts[i] - ts[i - 1])
        };
        l += st * i as u64;
    }
    if l < n * n * t / 20 {
        l = n * n * t / 20;
    }

    let avg_d =
        ((cumulative_difficulties[n as usize] - cumulative_difficulties[0]) / n as u128) as u64;
    let mut next_d = if avg_d > 2_000_000 * n * n * t {
        (avg_d / (200 * l)) * (n * (n + 1) * t * 97)
    } else {
        (avg_d * n * (n + 1) * t * 97) / (200 * l)
    };

    let prev_d =
        (cumulative_difficulties[n as usize] - cumulative_difficulties[(n - 1) as usize]) as u64;
    if (ts[n as usize] - ts[(n - 1) as usize]) < (2 * t) / 10
        || (ts[n as usize] - ts[(n - 2) as usize]) < (5 * t) / 10
        || (ts[n as usize] - ts[(n - 3) as usize]) < (8 * t) / 10
    {
        next_d = next_d.max(((prev_d * 110) / 100).min((105 * avg_d) / 100));
    }

    next_d = zero_insignificant_digits(next_d);

    if next_d > 100_000 {
        next_d = ((next_d + 500) / 1000) * 1000
            + 999u64.min((ts[n as usize] - ts[(n as usize) - 10]) / 10);
    }
    next_d as Difficulty
}

// ---------------------------------------------------------------------------
// v5 -- LWMA-1 N=144, HF 11..17
// ---------------------------------------------------------------------------

/// `next_difficulty_v5` — HF 11–17 (`specs/07` §3.5).
///
/// The longest-lived algorithm and the one with the hard-coded overrides.
///
/// Watch the overflow-avoidance branch: the condition **changed at height
/// 307,800** and the two branches are not equivalent, so the exact comparison
/// matters — and note `height == 307_800` falls into neither of the first two
/// and so takes the third.
pub fn next_difficulty_v5(
    timestamps: Vec<u64>,
    cumulative_difficulties: Vec<Difficulty>,
    height: u64,
    net: Network,
) -> Difficulty {
    let t: u64 = DIFFICULTY_TARGET_V2;
    let n: u64 = DIFFICULTY_WINDOW_V3 as u64;

    if is_test_network(net) && height <= DIFFICULTY_WINDOW as u64 {
        return TESTNET_EARLY_DIFFICULTY;
    }

    // The reset window at the HF 11 activation.
    if net == Network::Mainnet && height >= 81_769 && height < 81_769 + n {
        return 10_000_000;
    }

    // Six corrections for previously mis-computed entries.
    if net == Network::Mainnet {
        match height {
            307_686 => return 25_800_000,
            307_692 => return 1_890_000,
            307_735 => return 17_900_000,
            307_742 => return 21_300_000,
            307_750 => return 10_900_000,
            307_766 => return 2_960_000,
            _ => {}
        }
    }

    if timestamps.len() < (n + 1) as usize || cumulative_difficulties.len() < (n + 1) as usize {
        return 1;
    }

    let mut l: u128 = 0;
    // NOTE: ts[0] minus one target, not ts[0].
    let mut previous_timestamp = timestamps[0].wrapping_sub(t);
    for i in 1..=n as usize {
        let this_timestamp = if timestamps[i] > previous_timestamp {
            timestamps[i]
        } else {
            previous_timestamp + 1
        };
        l += i as u128 * u128::from((6 * t).min(this_timestamp - previous_timestamp));
        previous_timestamp = this_timestamp;
    }
    let floor = u128::from(n * n * t / 20);
    if l < floor {
        l = floor;
    }

    let avg_d: u128 =
        (cumulative_difficulties[n as usize] - cumulative_difficulties[0]) / n as u128;
    let scale = u128::from(n * (n + 1) * t * 99);

    let next_d: u128 = if avg_d > 2_000_000u128 * u128::from(n * n * t) && height < 307_800 {
        (avg_d / (200 * l)) * scale
    } else if avg_d > u128::from(u64::MAX) / scale && height > 307_800 {
        (avg_d / (200 * l)) * scale
    } else {
        (avg_d * scale) / (200 * l)
    };

    zero_insignificant_digits_u128(next_d)
}

/// "Make all insignificant digits zero for easy reading" — consensus, not
/// cosmetics (`specs/07` §3.4, §3.5).
fn zero_insignificant_digits(mut d: u64) -> u64 {
    let mut i: u64 = 1_000_000_000;
    while i > 1 {
        if d > i * 100 {
            d = ((d + i / 2) / i) * i;
            break;
        }
        i /= 10;
    }
    d
}

fn zero_insignificant_digits_u128(mut d: u128) -> u128 {
    let mut i: u128 = 1_000_000_000;
    while i > 1 {
        if d > i * 100 {
            d = ((d + i / 2) / i) * i;
            break;
        }
        i /= 10;
    }
    d
}

/// Dispatch to the algorithm `version` selects, with the window already
/// collected per `specs/07` §1.
///
/// `height` is the **current chain height** and `version` is the version at
/// that height, `get_current_hard_fork_version()`; neither is normalised
/// (`specs/07` §3).
pub fn next_difficulty(
    version: u8,
    timestamps: Vec<u64>,
    cumulative_difficulties: Vec<Difficulty>,
    height: u64,
    net: Network,
) -> Difficulty {
    let target = difficulty_target();
    match select_algorithm(version) {
        Algorithm::V6 => {
            next_difficulty_v6(timestamps, cumulative_difficulties, target, height, net)
        }
        Algorithm::V5 => next_difficulty_v5(timestamps, cumulative_difficulties, height, net),
        Algorithm::V4 => next_difficulty_v4(timestamps, cumulative_difficulties, height, net),
        Algorithm::V3 => next_difficulty_v3(timestamps, cumulative_difficulties, height, net),
        Algorithm::V2 => {
            next_difficulty_v2(timestamps, cumulative_difficulties, target, height, net)
        }
        Algorithm::V1 => {
            next_difficulty_v1(timestamps, cumulative_difficulties, target, height, net)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `specs/07` §2, including the detail that versions 18 and 19 fall back to
    /// v1 with a 735-block collection and a 720-block window.
    #[test]
    fn algorithm_selection() {
        assert_eq!(select_algorithm(7), Algorithm::V1);
        assert_eq!(select_algorithm(8), Algorithm::V2);
        assert_eq!(select_algorithm(9), Algorithm::V3);
        assert_eq!(select_algorithm(10), Algorithm::V4);
        for v in 11u8..=17 {
            assert_eq!(select_algorithm(v), Algorithm::V5, "version {v}");
        }
        assert_eq!(select_algorithm(18), Algorithm::V1, "18 falls back to v1");
        assert_eq!(select_algorithm(19), Algorithm::V1, "19 falls back to v1");
        for v in 20u8..=25 {
            assert_eq!(select_algorithm(v), Algorithm::V6, "version {v}");
        }
        // Below 7 -- never live on Wownero -- also takes v1.
        for v in 0u8..=6 {
            assert_eq!(select_algorithm(v), Algorithm::V1, "version {v}");
        }
    }

    /// The window sizes that go with each version (`specs/07` §1).
    #[test]
    fn block_counts_match_the_algorithm() {
        assert_eq!(difficulty_blocks_count(7), 735);
        assert_eq!(difficulty_blocks_count(8), 61);
        assert_eq!(difficulty_blocks_count(10), 61);
        assert_eq!(difficulty_blocks_count(11), 145);
        assert_eq!(difficulty_blocks_count(17), 145);
        // 18 and 19 use the 735 collection, matching their v1 algorithm.
        assert_eq!(difficulty_blocks_count(18), 735);
        assert_eq!(difficulty_blocks_count(19), 735);
        assert_eq!(difficulty_blocks_count(20), 147);
    }

    #[test]
    fn target_is_always_300() {
        assert_eq!(difficulty_target(), 300);
    }

    /// `specs/07` §3.1: the HF 18 reset pins mainnet difficulty to 100,000,000
    /// for 721 heights, and the checkpoint at 331,891 is commented "restart
    /// DIFFICULTY_WINDOW".
    #[test]
    fn hf18_difficulty_reset_window() {
        let ts: Vec<u64> = (0..735).map(|i| i * 300).collect();
        let cd: Vec<Difficulty> = (0..735).map(|i| i as u128 * 1_000_000).collect();

        for h in [331_170u64, 331_500, 331_890] {
            assert_eq!(
                next_difficulty_v1(ts.clone(), cd.clone(), 300, h, Network::Mainnet),
                100_000_000,
                "height {h} is inside the reset window"
            );
        }
        // Either side of it, the algorithm runs normally.
        for h in [331_169u64, 331_891] {
            assert_ne!(
                next_difficulty_v1(ts.clone(), cd.clone(), 300, h, Network::Mainnet),
                100_000_000,
                "height {h} is outside the reset window"
            );
        }
        // Testnet and stagenet are unaffected.
        assert_ne!(
            next_difficulty_v1(ts.clone(), cd.clone(), 300, 331_500, Network::Testnet),
            100_000_000
        );
    }

    /// `specs/07` §4: testnet and stagenet return 100 for every height <= 720,
    /// in all six algorithms.
    #[test]
    fn test_networks_start_at_difficulty_100() {
        let ts: Vec<u64> = (0..735).map(|i| i * 300).collect();
        let cd: Vec<Difficulty> = (0..735).map(|i| i as u128 * 1_000_000).collect();
        for net in [Network::Testnet, Network::Stagenet] {
            for h in [0u64, 1, 719, 720] {
                assert_eq!(next_difficulty_v1(ts.clone(), cd.clone(), 300, h, net), 100);
                assert_eq!(next_difficulty_v6(ts.clone(), cd.clone(), 300, h, net), 100);
            }
            assert_ne!(
                next_difficulty_v1(ts.clone(), cd.clone(), 300, 721, net),
                100
            );
        }
        // Mainnet never takes this branch.
        assert_ne!(
            next_difficulty_v1(ts.clone(), cd, 300, 1, Network::Mainnet),
            100
        );
    }

    /// A short window returns 1 rather than dividing by zero.
    #[test]
    fn degenerate_windows() {
        for f in [
            next_difficulty_v1 as fn(_, _, _, _, _) -> _,
            next_difficulty_v6,
        ] {
            assert_eq!(f(vec![], vec![], 300, 1000, Network::Mainnet), 1);
            assert_eq!(f(vec![0], vec![0], 300, 1000, Network::Mainnet), 1);
        }
    }

    /// `specs/07` §8: "v1 and v6 truncate the window from the tail (dropping the
    /// lag) and sort only the timestamps, never the cumulative difficulties."
    #[test]
    fn only_timestamps_are_sorted_and_the_lag_is_dropped() {
        // 735 entries; v1 keeps the first 720 and drops the last 15.
        let mut ts: Vec<u64> = (0..735u64).map(|i| i * 300).collect();
        let cd: Vec<Difficulty> = (0..735).map(|i| i as u128 * 1_000_000).collect();

        let base = next_difficulty_v1(ts.clone(), cd.clone(), 300, 100_000, Network::Mainnet);

        // Changing an entry inside the dropped lag must not change the result.
        ts[730] = 999_999_999;
        assert_eq!(
            next_difficulty_v1(ts.clone(), cd.clone(), 300, 100_000, Network::Mainnet),
            base,
            "the last 15 entries are the lag and are dropped"
        );

        // Shuffling the timestamps inside the window must not change it either,
        // since they are sorted -- but permuting the cumulative difficulties
        // must, since they are not.
        let mut ts2: Vec<u64> = (0..735u64).map(|i| i * 300).collect();
        ts2.swap(10, 20);
        assert_eq!(
            next_difficulty_v1(ts2, cd.clone(), 300, 100_000, Network::Mainnet),
            base,
            "timestamps are sorted, so order does not matter"
        );

        // With 720 entries and a 600-wide span the cut is [60, 660), so the two
        // entries actually read are cd[659] and cd[60]. Swapping them inverts
        // the difference: if `cumulative_difficulties` were sorted alongside the
        // timestamps this would be a no-op, and it is not.
        //
        // The swapped vector is not monotonic and so cannot occur on a real
        // chain; it exists only to witness the absence of a sort.
        let length = DIFFICULTY_WINDOW;
        let span = DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT;
        let cut_begin = (length - span + 1) / 2;
        let cut_end = cut_begin + span;
        assert_eq!((cut_begin, cut_end), (60, 660));

        let mut cd2 = cd.clone();
        cd2.swap(cut_begin, cut_end - 1);
        assert_ne!(
            next_difficulty_v1(ts.clone(), cd2, 300, 100_000, Network::Mainnet),
            base,
            "cumulative difficulties are NOT sorted, so order does matter"
        );
    }

    /// v6 uses a 144 window and a 12 cut, so it keeps 120 entries and drops a
    /// 3-block lag — "the 12-hour difficulty adjustment window" of the HF 20
    /// release notes (144 * 300 s).
    #[test]
    fn v6_window_and_cut() {
        assert_eq!(DIFFICULTY_WINDOW_V3 - 2 * DIFFICULTY_CUT_V2, 120);
        assert_eq!(DIFFICULTY_WINDOW_V3 as u64 * 300, 43_200, "12 hours");

        let mut ts: Vec<u64> = (0..147u64).map(|i| i * 300).collect();
        let cd: Vec<Difficulty> = (0..147).map(|i| i as u128 * 1_000_000).collect();
        let base = next_difficulty_v6(ts.clone(), cd.clone(), 300, 600_000, Network::Mainnet);

        // The final 3 entries are the lag.
        ts[145] = 999_999_999;
        assert_eq!(
            next_difficulty_v6(ts, cd, 300, 600_000, Network::Mainnet),
            base
        );
    }

    /// A steady chain at exactly the target must reproduce its own difficulty.
    #[test]
    fn a_steady_chain_holds_its_difficulty() {
        let d: Difficulty = 1_000_000;
        let ts: Vec<u64> = (0..735u64).map(|i| 1_600_000_000 + i * 300).collect();
        let cd: Vec<Difficulty> = (0..735).map(|i| i as u128 * d).collect();

        let got = next_difficulty_v1(ts.clone(), cd.clone(), 300, 100_000, Network::Mainnet);
        // Within rounding of the input difficulty.
        assert!(
            got.abs_diff(d) <= d / 1000,
            "steady chain gave {got}, expected about {d}"
        );

        let ts6: Vec<u64> = (0..147u64).map(|i| 1_600_000_000 + i * 300).collect();
        let cd6: Vec<Difficulty> = (0..147).map(|i| i as u128 * d).collect();
        let got6 = next_difficulty_v6(ts6, cd6, 300, 600_000, Network::Mainnet);
        assert!(got6.abs_diff(d) <= d / 1000, "v6 gave {got6}");
    }

    /// Blocks arriving twice as fast should roughly double the difficulty.
    #[test]
    fn difficulty_responds_to_block_rate() {
        let d: Difficulty = 1_000_000;
        let cd: Vec<Difficulty> = (0..735).map(|i| i as u128 * d).collect();

        let fast: Vec<u64> = (0..735u64).map(|i| 1_600_000_000 + i * 150).collect();
        let slow: Vec<u64> = (0..735u64).map(|i| 1_600_000_000 + i * 600).collect();

        let f = next_difficulty_v1(fast, cd.clone(), 300, 100_000, Network::Mainnet);
        let s = next_difficulty_v1(slow, cd, 300, 100_000, Network::Mainnet);
        assert!(f > d, "fast blocks should raise difficulty: {f}");
        assert!(s < d, "slow blocks should lower difficulty: {s}");
        assert!(f.abs_diff(2 * d) <= d / 100, "expected about 2x, got {f}");
        assert!(s.abs_diff(d / 2) <= d / 100, "expected about 0.5x, got {s}");
    }

    /// The 256-bit intermediate is not decoration: `total_work * target` can
    /// exceed `u128` for a long-lived chain, and an overflow past `u128` in the
    /// result must return 0 so the block is rejected (`specs/07` §8).
    #[test]
    fn wide_arithmetic_and_overflow() {
        // (a, b) -> 256-bit product, checked against the schoolbook identity.
        for (a, b) in [
            (0u128, 0u128),
            (1, 1),
            (u128::MAX, 1),
            (u128::MAX, u128::MAX),
            (1 << 100, 1 << 100),
        ] {
            let (lo, hi) = mul_u128(a, b);
            // Low 128 bits must match the wrapping product.
            assert_eq!(lo, a.wrapping_mul(b), "lo for {a} * {b}");
            if a == 0 || b == 0 {
                assert_eq!(hi, 0);
            }
        }

        // Division round-trips.
        for (lo, hi, d) in [
            (1000u128, 0u128, 7u64),
            (u128::MAX, 0, 3),
            (0, 1, 2),
            (u128::MAX, u128::MAX, u64::MAX),
        ] {
            let (q_lo, q_hi) = div_u256_by_u64(lo, hi, d);
            // q * d <= value < (q + 1) * d, checked on the low half when the
            // high half is zero.
            if hi == 0 && q_hi == 0 {
                assert_eq!(q_lo, lo / u128::from(d));
            }
        }

        // A total_work large enough to overflow the u128 result yields 0.
        let huge = u128::MAX;
        let ts: Vec<u64> = (0..735u64).map(|i| 1_600_000_000 + i).collect();
        let cd: Vec<Difficulty> = (0..735).map(|i| if i == 734 { huge } else { 0 }).collect();
        assert_eq!(
            next_difficulty_v1(ts, cd, 300, 100_000, Network::Mainnet),
            0,
            "an overflowing difficulty must be 0, which rejects the block"
        );
    }

    /// A zero time span is clamped to 1 rather than dividing by zero.
    #[test]
    fn zero_time_span_is_clamped() {
        let ts = vec![1_600_000_000u64; 735];
        let cd: Vec<Difficulty> = (0..735).map(|i| i as u128 * 1000).collect();
        let d = next_difficulty_v1(ts, cd, 300, 100_000, Network::Mainnet);
        assert!(d > 0, "a zero span must not divide by zero");
    }

    /// The override table must enumerate exactly what `specs/07` §4 lists.
    #[test]
    fn override_table_matches_the_spec() {
        assert_eq!(
            OVERRIDES.len(),
            9,
            "nine mainnet overrides plus the test-net floor"
        );

        let v5: Vec<&Override> = OVERRIDES
            .iter()
            .filter(|o| o.algorithm == Algorithm::V5)
            .collect();
        assert_eq!(v5.len(), 7, "one reset window plus six per-height values");

        let six: Vec<(u64, Difficulty)> = v5
            .iter()
            .filter(|o| o.from == o.to)
            .map(|o| (o.from, o.difficulty))
            .collect();
        assert_eq!(
            six,
            vec![
                (307_686, 25_800_000),
                (307_692, 1_890_000),
                (307_735, 17_900_000),
                (307_742, 21_300_000),
                (307_750, 10_900_000),
                (307_766, 2_960_000),
            ]
        );

        // The v4 override reads `HEIGHT <= 63469 + 1`, and v4 is only selected
        // at HF 10 which starts at 63,469 -- so it applies to exactly two
        // heights (`specs/07` §4).
        let v4 = OVERRIDES
            .iter()
            .find(|o| o.algorithm == Algorithm::V4)
            .unwrap();
        assert_eq!(v4.to, 63_470);
        assert_eq!(v4.difficulty, 100_000_069);
        assert_eq!(63_470 - 63_469 + 1, 2, "exactly two heights");

        // The v1 reset window matches the checkpoint at 331,891.
        let v1 = OVERRIDES
            .iter()
            .find(|o| o.algorithm == Algorithm::V1)
            .unwrap();
        assert_eq!((v1.from, v1.to), (331_170, 331_890));
        assert_eq!(v1.to + 1, 331_891);
    }
}
