//! Block timestamp rules and adjusted time.
//!
//! `specs/06-consensus-rules.md` §2.1 and §2.2.
//!
//! Both take the **tip's** hard-fork version, not the version of the block
//! being validated (`specs/06` §9.4).

use crate::constants::*;
use crate::emission::median;

/// `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT` / `..._V2` — how far ahead of the
/// wall clock a block's timestamp may be.
///
/// 7200 s below HF 8, 600 s from HF 8. Wownero's 300 s target makes the newer
/// limit two blocks' worth.
pub const fn future_time_limit(hf_version: u8) -> u64 {
    if hf_version >= 8 {
        CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2
    } else {
        CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT
    }
}

/// `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` / `..._V2` — 60 blocks below HF 10,
/// 11 from HF 10.
pub const fn timestamp_check_window(hf_version: u8) -> usize {
    if hf_version >= 10 {
        BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2
    } else {
        BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW
    }
}

/// Why a timestamp was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampError {
    /// `block.timestamp > now + ftl`.
    TooFarInTheFuture { limit: u64 },
    /// `block.timestamp < median(last window timestamps)`.
    BelowMedian { median: u64 },
}

/// `check_block_timestamp` (`specs/06` §2.1).
///
/// ```text
/// ftl    = if hf >= 8  { 600 } else { 7200 }
/// window = if hf >= 10 { 11 }  else { 60 }
///
/// reject if timestamp > now + ftl
/// if chain_height >= window { reject if timestamp < median(last window) }
/// ```
///
/// `now` is the caller's wall clock — `time(NULL)` in the C. It is passed in
/// rather than read here so the rule stays a pure function; a node reads the
/// clock once per block and a test supplies a fixed value.
///
/// `recent_timestamps` are the timestamps of the last
/// [`timestamp_check_window`] blocks. Fewer than a full window means the chain
/// is shorter than the window, and the median check does not apply — the C
/// tests `m_db->height() < window` for exactly this.
pub fn check_block_timestamp(
    hf_version: u8,
    timestamp: u64,
    now: u64,
    recent_timestamps: &mut [u64],
) -> Result<(), TimestampError> {
    let ftl = future_time_limit(hf_version);
    let limit = now.saturating_add(ftl);
    if timestamp > limit {
        return Err(TimestampError::TooFarInTheFuture { limit });
    }

    let window = timestamp_check_window(hf_version);
    if recent_timestamps.len() < window {
        return Ok(());
    }
    let m = median(recent_timestamps);
    if timestamp < m {
        return Err(TimestampError::BelowMedian { median: m });
    }
    Ok(())
}

/// `get_adjusted_time(height)` (`specs/06` §2.2) — the deterministic clock
/// used for time-based unlock evaluation from HF 16.
///
/// ```text
/// if height < window { return now }                  // wall clock
/// ts        = timestamps of [height - window, height)
/// median_ts = median(ts) + (window + 1) * 300 / 2
/// adjusted  = ts.last() + 300
/// min(adjusted, median_ts)
/// ```
///
/// Three things the name hides:
///
/// * the projection constant is a hard-coded `DIFFICULTY_TARGET_V2` (300), not
///   the version-dependent target;
/// * `(window + 1) * 300 / 2` is evaluated left to right in `size_t`, so for
///   the 11-block window it is `12 * 300 / 2 = 1800`, exactly;
/// * below the window it falls back to the **wall clock**, which is the one
///   case where this is not deterministic. That only happens in the first 11
///   (or 60) blocks of a chain.
///
/// `window_timestamps` must be the timestamps of `[height - window, height)`
/// in ascending height order; `median` sorts a copy of the slice, but the
/// `ts.last()` projection reads the **last element as given**, so the order
/// matters.
pub fn get_adjusted_time(
    hf_version: u8,
    height: u64,
    window_timestamps: &[u64],
    wall_clock_now: u64,
) -> u64 {
    let window = timestamp_check_window(hf_version);
    if height < window as u64 || window_timestamps.is_empty() {
        return wall_clock_now;
    }

    let mut sorted = window_timestamps.to_vec();
    let median_ts = median(&mut sorted) + (window as u64 + 1) * DIFFICULTY_TARGET_V2 / 2;

    // The *last by height*, not the largest.
    let adjusted = window_timestamps[window_timestamps.len() - 1] + DIFFICULTY_TARGET_V2;

    adjusted.min(median_ts)
}

/// `is_tx_spendtime_unlocked(unlock_time)` (`specs/06` §5.9).
///
/// ```text
/// if unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER (500_000_000) {
///     (db_height - 1) + 1 >= unlock_time                  // height-based
/// } else {
///     now + 300 >= unlock_time                            // time-based
/// }
/// ```
///
/// `now` is [`get_adjusted_time`] from HF 16 and the wall clock before it —
/// that switch is what makes unlock evaluation deterministic across nodes
/// (`specs/06` §5.9). Pass whichever the caller's hard-fork version selects.
///
/// The height branch reads `(db_height - 1) + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS`,
/// which is just `db_height` — written the long way because the two terms come
/// from different constants and only coincide because the delta is 1.
pub fn is_tx_spendtime_unlocked(unlock_time: u64, db_height: u64, now: u64) -> bool {
    if unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER {
        db_height.saturating_sub(1) + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time
    } else {
        now.saturating_add(CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2) >= unlock_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limits_switch_at_the_right_forks() {
        assert_eq!(future_time_limit(7), 7_200);
        assert_eq!(future_time_limit(8), 600);
        assert_eq!(future_time_limit(20), 600);

        assert_eq!(timestamp_check_window(9), 60);
        assert_eq!(timestamp_check_window(10), 11);
        assert_eq!(timestamp_check_window(20), 11);
    }

    /// `specs/06` §2.1: the future limit is against the wall clock, inclusive.
    #[test]
    fn a_timestamp_may_reach_the_future_limit_but_not_pass_it() {
        let now = 1_700_000_000u64;
        assert!(check_block_timestamp(20, now + 600, now, &mut []).is_ok());
        assert_eq!(
            check_block_timestamp(20, now + 601, now, &mut []),
            Err(TimestampError::TooFarInTheFuture { limit: now + 600 })
        );
        // Before HF 8 the window is twelve times wider.
        assert!(check_block_timestamp(7, now + 7_200, now, &mut []).is_ok());
        assert!(check_block_timestamp(7, now + 7_201, now, &mut []).is_err());
    }

    /// The median check needs a full window; a short chain skips it entirely.
    #[test]
    fn the_median_check_needs_a_full_window() {
        let now = 1_700_000_000u64;
        // 10 timestamps is one short of the HF 10 window.
        let mut short: Vec<u64> = (0..10).map(|i| now - 10_000 + i).collect();
        assert!(
            check_block_timestamp(20, 0, now, &mut short).is_ok(),
            "a zero timestamp passes while the window is not full"
        );

        let mut full: Vec<u64> = (0..11).map(|i| now - 10_000 + i).collect();
        let m = median(&mut full.clone());
        assert!(
            check_block_timestamp(20, m, now, &mut full).is_ok(),
            "equal is fine"
        );
        assert_eq!(
            check_block_timestamp(20, m - 1, now, &mut full),
            Err(TimestampError::BelowMedian { median: m })
        );
    }

    /// `check_block_timestamp` does not sort its caller's data destructively in
    /// a way that changes the answer — but it *does* sort, so the caller must
    /// pass a copy if order matters to it. Pin the median value itself.
    #[test]
    fn the_median_is_over_the_whole_window() {
        let now = 2_000_000u64;
        // A single very old block in an otherwise recent window must not drag
        // the median down to it.
        let mut ts = vec![now - 1; 11];
        ts[0] = 0;
        let m = median(&mut ts.clone());
        assert_eq!(m, now - 1, "one outlier of eleven does not move the median");
        assert!(check_block_timestamp(20, now - 1, now, &mut ts).is_ok());
    }

    /// `specs/06` §2.2: below the window there is no median, so the wall clock
    /// is returned — the one non-deterministic case.
    #[test]
    fn adjusted_time_falls_back_to_the_wall_clock() {
        let now = 1_700_000_000u64;
        assert_eq!(
            get_adjusted_time(20, 10, &[1, 2, 3], now),
            now,
            "height < 11"
        );
        assert_eq!(
            get_adjusted_time(9, 59, &[1, 2, 3], now),
            now,
            "height < 60"
        );
        assert_eq!(get_adjusted_time(20, 11, &[], now), now, "no timestamps");
    }

    /// The projection is `min(last + 300, median + 1800)`, and which side wins
    /// depends on how spread out the window is.
    #[test]
    fn adjusted_time_takes_the_smaller_projection() {
        let base = 1_700_000_000u64;

        // Blocks arriving at the 300 s target: last + 300 is the smaller.
        let on_target: Vec<u64> = (0..11).map(|i| base + i * 300).collect();
        let last = base + 10 * 300;
        let median_ts = median(&mut on_target.clone()) + 12 * 300 / 2;
        let got = get_adjusted_time(20, 1_000, &on_target, 0);
        assert_eq!(got, (last + 300).min(median_ts));
        assert_eq!(
            got,
            last + 300,
            "a steady chain projects from the last block"
        );

        // A stalled chain that then jumps: the median caps the projection.
        let mut stalled = vec![base; 10];
        stalled.push(base + 1_000_000);
        let got = get_adjusted_time(20, 1_000, &stalled, 0);
        assert_eq!(
            got,
            median(&mut stalled.clone()) + 1_800,
            "the median wins when the last block is far ahead"
        );
        assert!(got < base + 1_000_000 + 300);
    }

    /// The projection constant is `(window + 1) * 300 / 2` — 1800 for the
    /// 11-block window, 9150 for the 60-block one. Not `window * 300`.
    #[test]
    fn the_projection_constant_is_exact() {
        assert_eq!((11u64 + 1) * DIFFICULTY_TARGET_V2 / 2, 1_800);
        assert_eq!((60u64 + 1) * DIFFICULTY_TARGET_V2 / 2, 9_150);

        let base = 1_700_000_000u64;
        let flat = vec![base; 11];
        // With a flat window the median is `base`, so median_ts = base + 1800
        // and adjusted = base + 300; the smaller wins.
        assert_eq!(get_adjusted_time(20, 1_000, &flat, 0), base + 300);

        // Force the median side by making the last element the only large one.
        let mut spiky = vec![base; 11];
        spiky[10] = base + 100_000;
        assert_eq!(get_adjusted_time(20, 1_000, &spiky, 0), base + 1_800);
    }

    /// `get_adjusted_time` reads `timestamps.back()` — the last by *height*,
    /// not the largest value. A non-monotonic window (which is legal: the rule
    /// is only that a timestamp is at least the median) must be read in order.
    #[test]
    fn adjusted_time_reads_the_last_block_not_the_largest() {
        let base = 1_700_000_000u64;
        // The largest value sits in the middle; the last is smaller.
        let mut ts = vec![base; 11];
        ts[5] = base + 500_000;
        ts[10] = base + 100;

        let got = get_adjusted_time(20, 1_000, &ts, 0);
        assert_eq!(got, (base + 100 + 300).min(median(&mut ts.clone()) + 1_800));
        assert_eq!(got, base + 400, "projected from ts[10], not ts[5]");
    }

    /// `specs/06` §5.9: the discriminator is 500,000,000, and the height branch
    /// is off by the allowed delta.
    #[test]
    fn spendtime_height_branch() {
        // An output unlocked at height 100 is spendable once db_height is 100.
        assert!(is_tx_spendtime_unlocked(100, 100, 0));
        assert!(!is_tx_spendtime_unlocked(100, 99, 0));
        assert!(is_tx_spendtime_unlocked(0, 0, 0), "never locked");

        // The largest height-based value.
        let max_h = CRYPTONOTE_MAX_BLOCK_NUMBER - 1;
        assert!(is_tx_spendtime_unlocked(max_h, max_h, 0));
        assert!(!is_tx_spendtime_unlocked(max_h, max_h - 1, 0));
    }

    /// At and above 500,000,000 the value is a Unix time, not a height — the
    /// switch is exact, and reading it the other way would unlock a locked
    /// output or lock a spendable one.
    #[test]
    fn spendtime_time_branch() {
        let t = CRYPTONOTE_MAX_BLOCK_NUMBER; // exactly at the boundary
                                             // Read as a time: needs now + 300 >= t.
        assert!(is_tx_spendtime_unlocked(t, u64::MAX, t - 300));
        assert!(!is_tx_spendtime_unlocked(t, u64::MAX, t - 301));
        // The height branch would have said yes for any db_height >= t.
        assert!(
            !is_tx_spendtime_unlocked(t, t, 0),
            "500_000_000 is a time, so a huge db_height does not unlock it"
        );

        // One below is a height, and the same db_height does unlock it.
        assert!(is_tx_spendtime_unlocked(t - 1, t - 1, 0));
    }
}
