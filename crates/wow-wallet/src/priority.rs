//! Which fee tier a transaction pays: `wallet2::adjust_priority` and
//! `wallet2::get_base_fee(priority)`.
//!
//! # Priority 0 is not "normal"
//!
//! Priorities 1 to 4 name the four per-byte rates `get_fee_estimate` returns:
//! unimportant, normal, elevated, priority. **0** means "let the wallet
//! choose", and the C++ chooses **unimportant** unless the network looks busy
//! -- a backlog in the pool at that rate, or recent blocks more than 80% full.
//! Reading 0 as normal instead charges about four times the fee on a quiet
//! chain.
//!
//! When the choice cannot be made -- a daemon call fails, the wallet holds
//! fewer than ten blocks -- `adjust_priority` hands the 0 back, and
//! `get_base_fee` maps a 0 that reaches it to the lowest tier all the same.
//!
//! # The backlog, and not the pool
//!
//! The backlog is read with `get_txpool_backlog`, as `estimate_backlog` reads
//! it: a weight and a fee per transaction. Downloading the whole pool to work
//! that out, as this once did, sent the daemon a request no C++ wallet makes,
//! at the moment it was about to send, and fetched every blob in the pool to
//! read two numbers from each. A daemon that does not serve the call (this
//! workspace's does not yet) fails it, and the 0 comes back.

use wow_daemon_client::DaemonClient;

use crate::keys_file::KeysFile;

/// `FEE_ESTIMATE_GRACE_BLOCKS`: how many blocks the estimate should hold for.
pub const FEE_ESTIMATE_GRACE_BLOCKS: u64 = 10;

/// `allowed_priority_strings`, indexed by priority.
pub const PRIORITY_NAMES: [&str; 5] = ["default", "unimportant", "normal", "elevated", "priority"];

/// How many blocks below the wallet's height `adjust_priority` weighs.
const RECENT_BLOCKS: usize = 10;

/// Recent blocks fuller than this share of the full reward zone are busy.
const BUSY_PERCENT: u64 = 80;

/// The two persisted settings `adjust_priority` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrioritySettings {
    /// `default_priority`, 0 to 4.
    pub default_priority: u32,
    /// `auto_low_priority`.
    pub auto_low_priority: bool,
}

impl PrioritySettings {
    pub fn from_keys_file(keys_file: &KeysFile) -> Self {
        PrioritySettings {
            default_priority: keys_file.default_priority(),
            auto_low_priority: keys_file.auto_low_priority(),
        }
    }
}

/// A priority by name or by number, 0 to 4.
pub fn parse_priority(s: &str) -> Option<u32> {
    PRIORITY_NAMES
        .iter()
        .position(|n| *n == s)
        .map(|i| i as u32)
        .or_else(|| s.parse::<u32>().ok().filter(|p| *p <= 4))
}

/// `get_base_fee(priority)` from the 2021 scaling: the rate for a priority.
///
/// 0 takes the lowest tier and anything past 4 the highest. A daemon that
/// gives a single rate rather than four has it used for every priority.
pub fn fee_per_byte(tiers: &[u64], priority: u32) -> u64 {
    let index = priority.clamp(1, 4) as usize - 1;
    tiers.get(index).or(tiers.first()).copied().unwrap_or(0)
}

/// `wallet2::adjust_priority(priority)`.
///
/// Only a 0, with no default priority set and `auto-low-priority` on, is
/// adjusted; anything else comes back as given. `wallet_height` is how far the
/// wallet has scanned: the C++ weighs the ten blocks below its own chain, not
/// the daemon's. `tiers` is `get_fee_estimate` at
/// [`FEE_ESTIMATE_GRACE_BLOCKS`].
///
/// The daemon calls come in the C++'s order, because a backlog answers 2
/// before the block weights are ever asked for, and a failure after that point
/// answers 0.
pub fn adjust_priority(
    client: &DaemonClient,
    priority: u32,
    settings: PrioritySettings,
    wallet_height: u64,
    tiers: &[u64],
) -> u32 {
    if priority != 0 || settings.default_priority != 0 || !settings.auto_low_priority {
        return priority;
    }

    // `estimate_backlog`. Every throw in the C++ lands in one `catch`, which
    // leaves the priority at 0 -- a zero rate and a zero reward zone included.
    let low = fee_per_byte(tiers, 1);
    let Ok(backlog) = client.get_txpool_backlog() else {
        return 0;
    };
    let Ok(info) = client.get_info() else {
        return 0;
    };
    let full_reward_zone = info.block_weight_limit / 2;
    if low == 0 || full_reward_zone == 0 {
        return 0;
    }
    let backlog: Vec<(u64, u64)> = backlog.iter().map(|e| (e.weight, e.fee)).collect();
    if backlog_blocks(&backlog, low, full_reward_zone) > 0 {
        // "We don't use the low priority because there's a backlog in the tx
        // pool."
        return 2;
    }

    if wallet_height < RECENT_BLOCKS as u64 {
        return 0;
    }
    let Ok(weights) =
        client.get_block_weights(wallet_height - RECENT_BLOCKS as u64, wallet_height - 1)
    else {
        return 0;
    };
    if weights.len() != RECENT_BLOCKS {
        return 0;
    }
    if fullness_percent(&weights, full_reward_zone) > BUSY_PERCENT {
        // "We don't use the low priority because recent blocks are quite full."
        2
    } else {
        1
    }
}

/// `estimate_backlog` for one rate: how many full reward zones the pool's
/// transactions paying at least `fee_per_byte` would fill.
///
/// `backlog` is `(weight, fee)` per transaction. A weightless entry is skipped,
/// as the C++ skips it.
pub fn backlog_blocks(backlog: &[(u64, u64)], fee_per_byte: u64, full_reward_zone: u64) -> u64 {
    let ahead: u64 = backlog
        .iter()
        .filter(|(weight, fee)| {
            *weight > 0 && *fee as u128 >= fee_per_byte as u128 * *weight as u128
        })
        .map(|(weight, _)| *weight)
        .sum();
    ahead / full_reward_zone
}

/// How much of the full reward zone the given blocks filled, in whole percent,
/// rounded down.
pub fn fullness_percent(weights: &[u64], full_reward_zone: u64) -> u64 {
    let sum: u128 = weights.iter().map(|w| *w as u128).sum();
    let capacity = weights.len() as u128 * full_reward_zone as u128;
    if capacity == 0 {
        return 0;
    }
    (100 * sum / capacity) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tiers the network gave on 2026-09-14.
    const TIERS: [u64; 4] = [260_000, 1_100_000, 4_100_000, 51_000_000];

    #[test]
    fn priorities_parse_by_name_and_by_number() {
        assert_eq!(parse_priority("default"), Some(0));
        assert_eq!(parse_priority("unimportant"), Some(1));
        assert_eq!(parse_priority("normal"), Some(2));
        assert_eq!(parse_priority("priority"), Some(4));
        assert_eq!(parse_priority("0"), Some(0));
        assert_eq!(parse_priority("3"), Some(3));
        assert_eq!(parse_priority("5"), None);
        assert_eq!(parse_priority("-1"), None);
        assert_eq!(parse_priority("Wo1abc"), None);
    }

    /// A 0 that reaches the fee pays the lowest tier, not normal.
    #[test]
    fn a_zero_priority_pays_the_lowest_tier() {
        assert_eq!(fee_per_byte(&TIERS, 0), 260_000);
        assert_eq!(fee_per_byte(&TIERS, 1), 260_000);
        assert_eq!(fee_per_byte(&TIERS, 2), 1_100_000);
        assert_eq!(fee_per_byte(&TIERS, 3), 4_100_000);
        assert_eq!(fee_per_byte(&TIERS, 4), 51_000_000);
        assert_eq!(
            fee_per_byte(&TIERS, 9),
            51_000_000,
            "clamped to the highest"
        );

        assert_eq!(
            fee_per_byte(&[7], 3),
            7,
            "a single rate serves every priority"
        );
        assert_eq!(fee_per_byte(&[], 2), 0);
    }

    /// Only an unset priority is adjusted. Every case here returns before the
    /// daemon is asked anything, so nothing needs to listen.
    #[test]
    fn only_an_unset_priority_is_adjusted() {
        let client = DaemonClient::new("127.0.0.1:1");
        let auto = PrioritySettings {
            default_priority: 0,
            auto_low_priority: true,
        };

        assert_eq!(adjust_priority(&client, 3, auto, 1_000, &TIERS), 3);
        assert_eq!(adjust_priority(&client, 1, auto, 1_000, &TIERS), 1);

        let with_default = PrioritySettings {
            default_priority: 2,
            ..auto
        };
        assert_eq!(
            adjust_priority(&client, 0, with_default, 1_000, &TIERS),
            0,
            "a default priority turns the adjustment off, and the 0 stays"
        );

        let off = PrioritySettings {
            auto_low_priority: false,
            ..auto
        };
        assert_eq!(adjust_priority(&client, 0, off, 1_000, &TIERS), 0);
    }

    /// A backlog is whole reward zones of transactions paying at least the
    /// rate; anything paying less is behind us and does not count.
    #[test]
    fn a_backlog_counts_what_pays_at_least_the_rate() {
        let zone = 300_000;
        let rate = 260_000;

        let paying = [(200_000, 200_000 * rate), (200_000, 200_000 * rate)];
        assert_eq!(backlog_blocks(&paying, rate, zone), 1);
        assert_eq!(backlog_blocks(&paying[..1], rate, zone), 0, "under a zone");

        let under = [(200_000, 200_000 * rate - 1), (200_000, 200_000 * rate - 1)];
        assert_eq!(
            backlog_blocks(&under, rate, zone),
            0,
            "a hair under the rate"
        );

        assert_eq!(backlog_blocks(&[(0, u64::MAX)], 1, 1), 0, "weightless");
        assert_eq!(backlog_blocks(&[], rate, zone), 0);
    }

    /// Busy means more than 80%: exactly 80 still gets the low tier.
    #[test]
    fn recent_blocks_are_busy_above_eighty_percent() {
        let zone = 300_000;

        // The network's last ten blocks on 2026-09-14.
        let quiet = [96, 96, 96, 3_542, 96, 96, 96, 96, 2_703, 2_698];
        assert_eq!(fullness_percent(&quiet, zone), 0);

        assert_eq!(fullness_percent(&[240_000; 10], zone), 80);
        assert!(fullness_percent(&[240_000; 10], zone) <= BUSY_PERCENT);
        assert_eq!(fullness_percent(&[243_000; 10], zone), 81);
        assert!(fullness_percent(&[243_000; 10], zone) > BUSY_PERCENT);

        assert_eq!(fullness_percent(&[], zone), 0);
    }
}
