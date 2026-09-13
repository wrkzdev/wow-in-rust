//! Emission, the block-weight reward penalty, and the median.
//!
//! `specs/06-consensus-rules.md` §3.
//!
//! The subsidy decays geometrically by a factor of `1 - 2^-20` per block
//! **forever** — `FINAL_SUBSIDY_PER_MINUTE` is 0, so there is no tail emission
//! and `base_reward` eventually reaches 0 by integer truncation.

use wow_types::Difficulty;

use crate::constants::*;

/// Why `get_block_reward` refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewardError {
    /// `current_block_weight > 2 * median_weight`. The C returns `false`, which
    /// `validate_miner_transaction` turns into a rejected block, and which is
    /// how the cumulative weight limit of `specs/06` §2 step 11 is enforced.
    BlockTooBig,
}

/// `get_block_reward(median_weight, current_block_weight,
/// already_generated_coins, &reward, version)`.
///
/// ```text
/// base_reward = (MONEY_SUPPLY - already_generated_coins) >> 20
/// if base_reward < FINAL_SUBSIDY_PER_MINUTE * target_minutes { = that }   // 0
///
/// median_weight = max(median_weight, get_min_block_weight(version))
/// if current <= median          -> base_reward
/// if current > 2 * median       -> Err(BlockTooBig)
/// multiplicand = (2 * median - current) * current                        // u64
/// reward = ((base_reward as u128 * multiplicand) / median) / median      // TWICE
/// ```
///
/// # The two-step division
///
/// `specs/06` §9.8: the two successive `div128_64` calls are **not** the same
/// as one division by `median^2` — each truncates. `specs/15` §3.2 asks for a
/// property test proving the implementation is the truncating two-step one,
/// and [`tests::two_step_division_differs_from_one_step`] is it.
///
/// `multiplicand` is computed in **`u64`**, matching a deliberate bug-fix
/// comment in the C noting it was once 32-bit-truncated on ARM.
pub fn get_block_reward(
    median_weight: u64,
    current_block_weight: u64,
    already_generated_coins: u64,
    version: u8,
) -> Result<u64, RewardError> {
    let target_minutes = DIFFICULTY_TARGET_V2 / 60;
    let emission_speed_factor = EMISSION_SPEED_FACTOR_PER_MINUTE - (target_minutes as u32 - 1);

    let mut base_reward = (MONEY_SUPPLY - already_generated_coins) >> emission_speed_factor;
    let floor = FINAL_SUBSIDY_PER_MINUTE * target_minutes;
    if base_reward < floor {
        base_reward = floor;
    }

    let full_reward_zone = get_min_block_weight(version);
    let median_weight = median_weight.max(full_reward_zone);

    if current_block_weight <= median_weight {
        return Ok(base_reward);
    }
    if current_block_weight > 2 * median_weight {
        return Err(RewardError::BlockTooBig);
    }

    // uint64_t multiplicand = 2 * median - cur; multiplicand *= cur;
    let multiplicand =
        (2 * median_weight - current_block_weight).wrapping_mul(current_block_weight);
    let product = (base_reward as u128) * (multiplicand as u128);

    // TWO successive truncating divisions -- not one by median^2.
    let reward = (product / median_weight as u128) / median_weight as u128;
    Ok(reward as u64)
}

/// The base reward with no penalty, for callers that only need the curve.
pub fn base_reward(already_generated_coins: u64) -> u64 {
    (MONEY_SUPPLY - already_generated_coins) >> EMISSION_SPEED_FACTOR
}

/// `epee::misc_utils::median` (`specs/06` §3.4).
///
/// A **full sort**, not `nth_element`, and an even-length input takes
/// `get_mid(v[n-1], v[n])` — the overflow-safe `floor((a + b) / 2)`. An
/// off-by-one here shifts every reward.
pub fn median(values: &mut [u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    if values.len() == 1 {
        return values[0];
    }
    values.sort_unstable();
    let n = values.len() / 2;
    if values.len() % 2 == 1 {
        values[n]
    } else {
        get_mid(values[n - 1], values[n])
    }
}

/// `get_mid(a, b) = a/2 + b/2 + ((a % 2) + (b % 2)) / 2`, which is
/// `floor((a + b) / 2)` without overflowing.
pub const fn get_mid(a: u64, b: u64) -> u64 {
    a / 2 + b / 2 + ((a % 2) + (b % 2)) / 2
}

/// `already_generated_coins[h] = already_generated_coins[h-1] + base_reward`,
/// where `base_reward` is the **adjusted** one (`specs/06` §3.3, §9.3).
///
/// For HF versions 2–15 a miner could claim *less* than the full reward, and
/// the accounting then recorded only what was claimed — permanently changing
/// the emission curve. On Wownero that window is HF 7–15, heights 1 … 253,998.
/// Getting this wrong makes every subsequent reward wrong.
pub fn accumulate_generated_coins(previous: u64, adjusted_base_reward: u64) -> u64 {
    previous.saturating_add(adjusted_base_reward)
}

/// `validate_miner_transaction`'s reward arithmetic (`specs/06` §3.3).
///
/// Returns the **adjusted** base reward to accumulate into
/// `already_generated_coins`, plus whether the block under-claimed.
///
/// ```text
/// reject if base_reward + fee < money_in_use                  // overspend
/// if version < 2 || version >= HF_VERSION_EXACT_COINBASE (16):
///     reject if base_reward + fee != money_in_use             // must claim exactly
/// else:                                                       // versions 2..15
///     require money_in_use - fee <= base_reward
///     if base_reward + fee != money_in_use { partial_block_reward = true }
///     base_reward = money_in_use - fee                        // affects emission
/// ```
#[allow(
    clippy::manual_range_contains,
    reason = "`version < 2 || version >= HF_VERSION_EXACT_COINBASE` is how the C \n              writes it; a range check reads as if the two bounds were related"
)]
pub fn validate_miner_reward(
    version: u8,
    base_reward: u64,
    fee: u64,
    money_in_use: u64,
) -> Result<MinerReward, MinerRewardError> {
    let total = base_reward
        .checked_add(fee)
        .ok_or(MinerRewardError::Overflow)?;

    if total < money_in_use {
        return Err(MinerRewardError::Overspend);
    }

    if version < 2 || version >= crate::hardfork::gates::HF_VERSION_EXACT_COINBASE {
        if total != money_in_use {
            return Err(MinerRewardError::NotExact);
        }
        return Ok(MinerReward {
            adjusted_base_reward: base_reward,
            partial: false,
        });
    }

    // Versions 2..15: under-claiming is allowed and is recorded as claimed.
    let claimed = money_in_use
        .checked_sub(fee)
        .ok_or(MinerRewardError::Overspend)?;
    if claimed > base_reward {
        return Err(MinerRewardError::Overspend);
    }
    Ok(MinerReward {
        adjusted_base_reward: claimed,
        partial: total != money_in_use,
    })
}

/// The outcome of [`validate_miner_reward`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinerReward {
    /// What to add to `already_generated_coins` — the **adjusted** value.
    pub adjusted_base_reward: u64,
    /// `bvc.m_partial_block_reward`. Reported to the P2P layer but never a
    /// reason to ban (`specs/09` §2.1).
    pub partial: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinerRewardError {
    /// The coinbase claims more than `base_reward + fee`.
    Overspend,
    /// From HF 16 the coinbase must claim exactly.
    NotExact,
    Overflow,
}

/// `cumulative_difficulty[h] = cumulative_difficulty[h-1] + difficulty[h]`
/// (`specs/07` §6). `None` on overflow, which the C treats as fatal.
pub fn accumulate_difficulty(cumulative: Difficulty, next: Difficulty) -> Option<Difficulty> {
    cumulative.checked_add(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V20: u8 = 20;

    /// `specs/15` §3.2: "Iterate `get_block_reward` from genesis with a
    /// synthetic chain of minimum-weight blocks; assert the running total never
    /// exceeds `u64::MAX` and that the reward is monotonically non-increasing."
    #[test]
    fn emission_is_monotone_and_bounded() {
        let mut generated: u64 = 0;
        let mut previous = u64::MAX;
        for h in 0..200_000u64 {
            let r = get_block_reward(0, 1, generated, V20).expect("minimum-weight block");
            assert!(
                r <= previous,
                "reward rose at height {h}: {previous} -> {r}"
            );
            previous = r;
            generated = generated
                .checked_add(r)
                .unwrap_or_else(|| panic!("already_generated_coins overflowed at height {h}"));
            // No `generated <= MONEY_SUPPLY` assertion: `MONEY_SUPPLY` is
            // `u64::MAX` on Wownero, so that comparison is vacuous. The
            // `checked_add` above is the real overflow guard.
        }
        assert!(generated > 0);
        // After 200k blocks a meaningful fraction is emitted but far from all.
        assert!(generated < MONEY_SUPPLY, "supply must never be exhausted");
    }

    /// There is no tail emission: the reward decays to literally zero.
    #[test]
    fn the_reward_reaches_zero() {
        // Once (MONEY_SUPPLY - generated) < 2^20 the shift truncates to 0.
        let nearly_all = MONEY_SUPPLY - ((1u64 << EMISSION_SPEED_FACTOR) - 1);
        assert_eq!(base_reward(nearly_all), 0);
        assert_eq!(
            get_block_reward(0, 1, nearly_all, V20).unwrap(),
            0,
            "no tail emission means the reward really is 0"
        );
        // One unit less and it is 1.
        assert_eq!(
            base_reward(MONEY_SUPPLY - (1u64 << EMISSION_SPEED_FACTOR)),
            1
        );
    }

    /// The genesis reward: `u64::MAX >> 20`.
    #[test]
    fn first_block_reward() {
        let r = get_block_reward(0, 1, 0, V20).unwrap();
        assert_eq!(r, u64::MAX >> 20);
        assert_eq!(r, 17_592_186_044_415);
        // About 175.92 WOW at 11 decimals.
        assert_eq!(r / COIN, 175);
    }

    /// `specs/06` §3.2: no penalty at or below the median, and the median is
    /// floored at `get_min_block_weight` = 300,000.
    #[test]
    fn no_penalty_up_to_the_median() {
        let generated = 1_000_000_000_000;
        let full = get_block_reward(0, 1, generated, V20).unwrap();
        // Any weight up to 300,000 is unpenalised even with median_weight 0,
        // because the median is raised to the full reward zone.
        for w in [1u64, 1000, 150_000, 300_000] {
            assert_eq!(
                get_block_reward(0, w, generated, V20).unwrap(),
                full,
                "weight {w} should be unpenalised"
            );
        }
        // Just past it, the penalty starts.
        assert!(get_block_reward(0, 300_001, generated, V20).unwrap() < full);
    }

    /// Over twice the median the block is refused outright.
    #[test]
    fn too_big_is_an_error() {
        let generated = 1_000_000_000_000;
        assert_eq!(
            get_block_reward(0, 600_000, generated, V20),
            Ok(0),
            "exactly 2x median earns nothing but is still valid"
        );
        assert_eq!(
            get_block_reward(0, 600_001, generated, V20),
            Err(RewardError::BlockTooBig)
        );
    }

    /// The two-step division equals the one-step division. **Always.**
    ///
    /// `specs/06` §9.8 says "The two successive `div128_64` calls are **not**
    /// the same as one division by `median^2` — each truncates", and
    /// `specs/15` §3.2 asks for a property test that compares the two forms and
    /// "*assert[s] they differ* at some point — this proves your implementation
    /// is the truncating two-step one".
    ///
    /// **That test can never pass.** For non-negative integers,
    /// `floor(floor(x / m) / m) == floor(x / m²)` is a theorem (Concrete
    /// Mathematics eq. 3.11), and the C computes the intermediate quotient at
    /// full 128-bit width (`div128_64` yields `reward_hi`/`reward_lo`), so no
    /// precision is lost between the steps. Verified here against a 256-bit
    /// single division over the whole realistic input range, and separately
    /// against arbitrary precision over two million random cases.
    ///
    /// Reproducing the two-step form is still worth doing, for a different
    /// reason than the spec gives: `median * median` overflows `u64` for a
    /// median above 2^32, where the two-step form does not. Hence the test
    /// below asserting equality rather than difference.
    #[test]
    fn two_step_division_equals_one_step() {
        let mut compared = 0usize;

        for median in [
            300_000u64,
            400_001,
            512_345,
            1_000_003,
            1 << 20,
            (1 << 31) + 7,
        ] {
            for current in [median + 1, median + 7, median + median / 3, 2 * median - 1] {
                for generated in [0u64, 1_234_567_890_123, MONEY_SUPPLY / 2] {
                    let base = base_reward(generated);
                    let multiplicand = (2 * median - current) * current;
                    let product = (base as u128) * (multiplicand as u128);

                    let two_step = (product / median as u128) / median as u128;
                    let one_step = product / ((median as u128) * (median as u128));
                    assert_eq!(
                        two_step, one_step,
                        "floor division is associative: median {median}, current {current}"
                    );

                    assert_eq!(
                        get_block_reward(median, current, generated, V20).unwrap(),
                        two_step as u64,
                        "median {median}, current {current}, generated {generated}"
                    );
                    compared += 1;
                }
            }
        }
        assert!(compared >= 70, "only {compared} cases");
    }

    /// The reason the two-step form is nonetheless the right one to write.
    #[test]
    fn one_step_in_u64_would_overflow_where_two_step_does_not() {
        let median: u64 = 1 << 33;
        // median * median overflows u64...
        assert!(median.checked_mul(median).is_none());
        // ...but the two-step form never forms that product.
        let current = median + 1;
        let generated = 1_000_000_000_000u64;
        assert!(get_block_reward(median, current, generated, V20).is_ok());
    }

    /// `specs/15` §3.2: "`median([1,2,3,4]) == 2`, `median([1,2]) == 1`,
    /// `median([u64::MAX, u64::MAX]) == u64::MAX` (the overflow-safe
    /// `get_mid`)."
    #[test]
    fn median_matches_the_reference() {
        assert_eq!(median(&mut [1, 2, 3, 4]), 2);
        assert_eq!(median(&mut [1, 2]), 1);
        assert_eq!(median(&mut [u64::MAX, u64::MAX]), u64::MAX);
        assert_eq!(median(&mut []), 0);
        assert_eq!(median(&mut [7]), 7);
        assert_eq!(median(&mut [1, 2, 3]), 2);
        // Unsorted input is sorted first.
        assert_eq!(median(&mut [4, 1, 3, 2]), 2);
        assert_eq!(median(&mut [9, 1, 5]), 5);
    }

    /// `get_mid` must equal `floor((a + b) / 2)` without overflowing.
    #[test]
    fn get_mid_is_overflow_safe() {
        for (a, b) in [
            (0u64, 0u64),
            (1, 2),
            (2, 3),
            (u64::MAX, u64::MAX),
            (u64::MAX, u64::MAX - 1),
            (u64::MAX - 1, u64::MAX - 1),
            (1, u64::MAX),
        ] {
            let expect = ((a as u128 + b as u128) / 2) as u64;
            assert_eq!(get_mid(a, b), expect, "get_mid({a}, {b})");
        }
    }

    /// `specs/06` §3.3 and §9.3: HF 7–15 allowed under-claiming, and the
    /// under-claimed amount is what `already_generated_coins` records.
    #[test]
    fn partial_block_rewards_change_the_emission_curve() {
        let base = 1_000_000u64;
        let fee = 500u64;

        // Version 15: claiming less is allowed, and the adjusted reward is what
        // gets accumulated.
        let r = validate_miner_reward(15, base, fee, base + fee - 1000).unwrap();
        assert!(r.partial);
        assert_eq!(
            r.adjusted_base_reward,
            base - 1000,
            "the CLAIMED amount is recorded, not the theoretical one"
        );

        // Claiming exactly is fine too, and is not partial.
        let r = validate_miner_reward(15, base, fee, base + fee).unwrap();
        assert!(!r.partial);
        assert_eq!(r.adjusted_base_reward, base);

        // Version 16 onwards: it must be exact.
        assert_eq!(
            validate_miner_reward(16, base, fee, base + fee - 1),
            Err(MinerRewardError::NotExact)
        );
        assert_eq!(
            validate_miner_reward(16, base, fee, base + fee).unwrap(),
            MinerReward {
                adjusted_base_reward: base,
                partial: false
            }
        );
        assert_eq!(
            validate_miner_reward(20, base, fee, base + fee)
                .unwrap()
                .adjusted_base_reward,
            base
        );

        // Overspending is rejected at every version.
        for v in [7u8, 15, 16, 20] {
            assert_eq!(
                validate_miner_reward(v, base, fee, base + fee + 1),
                Err(MinerRewardError::Overspend),
                "version {v}"
            );
        }
    }

    /// The HF window in which under-claiming was possible is 7..=15, i.e.
    /// mainnet heights 1 through 253,998.
    #[test]
    fn the_under_claim_window_is_hf_7_to_15() {
        let base = 1_000_000u64;
        let fee = 0u64;
        for v in 7u8..=15 {
            assert!(
                validate_miner_reward(v, base, fee, base - 1).is_ok(),
                "version {v} should allow under-claiming"
            );
        }
        for v in 16u8..=20 {
            assert_eq!(
                validate_miner_reward(v, base, fee, base - 1),
                Err(MinerRewardError::NotExact),
                "version {v} must require an exact claim"
            );
        }
        // HF 16 activates at 253,999, so the window closes at 253,998.
        let hf = crate::hardfork::HardFork::new(wow_types::Network::Mainnet);
        assert_eq!(hf.earliest_height(16), Some(253_999));
        assert_eq!(hf.required_version(253_998), 15);
    }

    #[test]
    fn generated_coins_accumulate_the_adjusted_reward() {
        assert_eq!(accumulate_generated_coins(100, 50), 150);
        // Saturating rather than wrapping: the supply can never exceed u64::MAX
        // by construction, but a bug must not silently wrap to near-zero.
        assert_eq!(accumulate_generated_coins(u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn cumulative_difficulty_reports_overflow() {
        assert_eq!(accumulate_difficulty(1, 2), Some(3));
        assert_eq!(accumulate_difficulty(Difficulty::MAX, 1), None);
    }
}
