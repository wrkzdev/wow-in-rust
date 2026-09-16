//! Dynamic fees.
//!
//! `specs/06-consensus-rules.md` §6.
//!
//! `check_fee` is a **mempool / block-acceptance** rule, not a pure function of
//! the block being validated: it reads the *tip's* hard-fork version and the
//! *current* weight medians. [`FeeContext`] is that ambient state made
//! explicit, so the call sites in `specs/06` §6.2 can be reproduced without
//! reaching into a blockchain object.
//!
//! Every division truncates and the order of divisions is load-bearing. The
//! `div128_64` chain in the C is modelled with `u128`, which matches a release
//! build exactly — the `assert(hi == 0)` after each division is compiled out
//! under `NDEBUG`, so the C keeps only the low 64 bits, and so does this.

use crate::constants::*;
use crate::emission::get_block_reward;
use crate::hardfork::gates::{
    HF_VERSION_2021_SCALING, HF_VERSION_DYNAMIC_FEE, HF_VERSION_LONG_TERM_BLOCK_WEIGHT,
    HF_VERSION_PER_BYTE_FEE,
};

/// `get_fee_quantization_mask()` = `10^(CRYPTONOTE_DISPLAY_DECIMAL_POINT -
/// PER_KB_FEE_QUANTIZATION_DECIMALS)` = `10^(11 - 8)` = **1000**.
///
/// Monero's is `10^(12 - 8)` = 10,000. Wownero has 11 decimals, so the mask is
/// a factor of ten smaller — a fee quantized with Monero's constant is ten
/// times too coarse.
pub const FEE_QUANTIZATION_MASK: u64 = 1_000;

/// `BLOCK_REWARD_OVERESTIMATE`, the high bound the *estimator* substitutes when
/// `get_block_reward` fails. Never used on the consensus path.
pub const BLOCK_REWARD_OVERESTIMATE: u64 = 10 * 1_000_000_000_000;

/// `CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES`.
pub const SCALING_2021_FEE_ROUNDING_PLACES: u32 = 2;

/// `get_dynamic_base_fee(block_reward, median_block_weight, version)`
/// (`specs/06` §6.1).
///
/// Returns a fee **per byte** from HF 12, and per kB before that.
///
/// ```text
/// median = max(median_block_weight, get_min_block_weight(version))
///
/// if version >= 12:                                 // per byte
///     v = block_reward * 3000                       // 128-bit
///     v /= median
///     if version >= 20:
///         v /= median;  lo = v as u64
///         lo -= lo / 20                             // * 0.95
///         return max(lo, 1)
///     else:
///         v /= min_block_weight;  lo = v as u64
///         return lo / 5                             // * 0.2
///
/// // per kB
/// fee_base = if version >= 5 { 400_000_000 } else { 2_000_000_000 }
/// unscaled = fee_base * min_block_weight / median
/// lo = (unscaled * block_reward / 10_000_000_000_000) as u64
/// (lo + 999) / 1000 * 1000                          // quantize up
/// ```
///
/// Note the asymmetry in the per-byte branches: the pre-2021 one divides once
/// by the median and once by the **minimum** block weight, while the 2021 one
/// divides by the median twice. Swapping them is silent at HF 20 only when the
/// median happens to sit at 300,000.
pub fn get_dynamic_base_fee(block_reward: u64, median_block_weight: u64, version: u8) -> u64 {
    let min_block_weight = get_min_block_weight(version);
    let median_block_weight = median_block_weight.max(min_block_weight);

    if version >= HF_VERSION_PER_BYTE_FEE {
        let mut v = (block_reward as u128) * (DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT as u128);
        v /= median_block_weight as u128;

        if version >= HF_VERSION_2021_SCALING {
            v /= median_block_weight as u128;
            // assert(hi == 0) is a no-op under NDEBUG; keep the low word.
            let lo = v as u64;
            let lo = lo - lo / 20;
            return if lo == 0 { 1 } else { lo };
        }
        v /= min_block_weight as u128;
        let lo = v as u64;
        return lo / 5;
    }

    let fee_base = if version >= 5 {
        DYNAMIC_FEE_PER_KB_BASE_FEE_V5
    } else {
        DYNAMIC_FEE_PER_KB_BASE_FEE
    };

    let unscaled_fee_base = fee_base * min_block_weight / median_block_weight;
    let lo = ((unscaled_fee_base as u128) * (block_reward as u128)
        / (DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD as u128)) as u64;

    quantize_up(lo)
}

/// `(v + mask - 1) / mask * mask` — round up to a multiple of
/// [`FEE_QUANTIZATION_MASK`], i.e. to 8 decimal places.
///
/// Saturating: the C overflows silently here, but a `u64` fee that close to the
/// top is already nonsense, and a wrapped value would *lower* the requirement.
pub const fn quantize_up(v: u64) -> u64 {
    match v.checked_add(FEE_QUANTIZATION_MASK - 1) {
        Some(x) => x / FEE_QUANTIZATION_MASK * FEE_QUANTIZATION_MASK,
        None => u64::MAX / FEE_QUANTIZATION_MASK * FEE_QUANTIZATION_MASK,
    }
}

/// The ambient blockchain state `check_fee` reads (`specs/06` §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeContext {
    /// `get_current_hard_fork_version()` — the version the **next** block must
    /// carry, not the tip block's.
    pub version: u8,
    /// `m_current_block_cumul_weight_limit`. `check_fee` uses `limit / 2`.
    pub cumulative_weight_limit: u64,
    /// `m_long_term_effective_median_block_weight`. Only read from HF 13.
    pub long_term_effective_median: u64,
    /// `already_generated_coins(height - 1)`, or 0 at height 0.
    pub already_generated_coins: u64,
}

impl FeeContext {
    /// `median = m_current_block_cumul_weight_limit / 2`.
    pub const fn median(&self) -> u64 {
        self.cumulative_weight_limit / 2
    }

    /// The median actually fed to `get_dynamic_base_fee`: from HF 13 the
    /// long-term effective median clamps it.
    pub fn fee_median(&self) -> u64 {
        if self.version >= HF_VERSION_LONG_TERM_BLOCK_WEIGHT {
            self.median().min(self.long_term_effective_median)
        } else {
            self.median()
        }
    }

    /// `get_block_reward(median, 1, already_generated_coins, version)`.
    ///
    /// The weight argument is **1**, not the block weight — so no penalty ever
    /// applies and this is the unpenalised base reward at the current supply.
    /// Below HF 4 the C leaves `base_reward` at 0 and never uses it.
    pub fn base_reward(&self) -> Result<u64, crate::emission::RewardError> {
        if self.version < HF_VERSION_DYNAMIC_FEE {
            return Ok(0);
        }
        get_block_reward(self.median(), 1, self.already_generated_coins, self.version)
    }
}

/// The minimum fee `check_fee` demands before the 2% buffer, and the buffer
/// applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequiredFee {
    /// `needed_fee` — the nominal requirement.
    pub needed: u64,
    /// `needed_fee - needed_fee / 50` — what a transaction must actually meet.
    pub accepted_minimum: u64,
    /// The per-byte (HF 12+) or per-kB fee used to get there.
    pub unit_fee: u64,
}

/// `check_fee(tx_weight, fee)` (`specs/06` §6.2), split so callers can report
/// the shortfall.
///
/// ```text
/// if version >= 12:                              // per byte
///     fee_per_byte = get_dynamic_base_fee(base_reward, fee_median, version)
///     needed = quantize_up(tx_weight * fee_per_byte)
/// else:                                          // per kB, rounded up
///     fee_per_kb = if version < 4 { FEE_PER_KB } else { get_dynamic_base_fee(..) }
///     kb = tx_weight / 1024 + (tx_weight % 1024 != 0)
///     needed = kb * fee_per_kb
///
/// accept iff fee >= needed - needed / 50         // 2% buffer
/// ```
pub fn required_fee(
    ctx: &FeeContext,
    tx_weight: u64,
) -> Result<RequiredFee, crate::emission::RewardError> {
    let base_reward = ctx.base_reward()?;

    let (needed, unit_fee) = if ctx.version >= HF_VERSION_PER_BYTE_FEE {
        let fee_per_byte = get_dynamic_base_fee(base_reward, ctx.fee_median(), ctx.version);
        (
            quantize_up(tx_weight.saturating_mul(fee_per_byte)),
            fee_per_byte,
        )
    } else {
        let fee_per_kb = if ctx.version < HF_VERSION_DYNAMIC_FEE {
            FEE_PER_KB
        } else {
            // Note: the pre-HF-12 branch passes the plain median, *not*
            // `fee_median` -- the long-term clamp only exists from HF 13, which
            // is already past HF 12, so this branch never sees it.
            get_dynamic_base_fee(base_reward, ctx.median(), ctx.version)
        };
        let mut kb = tx_weight / 1024;
        if !tx_weight.is_multiple_of(1024) {
            kb += 1;
        }
        (kb.saturating_mul(fee_per_kb), fee_per_kb)
    };

    Ok(RequiredFee {
        needed,
        accepted_minimum: needed - needed / 50,
        unit_fee,
    })
}

/// `check_fee` proper: does `fee` clear the requirement?
pub fn check_fee(
    ctx: &FeeContext,
    tx_weight: u64,
    fee: u64,
) -> Result<bool, crate::emission::RewardError> {
    Ok(fee >= required_fee(ctx, tx_weight)?.accepted_minimum)
}

/// The four 2021-scaling fee tiers, mapped to wallet priorities 1..4
/// (low / normal / medium / high). `specs/06` §6.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeTiers {
    pub low: u64,
    pub normal: u64,
    pub medium: u64,
    pub high: u64,
}

/// `get_dynamic_base_fee_estimate_2021_scaling(grace_blocks, base_reward, Mnw,
/// Mlw, fees)` (`specs/06` §6.4). **Wallet policy, not consensus.**
///
/// ```text
/// Mfw = min(Mnw, Mlw)
/// Fl = base_reward * 3000 / (Mfw * Mfw)
/// Fn = 4  * base_reward * 3000 / (Mfw * Mfw)
/// Fm = 16 * base_reward * 3000 / (300_000 * Mfw)
/// Fh = max(4 * Fm, 4 * Fm * Mfw / (32 * 3000 * Mnw / 300_000))
/// [round_money_up(F, 2) for F in (Fl, Fn, Fm, Fh)]
/// ```
///
/// `Fn` is *not* `4 * Fl`: the C folds the factor of four inside the division
/// so the truncation happens once, at the end. The comment in the C says so
/// outright — "fold Fl into this for better precision (and to match the test
/// cases in the PDF)". Computing `4 * Fl` instead gives a different number.
pub fn fee_tiers_2021(base_reward: u64, mnw: u64, mlw: u64) -> FeeTiers {
    let mfw = mnw.min(mlw);
    let br = base_reward as u128;
    let rw = DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT as u128;
    let mfw2 = (mfw as u128) * (mfw as u128);

    let fl = (br * rw / mfw2) as u64;
    let fnorm = (4 * br * rw / mfw2) as u64;
    let fm = (16 * br * rw / ((BLOCK_GRANTED_FULL_REWARD_ZONE_V5 as u128) * (mfw as u128))) as u64;

    // 32 * 3000 * Mnw / 300_000 -- an integer division that can reach 0, in
    // which case the C divides by zero. It cannot in practice: Mnw >= 300_000
    // always, so the divisor is >= 96_000.
    let divisor = 32 * rw * (mnw as u128) / (BLOCK_GRANTED_FULL_REWARD_ZONE_V5 as u128);
    let fh_scaled = (4 * (fm as u128) * (mfw as u128))
        .checked_div(divisor)
        .unwrap_or(4 * fm as u128);
    let fh = (4 * fm as u128).max(fh_scaled) as u64;

    FeeTiers {
        low: round_money_up(fl, SCALING_2021_FEE_ROUNDING_PLACES),
        normal: round_money_up(fnorm, SCALING_2021_FEE_ROUNDING_PLACES),
        medium: round_money_up(fm, SCALING_2021_FEE_ROUNDING_PLACES),
        high: round_money_up(fh, SCALING_2021_FEE_ROUNDING_PLACES),
    }
}

/// `cryptonote::round_money_up(amount, significant_digits)`.
///
/// Keeps `significant_digits` leading decimal digits and rounds **up** — the
/// C's comment claims it bumps "if the following digits past significant digits
/// were to be 5 or more", but the code bumps on **any** non-zero trailing
/// digit. The comment is wrong; the behaviour is a ceiling.
///
/// Saturates instead of throwing on the carry-past-`u64::MAX` case that makes
/// the C's `strtoull` set `ERANGE`.
pub fn round_money_up(amount: u64, significant_digits: u32) -> u64 {
    assert!(significant_digits > 0, "significant_digits must not be 0");

    let mut digits: Vec<u8> = amount.to_string().into_bytes();
    let len = digits.len() as u32;
    if len <= significant_digits {
        return amount;
    }

    let keep = significant_digits as usize;
    let mut bump = false;
    for d in digits[keep..].iter_mut() {
        if *d != b'0' {
            bump = true;
            *d = b'0';
        }
    }

    let mut i = keep;
    while bump && i > 0 {
        i -= 1;
        if digits[i] == b'9' {
            digits[i] = b'0';
        } else {
            digits[i] += 1;
            bump = false;
        }
    }
    if bump {
        // The carry reached the highest digit: prepend a 1.
        digits.insert(0, b'1');
    }

    // SAFETY-free: every byte is an ASCII digit by construction.
    let s = std::str::from_utf8(&digits).expect("ascii digits");
    s.parse::<u64>().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wownero's 11 decimals make the mask 1000, not Monero's 10,000.
    #[test]
    fn quantization_mask_is_wownero_sized() {
        assert_eq!(FEE_QUANTIZATION_MASK, 1_000);
        assert_eq!(
            FEE_QUANTIZATION_MASK,
            10u64.pow(CRYPTONOTE_DISPLAY_DECIMAL_POINT - 8)
        );
        assert_ne!(FEE_QUANTIZATION_MASK, 10_000, "that is Monero's mask");

        assert_eq!(quantize_up(0), 0);
        assert_eq!(quantize_up(1), 1_000);
        assert_eq!(quantize_up(999), 1_000);
        assert_eq!(quantize_up(1_000), 1_000);
        assert_eq!(quantize_up(1_001), 2_000);
        // Saturates rather than wrapping to a *smaller* requirement.
        assert!(quantize_up(u64::MAX) >= u64::MAX - FEE_QUANTIZATION_MASK);
    }

    /// `specs/06` §6.1: below HF 12 the fee is per kB and quantized up.
    ///
    /// `DYNAMIC_FEE_PER_KB_BASE_FEE_V5` is *defined* as
    /// `2_000_000_000 * 60_000 / 300_000`, i.e. the pre-v5 base fee rescaled by
    /// the ratio of the two full-reward zones. The two versions therefore
    /// produce **identical** fees for every median at or above 300,000 --
    /// `fee_base * min_block_weight` is 1.2e14 either way. They separate only
    /// below 300,000, where v5+ floors the median and v4 does not.
    #[test]
    fn per_kb_fee_before_hf12() {
        let reward = DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD; // 10^13
        let fee = get_dynamic_base_fee(reward, 300_000, 11);
        // unscaled = 400_000_000 * 300_000 / 300_000 = 400_000_000
        // lo = 400_000_000 * reward / reward = 400_000_000, already a multiple
        assert_eq!(fee, DYNAMIC_FEE_PER_KB_BASE_FEE_V5);
        assert_eq!(fee, 400_000_000);

        assert_eq!(
            DYNAMIC_FEE_PER_KB_BASE_FEE * BLOCK_GRANTED_FULL_REWARD_ZONE_V2,
            DYNAMIC_FEE_PER_KB_BASE_FEE_V5 * BLOCK_GRANTED_FULL_REWARD_ZONE_V5,
            "the two base fees are the same product"
        );
        for m in [300_000u64, 900_000, 1_200_000] {
            assert_eq!(
                get_dynamic_base_fee(reward, m, 4),
                get_dynamic_base_fee(reward, m, 11),
                "v4 and v11 must agree at median {m}"
            );
        }

        // Below 300,000 they diverge: v4's floor is 60,000, so it keeps using
        // the real median and charges more.
        assert!(
            get_dynamic_base_fee(reward, 100_000, 4) > get_dynamic_base_fee(reward, 100_000, 11)
        );
        assert_eq!(get_dynamic_base_fee(reward, 100_000, 4), 1_200_000_000);
        assert_eq!(get_dynamic_base_fee(reward, 100_000, 11), 400_000_000);
        assert_eq!(get_dynamic_base_fee(reward, 100_000, 11), fee, "floored");

        // A larger median lowers the fee.
        assert!(get_dynamic_base_fee(reward, 1_200_000, 11) < fee);
        // Always quantized.
        for v in [4u8, 5, 11] {
            assert_eq!(
                get_dynamic_base_fee(reward, 777_777, v) % FEE_QUANTIZATION_MASK,
                0
            );
        }
    }

    /// A median below the minimum block weight is raised to it, so the fee
    /// cannot be inflated by an empty chain.
    #[test]
    fn the_median_is_floored_at_the_minimum_block_weight() {
        // The floor is 60,000 below version 5 and 300,000 from version 5.
        assert_eq!(get_min_block_weight(4), BLOCK_GRANTED_FULL_REWARD_ZONE_V2);
        assert_eq!(get_min_block_weight(5), BLOCK_GRANTED_FULL_REWARD_ZONE_V5);
        for v in [4u8, 11, 12, 15, 20] {
            assert_eq!(
                get_dynamic_base_fee(1_000_000_000, 0, v),
                get_dynamic_base_fee(1_000_000_000, get_min_block_weight(v), v),
                "version {v}"
            );
            assert_eq!(
                get_dynamic_base_fee(1_000_000_000, 1, v),
                get_dynamic_base_fee(1_000_000_000, get_min_block_weight(v), v),
                "version {v}"
            );
        }
    }

    /// `specs/06` §6.1: HF 12..19 divides by the median *once* and by the
    /// minimum block weight once, then by 5. HF 20+ divides by the median
    /// twice, then takes 95%. At median == 300,000 the two divisors coincide,
    /// so the branches must be separated with a median that differs from it.
    #[test]
    fn per_byte_branches_differ_away_from_the_minimum() {
        let reward = 2_000_000_000_000u64;

        // At the minimum the divisors are identical, and only the trailing
        // 0.2x vs 0.95x factor distinguishes the branches.
        let at_min_old = get_dynamic_base_fee(reward, 300_000, 19);
        let at_min_new = get_dynamic_base_fee(reward, 300_000, 20);
        let raw = (reward as u128) * 3000 / 300_000 / 300_000;
        assert_eq!(at_min_old, (raw as u64) / 5);
        assert_eq!(at_min_new, {
            let lo = raw as u64;
            lo - lo / 20
        });

        // Away from the minimum they diverge structurally.
        let m = 900_000u64;
        let old = get_dynamic_base_fee(reward, m, 19);
        let new = get_dynamic_base_fee(reward, m, 20);
        let expect_old = (((reward as u128) * 3000 / m as u128 / 300_000) as u64) / 5;
        let expect_new = {
            let lo = ((reward as u128) * 3000 / m as u128 / m as u128) as u64;
            let lo = lo - lo / 20;
            if lo == 0 {
                1
            } else {
                lo
            }
        };
        assert_eq!(old, expect_old, "HF 19 divides by the *minimum* second");
        assert_eq!(new, expect_new, "HF 20 divides by the *median* twice");
        assert_ne!(old, new);
    }

    /// The 2021 branch never returns zero — a fee of zero would let any
    /// transaction through.
    #[test]
    fn the_2021_fee_is_never_zero() {
        // A tiny reward with a huge median truncates to zero before the clamp.
        let fee = get_dynamic_base_fee(1, 50_000_000, 20);
        assert_eq!(fee, 1, "clamped up from zero");

        // The pre-2021 branch has no such clamp and *can* return zero.
        assert_eq!(get_dynamic_base_fee(1, 50_000_000, 19), 0);
    }

    fn ctx(version: u8) -> FeeContext {
        FeeContext {
            version,
            cumulative_weight_limit: 600_000, // median 300_000
            long_term_effective_median: 300_000,
            already_generated_coins: 5_000_000_000_000_000,
        }
    }

    /// `specs/06` §6.2: the 2% buffer means a transaction paying 98% of the
    /// nominal fee is still accepted, and 97.9% is not.
    #[test]
    fn the_two_percent_buffer_is_applied() {
        let c = ctx(20);
        let r = required_fee(&c, 2_000).unwrap();
        assert_eq!(r.accepted_minimum, r.needed - r.needed / 50);
        assert!(r.needed > 0);

        assert!(check_fee(&c, 2_000, r.needed).unwrap());
        assert!(check_fee(&c, 2_000, r.accepted_minimum).unwrap());
        assert!(!check_fee(&c, 2_000, r.accepted_minimum - 1).unwrap());
        assert!(!check_fee(&c, 2_000, 0).unwrap());

        // 98% of the nominal fee clears it; the buffer is exactly needed/50.
        assert_eq!(r.needed - r.accepted_minimum, r.needed / 50);
    }

    /// `needed_fee` is quantized up from HF 12, so the per-byte requirement is
    /// always a multiple of 1000.
    #[test]
    fn the_per_byte_requirement_is_quantized() {
        let c = ctx(20);
        for weight in [1u64, 7, 1_500, 2_001, 100_000] {
            let r = required_fee(&c, weight).unwrap();
            assert_eq!(
                r.needed % FEE_QUANTIZATION_MASK,
                0,
                "weight {weight} gave {}",
                r.needed
            );
            assert!(r.needed >= weight * r.unit_fee, "rounded up, not down");
        }
    }

    /// Before HF 12 the requirement is per **kB with the remainder rounded up**
    /// — 1025 bytes costs two kB, not one.
    #[test]
    fn the_per_kb_requirement_rounds_partial_kilobytes_up() {
        let c = ctx(11);
        let one = required_fee(&c, 1024).unwrap();
        let two = required_fee(&c, 1025).unwrap();
        assert_eq!(one.needed, one.unit_fee, "exactly one kB");
        assert_eq!(two.needed, 2 * two.unit_fee, "1025 bytes is two kB");
        // A zero-weight transaction needs nothing.
        assert_eq!(required_fee(&c, 0).unwrap().needed, 0);
        // 1 byte still costs a full kB.
        assert_eq!(required_fee(&c, 1).unwrap().needed, one.unit_fee);
    }

    /// Below HF 4 the fee is the flat `FEE_PER_KB`, with no reward lookup at
    /// all.
    #[test]
    fn before_the_dynamic_fee_the_rate_is_flat() {
        let c = ctx(3);
        assert_eq!(c.base_reward().unwrap(), 0, "never computed below HF 4");
        let r = required_fee(&c, 2048).unwrap();
        assert_eq!(r.unit_fee, FEE_PER_KB);
        assert_eq!(r.needed, 2 * FEE_PER_KB);
    }

    /// From HF 13 the long-term effective median clamps the fee median — a
    /// surge in block weights cannot cheapen fees indefinitely.
    #[test]
    fn the_long_term_median_clamps_the_fee_median() {
        let mut c = ctx(15);
        c.cumulative_weight_limit = 20_000_000; // median 10_000_000
        c.long_term_effective_median = 300_000;
        assert_eq!(c.fee_median(), 300_000, "the long-term median wins");

        // At HF 12 the clamp does not exist yet.
        c.version = 12;
        assert_eq!(c.fee_median(), 10_000_000, "unclamped below HF 13");

        // A short-term median *below* the long-term one is used as-is.
        c.version = 15;
        c.cumulative_weight_limit = 400_000; // median 200_000
        assert_eq!(c.fee_median(), 200_000);
    }

    /// `get_block_reward` is called with weight **1**, so the fee never sees a
    /// block-weight penalty.
    #[test]
    fn the_fee_base_reward_is_unpenalised() {
        let c = ctx(20);
        let expected =
            get_block_reward(c.median(), 1, c.already_generated_coins, c.version).unwrap();
        assert_eq!(c.base_reward().unwrap(), expected);
        assert_eq!(
            expected,
            crate::emission::base_reward(c.already_generated_coins),
            "weight 1 <= median, so no penalty applies"
        );
    }

    /// `specs/06` §6.4: `round_money_up` is a ceiling on significant digits,
    /// despite the C's comment claiming it rounds at 5.
    #[test]
    fn round_money_up_is_a_ceiling_not_a_rounding() {
        // Any non-zero trailing digit bumps -- 101 -> 110, not 100.
        assert_eq!(round_money_up(101, 2), 110);
        assert_eq!(round_money_up(100, 2), 100, "already exact");
        assert_eq!(round_money_up(149, 2), 150);
        assert_eq!(round_money_up(150, 2), 150);
        assert_eq!(round_money_up(151, 2), 160);

        // Shorter than the digit count passes through.
        assert_eq!(round_money_up(0, 2), 0);
        assert_eq!(round_money_up(7, 2), 7);
        assert_eq!(round_money_up(99, 2), 99);

        // Carry across a nine.
        assert_eq!(round_money_up(991, 2), 1000);
        assert_eq!(round_money_up(9_999_999, 2), 10_000_000);
        // Carry into a new leading digit.
        assert_eq!(round_money_up(999, 1), 1000);

        // One significant digit.
        assert_eq!(round_money_up(1_234, 1), 2_000);
        assert_eq!(round_money_up(1_000, 1), 1_000);

        // The result is always >= the input and a "round" number.
        for v in [1u64, 42, 12_345, 987_654_321, u64::MAX / 3] {
            let r = round_money_up(v, 2);
            assert!(r >= v, "{v} -> {r}");
            let s = r.to_string();
            assert!(
                s.len() <= 2 || s[2..].bytes().all(|b| b == b'0'),
                "{v} -> {r} is not 2-significant"
            );
        }
    }

    /// `specs/06` §6.4: the four tiers are ordered, and `normal` is computed by
    /// folding the factor of four *inside* the division rather than
    /// multiplying `low`.
    #[test]
    fn fee_tiers_are_ordered_and_folded() {
        let base_reward = 2_000_000_000_000u64;
        let mlw = 300_000u64;
        let mnw = 600_000u64;
        let t = fee_tiers_2021(base_reward, mnw, mlw);

        assert!(t.low <= t.normal, "{t:?}");
        assert!(t.normal <= t.medium, "{t:?}");
        assert!(t.medium <= t.high, "{t:?}");

        // Mfw = min(600_000, 300_000) = 300_000.
        let mfw = 300_000u128;
        let raw_fl = (base_reward as u128) * 3000 / (mfw * mfw);
        let raw_fn = 4 * (base_reward as u128) * 3000 / (mfw * mfw);
        assert_eq!(t.low, round_money_up(raw_fl as u64, 2));
        assert_eq!(t.normal, round_money_up(raw_fn as u64, 2));

        // High is at least 4x medium by construction.
        assert!(
            t.high
                >= round_money_up(
                    4 * (16 * (base_reward as u128) * 3000 / (300_000u128 * mfw)) as u64,
                    2
                ) / 2
        );
    }

    /// The folded `Fn` differs from `4 * Fl` whenever the division truncates,
    /// which is the whole reason the C folds it. These inputs were searched for
    /// so the difference survives the 2-significant-digit rounding as well.
    #[test]
    fn folded_normal_differs_from_four_times_low() {
        let mfw = 1_000_000u128;
        let base_reward = 800_084_000_000u64;

        let fl = (base_reward as u128) * 3000 / (mfw * mfw);
        let folded = 4 * (base_reward as u128) * 3000 / (mfw * mfw);
        assert_eq!(fl, 2400);
        assert_eq!(folded, 9601, "one more than 4 * 2400");
        assert_ne!(folded, 4 * fl);

        let t = fee_tiers_2021(base_reward, mfw as u64, mfw as u64);
        assert_eq!(t.normal, round_money_up(folded as u64, 2));
        assert_eq!(t.normal, 9_700);
        assert_ne!(
            t.normal,
            round_money_up((4 * fl) as u64, 2),
            "computing Fn as 4 * Fl gives 9_600 -- a different tier"
        );
    }

    /// The `Fh` divisor cannot be zero on a real chain, because `Mnw` is
    /// floored at the minimum penalty-free zone.
    #[test]
    fn the_high_tier_divisor_is_safe() {
        let min_divisor = 32u128 * 3000 * 300_000 / 300_000;
        assert_eq!(min_divisor, 96_000);
        // Even at the floor the function terminates and orders correctly.
        let t = fee_tiers_2021(1, 300_000, 300_000);
        assert!(t.low <= t.normal && t.normal <= t.medium && t.medium <= t.high);
    }
}
