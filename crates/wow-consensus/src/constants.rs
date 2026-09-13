//! Every consensus constant, from `specs/01-constants.md`.
//!
//! `specs/01` opens with: "Every value in this document is consensus- or
//! wire-critical unless marked *(policy)* or *(local)*. Implement them as
//! `const` in `wow-consensus`; **do not re-derive them**."
//!
//! So they are written out, with the derived ones carrying a test that checks
//! the derivation rather than a comment claiming it.

// ---------------------------------------------------------------------------
// §1 Identity
// ---------------------------------------------------------------------------

/// `CRYPTONOTE_NAME`.
pub const CRYPTONOTE_NAME: &str = "wownero";

/// `CRYPTONOTE_DISPLAY_DECIMAL_POINT`.
pub const CRYPTONOTE_DISPLAY_DECIMAL_POINT: u32 = 11;

/// Atomic units per WOW: `10^11`.
pub const COIN: u64 = 100_000_000_000;

/// `(3 << 16) | 15`.
pub const CORE_RPC_VERSION: u32 = (3 << 16) | 15;
/// `(1 << 16) | 30`.
pub const WALLET_RPC_VERSION: u32 = (1 << 16) | 30;

/// The payment URI scheme, checked case-sensitively (`specs/12` §6).
pub const URI_SCHEME: &str = "wownero:";

/// `HASH_KEY_MESSAGE_SIGNING` — **Wownero-specific**, so Monero tooling cannot
/// verify Wownero signatures or vice versa.
pub const HASH_KEY_MESSAGE_SIGNING: &[u8] = b"WowneroMessageSignature";

// ---------------------------------------------------------------------------
// §4 Block & chain
// ---------------------------------------------------------------------------

/// `DIFFICULTY_TARGET_V1`. Wownero has always targeted 5 minutes.
pub const DIFFICULTY_TARGET_V1: u64 = 300;
/// `DIFFICULTY_TARGET_V2`. Identical, which makes `get_difficulty_target()`
/// unconditionally 300 (`specs/07` §1).
pub const DIFFICULTY_TARGET_V2: u64 = 300;

/// `CURRENT_BLOCK_MAJOR_VERSION` — genesis only.
pub const CURRENT_BLOCK_MAJOR_VERSION: u8 = 7;
/// `CURRENT_BLOCK_MINOR_VERSION` — genesis only.
pub const CURRENT_BLOCK_MINOR_VERSION: u8 = 7;

/// `CRYPTONOTE_MAX_BLOCK_NUMBER` — the `unlock_time` height/time discriminator.
pub const CRYPTONOTE_MAX_BLOCK_NUMBER: u64 = 500_000_000;

/// `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT` — block version < 8.
pub const CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT: u64 = 7200;
/// `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2` — block version >= 8.
pub const CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2: u64 = 600;

/// `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` — version < 10.
pub const BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW: usize = 60;
/// `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2` — version >= 10.
pub const BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2: usize = 11;

/// `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` — minimum output age from HF 15.
pub const CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE: u64 = 4;

/// `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` — coinbase lock before HF 16.
pub const CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW: u64 = 60;
/// `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_V2` — from HF 18, about one day.
pub const CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_V2: u64 = 288;

/// `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS`.
pub const CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS: u64 = 1;
/// `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2` = `TARGET_V2 * 1`.
pub const CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2: u64 = 300;

// ---------------------------------------------------------------------------
// §5 Emission
// ---------------------------------------------------------------------------

/// `MONEY_SUPPLY` — the whole `u64` range.
pub const MONEY_SUPPLY: u64 = u64::MAX;

/// `EMISSION_SPEED_FACTOR_PER_MINUTE`.
pub const EMISSION_SPEED_FACTOR_PER_MINUTE: u32 = 24;

/// `FINAL_SUBSIDY_PER_MINUTE` — **zero**. There is no tail emission.
pub const FINAL_SUBSIDY_PER_MINUTE: u64 = 0;

/// `CRYPTONOTE_REWARD_BLOCKS_WINDOW`.
pub const CRYPTONOTE_REWARD_BLOCKS_WINDOW: usize = 100;

/// `config::BASE_REWARD_CLAMP_THRESHOLD`.
pub const BASE_REWARD_CLAMP_THRESHOLD: u64 = 100_000_000;

/// `config::DEFAULT_DUST_THRESHOLD`.
pub const DEFAULT_DUST_THRESHOLD: u64 = 2_000_000_000;

/// The effective emission-speed factor: `24 - (300/60 - 1)` = **20**.
///
/// `base_reward = (MONEY_SUPPLY - already_generated_coins) >> 20`.
pub const EMISSION_SPEED_FACTOR: u32 =
    EMISSION_SPEED_FACTOR_PER_MINUTE - ((DIFFICULTY_TARGET_V2 as u32 / 60) - 1);

// ---------------------------------------------------------------------------
// §6 Block weight
// ---------------------------------------------------------------------------

/// `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1` — block version < 2.
pub const BLOCK_GRANTED_FULL_REWARD_ZONE_V1: u64 = 20_000;
/// `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2` — 2 <= version < 5.
pub const BLOCK_GRANTED_FULL_REWARD_ZONE_V2: u64 = 60_000;
/// `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5` — version >= 5, i.e. always
/// on Wownero, whose first fork is version 7.
pub const BLOCK_GRANTED_FULL_REWARD_ZONE_V5: u64 = 300_000;

/// `CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE`.
pub const LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE: u64 = 100_000;
/// `CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR`.
pub const SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR: u64 = 50;
/// `CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE`.
pub const COINBASE_BLOB_RESERVED_SIZE: usize = 600;

/// `get_min_block_weight(version)`.
///
/// `specs/01` §15: "returns 300,000 for every version >= 5" — which is every
/// version Wownero has ever had. The V1/V2 branches are dead code, reproduced
/// for completeness.
pub const fn get_min_block_weight(version: u8) -> u64 {
    if version < 2 {
        BLOCK_GRANTED_FULL_REWARD_ZONE_V1
    } else if version < 5 {
        BLOCK_GRANTED_FULL_REWARD_ZONE_V2
    } else {
        BLOCK_GRANTED_FULL_REWARD_ZONE_V5
    }
}

// ---------------------------------------------------------------------------
// §7 Fees
// ---------------------------------------------------------------------------

pub const FEE_PER_KB_OLD: u64 = 10_000_000_000;
pub const FEE_PER_KB: u64 = 2_000_000_000;
pub const FEE_PER_BYTE: u64 = 300_000;
pub const DYNAMIC_FEE_PER_KB_BASE_FEE: u64 = 2_000_000_000;
pub const DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD: u64 = 10_000_000_000_000;
/// `DYNAMIC_FEE_PER_KB_BASE_FEE_V5` = `2_000_000_000 * 60_000 / 300_000`.
pub const DYNAMIC_FEE_PER_KB_BASE_FEE_V5: u64 = DYNAMIC_FEE_PER_KB_BASE_FEE
    * BLOCK_GRANTED_FULL_REWARD_ZONE_V2
    / BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
pub const DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT: u64 = 3_000;
pub const PER_KB_FEE_QUANTIZATION_DECIMALS: u32 = 8;
pub const CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES: u32 = 2;

/// `get_fee_quantization_mask()` =
/// `10^(CRYPTONOTE_DISPLAY_DECIMAL_POINT - PER_KB_FEE_QUANTIZATION_DECIMALS)`.
pub const FEE_QUANTIZATION_MASK: u64 =
    10u64.pow(CRYPTONOTE_DISPLAY_DECIMAL_POINT - PER_KB_FEE_QUANTIZATION_DECIMALS);

// ---------------------------------------------------------------------------
// §8 Difficulty windows
// ---------------------------------------------------------------------------

pub const DIFFICULTY_WINDOW: usize = 720;
pub const DIFFICULTY_WINDOW_V2: usize = 60;
pub const DIFFICULTY_WINDOW_V3: usize = 144;
pub const DIFFICULTY_LAG: usize = 15;
pub const DIFFICULTY_LAG_V2: usize = 3;
pub const DIFFICULTY_CUT: usize = 60;
pub const DIFFICULTY_CUT_V2: usize = 12;

pub const DIFFICULTY_BLOCKS_COUNT: usize = DIFFICULTY_WINDOW + DIFFICULTY_LAG;
pub const DIFFICULTY_BLOCKS_COUNT_V2: usize = DIFFICULTY_WINDOW_V2 + 1;
pub const DIFFICULTY_BLOCKS_COUNT_V3: usize = DIFFICULTY_WINDOW_V3 + 1;
pub const DIFFICULTY_BLOCKS_COUNT_V4: usize = DIFFICULTY_WINDOW_V3 + DIFFICULTY_LAG_V2;

// ---------------------------------------------------------------------------
// §9 Ring signatures & proofs
// ---------------------------------------------------------------------------

/// `min_mixin` at HF 7–8: ring size 8.
pub const MIN_MIXIN_V7: usize = 7;
/// `min_mixin` from HF 9: ring size **22**.
pub const MIN_MIXIN_V9: usize = 21;

pub const BULLETPROOF_MAX_OUTPUTS: usize = 16;
pub const BULLETPROOF_PLUS_MAX_OUTPUTS: usize = 16;
pub const MULTISIG_MAX_SIGNERS: usize = 16;

/// `MAX_TX_EXTRA_SIZE` — *relay policy*, not consensus (`specs/06` §6.3).
pub const MAX_TX_EXTRA_SIZE: usize = 1_060;
pub const TX_EXTRA_PADDING_MAX_COUNT: usize = 255;
pub const TX_EXTRA_NONCE_MAX_COUNT: usize = 255;

/// `CRYPTONOTE_MAX_TX_SIZE`.
pub const CRYPTONOTE_MAX_TX_SIZE: usize = 1_000_000;
/// `CRYPTONOTE_MAX_TX_PER_BLOCK`.
pub const CRYPTONOTE_MAX_TX_PER_BLOCK: usize = 0x1000_0000;

// ---------------------------------------------------------------------------
// §12.1 Sync sizing (policy, but two of these are load-bearing)
// ---------------------------------------------------------------------------

pub const BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT: usize = 10_000;
pub const BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT: usize = 25_000;
pub const BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4: usize = 100;
pub const BLOCKS_SYNCHRONIZING_DEFAULT_COUNT: usize = 20;
/// **Must equal `SEEDHASH_EPOCH_BLOCKS`** so a sync batch shares a RandomWOW
/// seed (`specs/01` §12.1, `specs/03` §3.4).
pub const BLOCKS_SYNCHRONIZING_MAX_COUNT: usize = 2_048;

/// `ORPHANED_BLOCKS_MAX_COUNT` *(policy)*.
pub const ORPHANED_BLOCKS_MAX_COUNT: usize = 100;

#[cfg(test)]
mod tests {
    use super::*;

    /// `specs/01` §15: "`get_min_block_weight` returns 300,000 for every
    /// version >= 5."
    #[test]
    fn min_block_weight_is_always_300k_on_wownero() {
        // Wownero's first hard fork is version 7, so only this branch is live.
        for v in 5u8..=255 {
            assert_eq!(get_min_block_weight(v), 300_000, "version {v}");
        }
        // The dead branches, for completeness.
        assert_eq!(get_min_block_weight(0), 20_000);
        assert_eq!(get_min_block_weight(1), 20_000);
        assert_eq!(get_min_block_weight(2), 60_000);
        assert_eq!(get_min_block_weight(4), 60_000);
    }

    /// `specs/01` §15: "`FINAL_SUBSIDY_PER_MINUTE` is 0 — there MUST be no tail
    /// emission." This single zero is the largest economic difference from
    /// Monero.
    #[test]
    fn there_is_no_tail_emission() {
        assert_eq!(FINAL_SUBSIDY_PER_MINUTE, 0);
        assert_eq!(MONEY_SUPPLY, u64::MAX);
        assert_eq!(MONEY_SUPPLY, 18_446_744_073_709_551_615);
    }

    /// `specs/01` §5: the effective factor is `24 - (300/60 - 1)` = 20.
    #[test]
    fn emission_speed_factor() {
        assert_eq!(EMISSION_SPEED_FACTOR, 20);
        // Total supply = u64::MAX atomic units = 184,467,440.73709551615 WOW.
        assert_eq!(MONEY_SUPPLY / COIN, 184_467_440);
    }

    /// `specs/01` §15: "The fee quantization mask is 1000."
    #[test]
    fn fee_quantization_mask() {
        assert_eq!(FEE_QUANTIZATION_MASK, 1000);
        assert_eq!(DYNAMIC_FEE_PER_KB_BASE_FEE_V5, 400_000_000);
    }

    /// `specs/01` §15: "`BLOCKS_SYNCHRONIZING_MAX_COUNT == SEEDHASH_EPOCH_BLOCKS
    /// == 2048`."
    #[test]
    fn sync_batch_matches_the_seed_epoch() {
        assert_eq!(BLOCKS_SYNCHRONIZING_MAX_COUNT, 2048);
        assert_eq!(
            BLOCKS_SYNCHRONIZING_MAX_COUNT as u64,
            wow_randomwow::SEEDHASH_EPOCH_BLOCKS
        );
    }

    /// Both difficulty targets are 300, which is what makes
    /// `get_difficulty_target()` unconditional (`specs/07` §1).
    #[test]
    fn both_difficulty_targets_are_300() {
        assert_eq!(DIFFICULTY_TARGET_V1, 300);
        assert_eq!(DIFFICULTY_TARGET_V2, 300);
        assert_eq!(DIFFICULTY_TARGET_V1, DIFFICULTY_TARGET_V2);
    }

    /// The derived block counts of `specs/01` §8.
    #[test]
    fn difficulty_block_counts() {
        assert_eq!(DIFFICULTY_BLOCKS_COUNT, 735);
        assert_eq!(DIFFICULTY_BLOCKS_COUNT_V2, 61);
        assert_eq!(DIFFICULTY_BLOCKS_COUNT_V3, 145);
        assert_eq!(DIFFICULTY_BLOCKS_COUNT_V4, 147);
    }

    /// Ring size is 8 at HF 7–8 and **22** from HF 9 (`specs/01` §9).
    #[test]
    fn ring_sizes() {
        assert_eq!(MIN_MIXIN_V7 + 1, 8);
        assert_eq!(MIN_MIXIN_V9 + 1, 22);
    }
}
