//! Wownero consensus rules.
//!
//! `specs/01-constants.md`, `specs/06-consensus-rules.md`,
//! `specs/07-difficulty.md`. Pure functions over values the caller has already
//! fetched — no storage, no network, no clock.
//!
//! # Reproduce the bugs
//!
//! `specs/06` §9 lists nine inherited quirks that are now consensus, and the
//! spec is blunt about them: "**Reproduce all of these.** Each one is a
//! potential chain split." They are implemented as written and each has a test
//! naming it:
//!
//! | Quirk | Where |
//! |---|---|
//! | §9.1 hard-coded difficulty overrides | [`difficulty::OVERRIDES`] |
//! | §9.3 partial block rewards changed the emission curve | [`emission::validate_miner_reward`] |
//! | §9.5 `get_ideal_version` skips table index 0 | [`hardfork::HardFork::ideal_version`] |
//! | §9.8 two-step division in the reward penalty | [`emission::get_block_reward`] |
//! | §6.4 `round_money_up` ceilings rather than rounds | [`fee::round_money_up`] |
//!
//! The remainder land in later modules as they are written.

#![forbid(unsafe_code)]

pub mod checkpoints;
pub mod constants;
pub mod difficulty;
pub mod emission;
pub mod fee;
pub mod genesis;
pub mod hardfork;
pub mod timestamp;
pub mod tx_rules;
pub mod weight;

pub use checkpoints::{Checkpoint, Checkpoints};
pub use difficulty::{next_difficulty, select_algorithm, Algorithm};
pub use emission::{base_reward, get_block_reward, median, RewardError};
pub use fee::{check_fee, get_dynamic_base_fee, required_fee, FeeContext, RequiredFee};
pub use genesis::{genesis_block, genesis_id, network_from_genesis};
pub use hardfork::{gates, Fork, HardFork};
pub use timestamp::{check_block_timestamp, get_adjusted_time, is_tx_spendtime_unlocked};
pub use tx_rules::{check_coinbase, check_output_types, check_ring_size, TxError};
pub use weight::{next_long_term_block_weight, update_next_cumulative_weight_limit, WeightLimits};
