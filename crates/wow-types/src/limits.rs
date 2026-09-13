//! Parse-time structural limits.
//!
//! `specs/04-serialization.md` §1.6 — "Reject at parse time (the C++ does)".
//! These are *parse* limits, not consensus rules; a value outside them makes
//! the blob unparseable rather than the block invalid.

/// `CURRENT_TRANSACTION_VERSION` — the maximum parseable tx version.
pub const CURRENT_TRANSACTION_VERSION: u64 = 2;

/// `CRYPTONOTE_MAX_TX_PER_BLOCK`.
pub const CRYPTONOTE_MAX_TX_PER_BLOCK: usize = 0x1000_0000;

/// `CRYPTONOTE_MAX_TX_SIZE`.
pub const CRYPTONOTE_MAX_TX_SIZE: usize = 1_000_000;

/// RCT `inputs` / `outputs` / `mixin` must each be `< 0xffffffff`.
pub const RCT_DIM_MAX: usize = 0xffff_ffff;

/// `BULLETPROOF_MAX_OUTPUTS` and `BULLETPROOF_PLUS_MAX_OUTPUTS`.
pub const BULLETPROOF_MAX_OUTPUTS: usize = 16;

/// `TX_EXTRA_NONCE_MAX_COUNT` and `TX_EXTRA_PADDING_MAX_COUNT`.
pub const TX_EXTRA_NONCE_MAX_COUNT: usize = 255;
pub const TX_EXTRA_PADDING_MAX_COUNT: usize = 255;

/// `MAX_TX_EXTRA_SIZE` — a **relay** policy, not a consensus or parse limit
/// (`specs/06-consensus-rules.md` §6.3). Named here so the distinction is
/// visible; the parsers must not apply it.
pub const MAX_TX_EXTRA_SIZE: usize = 1060;

/// `CRYPTONOTE_MAX_BLOCK_NUMBER` — the `unlock_time` height/time discriminator.
pub const CRYPTONOTE_MAX_BLOCK_NUMBER: u64 = 500_000_000;

/// The hard-fork version at which the block header gains `signature` and
/// `vote`. `HF_VERSION_BLOCK_HEADER_MINER_SIG`.
///
/// This one is in `wow-types` rather than `wow-consensus` because the
/// *serialization* branches on it: `specs/04` §1.4 and `specs/05` §1.1.
pub const HF_VERSION_BLOCK_HEADER_MINER_SIG: u8 = 18;
