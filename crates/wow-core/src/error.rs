//! Why a block was rejected.
//!
//! The variants follow `specs/06-consensus-rules.md` §2's numbered order, so a
//! rejection says not just what failed but **how far the block got** — which is
//! the first thing to know when a node and `wownerod` disagree.

use wow_consensus::TxError;
use wow_crypto::types::Hash256;

/// A block was not added to the main chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockError {
    // -- §2 step 1 --
    /// `have_block(id)` — already in the chain or the alt store.
    AlreadyExists {
        id: Hash256,
    },

    // -- §2 step 2 --
    /// `prev_id` is not the tip, so this belongs to `handle_alternative_block`.
    ///
    /// Not a failure: the caller routes it to the alt-chain path (§8).
    NotOnTip {
        prev: Hash256,
        tip: Hash256,
    },

    // -- §2 step 3 --
    /// `HardFork::check` — the version is not the one this height requires, or
    /// the vote is below it.
    WrongVersion {
        height: u64,
        found: u8,
        required: u8,
        vote: u8,
    },

    // -- §2 step 4 --
    Timestamp(wow_consensus::timestamp::TimestampError),

    // -- §2 step 6 --
    /// The proof of work does not meet the difficulty.
    InsufficientPow {
        difficulty: u128,
    },
    /// The proof of work could not be computed at all — see
    /// [`crate::pow::PowError`].
    Pow(crate::pow::PowError),

    // -- §2 step 7 --
    /// The height is checkpointed and the hash does not match.
    CheckpointMismatch {
        height: u64,
        expected: Hash256,
        found: Hash256,
    },

    // -- §2 step 8 --
    /// `prevalidate_miner_transaction`.
    Coinbase(TxError),

    // -- §2 step 9 --
    /// A transaction hash appears twice in one block.
    DuplicateTxInBlock {
        index: usize,
    },
    /// A transaction is already in the chain.
    TxAlreadyInChain {
        hash: Hash256,
    },
    /// A transaction named by the block was not supplied and is not in the
    /// pool.
    MissingTx {
        hash: Hash256,
    },
    /// A key image appears twice inside one block, or is already spent.
    ///
    /// `specs/06` §2 step 9: the C++ keeps a per-block `key_images_container`,
    /// so an image may appear **at most once across the whole block**.
    DoubleSpend {
        image: [u8; 32],
    },
    /// A transaction failed its own validation.
    Tx {
        index: usize,
        error: TxError,
    },

    // -- §2 step 10 --
    /// `validate_miner_transaction`.
    MinerReward(wow_consensus::emission::MinerRewardError),

    // -- §2 step 11 --
    /// `cumulative_block_weight > 2 * median`, which the C++ surfaces as
    /// `get_block_reward` returning false.
    BlockTooBig {
        weight: u64,
        limit: u64,
    },

    // -- §2 step 12 --
    /// The commit failed.
    Storage(String),

    /// The block did not parse, or a field it needs is absent.
    Malformed(&'static str),
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use BlockError::*;
        match self {
            AlreadyExists { .. } => write!(f, "block already known"),
            NotOnTip { .. } => write!(f, "block does not extend the tip"),
            WrongVersion {
                height,
                found,
                required,
                vote,
            } => write!(
                f,
                "height {height} requires version {required}, block has {found} \
                 (vote {vote})"
            ),
            Timestamp(e) => write!(f, "timestamp: {e:?}"),
            InsufficientPow { difficulty } => {
                write!(f, "proof of work below difficulty {difficulty}")
            }
            Pow(e) => write!(f, "proof of work: {e}"),
            CheckpointMismatch { height, .. } => {
                write!(f, "checkpoint mismatch at height {height}")
            }
            Coinbase(e) => write!(f, "coinbase: {e:?}"),
            DuplicateTxInBlock { index } => {
                write!(f, "transaction {index} is a duplicate within the block")
            }
            TxAlreadyInChain { .. } => write!(f, "transaction already in the chain"),
            MissingTx { .. } => write!(f, "a transaction named by the block is missing"),
            DoubleSpend { .. } => write!(f, "double spend"),
            Tx { index, error } => write!(f, "transaction {index}: {error:?}"),
            MinerReward(e) => write!(f, "miner reward: {e:?}"),
            BlockTooBig { weight, limit } => {
                write!(f, "block weight {weight} exceeds the limit {limit}")
            }
            Storage(e) => write!(f, "storage: {e}"),
            Malformed(what) => write!(f, "malformed block: {what}"),
        }
    }
}

impl std::error::Error for BlockError {}

impl From<wow_storage::DbError> for BlockError {
    fn from(e: wow_storage::DbError) -> Self {
        BlockError::Storage(e.to_string())
    }
}

/// How far a block got, for the `NotOnTip` case that is not really an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    /// Extended the main chain.
    MainChain { height: u64 },
    /// Stored as an alternative block; no reorg followed.
    AltChain { height: u64 },
    /// Stored as an alternative block and the chain switched to it.
    Reorg { height: u64, popped: u64 },
}
