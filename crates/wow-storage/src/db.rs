//! The `BlockchainDb` trait.
//!
//! `specs/10-storage-lmdb.md` §9: "Keep the trait as the seam, both to allow a
//! test double (the equivalent of `testdb.h`) and to keep an alternative
//! backend possible later."
//!
//! # Why it is not shaped like a RocksDB trait
//!
//! `specs/10` §9 is explicit about three differences, and each is load-bearing:
//!
//! * **No `snapshot()`.** A `RoTxn` *is* the snapshot. LMDB readers see a
//!   consistent view for the transaction's whole life, so an extra abstraction
//!   would only add a way to hold one open too long (`specs/10` §6.2).
//! * **No `verify_and_repair_tip()`.** LMDB's two meta pages mean a crash
//!   leaves the file structurally valid at *some* commit, so there is no torn
//!   tip to repair (`specs/10` §6.3).
//! * **Explicit [`BlockchainDb::batch_start`], [`BlockchainDb::batch_stop`] and
//!   [`BlockchainDb::resize_barrier`].** LMDB's transaction and map-size model
//!   cannot be hidden: a resize invalidates every outstanding pointer, so it
//!   has to be part of the interface rather than something the backend does
//!   opportunistically (`specs/10` §2.2).
//!
//! # `&self` on the mutating methods
//!
//! `add_block` and friends take `&self`, not `&mut self`. That is deliberate
//! and matches the C++: one environment is shared by the block-adding thread
//! and every RPC reader, and LMDB already serialises writers itself. An
//! implementation carries the write transaction behind its own lock.

use std::collections::BTreeMap;

use wow_crypto::types::{Hash256, KeyImage};
use wow_types::{Block, Transaction};

use crate::records::{AltBlock, BlockInfo, TxPoolMeta};

/// Why a database operation failed.
#[derive(Debug)]
pub enum DbError {
    /// The key was not present. Distinct from a decoding failure: the C++
    /// throws `BLOCK_DNE` / `TX_DNE` and callers branch on it.
    NotFound,
    /// A stored record did not decode — a corrupt or foreign database.
    Record(crate::records::RecordError),
    /// The backend itself.
    Backend(Box<dyn std::error::Error + Send + Sync>),
    /// A write was attempted on a database this node may not write to
    /// (`specs/10` §2.3).
    ReadOnly,
    /// A resize was requested while a transaction was open. `specs/10` §2.2
    /// makes this a hard constraint: the C++ throws, and so does this.
    ResizeWhileOpen,
}

impl From<crate::records::RecordError> for DbError {
    fn from(e: crate::records::RecordError) -> Self {
        DbError::Record(e)
    }
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::NotFound => write!(f, "not found"),
            DbError::Record(e) => write!(f, "malformed record: {e:?}"),
            DbError::Backend(e) => write!(f, "backend: {e}"),
            DbError::ReadOnly => write!(f, "database is read-only"),
            DbError::ResizeWhileOpen => {
                write!(f, "cannot resize the map while a transaction is open")
            }
        }
    }
}

impl std::error::Error for DbError {}

pub type Result<T> = std::result::Result<T, DbError>;

/// `tx_data_t` — what `tx_indices` stores about a transaction
/// (`specs/10` §4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TxData {
    pub tx_id: u64,
    pub unlock_time: u64,
    /// The **height** of the containing block, despite the C++ field being
    /// called `block_id`.
    pub block_height: u64,
}

/// `output_data_t` — one output as `get_output_key` returns it
/// (`specs/10` §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct OutputData {
    pub pubkey: [u8; 32],
    pub unlock_time: u64,
    pub height: u64,
    /// `None` when the caller did not ask for it.
    ///
    /// For a pre-RingCT output the stored record has no commitment, and the
    /// C++ synthesises `zero_commit(amount)` — see
    /// [`crate::semantics`] and `wow_crypto::rct::zero_commit`.
    pub commitment: Option<[u8; 32]>,
}

/// `alt_block_data_t` (`specs/10` §4.10), without the trailing blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AltBlockData {
    pub height: u64,
    pub cumulative_weight: u64,
    pub cumulative_difficulty: u128,
    pub already_generated_coins: u64,
}

impl From<&AltBlock> for AltBlockData {
    fn from(a: &AltBlock) -> Self {
        AltBlockData {
            height: a.height,
            cumulative_weight: a.cumulative_weight,
            cumulative_difficulty: a.cumulative_difficulty,
            already_generated_coins: a.already_generated_coins,
        }
    }
}

/// One row of `get_output_histogram`: `(total, unlocked, recent)`.
pub type HistogramEntry = (u64, u64, u64);

/// The callback [`BlockchainDb::for_all_txpool_txes`] drives.
///
/// The blob is `None` when the caller asked for metadata only, which is how the
/// C++ avoids reading every transaction body to list the pool. Returning
/// `false` stops the walk.
pub type TxPoolVisitor<'a> = dyn FnMut(&Hash256, &TxPoolMeta, Option<&[u8]>) -> bool + 'a;

/// The storage seam (`specs/10` §9).
pub trait BlockchainDb: Send + Sync {
    // ----------------------------------------------------------------- chain

    /// `mdb_stat(blocks).ms_entries` — a table entry count, never a cached
    /// counter (`specs/10` §5.1).
    fn height(&self) -> u64;

    fn block_exists(&self, h: &Hash256) -> Result<bool>;
    fn get_block_hash(&self, height: u64) -> Result<Hash256>;
    fn get_block_height(&self, h: &Hash256) -> Result<u64>;
    fn get_block_blob(&self, height: u64) -> Result<Vec<u8>>;
    fn get_block_info(&self, height: u64) -> Result<BlockInfo>;
    fn get_block_timestamp(&self, height: u64) -> Result<u64>;
    fn get_block_weight(&self, height: u64) -> Result<u64>;

    /// The **stored** long-term weight. It cannot be recomputed from block
    /// weights (`specs/06` §3.4), so this record is authoritative.
    fn get_block_long_term_weight(&self, height: u64) -> Result<u64>;

    fn get_block_cumulative_difficulty(&self, height: u64) -> Result<u128>;
    fn get_block_already_generated_coins(&self, height: u64) -> Result<u64>;
    fn get_block_cumulative_rct_outputs(&self, heights: &[u64]) -> Result<Vec<u64>>;

    /// The median of the stored long-term weights over `[start, start + count)`.
    ///
    /// The C++ keeps a rolling median cache for this; `wow_consensus::weight`
    /// has an equivalent structure, and the module header there explains why
    /// the rolling median and the plain sorted one agree.
    fn get_long_term_block_weight_median(&self, start: u64, count: u64) -> Result<u64>;

    // ---------------------------------------------------------- transactions

    fn tx_exists(&self, h: &Hash256) -> Result<bool>;
    fn get_tx_data(&self, h: &Hash256) -> Result<TxData>;
    fn get_tx_blob(&self, h: &Hash256) -> Result<Vec<u8>>;
    fn get_pruned_tx_blob(&self, h: &Hash256) -> Result<Vec<u8>>;
    fn get_prunable_tx_hash(&self, h: &Hash256) -> Result<Hash256>;
    fn get_tx_block_height(&self, h: &Hash256) -> Result<u64>;

    /// The amount output indices for `n` consecutive transactions from `tx_id`.
    fn get_tx_amount_output_indices(&self, tx_id: u64, n: usize) -> Result<Vec<Vec<u64>>>;

    // -------------------------------------------------------------- outputs

    /// The dup count under `output_amounts[amount]`.
    ///
    /// **Consensus-relevant**: it decides whether a pre-RingCT amount is
    /// mixable (`specs/06` §5.3), so it is the closure
    /// `wow_consensus::tx_rules::summarise_mixin` takes.
    fn get_num_outputs(&self, amount: u64) -> Result<u64>;

    /// One output by amount and per-amount index.
    ///
    /// With `with_commitment`, a pre-RingCT output gets a synthesised
    /// `zero_commit(amount)` rather than `None` (`specs/10` §4.5).
    fn get_output_key(&self, amount: u64, index: u64, with_commitment: bool) -> Result<OutputData>;

    /// A ring's worth of outputs. `allow_partial` mirrors the C++ flag that
    /// lets a caller tolerate missing entries instead of failing the batch.
    fn get_output_keys(
        &self,
        amounts: &[u64],
        offsets: &[u64],
        allow_partial: bool,
    ) -> Result<Vec<OutputData>>;

    fn get_output_tx_and_index(&self, amount: u64, index: u64) -> Result<(Hash256, u64)>;
    fn get_output_tx_and_index_from_global(&self, output_id: u64) -> Result<(Hash256, u64)>;

    fn get_output_histogram(
        &self,
        amounts: &[u64],
        unlocked: bool,
        recent_cutoff: u64,
        min_count: u64,
    ) -> Result<BTreeMap<u64, HistogramEntry>>;

    /// Derived from `bi_cum_rct` differences for amount 0. Wallets use it for
    /// decoy selection (`specs/12` §4.3), so the values must match the C++.
    fn get_output_distribution(&self, amount: u64, from: u64, to: u64) -> Result<Vec<u64>>;

    // ----------------------------------------------------------- key images

    fn has_key_image(&self, ki: &KeyImage) -> Result<bool>;

    // ------------------------------------------------------------ hard fork

    fn set_hard_fork_version(&self, height: u64, version: u8) -> Result<()>;
    fn get_hard_fork_version(&self, height: u64) -> Result<u8>;

    // ------------------------------------------------------------- mempool

    fn add_txpool_tx(&self, h: &Hash256, blob: &[u8], meta: &TxPoolMeta) -> Result<()>;
    fn update_txpool_tx(&self, h: &Hash256, meta: &TxPoolMeta) -> Result<()>;
    fn remove_txpool_tx(&self, h: &Hash256) -> Result<()>;
    fn get_txpool_tx_meta(&self, h: &Hash256) -> Result<TxPoolMeta>;
    fn get_txpool_tx_blob(&self, h: &Hash256) -> Result<Vec<u8>>;

    /// Visit every pool entry. Returning `false` stops the walk, matching the
    /// C++ callback convention.
    fn for_all_txpool_txes(&self, f: &mut TxPoolVisitor<'_>) -> Result<()>;

    // --------------------------------------------------------- alt blocks

    fn add_alt_block(&self, h: &Hash256, data: &AltBlockData, blob: &[u8]) -> Result<()>;
    fn get_alt_block(&self, h: &Hash256) -> Result<(AltBlockData, Vec<u8>)>;
    fn remove_alt_block(&self, h: &Hash256) -> Result<()>;
    fn get_alt_block_count(&self) -> Result<u64>;
    fn drop_alt_blocks(&self) -> Result<()>;

    // ----------------------------------------------------------- mutation

    /// Append a block, returning its height.
    ///
    /// The id-assignment order in `specs/10` §5.1 is not optional: the coinbase
    /// is added **first**, and `tx_id` / `output_id` come from table entry
    /// counts. `crate::semantics` holds those rules.
    ///
    /// `long_term_block_weight` is supplied by the caller because it cannot be
    /// recomputed here (`specs/06` §3.4).
    #[allow(clippy::too_many_arguments, reason = "mirrors the C++ signature")]
    fn add_block(
        &self,
        blk: &Block,
        blk_blob: &[u8],
        block_weight: u64,
        long_term_block_weight: u64,
        cumulative_difficulty: u128,
        coins_generated: u64,
        txs: &[(Transaction, Vec<u8>)],
    ) -> Result<u64>;

    /// Remove the tip, returning it and its transactions.
    ///
    /// Must restore the exact previous state: `specs/15` §3.3 asks for a test
    /// that hashes every table before and after an `add_block` / `pop_block`
    /// pair and compares.
    fn pop_block(&self) -> Result<(Block, Vec<Transaction>)>;

    /// Rewrite cumulative difficulties in place, for
    /// `recalculate_difficulties` (`specs/07` §6).
    fn correct_block_cumulative_difficulties(&self, start: u64, values: &[u128]) -> Result<()>;

    // ---------------------------------------------------------- lifecycle

    /// Begin a batch. Pre-computes an estimated size and resizes by
    /// `max(estimated, 512 MiB)` first (`specs/10` §2.2), because a resize
    /// **must not** happen once the batch transaction is open.
    fn batch_start(&self, n_blocks: u64, bytes: u64) -> Result<()>;
    fn batch_stop(&self) -> Result<()>;

    /// Drain every open transaction and grow the map (`specs/10` §2.2).
    ///
    /// Changing the map size invalidates every outstanding pointer, so this
    /// takes a lock excluding all readers. `specs/10` calls this "the part of
    /// LMDB that most resembles a footgun" and says not to resize
    /// opportunistically from a reader.
    fn resize_barrier(&self) -> Result<()>;

    /// `mdb_env_sync`.
    fn sync(&self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trait must stay object-safe: `specs/10` §9 wants a test double
    /// alongside the real backend, and `wow-core` will hold one as
    /// `Arc<dyn BlockchainDb>`.
    #[test]
    fn the_trait_is_object_safe() {
        fn assert_object_safe(_: Option<&dyn BlockchainDb>) {}
        assert_object_safe(None);
    }

    #[test]
    fn alt_block_data_drops_the_blob() {
        let full = AltBlock {
            height: 5,
            cumulative_weight: 6,
            cumulative_difficulty: 7,
            already_generated_coins: 8,
            blob: vec![1, 2, 3],
        };
        let data = AltBlockData::from(&full);
        assert_eq!(data.height, 5);
        assert_eq!(data.cumulative_weight, 6);
        assert_eq!(data.cumulative_difficulty, 7);
        assert_eq!(data.already_generated_coins, 8);
    }

    /// `NotFound` is a distinct variant rather than an `Option`, because the
    /// C++ callers branch on `BLOCK_DNE` and a `Result<Option<_>>` everywhere
    /// would obscure which lookups can legitimately miss.
    #[test]
    fn not_found_is_its_own_error() {
        let e = DbError::NotFound;
        assert_eq!(e.to_string(), "not found");
        assert!(!matches!(e, DbError::ReadOnly));
    }

    #[test]
    fn errors_describe_themselves() {
        assert!(DbError::ReadOnly.to_string().contains("read-only"));
        assert!(DbError::ResizeWhileOpen
            .to_string()
            .contains("transaction is open"));
        assert!(
            DbError::from(crate::records::RecordError::NotAnOutputRecord { found: 80 })
                .to_string()
                .contains("malformed record")
        );
    }
}
