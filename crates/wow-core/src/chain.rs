//! The `Blockchain` state machine.
//!
//! `specs/06-consensus-rules.md` §2 gives twelve numbered steps and opens with
//! "**Order matters because some checks feed later ones.**" That is the whole
//! design of this module: [`Blockchain::add_block`] runs them in order and
//! [`Step`] names each one, so a rejection reports how far the block got.
//!
//! Two orderings are easy to get wrong and are called out where they happen:
//!
//! * the difficulty algorithm is chosen by the **tip's** hard-fork version, not
//!   the incoming block's (`specs/07` §3, `specs/06` §9.4);
//! * the weight limit used to validate a block is the one computed **after the
//!   previous block**, not one derived from this block (`specs/06` §3.4).

use std::sync::Arc;

use wow_consensus::checkpoints::Checkpoints;
use wow_consensus::difficulty::{difficulty_blocks_count, next_difficulty};
use wow_consensus::emission::{get_block_reward, validate_miner_reward, MinerReward};
use wow_consensus::hardfork::HardFork;
use wow_consensus::timestamp::{check_block_timestamp, timestamp_check_window};
use wow_consensus::weight::{
    next_long_term_block_weight, update_next_cumulative_weight_limit, LongTermWeightWindow,
    WeightLimits,
};
use wow_consensus::{constants, tx_rules};
use wow_crypto::types::Hash256;
use wow_storage::db::BlockchainDb;
use wow_types::{check_hash, Block, Difficulty, Network, Transaction};

use crate::error::{Added, BlockError};
use crate::pow::PowVerifier;

/// Which of `specs/06` §2's twelve steps a block reached.
///
/// Reported alongside a rejection: knowing a block failed at step 6 rather than
/// step 9 is the difference between a PoW problem and a transaction problem.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    HaveIt = 1,
    ParentIsTip = 2,
    HardFork = 3,
    Timestamp = 4,
    Difficulty = 5,
    ProofOfWork = 6,
    Checkpoint = 7,
    CoinbasePrevalidation = 8,
    Transactions = 9,
    CoinbaseAmount = 10,
    WeightLimit = 11,
    Commit = 12,
}

/// A rejection, with the step it happened at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub step: Step,
    pub error: BlockError,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "step {} ({:?}): {}",
            self.step as u8, self.step, self.error
        )
    }
}

impl std::error::Error for Rejection {}

/// The cached state `specs/06` and `specs/10` require a node to carry between
/// blocks.
///
/// None of it is derivable from the tip alone, which is why it lives here
/// rather than being recomputed per block.
#[derive(Debug)]
pub struct ChainState {
    /// `m_current_block_cumul_weight_median` / `..._limit`, updated after every
    /// block (`specs/06` §3.4).
    pub weights: WeightLimits,
    /// The sliding window of **stored** long-term weights.
    pub long_term: LongTermWeightWindow,
    /// The last `CRYPTONOTE_REWARD_BLOCKS_WINDOW` block weights.
    pub recent_weights: std::collections::VecDeque<u64>,
    /// `already_generated_coins` at the tip.
    pub already_generated_coins: u64,
    /// The tip's cumulative difficulty.
    pub cumulative_difficulty: u128,
    /// `(timestamp, cumulative_difficulty)` for the most recent
    /// [`DIFFICULTY_WINDOW_CACHE`] blocks, newest last.
    ///
    /// The reference keeps the same two rolling vectors (`m_timestamps` and
    /// `m_difficulties`) for the same reason: without them, every block costs
    /// another `difficulty_blocks_count` reads, which at hard-fork version 7 is
    /// **735** -- each its own read transaction. That was measured at roughly
    /// six blocks a second against a live peer, or about two days for a
    /// mainnet sync.
    ///
    /// The window is always kept at the largest size any version asks for, so
    /// a fork that widens it is served from the same cache rather than falling
    /// back to the database.
    pub difficulty_window: std::collections::VecDeque<(u64, u128)>,
}

/// How many `(timestamp, cumulative_difficulty)` pairs to keep.
///
/// `difficulty_blocks_count` returns 735, 145, 147 or 61 depending on the
/// version; the cache holds the largest so every version can be served by
/// taking the tail.
pub const DIFFICULTY_WINDOW_CACHE: usize = wow_consensus::constants::DIFFICULTY_BLOCKS_COUNT;

impl Default for ChainState {
    fn default() -> Self {
        ChainState {
            weights: WeightLimits {
                median: constants::BLOCK_GRANTED_FULL_REWARD_ZONE_V5,
                limit: constants::BLOCK_GRANTED_FULL_REWARD_ZONE_V5 * 2,
                long_term_effective_median: None,
            },
            long_term: LongTermWeightWindow::new(),
            recent_weights: std::collections::VecDeque::new(),
            already_generated_coins: 0,
            cumulative_difficulty: 0,
            difficulty_window: std::collections::VecDeque::new(),
        }
    }
}

/// The chain.
pub struct Blockchain<D: BlockchainDb> {
    db: Arc<D>,
    pow: Arc<dyn PowVerifier>,
    network: Network,
    hardfork: HardFork,
    checkpoints: Checkpoints,
    state: ChainState,
    /// Below this height, a block's transaction *rules* are not re-checked.
    ///
    /// Zero -- the default -- checks everything. See
    /// [`Blockchain::trust_below`] for why anything else is ever correct.
    trusted_below: u64,
}

impl<D: BlockchainDb> Blockchain<D> {
    /// Open a chain over an existing store, rebuilding the cached state from
    /// it.
    pub fn new(
        db: Arc<D>,
        pow: Arc<dyn PowVerifier>,
        network: Network,
    ) -> Result<Self, BlockError> {
        let mut chain = Blockchain {
            db,
            pow,
            network,
            hardfork: HardFork::new(network),
            checkpoints: Checkpoints::new(network),
            state: ChainState::default(),
            trusted_below: 0,
        };
        chain.reload_state()?;
        Ok(chain)
    }

    pub fn db(&self) -> &Arc<D> {
        &self.db
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn hardfork(&self) -> &HardFork {
        &self.hardfork
    }

    pub fn checkpoints(&self) -> &Checkpoints {
        &self.checkpoints
    }

    /// Stop re-checking transaction *rules* below `height`.
    ///
    /// This reproduces the reference's `PER_BLOCK_CHECKPOINT` behaviour, and it
    /// is not an optimisation: **the chain does not satisfy its own rules**.
    /// `Blockchain::handle_block_to_main_chain` sets `fast_check` for any block
    /// covered by the embedded `blocks.dat` hash table and then skips both the
    /// proof of work and `check_tx_inputs` entirely. Mainnet block 460 carries
    /// a transaction with ring size 12 where `check_tx_inputs` demands mixin
    /// exactly 7 at hard-fork version 7; it has never been examined by a
    /// released node. A verifier that applied `specs/06` §9 from genesis would
    /// stop there, having copied the rule correctly.
    ///
    /// `docs/spec-deltas.md` §23 and `docs/cpp-findings.md` §13 record the
    /// mechanism and what it hides.
    ///
    /// **How this differs from the reference.** The C++ keys the bypass on a
    /// per-block hash for *every* height below the table, so a forged block is
    /// caught at once. This node has 39 hard-coded checkpoints, so between two
    /// of them it is trusting the `prev_id` chain and will only discover a
    /// forgery when it reaches the next checkpoint. That is a weaker position,
    /// and the caller should set this from the checkpoint list rather than from
    /// a peer's claims.
    ///
    /// What is still checked below `height`: the parent link, the hard-fork
    /// version, the timestamp, the difficulty, the checkpoint hashes
    /// themselves, coinbase prevalidation and amount, the weight limit,
    /// duplicate transactions, and key-image double spends. What is not: the
    /// per-transaction rules in `specs/06` §9.
    pub fn trust_below(&mut self, height: u64) {
        self.trusted_below = height;
    }

    /// The height below which transaction rules are not re-checked.
    pub fn trusted_below(&self) -> u64 {
        self.trusted_below
    }

    pub fn state(&self) -> &ChainState {
        &self.state
    }

    pub fn height(&self) -> u64 {
        self.db.height()
    }

    /// The tip's hash, or `None` on an empty chain.
    pub fn top_hash(&self) -> Option<Hash256> {
        let h = self.height();
        if h == 0 {
            return None;
        }
        self.db.get_block_hash(h - 1).ok()
    }

    /// The hard-fork version in force at the tip.
    ///
    /// This is what `get_current_hard_fork_version()` returns, and it is what
    /// several rules read where a reader would expect the block's own version
    /// (`specs/06` §9.4).
    pub fn tip_version(&self) -> u8 {
        self.hardfork
            .required_version(self.height().saturating_sub(1))
    }

    /// Rebuild the cached state from the store.
    ///
    /// Called on open and after a reorg, which is where `specs/06` §7 step 6
    /// says the caches must be recomputed.
    pub fn reload_state(&mut self) -> Result<(), BlockError> {
        let height = self.height();
        let mut state = ChainState::default();

        if height > 0 {
            let tip = self.db.get_block_info(height - 1)?;
            state.already_generated_coins = tip.coins;
            state.cumulative_difficulty = tip.cumulative_difficulty;

            // The last 100 block weights, for the short-term median.
            let from = height.saturating_sub(constants::CRYPTONOTE_REWARD_BLOCKS_WINDOW as u64);
            for h in from..height {
                state
                    .recent_weights
                    .push_back(self.db.get_block_info(h)?.weight);
            }

            // The long-term window: the stored column, not the block weights.
            let n = wow_consensus::weight::long_term_window(height);
            for h in (height - n)..height {
                state.long_term.push(self.db.get_block_long_term_weight(h)?);
            }

            // The difficulty window. This is the expensive one to rebuild and
            // the expensive one to do without, so it is read once here and then
            // carried forward a block at a time.
            let from = height.saturating_sub(DIFFICULTY_WINDOW_CACHE as u64);
            for h in from..height {
                let info = self.db.get_block_info(h)?;
                state
                    .difficulty_window
                    .push_back((info.timestamp, info.cumulative_difficulty));
            }

            state.weights = self.compute_weight_limits(&state, self.tip_version());
        }

        self.state = state;
        Ok(())
    }

    fn compute_weight_limits(&self, state: &ChainState, version: u8) -> WeightLimits {
        let mut recent: Vec<u64> = state.recent_weights.iter().copied().collect();
        update_next_cumulative_weight_limit(version, &mut recent, state.long_term.median())
    }

    /// The difficulty the next block must meet (`specs/07` §1).
    ///
    /// The algorithm is chosen by the **tip's** version, not by the block being
    /// validated (`specs/07` §3).
    pub fn next_difficulty(&self) -> Result<Difficulty, BlockError> {
        let height = self.height();
        if height == 0 {
            return Ok(1);
        }
        let version = self.tip_version();
        let count = difficulty_blocks_count(version) as u64;

        let offset = {
            let o = height - height.min(count);
            if o == 0 {
                1
            } else {
                o
            }
        };
        // The cache holds heights `start..height`. `offset` is never below
        // `start`, because the cache is as wide as the widest window any
        // version asks for.
        let window = &self.state.difficulty_window;
        let start = height - window.len() as u64;
        let skip = offset.saturating_sub(start) as usize;

        let mut timestamps = Vec::with_capacity(window.len() - skip.min(window.len()));
        let mut cumulative = Vec::with_capacity(window.len() - skip.min(window.len()));
        for (ts, cd) in window.iter().skip(skip) {
            timestamps.push(*ts);
            cumulative.push(*cd);
        }
        Ok(next_difficulty(
            version,
            timestamps,
            cumulative,
            height,
            self.network,
        ))
    }

    /// The timestamps `check_block_timestamp` compares against.
    fn recent_timestamps(&self, version: u8) -> Result<Vec<u64>, BlockError> {
        let height = self.height();
        let window = timestamp_check_window(version) as u64;
        if height < window {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(window as usize);
        for h in (height - window)..height {
            out.push(self.db.get_block_info(h)?.timestamp);
        }
        Ok(out)
    }

    /// `specs/06` §2, steps 1–12, in order.
    ///
    /// `txs` are the block's non-coinbase transactions, in `tx_hashes` order.
    /// `now` is the wall clock for the timestamp check, passed in so the rule
    /// stays testable.
    pub fn add_block(
        &mut self,
        blk: &Block,
        blob: &[u8],
        txs: &[(Transaction, Vec<u8>)],
        now: u64,
    ) -> Result<Added, Rejection> {
        let height = self.height();
        let id = blk
            .block_id()
            .ok_or_else(|| reject(Step::HaveIt, BlockError::Malformed("no block id")))?;

        // 1. Have it already?
        if self
            .db
            .block_exists(&id)
            .map_err(|e| reject(Step::HaveIt, e.into()))?
        {
            return Err(reject(Step::HaveIt, BlockError::AlreadyExists { id }));
        }

        // 2. Parent is the tip?
        let tip = self.top_hash();
        match (height, tip) {
            (0, _) => {}
            (_, Some(t)) if blk.header.prev_id == t => {}
            (_, Some(t)) => {
                return Err(reject(
                    Step::ParentIsTip,
                    BlockError::NotOnTip {
                        prev: blk.header.prev_id,
                        tip: t,
                    },
                ))
            }
            (_, None) => return Err(reject(Step::ParentIsTip, BlockError::Malformed("no tip"))),
        }

        // 3. Hard fork.
        let required = self.hardfork.required_version(height);
        let vote = blk.header.hard_fork_vote();
        if !self.hardfork.check(height, blk.header.major_version, vote) {
            return Err(reject(
                Step::HardFork,
                BlockError::WrongVersion {
                    height,
                    found: blk.header.major_version,
                    required,
                    vote,
                },
            ));
        }

        // 4. Timestamp. The window and the limit come from the *tip's* version.
        let tip_version = self.tip_version();
        let mut recent = self
            .recent_timestamps(tip_version)
            .map_err(|e| reject(Step::Timestamp, e))?;
        check_block_timestamp(tip_version, blk.header.timestamp, now, &mut recent)
            .map_err(|e| reject(Step::Timestamp, BlockError::Timestamp(e)))?;

        // 5. Difficulty.
        let difficulty = self
            .next_difficulty()
            .map_err(|e| reject(Step::Difficulty, e))?;

        // 6. Proof of work.
        if !self.pow.may_skip(height) {
            let hashing_blob = blk.hashing_blob().ok_or_else(|| {
                reject(
                    Step::ProofOfWork,
                    BlockError::Pow(crate::pow::PowError::NoHashingBlob),
                )
            })?;
            let seed = self
                .seed_hash_for(height)
                .map_err(|e| reject(Step::ProofOfWork, e))?;
            let pow = self
                .pow
                .pow_hash(height, blk.header.major_version, &hashing_blob, &seed)
                .map_err(|e| reject(Step::ProofOfWork, BlockError::Pow(e)))?;
            if !check_hash(&pow, difficulty) {
                return Err(reject(
                    Step::ProofOfWork,
                    BlockError::InsufficientPow { difficulty },
                ));
            }
        }

        // 7. Checkpoint.
        if let Some(cp) = self.checkpoints.at(height) {
            let expected = cp.hash;
            if expected != id {
                return Err(reject(
                    Step::Checkpoint,
                    BlockError::CheckpointMismatch {
                        height,
                        expected,
                        found: id,
                    },
                ));
            }
        }

        // 8. Coinbase prevalidation.
        let unlock = self
            .coinbase_unlock_time(height, blk.header.major_version)
            .map_err(|e| reject(Step::CoinbasePrevalidation, e))?;
        tx_rules::check_coinbase(&blk.miner_tx, blk.header.major_version, height, unlock)
            .map_err(|e| reject(Step::CoinbasePrevalidation, BlockError::Coinbase(e)))?;

        // 9. Transactions.
        let fees = self
            .check_transactions(blk, txs, height)
            .map_err(|(step, e)| reject(step, e))?;

        // 10 & 11. Coinbase amount and the weight limit.
        //
        // These are one computation in the C++: `get_block_reward` returns
        // false when `current_block_weight > 2 * median_weight`, which is how
        // step 11 is enforced (`specs/06` §2 step 11).
        let cumulative_weight = self.cumulative_block_weight(blk, txs);
        let claimed: u64 = blk.miner_tx.prefix.vout.iter().map(|o| o.amount).sum();

        // Step 11 is enforced *through* step 10: `get_block_reward` returns
        // false when `current_block_weight > 2 * median_weight`, which is how
        // the C++ applies the cumulative weight limit (`specs/06` §2 step 11).
        // So the weight rejection comes out of the reward call, not from a
        // separate comparison.
        let base_reward = get_block_reward(
            self.state.weights.median,
            cumulative_weight,
            self.state.already_generated_coins,
            blk.header.major_version,
        )
        .map_err(|_| {
            reject(
                Step::WeightLimit,
                BlockError::BlockTooBig {
                    weight: cumulative_weight,
                    limit: self.state.weights.limit,
                },
            )
        })?;

        let reward: MinerReward =
            validate_miner_reward(blk.header.major_version, base_reward, fees, claimed)
                .map_err(|e| reject(Step::CoinbaseAmount, BlockError::MinerReward(e)))?;

        // 12. Commit.
        let long_term_weight = next_long_term_block_weight(
            blk.header.major_version,
            cumulative_weight,
            self.state.long_term.median(),
        );
        let cumulative_difficulty = self.state.cumulative_difficulty + difficulty;
        let coins = self
            .state
            .already_generated_coins
            .saturating_add(reward.adjusted_base_reward);

        self.db
            .add_block(
                blk,
                blob,
                cumulative_weight,
                long_term_weight,
                cumulative_difficulty,
                coins,
                txs,
            )
            .map_err(|e| reject(Step::Commit, e.into()))?;

        // Advance the cached state, in the order `specs/06` §3.4 fixes: the
        // long-term weight is stored first, then the limit for the *next* block
        // is computed with the *next* block's version.
        self.state.long_term.push(long_term_weight);
        self.state.recent_weights.push_back(cumulative_weight);
        while self.state.recent_weights.len() > constants::CRYPTONOTE_REWARD_BLOCKS_WINDOW {
            self.state.recent_weights.pop_front();
        }
        self.state.already_generated_coins = coins;
        self.state.cumulative_difficulty = cumulative_difficulty;

        self.state
            .difficulty_window
            .push_back((blk.header.timestamp, cumulative_difficulty));
        while self.state.difficulty_window.len() > DIFFICULTY_WINDOW_CACHE {
            self.state.difficulty_window.pop_front();
        }

        let next_version = self.hardfork.required_version(height + 1);
        self.state.weights = self.compute_weight_limits(&self.state, next_version);

        Ok(Added::MainChain { height })
    }

    /// Step 9 (`specs/06` §2), returning the total fee.
    ///
    /// The per-block key-image set is the part worth reading twice: the C++
    /// keeps a `key_images_container` populated as each transaction is
    /// accepted, "so a key image may appear at most once across the whole
    /// block (and must not already be in `spent_keys`)".
    fn check_transactions(
        &self,
        blk: &Block,
        txs: &[(Transaction, Vec<u8>)],
        height: u64,
    ) -> Result<u64, (Step, BlockError)> {
        use std::collections::BTreeSet;

        if txs.len() != blk.tx_hashes.len() {
            return Err((
                Step::Transactions,
                BlockError::Malformed("transaction count does not match tx_hashes"),
            ));
        }

        let mut seen_hashes: BTreeSet<Hash256> = BTreeSet::new();
        let mut block_images: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut fees: u64 = 0;
        let version = blk.header.major_version;

        for (i, (hash, (tx, _))) in blk.tx_hashes.iter().zip(txs.iter()).enumerate() {
            if !seen_hashes.insert(*hash) {
                return Err((
                    Step::Transactions,
                    BlockError::DuplicateTxInBlock { index: i },
                ));
            }
            if self
                .db
                .tx_exists(hash)
                .map_err(|e| (Step::Transactions, e.into()))?
            {
                return Err((
                    Step::Transactions,
                    BlockError::TxAlreadyInChain { hash: *hash },
                ));
            }

            // Semantic checks, then the input rules -- unless this height is
            // inside the trusted zone, where the reference does not check them
            // either and the chain does not satisfy them. See
            // `Blockchain::trust_below`.
            let semantic_fee = if height < self.trusted_below {
                tx.fee().map(Some).ok_or((
                    Step::Transactions,
                    BlockError::Tx {
                        index: i,
                        error: tx_rules::TxError::InputsOverflow,
                    },
                ))?
            } else {
                let semantic_fee = tx_rules::check_tx_semantic(tx)
                    .map_err(|error| (Step::Transactions, BlockError::Tx { index: i, error }))?;
                tx_rules::check_min_outputs(tx, version)
                    .map_err(|error| (Step::Transactions, BlockError::Tx { index: i, error }))?;
                tx_rules::check_inputs_sorted(tx)
                    .map_err(|error| (Step::Transactions, BlockError::Tx { index: i, error }))?;
                tx_rules::check_tx_rct_type(tx, version)
                    .map_err(|error| (Step::Transactions, BlockError::Tx { index: i, error }))?;

                let summary = tx_rules::summarise_mixin(tx, version, |amount| {
                    self.db.get_num_outputs(amount).unwrap_or(0)
                });
                tx_rules::check_ring_size(&summary, version)
                    .map_err(|error| (Step::Transactions, BlockError::Tx { index: i, error }))?;
                tx_rules::check_tx_version(tx.prefix.version, version, summary.n_unmixable)
                    .map_err(|error| (Step::Transactions, BlockError::Tx { index: i, error }))?;
                semantic_fee
            };

            // Double spends: within the block, and against the chain.
            for image in tx_rules_key_images(tx) {
                if !block_images.insert(image) {
                    return Err((Step::Transactions, BlockError::DoubleSpend { image }));
                }
                let ki = wow_crypto::types::KeyImage(image);
                if self
                    .db
                    .has_key_image(&ki)
                    .map_err(|e| (Step::Transactions, e.into()))?
                {
                    return Err((Step::Transactions, BlockError::DoubleSpend { image }));
                }
            }

            // v1 carries its fee as the input/output difference; v2 in the RCT
            // signatures.
            let fee = semantic_fee.unwrap_or(tx.rct_signatures.txn_fee);
            fees = fees.saturating_add(fee);
            let _ = height;
        }
        Ok(fees)
    }

    /// `cumulative_block_weight` (`specs/05` §5).
    ///
    /// The coinbase contributes its **blob size** and every other transaction
    /// its **weight** — which differ once a batched range proof triggers the
    /// clawback. A coinbase never carries one, so the asymmetry is invisible
    /// today, but it is how the C++ adds them up.
    fn cumulative_block_weight(&self, blk: &Block, txs: &[(Transaction, Vec<u8>)]) -> u64 {
        let mut w = wow_serialize::binary::Writer::with_capacity(2048);
        blk.miner_tx.write(&mut w);
        let mut total = w.len() as u64;

        for (tx, blob) in txs {
            total = total.saturating_add(wow_types::get_transaction_weight(tx, blob.len()));
        }
        total
    }

    /// The coinbase unlock time this height demands (`specs/06` §5.1.1).
    ///
    /// The HF 16–17 regime reads the id of the block `N` back, so it needs the
    /// chain.
    fn coinbase_unlock_time(&self, height: u64, version: u8) -> Result<u64, BlockError> {
        use wow_consensus::hardfork::gates::{HF_VERSION_DYNAMIC_UNLOCK, HF_VERSION_FIXED_UNLOCK};
        // Only the middle regime -- HF 16 and 17 -- needs the chain. The fixed
        // and the flat windows are arithmetic on the height alone.
        if !(HF_VERSION_DYNAMIC_UNLOCK..HF_VERSION_FIXED_UNLOCK).contains(&version) {
            return Ok(tx_rules::coinbase_unlock_time(version, height, None));
        }
        let back = tx_rules::dynamic_unlock_lookback(self.network);
        let referenced = height
            .checked_sub(back)
            .ok_or(BlockError::Malformed("dynamic unlock below genesis"))?;
        let id = self.db.get_block_hash(referenced)?;
        Ok(tx_rules::coinbase_unlock_time(version, height, Some(&id)))
    }

    /// The RandomWOW seed hash for a height (`specs/03` §3.4).
    fn seed_hash_for(&self, height: u64) -> Result<Hash256, BlockError> {
        let seed_height = wow_randomwow::seed::rx_seedheight(height);
        if self.height() > seed_height {
            Ok(self.db.get_block_hash(seed_height)?)
        } else {
            // Before the first seed block exists the seed is the null hash,
            // which is what the C++ uses too.
            Ok([0u8; 32])
        }
    }
}

/// The key images a transaction spends, as plain arrays.
fn tx_rules_key_images(tx: &Transaction) -> Vec<[u8; 32]> {
    tx.prefix
        .vin
        .iter()
        .filter_map(|i| match i {
            wow_types::TxIn::ToKey { k_image, .. } => Some(*k_image.as_bytes()),
            _ => None,
        })
        .collect()
}

fn reject(step: Step, error: BlockError) -> Rejection {
    Rejection { step, error }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_steps_are_numbered_as_the_spec_numbers_them() {
        assert_eq!(Step::HaveIt as u8, 1);
        assert_eq!(Step::ParentIsTip as u8, 2);
        assert_eq!(Step::HardFork as u8, 3);
        assert_eq!(Step::Timestamp as u8, 4);
        assert_eq!(Step::Difficulty as u8, 5);
        assert_eq!(Step::ProofOfWork as u8, 6);
        assert_eq!(Step::Checkpoint as u8, 7);
        assert_eq!(Step::CoinbasePrevalidation as u8, 8);
        assert_eq!(Step::Transactions as u8, 9);
        assert_eq!(Step::CoinbaseAmount as u8, 10);
        assert_eq!(Step::WeightLimit as u8, 11);
        assert_eq!(Step::Commit as u8, 12);
    }

    /// The steps sort in the order they run, so "how far did it get" is a
    /// comparison rather than a lookup.
    #[test]
    fn the_steps_are_ordered() {
        assert!(Step::HaveIt < Step::ProofOfWork);
        assert!(Step::ProofOfWork < Step::Transactions);
        assert!(Step::Transactions < Step::Commit);
    }

    /// A fresh chain starts at the full-reward-zone floor, not at zero — an
    /// empty `recent_weights` medians to 0 and the floor lifts it
    /// (`specs/06` §3.4).
    #[test]
    fn the_default_state_starts_at_the_weight_floor() {
        let s = ChainState::default();
        assert_eq!(
            s.weights.median,
            constants::BLOCK_GRANTED_FULL_REWARD_ZONE_V5
        );
        assert_eq!(s.weights.limit, s.weights.median * 2);
        assert_eq!(s.weights.median, 300_000);
        assert_eq!(s.already_generated_coins, 0);
        assert_eq!(s.cumulative_difficulty, 0);
        assert!(s.long_term.is_empty());
    }

    #[test]
    fn a_rejection_says_which_step() {
        let r = Rejection {
            step: Step::ProofOfWork,
            error: BlockError::InsufficientPow { difficulty: 1000 },
        };
        let s = r.to_string();
        assert!(s.contains("step 6"), "{s}");
        assert!(s.contains("ProofOfWork"), "{s}");
        assert!(s.contains("1000"), "{s}");
    }
}
