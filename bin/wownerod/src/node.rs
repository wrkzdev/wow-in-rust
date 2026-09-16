//! The chain and the pool, as the peer-to-peer layer and the RPC server see
//! them (`specs/09` §2, §5).
//!
//! # Two locks, one order
//!
//! The chain and the pool each sit behind a mutex. Where both are needed the
//! chain is taken first: applying a block holds the chain and then clears the
//! pool of what the block contained. Nothing takes them the other way round --
//! filling a fluffy block from the pool releases the pool before it touches the
//! chain.
//!
//! The reads a peer makes constantly -- the tip, whether a block is known, the
//! short history -- go to the database directly rather than through the chain
//! lock, so a sync applying a hundred blocks does not hold every other
//! connection's timed sync behind it.
//!
//! # Announcements
//!
//! A [`Listener`] -- the ZMQ publisher -- hears of new pool transactions,
//! miner data and blocks as they happen, in the C++'s order.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use wow_consensus::fee::FeeContext;
use wow_consensus::hardfork::HardFork;
use wow_core::{Added, BlockError, Blockchain, PowError, Rejection};
use wow_crypto::random::Rng;
use wow_crypto::types::{Hash256, KeyImage};
use wow_p2p::messages::{BlockEntry, CoreSyncData, BLOCK_IDS_DEFAULT_COUNT};
use wow_p2p::node::{BlockVerdict, ChainReply, Core, TxVerdict};
use wow_storage::db::BlockchainDb;
use wow_storage::lmdb::LmdbDb;
use wow_types::address::Address;
use wow_types::block::Block;
use wow_types::tx::{Transaction, TxIn};
use wow_types::Network;

use crate::mempool::{Rejection as PoolRejection, TxPool};
use crate::netsync::{ChainPow, ChainTxs, LocalChain, PendingTx, Refusal, Submitted};
use crate::template::{ExtraNonce, NextBlock, Template, TemplateError};

const LOG: &str = "blockchain";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Told what the chain and the pool do as they do it (`specs/09` §3.2).
///
/// Called with the chain lock held, in the order the C++ notifies for a
/// block: transactions that reached it without passing through the pool, then
/// miner data, then the block. An implementation must neither block nor call
/// back into the node.
pub trait Listener: Send + Sync {
    /// Whether anyone wants to hear of `event`, so what nobody wants is not
    /// built.
    fn wants(&self, event: Event) -> bool;
    fn txpool_add(&self, txs: &[PoolTx]);
    fn miner_data(&self, data: &MinerData);
    fn chain_main(&self, height: u64, block: &Block);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    TxpoolAdd,
    MinerData,
    ChainMain,
}

/// A transaction new to the pool, or to the chain without the pool.
pub struct PoolTx {
    pub id: Hash256,
    pub tx: Transaction,
    pub blob_size: usize,
    pub weight: u64,
    pub fee: u64,
}

/// What a miner needs to build on a new tip (`send_miner_notifications`).
pub struct MinerData {
    pub major_version: u8,
    /// The next block's height.
    pub height: u64,
    pub prev_id: Hash256,
    pub seed_hash: Hash256,
    pub difficulty: u128,
    pub median_weight: u64,
    pub already_generated_coins: u64,
    /// `(id, weight, fee)` of what a block template would draw on.
    pub tx_backlog: Vec<(Hash256, u64, u64)>,
}

/// The node's chain and pool.
pub struct NodeCore {
    db: Arc<LmdbDb>,
    hardfork: HardFork,
    chain: Mutex<LocalChain>,
    /// The chain's proof-of-work verifier, reachable without the chain lock.
    pow: Arc<ChainPow>,
    /// The chain's transaction verifier, reachable for the same reason.
    txs: Arc<ChainTxs>,
    pool: Arc<Mutex<TxPool>>,
    /// A snapshot of what fee checks read, refreshed after every block, so an
    /// RPC fee estimate does not wait on a sync holding the chain.
    fee: Mutex<FeeContext>,
    listener: OnceLock<Arc<dyn Listener>>,
    /// When the pool is next walked for transactions due to go out again.
    next_relay_check: AtomicU64,
}

impl NodeCore {
    pub fn new(
        db: Arc<LmdbDb>,
        network: Network,
        pool: Arc<Mutex<TxPool>>,
    ) -> Result<Arc<NodeCore>, String> {
        let chain = LocalChain::new(db.clone(), network)?;
        let fee = fee_context_of(&chain);
        let pow = chain.pow();
        let txs = chain.txs();
        Ok(Arc::new(NodeCore {
            db,
            hardfork: HardFork::new(network),
            chain: Mutex::new(chain),
            pow,
            txs,
            pool,
            fee: Mutex::new(fee),
            listener: OnceLock::new(),
            next_relay_check: AtomicU64::new(0),
        }))
    }

    /// Announce what happens from now on to `listener`. The first one set
    /// stays.
    pub fn set_listener(&self, listener: Arc<dyn Listener>) {
        let _ = self.listener.set(listener);
    }

    fn listening(&self, event: Event) -> Option<&dyn Listener> {
        self.listener.get().map(|l| &**l).filter(|l| l.wants(event))
    }

    /// Transactions just admitted to the pool, announced. One kept from relay
    /// is not: a subscriber hears what goes out to the network, as the C++'s
    /// `relay_category::legacy` has it.
    pub fn announce_pool_txs(&self, ids: &[Hash256]) {
        let Some(listener) = self.listening(Event::TxpoolAdd) else {
            return;
        };
        let entries: Vec<(Hash256, Vec<u8>, u64, u64)> = {
            let pool = lock(&self.pool);
            ids.iter()
                .filter_map(|id| {
                    let e = pool.get(id).filter(|e| !e.do_not_relay)?;
                    Some((*id, e.blob.clone(), e.weight, e.fee))
                })
                .collect()
        };
        let txs: Vec<PoolTx> = entries
            .into_iter()
            .filter_map(|(id, blob, weight, fee)| {
                Some(PoolTx {
                    id,
                    tx: Transaction::from_blob(&blob).ok()?,
                    blob_size: blob.len(),
                    weight,
                    fee,
                })
            })
            .collect();
        if !txs.is_empty() {
            listener.txpool_add(&txs);
        }
    }

    /// The height below which checkpoints stand in for verification.
    pub fn trusted_below(&self) -> u64 {
        lock(&self.chain).trusted_below()
    }

    pub fn fee_context(&self) -> FeeContext {
        *lock(&self.fee)
    }

    pub fn height(&self) -> u64 {
        self.db.height()
    }

    /// `--fixed-difficulty`, on regtest (`specs/07` §5).
    pub fn set_fixed_difficulty(&self, difficulty: Option<u128>) {
        lock(&self.chain)
            .blockchain_mut()
            .set_fixed_difficulty(difficulty);
    }

    /// What the next block must be, read under the chain lock.
    pub fn next_block(&self) -> Result<NextBlock, String> {
        next_block_of(lock(&self.chain).blockchain())
    }

    /// `create_block_template` (`specs/09` §6.1).
    ///
    /// The chain lock is held throughout and the pool's is taken inside it --
    /// the order everything here takes them in -- so no block lands between
    /// reading the tip and choosing the transactions.
    pub fn block_template(
        &self,
        address: &Address,
        extra: &ExtraNonce,
        rng: &mut Rng,
    ) -> Result<Template, TemplateError> {
        let chain = lock(&self.chain);
        let bc = chain.blockchain();
        let next = next_block_of(bc).map_err(TemplateError::Chain)?;
        let pool = lock(&self.pool);
        crate::template::build(
            &self.db,
            bc.network(),
            &next,
            &pool,
            address,
            extra,
            unix_now(),
            rng,
        )
    }

    /// `pop_blocks`: take up to `n` blocks off the tip, returning their
    /// transactions to the pool.
    pub fn pop_blocks(&self, n: u64) -> Result<u64, String> {
        let mut chain = lock(&self.chain);
        let popped = chain
            .blockchain_mut()
            .pop_blocks(n)
            .map_err(|e| e.to_string())?;
        chain.resync_hashes()?;
        self.settle(&mut chain);
        wow_log::warn!(
            LOG,
            "popped {popped} block(s); height is now {}",
            self.db.height()
        );
        Ok(popped)
    }

    /// A whole block from outside the peer network, such as `submit_block`.
    ///
    /// Returns what became of it and, when it was accepted, the block with its
    /// transactions for relaying.
    pub fn submit_block(&self, blob: &[u8]) -> (BlockVerdict, Option<BlockEntry>) {
        let entry = BlockEntry {
            block: blob.to_vec(),
            txs: Vec::new(),
            block_weight: 0,
        };
        match self.fill(&entry) {
            Ok(txs) => {
                let verdict = {
                    let mut chain = lock(&self.chain);
                    self.apply(&mut chain, blob, &txs)
                };
                let relay = matches!(verdict, BlockVerdict::Added).then(|| BlockEntry {
                    block: blob.to_vec(),
                    txs,
                    block_weight: 0,
                });
                (verdict, relay)
            }
            Err(v) => (v, None),
        }
    }

    fn apply(&self, chain: &mut LocalChain, blob: &[u8], txs: &[Vec<u8>]) -> BlockVerdict {
        let before = self.db.height();
        match chain.submit(blob, txs) {
            Ok(s) => {
                self.after(chain, &s, before);
                match s.added {
                    Added::AltChain { .. } => BlockVerdict::Alternative,
                    _ => BlockVerdict::Added,
                }
            }
            Err(Refusal::Malformed(reason)) => BlockVerdict::Rejected { reason, ban: true },
            Err(Refusal::Rejected(r)) => verdict(r),
            // The sender is not at fault for a block the checkpoints name, so
            // the sync stalls and retries rather than banning it.
            Err(Refusal::Checkpointed(r)) => match verdict(r) {
                BlockVerdict::Rejected { reason, .. } => BlockVerdict::Rejected {
                    reason: format!(
                        "{reason}; the block is the checkpointed one, so this node's rules \
                         are wrong, not the peer"
                    ),
                    ban: false,
                },
                other => other,
            },
        }
    }

    /// What a block changes beyond the chain. `before` is the chain's height
    /// before it arrived.
    fn after(&self, chain: &mut LocalChain, s: &Submitted, before: u64) {
        let (first, unpooled) = match s.added {
            Added::AltChain { height } => {
                wow_log::info!(LOG, "alternative block at height {height}");
                return;
            }
            Added::MainChain { height } => {
                // Transactions that reach the chain without having been in the
                // pool are news to a listener too (`handle_block_to_main_chain`).
                let unpooled = match self.listening(Event::TxpoolAdd) {
                    Some(_) => self.unpooled(&s.txs),
                    None => Vec::new(),
                };
                let spent = key_images(&s.txs);
                lock(&self.pool).remove_mined(&s.block.tx_hashes, &spent);
                if (height + 1) % 1_000 == 0 {
                    wow_log::info!(LOG, "height {}", height + 1);
                } else {
                    wow_log::debug!(LOG, "height {}", height + 1);
                }
                (height, unpooled)
            }
            Added::Reorg { height, popped } => {
                wow_log::warn!(
                    LOG,
                    "reorganised: {popped} block(s) replaced; the tip is now height {}",
                    height + 1
                );
                lock(&self.pool).remove_confirmed(&self.db);
                // The chain was popped down to one past the split, so the
                // replacing blocks start where the popped ones did.
                (before.saturating_sub(popped), Vec::new())
            }
        };
        self.settle(chain);
        self.announce(chain, first, &unpooled);
    }

    /// Tell the listener of a new tip: transactions, then miner data, then
    /// every block from `first` up, one message each as the C++ sends them.
    fn announce(&self, chain: &LocalChain, first: u64, unpooled: &[PoolTx]) {
        let Some(listener) = self.listener.get() else {
            return;
        };
        if !unpooled.is_empty() && listener.wants(Event::TxpoolAdd) {
            listener.txpool_add(unpooled);
        }
        if let Some(data) = listener
            .wants(Event::MinerData)
            .then(|| self.miner_data(chain))
            .flatten()
        {
            listener.miner_data(&data);
        }
        if listener.wants(Event::ChainMain) {
            for h in first..self.db.height() {
                let block = self
                    .db
                    .get_block_blob(h)
                    .ok()
                    .and_then(|b| Block::from_blob(&b).ok());
                if let Some(block) = block {
                    listener.chain_main(h, &block);
                }
            }
        }
    }

    /// A block's transactions the pool did not hold.
    fn unpooled(&self, txs: &[(Transaction, Vec<u8>)]) -> Vec<PoolTx> {
        let pool = lock(&self.pool);
        txs.iter()
            .filter_map(|(tx, blob)| {
                let id = wow_types::hashes::transaction_hash_from_blob(tx, blob)?;
                (!pool.contains(&id)).then(|| PoolTx {
                    id,
                    tx: tx.clone(),
                    blob_size: blob.len(),
                    weight: wow_types::weight::get_transaction_weight(tx, blob.len()),
                    fee: tx.fee().unwrap_or(0),
                })
            })
            .collect()
    }

    /// `send_miner_notifications`, for the tip `chain` has now.
    ///
    /// The backlog is `get_block_template_backlog`'s: what may be relayed,
    /// best paying first, up to 112.5% of the median weight -- enough for a
    /// full block. The C++ also drops transactions whose key images collide;
    /// the pool here admits no such pair in the first place.
    fn miner_data(&self, chain: &LocalChain) -> Option<MinerData> {
        let next = next_block_of(chain.blockchain()).ok()?;
        let (seed_height, _) = wow_randomwow::seed::rx_seedheights(next.height);
        let seed_hash = if seed_height < next.height {
            self.db.get_block_hash(seed_height).ok()?
        } else {
            [0u8; 32]
        };
        let max_weight = next.median_weight.saturating_add(next.median_weight / 8);
        let mut tx_backlog = Vec::new();
        let mut weight = 0u64;
        for (id, e) in lock(&self.pool).by_fee() {
            if e.do_not_relay {
                continue;
            }
            tx_backlog.push((id, e.weight, e.fee));
            weight = weight.saturating_add(e.weight);
            if weight > max_weight {
                break;
            }
        }
        Some(MinerData {
            major_version: self.hardfork.required_version(next.height),
            height: next.height,
            prev_id: next.prev_id,
            seed_hash,
            difficulty: next.difficulty,
            median_weight: next.median_weight,
            already_generated_coins: next.already_generated_coins,
            tx_backlog,
        })
    }

    /// Return what a reorganisation or a pop took off the chain to the pool,
    /// and refresh the fee snapshot.
    fn settle(&self, chain: &mut LocalChain) {
        let orphaned = chain.blockchain_mut().take_orphaned_txs();
        let fee = fee_context_of(chain);
        if !orphaned.is_empty() {
            let now = unix_now();
            let mut pool = lock(&self.pool);
            let back = orphaned
                .iter()
                .filter(|(tx, blob)| {
                    pool.add_kept_by_block(&self.db, tx, blob, fee.version, now)
                        .is_ok()
                })
                .count();
            wow_log::info!(
                "txpool",
                "{back} of {} transaction(s) from replaced blocks returned to the pool",
                orphaned.len()
            );
        }
        *lock(&self.fee) = fee;
    }

    /// A block's transactions, from the message by hash and then from the
    /// pool, or the verdict that makes looking pointless.
    fn fill(&self, entry: &BlockEntry) -> Result<Vec<Vec<u8>>, BlockVerdict> {
        let refuse = |reason: &str| BlockVerdict::Rejected {
            reason: reason.into(),
            ban: true,
        };
        let block =
            Block::from_blob(&entry.block).map_err(|_| refuse("the block does not parse"))?;
        let id = block
            .block_id()
            .ok_or_else(|| refuse("the block has no id"))?;
        if self.have_block(&id) {
            return Err(BlockVerdict::AlreadyHave);
        }

        let mut supplied: HashMap<Hash256, Vec<u8>> = HashMap::new();
        for blob in &entry.txs {
            let tx =
                Transaction::from_blob(blob).map_err(|_| refuse("a transaction does not parse"))?;
            let h = wow_types::hashes::transaction_hash_from_blob(&tx, blob)
                .ok_or_else(|| refuse("a transaction has no hash"))?;
            supplied.insert(h, blob.clone());
        }

        let pool = lock(&self.pool);
        let mut txs = Vec::with_capacity(block.tx_hashes.len());
        let mut missing = Vec::new();
        for (i, h) in block.tx_hashes.iter().enumerate() {
            if let Some(b) = supplied.remove(h) {
                txs.push(b);
            } else if let Some(e) = pool.get(h) {
                txs.push(e.blob.clone());
            } else {
                missing.push(i as u64);
            }
        }
        if !missing.is_empty() {
            return Err(BlockVerdict::MissingTxs(missing));
        }
        Ok(txs)
    }

    /// A main-chain block with its transactions.
    fn entry_at(&self, id: &Hash256) -> Option<BlockEntry> {
        let height = self.db.get_block_height(id).ok()?;
        let blob = self.db.get_block_blob(height).ok()?;
        let block = Block::from_blob(&blob).ok()?;
        let txs = block
            .tx_hashes
            .iter()
            .map(|t| self.db.get_tx_blob(t).ok())
            .collect::<Option<Vec<_>>>()?;
        Some(BlockEntry {
            block: blob,
            txs,
            block_weight: self.db.get_block_weight(height).unwrap_or(0),
        })
    }
}

/// What the fee checks read, from the chain's cached state.
fn fee_context_of(chain: &LocalChain) -> FeeContext {
    let bc = chain.blockchain();
    let state = bc.state();
    FeeContext {
        version: bc.current_version(),
        cumulative_weight_limit: state.weights.limit,
        long_term_effective_median: state
            .weights
            .long_term_effective_median
            .unwrap_or(state.weights.median),
        already_generated_coins: state.already_generated_coins,
    }
}

/// The next block's parameters, from the chain's cached state.
fn next_block_of(bc: &Blockchain<LmdbDb>) -> Result<NextBlock, String> {
    let state = bc.state();
    Ok(NextBlock {
        height: bc.height(),
        prev_id: bc.top_hash().ok_or("the chain has no genesis block")?,
        difficulty: bc.next_difficulty().map_err(|e| e.to_string())?,
        median_weight: state.weights.median,
        already_generated_coins: state.already_generated_coins,
    })
}

/// A chain rejection, as the network layer acts on it.
///
/// `specs/09` §2.1: only a failed verification or bad proof of work justifies
/// a ban. A block this node could not check -- a proof-of-work variant it does
/// not implement, a storage error, a clock that disagrees -- is not evidence
/// against the peer.
fn verdict(r: Rejection) -> BlockVerdict {
    let ban = match &r.error {
        BlockError::AlreadyExists { .. } => return BlockVerdict::AlreadyHave,
        BlockError::Orphan { .. } | BlockError::NotOnTip { .. } => return BlockVerdict::Orphan,
        BlockError::Pow(PowError::CryptoNightNotImplemented { .. } | PowError::RandomWow(_)) => {
            false
        }
        BlockError::Storage(_) | BlockError::MissingTx { .. } => false,
        // A transaction shape this node has no verifier for is this node's
        // gap. The block is still refused; the peer that sent it is not
        // blamed for a rule nobody here has written.
        BlockError::TxSignature {
            error: wow_core::TxCheckError::Unsupported(_),
            ..
        } => false,
        BlockError::Timestamp(wow_consensus::timestamp::TimestampError::TooFarInTheFuture {
            ..
        }) => false,
        _ => true,
    };
    BlockVerdict::Rejected {
        reason: r.to_string(),
        ban,
    }
}

fn key_images(txs: &[(Transaction, Vec<u8>)]) -> Vec<KeyImage> {
    txs.iter()
        .flat_map(|(t, _)| t.prefix.vin.iter())
        .filter_map(|i| match i {
            TxIn::ToKey { k_image, .. } => Some(*k_image),
            _ => None,
        })
        .collect()
}

impl Core for NodeCore {
    fn sync_data(&self) -> CoreSyncData {
        let height = self.db.height();
        let (top_id, cumulative_difficulty) = if height == 0 {
            (wow_crypto::NULL_HASH, 0)
        } else {
            (
                self.db
                    .get_block_hash(height - 1)
                    .unwrap_or(wow_crypto::NULL_HASH),
                self.db
                    .get_block_cumulative_difficulty(height - 1)
                    .unwrap_or(0),
            )
        };
        CoreSyncData {
            current_height: height,
            cumulative_difficulty,
            top_id,
            top_version: self.hardfork.required_version(height.saturating_sub(1)),
            pruning_seed: 0,
        }
    }

    /// `get_short_chain_history`, read from the database: the same shape as
    /// [`wow_p2p::sync::short_history`] without holding every hash.
    fn short_history(&self) -> Vec<Hash256> {
        let len = self.db.height();
        let mut out = Vec::new();
        if len == 0 {
            return out;
        }
        let (mut i, mut step) = (0u64, 1u64);
        while i < len {
            if let Ok(h) = self.db.get_block_hash(len - 1 - i) {
                out.push(h);
            }
            if out.len() > 10 {
                step *= 2;
            }
            i += step;
        }
        if let Ok(genesis) = self.db.get_block_hash(0) {
            if out.last() != Some(&genesis) {
                out.push(genesis);
            }
        }
        out
    }

    fn have_block(&self, id: &Hash256) -> bool {
        self.db.block_exists(id).unwrap_or(false) || self.db.get_alt_block(id).is_ok()
    }

    fn chain_reply(&self, history: &[Hash256]) -> Option<ChainReply> {
        // `find_blockchain_supplement` insists the history ends at this node's
        // genesis: a peer whose does not is on another chain entirely.
        let genesis = self.db.get_block_hash(0).ok()?;
        if history.last() != Some(&genesis) {
            return None;
        }
        let height = self.db.height();
        let start = history
            .iter()
            .find_map(|h| self.db.get_block_height(h).ok())?;
        let end = height.min(start + BLOCK_IDS_DEFAULT_COUNT as u64);

        let mut block_ids = Vec::with_capacity((end - start) as usize);
        let mut block_weights = Vec::with_capacity((end - start) as usize);
        for h in start..end {
            block_ids.push(self.db.get_block_hash(h).ok()?);
            block_weights.push(self.db.get_block_weight(h).unwrap_or(0));
        }
        Some(ChainReply {
            start_height: start,
            total_height: height,
            cumulative_difficulty: self
                .db
                .get_block_cumulative_difficulty(height.saturating_sub(1))
                .unwrap_or(0),
            block_ids,
            block_weights,
            first_block: self.db.get_block_blob(start).ok()?,
        })
    }

    fn blocks(&self, ids: &[Hash256]) -> (Vec<BlockEntry>, Vec<Hash256>) {
        let mut found = Vec::new();
        let mut missed = Vec::new();
        for id in ids {
            match self.entry_at(id) {
                Some(e) => found.push(e),
                None => missed.push(*id),
            }
        }
        (found, missed)
    }

    fn apply_blocks(&self, blocks: &[BlockEntry]) -> (usize, Option<BlockVerdict>) {
        // The proofs and the ring signatures first, on every core and without
        // the chain lock. Between them they are nearly all of the cost of
        // applying a batch, and neither needs the chain to be still.
        let work = self.pow_work(blocks);
        self.pow.prehash(&work);
        let tx_work = self.tx_work(blocks);
        self.txs.prevalidate(&tx_work, unix_now());
        let taken = {
            let mut chain = lock(&self.chain);
            blocks
                .iter()
                .enumerate()
                .find_map(|(i, b)| match self.apply(&mut chain, &b.block, &b.txs) {
                    BlockVerdict::Added | BlockVerdict::AlreadyHave | BlockVerdict::Alternative => {
                        None
                    }
                    other => Some((i, Some(other))),
                })
                .unwrap_or((blocks.len(), None))
        };
        self.pow.forget(&work);
        self.txs.forget(&tx_work);
        taken
    }

    fn new_block(&self, entry: &BlockEntry) -> BlockVerdict {
        match self.fill(entry) {
            Ok(txs) => {
                let mut chain = lock(&self.chain);
                self.apply(&mut chain, &entry.block, &txs)
            }
            Err(v) => v,
        }
    }

    fn block_with_txs(&self, id: &Hash256, indices: &[u64]) -> Option<BlockEntry> {
        let height = self.db.get_block_height(id).ok()?;
        let blob = self.db.get_block_blob(height).ok()?;
        let block = Block::from_blob(&blob).ok()?;
        let txs = indices
            .iter()
            .map(|i| {
                block
                    .tx_hashes
                    .get(*i as usize)
                    .and_then(|t| self.db.get_tx_blob(t).ok())
            })
            .collect::<Option<Vec<_>>>()?;
        Some(BlockEntry {
            block: blob,
            txs,
            block_weight: self.db.get_block_weight(height).unwrap_or(0),
        })
    }

    fn incoming_txs(&self, txs: &[Vec<u8>]) -> Vec<TxVerdict> {
        let verdicts = self.admit_txs(txs);
        let accepted: Vec<Hash256> = verdicts
            .iter()
            .filter_map(|v| match v {
                TxVerdict::Accepted { id, .. } => Some(*id),
                _ => None,
            })
            .collect();
        if !accepted.is_empty() {
            self.announce_pool_txs(&accepted);
        }
        verdicts
    }

    fn pool_txs_except(&self, known: &HashSet<Hash256>) -> Vec<Vec<u8>> {
        lock(&self.pool).public_txs_except(known, unix_now())
    }

    fn pool_hashes(&self) -> Vec<Hash256> {
        lock(&self.pool).relayable_ids()
    }

    fn tx_relayed(&self, ids: &[Hash256]) {
        lock(&self.pool).mark_relayed(ids, unix_now());
    }

    fn due_for_relay(&self) -> Vec<(Hash256, Vec<u8>)> {
        use std::sync::atomic::Ordering::Relaxed;
        // Asked every tick; the pool is walked every two minutes.
        let now = unix_now();
        if now < self.next_relay_check.load(Relaxed) {
            return Vec::new();
        }
        self.next_relay_check
            .store(now + crate::mempool::RELAY_CHECK_SECS, Relaxed);
        lock(&self.pool).due_for_relay(now)
    }
}

impl NodeCore {
    /// The `(seed, hashing blob)` of each block in a sync batch whose proof the
    /// chain is going to compute: RandomWOW blocks at or above both the tip and
    /// the trusted range. A seed at or above the tip is an earlier block of the
    /// same batch.
    ///
    /// A guess rather than a ruling. A block that does not parse ends the list,
    /// since the chain stops there too; one that turns out to be on another
    /// branch only wastes its hash.
    fn pow_work(&self, blocks: &[BlockEntry]) -> Vec<(Hash256, Vec<u8>)> {
        let tip = self.db.height();
        let from = tip.max(self.pow.trusted_below());
        let mut ids = HashMap::new();
        let mut work = Vec::new();
        for entry in blocks {
            let Ok(block) = Block::from_blob(&entry.block) else {
                break;
            };
            let height = match block.miner_tx.prefix.vin.as_slice() {
                [TxIn::Gen { height }] => *height,
                _ => break,
            };
            if let Some(id) = block.block_id() {
                ids.insert(height, id);
            }
            if height < from || block.major_version < wow_randomwow::RX_BLOCK_VERSION {
                continue;
            }
            let seed_height = wow_randomwow::rx_seedheight(height);
            let seed = if seed_height < tip {
                self.db.get_block_hash(seed_height).ok()
            } else {
                ids.get(&seed_height).copied()
            };
            if let (Some(seed), Some(blob)) = (seed, block.hashing_blob()) {
                work.push((seed, blob));
            }
        }
        work
    }

    /// Every transaction of a batch that the chain will actually check, with
    /// the major version of the block carrying it.
    ///
    /// The same shape as [`NodeCore::pow_work`], and the same boundary: below
    /// `trusted_below` the chain does not run these rules, so hashing rings
    /// there would be work for nothing. A blob that does not parse is left
    /// out rather than reported -- the chain refuses it, with the height and
    /// the index this cannot know.
    fn tx_work(&self, blocks: &[BlockEntry]) -> Vec<PendingTx> {
        let from = self.db.height().max(self.pow.trusted_below());
        let mut work = Vec::new();
        for entry in blocks {
            let Ok(block) = Block::from_blob(&entry.block) else {
                break;
            };
            let height = match block.miner_tx.prefix.vin.as_slice() {
                [TxIn::Gen { height }] => *height,
                _ => break,
            };
            if height < from {
                continue;
            }
            for blob in &entry.txs {
                let Ok(tx) = Transaction::from_blob(blob) else {
                    continue;
                };
                let Some(id) = wow_types::hashes::transaction_hash_from_blob(&tx, blob) else {
                    continue;
                };
                work.push((id, tx, block.major_version));
            }
        }
        work
    }

    /// Transactions from a peer, into the pool.
    fn admit_txs(&self, txs: &[Vec<u8>]) -> Vec<TxVerdict> {
        let ctx = self.fee_context();
        let now = unix_now();
        let mut pool = lock(&self.pool);
        txs.iter()
            .map(|blob| {
                let id = Transaction::from_blob(blob)
                    .ok()
                    .and_then(|t| wow_types::hashes::transaction_hash_from_blob(&t, blob));
                let Some(id) = id else {
                    return TxVerdict::Rejected {
                        reason: "a transaction that does not parse".into(),
                        ban: true,
                    };
                };
                if pool.contains(&id) || self.db.tx_exists(&id).unwrap_or(false) {
                    return TxVerdict::Known { id };
                }
                match pool.add(&self.db, blob, &ctx, now, false) {
                    Ok(id) => TxVerdict::Accepted { id, relay: true },
                    Err(PoolRejection::AlreadyInPool) => TxVerdict::Known { id },
                    // A refusal here is policy, or a ring this node cannot
                    // resolve yet while it catches up; neither is proof the
                    // peer lied (`specs/08` §8.2).
                    Err(r) => TxVerdict::Rejected {
                        reason: r.reason(),
                        ban: false,
                    },
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejection(error: BlockError) -> Rejection {
        Rejection {
            step: wow_core::Step::Transactions,
            error,
        }
    }

    /// Only evidence of misbehaviour bans; this node's own limits do not.
    #[test]
    fn only_a_failed_verification_bans() {
        assert_eq!(
            verdict(rejection(BlockError::Orphan { prev: [0; 32] })),
            BlockVerdict::Orphan
        );
        assert_eq!(
            verdict(rejection(BlockError::AlreadyExists { id: [0; 32] })),
            BlockVerdict::AlreadyHave
        );
        for (error, ban) in [
            (BlockError::InsufficientPow { difficulty: 5 }, true),
            (BlockError::DoubleSpend { image: [1; 32] }, true),
            (
                BlockError::Pow(PowError::CryptoNightNotImplemented {
                    height: 60_000,
                    variant: "variant 2",
                }),
                false,
            ),
            (BlockError::Storage("disk".into()), false),
            (
                BlockError::Timestamp(
                    wow_consensus::timestamp::TimestampError::TooFarInTheFuture { limit: 1 },
                ),
                false,
            ),
            // A ring signature that does not verify is the sender's fault.
            (
                BlockError::TxSignature {
                    index: 0,
                    error: wow_core::TxCheckError::Invalid("input 0: bad CLSAG".into()),
                },
                true,
            ),
            // A shape this node has no verifier for is not.
            (
                BlockError::TxSignature {
                    index: 0,
                    error: wow_core::TxCheckError::Unsupported("RCT type Null".into()),
                },
                false,
            ),
        ] {
            match verdict(rejection(error.clone())) {
                BlockVerdict::Rejected { ban: b, .. } => assert_eq!(b, ban, "{error:?}"),
                other => panic!("{error:?} gave {other:?}"),
            }
        }
    }
}
