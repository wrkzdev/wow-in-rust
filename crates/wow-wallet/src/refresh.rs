//! The refresh loop: asking a daemon what happened and working out what of it
//! was ours.
//!
//! `specs/12` §3. `wallet2::refresh` and `process_new_blockchain_entry`.
//!
//! # The daemon decides where to start, not the wallet
//!
//! A wallet does not say "give me height N". It sends a **short chain
//! history** — its last ten block hashes, then exponentially spaced ones, then
//! genesis — and the daemon answers from the newest of those hashes it has.
//! That is how a reorg is detected without the wallet having to ask: if the
//! chain the wallet is on no longer exists, the daemon simply starts further
//! back, and `start_height` in the reply says where.
//!
//! The reply starts **at** that block, not after it, so its first block is
//! normally one the wallet already holds (`find_blockchain_supplement`:
//! "INCLUDING last known id"). A block the wallet holds is compared, not
//! scanned: the same hash is passed over, and a different one is where the
//! chains split. Reading every reply that started below the tip as a reorg
//! made each batch from a C++ node detach a block and scan it again.
//!
//! Only a wallet with no history names a height. The reference answers a start
//! height above zero from that height whatever the history says, so a wallet
//! that kept naming one was answered from the same place every time.
//!
//! # What is checked, and what is taken on trust
//!
//! Blocks arrive as blobs from a node the wallet did not write. Every one is
//! parsed here and its outputs are checked against the wallet's own keys and
//! its own commitments (`crate::scan`), so a daemon cannot invent money.
//!
//! What a daemon *can* do is lie by omission — withhold a block, or serve a
//! fork — and no amount of checking inside a wallet fixes that. What the wallet
//! does about it is refuse to let the chain jump: each returned block must name
//! the previous one as its parent, so a fork has to be a fork from somewhere
//! the wallet has seen, and a reorg deeper than `max_reorg_depth` is refused
//! outright.

use std::collections::HashMap;

use wow_crypto::types::{Hash256, Hash8, KeyDerivation, KeyImage, PublicKey, SubaddressIndex};
use wow_types::block::Block;
use wow_types::tx::{Transaction, TxIn};

use crate::account::AccountBase;
use crate::history::{SeenSpend, SentTx};
use crate::scan::{scan_transaction, ScanKeys};
use crate::subaddress::SubaddressTable;

/// `COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT`.
pub const MAX_BLOCKS_PER_CALL: u64 = 1_000;

/// The fewest blocks a batch is cut down to. A reply starts with a block the
/// wallet already holds, so one block alone would never bring anything new.
const MIN_BLOCKS_PER_CALL: u64 = 2;

/// `wallet2`'s log category, so one `--log-level` means the same to both.
const LOG: &str = "wallet.wallet2";

/// `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`.
const SPENDABLE_AGE: u64 = 4;

/// One output the wallet owns. `wallet2::transfer_details`, trimmed to what is
/// actually used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub block_height: u64,
    pub txid: Hash256,
    /// Index within its transaction.
    pub internal_output_index: u64,
    /// Index in the chain-wide amount-output table, which is what a ring
    /// references. Zero when the daemon did not supply one.
    pub global_output_index: u64,
    pub public_key: PublicKey,
    /// The derivation this output matched under.
    ///
    /// Kept because spending needs the one-time secret key
    /// `x = Hs(D || i) + b [+ m]`, and `D` cannot be recovered from the output
    /// alone — for a subaddress payment it came from one of the *additional*
    /// transaction public keys, and which one is not recorded anywhere else.
    ///
    /// This is not a new disclosure: the sender already knows `D`, and a cache
    /// that holds the output's public key and transaction id already links the
    /// two. It is not enough to spend with; that needs the spend key.
    pub derivation: KeyDerivation,
    pub key_image: Option<KeyImage>,
    pub mask: [u8; 32],
    pub amount: u64,
    pub subaddress: SubaddressIndex,
    pub spent: bool,
    pub spent_height: u64,
    pub unlock_time: u64,
    pub is_coinbase: bool,
    /// The timestamp of the block it is in. Zero when read from a cache
    /// written before it was kept.
    pub timestamp: u64,
    /// The payment id its transaction carried, decrypted: the key the C++
    /// files its `payment_details` under. `None` for none, and when read from
    /// a cache written before it was kept.
    pub payment_id: Option<Hash8>,
}

impl Transfer {
    /// See [`unlocked_at`].
    pub fn unlocked(&self, chain_height: u64, now: u64) -> bool {
        unlocked_at(self.unlock_time, self.block_height, chain_height, now)
    }
}

/// `is_transfer_unlocked` (`specs/12` §4.2): the transaction's own unlock
/// time, **and** a minimum age of four blocks.
pub fn unlocked_at(unlock_time: u64, block_height: u64, chain_height: u64, now: u64) -> bool {
    wow_consensus::timestamp::is_tx_spendtime_unlocked(unlock_time, chain_height, now)
        && block_height + SPENDABLE_AGE <= chain_height
}

/// How many more blocks until [`unlocked_at`] holds, from a chain of
/// `chain_height` blocks: zero once it does. An unlock time that is a
/// timestamp is counted at the target block time, so for one of those this is
/// an estimate.
pub fn blocks_until_unlocked(
    unlock_time: u64,
    block_height: u64,
    chain_height: u64,
    now: u64,
) -> u64 {
    use wow_consensus::constants::{
        CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS, CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2,
        CRYPTONOTE_MAX_BLOCK_NUMBER, DIFFICULTY_TARGET_V2,
    };
    let age = (block_height + SPENDABLE_AGE).saturating_sub(chain_height);
    let own = if unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER {
        unlock_time.saturating_sub(
            chain_height.saturating_sub(1) + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS,
        )
    } else {
        unlock_time
            .saturating_sub(now.saturating_add(CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2))
            .div_ceil(DIFFICULTY_TARGET_V2)
    };
    age.max(own)
}

/// A block and its transactions, as a source hands them over.
#[derive(Clone, Debug, Default)]
pub struct BlockBundle {
    pub block: Vec<u8>,
    pub txs: Vec<Vec<u8>>,
    /// Global output indices, coinbase first then `tx_hashes` order.
    pub output_indices: Vec<Vec<u64>>,
    /// The transactions are pruned: prefix and RingCT base only, which is all
    /// a scan reads.
    pub pruned: bool,
}

/// One batch of blocks.
#[derive(Clone, Debug, Default)]
pub struct Batch {
    pub blocks: Vec<BlockBundle>,
    pub start_height: u64,
    pub current_height: u64,
}

/// Where blocks come from.
///
/// A trait rather than a `DaemonClient` directly, so the loop can be driven by
/// a fixture. The daemon is the interesting failure mode, and a test that has
/// to stand one up tests the network stack instead of the loop.
pub trait BlockSource {
    type Error: std::fmt::Display;

    /// At most `max_blocks` blocks, from where `block_ids` meets the source's
    /// chain, or from `start_height` when that is above zero.
    fn get_blocks(
        &self,
        block_ids: &[Hash256],
        start_height: u64,
        max_blocks: u64,
    ) -> std::result::Result<Batch, Self::Error>;

    /// Whether `error` is a reply cut off before its end, which a batch of
    /// fewer blocks might get past.
    fn cut_short(_error: &Self::Error) -> bool {
        false
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error("the daemon said: {0}")]
    Source(String),
    #[error("a block at height {height} does not parse: {reason}")]
    BadBlock { height: u64, reason: String },
    #[error("a transaction in the block at height {height} does not parse: {reason}")]
    BadTransaction { height: u64, reason: String },
    #[error("the daemon answered from height {got}, which is past our tip at {tip}")]
    GapInChain { got: u64, tip: u64 },
    #[error("the block at height {height} names {names} as its parent, not {expected}")]
    BrokenChain {
        height: u64,
        names: String,
        expected: String,
    },
    #[error("a reorg {depth} blocks deep exceeds max_reorg_depth of {limit}")]
    ReorgTooDeep { depth: u64, limit: u64 },
    #[error(
        "the daemon answered from height {from} with no block this wallet could add, though its chain reaches {current}"
    )]
    NoProgress { from: u64, current: u64 },
}

type Result<T> = std::result::Result<T, RefreshError>;

/// What one refresh did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefreshSummary {
    /// Blocks added to the wallet's chain. One it already held, sent again
    /// for it to compare, is not counted.
    pub blocks_scanned: u64,
    pub received: usize,
    pub spent: usize,
    /// The height the chain was detached to, if a reorg happened.
    pub reorg_to: Option<u64>,
    /// True when the wallet has caught up with the daemon.
    pub caught_up: bool,
    /// The daemon's height as of the last batch, which moves during a long
    /// refresh.
    pub current_height: u64,
    /// What was found, in chain order.
    pub events: Vec<RefreshEvent>,
}

/// Something a refresh found about this wallet's money: what
/// `on_money_received` and `on_money_spent` report in the C++.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshEvent {
    /// An output paid to this wallet. `burnt` is the smaller output with the
    /// same public key that it replaced, which can no longer be spent.
    Received {
        height: u64,
        txid: Hash256,
        amount: u64,
        burnt: u64,
        subaddress: SubaddressIndex,
    },
    /// An output of this wallet's spent by the transaction `txid`.
    Spent {
        height: u64,
        txid: Hash256,
        amount: u64,
        subaddress: SubaddressIndex,
    },
}

/// What recording an output did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Receipt {
    New,
    /// It replaced a smaller output with the same public key.
    Replaced {
        burnt: u64,
    },
    /// An output with the same public key is already held, spent or at least
    /// as large.
    Ignored,
}

/// The wallet's view of the chain and of its own money.
pub struct WalletState {
    pub account: AccountBase,
    pub subaddresses: SubaddressTable,
    /// Block hashes from [`start_height`](Self::start_height) upward.
    ///
    /// `wallet2` keeps the same thing (`m_blockchain`). It costs 32 bytes a
    /// block, which is a few megabytes for this chain, and it is what makes the
    /// short chain history and reorg detection possible without a round trip.
    pub hashes: Vec<Hash256>,
    /// The height `hashes[0]` sits at.
    pub start_height: u64,
    pub transfers: Vec<Transfer>,
    /// Key image → index into `transfers`, for spotting our own outputs being
    /// spent.
    pub by_key_image: HashMap<KeyImage, usize>,
    /// One-time public key → index into `transfers`, so an output key seen
    /// twice is held once (`m_pub_keys`).
    pub by_public_key: HashMap<PublicKey, usize>,
    /// Transactions that spent this wallet's outputs, sent from here or found
    /// in a block ([`crate::history`]).
    pub sent: Vec<SentTx>,
    /// `max_reorg_depth`. Zero means unlimited, as in the reference.
    pub max_reorg_depth: u64,
    /// This chain's genesis hash.
    ///
    /// Needed because the short chain history must never be *empty*: see
    /// [`WalletState::short_chain_history`].
    pub genesis: Hash256,
    /// How many blocks to ask for at once: halved when a reply is cut short,
    /// doubled back after one that arrives whole. Not saved; each run starts
    /// at the most a daemon sends.
    batch_size: u64,
}

impl WalletState {
    /// A wallet that will start scanning at `start_height`.
    pub fn new(
        account: AccountBase,
        subaddresses: SubaddressTable,
        start_height: u64,
        network: wow_types::Network,
    ) -> Self {
        let genesis = wow_consensus::genesis::genesis_id(network);
        WalletState {
            genesis,
            account,
            subaddresses,
            // A wallet starting at zero already knows the block at height
            // zero, so it holds genesis from the outset --
            // `wallet2::generate` does `m_blockchain.push_back(genesis_hash)`
            // for the same reason.
            hashes: if start_height == 0 {
                vec![genesis]
            } else {
                Vec::new()
            },
            start_height,
            transfers: Vec::new(),
            by_key_image: HashMap::new(),
            by_public_key: HashMap::new(),
            sent: Vec::new(),
            max_reorg_depth: 0,
            batch_size: MAX_BLOCKS_PER_CALL,
        }
    }

    /// One past the highest block the wallet has scanned.
    pub fn scan_height(&self) -> u64 {
        self.start_height + self.hashes.len() as u64
    }

    /// The total of every unspent output, and the change still to come back
    /// from transactions not yet in a block.
    ///
    /// `wallet2::balance` counts that change too. Without it, a send looks as
    /// if it took the whole of its inputs until a block carries it.
    pub fn balance(&self) -> u64 {
        self.transfers
            .iter()
            .filter(|t| !t.spent)
            .map(|t| t.amount)
            .sum::<u64>()
            + self.pending_change()
    }

    /// The total of every unspent output that can actually be spent now.
    ///
    /// Reported separately from [`balance`](Self::balance) because a wallet
    /// that has just mined has a balance it cannot touch for a day
    /// (`specs/12` §4.2).
    pub fn unlocked_balance(&self, chain_height: u64, now: u64) -> u64 {
        self.transfers
            .iter()
            .filter(|t| !t.spent && t.unlocked(chain_height, now))
            .map(|t| t.amount)
            .sum()
    }

    /// What cannot be spent yet: the total of the unspent outputs still
    /// locked, and how many blocks until the first of them unlocks (`None`
    /// when none is). Change on its way back is not in it, having no block
    /// yet to count from.
    pub fn locked(&self, chain_height: u64, now: u64) -> (u64, Option<u64>) {
        self.transfers
            .iter()
            .filter(|t| !t.spent && !t.unlocked(chain_height, now))
            .fold((0, None), |(total, soonest): (u64, Option<u64>), t| {
                let blocks =
                    blocks_until_unlocked(t.unlock_time, t.block_height, chain_height, now);
                (
                    total + t.amount,
                    Some(soonest.map_or(blocks, |s| s.min(blocks))),
                )
            })
    }

    /// The short chain history: the last ten hashes, then exponentially spaced
    /// ones, then genesis (`specs/12` §3.1).
    ///
    /// Newest first. The gaps are what make a deep reorg cost one round trip
    /// instead of one per block.
    pub fn short_chain_history(&self) -> Vec<Hash256> {
        let mut out = Vec::new();
        // A wallet that has scanned nothing still sends genesis, never an
        // empty list. `wallet2::get_short_chain_history` does the same:
        //
        // ```cpp
        // if(!sz)
        // {
        //   ids.push_back(m_blockchain.genesis());
        //   return;
        // }
        // ```
        //
        // The reference daemon *requires* it. With `start_height == 0` and no
        // ids, `Blockchain::find_blockchain_supplement` fails on
        // `qblock_ids.empty()` and `/getblocks.bin` answers `status: "Failed"`
        // -- which is how a brand-new wallet, pointed at a real node, refused
        // to refresh at all.
        if self.hashes.is_empty() {
            out.push(self.genesis);
            return out;
        }

        let len = self.hashes.len();
        let mut i = 0usize; // how far back from the tip
        let mut step = 1usize;
        while i < len {
            out.push(self.hashes[len - 1 - i]);
            if out.len() > 10 {
                step *= 2;
            }
            i += step;
        }
        // The first block the wallet holds, if the gaps skipped it, and then
        // genesis. For a wallet that starts above zero those are different
        // blocks, and the reference refuses a history that does not end at
        // genesis ("genesis block mismatch").
        for anchor in [self.hashes[0], self.genesis] {
            if out.last() != Some(&anchor) {
                out.push(anchor);
            }
        }
        out
    }

    pub(crate) fn keys(&self) -> ScanKeys<'_> {
        ScanKeys {
            address: &self.account.keys.account_address,
            view_secret_key: &self.account.keys.view_secret_key,
            spend_secret_key: if self.account.keys.is_view_only() {
                None
            } else {
                Some(&self.account.keys.spend_secret_key)
            },
            subaddresses: &self.subaddresses,
        }
    }

    /// Drop everything at or above `height`, for a reorg.
    fn detach(&mut self, height: u64) {
        let keep = height.saturating_sub(self.start_height) as usize;
        self.hashes.truncate(keep.min(self.hashes.len()));

        self.transfers.retain(|t| t.block_height < height);
        // A spend recorded in a detached block is un-spent: the transaction
        // that consumed the output is no longer on the chain.
        for t in self.transfers.iter_mut() {
            if t.spent && t.spent_height >= height {
                t.spent = false;
                t.spent_height = 0;
            }
        }
        self.reindex();
        self.detach_sent(height);
    }

    /// Rebuild the lookups over `transfers`, after it was cut short or read
    /// back from a cache.
    pub(crate) fn reindex(&mut self) {
        self.by_key_image = self
            .transfers
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.key_image.map(|k| (k, i)))
            .collect();
        self.by_public_key = self
            .transfers
            .iter()
            .enumerate()
            .map(|(i, t)| (t.public_key, i))
            .collect();
    }

    /// Forget everything scanned and start again at `height`: `rescan_bc`.
    ///
    /// What the chain will say again is dropped. Where this wallet's own
    /// transactions went is not on the chain, so those records are kept and
    /// matched up again as the scan finds them.
    pub fn rescan_from(&mut self, height: u64) {
        // From zero, holding genesis again, as a new wallet does.
        self.hashes = if height == 0 {
            vec![self.genesis]
        } else {
            Vec::new()
        };
        self.transfers.clear();
        self.by_key_image.clear();
        self.by_public_key.clear();
        self.start_height = height;
        self.detach_sent(height);
    }

    /// Fetch one batch and process it.
    ///
    /// Returns what happened. Call it until
    /// [`caught_up`](RefreshSummary::caught_up).
    pub fn refresh_once<S: BlockSource>(&mut self, source: &S) -> Result<RefreshSummary> {
        let history = self.short_chain_history();
        // A start height above zero makes the reference answer from there and
        // ignore the history, so it is only named while there is no history to
        // go by. After that it is zero and the hashes decide, as
        // `wallet2::refresh` resets it.
        let start_height = if self.hashes.is_empty() {
            self.start_height
        } else {
            0
        };
        wow_log::debug!(
            LOG,
            "asking for blocks: scanned to {}, {} history hash(es), start_height {start_height}, at most {}",
            self.scan_height(),
            history.len(),
            self.batch_size
        );
        let batch = loop {
            match source.get_blocks(&history, start_height, self.batch_size) {
                Ok(batch) => break batch,
                // A reply cut off before its end: ask for fewer blocks. A node
                // or a link that cannot carry a thousand blocks in one reply may
                // still carry a few hundred.
                Err(e) if S::cut_short(&e) && self.batch_size > MIN_BLOCKS_PER_CALL => {
                    self.batch_size = (self.batch_size / 2).max(MIN_BLOCKS_PER_CALL);
                    wow_log::info!(
                        LOG,
                        "{e}; asking for {} block(s) at a time",
                        self.batch_size
                    );
                }
                Err(e) => return Err(RefreshError::Source(e.to_string())),
            }
        };
        // Back toward the most, after a reply that arrived whole.
        self.batch_size = (self.batch_size * 2).min(MAX_BLOCKS_PER_CALL);

        let mut summary = RefreshSummary {
            current_height: batch.current_height,
            ..Default::default()
        };

        wow_log::debug!(
            LOG,
            "{} block(s) from height {}, the daemon at {}",
            batch.blocks.len(),
            batch.start_height,
            batch.current_height
        );
        if batch.blocks.is_empty() {
            summary.caught_up = true;
            return Ok(summary);
        }

        let tip = self.scan_height();
        if batch.start_height > tip {
            // A gap: the daemon skipped blocks we have never seen. Accepting it
            // would leave a hole in the hash chain and, with it, in the money.
            return Err(RefreshError::GapInChain {
                got: batch.start_height,
                tip,
            });
        }
        if batch.start_height < self.start_height && !self.hashes.is_empty() {
            // Every block the wallet holds is at or above where it starts, so a
            // reply from below that means the daemon has none of them: the
            // chains split before the wallet's first block. Drop them all, and
            // the next request names the wallet's start height again.
            self.check_reorg_depth(tip - self.start_height)?;
            wow_log::info!(
                LOG,
                "the daemon has none of this wallet's blocks; detaching from {}",
                self.start_height
            );
            self.detach(self.start_height);
            summary.reorg_to = Some(self.start_height);
            return Ok(summary);
        }

        for (n, bundle) in batch.blocks.iter().enumerate() {
            let height = batch.start_height + n as u64;
            // Below where this wallet starts, from a daemon that did not answer
            // from the height it was given. Nothing there is the wallet's.
            if height < self.start_height {
                continue;
            }
            let (block, block_hash) = parse_block(height, bundle)?;
            if height < self.scan_height() {
                // A block the wallet holds already, sent again to be compared
                // (`wallet2::process_parsed_blocks`).
                if block_hash == self.hashes[(height - self.start_height) as usize] {
                    continue;
                }
                self.check_reorg_depth(self.scan_height() - height)?;
                wow_log::info!(
                    LOG,
                    "the chain changed at height {height}; detaching {} block(s)",
                    self.scan_height() - height
                );
                self.detach(height);
                summary.reorg_to = Some(height);
            }
            self.process_block(height, &block, block_hash, bundle, &mut summary)?;
            summary.blocks_scanned += 1;
        }

        summary.caught_up = self.scan_height() >= batch.current_height;
        wow_log::debug!(
            LOG,
            "{} block(s) added, scanned to {}",
            summary.blocks_scanned,
            self.scan_height()
        );
        if summary.blocks_scanned == 0 && !summary.caught_up {
            // Asking again would get the same answer, forever.
            return Err(RefreshError::NoProgress {
                from: batch.start_height,
                current: batch.current_height,
            });
        }
        Ok(summary)
    }

    /// `max_reorg_depth`, checked before anything is detached.
    fn check_reorg_depth(&self, depth: u64) -> Result<()> {
        if self.max_reorg_depth != 0 && depth > self.max_reorg_depth {
            return Err(RefreshError::ReorgTooDeep {
                depth,
                limit: self.max_reorg_depth,
            });
        }
        Ok(())
    }

    /// Refresh until caught up, or until `max_batches` have been fetched.
    ///
    /// The bound is not a nicety: without it a daemon that keeps answering
    /// from further back never terminates.
    pub fn refresh<S: BlockSource>(
        &mut self,
        source: &S,
        max_batches: usize,
    ) -> Result<RefreshSummary> {
        let mut total = RefreshSummary::default();
        for _ in 0..max_batches {
            let s = self.refresh_once(source)?;
            total.blocks_scanned += s.blocks_scanned;
            total.received += s.received;
            total.spent += s.spent;
            total.reorg_to = s.reorg_to.or(total.reorg_to);
            total.caught_up = s.caught_up;
            total.current_height = s.current_height;
            total.events.extend(s.events);
            if s.caught_up {
                break;
            }
        }
        Ok(total)
    }

    fn process_block(
        &mut self,
        height: u64,
        block: &Block,
        block_hash: Hash256,
        bundle: &BlockBundle,
        summary: &mut RefreshSummary,
    ) -> Result<()> {
        // The chain must be continuous. A daemon that serves a block whose
        // parent we do not have at the height below is serving a different
        // chain, and the loop refuses rather than stitching them together.
        if let Some(previous) = self.hashes.last() {
            if height == self.scan_height() && block.header.prev_id != *previous {
                return Err(RefreshError::BrokenChain {
                    height,
                    names: wow_crypto::hex::encode(&block.header.prev_id),
                    expected: wow_crypto::hex::encode(previous),
                });
            }
        }

        // Each transaction's id is the block's, as `wallet2` takes it: a pruned
        // transaction has lost part of what its id is a hash of. Checked before
        // anything is recorded, so a short list cannot pair a transaction with
        // another's id.
        if bundle.txs.len() != block.tx_hashes.len() {
            return Err(RefreshError::BadBlock {
                height,
                reason: format!(
                    "{} transaction(s) for {} hash(es)",
                    bundle.txs.len(),
                    block.tx_hashes.len()
                ),
            });
        }

        // The coinbase first, then the transactions, which is the order the
        // global output indices come in (`specs/11` §5.1).
        let timestamp = block.header.timestamp;
        let coinbase_indices = bundle.output_indices.first().cloned().unwrap_or_default();
        self.process_transaction(
            height,
            timestamp,
            &block.miner_tx,
            wow_types::hashes::transaction_hash(&block.miner_tx).unwrap_or(wow_crypto::NULL_HASH),
            &coinbase_indices,
            summary,
        );

        for (i, (blob, &txid)) in bundle.txs.iter().zip(&block.tx_hashes).enumerate() {
            let parsed = if bundle.pruned {
                Transaction::from_blob_base_only(blob)
            } else {
                Transaction::from_blob(blob)
            };
            let tx = parsed.map_err(|e| RefreshError::BadTransaction {
                height,
                reason: e.to_string(),
            })?;
            let indices = bundle
                .output_indices
                .get(i + 1)
                .cloned()
                .unwrap_or_default();
            self.process_transaction(height, timestamp, &tx, txid, &indices, summary);
        }

        if height == self.scan_height() {
            self.hashes.push(block_hash);
        }
        Ok(())
    }

    fn process_transaction(
        &mut self,
        height: u64,
        timestamp: u64,
        tx: &Transaction,
        txid: Hash256,
        global_indices: &[u64],
        summary: &mut RefreshSummary,
    ) {
        let is_coinbase = matches!(tx.prefix.vin.first(), Some(TxIn::Gen { .. }));

        // Spends first: outputs of ours consumed by this transaction.
        let mut spent = 0u64;
        let mut account = None;
        let mut minors = Vec::new();
        let mut key_images = Vec::new();
        for input in &tx.prefix.vin {
            if let TxIn::ToKey { k_image, .. } = input {
                if let Some(&i) = self.by_key_image.get(k_image) {
                    let t = &mut self.transfers[i];
                    // Spent at height zero is spent by a transaction that was
                    // not in a block yet. This is its block.
                    if !t.spent || t.spent_height == 0 {
                        t.spent = true;
                        t.spent_height = height;
                        summary.spent += 1;
                        summary.events.push(RefreshEvent::Spent {
                            height,
                            txid,
                            amount: t.amount,
                            subaddress: t.subaddress,
                        });
                    }
                    spent += t.amount;
                    account = Some(t.subaddress.major);
                    minors.push(t.subaddress.minor);
                    key_images.push(*k_image);
                }
            }
        }

        // Then receipts. A scan failure is a fact about the transaction, not
        // about the wallet: a malformed transaction on chain must not stop a
        // refresh, and the reference logs and moves on too.
        let found = scan_transaction(tx, &self.keys()).unwrap_or_default();
        // Decrypting the payment id costs a scalar multiplication, so only a
        // transaction that paid this wallet is asked for one.
        let payment_id = if found.is_empty() {
            None
        } else {
            crate::scan::payment_id(tx, &self.account.keys.view_secret_key)
        };

        let mut received = 0u64;
        for r in found {
            let key_image = r.key_image;
            // Found again by a rescan, and already spent by a transaction
            // still waiting for a block.
            let spent_by_pending = key_image.is_some_and(|k| self.is_pending_input(&k));
            let receipt = self.add_transfer(Transfer {
                block_height: height,
                txid,
                derivation: r.derivation,
                internal_output_index: r.output_index,
                global_output_index: global_indices
                    .get(r.output_index as usize)
                    .copied()
                    .unwrap_or(0),
                public_key: r.public_key,
                key_image,
                mask: r.mask,
                amount: r.amount,
                subaddress: r.subaddress,
                spent: spent_by_pending,
                spent_height: 0,
                unlock_time: tx.prefix.unlock_time,
                is_coinbase,
                timestamp,
                payment_id,
            });
            let burnt = match receipt {
                Receipt::Ignored => continue,
                Receipt::New => {
                    summary.received += 1;
                    0
                }
                Receipt::Replaced { burnt } => burnt,
            };
            if Some(r.subaddress.major) == account {
                received += r.amount - burnt;
            }
            summary.events.push(RefreshEvent::Received {
                height,
                txid,
                amount: r.amount,
                burnt,
                subaddress: r.subaddress,
            });
        }

        if let Some(account) = account {
            minors.sort_unstable();
            minors.dedup();
            self.spend_seen(SeenSpend {
                txid,
                height,
                timestamp,
                spent,
                received,
                fee: tx.fee().unwrap_or(0),
                unlock_time: tx.prefix.unlock_time,
                account,
                minors,
                key_images,
            });
        }
    }

    /// Record an output found in a block, once per public key: `m_pub_keys`
    /// in `wallet2::process_new_transaction`.
    ///
    /// Two outputs can carry the same one-time public key -- a sender reusing a
    /// transaction key, by mistake or to cheat -- and then they share a key
    /// image, so only one of them can ever be spent. The larger is kept and
    /// the other ignored, as the reference does. Holding both would leave one
    /// looking spendable after the other was spent, and every transaction
    /// built from it would be refused as a double spend.
    fn add_transfer(&mut self, t: Transfer) -> Receipt {
        if let Some(&i) = self.by_public_key.get(&t.public_key) {
            let held = &mut self.transfers[i];
            if held.spent || held.amount >= t.amount {
                return Receipt::Ignored;
            }
            let burnt = held.amount;
            // The key image is the same: it depends only on the one-time key.
            *held = Transfer {
                key_image: held.key_image.or(t.key_image),
                ..t
            };
            return Receipt::Replaced { burnt };
        }
        let i = self.transfers.len();
        if let Some(k) = t.key_image {
            self.by_key_image.insert(k, i);
        }
        self.by_public_key.insert(t.public_key, i);
        self.transfers.push(t);
        Receipt::New
    }
}

/// Parse a block a source sent, and hash it.
fn parse_block(height: u64, bundle: &BlockBundle) -> Result<(Block, Hash256)> {
    let block = Block::from_blob(&bundle.block).map_err(|e| RefreshError::BadBlock {
        height,
        reason: e.to_string(),
    })?;
    let id = block.block_id().ok_or_else(|| RefreshError::BadBlock {
        height,
        reason: "the block has no id".into(),
    })?;
    Ok((block, id))
}

/// The one-time secret key for an output this wallet owns.
///
/// `x = Hs(D || i) + b`, plus the subaddress secret `m` when the output went to
/// a subaddress — the same value scanning used to derive the key image, and the
/// value a CLSAG signs with.
///
/// Returns `None` for a view-only wallet, which has no `b`.
pub fn one_time_secret_key(
    account: &AccountBase,
    transfer: &Transfer,
) -> Option<wow_crypto::types::SecretKey> {
    if account.keys.is_view_only() {
        return None;
    }
    let mut x = wow_crypto::derive_secret_key(
        &transfer.derivation,
        transfer.internal_output_index,
        &account.keys.spend_secret_key,
    );
    if !transfer.subaddress.is_main() {
        let m = wow_crypto::keys::subaddress_secret_key(
            &account.keys.view_secret_key,
            transfer.subaddress,
        );
        x = wow_crypto::types::SecretKey(wow_crypto::ops::sc_add(&x.0, &m.0));
    }
    Some(x)
}

/// A live daemon as a [`BlockSource`].
///
/// The only thing this adds over the trait is the shape change: the client
/// speaks `specs/11` and the loop speaks blocks.
///
/// `prune` is true, as `wallet2::pull_blocks` asks: a scan reads prefixes and
/// RingCT bases, and the signatures and proofs pruning leaves out are nearly
/// all of a block. A thousand early blocks are 42 MB whole and 1.8 MB pruned,
/// and a daemon that ignores the flag sends them whole, which reads just as
/// well. `no_miner_tx` is false because a wallet must see coinbase outputs —
/// mining is how most wallets on this chain get paid.
impl BlockSource for wow_daemon_client::DaemonClient {
    type Error = wow_daemon_client::DaemonError;

    fn get_blocks(
        &self,
        block_ids: &[Hash256],
        start_height: u64,
        max_blocks: u64,
    ) -> std::result::Result<Batch, Self::Error> {
        let res = wow_daemon_client::DaemonClient::get_blocks(
            self,
            block_ids,
            start_height,
            true,
            false,
            max_blocks,
        )?;
        Ok(Batch {
            blocks: res
                .blocks
                .into_iter()
                .map(|b| BlockBundle {
                    block: b.block,
                    txs: b.txs,
                    output_indices: b.output_indices,
                    pruned: b.pruned,
                })
                .collect(),
            start_height: res.start_height,
            current_height: res.current_height,
        })
    }

    fn cut_short(error: &Self::Error) -> bool {
        matches!(
            error,
            wow_daemon_client::DaemonError::Http(wow_daemon_client::HttpError::Truncated { .. })
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    /// The count of blocks until an output unlocks agrees with `unlocked_at`
    /// at every height it passes through: not spendable a block early, and
    /// spendable on the block it names.
    #[test]
    fn blocks_until_unlocked_counts_down_to_the_unlock() {
        // Received at 100, with no unlock time of its own: four blocks of age.
        assert_eq!(blocks_until_unlocked(0, 100, 101, 0), 3);
        assert_eq!(blocks_until_unlocked(0, 100, 104, 0), 0);

        // Locked until a height, as a coinbase is.
        for chain in 101..400 {
            let left = blocks_until_unlocked(388, 100, chain, 0);
            assert_eq!(left == 0, unlocked_at(388, 100, chain, 0), "at {chain}");
            if left > 0 {
                assert!(
                    !unlocked_at(388, 100, chain + left - 1, 0),
                    "early, at {chain}"
                );
                assert!(
                    unlocked_at(388, 100, chain + left, 0),
                    "on time, at {chain}"
                );
            }
        }

        // Locked until a time an hour away: 3,300 seconds past the allowed
        // delta, eleven blocks of five minutes.
        let now = 1_800_000_000;
        assert_eq!(blocks_until_unlocked(now + 3_600, 100, 1_000, now), 11);
        assert_eq!(blocks_until_unlocked(now, 100, 1_000, now), 0);
    }
    use curve25519_dalek::scalar::Scalar;
    use wow_crypto::ops::encode_point;
    use wow_crypto::types::{AccountPublicAddress, PublicKey, SecretKey};
    use wow_serialize::binary::Writer;
    use wow_types::block::{Block, BlockHeader};

    fn account(seed: u8) -> AccountBase {
        let spend = SecretKey(wow_crypto::ops::sc_reduce32(&[seed; 32]));
        AccountBase::from_spend_key(spend, 0).expect("valid")
    }

    fn state(seed: u8, start_height: u64) -> WalletState {
        let a = account(seed);
        let table = SubaddressTable::new(&a.keys.account_address, &a.keys.view_secret_key, 2, 3);
        WalletState::new(a, table, start_height, wow_types::Network::Mainnet)
    }

    /// Build a real transaction paying `to`.
    ///
    /// This goes through [`crate::transfer::construct`] rather than assembling
    /// a prefix by hand. Hand-assembly does not survive the round trip through
    /// a blob: a transaction claiming a Bulletproof+ type needs a proof that
    /// covers its outputs and a ring signature per input, and the parser checks
    /// both. Building it properly makes the fixture a transaction a node would
    /// accept, which is what a refresh is supposed to be reading.
    fn payment(to: &AccountPublicAddress, amount: u64, seed: u8) -> Transaction {
        payment_with_id(to, amount, seed, None)
    }

    /// [`payment`], carrying a payment id as an integrated address would.
    fn payment_with_id(
        to: &AccountPublicAddress,
        amount: u64,
        seed: u8,
        payment_id: Option<Hash8>,
    ) -> Transaction {
        let sender = account(seed ^ 0xa5);
        let fee = 1_000u64;
        let input = spendable_input(amount + fee + 500, seed);

        let destinations = vec![
            crate::transfer::Destination {
                address: *to,
                is_subaddress: false,
                amount,
            },
            crate::transfer::Destination {
                address: sender.keys.account_address,
                is_subaddress: false,
                amount: input.amount - amount - fee,
            },
        ];

        let mut n = (seed as u64) | 1;
        let mut rand = move || {
            n = n
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&n.to_le_bytes());
            b[8..16].copy_from_slice(&n.rotate_left(19).to_le_bytes());
            b[16..24].copy_from_slice(&n.rotate_left(37).to_le_bytes());
            Scalar::from_bytes_mod_order(b)
        };

        crate::transfer::construct(
            std::slice::from_ref(&input),
            &destinations,
            fee,
            payment_id,
            &mut rand,
        )
        .expect("construct")
        .tx
    }

    /// An owned output with a ring around it, enough to sign with.
    fn spendable_input(amount: u64, seed: u8) -> crate::transfer::SpendableOutput {
        let x = Scalar::from_bytes_mod_order([seed | 1; 32]);
        let public_key = PublicKey(encode_point(&(x * ED25519_BASEPOINT_POINT)));
        let secret_key = SecretKey(x.to_bytes());
        let mask = Scalar::from_bytes_mod_order([seed ^ 0x5a | 1; 32]);
        let key_image = wow_crypto::generate_key_image(&public_key, &secret_key).expect("an image");

        const RING: usize = 11;
        let real = 3usize;
        let mut ring = Vec::with_capacity(RING);
        let mut global_indices = Vec::with_capacity(RING);
        for i in 0..RING {
            if i == real {
                ring.push(wow_crypto::clsag::RingMember {
                    dest: public_key,
                    mask: wow_crypto::rct::commit(amount, &mask),
                });
            } else {
                let d = Scalar::from_bytes_mod_order([seed.wrapping_add(i as u8 + 3) | 1; 32]);
                let m = Scalar::from_bytes_mod_order([seed.wrapping_add(i as u8 + 90) | 1; 32]);
                ring.push(wow_crypto::clsag::RingMember {
                    dest: PublicKey(encode_point(&(d * ED25519_BASEPOINT_POINT))),
                    mask: wow_crypto::rct::commit(500 + i as u64, &m),
                });
            }
            global_indices.push(200 + (i as u64) * 11);
        }

        crate::transfer::SpendableOutput {
            public_key,
            secret_key,
            mask,
            amount,
            key_image,
            ring,
            global_indices,
            real_index: real,
        }
    }

    /// A transaction whose input carries `k_image`, so a wallet holding that
    /// output sees a spend.
    ///
    /// Built through `construct` so it parses, with the key image overridden to
    /// the one being spent. The ring signature therefore does not correspond to
    /// that image, which is fine here and worth being explicit about: **a
    /// refresh does not verify ring signatures.** Verifying every signature on
    /// the chain is the node's job, and a wallet that repeated it would sync at
    /// a fraction of the speed for no gain -- it would still be trusting the
    /// node about which blocks exist at all.
    fn spend_of(k_image: KeyImage, seed: u8) -> Transaction {
        let payer = account(seed ^ 0x3c);
        let mut input = spendable_input(10_000, seed ^ 0x7e);
        input.key_image = k_image;

        let destinations = vec![
            crate::transfer::Destination {
                address: payer.keys.account_address,
                is_subaddress: false,
                amount: 6_000,
            },
            crate::transfer::Destination {
                address: payer.keys.account_address,
                is_subaddress: false,
                amount: 3_500,
            },
        ];

        let mut n = (seed as u64) | 3;
        let mut rand = move || {
            n = n
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&n.to_le_bytes());
            b[8..16].copy_from_slice(&n.rotate_left(23).to_le_bytes());
            b[16..24].copy_from_slice(&n.rotate_left(41).to_le_bytes());
            Scalar::from_bytes_mod_order(b)
        };

        crate::transfer::construct(
            std::slice::from_ref(&input),
            &destinations,
            500,
            None,
            &mut rand,
        )
        .expect("construct")
        .tx
    }

    /// A block with a given parent and a nonce that makes its hash unique.
    fn block_with(prev: Hash256, nonce: u32, txs: &[Transaction]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut miner = Transaction::default();
        miner.prefix.version = 1;
        miner.prefix.unlock_time = 0;
        miner.prefix.vin = vec![TxIn::Gen {
            height: nonce as u64,
        }];
        miner.prefix.vout = Vec::new();
        miner.prefix.extra = Vec::new();

        let block = Block {
            header: BlockHeader {
                major_version: 16,
                minor_version: 16,
                timestamp: 1_600_000_000 + nonce as u64,
                prev_id: prev,
                nonce,
                ..Default::default()
            },
            miner_tx: miner,
            tx_hashes: txs
                .iter()
                .map(|t| wow_types::hashes::transaction_hash(t).unwrap_or(wow_crypto::NULL_HASH))
                .collect(),
        };

        let mut w = Writer::with_capacity(512);
        block.write(&mut w);
        let blob = w.into_vec();

        let tx_blobs = txs
            .iter()
            .map(|t| {
                let mut w = Writer::with_capacity(512);
                t.write(&mut w);
                w.into_vec()
            })
            .collect();
        (blob, tx_blobs)
    }

    /// A source that serves a fixed chain, answering from the newest hash in the
    /// history it has, that block included, as the C++ daemon does.
    /// `(block blob, transaction blobs, global output indices)`.
    type StoredBlock = (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u64>>);

    struct Chain {
        /// One per height, from height 0.
        blocks: Vec<StoredBlock>,
        hashes: Vec<Hash256>,
    }

    impl Chain {
        fn new() -> Chain {
            Chain {
                blocks: Vec::new(),
                hashes: Vec::new(),
            }
        }

        fn push(&mut self, txs: &[Transaction], indices: Vec<Vec<u64>>) {
            let prev = self.hashes.last().copied().unwrap_or([0u8; 32]);
            let nonce = self.blocks.len() as u32 + 1;
            let (blob, tx_blobs) = block_with(prev, nonce, txs);
            let hash = Block::from_blob(&blob)
                .expect("our own block parses")
                .block_id()
                .expect("an id");
            self.blocks.push((blob, tx_blobs, indices));
            self.hashes.push(hash);
        }

        /// Drop everything from `height` up, then extend with fresh blocks —
        /// a reorg.
        fn reorg_from(&mut self, height: usize, extra: usize) {
            self.blocks.truncate(height);
            self.hashes.truncate(height);
            for i in 0..extra {
                let prev = self.hashes.last().copied().unwrap_or([0u8; 32]);
                // A different nonce base, so the new blocks differ from the old.
                let nonce = 10_000 + (height + i) as u32;
                let (blob, tx_blobs) = block_with(prev, nonce, &[]);
                let hash = Block::from_blob(&blob)
                    .expect("parses")
                    .block_id()
                    .expect("an id");
                self.blocks.push((blob, tx_blobs, Vec::new()));
                self.hashes.push(hash);
            }
        }
    }

    #[derive(Debug)]
    struct Never;
    impl std::fmt::Display for Never {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unreachable")
        }
    }

    impl BlockSource for Chain {
        type Error = Never;

        fn get_blocks(
            &self,
            block_ids: &[Hash256],
            start_height: u64,
            max_blocks: u64,
        ) -> std::result::Result<Batch, Never> {
            // `on_get_blocks`: a history whose newest hash is the top block has
            // nothing new.
            if !block_ids.is_empty() && block_ids.first() == self.hashes.last() {
                return Ok(Batch {
                    blocks: Vec::new(),
                    start_height: 0,
                    current_height: self.blocks.len() as u64,
                });
            }
            // `find_blockchain_supplement`: a start height above zero is taken
            // as given. Otherwise the answer starts **at** the newest hash in
            // the history this chain has, a block the wallet already holds.
            //
            // Unlike the reference, a history this chain has none of is
            // answered from zero rather than refused. These chains start at a
            // block zero of their own, not at the network's genesis that a
            // wallet's history ends with.
            let from = if start_height > 0 {
                start_height as usize
            } else {
                block_ids
                    .iter()
                    .find_map(|h| self.hashes.iter().position(|x| x == h))
                    .unwrap_or(0)
            };
            let most = max_blocks.min(MAX_BLOCKS_PER_CALL) as usize;
            let end = self.blocks.len().min(from + most);
            let blocks = self.blocks[from.min(end)..end]
                .iter()
                .map(|(b, t, o)| BlockBundle {
                    block: b.clone(),
                    txs: t.clone(),
                    output_indices: o.clone(),
                    pruned: false,
                })
                .collect();
            Ok(Batch {
                blocks,
                start_height: from as u64,
                current_height: self.blocks.len() as u64,
            })
        }
    }

    /// The basic loop: scan an empty chain and end up at its height.
    #[test]
    fn it_scans_to_the_tip() {
        let mut chain = Chain::new();
        for _ in 0..5 {
            chain.push(&[], Vec::new());
        }

        let mut w = state(7, 0);
        let s = w.refresh(&chain, 10).expect("refresh");
        assert!(s.caught_up);
        assert_eq!(w.scan_height(), 5);
        assert_eq!(w.hashes.len(), 5);
        assert_eq!(w.hashes, chain.hashes);
        assert_eq!(w.balance(), 0);
    }

    /// A payment in a block is found, with its global output index.
    #[test]
    fn it_finds_a_payment() {
        let me = state(7, 0);
        let tx = payment(&me.account.keys.account_address, 1_234_000_000, 3);

        let mut chain = Chain::new();
        chain.push(&[], Vec::new());
        // Coinbase indices first, then the transaction's.
        chain.push(&[tx], vec![vec![], vec![4_242]]);
        chain.push(&[], Vec::new());

        let mut w = me;
        let s = w.refresh(&chain, 10).expect("refresh");
        assert_eq!(s.received, 1);
        assert_eq!(w.transfers.len(), 1);
        assert_eq!(w.transfers[0].amount, 1_234_000_000);
        assert_eq!(w.transfers[0].block_height, 1);
        assert_eq!(w.transfers[0].global_output_index, 4_242);
        assert!(!w.transfers[0].spent);
        assert_eq!(w.balance(), 1_234_000_000);
        assert_eq!(s.current_height, 3, "the daemon's height");
        assert!(
            matches!(
                s.events.as_slice(),
                [RefreshEvent::Received {
                    height: 1,
                    amount: 1_234_000_000,
                    burnt: 0,
                    ..
                }]
            ),
            "{:?}",
            s.events
        );
    }

    /// An output the wallet owns, then spent, is marked spent and leaves the
    /// balance.
    #[test]
    fn it_notices_its_own_output_being_spent() {
        let me = state(7, 0);
        let tx = payment(&me.account.keys.account_address, 500, 5);

        let mut w = me;
        let mut chain = Chain::new();
        chain.push(&[tx], vec![vec![], vec![1]]);
        w.refresh(&chain, 10).expect("refresh");
        assert_eq!(w.balance(), 500);

        let image = w.transfers[0].key_image.expect("a full wallet has one");
        chain.push(&[spend_of(image, 21)], vec![vec![], vec![]]);

        let s = w.refresh(&chain, 10).expect("refresh");
        assert_eq!(s.spent, 1);
        assert!(w.transfers[0].spent);
        assert_eq!(w.transfers[0].spent_height, 1);
        assert_eq!(w.balance(), 0);
        assert!(
            matches!(
                s.events.as_slice(),
                [RefreshEvent::Spent {
                    height: 1,
                    amount: 500,
                    ..
                }]
            ),
            "{:?}",
            s.events
        );
    }

    /// A reorg detaches the wallet's chain and rescans. The payment in the
    /// orphaned block goes away.
    #[test]
    fn a_reorg_detaches_and_rescans() {
        let me = state(7, 0);
        let tx = payment(&me.account.keys.account_address, 900, 9);

        let mut w = me;
        let mut chain = Chain::new();
        chain.push(&[], Vec::new());
        chain.push(&[], Vec::new());
        chain.push(&[tx], vec![vec![], vec![77]]);
        chain.push(&[], Vec::new());

        w.refresh(&chain, 10).expect("refresh");
        assert_eq!(w.balance(), 900);
        assert_eq!(w.scan_height(), 4);

        // Rewind to height 2 and build a different tip, without the payment.
        chain.reorg_from(2, 3);

        let s = w.refresh(&chain, 10).expect("refresh");
        assert_eq!(s.reorg_to, Some(2), "detached to the split");
        assert_eq!(w.balance(), 0, "the orphaned payment is gone");
        assert!(w.transfers.is_empty());
        assert_eq!(w.scan_height(), 5);
        assert_eq!(w.hashes, chain.hashes);
    }

    /// A spend that only existed on the orphaned chain is un-spent, not lost.
    #[test]
    fn a_reorg_unspends() {
        let me = state(7, 0);
        let tx = payment(&me.account.keys.account_address, 4_000, 11);

        let mut w = me;
        let mut chain = Chain::new();
        chain.push(&[tx], vec![vec![], vec![3]]);
        w.refresh(&chain, 10).expect("refresh");
        let image = w.transfers[0].key_image.expect("an image");

        chain.push(&[spend_of(image, 21)], vec![vec![], vec![]]);
        w.refresh(&chain, 10).expect("refresh");
        assert!(w.transfers[0].spent);
        assert_eq!(w.balance(), 0);

        // The block carrying the spend is orphaned.
        chain.reorg_from(1, 2);
        w.refresh(&chain, 10).expect("refresh");

        assert!(!w.transfers[0].spent, "the spend was undone");
        assert_eq!(w.transfers[0].spent_height, 0);
        assert_eq!(w.balance(), 4_000, "the money is back");
    }

    /// `max_reorg_depth` is honoured: a deeper reorg is refused rather than
    /// silently applied.
    #[test]
    fn a_reorg_deeper_than_the_limit_is_refused() {
        let mut chain = Chain::new();
        for _ in 0..10 {
            chain.push(&[], Vec::new());
        }
        let mut w = state(7, 0);
        w.max_reorg_depth = 3;
        w.refresh(&chain, 10).expect("refresh");
        assert_eq!(w.scan_height(), 10);

        chain.reorg_from(2, 5);
        let e = w.refresh(&chain, 10).expect_err("too deep");
        assert!(
            matches!(e, RefreshError::ReorgTooDeep { depth: 8, limit: 3 }),
            "{e}"
        );
        // And nothing was detached.
        assert_eq!(w.scan_height(), 10);
    }

    /// The history is **never empty**, even before the first block is scanned.
    ///
    /// `Blockchain::find_blockchain_supplement` refuses an empty `block_ids`
    /// when `start_height` is zero, and `/getblocks.bin` answers
    /// `status: "Failed"`. A brand-new wallet pointed at a real node could not
    /// refresh at all until it sent genesis, which is what
    /// `wallet2::get_short_chain_history` has always done:
    ///
    /// ```cpp
    /// if(!sz) { ids.push_back(m_blockchain.genesis()); return; }
    /// ```
    #[test]
    fn an_unscanned_wallet_still_sends_genesis() {
        let w = state(7, 0);
        let history = w.short_chain_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0], w.genesis);
        assert_ne!(history[0], [0u8; 32], "genesis is a real hash, not a null");
        assert_eq!(
            history[0],
            wow_consensus::genesis::genesis_id(wow_types::Network::Mainnet)
        );
    }

    /// The short chain history is newest-first, dense near the tip, sparse
    /// below, and ends at genesis.
    #[test]
    fn the_short_chain_history_has_the_right_shape() {
        let mut w = state(7, 0);
        assert_eq!(
            w.short_chain_history(),
            vec![w.genesis],
            "a wallet that has scanned nothing still sends genesis"
        );

        w.hashes = (0u32..100)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..4].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();
        // Height zero is genesis.
        w.hashes[0] = w.genesis;

        let history = w.short_chain_history();
        // Newest first.
        assert_eq!(history[0], w.hashes[99]);
        assert_eq!(history[1], w.hashes[98]);
        // The first ten are consecutive.
        for (i, h) in history.iter().take(10).enumerate() {
            assert_eq!(*h, w.hashes[99 - i], "entry {i}");
        }
        // Then the gaps widen.
        assert!(history.len() < 25, "gaps keep it short: {}", history.len());
        // Genesis is last.
        assert_eq!(*history.last().expect("non-empty"), w.hashes[0]);
    }

    /// A block whose parent is not the wallet's tip is refused. A daemon
    /// serving a different chain cannot splice it onto this one.
    #[test]
    fn a_block_with_the_wrong_parent_is_refused() {
        let mut chain = Chain::new();
        chain.push(&[], Vec::new());
        chain.push(&[], Vec::new());

        let mut w = state(7, 0);
        w.refresh(&chain, 10).expect("refresh");

        // A block claiming a parent nobody has seen, offered at our tip.
        let (blob, txs) = block_with([0xab; 32], 9_999, &[]);
        struct Liar(Vec<u8>, Vec<Vec<u8>>, u64);
        impl BlockSource for Liar {
            type Error = Never;
            fn get_blocks(
                &self,
                _ids: &[Hash256],
                _start: u64,
                _max: u64,
            ) -> std::result::Result<Batch, Never> {
                Ok(Batch {
                    blocks: vec![BlockBundle {
                        block: self.0.clone(),
                        txs: self.1.clone(),
                        output_indices: Vec::new(),
                        pruned: false,
                    }],
                    start_height: self.2,
                    current_height: self.2 + 1,
                })
            }
        }

        let e = w
            .refresh_once(&Liar(blob, txs, 2))
            .expect_err("a spliced chain is refused");
        assert!(
            matches!(e, RefreshError::BrokenChain { height: 2, .. }),
            "{e}"
        );
    }

    /// A daemon that answers from beyond the wallet's tip would leave a hole.
    #[test]
    fn a_gap_in_the_chain_is_refused() {
        struct Skipper;
        impl BlockSource for Skipper {
            type Error = Never;
            fn get_blocks(
                &self,
                _ids: &[Hash256],
                _start: u64,
                _max: u64,
            ) -> std::result::Result<Batch, Never> {
                let (blob, txs) = block_with([0u8; 32], 1, &[]);
                Ok(Batch {
                    blocks: vec![BlockBundle {
                        block: blob,
                        txs,
                        output_indices: Vec::new(),
                        pruned: false,
                    }],
                    start_height: 500,
                    current_height: 501,
                })
            }
        }

        let mut w = state(7, 0);
        // The tip is 1, not 0: a wallet starting at zero holds the genesis
        // hash from the outset, so it has one block before it scans anything.
        let e = w.refresh_once(&Skipper).expect_err("a gap is refused");
        assert!(
            matches!(e, RefreshError::GapInChain { got: 500, tip: 1 }),
            "{e}"
        );
    }

    /// Unlock rules: an output needs four confirmations, and a coinbase with an
    /// unlock time waits for it.
    #[test]
    fn the_unlock_rules() {
        let t = Transfer {
            block_height: 100,
            txid: [0u8; 32],
            derivation: wow_crypto::types::KeyDerivation::ZERO,
            internal_output_index: 0,
            global_output_index: 0,
            public_key: PublicKey::ZERO,
            key_image: None,
            mask: [0u8; 32],
            amount: 1,
            subaddress: SubaddressIndex::MAIN,
            spent: false,
            spent_height: 0,
            unlock_time: 0,
            is_coinbase: false,
            timestamp: 0,
            payment_id: None,
        };

        let now = 1_700_000_000;
        assert!(!t.unlocked(103, now), "three confirmations is not enough");
        assert!(t.unlocked(104, now), "four is");

        // A coinbase at HF >= 18 unlocks 288 blocks later (`specs/12` §4.2).
        let mined = Transfer {
            unlock_time: 100 + 288,
            is_coinbase: true,
            ..t
        };
        assert!(!mined.unlocked(300, now));
        assert!(mined.unlocked(400, now));
    }

    /// A view-only wallet sees the money and records no key images, so it
    /// cannot notice its own outputs being spent.
    #[test]
    fn a_view_only_wallet_records_no_key_images() {
        let full = state(7, 0);
        let tx = payment(&full.account.keys.account_address, 777, 13);

        let mut a = full.account.clone();
        a.forget_spend_key();
        let table = SubaddressTable::new(&a.keys.account_address, &a.keys.view_secret_key, 2, 3);
        let mut w = WalletState::new(a, table, 0, wow_types::Network::Mainnet);

        let mut chain = Chain::new();
        chain.push(&[tx], vec![vec![], vec![8]]);
        w.refresh(&chain, 10).expect("refresh");

        assert_eq!(w.balance(), 777, "it still sees the money");
        assert_eq!(w.transfers[0].key_image, None);
        assert!(w.by_key_image.is_empty());
    }

    /// A payment's id is read as its payee reads it and kept with the output.
    /// A transaction carrying only the dummy has none.
    #[test]
    fn a_payment_id_is_kept_with_its_output() {
        let mut w = state(7, 0);
        let to = w.account.keys.account_address;
        let id = [0xf9, 0x33, 0x77, 0x88, 0xdd, 0x75, 0x25, 0x55];

        let mut chain = Chain::new();
        chain.push(
            &[
                payment_with_id(&to, 5_000, 21, Some(id)),
                payment(&to, 6_000, 22),
            ],
            vec![vec![], vec![8, 9], vec![10, 11]],
        );
        w.refresh(&chain, 10).expect("refresh");

        let mut got: Vec<(u64, Option<Hash8>)> = w
            .transfers
            .iter()
            .map(|t| (t.amount, t.payment_id))
            .collect();
        got.sort_unstable();
        assert_eq!(got, vec![(5_000, Some(id)), (6_000, None)]);
    }

    /// Two outputs with the same one-time key share a key image, so only one
    /// can ever be spent. The larger is held and the other ignored, as
    /// `wallet2` does; holding both would leave one looking spendable after
    /// the other was spent.
    #[test]
    fn a_reused_output_key_is_held_once() {
        let mut w = state(7, 0);
        let first = Transfer {
            block_height: 10,
            txid: [1u8; 32],
            derivation: wow_crypto::types::KeyDerivation::ZERO,
            internal_output_index: 0,
            global_output_index: 0,
            public_key: PublicKey([4u8; 32]),
            key_image: Some(KeyImage([3u8; 32])),
            mask: [0u8; 32],
            amount: 500,
            subaddress: SubaddressIndex::MAIN,
            spent: false,
            spent_height: 0,
            unlock_time: 0,
            is_coinbase: false,
            timestamp: 0,
            payment_id: None,
        };
        assert_eq!(w.add_transfer(first.clone()), Receipt::New);

        let smaller = Transfer {
            txid: [2u8; 32],
            amount: 400,
            ..first.clone()
        };
        assert_eq!(w.add_transfer(smaller), Receipt::Ignored);

        let larger = Transfer {
            txid: [3u8; 32],
            block_height: 12,
            amount: 900,
            ..first.clone()
        };
        assert_eq!(w.add_transfer(larger), Receipt::Replaced { burnt: 500 });
        assert_eq!(w.transfers.len(), 1);
        assert_eq!(w.transfers[0].txid, [3u8; 32]);
        assert_eq!(w.balance(), 900);
        assert_eq!(w.by_key_image.len(), 1);

        // Once spent, even a larger one is ignored: its key image is used up.
        w.transfers[0].spent = true;
        let later = Transfer {
            amount: 5_000,
            ..first
        };
        assert_eq!(w.add_transfer(later), Receipt::Ignored);
        assert_eq!(w.balance(), 0);
    }

    /// A refresh with nothing new is a no-op that reports caught up.
    #[test]
    fn refreshing_at_the_tip_does_nothing() {
        let mut chain = Chain::new();
        chain.push(&[], Vec::new());

        let mut w = state(7, 0);
        w.refresh(&chain, 10).expect("refresh");
        let before = w.scan_height();

        let s = w.refresh_once(&chain).expect("refresh");
        assert!(s.caught_up);
        assert_eq!(s.blocks_scanned, 0);
        assert_eq!(w.scan_height(), before);
    }

    /// A spend of ours that was not sent from here is recorded from what its
    /// block shows: what left, the fee, the time. Not where it went. Orphaned,
    /// it is forgotten, since nothing but that block said it happened.
    #[test]
    fn a_spend_found_in_a_block_is_recorded() {
        use crate::history::SentState;

        let me = state(7, 0);
        let tx = payment(&me.account.keys.account_address, 4_000, 11);

        let mut w = me;
        let mut chain = Chain::new();
        chain.push(&[tx], vec![vec![], vec![3]]);
        w.refresh(&chain, 10).expect("refresh");
        let image = w.transfers[0].key_image.expect("an image");

        let spend = spend_of(image, 21);
        let txid = wow_types::hashes::transaction_hash(&spend).expect("an id");
        chain.push(&[spend], vec![vec![], vec![]]);
        w.refresh(&chain, 10).expect("refresh");

        assert_eq!(w.sent.len(), 1);
        let s = &w.sent[0];
        assert_eq!(s.txid, txid);
        assert_eq!(s.state, SentState::Confirmed(1));
        assert_eq!(s.amount_in, 4_000);
        assert_eq!(s.fee(), 500, "the fee the transaction carries");
        assert!(s.destinations.is_empty(), "a block does not say where");
        assert_eq!(s.timestamp, 1_600_000_002, "its block's timestamp");
        assert_eq!(w.transfers[0].timestamp, 1_600_000_001);

        chain.reorg_from(1, 2);
        w.refresh(&chain, 10).expect("refresh");
        assert!(w.sent.is_empty());
    }

    /// A send spends its inputs when it is relayed, is confirmed by the block
    /// that carries it, and goes back to pending, still holding its inputs, if
    /// that block is orphaned.
    #[test]
    fn a_send_waits_for_its_block_and_again_after_a_reorg() {
        use crate::history::SentState;

        let me = state(7, 0);
        let tx = payment(&me.account.keys.account_address, 4_000, 11);

        let mut w = me;
        let mut chain = Chain::new();
        chain.push(&[tx], vec![vec![], vec![3]]);
        w.refresh(&chain, 10).expect("refresh");
        let image = w.transfers[0].key_image.expect("an image");

        let spend = spend_of(image, 21);
        let txid = wow_types::hashes::transaction_hash(&spend).expect("an id");
        let plan = crate::spend::SpendPlan {
            inputs: vec![0],
            amounts: vec![3_000],
            change: 500,
            fee: 500,
            estimated_weight: 0,
            sweep: false,
            left_behind: 0,
        };
        w.record_sent(txid, &plan, &["Wo1payee"], None, 1_700_000_000);
        assert!(w.transfers[0].spent, "spent from the moment it is relayed");
        assert_eq!(w.balance(), 500, "only the change on its way back");

        chain.push(&[spend], vec![vec![], vec![]]);
        w.refresh(&chain, 10).expect("refresh");
        assert_eq!(w.sent.len(), 1, "matched up, not recorded twice");
        assert_eq!(w.sent[0].state, SentState::Confirmed(1));
        assert_eq!(w.sent[0].destinations[0].address, "Wo1payee");
        assert_eq!(w.transfers[0].spent_height, 1);

        chain.reorg_from(1, 2);
        w.refresh(&chain, 10).expect("refresh");
        assert_eq!(w.sent[0].state, SentState::Pending);
        assert!(w.transfers[0].spent, "its input stays spent while it waits");
        assert_eq!(w.transfers[0].spent_height, 0);

        // A rescan keeps the record, and the input it spends is found spent.
        w.rescan_from(0);
        w.refresh(&chain, 10).expect("refresh");
        assert_eq!(w.sent[0].destinations[0].address, "Wo1payee");
        assert!(w.transfers[0].spent);
    }

    /// A wallet on `chain`, whose block zero stands in for the network's
    /// genesis. A wallet from [`state`] holds the real genesis, which no
    /// fixture chain starts with, so its first refresh replaces it.
    fn state_on(seed: u8, chain: &Chain) -> WalletState {
        let mut w = state(seed, 0);
        w.genesis = chain.hashes[0];
        w.hashes = vec![chain.hashes[0]];
        w
    }

    /// A reply starts at the newest block the daemon and the wallet share,
    /// which the wallet already holds (`find_blockchain_supplement`:
    /// "INCLUDING last known id"). That block is compared and passed over.
    ///
    /// Reading it as a split made every batch from a C++ node a reorg: the
    /// wallet detached a block it had, scanned it again, and said so.
    #[test]
    fn the_block_a_daemon_repeats_is_not_a_reorg() {
        let mut chain = Chain::new();
        for _ in 0..4 {
            chain.push(&[], Vec::new());
        }
        let mut w = state_on(7, &chain);
        let tx = payment(&w.account.keys.account_address, 2_500, 17);
        chain.push(&[tx], vec![vec![], vec![6]]);

        let s = w.refresh(&chain, 10).expect("refresh");
        assert_eq!(s.reorg_to, None);
        assert_eq!(s.blocks_scanned, 4, "block zero was held already");
        assert_eq!(s.received, 1);
        assert_eq!(w.hashes, chain.hashes);

        chain.push(&[], Vec::new());
        let s = w.refresh_once(&chain).expect("refresh");
        assert_eq!(s.reorg_to, None, "the tip sent again is not a split");
        assert_eq!(s.blocks_scanned, 1, "only the new block is scanned");
        assert!(
            s.events.is_empty(),
            "nothing is found twice: {:?}",
            s.events
        );
        assert_eq!(w.transfers.len(), 1);
        assert_eq!(w.hashes, chain.hashes);
    }

    /// A wallet restored above zero names its height only while it holds no
    /// hashes. The reference answers a start height above zero from that
    /// height whatever the history says, so a wallet that went on naming it
    /// was sent the same blocks on every call.
    #[test]
    fn a_restored_wallet_names_its_height_only_until_it_has_a_history() {
        use std::cell::RefCell;

        struct Asked<'a>(&'a Chain, RefCell<Vec<u64>>);
        impl BlockSource for Asked<'_> {
            type Error = Never;
            fn get_blocks(
                &self,
                ids: &[Hash256],
                start: u64,
                max: u64,
            ) -> std::result::Result<Batch, Never> {
                self.1.borrow_mut().push(start);
                self.0.get_blocks(ids, start, max)
            }
        }

        let mut chain = Chain::new();
        for _ in 0..8 {
            chain.push(&[], Vec::new());
        }
        let mut w = state(7, 5);
        {
            let asked = Asked(&chain, RefCell::new(Vec::new()));
            let s = w.refresh(&asked, 10).expect("refresh");
            assert!(s.caught_up);
            assert_eq!(
                asked.1.into_inner(),
                vec![5],
                "no history yet, so the height"
            );
        }
        assert_eq!(w.hashes, chain.hashes[5..]);

        chain.push(&[], Vec::new());
        chain.push(&[], Vec::new());
        let asked = Asked(&chain, RefCell::new(Vec::new()));
        let s = w.refresh(&asked, 10).expect("refresh");
        assert!(s.caught_up);
        assert_eq!(s.reorg_to, None);
        assert_eq!(s.blocks_scanned, 2);
        assert_eq!(asked.1.into_inner(), vec![0], "a history now, so no height");
        assert_eq!(w.hashes, chain.hashes[5..]);
    }

    /// The history ends at the network's genesis even for a wallet that starts
    /// above zero, after the first block it holds: the reference refuses a
    /// history that does not end at its genesis ("genesis block mismatch").
    #[test]
    fn a_history_always_ends_at_genesis() {
        let mut w = state(7, 500);
        w.hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        assert_eq!(
            w.short_chain_history(),
            vec![[3u8; 32], [2u8; 32], [1u8; 32], w.genesis]
        );
    }

    /// A split below the first block a restored wallet holds leaves the daemon
    /// with none of its blocks, so it answers from further down than the
    /// wallet starts. The wallet drops what it holds and asks from its own
    /// start again, rather than scanning blocks below it.
    #[test]
    fn a_split_below_where_a_wallet_starts_rescans_from_its_start() {
        let mut chain = Chain::new();
        for _ in 0..8 {
            chain.push(&[], Vec::new());
        }
        let mut w = state(7, 5);
        w.refresh(&chain, 10).expect("refresh");
        assert_eq!(w.hashes, chain.hashes[5..]);

        chain.reorg_from(3, 6);
        let s = w.refresh(&chain, 10).expect("refresh");
        assert_eq!(s.reorg_to, Some(5), "back to where the wallet starts");
        assert!(s.caught_up);
        assert_eq!(w.hashes, chain.hashes[5..]);
    }

    /// A reply of only blocks the wallet holds, from a daemon whose chain is
    /// taller, would have the loop ask again forever. It is refused instead.
    #[test]
    fn a_reply_with_nothing_new_from_a_taller_chain_is_refused() {
        let mut chain = Chain::new();
        for _ in 0..4 {
            chain.push(&[], Vec::new());
        }
        let mut w = state_on(7, &chain);
        w.refresh(&chain, 10).expect("refresh");

        struct Stale<'a>(&'a Chain);
        impl BlockSource for Stale<'_> {
            type Error = Never;
            fn get_blocks(
                &self,
                _ids: &[Hash256],
                _start: u64,
                _max: u64,
            ) -> std::result::Result<Batch, Never> {
                let mut batch = self
                    .0
                    .get_blocks(&[self.0.hashes[0]], 0, MAX_BLOCKS_PER_CALL)?;
                batch.current_height += 10;
                Ok(batch)
            }
        }

        let e = w
            .refresh_once(&Stale(&chain))
            .expect_err("no progress is refused");
        assert!(
            matches!(
                e,
                RefreshError::NoProgress {
                    from: 0,
                    current: 14
                }
            ),
            "{e}"
        );
        assert_eq!(w.hashes, chain.hashes, "and nothing was dropped");
    }

    /// A pruned transaction keeps its prefix and RingCT base, which is all a
    /// scan reads, and takes its id from its block.
    #[test]
    fn a_pruned_block_is_scanned_like_a_whole_one() {
        struct Pruned<'a>(&'a Chain);
        impl BlockSource for Pruned<'_> {
            type Error = Never;
            fn get_blocks(
                &self,
                ids: &[Hash256],
                start: u64,
                max: u64,
            ) -> std::result::Result<Batch, Never> {
                let mut batch = self.0.get_blocks(ids, start, max)?;
                for bundle in &mut batch.blocks {
                    for blob in &mut bundle.txs {
                        let whole = Transaction::from_blob(blob).expect("a whole transaction");
                        blob.truncate(whole.unprunable_size);
                    }
                    bundle.pruned = true;
                }
                Ok(batch)
            }
        }

        let mut chain = Chain::new();
        chain.push(&[], Vec::new());
        let mut w = state_on(7, &chain);
        let tx = payment(&w.account.keys.account_address, 3_300, 23);
        let txid = wow_types::hashes::transaction_hash(&tx).expect("an id");
        chain.push(&[tx], vec![vec![], vec![9, 10]]);

        let batch = Pruned(&chain)
            .get_blocks(&[chain.hashes[0]], 0, MAX_BLOCKS_PER_CALL)
            .expect("blocks");
        assert!(
            Transaction::from_blob(&batch.blocks[1].txs[0]).is_err(),
            "pruned, it is not a whole transaction any more"
        );

        let s = w.refresh(&Pruned(&chain), 10).expect("refresh");
        assert_eq!(s.received, 1);
        assert_eq!(w.transfers[0].amount, 3_300);
        assert_eq!(w.transfers[0].txid, txid, "the id its block gives");
        assert_eq!(w.hashes, chain.hashes);
    }

    /// A reply cut short is asked for again with half as many blocks, and the
    /// batch grows back after replies that arrive whole. One that cannot get
    /// even two blocks through gives up with the reason.
    #[test]
    fn a_reply_cut_short_is_asked_for_again_with_fewer_blocks() {
        use std::cell::RefCell;

        /// Cuts off any reply of more than `.1` blocks.
        struct Narrow<'a>(&'a Chain, u64, RefCell<Vec<u64>>);
        impl BlockSource for Narrow<'_> {
            type Error = &'static str;
            fn get_blocks(
                &self,
                ids: &[Hash256],
                start: u64,
                max: u64,
            ) -> std::result::Result<Batch, &'static str> {
                self.2.borrow_mut().push(max);
                if max > self.1 {
                    return Err("the connection closed early");
                }
                self.0
                    .get_blocks(ids, start, max)
                    .map_err(|_| "unreachable")
            }

            fn cut_short(_error: &&'static str) -> bool {
                true
            }
        }

        let mut chain = Chain::new();
        for _ in 0..8 {
            chain.push(&[], Vec::new());
        }

        let mut w = state_on(7, &chain);
        let narrow = Narrow(&chain, 3, RefCell::new(Vec::new()));
        let s = w.refresh(&narrow, 20).expect("refresh");
        assert!(s.caught_up);
        assert_eq!(w.hashes, chain.hashes);
        let asked = narrow.2.into_inner();
        assert_eq!(
            asked[..11],
            [1000, 500, 250, 125, 62, 31, 15, 7, 3, 6, 3],
            "halved until one got through, then tried double: {asked:?}"
        );

        let mut w = state_on(7, &chain);
        let e = w
            .refresh_once(&Narrow(&chain, 1, RefCell::new(Vec::new())))
            .expect_err("nothing gets through");
        assert!(
            matches!(&e, RefreshError::Source(m) if m.contains("closed early")),
            "{e}"
        );
    }

    /// A rescan from zero holds genesis again, as a new wallet does, so the
    /// first reply is compared with it whether it starts at genesis or after.
    #[test]
    fn a_rescan_from_zero_holds_genesis() {
        let mut w = state(7, 0);
        w.hashes.push([1u8; 32]);
        w.rescan_from(0);
        assert_eq!(w.hashes, vec![w.genesis]);
        assert_eq!(w.scan_height(), 1);

        w.rescan_from(40);
        assert!(w.hashes.is_empty());
        assert_eq!(w.scan_height(), 40);
    }
}
