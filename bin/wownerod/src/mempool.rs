//! The transaction pool (`specs/09` §2.2).
//!
//! # In memory, saved on the way down
//!
//! `specs/09` §2.2 describes an in-memory index backed by two persisted tables
//! so the pool survives a restart. This keeps the index in memory and writes
//! the tables when the node stops ([`TxPool::save`]), reading them back when it
//! starts ([`TxPool::load`]). A crash therefore loses the pool, which is the
//! safe way round: senders re-broadcast a dropped transaction, where a pool
//! trusted blindly after a restart would keep serving transactions the chain
//! has since moved past -- which is why a load re-checks each one against the
//! chain rather than believing the tables.
//!
//! # Admission is the interesting part
//!
//! `specs/09` §2.2 gives seven checks in order, and `specs/06` §6.3 is explicit
//! that five of them are **relay policy, not consensus**: they apply to a
//! transaction arriving from a wallet or a peer, and never to one already
//! inside a block. Two of those five are Wownero-specific and are the ones a
//! wallet author trips over:
//!
//! * `tx.extra` above 1,060 bytes is not relayed, and
//! * **any** non-zero unlock time is not relayed, though such a transaction is
//!   perfectly valid inside a block.
//!
//! The last check is not policy. `check_tx_inputs` verifies every ring
//! signature and the range proof, and a node that skipped it would relay
//! forgeries.
//!
//! # What the pool keeps to itself
//!
//! Every entry carries the C++'s `relay_method`: how the transaction arrived
//! and how far it has gone since, which only ever moves up -- kept from relay,
//! submitted here, in a Dandelion++ stem, fluffed, mined. Only the last two are
//! the network's already (`relay_category::broadcasted`). A transaction still
//! in its stem, or submitted here and not yet out, is exactly what Dandelion++
//! exists to hide, so everything an outsider can ask about the pool -- the
//! restricted RPC, the ZMQ RPC, a peer's complement request, a block template
//! -- sees only [`PoolEntry::is_public`] ones.

use std::collections::HashMap;

use wow_crypto::types::{Hash256, KeyImage};
use wow_storage::db::{BlockchainDb, OutputData};
use wow_storage::lmdb::LmdbDb;
pub use wow_storage::records::RelayMethod;
use wow_storage::records::TxPoolMeta;
use wow_types::tx::{Transaction, TxIn};

/// `CRYPTONOTE_MAX_TX_SIZE`.
const MAX_TX_SIZE: u64 = 1_000_000;
/// `MAX_TX_EXTRA_SIZE`.
const MAX_TX_EXTRA_SIZE: usize = 1_060;
/// `DEFAULT_TXPOOL_MAX_WEIGHT`.
const MAX_POOL_WEIGHT: u64 = 648_000_000;
/// `CRYPTONOTE_MEMPOOL_TX_LIVETIME`, three days.
const TX_LIVETIME: u64 = 3 * 86_400;
/// `CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME`, a week: a transaction that
/// came back out of a replaced block gets longer to be mined again.
const TX_FROM_ALT_BLOCK_LIVETIME: u64 = 7 * 86_400;
/// `MIN_RELAY_TIME`: a transaction sent to peers is not sent again sooner.
pub const MIN_RELAY_SECS: u64 = 5 * 60;
/// `MAX_RELAY_TIME`: nor later than this after the last time.
pub const MAX_RELAY_SECS: u64 = 4 * 3_600;
/// `max_relayable_check`: how often the pool is walked for what is due.
pub const RELAY_CHECK_SECS: u64 = 2 * 60;

/// Why a transaction was not admitted.
///
/// The variants line up with the booleans `specs/11` §3.1 requires in a
/// `send_raw_transaction` response, so a wallet learns *which* rule it broke
/// rather than only that something was wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    TooBig {
        weight: u64,
    },
    FeeTooLow {
        got: u64,
        needed: u64,
    },
    TxExtraTooBig {
        len: usize,
    },
    NonZeroUnlockTime {
        unlock_time: u64,
    },
    /// A key image a block or another pooled transaction has spent.
    ///
    /// Which one is deliberately not said. Naming the pooled transaction told
    /// anyone with a key image to try which transaction this node held for it
    /// -- including one still in its Dandelion++ stem, which is the one thing
    /// the stem is there to keep quiet. The C++'s reason is "double spend" and
    /// nothing more.
    DoubleSpend,
    /// Already held publicly or kept from relay, or already on the chain
    /// (`core::add_new_tx`'s early return). Not a failure to the C++: it
    /// answers OK, and relays nothing.
    AlreadyInPool,
    InvalidInput(String),
    InvalidOutput(String),
    Overspend,
    TooFewOutputs {
        count: usize,
    },
    NotParseable(String),
    /// A RingCT shape this node has no verifier for.
    ///
    /// Its own variant, not an [`Rejection::InvalidInput`], because the two
    /// mean opposite things about whoever sent it: an invalid input is the
    /// sender's fault, and this is **ours**. A block carrying one is refused
    /// either way, but the peer that sent it is not banned for this node's
    /// gap -- the same distinction `PowError::CryptoNightNotImplemented`
    /// makes for proofs of work, and the one that stops a missing rule
    /// costing this node every peer it has.
    UnsupportedRctType {
        ty: wow_types::rct::RctType,
    },
}

impl Rejection {
    /// The human-readable `reason` field.
    pub fn reason(&self) -> String {
        match self {
            Rejection::TooBig { weight } => {
                format!("the transaction weighs {weight}, over the limit of {MAX_TX_SIZE}")
            }
            Rejection::FeeTooLow { got, needed } => {
                format!("the fee is {got}, and {needed} is needed")
            }
            Rejection::TxExtraTooBig { len } => {
                format!("tx_extra is {len} bytes, over the relay limit of {MAX_TX_EXTRA_SIZE}")
            }
            Rejection::NonZeroUnlockTime { unlock_time } => format!(
                "the unlock time is {unlock_time}; Wownero does not relay a transaction with a \
                 non-zero unlock time, though one is valid inside a block"
            ),
            Rejection::DoubleSpend => "double spend".into(),
            Rejection::AlreadyInPool => "the transaction is already in the pool".into(),
            Rejection::InvalidInput(w) => format!("an input is not valid: {w}"),
            Rejection::InvalidOutput(w) => format!("an output is not valid: {w}"),
            Rejection::Overspend => "the amounts do not balance".into(),
            Rejection::TooFewOutputs { count } => {
                format!("{count} output(s); at least two are required")
            }
            Rejection::NotParseable(w) => format!("the transaction does not parse: {w}"),
            Rejection::UnsupportedRctType { ty } => format!(
                "RCT type {ty:?} is not one this node can verify yet, so the \
                 transaction is refused rather than taken on trust"
            ),
        }
    }

    /// The flags `specs/11` §3.1 asks for, as `(name, set)` pairs.
    ///
    /// Every one is emitted whether set or not, which the spec requires: a
    /// client that reads `double_spend` must not have to distinguish false
    /// from absent.
    pub fn flags(&self) -> [(&'static str, bool); 9] {
        [
            ("low_mixin", false),
            ("double_spend", matches!(self, Rejection::DoubleSpend)),
            ("invalid_input", matches!(self, Rejection::InvalidInput(_))),
            (
                "invalid_output",
                matches!(self, Rejection::InvalidOutput(_)),
            ),
            ("too_big", matches!(self, Rejection::TooBig { .. })),
            ("overspend", matches!(self, Rejection::Overspend)),
            ("fee_too_low", matches!(self, Rejection::FeeTooLow { .. })),
            (
                "too_few_outputs",
                matches!(self, Rejection::TooFewOutputs { .. }),
            ),
            (
                "nonzero_unlock_time",
                matches!(self, Rejection::NonZeroUnlockTime { .. }),
            ),
        ]
    }

    pub fn tx_extra_too_big(&self) -> bool {
        matches!(self, Rejection::TxExtraTooBig { .. })
    }
}

/// Where a relay method stands in `relay_method`'s order, which a transaction
/// only ever moves up: kept from relay, submitted here, forwarded, stem,
/// fluff, mined (`txpool_tx_meta_t::upgrade_relay_method`).
///
/// Spelled out rather than read off the enum, whose declaration order is the
/// storage record's and puts `Block` before `Fluff`.
fn rank(method: RelayMethod) -> u8 {
    match method {
        RelayMethod::None => 0,
        RelayMethod::Local => 1,
        RelayMethod::Forward => 2,
        RelayMethod::Stem => 3,
        RelayMethod::Fluff => 4,
        RelayMethod::Block => 5,
    }
}

/// One transaction in the pool.
#[derive(Clone, Debug)]
pub struct PoolEntry {
    pub blob: Vec<u8>,
    pub weight: u64,
    pub fee: u64,
    pub receive_time: u64,
    /// How it reached the pool and how far it has gone since. `None` is
    /// `do_not_relay`, and `Block` is `kept_by_block`: in the C++ those two
    /// flags are this, stored.
    pub relay: RelayMethod,
    /// Whether it has been sent to a peer, or came from one. Separate from the
    /// relay method: a transaction nobody forbade relaying has still not been
    /// relayed until something sends it.
    pub relayed: bool,
    pub double_spend_seen: bool,
}

impl PoolEntry {
    /// `relay_category::broadcasted`: fluffed or mined, and so already the
    /// network's to see. The only transactions anyone outside this node is
    /// told about.
    pub fn is_public(&self) -> bool {
        matches!(self.relay, RelayMethod::Fluff | RelayMethod::Block)
    }

    /// `relay_category::legacy`: public, or kept from relay by whoever
    /// submitted it -- the transactions the pool simply holds, as opposed to
    /// ones still on their private way out.
    pub fn is_legacy(&self) -> bool {
        self.is_public() || self.relay == RelayMethod::None
    }

    /// Submitted with `do_not_relay`.
    pub fn do_not_relay(&self) -> bool {
        self.relay == RelayMethod::None
    }

    /// It came back out of a block a reorganisation replaced.
    pub fn kept_by_block(&self) -> bool {
        self.relay == RelayMethod::Block
    }

    /// `upgrade_relay_method`: move on to `method` if that is further along.
    /// Returns whether it moved.
    fn upgrade(&mut self, method: RelayMethod) -> bool {
        if rank(self.relay) < rank(method) {
            self.relay = method;
            true
        } else {
            false
        }
    }
}

/// A transaction the pool took (`tx_verification_context`, the part a caller
/// acts on).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub id: Hash256,
    /// `m_relay`: how it goes on from here. `RelayMethod::None` for not at
    /// all -- asked not to be, or paying no fee.
    pub relay: RelayMethod,
}

/// The pool.
pub struct TxPool {
    by_id: HashMap<Hash256, PoolEntry>,
    /// Key images spent by pooled transactions, so a second spend of the same
    /// output is caught before it is verified.
    spent: HashMap<KeyImage, Hash256>,
    weight: u64,
    /// `--max-txpool-weight`.
    max_weight: u64,
    /// When each transaction last went out to peers from this process. Not
    /// saved: a pool loaded at start has everything due to go out again,
    /// which is what a restart should do.
    relayed_at: HashMap<Hash256, u64>,
}

impl Default for TxPool {
    fn default() -> Self {
        TxPool::new()
    }
}

impl TxPool {
    pub fn new() -> TxPool {
        TxPool {
            by_id: HashMap::new(),
            spent: HashMap::new(),
            weight: 0,
            max_weight: MAX_POOL_WEIGHT,
            relayed_at: HashMap::new(),
        }
    }

    /// `--max-txpool-weight`. Takes effect at the next admission.
    pub fn set_max_weight(&mut self, max_weight: u64) {
        self.max_weight = max_weight;
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// The pool's total weight, which is what eviction is measured against.
    #[allow(
        dead_code,
        reason = "read by the tests and by the block template to come"
    )]
    pub fn weight(&self) -> u64 {
        self.weight
    }

    /// Whether the pool already holds this transaction.
    pub fn contains(&self, id: &Hash256) -> bool {
        self.by_id.contains_key(id)
    }

    pub fn get(&self, id: &Hash256) -> Option<&PoolEntry> {
        self.by_id.get(id)
    }

    /// The transaction ids a caller may see: every one with
    /// `include_sensitive`, the public ones otherwise
    /// (`get_transaction_hashes`).
    pub fn ids(&self, include_sensitive: bool) -> Vec<Hash256> {
        self.by_id
            .iter()
            .filter(|(_, e)| include_sensitive || e.is_public())
            .map(|(id, _)| *id)
            .collect()
    }

    /// How many transactions [`TxPool::ids`] would list
    /// (`get_transactions_count`).
    pub fn count(&self, include_sensitive: bool) -> usize {
        self.by_id
            .values()
            .filter(|e| include_sensitive || e.is_public())
            .count()
    }

    /// In the order a block template wants them: descending fee per weight,
    /// then oldest first (`specs/09` §2.2).
    pub fn by_fee(&self) -> Vec<(Hash256, &PoolEntry)> {
        let mut v: Vec<(Hash256, &PoolEntry)> = self.by_id.iter().map(|(id, e)| (*id, e)).collect();
        v.sort_by(|a, b| {
            let ra = fee_rate(a.1);
            let rb = fee_rate(b.1);
            rb.partial_cmp(&ra)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.1.receive_time.cmp(&b.1.receive_time))
        });
        v
    }

    pub fn remove(&mut self, id: &Hash256) -> Option<PoolEntry> {
        let entry = self.by_id.remove(id)?;
        self.relayed_at.remove(id);
        self.weight = self.weight.saturating_sub(entry.weight);
        self.spent.retain(|_, owner| owner != id);
        Some(entry)
    }

    /// Drop transactions older than `CRYPTONOTE_MEMPOOL_TX_LIVETIME`, or the
    /// week a transaction from a replaced block gets.
    pub fn expire(&mut self, now: u64) -> usize {
        let stale: Vec<Hash256> = self
            .by_id
            .iter()
            .filter(|(_, e)| {
                let life = if e.kept_by_block() {
                    TX_FROM_ALT_BLOCK_LIVETIME
                } else {
                    TX_LIVETIME
                };
                now.saturating_sub(e.receive_time) > life
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &stale {
            self.remove(id);
        }
        stale.len()
    }

    /// Evict the worst-paying transactions until the pool fits.
    ///
    /// Lowest fee per weight first, which is the reverse of the template
    /// order — the pool keeps what a miner would take.
    ///
    /// A transaction that came back out of a replaced block is never evicted,
    /// as `tx_memory_pool::prune` skips `kept_by_block`: it is in the pool
    /// because the chain it was mined in lost, and dropping it for weight
    /// could leave a payment the network had already confirmed nowhere.
    ///
    /// Each eviction goes through [`TxPool::remove`], which takes the weight
    /// and the key images out with the entry. There is no store to keep in
    /// step here -- the pool is written only by [`TxPool::save`] -- so none of
    /// `prune`'s half-done states (a database rolled back under a pool that
    /// was not, key images freed for a transaction still held) can arise.
    pub fn evict_to_fit(&mut self) -> usize {
        if self.weight <= self.max_weight {
            return 0;
        }
        let mut order: Vec<(Hash256, f64)> = self
            .by_id
            .iter()
            .filter(|(_, e)| !e.kept_by_block())
            .map(|(id, e)| (*id, fee_rate(e)))
            .collect();
        order.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        let mut dropped = 0;
        for (id, _) in order {
            if self.weight <= self.max_weight {
                break;
            }
            self.remove(&id);
            dropped += 1;
        }
        dropped
    }

    /// Refuse a key image a block or a pooled transaction has spent.
    fn check_unspent(
        &self,
        db: &LmdbDb,
        k_image: &KeyImage,
        id: &Hash256,
    ) -> Result<(), Rejection> {
        if db.has_key_image(k_image).unwrap_or(false) || self.spent_in_pool(k_image, id) {
            return Err(Rejection::DoubleSpend);
        }
        Ok(())
    }

    /// `have_tx_keyimg_as_spent`: whether a pooled transaction spends this key
    /// image, when the transaction asking is `id`.
    ///
    /// `id`'s own spend counts only when the pool holds `id` as
    /// `relay_category::legacy`. One held privately -- submitted here, or in
    /// its stem -- is being seen again, not spent twice, and refusing it as a
    /// double spend both stalled its relay and told whoever sent it that this
    /// node had it.
    fn spent_in_pool(&self, k_image: &KeyImage, id: &Hash256) -> bool {
        match self.spent.get(k_image) {
            None => false,
            Some(owner) if owner != id => true,
            Some(owner) => self.by_id.get(owner).is_some_and(PoolEntry::is_legacy),
        }
    }

    /// Add a transaction that has already been checked.
    fn insert(&mut self, id: Hash256, tx: &Transaction, entry: PoolEntry) {
        for input in &tx.prefix.vin {
            if let TxIn::ToKey { k_image, .. } = input {
                self.spent.insert(*k_image, id);
            }
        }
        self.weight += entry.weight;
        self.by_id.insert(id, entry);
    }

    /// `add_new_tx` and `add_tx` for a transaction arriving from a wallet or a
    /// peer, as `method`: `None` for `do_not_relay`, `Local` from this node's
    /// RPC, `Stem` or `Fluff` from a peer.
    ///
    /// First, as `add_new_tx` asks: one the pool holds as
    /// `relay_category::legacy`, or the chain holds, is already known. Then
    /// the checks are `specs/09` §2.2's, in its order. `kept_by_block` is not
    /// a method this path takes: a transaction inside a block goes through
    /// consensus validation in `wow-core`, not through here.
    ///
    /// One held privately -- submitted here, or in its stem -- is not known in
    /// that sense, since it is not to anyone asking. It is checked again and
    /// moves on as far as the new copy takes it: a fluffed copy of a stem
    /// transaction fluffs it, and a stem copy of one already held as stem is a
    /// Dandelion++ loop and fluffs it too. Once it moves, its receive time is
    /// the time it went public, not the time it arrived privately.
    pub fn add(
        &mut self,
        db: &LmdbDb,
        blob: &[u8],
        fee_context: &wow_consensus::fee::FeeContext,
        now: u64,
        method: RelayMethod,
    ) -> Result<Admitted, Rejection> {
        let tx =
            Transaction::from_blob(blob).map_err(|e| Rejection::NotParseable(e.to_string()))?;
        let id = wow_types::hashes::transaction_hash_from_blob(&tx, blob)
            .ok_or_else(|| Rejection::NotParseable("no transaction hash".into()))?;

        // Already known. Before the key images, which a transaction the pool
        // holds spends itself: checked the other way round, sending a pooled
        // transaction again was answered as a double spend of its own inputs.
        if self.by_id.get(&id).is_some_and(PoolEntry::is_legacy)
            || db.tx_exists(&id).unwrap_or(false)
        {
            return Err(Rejection::AlreadyInPool);
        }

        let weight = wow_types::weight::get_transaction_weight(&tx, blob.len());

        // 1. Size.
        if weight > MAX_TX_SIZE {
            return Err(Rejection::TooBig { weight });
        }

        // 2. Fee.
        let fee = tx.rct_signatures.txn_fee;
        let required = wow_consensus::fee::required_fee(fee_context, weight)
            .map_err(|e| Rejection::InvalidInput(format!("{e:?}")))?;
        if fee < required.accepted_minimum {
            return Err(Rejection::FeeTooLow {
                got: fee,
                needed: required.needed,
            });
        }

        // 3. `tx_extra` size — relay policy (`specs/06` §6.3).
        if tx.prefix.extra.len() > MAX_TX_EXTRA_SIZE {
            return Err(Rejection::TxExtraTooBig {
                len: tx.prefix.extra.len(),
            });
        }

        // 4. Unlock time — relay policy, and Wownero-specific.
        if tx.prefix.unlock_time != 0 {
            return Err(Rejection::NonZeroUnlockTime {
                unlock_time: tx.prefix.unlock_time,
            });
        }

        // 5. Key images unspent, on chain and in the pool.
        for input in &tx.prefix.vin {
            if let TxIn::ToKey { k_image, .. } = input {
                self.check_unspent(db, k_image, &id)?;
            }
        }

        // 6. Full verification. Not policy: skipping it relays forgeries.
        verify(db, &tx, fee_context.version, db.height(), now)?;

        // What came from a peer has, as far as the pool's statistics go, been
        // relayed (`handle_incoming_tx(..., relayed = true)`), a forward from
        // an anonymity network included.
        let relayed = matches!(
            method,
            RelayMethod::Stem | RelayMethod::Fluff | RelayMethod::Forward
        );
        let mut method = method;
        match self.by_id.get_mut(&id) {
            Some(entry) => {
                // A Dandelion++ loop: this node's own stem came back to it.
                if method == RelayMethod::Stem && entry.relay == RelayMethod::Stem {
                    method = RelayMethod::Fluff;
                }
                if entry.upgrade(method) {
                    entry.receive_time = now;
                    entry.relayed = relayed;
                    entry.double_spend_seen = false;
                }
            }
            None => {
                // The pool has no clock of its own, so a stale entry goes when
                // something else arrives. That is enough: a pool nobody is
                // adding to is a pool nobody is reading either.
                self.expire(now);

                self.insert(
                    id,
                    &tx,
                    PoolEntry {
                        blob: blob.to_vec(),
                        weight,
                        fee,
                        receive_time: now,
                        relay: method,
                        relayed,
                        double_spend_seen: false,
                    },
                );
                self.evict_to_fit();
            }
        }
        // A transaction paying nothing is never relayed.
        let relay = if fee > 0 { method } else { RelayMethod::None };
        Ok(Admitted { id, relay })
    }

    /// `add_tx` with `kept_by_block`: a transaction coming back out of a block
    /// that left the main chain (`specs/06` §7 step 4).
    ///
    /// The relay-policy checks do not apply -- it was valid in a block, and
    /// policy is not consensus -- but it is still verified against the chain
    /// as it now stands, which may no longer hold the outputs it spends.
    pub fn add_kept_by_block(
        &mut self,
        db: &LmdbDb,
        tx: &Transaction,
        blob: &[u8],
        hf_version: u8,
        now: u64,
    ) -> Result<Hash256, Rejection> {
        let id = wow_types::hashes::transaction_hash_from_blob(tx, blob)
            .ok_or_else(|| Rejection::NotParseable("no transaction hash".into()))?;
        if self.contains(&id) {
            return Err(Rejection::AlreadyInPool);
        }
        for input in &tx.prefix.vin {
            if let TxIn::ToKey { k_image, .. } = input {
                self.check_unspent(db, k_image, &id)?;
            }
        }
        verify(db, tx, hf_version, db.height(), now)?;
        self.insert(
            id,
            tx,
            PoolEntry {
                blob: blob.to_vec(),
                weight: wow_types::weight::get_transaction_weight(tx, blob.len()),
                fee: tx.rct_signatures.txn_fee,
                receive_time: now,
                // Mined once already, so public, and relayed as the C++ counts
                // it.
                relay: RelayMethod::Block,
                relayed: true,
                double_spend_seen: false,
            },
        );
        Ok(id)
    }

    /// Take out what a new main-chain block made redundant: the transactions
    /// it contains, and any other that spends a key image it spent.
    pub fn remove_mined(&mut self, included: &[Hash256], spent: &[KeyImage]) -> usize {
        let mut gone = 0;
        for id in included {
            if self.remove(id).is_some() {
                gone += 1;
            }
        }
        for ki in spent {
            if let Some(owner) = self.spent.get(ki).copied() {
                if self.remove(&owner).is_some() {
                    gone += 1;
                }
            }
        }
        gone
    }

    /// After a reorganisation, drop whatever the new chain confirmed or spent.
    pub fn remove_confirmed(&mut self, db: &LmdbDb) -> usize {
        let mut stale: Vec<Hash256> = self
            .by_id
            .keys()
            .filter(|id| db.tx_exists(id).unwrap_or(false))
            .copied()
            .collect();
        stale.extend(
            self.spent
                .iter()
                .filter(|(ki, _)| db.has_key_image(ki).unwrap_or(false))
                .map(|(_, owner)| *owner),
        );
        stale.sort();
        stale.dedup();
        stale.iter().filter(|id| self.remove(id).is_some()).count()
    }

    /// `get_complement`: the public transactions whose hashes are not in
    /// `known`, for a peer's `NOTIFY_GET_TXPOOL_COMPLEMENT`.
    ///
    /// Fluffed or mined ones only, as the C++ serves. One still in its
    /// Dandelion++ stem, or submitted here and not out yet, is not this node's
    /// to hand to a peer that did not get it through the stem; this used to be
    /// guessed from the receive time, which a stem outlasts often enough.
    pub fn public_txs_except(&self, known: &std::collections::HashSet<Hash256>) -> Vec<Vec<u8>> {
        self.by_id
            .iter()
            .filter(|(id, e)| e.is_public() && !known.contains(*id))
            .map(|(_, e)| e.blob.clone())
            .collect()
    }

    /// `set_relayed`: these went out to peers at `now`, as `method` -- `Stem`
    /// or `Fluff`.
    ///
    /// Returns the ones that became public by it. That is when a listener
    /// hears of a transaction that arrived privately, and not before
    /// (`core::on_transactions_relayed`).
    pub fn set_relayed(&mut self, ids: &[Hash256], method: RelayMethod, now: u64) -> Vec<Hash256> {
        let mut public = Vec::new();
        for id in ids {
            if let Some(e) = self.by_id.get_mut(id) {
                // Stem and fluff copies can arrive in either order.
                let was_public = e.is_public();
                e.upgrade(method);
                e.relayed = true;
                self.relayed_at.insert(*id, now);
                if !was_public && e.is_public() {
                    public.push(*id);
                }
            }
        }
        public
    }

    /// `get_relayable_transactions`: what is due to go out to peers again, and
    /// as what.
    ///
    /// One never sent from this process goes at once -- except one in its
    /// stem, whose embargo is the peer-to-peer layer's to run and which
    /// nothing has sent yet: offering it here fluffed stem transactions the
    /// moment they arrived, whenever this walk landed between a peer's message
    /// and its relay. One sent goes again after [`relay_delay`], since a
    /// single send can reach no one: a peer that drops it, a connection that
    /// closes, no peer synchronised at the time. One older than half its
    /// lifetime is left to expire rather than spread again, where a node about
    /// to drop it would take it back.
    ///
    /// The method says how it goes: one submitted here and still `Local`
    /// through the stem, anything else as fluff.
    pub fn due_for_relay(&self, now: u64) -> Vec<(Hash256, Vec<u8>, RelayMethod)> {
        self.by_id
            .iter()
            .filter(|(id, e)| {
                // A transaction paying no fee is never relayed.
                if e.do_not_relay() || e.fee == 0 {
                    return false;
                }
                let life = if e.kept_by_block() {
                    TX_FROM_ALT_BLOCK_LIVETIME
                } else {
                    TX_LIVETIME
                };
                if now.saturating_sub(e.receive_time) > life / 2 {
                    return false;
                }
                match self.relayed_at.get(*id) {
                    // A forward is offered at once and the peer-to-peer layer
                    // holds it for its delay, which is where that delay
                    // lives; the C++ keeps it in `last_relayed_time` instead.
                    // A stem is the other way about: its embargo is that
                    // layer's too, and offering it here would fluff it the
                    // moment it arrived.
                    None => e.relay != RelayMethod::Stem,
                    Some(&last) => now.saturating_sub(last) > relay_delay(last, e.receive_time),
                }
            })
            .map(|(id, e)| (*id, e.blob.clone(), e.relay))
            .collect()
    }

    /// `flush_txpool`: drop the named transactions, or every one when none are
    /// named. Returns how many went.
    pub fn flush(&mut self, ids: &[Hash256]) -> usize {
        if ids.is_empty() {
            let n = self.by_id.len();
            self.by_id.clear();
            self.spent.clear();
            self.relayed_at.clear();
            self.weight = 0;
            return n;
        }
        ids.iter().filter(|id| self.remove(id).is_some()).count()
    }

    /// Every entry, in no particular order.
    pub fn entries(&self) -> impl Iterator<Item = (&Hash256, &PoolEntry)> {
        self.by_id.iter()
    }

    /// Whether a pooled transaction a caller may see spends this key image:
    /// any with `include_sensitive`, a public one otherwise
    /// (`check_for_key_images`).
    pub fn spends(&self, ki: &KeyImage, include_sensitive: bool) -> bool {
        self.spent
            .get(ki)
            .and_then(|owner| self.by_id.get(owner))
            .is_some_and(|e| include_sensitive || e.is_public())
    }

    /// Key images spent by pooled transactions a caller may see, with the
    /// transaction spending each.
    pub fn spent_key_images(&self, include_sensitive: bool) -> Vec<(KeyImage, Hash256)> {
        self.spent
            .iter()
            .filter(|(_, owner)| {
                self.by_id
                    .get(*owner)
                    .is_some_and(|e| include_sensitive || e.is_public())
            })
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    /// Write the pool to `txpool_meta` / `txpool_blob`, replacing what they
    /// held (`specs/10` §4.9).
    pub fn save(&self, db: &LmdbDb) -> Result<usize, String> {
        let mut stored: Vec<Hash256> = Vec::new();
        db.for_all_txpool_txes(&mut |h, _, _| {
            stored.push(*h);
            true
        })
        .map_err(|e| format!("cannot read the stored pool: {e}"))?;
        for h in stored.iter().filter(|h| !self.by_id.contains_key(*h)) {
            db.remove_txpool_tx(h)
                .map_err(|e| format!("cannot clear the stored pool: {e}"))?;
        }
        for (id, e) in &self.by_id {
            db.add_txpool_tx(id, &e.blob, &meta_of(e))
                .map_err(|e| format!("cannot store the pool: {e}"))?;
        }
        Ok(self.by_id.len())
    }

    /// Read a saved pool back, dropping what no longer belongs: a transaction
    /// that does not parse, is already in the chain, spends a key image the
    /// chain has spent, or has outlived its welcome.
    pub fn load(db: &LmdbDb, now: u64) -> TxPool {
        let mut stored: Vec<(Hash256, TxPoolMeta, Vec<u8>)> = Vec::new();
        let _ = db.for_all_txpool_txes(&mut |h, meta, blob| {
            if let Some(b) = blob {
                stored.push((*h, *meta, b.to_vec()));
            }
            true
        });

        let mut pool = TxPool::new();
        for (id, meta, blob) in stored {
            let Ok(tx) = Transaction::from_blob(&blob) else {
                continue;
            };
            if wow_types::hashes::transaction_hash_from_blob(&tx, &blob) != Some(id)
                || db.tx_exists(&id).unwrap_or(false)
            {
                continue;
            }
            let spent_on_chain = tx.prefix.vin.iter().any(|i| match i {
                TxIn::ToKey { k_image, .. } => {
                    db.has_key_image(k_image).unwrap_or(false) || pool.spent.contains_key(k_image)
                }
                _ => false,
            });
            if spent_on_chain {
                continue;
            }
            pool.insert(
                id,
                &tx,
                PoolEntry {
                    blob,
                    weight: meta.weight,
                    fee: meta.fee,
                    receive_time: meta.receive_time,
                    relay: meta.relay_method(),
                    relayed: meta.relayed,
                    double_spend_seen: meta.double_spend_seen,
                },
            );
        }
        pool.expire(now);
        pool
    }
}

/// The `txpool_meta` record for an entry.
///
/// The relay method is not a field of its own in the record but five flags
/// across bytes 112, 114 and 115, laid out as the C++ lays them out, so a pool
/// saved here and read by a C++ node -- or the other way round -- keeps a stem
/// transaction private.
fn meta_of(e: &PoolEntry) -> TxPoolMeta {
    let mut meta = TxPoolMeta {
        weight: e.weight,
        fee: e.fee,
        receive_time: e.receive_time,
        relayed: e.relayed,
        double_spend_seen: e.double_spend_seen,
        ..Default::default()
    };
    meta.set_relay_method(e.relay);
    meta
}

/// `get_relay_delay`: the wait before sending a transaction again, five minutes
/// more for every five minutes it had been in the pool when last sent, and at
/// most four hours.
fn relay_delay(last_relayed: u64, received: u64) -> u64 {
    let age = last_relayed.saturating_sub(received);
    ((age + MIN_RELAY_SECS) / MIN_RELAY_SECS * MIN_RELAY_SECS).min(MAX_RELAY_SECS)
}

fn fee_rate(e: &PoolEntry) -> f64 {
    if e.weight == 0 {
        0.0
    } else {
        e.fee as f64 / e.weight as f64
    }
}

/// `check_tx_inputs`: every ring signature, the range proof, and the balance.
///
/// This is what makes a pool worth having. A node that admits without verifying
/// is a node that relays forgeries, and the wallet on the other end cannot tell
/// the difference until the transaction fails to confirm.
///
/// It is also what a *block's* transactions are checked with
/// (`netsync::ChainTxs`), and deliberately the same function: a transaction in
/// a block and the same transaction in the pool have to be judged identically,
/// or this node disagrees with itself about the same bytes.
///
/// `chain_height` is the height the checks are made at -- `db.height()` for
/// the pool, and for a block the height the chain stands at before it is
/// added, which is what the C++ `check_tx_inputs` sees. It is a parameter
/// rather than a call to `db.height()` because the block path verifies a whole
/// batch ahead of applying it, at a height below the one each block lands at.
pub(crate) fn verify(
    db: &LmdbDb,
    tx: &Transaction,
    hf_version: u8,
    chain_height: u64,
    now: u64,
) -> Result<(), Rejection> {
    use wow_crypto::bulletproofs_plus as bpp;
    use wow_crypto::clsag;

    let rct = &tx.rct_signatures;

    // Only the shapes this chain currently produces are verified here. A type
    // this node cannot check is refused rather than waved through.
    if !rct.ty.is_bulletproof_plus() {
        return Err(Rejection::UnsupportedRctType { ty: rct.ty });
    }
    if tx.prefix.vout.len() < 2 {
        return Err(Rejection::TooFewOutputs {
            count: tx.prefix.vout.len(),
        });
    }
    if rct.clsags.len() != tx.prefix.vin.len() || rct.pseudo_outs.len() != tx.prefix.vin.len() {
        return Err(Rejection::InvalidInput(
            "the signature count does not match the input count".into(),
        ));
    }

    // The range proof. `V` is reconstructed from `outPk`, and type 8 stores
    // `C / 8` where type 9 stores `C` (`specs/02` §4.4).
    let wire = rct
        .bulletproofs_plus
        .first()
        .ok_or_else(|| Rejection::InvalidOutput("there is no range proof".into()))?;
    let v: Vec<wow_crypto::types::EcPoint> = if rct.ty.is_bp_plus_legacy() {
        rct.out_pk.clone()
    } else {
        rct.out_pk
            .iter()
            .map(wow_crypto::rct::div8)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| Rejection::InvalidOutput("an outPk does not decode".into()))?
    };
    let proof = bpp::BulletproofPlus {
        v,
        a: wire.a,
        a1: wire.a1,
        b: wire.b,
        r1: wire.r1,
        s1: wire.s1,
        d1: wire.d1,
        l: wire.l.clone(),
        r: wire.r.clone(),
    };
    bpp::verify(&proof).map_err(|e| Rejection::InvalidOutput(e.to_string()))?;

    // The amounts balance.
    if !balances(rct) {
        return Err(Rejection::Overspend);
    }

    // Each ring signature, over the message the transaction commits to.
    let message = wow_types::hashes::tx_prefix_hash(&tx.prefix);
    let full =
        wow_types::hashes::pre_mlsag_hash(&message, rct, tx.prefix.vin.len(), tx.prefix.vout.len());

    for (slot, input) in tx.prefix.vin.iter().enumerate() {
        let TxIn::ToKey {
            key_offsets,
            k_image,
            ..
        } = input
        else {
            return Err(Rejection::InvalidInput(
                "a non-RingCT input in a RingCT transaction".into(),
            ));
        };

        // The ring, resolved from relative offsets (`specs/05` §2.1).
        let absolute = to_absolute(key_offsets)
            .ok_or_else(|| Rejection::InvalidInput("the key offsets overflow".into()))?;
        let amounts = vec![0u64; absolute.len()];
        let keys = db
            .get_output_keys(&amounts, &absolute, false)
            .map_err(|e| Rejection::InvalidInput(format!("a ring member is unknown: {e}")))?;
        if keys.len() != absolute.len() {
            return Err(Rejection::InvalidInput(
                "a ring member is unknown to this node".into(),
            ));
        }
        check_ring_members(&keys, slot, chain_height, hf_version, now)?;

        let ring: Vec<clsag::RingMember> = keys
            .iter()
            .map(|k| clsag::RingMember {
                dest: wow_crypto::types::PublicKey(k.pubkey),
                mask: wow_crypto::types::EcPoint(k.commitment.unwrap_or([0u8; 32])),
            })
            .collect();

        let sig = &rct.clsags[slot];
        let c = clsag::Clsag {
            s: sig.s.clone(),
            c1: sig.c1,
            d: sig.d,
            i: *k_image,
        };
        clsag::verify(&full, &c, k_image, &ring, &rct.pseudo_outs[slot])
            .map_err(|e| Rejection::InvalidInput(format!("input {slot}: {e}")))?;
    }

    Ok(())
}

/// The outputs one input's ring names, against the chain as it stands: each
/// one unlocked (`outputs_visitor::handle_output`), and from HF 15 none younger
/// than `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` blocks (`check_tx_inputs`).
///
/// A signature over a locked output verifies perfectly, which is why this is a
/// check of its own -- and why a node that checked only the signature admitted,
/// and relayed, transactions every C++ node refuses.
fn check_ring_members(
    members: &[OutputData],
    slot: usize,
    chain_height: u64,
    hf_version: u8,
    now: u64,
) -> Result<(), Rejection> {
    for m in members {
        if !wow_consensus::is_tx_spendtime_unlocked(m.unlock_time, chain_height, now) {
            return Err(Rejection::InvalidInput(format!(
                "input {slot}: a ring member from block {} is locked (unlock time {})",
                m.height, m.unlock_time
            )));
        }
    }
    let newest = members.iter().map(|m| m.height).max().unwrap_or(0);
    wow_consensus::tx_rules::check_min_output_age(hf_version, newest, chain_height).map_err(|_| {
        Rejection::InvalidInput(format!(
            "input {slot}: a ring member from block {newest} is younger than {} blocks",
            wow_consensus::constants::CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE
        ))
    })
}

/// `sum(pseudoOuts) == sum(outPk) + fee*H`.
fn balances(rct: &wow_types::rct::RctSignatures) -> bool {
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;

    let sum = |pts: &[wow_crypto::types::EcPoint], times_eight: bool| -> Option<EdwardsPoint> {
        let mut acc = EdwardsPoint::default();
        for p in pts {
            let q = wow_crypto::ops::decode_point(&p.0)?;
            acc += if times_eight {
                wow_crypto::ops::mul8(&q)
            } else {
                q
            };
        }
        Some(acc)
    };

    let (Some(ins), Some(outs)) = (
        sum(&rct.pseudo_outs, false),
        sum(&rct.out_pk, rct.ty.is_bp_plus_legacy()),
    ) else {
        return false;
    };
    ins == outs + wow_crypto::rct::scalarmult_h(&Scalar::from(rct.txn_fee))
}

/// Relative key offsets to absolute (`specs/05` §2.1).
fn to_absolute(relative: &[u64]) -> Option<Vec<u64>> {
    let mut out = Vec::with_capacity(relative.len());
    let mut acc = 0u64;
    for (i, r) in relative.iter().enumerate() {
        acc = if i == 0 { *r } else { acc.checked_add(*r)? };
        out.push(acc);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fluffed transaction: the public kind, as most of a pool is.
    fn entry(fee: u64, weight: u64, receive_time: u64) -> PoolEntry {
        PoolEntry {
            blob: vec![0u8; weight as usize],
            weight,
            fee,
            receive_time,
            relay: RelayMethod::Fluff,
            relayed: false,
            double_spend_seen: false,
        }
    }

    fn with_relay(relay: RelayMethod, weight: u64) -> PoolEntry {
        PoolEntry {
            relay,
            ..entry(100, weight, 0)
        }
    }

    fn put(pool: &mut TxPool, n: u8, relay: RelayMethod, weight: u64) {
        pool.by_id.insert(id(n), with_relay(relay, weight));
    }

    /// Never sent goes now; sent goes again on a delay that grows with its
    /// age; kept private or past half its lifetime, it never goes.
    #[test]
    fn a_transaction_goes_out_again_on_a_growing_delay() {
        let t0 = 10_000_000;
        let mut pool = TxPool::new();
        pool.by_id.insert(id(1), entry(100, 10, t0));
        let mut private = entry(100, 10, t0);
        private.relay = RelayMethod::None;
        pool.by_id.insert(id(2), private);
        pool.by_id
            .insert(id(3), entry(100, 10, t0 - TX_LIVETIME / 2 - 1));

        let due = |pool: &TxPool, now: u64| -> Vec<u8> {
            let mut ids: Vec<u8> = pool
                .due_for_relay(now)
                .iter()
                .map(|(id, _, _)| id[0])
                .collect();
            ids.sort_unstable();
            ids
        };
        assert_eq!(due(&pool, t0), vec![1], "never sent: at once");

        pool.set_relayed(&[id(1)], RelayMethod::Fluff, t0);
        assert!(due(&pool, t0 + MIN_RELAY_SECS).is_empty(), "just sent");
        assert_eq!(due(&pool, t0 + MIN_RELAY_SECS + 1), vec![1]);

        // Sent again an hour after it arrived: it waits an hour and five
        // minutes before the next time.
        pool.set_relayed(&[id(1)], RelayMethod::Fluff, t0 + 3_600);
        assert!(due(&pool, t0 + 7_200).is_empty());
        assert_eq!(relay_delay(t0 + 3_600, t0), 3_600 + MIN_RELAY_SECS);
        assert_eq!(relay_delay(t0 + 86_400, t0), MAX_RELAY_SECS, "capped");

        pool.remove(&id(1));
        assert!(pool.relayed_at.is_empty(), "forgotten with the transaction");
    }

    /// One submitted here goes out again through the stem; one in its stem
    /// that nothing has sent yet is not offered at all, since its embargo is
    /// the peer-to-peer layer's and offering it fluffed it on arrival.
    #[test]
    fn a_stem_transaction_is_not_offered_before_it_is_sent() {
        let mut pool = TxPool::new();
        put(&mut pool, 1, RelayMethod::Local, 10);
        put(&mut pool, 2, RelayMethod::Stem, 11);

        let due = pool.due_for_relay(0);
        assert_eq!(due.len(), 1);
        assert_eq!((due[0].0, due[0].2), (id(1), RelayMethod::Local));

        // A forward is offered at once, as what it is: the wait before it is
        // stemmed on the public network is the peer-to-peer layer's, which
        // holds it there rather than asking the pool again.
        put(&mut pool, 3, RelayMethod::Forward, 12);
        let due = pool.due_for_relay(0);
        assert_eq!(due.len(), 2);
        assert!(due
            .iter()
            .any(|(i, _, how)| *i == id(3) && *how == RelayMethod::Forward));

        // Once stemmed, it comes back after the delay -- to be fluffed.
        pool.set_relayed(&[id(2)], RelayMethod::Stem, 0);
        let due = pool.due_for_relay(MIN_RELAY_SECS + 1);
        assert!(due
            .iter()
            .any(|(i, _, how)| *i == id(2) && *how == RelayMethod::Stem));
    }

    /// A relay method moves up and never down: a stem copy after a fluffed one
    /// does not make it private again, and a mined one stays mined.
    #[test]
    fn a_relay_method_only_moves_up() {
        let mut e = with_relay(RelayMethod::None, 10);
        assert!(e.upgrade(RelayMethod::Local));
        assert!(!e.upgrade(RelayMethod::Local), "no move to where it is");
        assert!(e.upgrade(RelayMethod::Stem));
        assert!(e.upgrade(RelayMethod::Fluff));
        assert!(!e.upgrade(RelayMethod::Stem));
        assert_eq!(e.relay, RelayMethod::Fluff);
        assert!(e.upgrade(RelayMethod::Block));
        assert!(!e.upgrade(RelayMethod::Fluff));
        assert!(e.kept_by_block() && e.is_public());

        // `relay_category`: public is fluff and block; legacy adds none.
        for (method, public, legacy) in [
            (RelayMethod::None, false, true),
            (RelayMethod::Local, false, false),
            (RelayMethod::Forward, false, false),
            (RelayMethod::Stem, false, false),
            (RelayMethod::Fluff, true, true),
            (RelayMethod::Block, true, true),
        ] {
            let e = with_relay(method, 10);
            assert_eq!(e.is_public(), public, "{method:?}");
            assert_eq!(e.is_legacy(), legacy, "{method:?}");
        }
    }

    /// Relaying reports what went public by it, once.
    #[test]
    fn relaying_says_what_became_public() {
        let mut pool = TxPool::new();
        put(&mut pool, 1, RelayMethod::Local, 10);
        put(&mut pool, 2, RelayMethod::Fluff, 11);

        let stemmed = pool.set_relayed(&[id(1), id(2)], RelayMethod::Stem, 5);
        assert!(stemmed.is_empty());
        assert_eq!(pool.get(&id(1)).unwrap().relay, RelayMethod::Stem);
        assert!(pool.get(&id(1)).unwrap().relayed);
        assert_eq!(
            pool.set_relayed(&[id(1), id(2)], RelayMethod::Fluff, 6),
            vec![id(1)],
            "the one that was private"
        );
        let again = pool.set_relayed(&[id(1)], RelayMethod::Fluff, 7);
        assert!(again.is_empty());
    }

    /// What is private stays out of every view an outsider has: the hashes,
    /// the count, the key images, the complement.
    #[test]
    fn private_transactions_stay_out_of_sight() {
        let mut pool = TxPool::new();
        for (n, method) in [
            (1, RelayMethod::None),
            (2, RelayMethod::Local),
            (3, RelayMethod::Stem),
            (4, RelayMethod::Fluff),
            (5, RelayMethod::Block),
        ] {
            put(&mut pool, n, method, 10 + u64::from(n));
            pool.spent.insert(KeyImage([n; 32]), id(n));
        }

        let mut public = pool.ids(false);
        public.sort_unstable();
        assert_eq!(public, vec![id(4), id(5)]);
        assert_eq!(pool.ids(true).len(), 5);
        assert_eq!((pool.count(false), pool.count(true)), (2, 5));

        assert!(!pool.spends(&KeyImage([3; 32]), false), "a stem spend");
        assert!(pool.spends(&KeyImage([3; 32]), true));
        assert!(pool.spends(&KeyImage([4; 32]), false));
        assert_eq!(pool.spent_key_images(false).len(), 2);
        assert_eq!(pool.spent_key_images(true).len(), 5);

        let mut sizes: Vec<usize> = pool
            .public_txs_except(&Default::default())
            .iter()
            .map(Vec::len)
            .collect();
        sizes.sort_unstable();
        assert_eq!(sizes, vec![14, 15], "fluffed and mined only");
    }

    /// A transaction's own key images are not a double spend of it while the
    /// pool holds it privately, and are once it holds it publicly. Another
    /// transaction's always are.
    #[test]
    fn a_private_transaction_seen_again_is_not_its_own_double_spend() {
        let mut pool = TxPool::new();
        put(&mut pool, 1, RelayMethod::Stem, 10);
        pool.spent.insert(KeyImage([1; 32]), id(1));

        assert!(!pool.spent_in_pool(&KeyImage([1; 32]), &id(1)));
        assert!(pool.spent_in_pool(&KeyImage([1; 32]), &id(2)));
        assert!(!pool.spent_in_pool(&KeyImage([9; 32]), &id(2)));

        pool.by_id.get_mut(&id(1)).unwrap().relay = RelayMethod::Fluff;
        assert!(pool.spent_in_pool(&KeyImage([1; 32]), &id(1)));
    }

    /// The saved record carries the relay method in the C++'s flags, so a stem
    /// transaction is still one after a restart -- here or in a C++ node.
    #[test]
    fn the_relay_method_is_saved_in_the_cpp_layout() {
        let mut stem = with_relay(RelayMethod::Stem, 10);
        stem.relayed = true;
        let raw = meta_of(&stem).encode();
        assert_eq!(raw[115], 0b0000_1000, "dandelionpp_stem, bit 3");
        assert_eq!((raw[112], raw[113], raw[114]), (0, 1, 0));

        let raw = meta_of(&with_relay(RelayMethod::None, 10)).encode();
        assert_eq!(raw[114], 1, "do_not_relay");
        let raw = meta_of(&with_relay(RelayMethod::Block, 10)).encode();
        assert_eq!(raw[112], 1, "kept_by_block");

        for method in [
            RelayMethod::None,
            RelayMethod::Local,
            RelayMethod::Stem,
            RelayMethod::Fluff,
            RelayMethod::Block,
        ] {
            let back = TxPoolMeta::decode(&meta_of(&with_relay(method, 10)).encode()).unwrap();
            assert_eq!(back.relay_method(), method);
        }
    }

    /// A transaction mined in a block leaves the pool, and so does one that
    /// spends a key image the block spent.
    #[test]
    fn a_mined_block_clears_what_it_made_redundant() {
        let mut pool = TxPool::new();
        pool.by_id.insert(id(1), entry(100, 10, 0));
        pool.by_id.insert(id(2), entry(100, 10, 0));
        pool.by_id.insert(id(3), entry(100, 10, 0));
        pool.weight = 30;
        pool.spent.insert(KeyImage([7u8; 32]), id(2));

        let gone = pool.remove_mined(&[id(1)], &[KeyImage([7u8; 32])]);
        assert_eq!(gone, 2);
        assert!(!pool.contains(&id(1)), "mined");
        assert!(!pool.contains(&id(2)), "double-spends the block");
        assert!(pool.contains(&id(3)));
    }

    /// A transaction from a replaced block lives a week, not three days.
    #[test]
    fn a_transaction_from_a_replaced_block_lives_longer() {
        let mut pool = TxPool::new();
        let mut kept = entry(100, 10, 0);
        kept.relay = RelayMethod::Block;
        pool.by_id.insert(id(1), kept);
        pool.by_id.insert(id(2), entry(100, 10, 0));
        pool.weight = 20;

        assert_eq!(pool.expire(TX_LIVETIME + 1), 1);
        assert!(pool.contains(&id(1)));
        assert_eq!(pool.expire(TX_FROM_ALT_BLOCK_LIVETIME + 1), 1);
    }

    /// The complement a peer asks for holds public transactions only, however
    /// long a private one has been in the pool, and none the peer has.
    #[test]
    fn the_complement_leaves_out_what_is_not_public() {
        let mut pool = TxPool::new();
        let mut stem_old = with_relay(RelayMethod::Stem, 11);
        stem_old.relayed = true;
        pool.by_id.insert(id(1), entry(100, 10, 1_000));
        pool.by_id.insert(id(2), stem_old);
        put(&mut pool, 3, RelayMethod::None, 12);
        put(&mut pool, 4, RelayMethod::Local, 13);

        let out = pool.public_txs_except(&Default::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 10);

        let known = [id(1)].into_iter().collect();
        assert!(pool.public_txs_except(&known).is_empty());
    }

    #[test]
    fn flushing_with_no_ids_empties_the_pool() {
        let mut pool = TxPool::new();
        pool.by_id.insert(id(1), entry(100, 10, 0));
        pool.by_id.insert(id(2), entry(100, 10, 0));
        pool.spent.insert(KeyImage([1u8; 32]), id(1));
        pool.weight = 20;

        assert_eq!(pool.flush(&[id(2), id(9)]), 1);
        assert_eq!(pool.flush(&[]), 1);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.weight(), 0);
        assert!(pool.spent_key_images(true).is_empty());
    }

    fn id(n: u8) -> Hash256 {
        [n; 32]
    }

    /// Relative offsets accumulate; the first is absolute.
    /// A ring member still locked, or too young, is refused however good the
    /// signature over it, as `handle_output` and `check_tx_inputs` refuse it.
    /// Checking only the signature let this node admit and relay transactions
    /// every C++ node turned away.
    #[test]
    fn locked_or_young_ring_members_are_refused() {
        const HEIGHT: u64 = 1_000;
        const NOW: u64 = 1_700_000_000;
        let member = |height, unlock_time| OutputData {
            pubkey: [0; 32],
            unlock_time,
            height,
            commitment: None,
        };

        // Unlocked, including a coinbase whose unlock height has passed.
        let fine = [member(900, 0), member(10, 0), member(700, 988)];
        assert!(check_ring_members(&fine, 0, HEIGHT, 20, NOW).is_ok());

        // A coinbase still inside its 288 blocks.
        let locked = [member(900, 0), member(950, 950 + 288)];
        let e = check_ring_members(&locked, 1, HEIGHT, 20, NOW).expect_err("locked");
        assert!(
            matches!(&e, Rejection::InvalidInput(why) if why.contains("input 1") && why.contains("locked")),
            "{e:?}"
        );

        // Four blocks old is old enough and three is not, from HF 15.
        assert!(check_ring_members(&[member(HEIGHT - 4, 0)], 0, HEIGHT, 20, NOW).is_ok());
        assert!(check_ring_members(&[member(HEIGHT - 3, 0)], 0, HEIGHT, 20, NOW).is_err());
        assert!(check_ring_members(&[member(HEIGHT - 3, 0)], 0, HEIGHT, 14, NOW).is_ok());
    }

    #[test]
    fn key_offsets_are_relative() {
        assert_eq!(to_absolute(&[5]), Some(vec![5]));
        assert_eq!(to_absolute(&[5, 4, 11]), Some(vec![5, 9, 20]));
        assert_eq!(to_absolute(&[0, 1, 1, 1]), Some(vec![0, 1, 2, 3]));
        // An overflow is refused rather than wrapping into a valid-looking
        // ring member.
        assert_eq!(to_absolute(&[u64::MAX, 1]), None);
    }

    /// A block template takes the best-paying first; eviction drops those same
    /// transactions last.
    #[test]
    fn the_pool_is_ordered_by_fee_rate() {
        let mut pool = TxPool::new();
        // 10 per byte, 1 per byte, 5 per byte.
        pool.by_id.insert(id(1), entry(1_000, 100, 10));
        pool.by_id.insert(id(2), entry(100, 100, 20));
        pool.by_id.insert(id(3), entry(500, 100, 30));
        pool.weight = 300;

        let order: Vec<Hash256> = pool.by_fee().into_iter().map(|(i, _)| i).collect();
        assert_eq!(order, vec![id(1), id(3), id(2)]);
    }

    /// Equal fee rates fall back to receive time, oldest first.
    #[test]
    fn ties_go_to_the_older_transaction() {
        let mut pool = TxPool::new();
        pool.by_id.insert(id(1), entry(100, 100, 99));
        pool.by_id.insert(id(2), entry(100, 100, 10));
        pool.weight = 200;

        let order: Vec<Hash256> = pool.by_fee().into_iter().map(|(i, _)| i).collect();
        assert_eq!(order, vec![id(2), id(1)], "the older one first");
    }

    /// Stale transactions are dropped after three days.
    #[test]
    fn old_transactions_expire() {
        let mut pool = TxPool::new();
        pool.by_id.insert(id(1), entry(100, 10, 0));
        pool.by_id.insert(id(2), entry(100, 10, 1_000_000));
        pool.weight = 20;

        assert_eq!(pool.expire(TX_LIVETIME), 0, "exactly at the limit stays");
        assert_eq!(pool.expire(TX_LIVETIME + 1), 1, "past it goes");
        assert!(!pool.contains(&id(1)));
        assert!(pool.contains(&id(2)));
    }

    /// Removing a transaction frees its weight and its key images.
    #[test]
    fn removing_frees_the_key_images() {
        let mut pool = TxPool::new();
        pool.by_id.insert(id(1), entry(100, 50, 0));
        pool.weight = 50;
        pool.spent.insert(KeyImage([9u8; 32]), id(1));

        assert!(pool.remove(&id(1)).is_some());
        assert_eq!(pool.weight(), 0);
        assert!(pool.spent.is_empty(), "the key image is spendable again");
        assert!(pool.remove(&id(1)).is_none());
    }

    /// Eviction takes the worst-paying transaction's weight and key images
    /// with it, and spares one that came back out of a replaced block however
    /// little it pays (`prune`'s `kept_by_block` skip).
    #[test]
    fn eviction_frees_key_images_and_spares_kept_by_block() {
        let mut pool = TxPool::new();
        pool.set_max_weight(200);
        pool.by_id.insert(id(1), entry(10, 100, 0));
        let mut kept = entry(0, 100, 0);
        kept.relay = RelayMethod::Block;
        pool.by_id.insert(id(2), kept);
        pool.by_id.insert(id(3), entry(1_000, 100, 0));
        for n in 1..=3 {
            pool.spent.insert(KeyImage([n; 32]), id(n));
        }
        pool.weight = 300;

        assert_eq!(pool.evict_to_fit(), 1);
        assert!(!pool.contains(&id(1)), "the worst-paying one goes");
        assert!(pool.contains(&id(2)), "kept_by_block stays, paying nothing");
        assert!(pool.contains(&id(3)));
        assert_eq!(pool.weight(), 200);
        assert!(
            !pool.spent.contains_key(&KeyImage([1; 32])),
            "freed with it"
        );
        assert_eq!(pool.spent.len(), 2);
        assert_eq!(pool.evict_to_fit(), 0, "it fits now");
    }

    /// Every rejection names itself, and every flag `specs/11` §3.1 requires is
    /// present whether set or not.
    #[test]
    fn rejections_report_themselves() {
        let cases = [
            Rejection::TooBig { weight: 2_000_000 },
            Rejection::FeeTooLow {
                got: 1,
                needed: 100,
            },
            Rejection::TxExtraTooBig { len: 2_000 },
            Rejection::NonZeroUnlockTime { unlock_time: 5 },
            Rejection::DoubleSpend,
            Rejection::AlreadyInPool,
            Rejection::Overspend,
            Rejection::TooFewOutputs { count: 1 },
        ];
        for c in &cases {
            assert!(!c.reason().is_empty(), "{c:?} has no reason");
            assert_eq!(c.flags().len(), 9, "every flag is emitted");
        }

        // Each one sets its own flag and no other.
        let d = Rejection::DoubleSpend;
        let set: Vec<&str> = d
            .flags()
            .iter()
            .filter(|(_, v)| *v)
            .map(|(n, _)| *n)
            .collect();
        assert_eq!(set, vec!["double_spend"]);

        // A double spend says no more than that, as the C++ says it: naming
        // the pooled transaction that spends the key image, or even that one
        // does, tells whoever asks what this node holds in its stem.
        assert_eq!(d.reason(), "double spend");

        // `tx_extra_too_big` is separate because it is not in the flag array.
        assert!(Rejection::TxExtraTooBig { len: 2_000 }.tx_extra_too_big());
        assert!(!d.tx_extra_too_big());
    }

    /// The Wownero-specific relay refusal says that the transaction is still
    /// valid in a block, because that is the part a wallet author needs.
    #[test]
    fn the_unlock_time_refusal_explains_itself() {
        let r = Rejection::NonZeroUnlockTime { unlock_time: 100 };
        let text = r.reason();
        assert!(text.contains("does not relay"), "{text}");
        assert!(text.contains("valid inside a block"), "{text}");
    }

    /// The limits are the documented ones.
    #[test]
    fn the_limits_are_the_documented_ones() {
        assert_eq!(MAX_TX_SIZE, 1_000_000);
        assert_eq!(MAX_TX_EXTRA_SIZE, 1_060);
        assert_eq!(MAX_POOL_WEIGHT, 648_000_000);
        assert_eq!(TX_LIVETIME, 3 * 86_400);
    }
}
