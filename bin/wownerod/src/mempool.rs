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

use std::collections::HashMap;

use wow_crypto::types::{Hash256, KeyImage};
use wow_storage::db::BlockchainDb;
use wow_storage::lmdb::LmdbDb;
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
/// How long a transaction stays out of `NOTIFY_GET_TXPOOL_COMPLEMENT` answers,
/// so one still in its Dandelion++ stem phase (embargo mean 39 s) is not
/// handed to a peer that did not get it through the stem.
const COMPLEMENT_QUIET_SECS: u64 = 120;
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
    TooBig { weight: u64 },
    FeeTooLow { got: u64, needed: u64 },
    TxExtraTooBig { len: usize },
    NonZeroUnlockTime { unlock_time: u64 },
    DoubleSpend { key_image: KeyImage },
    AlreadyInPool,
    InvalidInput(String),
    InvalidOutput(String),
    Overspend,
    TooFewOutputs { count: usize },
    NotParseable(String),
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
            Rejection::DoubleSpend { key_image } => format!(
                "the output with key image {} has already been spent",
                wow_crypto::hex::encode(&key_image.0)
            ),
            Rejection::AlreadyInPool => "the transaction is already in the pool".into(),
            Rejection::InvalidInput(w) => format!("an input is not valid: {w}"),
            Rejection::InvalidOutput(w) => format!("an output is not valid: {w}"),
            Rejection::Overspend => "the amounts do not balance".into(),
            Rejection::TooFewOutputs { count } => {
                format!("{count} output(s); at least two are required")
            }
            Rejection::NotParseable(w) => format!("the transaction does not parse: {w}"),
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
            (
                "double_spend",
                matches!(self, Rejection::DoubleSpend { .. }),
            ),
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

/// One transaction in the pool.
#[derive(Clone, Debug)]
pub struct PoolEntry {
    pub blob: Vec<u8>,
    pub weight: u64,
    pub fee: u64,
    pub receive_time: u64,
    /// Set when the submitter asked for the transaction not to be broadcast.
    pub do_not_relay: bool,
    /// Whether it has actually been sent to a peer. Separate from
    /// `do_not_relay`: a transaction nobody forbade relaying has still not
    /// been relayed until something sends it.
    pub relayed: bool,
    pub double_spend_seen: bool,
    /// It came back out of a block a reorganisation replaced.
    pub kept_by_block: bool,
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

    /// Every transaction id in the pool.
    pub fn ids(&self) -> Vec<Hash256> {
        self.by_id.keys().copied().collect()
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
                let life = if e.kept_by_block {
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
    pub fn evict_to_fit(&mut self) -> usize {
        if self.weight <= self.max_weight {
            return 0;
        }
        let mut order: Vec<(Hash256, f64)> = self
            .by_id
            .iter()
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

    /// `add_tx` for a transaction arriving from a wallet or a peer.
    ///
    /// The checks are `specs/09` §2.2's, in its order. `kept_by_block` is not a
    /// parameter because this path never has it: a transaction inside a block
    /// goes through consensus validation in `wow-core`, not through here.
    pub fn add(
        &mut self,
        db: &LmdbDb,
        blob: &[u8],
        fee_context: &wow_consensus::fee::FeeContext,
        now: u64,
        do_not_relay: bool,
    ) -> Result<Hash256, Rejection> {
        let tx =
            Transaction::from_blob(blob).map_err(|e| Rejection::NotParseable(e.to_string()))?;
        let id = wow_types::hashes::transaction_hash_from_blob(&tx, blob)
            .ok_or_else(|| Rejection::NotParseable("no transaction hash".into()))?;

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
                if db.has_key_image(k_image).unwrap_or(false) || self.spent.contains_key(k_image) {
                    return Err(Rejection::DoubleSpend {
                        key_image: *k_image,
                    });
                }
            }
        }

        // 6. Not already here.
        if self.contains(&id) {
            return Err(Rejection::AlreadyInPool);
        }

        // 7. Full verification. Not policy: skipping it relays forgeries.
        verify(db, &tx)?;

        // The pool has no clock of its own, so a stale entry goes when something
        // else arrives. That is enough: a pool nobody is adding to is a pool
        // nobody is reading either.
        self.expire(now);

        self.insert(
            id,
            &tx,
            PoolEntry {
                blob: blob.to_vec(),
                weight,
                fee,
                receive_time: now,
                do_not_relay,
                relayed: false,
                double_spend_seen: false,
                kept_by_block: false,
            },
        );
        self.evict_to_fit();
        Ok(id)
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
        now: u64,
    ) -> Result<Hash256, Rejection> {
        let id = wow_types::hashes::transaction_hash_from_blob(tx, blob)
            .ok_or_else(|| Rejection::NotParseable("no transaction hash".into()))?;
        if self.contains(&id) {
            return Err(Rejection::AlreadyInPool);
        }
        for input in &tx.prefix.vin {
            if let TxIn::ToKey { k_image, .. } = input {
                if db.has_key_image(k_image).unwrap_or(false) || self.spent.contains_key(k_image) {
                    return Err(Rejection::DoubleSpend {
                        key_image: *k_image,
                    });
                }
            }
        }
        verify(db, tx)?;
        self.insert(
            id,
            tx,
            PoolEntry {
                blob: blob.to_vec(),
                weight: wow_types::weight::get_transaction_weight(tx, blob.len()),
                fee: tx.rct_signatures.txn_fee,
                receive_time: now,
                do_not_relay: false,
                relayed: false,
                double_spend_seen: false,
                kept_by_block: true,
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

    /// Transactions that may be relayed.
    pub fn relayable_ids(&self) -> Vec<Hash256> {
        self.by_id
            .iter()
            .filter(|(_, e)| !e.do_not_relay)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Relayed transactions whose hashes are not in `known`, for a peer's
    /// `NOTIFY_GET_TXPOOL_COMPLEMENT`.
    ///
    /// A transaction received in the last [`COMPLEMENT_QUIET_SECS`] is held
    /// back: it may still be in its Dandelion++ stem, and answering with it
    /// would publish what the stem is there to hide.
    pub fn public_txs_except(
        &self,
        known: &std::collections::HashSet<Hash256>,
        now: u64,
    ) -> Vec<Vec<u8>> {
        self.by_id
            .iter()
            .filter(|(id, e)| {
                e.relayed
                    && !e.do_not_relay
                    && now.saturating_sub(e.receive_time) >= COMPLEMENT_QUIET_SECS
                    && !known.contains(*id)
            })
            .map(|(_, e)| e.blob.clone())
            .collect()
    }

    /// These went out to peers at `now`.
    pub fn mark_relayed(&mut self, ids: &[Hash256], now: u64) {
        for id in ids {
            if let Some(e) = self.by_id.get_mut(id) {
                e.relayed = true;
                self.relayed_at.insert(*id, now);
            }
        }
    }

    /// `get_relayable_transactions`: what is due to go out to peers again.
    ///
    /// One never sent from this process goes at once. One sent goes again
    /// after [`relay_delay`], since a single send can reach no one: a peer
    /// that drops it, a connection that closes, no peer synchronised at the
    /// time. One older than half its lifetime is left to expire rather than
    /// spread again, where a node about to drop it would take it back.
    pub fn due_for_relay(&self, now: u64) -> Vec<(Hash256, Vec<u8>)> {
        self.by_id
            .iter()
            .filter(|(id, e)| {
                // A transaction paying no fee is never relayed.
                if e.do_not_relay || e.fee == 0 {
                    return false;
                }
                let life = if e.kept_by_block {
                    TX_FROM_ALT_BLOCK_LIVETIME
                } else {
                    TX_LIVETIME
                };
                if now.saturating_sub(e.receive_time) > life / 2 {
                    return false;
                }
                match self.relayed_at.get(*id) {
                    None => true,
                    Some(&last) => now.saturating_sub(last) > relay_delay(last, e.receive_time),
                }
            })
            .map(|(id, e)| (*id, e.blob.clone()))
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

    /// Whether a pooled transaction spends this key image.
    pub fn spends(&self, ki: &KeyImage) -> bool {
        self.spent.contains_key(ki)
    }

    /// Key images spent by pooled transactions, with the transaction spending
    /// each.
    pub fn spent_key_images(&self) -> Vec<(KeyImage, Hash256)> {
        self.spent.iter().map(|(k, v)| (*k, *v)).collect()
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
            let meta = wow_storage::records::TxPoolMeta {
                weight: e.weight,
                fee: e.fee,
                receive_time: e.receive_time,
                kept_by_block: e.kept_by_block,
                relayed: e.relayed,
                do_not_relay: e.do_not_relay,
                double_spend_seen: e.double_spend_seen,
                ..Default::default()
            };
            db.add_txpool_tx(id, &e.blob, &meta)
                .map_err(|e| format!("cannot store the pool: {e}"))?;
        }
        Ok(self.by_id.len())
    }

    /// Read a saved pool back, dropping what no longer belongs: a transaction
    /// that does not parse, is already in the chain, spends a key image the
    /// chain has spent, or has outlived its welcome.
    pub fn load(db: &LmdbDb, now: u64) -> TxPool {
        let mut stored: Vec<(Hash256, wow_storage::records::TxPoolMeta, Vec<u8>)> = Vec::new();
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
                    do_not_relay: meta.do_not_relay,
                    relayed: meta.relayed,
                    double_spend_seen: meta.double_spend_seen,
                    kept_by_block: meta.kept_by_block,
                },
            );
        }
        pool.expire(now);
        pool
    }
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
fn verify(db: &LmdbDb, tx: &Transaction) -> Result<(), Rejection> {
    use wow_crypto::bulletproofs_plus as bpp;
    use wow_crypto::clsag;

    let rct = &tx.rct_signatures;

    // Only the shapes this chain currently produces are verified here. A type
    // this node cannot check is refused rather than waved through.
    if !rct.ty.is_bulletproof_plus() {
        return Err(Rejection::InvalidInput(format!(
            "RCT type {:?} is not one this node verifies yet",
            rct.ty
        )));
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

    fn entry(fee: u64, weight: u64, receive_time: u64) -> PoolEntry {
        PoolEntry {
            blob: vec![0u8; weight as usize],
            weight,
            fee,
            receive_time,
            do_not_relay: false,
            relayed: false,
            double_spend_seen: false,
            kept_by_block: false,
        }
    }

    /// Never sent goes now; sent goes again on a delay that grows with its
    /// age; kept private or past half its lifetime, it never goes.
    #[test]
    fn a_transaction_goes_out_again_on_a_growing_delay() {
        let t0 = 10_000_000;
        let mut pool = TxPool::new();
        pool.by_id.insert(id(1), entry(100, 10, t0));
        let mut private = entry(100, 10, t0);
        private.do_not_relay = true;
        pool.by_id.insert(id(2), private);
        pool.by_id
            .insert(id(3), entry(100, 10, t0 - TX_LIVETIME / 2 - 1));

        let due = |pool: &TxPool, now: u64| -> Vec<u8> {
            let mut ids: Vec<u8> = pool
                .due_for_relay(now)
                .iter()
                .map(|(id, _)| id[0])
                .collect();
            ids.sort_unstable();
            ids
        };
        assert_eq!(due(&pool, t0), vec![1], "never sent: at once");

        pool.mark_relayed(&[id(1)], t0);
        assert!(due(&pool, t0 + MIN_RELAY_SECS).is_empty(), "just sent");
        assert_eq!(due(&pool, t0 + MIN_RELAY_SECS + 1), vec![1]);

        // Sent again an hour after it arrived: it waits an hour and five
        // minutes before the next time.
        pool.mark_relayed(&[id(1)], t0 + 3_600);
        assert!(due(&pool, t0 + 7_200).is_empty());
        assert_eq!(relay_delay(t0 + 3_600, t0), 3_600 + MIN_RELAY_SECS);
        assert_eq!(relay_delay(t0 + 86_400, t0), MAX_RELAY_SECS, "capped");

        pool.remove(&id(1));
        assert!(pool.relayed_at.is_empty(), "forgotten with the transaction");
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
        kept.kept_by_block = true;
        pool.by_id.insert(id(1), kept);
        pool.by_id.insert(id(2), entry(100, 10, 0));
        pool.weight = 20;

        assert_eq!(pool.expire(TX_LIVETIME + 1), 1);
        assert!(pool.contains(&id(1)));
        assert_eq!(pool.expire(TX_FROM_ALT_BLOCK_LIVETIME + 1), 1);
    }

    /// The complement a peer asks for holds relayed transactions only, and
    /// none still young enough to be in a Dandelion++ stem.
    #[test]
    fn the_complement_leaves_out_what_is_not_public() {
        let mut pool = TxPool::new();
        let mut relayed_old = entry(100, 10, 0);
        relayed_old.relayed = true;
        let mut relayed_new = entry(100, 11, 1_000);
        relayed_new.relayed = true;
        let mut private = entry(100, 12, 0);
        private.relayed = true;
        private.do_not_relay = true;
        pool.by_id.insert(id(1), relayed_old);
        pool.by_id.insert(id(2), relayed_new);
        pool.by_id.insert(id(3), private);
        pool.by_id.insert(id(4), entry(100, 13, 0));

        let out = pool.public_txs_except(&Default::default(), 1_000 + COMPLEMENT_QUIET_SECS - 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 10);

        let known = [id(1)].into_iter().collect();
        assert!(pool
            .public_txs_except(&known, 1_000 + COMPLEMENT_QUIET_SECS - 1)
            .is_empty());
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
        assert!(pool.spent_key_images().is_empty());
    }

    fn id(n: u8) -> Hash256 {
        [n; 32]
    }

    /// Relative offsets accumulate; the first is absolute.
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
            Rejection::DoubleSpend {
                key_image: KeyImage([1u8; 32]),
            },
            Rejection::AlreadyInPool,
            Rejection::Overspend,
            Rejection::TooFewOutputs { count: 1 },
        ];
        for c in &cases {
            assert!(!c.reason().is_empty(), "{c:?} has no reason");
            assert_eq!(c.flags().len(), 9, "every flag is emitted");
        }

        // Each one sets its own flag and no other.
        let d = Rejection::DoubleSpend {
            key_image: KeyImage([1u8; 32]),
        };
        let set: Vec<&str> = d
            .flags()
            .iter()
            .filter(|(_, v)| *v)
            .map(|(n, _)| *n)
            .collect();
        assert_eq!(set, vec!["double_spend"]);

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
