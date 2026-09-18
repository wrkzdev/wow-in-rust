//! What this wallet sent: `store-tx-info`.
//!
//! `wallet2::m_unconfirmed_txs` and `m_confirmed_txs`, kept here as one list.
//!
//! An output of ours being spent says that money left, not where it went. The
//! chain cannot say where: every output is a one-time key, and only the sender
//! knew whose it was. So a wallet that is to show "sent 5 to Wo…" has to write
//! that down when it sends, which is what `store-tx-info` does in the C++
//! wallet, and here.
//!
//! A transaction that spends this wallet's outputs but was not sent from here
//! (by another copy of the wallet, or before a restore) is recorded when a
//! block or the daemon's pool shows it, with what the transaction can tell:
//! what left, the fee, and what came back as change. Not where the rest went.
//!
//! Transaction secret keys are not kept. `get_tx_key` needs them, and the
//! cache they would be written to is not encrypted.

use std::collections::{HashMap, HashSet};

use wow_crypto::types::{Hash256, KeyImage};
use wow_types::tx::{Transaction, TxIn};

use crate::refresh::{unlocked_at, WalletState};
use crate::scan::scan_transaction;
use crate::spend::SpendPlan;

/// How long a sent transaction may be in neither a block nor the daemon's pool
/// before it is judged to have failed: `tx_propagation_timeout` in
/// `wallet2::process_unconfirmed_transfer`.
pub const PROPAGATION_TIMEOUT: u64 = 500;

/// Where a sent transaction has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentState {
    /// Handed to a daemon, and not yet in a block.
    Pending,
    /// In neither a block nor the pool, for longer than
    /// [`PROPAGATION_TIMEOUT`]. Its inputs are unspent again.
    Failed,
    /// In the block at this height.
    Confirmed(u64),
}

/// One payee, as the sender named it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentDestination {
    /// The address as it was given, so a subaddress or an integrated address
    /// shows as one.
    pub address: String,
    pub amount: u64,
}

/// A transaction that spent this wallet's outputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentTx {
    pub txid: Hash256,
    pub state: SentState,
    /// The total of this wallet's outputs it spent.
    pub amount_in: u64,
    /// The total of its outputs, change included: `amount_in` less the fee.
    pub amount_out: u64,
    /// What came back to the account it was spent from.
    pub change: u64,
    /// Where the rest went. Empty for a transaction not sent from here, or sent
    /// with `store-tx-info` off.
    pub destinations: Vec<SentDestination>,
    pub payment_id: Option<[u8; 8]>,
    /// When it was sent, until a block carries it; then that block's timestamp.
    pub timestamp: u64,
    /// When it was sent from here or first seen in the daemon's pool, or zero
    /// for one found in a block. The propagation timeout counts from this.
    pub sent_time: u64,
    pub unlock_time: u64,
    /// The subaddress account its inputs came from, and their minor indices.
    pub account: u32,
    pub minors: Vec<u32>,
    /// Its inputs' key images, which is how a failed transaction gives its
    /// inputs back.
    pub key_images: Vec<KeyImage>,
}

impl SentTx {
    pub fn fee(&self) -> u64 {
        self.amount_in.saturating_sub(self.amount_out)
    }

    /// What left the account: what went in, less the change and the fee, as
    /// `get_transfers` reports it.
    pub fn amount(&self) -> u64 {
        self.amount_out.saturating_sub(self.change)
    }

    /// The height of the block it is in.
    pub fn height(&self) -> Option<u64> {
        match self.state {
            SentState::Confirmed(h) => Some(h),
            _ => None,
        }
    }
}

/// What a history entry is: `transfer_view::type` in the C++.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    In,
    Coinbase,
    Out,
    Pending,
    Failed,
}

impl EntryKind {
    /// The name `show_transfers` and `get_transfers` give it.
    pub fn name(self) -> &'static str {
        match self {
            EntryKind::In => "in",
            EntryKind::Coinbase => "block",
            EntryKind::Out => "out",
            EntryKind::Pending => "pending",
            EntryKind::Failed => "failed",
        }
    }
}

/// One entry in the transfer history: a payment received, or a transaction
/// sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    pub kind: EntryKind,
    pub txid: Hash256,
    /// `None` until a block carries it.
    pub height: Option<u64>,
    pub timestamp: u64,
    /// Received: the total to one subaddress. Sent: what left the account.
    pub amount: u64,
    /// Received: each output's amount.
    pub amounts: Vec<u64>,
    pub fee: u64,
    pub destinations: Vec<SentDestination>,
    pub payment_id: Option<[u8; 8]>,
    pub account: u32,
    /// Received: the subaddress it came in on. Sent: the ones it spent from.
    pub minors: Vec<u32>,
    pub unlock_time: u64,
}

impl HistoryEntry {
    /// Whether it is spendable; never, before a block carries it.
    pub fn unlocked(&self, chain_height: u64, now: u64) -> bool {
        self.height
            .is_some_and(|h| unlocked_at(self.unlock_time, h, chain_height, now))
    }
}

/// The key `wallet2` files a payment under, a `crypto::hash`: an encrypted
/// id's eight bytes and 24 zeros, or all zeros for none.
pub fn payment_key(payment_id: Option<[u8; 8]>) -> [u8; 32] {
    let mut key = [0u8; 32];
    if let Some(id) = payment_id {
        key[..8].copy_from_slice(&id);
    }
    key
}

/// A payment id as `wallet2::parse_payment_id` reads one: 64 hex characters,
/// or 16 that stand for the first eight bytes of 64.
///
/// A long id with anything past its first eight bytes names no payment this
/// wallet keeps: it reads only encrypted ids, and the C++ ignores plain ones
/// from block version 12.
pub fn parse_payment_key(text: &str) -> Option<[u8; 32]> {
    let bytes = wow_crypto::hex::decode(text)?;
    match bytes.len() {
        32 => bytes.try_into().ok(),
        8 => Some(payment_key(bytes.try_into().ok())),
        _ => None,
    }
}

/// A transaction waiting in the daemon's pool.
#[derive(Clone, Debug)]
pub struct PooledTx {
    pub txid: Hash256,
    pub tx: Transaction,
    /// When the daemon received it, or zero if it did not say.
    pub receive_time: u64,
}

/// What a transaction in a block showed about this wallet's spending.
pub(crate) struct SeenSpend {
    pub txid: Hash256,
    pub height: u64,
    pub timestamp: u64,
    /// The total of this wallet's outputs it spent.
    pub spent: u64,
    /// What it paid back to the account those came from.
    pub received: u64,
    pub fee: u64,
    pub unlock_time: u64,
    pub account: u32,
    pub minors: Vec<u32>,
    pub key_images: Vec<KeyImage>,
}

impl WalletState {
    /// Write down a transaction this wallet has just handed to a daemon, and
    /// spend its inputs: `wallet2::commit_tx`.
    ///
    /// The inputs are spent from the moment the daemon has the transaction,
    /// not from when a block carries it. Otherwise a second send before the
    /// first is mined picks the same outputs, and the daemon refuses it as a
    /// double spend.
    ///
    /// `payees` are the destination addresses, in the order of `plan.amounts`.
    /// With `store-tx-info` off, pass none, and no payment id.
    pub fn record_sent(
        &mut self,
        txid: Hash256,
        plan: &SpendPlan,
        payees: &[&str],
        payment_id: Option<[u8; 8]>,
        now: u64,
    ) {
        let mut amount_in = 0u64;
        let mut minors = Vec::new();
        let mut key_images = Vec::new();
        for &i in &plan.inputs {
            let t = &mut self.transfers[i];
            t.spent = true;
            t.spent_height = 0;
            amount_in += t.amount;
            minors.push(t.subaddress.minor);
            key_images.extend(t.key_image);
        }
        minors.sort_unstable();
        minors.dedup();
        let account = plan
            .inputs
            .first()
            .map_or(0, |&i| self.transfers[i].subaddress.major);

        let record = SentTx {
            txid,
            state: SentState::Pending,
            amount_in,
            amount_out: amount_in.saturating_sub(plan.fee),
            change: plan.change,
            destinations: payees
                .iter()
                .zip(&plan.amounts)
                .map(|(address, &amount)| SentDestination {
                    address: address.to_string(),
                    amount,
                })
                .collect(),
            payment_id,
            timestamp: now,
            // Never zero, which would read as "found in a block".
            sent_time: now.max(1),
            unlock_time: 0,
            account,
            minors,
            key_images,
        };
        match self.sent.iter_mut().find(|s| s.txid == txid) {
            Some(s) => *s = record,
            None => self.sent.push(record),
        }
    }

    /// `process_unconfirmed_transfer`, for every sent transaction not yet in a
    /// block, given the hashes in the daemon's pool.
    ///
    /// One in the pool is pending, and its inputs spent, even if it was judged
    /// failed before. One missing from the pool for longer than
    /// [`PROPAGATION_TIMEOUT`] has failed, and its inputs are spendable again.
    /// Returns the ones that failed just now.
    ///
    /// Call it only when a refresh has caught up. A transaction missing from
    /// the pool may be in a block the wallet has not read yet, and judging it
    /// failed then would hand its inputs back to be spent twice.
    pub fn update_pending(&mut self, pool: &HashSet<Hash256>, now: u64) -> Vec<Hash256> {
        let mut failed = Vec::new();
        let mut unspend = Vec::new();
        for s in &mut self.sent {
            if s.height().is_some() {
                continue;
            }
            if pool.contains(&s.txid) {
                s.state = SentState::Pending;
            } else if s.state == SentState::Pending
                && now > s.sent_time.saturating_add(PROPAGATION_TIMEOUT)
            {
                s.state = SentState::Failed;
                unspend.extend_from_slice(&s.key_images);
                failed.push(s.txid);
            }
        }
        // Given back first, then spent again for everything still waiting, so
        // an output named by a failed transaction and a pending one stays
        // spent.
        self.set_inputs_spent(&unspend, false);
        self.spend_pending_inputs();
        failed
    }

    /// Pool transactions that spend this wallet's outputs and were not sent
    /// from here: sent by another copy of the wallet, or by this one before a
    /// restore. `wallet2::process_new_transaction` for a pool transaction,
    /// which adds such a one to `m_unconfirmed_txs` as though it had been
    /// sent.
    ///
    /// Each is recorded as a pending send, and its inputs spent, so the next
    /// transaction does not pick them and get refused as a double spend. From
    /// then on it is a pending send like any other: confirmed by the block
    /// that carries it, or failed once gone from the pool for
    /// [`PROPAGATION_TIMEOUT`], which gives its inputs back.
    ///
    /// Unlike [`update_pending`](Self::update_pending) this is safe without a
    /// refresh, because it only ever spends. Returns the transactions recorded
    /// just now.
    pub fn note_pool_spends(&mut self, pool: &[PooledTx], now: u64) -> Vec<Hash256> {
        let mut noted = Vec::new();
        for p in pool {
            if self.sent.iter().any(|s| s.txid == p.txid) {
                continue;
            }
            let mut amount_in = 0u64;
            let mut account = None;
            let mut minors = Vec::new();
            let mut key_images = Vec::new();
            for input in &p.tx.prefix.vin {
                let TxIn::ToKey { k_image, .. } = input else {
                    continue;
                };
                let Some(&i) = self.by_key_image.get(k_image) else {
                    continue;
                };
                let t = &self.transfers[i];
                amount_in += t.amount;
                account = Some(t.subaddress.major);
                minors.push(t.subaddress.minor);
                key_images.push(*k_image);
            }
            let Some(account) = account else {
                continue;
            };
            minors.sort_unstable();
            minors.dedup();

            // What it pays back to the account it spends from is change.
            let change = scan_transaction(&p.tx, &self.keys())
                .unwrap_or_default()
                .iter()
                .filter(|r| r.subaddress.major == account)
                .map(|r| r.amount)
                .sum();
            let fee = p.tx.fee().unwrap_or(0);
            self.sent.push(SentTx {
                txid: p.txid,
                state: SentState::Pending,
                amount_in,
                amount_out: amount_in.saturating_sub(fee),
                change,
                destinations: Vec::new(),
                payment_id: None,
                timestamp: if p.receive_time > 0 {
                    p.receive_time
                } else {
                    now
                },
                // Never zero, which would read as "found in a block".
                sent_time: now.max(1),
                unlock_time: p.tx.prefix.unlock_time,
                account,
                minors,
                key_images,
            });
            noted.push(p.txid);
        }
        self.spend_pending_inputs();
        noted
    }

    /// The change still to come back from transactions not yet in a block.
    pub fn pending_change(&self) -> u64 {
        self.sent
            .iter()
            .filter(|s| s.state == SentState::Pending)
            .map(|s| s.change)
            .sum()
    }

    /// The transfer history: what is in a block first, by height and then by
    /// time, and then what is not. `simple_wallet::get_transfers`.
    ///
    /// Payments received are one entry per transaction and subaddress. An
    /// output paid back to the account a transaction spent from is change, not
    /// a payment, and is left out, as `process_new_transaction` leaves it out.
    pub fn history(&self) -> Vec<HistoryEntry> {
        let spent_from: HashMap<Hash256, u32> =
            self.sent.iter().map(|s| (s.txid, s.account)).collect();

        let mut entries: Vec<HistoryEntry> = Vec::new();
        let mut by_payment: HashMap<(Hash256, u32, u32), usize> = HashMap::new();
        for t in &self.transfers {
            if spent_from.get(&t.txid) == Some(&t.subaddress.major) {
                continue;
            }
            let key = (t.txid, t.subaddress.major, t.subaddress.minor);
            if let Some(&i) = by_payment.get(&key) {
                entries[i].amount += t.amount;
                entries[i].amounts.push(t.amount);
                continue;
            }
            by_payment.insert(key, entries.len());
            entries.push(HistoryEntry {
                kind: if t.is_coinbase {
                    EntryKind::Coinbase
                } else {
                    EntryKind::In
                },
                txid: t.txid,
                height: Some(t.block_height),
                timestamp: t.timestamp,
                amount: t.amount,
                amounts: vec![t.amount],
                fee: 0,
                destinations: Vec::new(),
                payment_id: t.payment_id,
                account: t.subaddress.major,
                minors: vec![t.subaddress.minor],
                unlock_time: t.unlock_time,
            });
        }

        for s in &self.sent {
            entries.push(HistoryEntry {
                kind: match s.state {
                    SentState::Pending => EntryKind::Pending,
                    SentState::Failed => EntryKind::Failed,
                    SentState::Confirmed(_) => EntryKind::Out,
                },
                txid: s.txid,
                height: s.height(),
                timestamp: s.timestamp,
                amount: s.amount(),
                amounts: Vec::new(),
                fee: s.fee(),
                destinations: s.destinations.clone(),
                payment_id: s.payment_id,
                account: s.account,
                minors: s.minors.clone(),
                unlock_time: s.unlock_time,
            });
        }

        entries.sort_by_key(|e| (e.height.is_none(), e.height.unwrap_or(0), e.timestamp));
        entries
    }

    /// Payments received in blocks above `min_height`: `wallet2::get_payments`.
    /// One per transaction and subaddress, as [`Self::history`] has them, change
    /// left out. [`payment_key`] says which id each was filed under.
    pub fn payments(&self, min_height: u64) -> Vec<HistoryEntry> {
        self.history()
            .into_iter()
            .filter(|e| matches!(e.kind, EntryKind::In | EntryKind::Coinbase))
            .filter(|e| e.height.is_some_and(|h| h > min_height))
            .collect()
    }

    /// A block spent outputs of ours: `process_unconfirmed` and
    /// `process_outgoing`. A transaction sent from here is confirmed; one that
    /// was not is recorded from what the block shows.
    pub(crate) fn spend_seen(&mut self, seen: SeenSpend) {
        let i = match self.sent.iter().position(|s| s.txid == seen.txid) {
            Some(i) => i,
            None => {
                self.sent.push(SentTx {
                    txid: seen.txid,
                    state: SentState::Confirmed(seen.height),
                    amount_in: seen.spent,
                    amount_out: seen.spent.saturating_sub(seen.fee),
                    change: seen.received,
                    destinations: Vec::new(),
                    payment_id: None,
                    timestamp: seen.timestamp,
                    sent_time: 0,
                    unlock_time: seen.unlock_time,
                    account: seen.account,
                    minors: seen.minors,
                    key_images: seen.key_images,
                });
                self.sent.len() - 1
            }
        };
        let s = &mut self.sent[i];
        s.state = SentState::Confirmed(seen.height);
        s.timestamp = seen.timestamp;
        s.unlock_time = seen.unlock_time;
        // Sent to itself: nothing left but the fee, so it shows as nothing sent
        // rather than as the whole of its inputs.
        if seen.spent == seen.received + seen.fee {
            s.change = seen.received;
        }
    }

    /// The blocks from `height` up are gone.
    ///
    /// A transaction sent from here that was in one is pending again, and holds
    /// its inputs as it did when first sent. One only ever seen in a block is
    /// forgotten, until a block shows it again.
    pub(crate) fn detach_sent(&mut self, height: u64) {
        self.sent.retain_mut(|s| match s.state {
            SentState::Confirmed(h) if h >= height => {
                if s.sent_time == 0 {
                    return false;
                }
                s.state = SentState::Pending;
                s.timestamp = s.sent_time;
                true
            }
            _ => true,
        });
        self.spend_pending_inputs();
    }

    /// Spend the inputs of every transaction still waiting for a block.
    fn spend_pending_inputs(&mut self) {
        let pending: Vec<KeyImage> = self
            .sent
            .iter()
            .filter(|s| s.state == SentState::Pending)
            .flat_map(|s| s.key_images.iter().copied())
            .collect();
        self.set_inputs_spent(&pending, true);
    }

    /// Whether a transaction still waiting for a block spends this output.
    pub(crate) fn is_pending_input(&self, image: &KeyImage) -> bool {
        self.sent
            .iter()
            .any(|s| s.state == SentState::Pending && s.key_images.contains(image))
    }

    /// Mark outputs spent by a transaction not yet in a block, or not spent by
    /// it after all. A spend a block recorded is left alone.
    fn set_inputs_spent(&mut self, images: &[KeyImage], spent: bool) {
        for image in images {
            let Some(&i) = self.by_key_image.get(image) else {
                continue;
            };
            let t = &mut self.transfers[i];
            if spent && !t.spent {
                t.spent = true;
                t.spent_height = 0;
            } else if !spent && t.spent && t.spent_height == 0 {
                t.spent = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountBase;
    use crate::refresh::Transfer;
    use crate::subaddress::SubaddressTable;
    use wow_crypto::types::{KeyDerivation, PublicKey, SecretKey, SubaddressIndex};

    const SENT: u64 = 1_700_000_000;

    /// A wallet holding one output of 10,000, received at height 5.
    fn wallet() -> WalletState {
        let spend = SecretKey(wow_crypto::ops::sc_reduce32(&[7u8; 32]));
        let account = AccountBase::from_spend_key(spend, 0).expect("keys");
        let table = SubaddressTable::new(
            &account.keys.account_address,
            &account.keys.view_secret_key,
            1,
            1,
        );
        let mut w = WalletState::new(account, table, 0, wow_types::Network::Mainnet);
        w.transfers.push(Transfer {
            block_height: 5,
            txid: [1u8; 32],
            internal_output_index: 0,
            global_output_index: 0,
            public_key: PublicKey::ZERO,
            derivation: KeyDerivation::ZERO,
            key_image: Some(KeyImage([9u8; 32])),
            mask: [0u8; 32],
            amount: 10_000,
            subaddress: SubaddressIndex::MAIN,
            spent: false,
            spent_height: 0,
            unlock_time: 0,
            is_coinbase: false,
            timestamp: 1_600_000_000,
            payment_id: None,
            frozen: false,
        });
        w.by_key_image.insert(KeyImage([9u8; 32]), 0);
        w
    }

    /// Send 7,000 of it, with a fee of 500 and 2,500 change.
    fn send(w: &mut WalletState) -> Hash256 {
        let plan = SpendPlan {
            inputs: vec![0],
            amounts: vec![7_000],
            change: 2_500,
            fee: 500,
            estimated_weight: 0,
            sweep: false,
            left_behind: 0,
        };
        let txid = [2u8; 32];
        w.record_sent(txid, &plan, &["Wo1payee"], Some([3u8; 8]), SENT);
        txid
    }

    #[test]
    fn a_send_spends_its_inputs_and_counts_its_change() {
        let mut w = wallet();
        send(&mut w);

        assert!(w.transfers[0].spent);
        assert_eq!(w.transfers[0].spent_height, 0, "not in a block yet");
        assert_eq!(w.balance(), 2_500, "the change on its way back");
        assert_eq!(w.unlocked_balance(100, SENT), 0, "but not spendable yet");

        let s = &w.sent[0];
        assert_eq!(s.state, SentState::Pending);
        assert_eq!(
            (s.amount_in, s.amount_out, s.fee(), s.amount()),
            (10_000, 9_500, 500, 7_000)
        );
    }

    /// In the pool, a send waits. Missing from it past the timeout, it has
    /// failed and its input is back. Seen in the pool again, it waits again.
    #[test]
    fn a_send_missing_from_the_pool_fails_after_the_timeout() {
        let mut w = wallet();
        let txid = send(&mut w);
        let in_pool: HashSet<Hash256> = [txid].into();
        let empty = HashSet::new();

        assert!(w.update_pending(&in_pool, SENT + 10_000).is_empty());
        assert_eq!(w.sent[0].state, SentState::Pending, "the pool has it");

        assert!(w
            .update_pending(&empty, SENT + PROPAGATION_TIMEOUT)
            .is_empty());
        assert_eq!(w.sent[0].state, SentState::Pending, "not yet");

        assert_eq!(
            w.update_pending(&empty, SENT + PROPAGATION_TIMEOUT + 1),
            vec![txid]
        );
        assert_eq!(w.sent[0].state, SentState::Failed);
        assert!(!w.transfers[0].spent, "its input is back");
        assert_eq!(w.balance(), 10_000, "and no change is expected");

        w.update_pending(&in_pool, SENT + 20_000);
        assert_eq!(
            w.sent[0].state,
            SentState::Pending,
            "it turned up after all"
        );
        assert!(w.transfers[0].spent);
    }

    /// A pool transaction this wallet did not send, spending one of its
    /// outputs, holds that output as a send from here would: spent at once,
    /// pending until a block, and given back once it has been gone from the
    /// pool past the timeout. This is what stops a restored wallet offering an
    /// output another copy has already spent, and the daemon refusing it.
    #[test]
    fn a_spend_in_the_pool_not_sent_from_here_holds_its_input() {
        let mut w = wallet();
        let spending = |image: [u8; 32]| {
            let mut tx = Transaction::default();
            tx.prefix.version = 2;
            tx.prefix.vin = vec![TxIn::ToKey {
                amount: 0,
                key_offsets: vec![1],
                k_image: KeyImage(image),
            }];
            tx
        };
        let ours = [6u8; 32];
        let pool = vec![
            PooledTx {
                txid: ours,
                tx: spending([9u8; 32]),
                receive_time: SENT - 20,
            },
            PooledTx {
                txid: [7u8; 32],
                tx: spending([1u8; 32]),
                receive_time: SENT,
            },
        ];

        assert_eq!(
            w.note_pool_spends(&pool, SENT),
            vec![ours],
            "only the one spending our output"
        );
        assert!(w.transfers[0].spent, "held by the pool transaction");
        assert_eq!(w.transfers[0].spent_height, 0);
        assert_eq!(w.balance(), 0);
        let s = &w.sent[0];
        assert_eq!((s.state, s.amount_in), (SentState::Pending, 10_000));
        assert_eq!(s.timestamp, SENT - 20, "when the daemon received it");
        assert!(s.destinations.is_empty(), "the pool does not say where");

        assert!(w.note_pool_spends(&pool, SENT + 60).is_empty(), "not twice");
        assert_eq!(w.sent.len(), 1);

        let in_pool: HashSet<Hash256> = [ours].into();
        assert!(w.update_pending(&in_pool, SENT + 10_000).is_empty());
        assert!(w.transfers[0].spent, "still waiting");

        assert_eq!(w.update_pending(&HashSet::new(), SENT + 10_001), vec![ours]);
        assert!(
            !w.transfers[0].spent,
            "gone from the pool: the output is back"
        );
        assert_eq!(w.balance(), 10_000);
    }

    /// A payment in, a send out with where it went, and the send's change left
    /// out of the payments.
    #[test]
    fn the_history_leaves_change_out_of_payments() {
        let mut w = wallet();
        let txid = send(&mut w);
        let change = Transfer {
            txid,
            block_height: 9,
            amount: 2_500,
            key_image: Some(KeyImage([8u8; 32])),
            ..w.transfers[0].clone()
        };
        w.transfers.push(change);
        w.sent[0].state = SentState::Confirmed(9);

        let h = w.history();
        assert_eq!(h.len(), 2, "{h:?}");
        assert_eq!((h[0].kind, h[0].amount), (EntryKind::In, 10_000));
        assert_eq!(
            (h[1].kind, h[1].amount, h[1].fee),
            (EntryKind::Out, 7_000, 500)
        );
        assert_eq!(h[1].destinations[0].address, "Wo1payee");
        assert_eq!(h[1].payment_id, Some([3u8; 8]));
    }

    /// `get_payments`: the payments in, change left out, above a height, filed
    /// under the key `wallet2` files them under.
    #[test]
    fn payments_are_found_by_payment_id() {
        let mut w = wallet();
        w.transfers[0].payment_id = Some([4u8; 8]);
        let txid = send(&mut w);
        let change = Transfer {
            txid,
            block_height: 9,
            amount: 2_500,
            key_image: Some(KeyImage([8u8; 32])),
            payment_id: None,
            ..w.transfers[0].clone()
        };
        w.transfers.push(change);
        w.sent[0].state = SentState::Confirmed(9);

        let payments = w.payments(0);
        assert_eq!(payments.len(), 1, "the change is not a payment");
        assert_eq!(payments[0].payment_id, Some([4u8; 8]));
        let short = parse_payment_key("0404040404040404").expect("a short id");
        assert_eq!(payment_key(payments[0].payment_id), short);
        assert_eq!(
            parse_payment_key(&format!("{}{}", "04".repeat(8), "0".repeat(48))),
            Some(short),
            "a short id is the long id it begins"
        );
        assert_eq!(payment_key(None), [0u8; 32], "none is the null hash");
        assert!(w.payments(5).is_empty(), "above the height, not at it");

        assert_eq!(parse_payment_key("0404"), None);
        assert_eq!(parse_payment_key("not hex"), None);
    }

    /// Sent to itself, a transaction shows as nothing sent: only the fee left.
    #[test]
    fn a_send_to_self_shows_as_nothing_sent() {
        let mut w = wallet();
        w.spend_seen(SeenSpend {
            txid: [5u8; 32],
            height: 20,
            timestamp: 1_700_000_500,
            spent: 10_000,
            received: 9_500,
            fee: 500,
            unlock_time: 0,
            account: 0,
            minors: vec![0],
            key_images: vec![KeyImage([9u8; 32])],
        });
        let s = &w.sent[0];
        assert_eq!(s.state, SentState::Confirmed(20));
        assert_eq!((s.amount(), s.fee()), (0, 500));
    }
}
