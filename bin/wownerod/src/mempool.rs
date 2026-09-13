//! The transaction pool (`specs/09` §2.2).
//!
//! # In memory, not on disk
//!
//! `specs/09` §2.2 describes an in-memory index backed by two persisted tables
//! so the pool survives a restart. This is the index without the tables: a
//! restart empties the pool. That is a real limitation and it is a safe one —
//! a dropped pool loses unconfirmed transactions, which senders re-broadcast,
//! where a *wrongly persisted* pool would keep serving transactions the chain
//! has moved past.
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
    /// There is no peer-to-peer layer yet, so nothing acts on it; it is
    /// reported back so a caller can see its request was understood.
    pub do_not_relay: bool,
    pub double_spend_seen: bool,
}

/// The pool.
#[derive(Default)]
pub struct TxPool {
    by_id: HashMap<Hash256, PoolEntry>,
    /// Key images spent by pooled transactions, so a second spend of the same
    /// output is caught before it is verified.
    spent: HashMap<KeyImage, Hash256>,
    weight: u64,
}

impl TxPool {
    pub fn new() -> TxPool {
        TxPool::default()
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
    ///
    /// Nothing calls this yet -- there is no miner -- but the ordering is a
    /// documented property of the pool and is cheaper to keep correct here than
    /// to reconstruct later.
    #[allow(dead_code, reason = "the block template is not built yet")]
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
        self.weight = self.weight.saturating_sub(entry.weight);
        self.spent.retain(|_, owner| owner != id);
        Some(entry)
    }

    /// Drop transactions older than `CRYPTONOTE_MEMPOOL_TX_LIVETIME`.
    pub fn expire(&mut self, now: u64) -> usize {
        let stale: Vec<Hash256> = self
            .by_id
            .iter()
            .filter(|(_, e)| now.saturating_sub(e.receive_time) > TX_LIVETIME)
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
        if self.weight <= MAX_POOL_WEIGHT {
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
            if self.weight <= MAX_POOL_WEIGHT {
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
                double_spend_seen: false,
            },
        );
        self.evict_to_fit();
        Ok(id)
    }
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
            double_spend_seen: false,
        }
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
