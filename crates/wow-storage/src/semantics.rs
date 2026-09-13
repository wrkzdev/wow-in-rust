//! The invariants the file format cannot enforce.
//!
//! `specs/10-storage-lmdb.md` §5: "The format enforces most invariants, but
//! these are the ones the format cannot check."
//!
//! Everything here is a pure function of a block or transaction. Getting any of
//! it wrong produces a database that is *structurally* valid and silently
//! wrong — `specs/10` §5.1 puts it plainly: "Any deviation here renumbers every
//! later output and every ring reference in every later transaction becomes
//! wrong."

use wow_crypto::rct::{scalarmult8, zero_commit};
use wow_crypto::types::EcPoint;
use wow_types::{RctType, Transaction, TxIn};

/// `BlockchainDB::get_indexing_base()` — 0 for LMDB (`specs/10` §5.5).
///
/// The BerkeleyDB backend returned 1. Nothing else in the tree varies, so this
/// is a constant rather than a trait method, but it is named so the assumption
/// is visible where output indices are computed.
pub const INDEXING_BASE: u64 = 0;

/// What [`transaction_order`] yields: the transactions of a block in the order
/// ids are assigned to them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxSlot {
    /// The coinbase, which is added **first** (`specs/10` §5.1).
    Miner,
    /// A non-coinbase transaction, by its index in `block.tx_hashes`.
    Block(usize),
}

/// The order `add_block` assigns transaction ids (`specs/10` §5.1).
///
/// ```text
/// add_transaction(miner_tx)                              # THE COINBASE IS FIRST
/// for tx in txs (in block.tx_hashes order): add_transaction(tx)
/// ```
///
/// The coinbase coming first is the part that is easy to get wrong, because
/// every *other* view of a block — the blob, the Merkle tree, the RPC — treats
/// the coinbase as a separate field rather than as element zero. Here it is
/// element zero, and its outputs therefore get the lowest `output_id`s in the
/// block.
pub fn transaction_order(num_block_txs: usize) -> impl Iterator<Item = TxSlot> {
    std::iter::once(TxSlot::Miner).chain((0..num_block_txs).map(TxSlot::Block))
}

/// The next `tx_id` (`specs/10` §5.1).
///
/// `get_tx_count()` is `mdb_stat(txs_pruned).ms_entries` — a **table entry
/// count**, not a stored counter, so it cannot drift out of sync with the data.
/// `specs/10` §5.1: "Keep that property: do not cache these in `properties`."
pub const fn next_tx_id(txs_pruned_entries: u64) -> u64 {
    txs_pruned_entries
}

/// The next global `output_id` (`specs/10` §5.1).
///
/// `num_outputs()` is `mdb_stat(output_txs).ms_entries`. Dense and global
/// across the whole chain, coinbase outputs included.
pub const fn next_output_id(output_txs_entries: u64) -> u64 {
    output_txs_entries
}

/// The next `amount_index` for an amount (`specs/10` §5.1).
///
/// `mdb_cursor_count` on the dup group under `output_amounts[amount]` — i.e.
/// how many outputs of this amount already exist. Per-amount, not global.
///
/// [`INDEXING_BASE`] is 0 for LMDB, so the first output of an amount gets index
/// 0.
pub const fn next_amount_index(existing_outputs_of_amount: u64) -> u64 {
    existing_outputs_of_amount + INDEXING_BASE
}

/// The height a block will be stored at: `mdb_stat(blocks).ms_entries`.
pub const fn next_height(blocks_entries: u64) -> u64 {
    blocks_entries
}

/// How one output is stored (`specs/10` §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredOutput {
    /// The amount written into the `output_amounts` **key**.
    ///
    /// Not always the output's own amount: a v2 coinbase output is filed under
    /// **zero**.
    pub amount: u64,
    /// `None` for a v1 output, which is stored in the 64-byte `pre_rct_outkey`
    /// form (`specs/10` §4.5).
    pub commitment: Option<EcPoint>,
}

impl StoredOutput {
    /// Which of the two `output_amounts` record lengths this output takes.
    pub const fn record_len(&self) -> usize {
        if self.commitment.is_some() {
            96
        } else {
            64
        }
    }
}

/// Why an output could not be prepared for storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// A v2 transaction has fewer `out_pk` entries than outputs.
    MissingOutPk { index: usize },
    /// An RCT type 8 commitment did not decode, so it cannot be multiplied by
    /// eight. The C++ throws here.
    UndecodableCommitment { index: usize },
}

/// `BlockchainDB::add_transaction`'s output rules
/// (`blockchain_db.cpp:206`, `specs/10` §5.2).
///
/// ```text
/// if is_miner_tx && tx.version == 2 {
///     commitment = zero_commit(vout[i].amount)   // identity mask
///     stored_amount = 0                          // <-- the amount is ZEROED
/// } else if tx.version > 1 {
///     commitment = tx.rct.out_pk[i].mask
///     if rct type == 8 { commitment = scalarmult8(commitment) }
///     stored_amount = vout[i].amount             // always 0 for a v2 tx
/// } else {
///     no commitment
///     stored_amount = vout[i].amount
/// }
/// ```
///
/// Three things `specs/10` §5.2 calls out, all of them live:
///
/// 1. **A v2 coinbase output is filed under amount 0** with an identity-mask
///    commitment, so it joins the RingCT output set and can be chosen as a
///    decoy. This is why the dup count under `output_amounts[0]` — which
///    [`crate::semantics::next_amount_index`] reads, and which decides
///    mixability in `specs/06` §5.3 — includes coinbase outputs.
/// 2. **The stored commitment is always the full `C`, never `C/8`.** RCT type 8
///    serialises `outPk.mask` as `C/8`, so it is multiplied by 8 on the way in;
///    type 9 already holds `C`.
/// 3. `zero_commit(a) = a*H + 1*G`.
pub fn stored_outputs(tx: &Transaction) -> Result<Vec<StoredOutput>, StoreError> {
    let is_miner = matches!(tx.prefix.vin.first(), Some(TxIn::Gen { .. }));
    let version = tx.prefix.version;
    let mut out = Vec::with_capacity(tx.prefix.vout.len());

    for (i, o) in tx.prefix.vout.iter().enumerate() {
        if is_miner && version == 2 {
            out.push(StoredOutput {
                amount: 0,
                commitment: Some(zero_commit(o.amount)),
            });
        } else if version > 1 {
            let mask = *tx
                .rct_signatures
                .out_pk
                .get(i)
                .ok_or(StoreError::MissingOutPk { index: i })?;
            let commitment = if tx.rct_signatures.ty == RctType::BulletproofPlus {
                scalarmult8(&mask).ok_or(StoreError::UndecodableCommitment { index: i })?
            } else {
                mask
            };
            out.push(StoredOutput {
                amount: o.amount,
                commitment: Some(commitment),
            });
        } else {
            out.push(StoredOutput {
                amount: o.amount,
                commitment: None,
            });
        }
    }
    Ok(out)
}

/// The key images a transaction contributes to `spent_keys`.
///
/// `txin_gen` contributes nothing (`specs/10` §5.1), which is why a coinbase
/// adds no spent keys despite being added first.
pub fn spent_key_images(tx: &Transaction) -> impl Iterator<Item = &[u8; 32]> {
    tx.prefix.vin.iter().filter_map(|i| match i {
        TxIn::ToKey { k_image, .. } => Some(k_image.as_bytes()),
        _ => None,
    })
}

/// The two halves `txs_pruned` and `txs_prunable` store (`specs/10` §4.8).
///
/// The split is at `unprunable_size`, which `wow-types` records during parsing.
/// `specs/10` §4.8: "In Rust, record both offsets during parsing and carry them
/// on the transaction — **never re-serialize**."
pub fn split_tx_blob(blob: &[u8], unprunable_size: usize) -> Option<(&[u8], &[u8])> {
    (unprunable_size <= blob.len()).then(|| blob.split_at(unprunable_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wow_types::{PublicKey, TransactionPrefix, TxOut, TxOutTarget, ViewTag};

    fn tx(version: u64, vin: Vec<TxIn>, amounts: &[u64]) -> Transaction {
        Transaction {
            prefix: TransactionPrefix {
                version,
                unlock_time: 0,
                vin,
                vout: amounts
                    .iter()
                    .enumerate()
                    .map(|(i, a)| TxOut {
                        amount: *a,
                        target: TxOutTarget::ToTaggedKey {
                            key: PublicKey([i as u8; 32]),
                            view_tag: ViewTag(i as u8),
                        },
                    })
                    .collect(),
                extra: Vec::new(),
            },
            signatures: Vec::new(),
            rct_signatures: Default::default(),
            prefix_size: 0,
            unprunable_size: 0,
        }
    }

    fn coinbase(version: u64, amounts: &[u64]) -> Transaction {
        tx(version, vec![TxIn::Gen { height: 100 }], amounts)
    }

    fn key_image(n: u8) -> wow_types::KeyImage {
        wow_types::KeyImage([n; 32])
    }

    /// `specs/10` §5.1: the coinbase is added **first**, before any block
    /// transaction, so its outputs take the lowest ids in the block.
    #[test]
    fn the_coinbase_is_first() {
        let order: Vec<TxSlot> = transaction_order(3).collect();
        assert_eq!(
            order,
            vec![
                TxSlot::Miner,
                TxSlot::Block(0),
                TxSlot::Block(1),
                TxSlot::Block(2)
            ]
        );
        assert_eq!(order[0], TxSlot::Miner, "the coinbase must be first");

        // A block with no other transactions still has its coinbase.
        assert_eq!(
            transaction_order(0).collect::<Vec<_>>(),
            vec![TxSlot::Miner]
        );
    }

    /// The ids are table entry counts, so the first of each is 0 and they are
    /// dense.
    #[test]
    fn ids_are_dense_counts_from_zero() {
        assert_eq!(next_height(0), 0, "the genesis block is height 0");
        assert_eq!(next_tx_id(0), 0);
        assert_eq!(next_output_id(0), 0);
        assert_eq!(next_amount_index(0), 0);
        assert_eq!(INDEXING_BASE, 0, "LMDB's indexing base; BerkeleyDB used 1");

        assert_eq!(next_height(514_000), 514_000);
        assert_eq!(next_output_id(9_999_999), 9_999_999);
        assert_eq!(next_amount_index(21), 21);
    }

    /// `specs/10` §5.2 case 1: **a v2 coinbase output is filed under amount 0**,
    /// with an identity-mask commitment — so it lands in the RingCT output set
    /// and can be picked as a decoy.
    #[test]
    fn a_v2_coinbase_output_is_stored_under_amount_zero() {
        let amount = 12_012_972_872_950u64; // a real Wownero block reward
        let cb = coinbase(2, &[amount]);
        let stored = stored_outputs(&cb).unwrap();

        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].amount, 0,
            "the amount is zeroed, not carried through"
        );
        assert_ne!(stored[0].amount, amount);
        assert_eq!(
            stored[0].commitment,
            Some(zero_commit(amount)),
            "the commitment still encodes the real amount"
        );
        assert_eq!(stored[0].record_len(), 96, "the RingCT record form");
    }

    /// A v1 coinbase is *not* rewritten: it keeps its amount and gets no
    /// commitment. The rule is gated on `tx.version == 2`.
    #[test]
    fn a_v1_coinbase_keeps_its_amount_and_has_no_commitment() {
        let amount = 17_592_184_995_840u64;
        let cb = coinbase(1, &[amount]);
        let stored = stored_outputs(&cb).unwrap();

        assert_eq!(stored[0].amount, amount);
        assert_eq!(stored[0].commitment, None);
        assert_eq!(stored[0].record_len(), 64, "the pre-RingCT record form");
    }

    /// Each coinbase output is committed to separately, so a multi-output
    /// coinbase produces distinct commitments.
    #[test]
    fn every_coinbase_output_commits_to_its_own_amount() {
        let cb = coinbase(2, &[100, 200, 100]);
        let stored = stored_outputs(&cb).unwrap();

        assert!(stored.iter().all(|s| s.amount == 0));
        assert_eq!(stored[0].commitment, Some(zero_commit(100)));
        assert_eq!(stored[1].commitment, Some(zero_commit(200)));
        assert_eq!(
            stored[0].commitment, stored[2].commitment,
            "equal amounts commit equally -- the mask is the identity"
        );
        assert_ne!(stored[0].commitment, stored[1].commitment);
    }

    /// `specs/10` §5.2 case 2: RCT type 8 serialises `C/8`, so the stored value
    /// must be multiplied by eight. Storing the serialised value instead gives
    /// a commitment that fails every sum check.
    #[test]
    fn rct_type_8_commitments_are_multiplied_by_eight() {
        let mask = EcPoint(wow_crypto::rct::H);
        let mut t = tx(
            2,
            vec![TxIn::ToKey {
                amount: 0,
                key_offsets: vec![1; 22],
                k_image: key_image(1),
            }],
            &[0],
        );
        t.rct_signatures.ty = RctType::BulletproofPlus;
        t.rct_signatures.out_pk = vec![mask];

        let stored = stored_outputs(&t).unwrap();
        assert_eq!(
            stored[0].commitment,
            scalarmult8(&mask),
            "type 8 stores 8 * the serialised mask"
        );
        assert_ne!(stored[0].commitment, Some(mask), "not the raw value");
    }

    /// Type 9 already holds the full `C`, so it is stored as-is. Multiplying it
    /// too would be just as wrong as not multiplying type 8.
    #[test]
    fn rct_type_9_commitments_are_stored_unchanged() {
        let mask = EcPoint(wow_crypto::rct::H);
        let mut t = tx(
            2,
            vec![TxIn::ToKey {
                amount: 0,
                key_offsets: vec![1; 22],
                k_image: key_image(1),
            }],
            &[0],
        );
        t.rct_signatures.ty = RctType::BulletproofPlusFullCommit;
        t.rct_signatures.out_pk = vec![mask];

        let stored = stored_outputs(&t).unwrap();
        assert_eq!(stored[0].commitment, Some(mask), "stored verbatim");
        assert_ne!(stored[0].commitment, scalarmult8(&mask));
    }

    /// CLSAG (type 7) and the bulletproof types also store the mask unchanged —
    /// only type 8 is special.
    #[test]
    fn only_type_8_is_multiplied() {
        let mask = EcPoint(wow_crypto::rct::H);
        for ty in [
            RctType::Bulletproof,
            RctType::Bulletproof2,
            RctType::Clsag,
            RctType::BulletproofPlusFullCommit,
        ] {
            let mut t = tx(
                2,
                vec![TxIn::ToKey {
                    amount: 0,
                    key_offsets: vec![1; 22],
                    k_image: key_image(1),
                }],
                &[0],
            );
            t.rct_signatures.ty = ty;
            t.rct_signatures.out_pk = vec![mask];
            assert_eq!(
                stored_outputs(&t).unwrap()[0].commitment,
                Some(mask),
                "{ty:?} must not be multiplied"
            );
        }
    }

    /// A v2 transaction with no `out_pk` for an output is an error, not a
    /// panic — a truncated record must not take the node down.
    #[test]
    fn a_missing_out_pk_is_an_error() {
        let mut t = tx(
            2,
            vec![TxIn::ToKey {
                amount: 0,
                key_offsets: vec![1; 22],
                k_image: key_image(1),
            }],
            &[0, 0],
        );
        t.rct_signatures.ty = RctType::Clsag;
        t.rct_signatures.out_pk = vec![EcPoint(wow_crypto::rct::H)]; // one short

        assert_eq!(
            stored_outputs(&t),
            Err(StoreError::MissingOutPk { index: 1 })
        );
    }

    /// An undecodable type 8 commitment is an error too. The C++ throws here.
    #[test]
    fn an_undecodable_type_8_commitment_is_an_error() {
        let mut t = tx(
            2,
            vec![TxIn::ToKey {
                amount: 0,
                key_offsets: vec![1; 22],
                k_image: key_image(1),
            }],
            &[0],
        );
        t.rct_signatures.ty = RctType::BulletproofPlus;
        t.rct_signatures.out_pk = vec![EcPoint([0xff; 32])];

        assert_eq!(
            stored_outputs(&t),
            Err(StoreError::UndecodableCommitment { index: 0 })
        );
    }

    /// `specs/10` §5.1: `txin_gen` contributes no key image, so a coinbase adds
    /// nothing to `spent_keys` even though it is added first.
    #[test]
    fn a_coinbase_contributes_no_spent_keys() {
        let cb = coinbase(2, &[100]);
        assert_eq!(spent_key_images(&cb).count(), 0);

        let spend = tx(
            2,
            vec![
                TxIn::ToKey {
                    amount: 0,
                    key_offsets: vec![1; 22],
                    k_image: key_image(7),
                },
                TxIn::ToKey {
                    amount: 0,
                    key_offsets: vec![1; 22],
                    k_image: key_image(3),
                },
            ],
            &[0, 0],
        );
        let images: Vec<&[u8; 32]> = spent_key_images(&spend).collect();
        assert_eq!(images.len(), 2);
        assert_eq!(images[0], &[7u8; 32]);
        assert_eq!(images[1], &[3u8; 32], "in input order, not sorted");
    }

    /// `specs/10` §4.8: the blob splits at `unprunable_size`, and the two halves
    /// reassemble to the original.
    #[test]
    fn the_blob_splits_at_the_unprunable_size() {
        let blob: Vec<u8> = (0..100u8).collect();
        let (pruned, prunable) = split_tx_blob(&blob, 40).unwrap();

        assert_eq!(pruned.len(), 40);
        assert_eq!(prunable.len(), 60);
        assert_eq!([pruned, prunable].concat(), blob, "no bytes lost");

        // A whole-blob split leaves an empty prunable half, which is what a
        // transaction with nothing prunable stores.
        let (pruned, prunable) = split_tx_blob(&blob, blob.len()).unwrap();
        assert_eq!(pruned.len(), 100);
        assert!(prunable.is_empty());

        // Past the end is an error rather than a panic.
        assert!(split_tx_blob(&blob, 101).is_none());
    }
}
