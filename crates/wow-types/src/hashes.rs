//! Transaction hashes.
//!
//! `specs/05-blocks-and-transactions.md` §3.
//!
//! The v2 transaction hash is a hash of three hashes taken over **slices of the
//! original blob**, not over a re-serialization. `specs/05` §9 is explicit:
//! "compute those offsets during parsing; do not re-serialize". Re-serializing
//! would also silently normalise a non-canonically encoded blob, changing its
//! hash.

use wow_crypto::hash::{cn_fast_hash, NULL_HASH};
use wow_crypto::types::Hash256;
use wow_serialize::binary::Writer;

use crate::rct::RctSignatures;
use crate::tx::{Transaction, TransactionPrefix};

/// `get_transaction_prefix_hash(tx)` = `cn_fast_hash(serialize(prefix))`.
///
/// This is the `message` for RingCT and for v1 ring signatures
/// (`specs/05` §3.1).
pub fn tx_prefix_hash(prefix: &TransactionPrefix) -> Hash256 {
    let mut w = Writer::with_capacity(256);
    prefix.write(&mut w);
    cn_fast_hash(w.as_slice())
}

/// The prefix hash taken from a parsed transaction's **original blob slice**,
/// which is what the reference hashes.
///
/// Falls back to re-serializing when no blob is supplied — correct for a
/// canonically encoded transaction, which is every transaction on chain.
pub fn tx_prefix_hash_from_blob(tx: &Transaction, blob: Option<&[u8]>) -> Hash256 {
    match blob {
        Some(b) if b.len() >= tx.prefix_size => cn_fast_hash(&b[..tx.prefix_size]),
        _ => tx_prefix_hash(&tx.prefix),
    }
}

/// `get_transaction_hash(tx)` for a transaction parsed from `blob`.
///
/// * **v1**: `cn_fast_hash(entire blob)`.
/// * **v2**: `cn_fast_hash(h0 || h1 || h2)` where
///   - `h0` = the prefix hash,
///   - `h1` = `cn_fast_hash(blob[prefix_size .. unprunable_size])` — exactly the
///     `rctSigBase` region,
///   - `h2` = the null hash when `rct.type == Null`, else the prunable hash.
///
/// Coinbase transactions from HF 15 are v2 with `rct.type == Null`, so their
/// `h2` is the null hash and their `h1` covers the single `type` byte `0x00`
/// (`specs/05` §3.2).
pub fn transaction_hash_from_blob(tx: &Transaction, blob: &[u8]) -> Option<Hash256> {
    if tx.prefix.version == 1 {
        return Some(cn_fast_hash(blob));
    }
    if blob.len() < tx.unprunable_size || tx.unprunable_size < tx.prefix_size {
        return None;
    }

    let h0 = cn_fast_hash(&blob[..tx.prefix_size]);
    let h1 = cn_fast_hash(&blob[tx.prefix_size..tx.unprunable_size]);
    let h2 = if tx.rct_signatures.ty.is_null() {
        NULL_HASH
    } else {
        cn_fast_hash(&blob[tx.unprunable_size..])
    };

    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(&h0);
    buf[32..64].copy_from_slice(&h1);
    buf[64..].copy_from_slice(&h2);
    Some(cn_fast_hash(&buf))
}

/// `get_transaction_prunable_hash(tx)` = `cn_fast_hash(blob[unprunable_size..])`.
///
/// Undefined, and unused, for `rct.type == Null` (`specs/05` §3.3).
pub fn tx_prunable_hash_from_blob(tx: &Transaction, blob: &[u8]) -> Option<Hash256> {
    if tx.rct_signatures.ty.is_null() || blob.len() < tx.unprunable_size {
        return None;
    }
    Some(cn_fast_hash(&blob[tx.unprunable_size..]))
}

/// The transaction hash for a transaction not carrying its original blob.
///
/// Re-serializes, and takes the three regions from **that** serialization.
/// This matches the reference exactly, which is less obvious than it looks:
///
/// ```cpp
/// get_transaction_prefix_hash(t, hashes[0]);
/// const blobdata blob = tx_to_blob(t);
/// const unsigned int unprunable_size = t.unprunable_size;
/// const unsigned int prefix_size = t.prefix_size;
/// ```
///
/// `tx_to_blob` runs **before** the two sizes are read, and the archive assigns
/// `prefix_size` / `unprunable_size` on *save* as well as on load
/// (`if (std::is_same<Archive<W>, binary_archive<W>>()) prefix_size = ...`), so
/// the offsets used are the re-serialization's, not the ones recorded when the
/// transaction was parsed. For a canonically encoded transaction — every one on
/// chain — the two agree.
///
/// [`transaction_hash_from_blob`] is still preferable when the original blob is
/// at hand: it avoids three re-serializations, and it is the only form that is
/// meaningful for a **pruned** transaction (the C refuses those outright:
/// `CHECK_AND_ASSERT_MES(!t.pruned, ...)`).
pub fn transaction_hash(tx: &Transaction) -> Option<Hash256> {
    let mut w = Writer::with_capacity(2048);
    tx.write(&mut w);
    let blob = w.into_vec();

    if tx.prefix.version == 1 {
        return Some(cn_fast_hash(&blob));
    }

    // Recompute the offsets from this serialization rather than trusting the
    // ones recorded at parse time, which belong to a different blob.
    let mut pw = Writer::with_capacity(256);
    tx.prefix.write(&mut pw);
    let prefix_size = pw.len();

    let unprunable_size = if tx.prefix.vin.is_empty() {
        prefix_size
    } else {
        let mut bw = Writer::with_capacity(256);
        tx.prefix.write(&mut bw);
        tx.rct_signatures.write_base(&mut bw, tx.prefix.vout.len());
        bw.len()
    };

    let shadow = Transaction {
        prefix_size,
        unprunable_size,
        ..tx.clone()
    };
    transaction_hash_from_blob(&shadow, &blob)
}

/// `get_pre_mlsag_hash(rv)` — the message every CLSAG in a transaction signs.
///
/// `src/ringct/rctSigs.cpp`. Three hashes, concatenated and hashed again:
///
/// 1. `rv.message`, which is the transaction prefix hash,
/// 2. the hash of the serialized `rctSigBase`, and
/// 3. the hash of the prunable part's group elements, **as a flat list of
///    32-byte keys** rather than as its serialized form.
///
/// The third is the one to be careful about. It is not `write_prunable`: it is
/// a specific sequence of fields with no length prefixes and no counts, and for
/// Bulletproofs+ it is `A, A1, B, r1, s1, d1, L…, R…` per proof. `V` is
/// deliberately absent — it is reconstructed from `outPk.mask`, which the
/// `rctSigBase` hash already covers.
///
/// This is why the range proof has to exist before the ring signatures can be
/// made: the proof is part of what they sign.
pub fn pre_mlsag_hash(
    message: &Hash256,
    rct: &RctSignatures,
    inputs: usize,
    outputs: usize,
) -> Hash256 {
    let mut w = Writer::with_capacity(1024);
    rct.write_base(&mut w, outputs);
    let base_hash = cn_fast_hash(w.as_slice());
    let _ = inputs;

    let mut kv = Vec::with_capacity(1024);
    if rct.ty.is_bulletproof_plus() {
        for p in &rct.bulletproofs_plus {
            kv.extend_from_slice(&p.a.0);
            kv.extend_from_slice(&p.a1.0);
            kv.extend_from_slice(&p.b.0);
            kv.extend_from_slice(&p.r1.0);
            kv.extend_from_slice(&p.s1.0);
            kv.extend_from_slice(&p.d1.0);
            for l in &p.l {
                kv.extend_from_slice(&l.0);
            }
            for r in &p.r {
                kv.extend_from_slice(&r.0);
            }
        }
    } else if rct.ty.is_bulletproof() {
        for p in &rct.bulletproofs {
            kv.extend_from_slice(&p.a.0);
            kv.extend_from_slice(&p.s.0);
            kv.extend_from_slice(&p.t1.0);
            kv.extend_from_slice(&p.t2.0);
            kv.extend_from_slice(&p.taux.0);
            kv.extend_from_slice(&p.mu.0);
            for l in &p.l {
                kv.extend_from_slice(&l.0);
            }
            for r in &p.r {
                kv.extend_from_slice(&r.0);
            }
            kv.extend_from_slice(&p.a_scalar.0);
            kv.extend_from_slice(&p.b.0);
            kv.extend_from_slice(&p.t.0);
        }
    } else {
        // Borromean range proofs: s0, s1, ee, then the 64 Ci.
        for r in &rct.range_sigs {
            for s in &r.asig_s0 {
                kv.extend_from_slice(&s.0);
            }
            for s in &r.asig_s1 {
                kv.extend_from_slice(&s.0);
            }
            kv.extend_from_slice(&r.asig_ee.0);
            for c in &r.ci {
                kv.extend_from_slice(&c.0);
            }
        }
    }
    let prunable_hash = cn_fast_hash(&kv);

    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(message);
    buf[32..64].copy_from_slice(&base_hash);
    buf[64..].copy_from_slice(&prunable_hash);
    cn_fast_hash(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rct::RctType;
    use crate::tx::{TxIn, TxOut, TxOutTarget};
    use wow_crypto::types::{KeyImage, PublicKey};

    fn v2_coinbase() -> Transaction {
        // An HF-15+ coinbase: v2, rct.type == Null, exactly one output.
        let prefix = TransactionPrefix {
            version: 2,
            unlock_time: 1000 + 288,
            vin: vec![TxIn::Gen { height: 1000 }],
            vout: vec![TxOut {
                amount: 42,
                target: TxOutTarget::ToKey {
                    key: PublicKey([7u8; 32]),
                },
            }],
            extra: vec![1, 2, 3],
        };
        let mut w = Writer::new();
        prefix.write(&mut w);
        let prefix_size = w.len();
        Transaction {
            prefix,
            signatures: Vec::new(),
            rct_signatures: crate::rct::RctSignatures::null(),
            prefix_size,
            // rctSigBase for a Null type is the single `type` byte.
            unprunable_size: prefix_size + 1,
        }
    }

    /// `specs/05` §9: a v2 coinbase hashes with `h2 = null_hash` and an `h1`
    /// covering just the `0x00` type byte.
    #[test]
    fn v2_coinbase_hash_uses_the_null_prunable_hash() {
        let tx = v2_coinbase();
        let mut w = Writer::new();
        tx.write(&mut w);
        let blob = w.into_vec();
        assert_eq!(blob.len(), tx.unprunable_size, "Null rct adds one byte");
        assert_eq!(blob[tx.prefix_size], 0x00, "the rct type byte");

        let got = transaction_hash_from_blob(&tx, &blob).unwrap();

        let h0 = cn_fast_hash(&blob[..tx.prefix_size]);
        let h1 = cn_fast_hash(&[0x00]);
        let h2 = NULL_HASH;
        let mut buf = [0u8; 96];
        buf[..32].copy_from_slice(&h0);
        buf[32..64].copy_from_slice(&h1);
        buf[64..].copy_from_slice(&h2);
        assert_eq!(got, cn_fast_hash(&buf));

        // The blob-free path must agree for a canonical blob.
        assert_eq!(transaction_hash(&tx), Some(got));
    }

    #[test]
    fn v1_hash_is_the_whole_blob() {
        let prefix = TransactionPrefix {
            version: 1,
            unlock_time: 0,
            vin: vec![TxIn::ToKey {
                amount: 5,
                key_offsets: vec![1, 2],
                k_image: KeyImage([3u8; 32]),
            }],
            vout: vec![TxOut {
                amount: 5,
                target: TxOutTarget::ToKey {
                    key: PublicKey([9u8; 32]),
                },
            }],
            extra: vec![],
        };
        let mut w = Writer::new();
        prefix.write(&mut w);
        let prefix_size = w.len();
        let tx = Transaction {
            prefix,
            signatures: vec![vec![Default::default(); 2]],
            rct_signatures: crate::rct::RctSignatures::null(),
            prefix_size,
            unprunable_size: prefix_size,
        };
        let mut w = Writer::new();
        tx.write(&mut w);
        let blob = w.into_vec();
        assert_eq!(
            transaction_hash_from_blob(&tx, &blob),
            Some(cn_fast_hash(&blob))
        );
    }

    /// The three regions must partition the blob exactly: prefix, base,
    /// prunable. An off-by-one anywhere changes the hash.
    #[test]
    fn regions_partition_the_blob() {
        let tx = v2_coinbase();
        assert!(tx.prefix_size <= tx.unprunable_size);
        let mut w = Writer::new();
        tx.write(&mut w);
        assert_eq!(w.len(), tx.unprunable_size);
    }

    #[test]
    fn prunable_hash_is_undefined_for_null_rct() {
        let tx = v2_coinbase();
        let mut w = Writer::new();
        tx.write(&mut w);
        assert_eq!(tx.rct_signatures.ty, RctType::Null);
        assert_eq!(tx_prunable_hash_from_blob(&tx, w.as_slice()), None);
    }

    #[test]
    fn prefix_hash_ignores_everything_after_the_prefix() {
        let tx = v2_coinbase();
        let mut w = Writer::new();
        tx.write(&mut w);
        let blob = w.into_vec();
        assert_eq!(
            tx_prefix_hash_from_blob(&tx, Some(&blob)),
            tx_prefix_hash(&tx.prefix)
        );
    }
}
