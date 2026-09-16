//! Transactions: inputs, outputs, the prefix, and the full transaction.
//!
//! `specs/05-blocks-and-transactions.md` §2. All layouts are the binary archive
//! (`specs/04` §1); field order is wire order and there is no framing, so
//! declaration order is part of the format.

use wow_crypto::types::{Hash256, KeyImage, PublicKey, Signature, ViewTag};
use wow_serialize::binary::{BinSerialize, Reader, Writer};
use wow_serialize::error::{Error, Result};

use crate::limits::*;
use crate::rct::{RctSignatures, RctType};

/// Variant tags for `txin_v` (`specs/04` §1.3).
pub mod txin_tag {
    pub const TO_SCRIPT: u8 = 0x00;
    pub const TO_SCRIPTHASH: u8 = 0x01;
    pub const TO_KEY: u8 = 0x02;
    /// Note this is `0xff`, not `0x03` — the coinbase input tag.
    pub const GEN: u8 = 0xff;
}

/// Variant tags for `txout_target_v` (`specs/04` §1.3).
pub mod txout_tag {
    pub const TO_SCRIPT: u8 = 0x00;
    pub const TO_SCRIPTHASH: u8 = 0x01;
    pub const TO_KEY: u8 = 0x02;
    /// HF 20+.
    pub const TO_TAGGED_KEY: u8 = 0x03;
}

/// A transaction input.
///
/// `txin_to_script` and `txin_to_scripthash` have never appeared on chain and
/// are rejected by `check_tx_inputs`, but they must still **parse** so that
/// blobs round-trip (`specs/05` §2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxIn {
    /// `txin_gen`, tag `0xff`: the coinbase input.
    Gen { height: u64 },
    /// `txin_to_key`, tag `0x02`.
    ToKey {
        amount: u64,
        /// **Relative** offsets. `absolute[0] = relative[0]`,
        /// `absolute[i] = absolute[i-1] + relative[i]`.
        key_offsets: Vec<u64>,
        k_image: KeyImage,
    },
    /// `txin_to_script`, tag `0x00`.
    ToScript {
        prev: Hash256,
        prevout: u64,
        sigset: Vec<u8>,
    },
    /// `txin_to_scripthash`, tag `0x01`.
    ToScriptHash {
        prev: Hash256,
        prevout: u64,
        script: TxOutTarget,
        sigset: Vec<u8>,
    },
}

impl TxIn {
    pub fn tag(&self) -> u8 {
        match self {
            TxIn::Gen { .. } => txin_tag::GEN,
            TxIn::ToKey { .. } => txin_tag::TO_KEY,
            TxIn::ToScript { .. } => txin_tag::TO_SCRIPT,
            TxIn::ToScriptHash { .. } => txin_tag::TO_SCRIPTHASH,
        }
    }

    /// `get_signature_size(txin)` — how many v1 ring signatures this input
    /// carries (`specs/05` §2.2).
    pub fn signature_size(&self) -> usize {
        match self {
            TxIn::Gen { .. } => 0,
            TxIn::ToKey { key_offsets, .. } => key_offsets.len(),
            TxIn::ToScript { .. } => 0,
            TxIn::ToScriptHash { .. } => 0,
        }
    }

    /// Ring size = `key_offsets.len()`; "mixin" = that minus one.
    pub fn ring_size(&self) -> Option<usize> {
        match self {
            TxIn::ToKey { key_offsets, .. } => Some(key_offsets.len()),
            _ => None,
        }
    }

    /// Convert the relative `key_offsets` to absolute global output indices.
    ///
    /// Returns `None` on overflow, which a hostile blob can trigger.
    pub fn absolute_key_offsets(&self) -> Option<Vec<u64>> {
        let TxIn::ToKey { key_offsets, .. } = self else {
            return None;
        };
        let mut out = Vec::with_capacity(key_offsets.len());
        let mut acc: u64 = 0;
        for (i, rel) in key_offsets.iter().enumerate() {
            acc = if i == 0 { *rel } else { acc.checked_add(*rel)? };
            out.push(acc);
        }
        Some(out)
    }

    fn write(&self, w: &mut Writer) {
        w.write_u8(self.tag());
        match self {
            TxIn::Gen { height } => w.write_varint(*height),
            TxIn::ToKey {
                amount,
                key_offsets,
                k_image,
            } => {
                w.write_varint(*amount);
                w.write_varint(key_offsets.len() as u64);
                for o in key_offsets {
                    w.write_varint(*o);
                }
                w.write_bytes(&k_image.0);
            }
            TxIn::ToScript {
                prev,
                prevout,
                sigset,
            } => {
                w.write_bytes(prev);
                w.write_varint(*prevout);
                w.write_bytes_prefixed(sigset);
            }
            TxIn::ToScriptHash {
                prev,
                prevout,
                script,
                sigset,
            } => {
                w.write_bytes(prev);
                w.write_varint(*prevout);
                script.write(w);
                w.write_bytes_prefixed(sigset);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<TxIn> {
        let tag = r.read_u8()?;
        Ok(match tag {
            txin_tag::GEN => TxIn::Gen {
                height: r.read_varint()?,
            },
            txin_tag::TO_KEY => {
                let amount = r.read_varint()?;
                // Each offset is at least one byte on the wire, so the
                // remaining input bounds the count.
                let n = r.read_len(r.remaining(), "key_offsets")?;
                let mut key_offsets = Vec::with_capacity(n.min(4096));
                for _ in 0..n {
                    key_offsets.push(r.read_varint()?);
                }
                TxIn::ToKey {
                    amount,
                    key_offsets,
                    k_image: KeyImage(r.read_array::<32>()?),
                }
            }
            txin_tag::TO_SCRIPT => TxIn::ToScript {
                prev: r.read_array::<32>()?,
                prevout: r.read_varint()?,
                sigset: r.read_bytes_prefixed(r.remaining(), "sigset")?.to_vec(),
            },
            txin_tag::TO_SCRIPTHASH => {
                let prev = r.read_array::<32>()?;
                let prevout = r.read_varint()?;
                let script = TxOutTarget::read(r)?;
                let sigset = r.read_bytes_prefixed(r.remaining(), "sigset")?.to_vec();
                TxIn::ToScriptHash {
                    prev,
                    prevout,
                    script,
                    sigset,
                }
            }
            other => return Err(Error::UnknownVariantTag(other)),
        })
    }
}

/// A transaction output's target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxOutTarget {
    /// `txout_to_key`, tag `0x02`.
    ToKey { key: PublicKey },
    /// `txout_to_tagged_key`, tag `0x03` — HF 20+.
    ToTaggedKey { key: PublicKey, view_tag: ViewTag },
    /// `txout_to_script`, tag `0x00`.
    ToScript {
        keys: Vec<PublicKey>,
        script: Vec<u8>,
    },
    /// `txout_to_scripthash`, tag `0x01`.
    ToScriptHash { hash: Hash256 },
}

impl TxOutTarget {
    pub fn tag(&self) -> u8 {
        match self {
            TxOutTarget::ToKey { .. } => txout_tag::TO_KEY,
            TxOutTarget::ToTaggedKey { .. } => txout_tag::TO_TAGGED_KEY,
            TxOutTarget::ToScript { .. } => txout_tag::TO_SCRIPT,
            TxOutTarget::ToScriptHash { .. } => txout_tag::TO_SCRIPTHASH,
        }
    }

    /// The one-time output public key, for the two target types that have one.
    pub fn public_key(&self) -> Option<PublicKey> {
        match self {
            TxOutTarget::ToKey { key } | TxOutTarget::ToTaggedKey { key, .. } => Some(*key),
            _ => None,
        }
    }

    pub fn view_tag(&self) -> Option<ViewTag> {
        match self {
            TxOutTarget::ToTaggedKey { view_tag, .. } => Some(*view_tag),
            _ => None,
        }
    }

    fn write(&self, w: &mut Writer) {
        w.write_u8(self.tag());
        match self {
            TxOutTarget::ToKey { key } => w.write_bytes(&key.0),
            TxOutTarget::ToTaggedKey { key, view_tag } => {
                w.write_bytes(&key.0);
                w.write_u8(view_tag.0);
            }
            TxOutTarget::ToScript { keys, script } => {
                w.write_varint(keys.len() as u64);
                for k in keys {
                    w.write_bytes(&k.0);
                }
                w.write_bytes_prefixed(script);
            }
            TxOutTarget::ToScriptHash { hash } => w.write_bytes(hash),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<TxOutTarget> {
        let tag = r.read_u8()?;
        Ok(match tag {
            txout_tag::TO_KEY => TxOutTarget::ToKey {
                key: PublicKey(r.read_array::<32>()?),
            },
            txout_tag::TO_TAGGED_KEY => {
                let key = PublicKey(r.read_array::<32>()?);
                TxOutTarget::ToTaggedKey {
                    key,
                    view_tag: ViewTag(r.read_u8()?),
                }
            }
            txout_tag::TO_SCRIPT => {
                let n = r.read_len(r.remaining() / 32, "txout keys")?;
                let mut keys = Vec::with_capacity(n.min(4096));
                for _ in 0..n {
                    keys.push(PublicKey(r.read_array::<32>()?));
                }
                TxOutTarget::ToScript {
                    keys,
                    script: r.read_bytes_prefixed(r.remaining(), "script")?.to_vec(),
                }
            }
            txout_tag::TO_SCRIPTHASH => TxOutTarget::ToScriptHash {
                hash: r.read_array::<32>()?,
            },
            other => return Err(Error::UnknownVariantTag(other)),
        })
    }
}

/// A transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub amount: u64,
    pub target: TxOutTarget,
}

impl TxOut {
    fn write(&self, w: &mut Writer) {
        w.write_varint(self.amount);
        self.target.write(w);
    }

    fn read(r: &mut Reader<'_>) -> Result<TxOut> {
        Ok(TxOut {
            amount: r.read_varint()?,
            target: TxOutTarget::read(r)?,
        })
    }
}

/// `transaction_prefix` (`specs/05` §2.1).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TransactionPrefix {
    pub version: u64,
    /// Height if `< CRYPTONOTE_MAX_BLOCK_NUMBER`, else a unix time.
    pub unlock_time: u64,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    /// Consensus-**opaque**. Parsed separately by [`crate::tx_extra`], and a
    /// parse failure there does not invalidate the transaction
    /// (`specs/05` §3.4).
    pub extra: Vec<u8>,
}

impl TransactionPrefix {
    pub fn write(&self, w: &mut Writer) {
        w.write_varint(self.version);
        w.write_varint(self.unlock_time);
        w.write_varint(self.vin.len() as u64);
        for i in &self.vin {
            i.write(w);
        }
        w.write_varint(self.vout.len() as u64);
        for o in &self.vout {
            o.write(w);
        }
        w.write_bytes_prefixed(&self.extra);
    }

    pub fn read(r: &mut Reader<'_>) -> Result<TransactionPrefix> {
        let version = r.read_varint()?;
        // `specs/04` §1.6: version 0 or > 2 is a parse error, not a validation
        // failure -- the C's `if (tx.version == 0 || tx.version > 2) return
        // false` inside the serializer.
        if version == 0 || version > CURRENT_TRANSACTION_VERSION {
            return Err(Error::InvalidValue("transaction version"));
        }
        let unlock_time = r.read_varint()?;

        let n_vin = r.read_len(r.remaining(), "vin")?;
        let mut vin = Vec::with_capacity(n_vin.min(4096));
        for _ in 0..n_vin {
            vin.push(TxIn::read(r)?);
        }

        let n_vout = r.read_len(r.remaining(), "vout")?;
        let mut vout = Vec::with_capacity(n_vout.min(4096));
        for _ in 0..n_vout {
            vout.push(TxOut::read(r)?);
        }

        let extra = r.read_bytes_prefixed(r.remaining(), "tx_extra")?.to_vec();

        Ok(TransactionPrefix {
            version,
            unlock_time,
            vin,
            vout,
            extra,
        })
    }

    /// Is this a coinbase? A single `txin_gen` input.
    pub fn is_miner_tx(&self) -> bool {
        self.vin.len() == 1 && matches!(self.vin[0], TxIn::Gen { .. })
    }
}

/// A full transaction.
///
/// `prefix_size` and `unprunable_size` are recorded during parsing because the
/// v2 transaction hash is a hash of three hashes over **blob slices**, not over
/// a re-serialization (`specs/05` §3.2). Re-serializing to recover them is both
/// slower and wrong for a non-canonically encoded blob.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Transaction {
    pub prefix: TransactionPrefix,
    /// v1 only: `get_signature_size(vin[i])` signatures per input, written
    /// back-to-back with **no** length prefixes.
    pub signatures: Vec<Vec<Signature>>,
    /// v2 only.
    pub rct_signatures: RctSignatures,
    /// Bytes consumed by `transaction_prefix`.
    pub prefix_size: usize,
    /// Bytes consumed by prefix + `rctSigBase` (for v1, the prefix alone).
    pub unprunable_size: usize,
}

impl core::ops::Deref for Transaction {
    type Target = TransactionPrefix;
    fn deref(&self) -> &TransactionPrefix {
        &self.prefix
    }
}

impl Transaction {
    pub fn read(r: &mut Reader<'_>) -> Result<Transaction> {
        Transaction::read_parts(r, false)
    }

    /// `transaction::serialize_base`: the prefix, and for v2 the RingCT base.
    ///
    /// What a pruned transaction keeps. v1 signatures and the v2 prunable half
    /// are not read, so a blob that ends where they would begin parses.
    pub fn read_base(r: &mut Reader<'_>) -> Result<Transaction> {
        Transaction::read_parts(r, true)
    }

    fn read_parts(r: &mut Reader<'_>, base_only: bool) -> Result<Transaction> {
        let start = r.pos();
        let prefix = TransactionPrefix::read(r)?;
        let prefix_size = r.pos() - start;

        let mut signatures = Vec::new();
        let mut rct_signatures = RctSignatures::null();
        let mut unprunable_size = prefix_size;

        if prefix.version == 1 {
            // `signatures` is a vector of vectors written with **no** length
            // prefixes at all: the sizes come from the inputs. The C's
            // `PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(), signatures)`
            // resizes the outer vector to one row per input on load, so there
            // is always exactly one row per input even when a row is empty
            // (a `txin_gen` has `get_signature_size() == 0`).
            if !base_only {
                signatures.reserve(prefix.vin.len());
                for input in &prefix.vin {
                    let n = input.signature_size();
                    let mut row = Vec::with_capacity(n);
                    for _ in 0..n {
                        row.push(Signature::from_bytes(&r.read_array::<64>()?));
                    }
                    signatures.push(row);
                }
            }
        } else if !prefix.vin.is_empty() {
            let inputs = prefix.vin.len();
            let outputs = prefix.vout.len();
            // `vin[0].key_offsets.size() - 1` when vin[0] is a `txin_to_key`,
            // else 0. Note the C computes this in `size_t`, so an **empty**
            // `key_offsets` underflows to `SIZE_MAX` and is then caught by the
            // `mixin >= 0xffffffff` guard below. `wrapping_sub` reproduces
            // that; `saturating_sub` would silently accept a blob the
            // reference rejects.
            let mixin = match &prefix.vin[0] {
                TxIn::ToKey { key_offsets, .. } => key_offsets.len().wrapping_sub(1),
                _ => 0,
            };
            if inputs >= RCT_DIM_MAX || outputs >= RCT_DIM_MAX || mixin >= RCT_DIM_MAX {
                return Err(Error::LimitExceeded("rct dimension"));
            }

            rct_signatures = RctSignatures::read_base(r, inputs, outputs)?;
            unprunable_size = r.pos() - start;
            if !base_only && !rct_signatures.ty.is_null() {
                rct_signatures.read_prunable(r, inputs, outputs, mixin)?;
            }
        }

        Ok(Transaction {
            prefix,
            signatures,
            rct_signatures,
            prefix_size,
            unprunable_size,
        })
    }

    /// Parse a standalone transaction blob.
    ///
    /// Mirrors `parse_and_validate_tx_from_blob`: archive parse, then
    /// [`Transaction::expand`]. Note the reference does **not** require the
    /// whole blob to be consumed, so trailing bytes are ignored here too.
    pub fn from_blob(blob: &[u8]) -> Result<Transaction> {
        let mut r = Reader::new(blob);
        let tx = Transaction::read(&mut r)?;
        tx.expand()?;
        Ok(tx)
    }

    /// `parse_and_validate_tx_base_from_blob`: the prefix, and for v2 the
    /// RingCT base, without the [`Transaction::expand`] checks.
    ///
    /// This is the `base_only` path for pruned transactions (`specs/05` §2.5),
    /// where the prunable half is absent. Given a whole blob it reads the same
    /// fields and ignores the rest. It used to read the whole transaction, so a
    /// pruned blob, which ends where the proofs would begin, did not parse.
    pub fn from_blob_base_only(blob: &[u8]) -> Result<Transaction> {
        let mut r = Reader::new(blob);
        Transaction::read_base(&mut r)
    }

    /// `expand_transaction_1(tx, base_only = false)`, the checks only.
    ///
    /// These live outside the archive in the reference, so they apply to a
    /// standalone tx blob but not to the `base_only` path. Reproducing the
    /// split matters: a pruned entry legitimately has no proofs at all.
    ///
    /// (The reference also fills `outPk[n].dest` from the output targets here.
    /// That field is never serialized and is only needed for signature
    /// verification, which is M2 work, so it is not materialised.)
    pub fn expand(&self) -> Result<()> {
        if self.prefix.version < 2 {
            return Ok(());
        }
        let rv = &self.rct_signatures;
        let n_outputs = self.prefix.vout.len();

        if rv.ty.is_bulletproof_plus() {
            if rv.bulletproofs_plus.len() != 1 {
                return Err(Error::InvalidValue("bulletproofs_plus.len() != 1"));
            }
            let bp = &rv.bulletproofs_plus[0];
            if bp.l.len() < 6 {
                return Err(Error::InvalidValue("bulletproofs_plus[0].L.len() < 6"));
            }
            let max = bp
                .max_amounts()
                .ok_or(Error::LimitExceeded("bpp max_amounts"))?;
            if max < n_outputs {
                return Err(Error::LimitExceeded("bpp max outputs < vout"));
            }
        }

        // `is_rct_new_bulletproof`: types 5, 6, 7.
        if matches!(
            rv.ty,
            RctType::Bulletproof | RctType::Bulletproof2 | RctType::Clsag
        ) {
            if rv.bulletproofs.len() != 1 {
                return Err(Error::InvalidValue("bulletproofs.len() != 1"));
            }
            let bp = &rv.bulletproofs[0];
            if bp.l.len() < 6 {
                return Err(Error::InvalidValue("bulletproofs[0].L.len() < 6"));
            }
            // Note the asymmetry: the reference applies this bound only for
            // RCT type 5, not for 6 or 7. The archive's own
            // `n_bulletproof_max_amounts < outputs` check already covers those.
            if rv.ty == RctType::Bulletproof {
                let max = bp
                    .max_amounts()
                    .ok_or(Error::LimitExceeded("bp max_amounts"))?;
                if max < n_outputs {
                    return Err(Error::LimitExceeded("bp max outputs < vout"));
                }
            }
        }

        // `outPk.len() != vout.len()` (`specs/04` §1.6).
        if !rv.ty.is_null() && rv.out_pk.len() != n_outputs {
            return Err(Error::InvalidValue("outPk.len() != vout.len()"));
        }
        Ok(())
    }

    pub fn write(&self, w: &mut Writer) {
        self.prefix.write(w);
        if self.prefix.version == 1 {
            for row in &self.signatures {
                for s in row {
                    w.write_bytes(&s.to_bytes());
                }
            }
        } else if !self.prefix.vin.is_empty() {
            self.rct_signatures.write_base(w, self.prefix.vout.len());
            if !self.rct_signatures.ty.is_null() {
                self.rct_signatures.write_prunable(w);
            }
        }
    }

    /// `get_transaction_weight`'s `fee` input (`specs/05` §5.2).
    ///
    /// For v1 this is `sum(inputs) - sum(outputs)`, which requires the caller
    /// to have validated non-overflow first; `None` signals that it did not
    /// hold.
    pub fn fee(&self) -> Option<u64> {
        if self.prefix.version == 1 {
            let mut input_sum: u64 = 0;
            for i in &self.prefix.vin {
                let amount = match i {
                    TxIn::ToKey { amount, .. } => *amount,
                    _ => 0,
                };
                input_sum = input_sum.checked_add(amount)?;
            }
            let mut output_sum: u64 = 0;
            for o in &self.prefix.vout {
                output_sum = output_sum.checked_add(o.amount)?;
            }
            input_sum.checked_sub(output_sum)
        } else {
            Some(self.rct_signatures.txn_fee)
        }
    }
}

impl BinSerialize for Transaction {
    fn write(&self, w: &mut Writer) {
        Transaction::write(self, w)
    }
}

impl BinSerialize for TransactionPrefix {
    fn write(&self, w: &mut Writer) {
        TransactionPrefix::write(self, w)
    }
}
