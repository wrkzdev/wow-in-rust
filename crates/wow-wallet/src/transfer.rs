//! Building a transaction: `construct_tx_with_tx_key`.
//!
//! `specs/12` §4.6, `src/cryptonote_core/cryptonote_tx_utils.cpp`.
//!
//! # The order is the whole problem
//!
//! Each step's input is the previous step's output, and getting the order
//! wrong produces a transaction that is internally consistent and rejected:
//!
//! 1. build the prefix **completely**, including a sorted `extra`,
//! 2. `tx_prefix_hash` — the RingCT `message`,
//! 3. the Bulletproof+ over the output amounts, which fixes `outPk`,
//! 4. `pre_mlsag_hash`, which hashes the proof, so it cannot be computed
//!    earlier,
//! 5. the CLSAGs, last, over that hash.
//!
//! # Type 8 only
//!
//! `specs/12` §4.6 is explicit that the reference wallet never builds RCT
//! type 9: `bp_version` 4 maps to `BulletproofPlus` and `wallet2` never
//! pre-sets the full-commit variant. So this builds type 8, which carries the
//! `outPk[i].mask = C_i / 8` convention — the same `V` the proof already holds,
//! stored unchanged.
//!
//! # What this does not do
//!
//! Decoy selection (`specs/12` §4.3) and input selection (§4.4) are the
//! caller's. This takes a ring that has already been chosen, because decoy
//! selection needs `get_output_distribution` from a daemon and is a privacy
//! decision rather than a correctness one — it belongs with the code that can
//! talk to a node.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;

use wow_crypto::bulletproofs_plus as bpp;
use wow_crypto::clsag::{self, RingMember};
use wow_crypto::ops::{decode_point, decode_scalar, encode_point};
use wow_crypto::types::{
    AccountPublicAddress, EcPoint, EcScalar, Hash256, Hash8, KeyImage, PublicKey, SecretKey,
};
use wow_types::rct::{EcdhInfo, RctSignatures, RctType};
use wow_types::tx::{Transaction, TransactionPrefix, TxIn, TxOut, TxOutTarget};
use wow_types::tx_extra::{serialize_tx_extra, TxExtraField};

use crate::spend::{fee_from_weight, SpendError, SpendPlan, FEE_CALCULATION_MAX_RETRIES};

/// An output this wallet owns and is about to spend.
pub struct SpendableOutput {
    /// The one-time public key on chain.
    pub public_key: PublicKey,
    /// `x`, the one-time secret key. `public_key = x * G`.
    pub secret_key: SecretKey,
    /// The amount blinding factor.
    pub mask: Scalar,
    pub amount: u64,
    pub key_image: KeyImage,
    /// The ring, including this output, in the order it will appear on the
    /// wire. Must be sorted by global index; `real_index` says which entry is
    /// the real one.
    pub ring: Vec<RingMember>,
    /// Global output indices, one per ring member, ascending.
    pub global_indices: Vec<u64>,
    pub real_index: usize,
}

/// Where money is going.
pub struct Destination {
    pub address: AccountPublicAddress,
    /// True when `address` is a subaddress, which changes how the transaction
    /// public key for it is derived.
    pub is_subaddress: bool,
    pub amount: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("no inputs")]
    NoInputs,
    #[error("no destinations")]
    NoDestinations,
    #[error("a transaction needs at least two outputs; add a change output")]
    TooFewOutputs,
    #[error("{0} outputs is past the Bulletproof+ aggregation limit of 16")]
    TooManyOutputs(usize),
    #[error("inputs total {inputs} but outputs plus fee total {outputs}")]
    Unbalanced { inputs: u128, outputs: u128 },
    #[error("input {0} has a ring of the wrong size or a bad real index")]
    BadRing(usize),
    #[error("a key does not decode")]
    BadKey,
    #[error("the range proof could not be built: {0}")]
    RangeProof(#[from] bpp::BppError),
    #[error("a ring signature could not be made: {0}")]
    Clsag(#[from] clsag::ClsagError),
}

type Result<T> = std::result::Result<T, TransferError>;

/// The randomness a transaction needs.
///
/// Everything secret in a transaction comes from here: the transaction key,
/// the output masks, the Bulletproof+ blinding and the CLSAG nonces. A
/// predictable source does not produce an invalid transaction — it produces a
/// valid one that reveals the spend.
pub trait Rng {
    fn scalar(&mut self) -> Scalar;
}

impl<F: FnMut() -> Scalar> Rng for F {
    fn scalar(&mut self) -> Scalar {
        self()
    }
}

/// A transaction, plus what the wallet needs to remember about it.
#[derive(Debug)]
pub struct BuiltTransaction {
    pub tx: Transaction,
    /// The transaction secret key, kept so the wallet can prove payments later.
    pub tx_secret_key: SecretKey,
    /// Per-destination transaction secret keys, for subaddress destinations.
    pub additional_tx_secret_keys: Vec<SecretKey>,
}

/// Build a transaction spending `inputs` to `destinations`.
///
/// `destinations` must already include the change output. `fee` is the
/// difference between the input and output totals and is checked, not derived
/// — computing it needs the transaction's weight, which needs the transaction.
pub fn construct(
    inputs: &[SpendableOutput],
    destinations: &[Destination],
    fee: u64,
    payment_id: Option<Hash8>,
    rng: &mut dyn Rng,
) -> Result<BuiltTransaction> {
    if inputs.is_empty() {
        return Err(TransferError::NoInputs);
    }
    if destinations.is_empty() {
        return Err(TransferError::NoDestinations);
    }
    // HF 15 onward: at least two outputs. A caller with one destination adds a
    // zero-amount change output to itself.
    if destinations.len() < 2 {
        return Err(TransferError::TooFewOutputs);
    }
    if destinations.len() > bpp::MAX_OUTPUTS {
        return Err(TransferError::TooManyOutputs(destinations.len()));
    }

    let in_total: u128 = inputs.iter().map(|i| i.amount as u128).sum();
    let out_total: u128 = destinations.iter().map(|d| d.amount as u128).sum::<u128>() + fee as u128;
    if in_total != out_total {
        return Err(TransferError::Unbalanced {
            inputs: in_total,
            outputs: out_total,
        });
    }

    for (i, inp) in inputs.iter().enumerate() {
        if inp.ring.is_empty()
            || inp.real_index >= inp.ring.len()
            || inp.global_indices.len() != inp.ring.len()
        {
            return Err(TransferError::BadRing(i));
        }
    }

    // ---- the transaction key, and the per-output keys a subaddress needs ----
    let tx_secret = rng.scalar();
    let any_subaddress = destinations.iter().any(|d| d.is_subaddress);

    // `TX_EXTRA_TAG_PUBKEY` is `r*G` unless *every* destination is a
    // subaddress and there is only one, in which case the reference still
    // writes `r*G`; the per-output keys carry the real work.
    let tx_public = PublicKey(encode_point(&(tx_secret * ED25519_BASEPOINT_POINT)));

    let mut additional_secrets = Vec::new();
    let mut additional_publics = Vec::new();
    if any_subaddress {
        for d in destinations {
            // A fresh key per output. For a subaddress the public key is
            // `r * D`, the recipient's subaddress spend key, not `r * G`.
            let r = rng.scalar();
            let pubkey = if d.is_subaddress {
                let spend =
                    decode_point(&d.address.spend_public_key.0).ok_or(TransferError::BadKey)?;
                PublicKey(encode_point(&(r * spend)))
            } else {
                PublicKey(encode_point(&(r * ED25519_BASEPOINT_POINT)))
            };
            additional_secrets.push(SecretKey(r.to_bytes()));
            additional_publics.push(pubkey);
        }
    }

    // ---- outputs ----
    let mut vout = Vec::with_capacity(destinations.len());
    let mut ecdh_info = Vec::with_capacity(destinations.len());
    let mut out_masks = Vec::with_capacity(destinations.len());
    let mut amounts = Vec::with_capacity(destinations.len());
    let mut first_derivation = None;

    for (j, d) in destinations.iter().enumerate() {
        let r = if any_subaddress {
            decode_scalar(&additional_secrets[j].0).ok_or(TransferError::BadKey)?
        } else {
            tx_secret
        };

        // The shared secret is `r * C`, the recipient's view key.
        let view = decode_point(&d.address.view_public_key.0).ok_or(TransferError::BadKey)?;
        let derivation =
            wow_crypto::types::KeyDerivation(encode_point(&wow_crypto::ops::mul8(&(r * view))));
        if j == 0 {
            first_derivation = Some(derivation);
        }

        let one_time =
            wow_crypto::derive_public_key(&derivation, j as u64, &d.address.spend_public_key)
                .ok_or(TransferError::BadKey)?;
        let view_tag = wow_crypto::derive_view_tag(&derivation, j as u64);

        vout.push(TxOut {
            amount: 0,
            target: TxOutTarget::ToTaggedKey {
                key: one_time,
                view_tag,
            },
        });

        // The amount, encoded the short way (`specs/02` §4.5).
        let shared = wow_crypto::derivation_to_scalar(&derivation, j as u64);
        let mask = wow_crypto::rct::commitment_mask(&shared);
        let pad = wow_crypto::rct::amount_pad(&shared);
        let mut enc = [0u8; 32];
        for (o, (b, p)) in enc
            .iter_mut()
            .zip(d.amount.to_le_bytes().iter().zip(pad.iter()))
        {
            *o = b ^ p;
        }
        ecdh_info.push(EcdhInfo {
            mask: EcScalar::ZERO,
            amount: EcScalar(enc),
        });
        out_masks.push(mask);
        amounts.push(d.amount);
    }

    // ---- extra ----
    let mut extra = vec![TxExtraField::Pubkey(tx_public)];
    if any_subaddress {
        extra.push(TxExtraField::AdditionalPubkeys(additional_publics));
    }
    // `construct_tx_with_tx_key` gives every transaction of one destination
    // plus change an encrypted payment id -- zeros when there is no real one --
    // so a transaction with an id looks like one without. Past two outputs it
    // adds no dummy.
    //
    // Nor when a subaddress is paid, where this builder parts from the C++: it
    // gives such a transaction per-output keys, while the C++ makes the
    // transaction key `r*D` for a single subaddress. The payee decrypts with
    // that key, so under this layout a dummy would come out as eight random
    // bytes -- a payment id the sender never gave.
    let encrypted_id = match payment_id {
        Some(pid) => Some(pid),
        None if destinations.len() == 2 && !any_subaddress => Some([0u8; 8]),
        None => None,
    };
    if let Some(pid) = encrypted_id {
        // Encrypted under the first output's derivation, the payee's, which is
        // why it has to be computed above first.
        let d = first_derivation.ok_or(TransferError::BadKey)?;
        let enc = wow_crypto::keys::encrypt_payment_id(&pid, &d);
        let mut nonce = Vec::with_capacity(9);
        nonce.push(0x01);
        nonce.extend_from_slice(&enc);
        extra.push(TxExtraField::Nonce(nonce));
    }

    // ---- inputs, sorted by descending key image ----
    let mut order: Vec<usize> = (0..inputs.len()).collect();
    order.sort_by(|&a, &b| inputs[b].key_image.0.cmp(&inputs[a].key_image.0));

    let mut vin = Vec::with_capacity(inputs.len());
    for &i in &order {
        let inp = &inputs[i];
        vin.push(TxIn::ToKey {
            amount: 0,
            key_offsets: relative_offsets(&inp.global_indices),
            k_image: inp.key_image,
        });
    }

    let prefix = TransactionPrefix {
        version: 2,
        // MUST be zero: a non-zero unlock time is not relayed (`specs/06` §6.3).
        unlock_time: 0,
        vin,
        vout,
        extra: serialize_tx_extra(&extra, true),
    };

    // Step 2: the message.
    let message = wow_types::hashes::tx_prefix_hash(&prefix);

    // Step 3: the range proof. Its commitments become `outPk`.
    let proof = bpp::prove(&amounts, &out_masks, &mut || rng.scalar())?;
    let out_pk: Vec<EcPoint> = proof.v.clone();

    // The pseudo-output commitments must sum to the real output commitments
    // plus the fee, so the last one absorbs the difference.
    let pseudo_outs = pseudo_output_commitments(inputs, &order, &out_masks, rng)?;

    let mut rct = RctSignatures {
        ty: RctType::BulletproofPlus,
        txn_fee: fee,
        ecdh_info,
        out_pk,
        bulletproofs_plus: vec![wow_types::rct::BulletproofPlus {
            a: proof.a,
            a1: proof.a1,
            b: proof.b,
            r1: proof.r1,
            s1: proof.s1,
            d1: proof.d1,
            l: proof.l.clone(),
            r: proof.r.clone(),
        }],
        pseudo_outs: pseudo_outs.iter().map(|(c, _)| *c).collect(),
        ..Default::default()
    };

    // Step 4: the hash the ring signatures sign, which covers the proof.
    let full_message =
        wow_types::hashes::pre_mlsag_hash(&message, &rct, inputs.len(), destinations.len());

    // Step 5: one CLSAG per input, in the sorted order.
    for (slot, &i) in order.iter().enumerate() {
        let inp = &inputs[i];
        let (c_offset, offset_mask) = pseudo_outs[slot];

        let p = decode_scalar(&inp.secret_key.0).ok_or(TransferError::BadKey)?;
        // z is the difference between the real commitment's mask and the
        // pseudo-output's, which is what lets the ring hide which is real.
        let z = inp.mask - offset_mask;

        let alpha = rng.scalar();
        let fake: Vec<Scalar> = (0..inp.ring.len()).map(|_| rng.scalar()).collect();

        let sig = clsag::sign(
            &full_message,
            &inp.ring,
            inp.real_index,
            &p,
            &z,
            &c_offset,
            &alpha,
            &fake,
        )?;
        rct.clsags.push(wow_types::rct::Clsag {
            s: sig.s,
            c1: sig.c1,
            d: sig.d,
        });
    }

    let tx = Transaction {
        prefix,
        signatures: Vec::new(),
        rct_signatures: rct,
        prefix_size: 0,
        unprunable_size: 0,
    };

    Ok(BuiltTransaction {
        tx,
        tx_secret_key: SecretKey(tx_secret.to_bytes()),
        additional_tx_secret_keys: additional_secrets,
    })
}

/// A transaction built at the fee its own blob needs.
#[derive(Debug)]
pub struct Settled {
    pub built: BuiltTransaction,
    /// The transaction, serialized for relay.
    pub blob: Vec<u8>,
    /// The plan as built: its fee, the change or swept amount that fee moved,
    /// and the built weight in `estimated_weight`.
    pub plan: SpendPlan,
}

#[derive(Debug, thiserror::Error)]
pub enum SettleError {
    #[error(transparent)]
    Build(#[from] TransferError),
    #[error(transparent)]
    Plan(#[from] SpendError),
}

/// Build a plan at the fee the built transaction needs, as
/// `wallet2::create_transactions_2` does before it hands a transaction over.
///
/// The plan's fee comes from [`crate::spend::estimate_tx_weight`], which runs a
/// few bytes over. The C++ builds at it, reads the weight off the blob, builds
/// again at that weight's fee, and repeats while a rebuild needs more than it
/// pays. So the fee on chain is the real weight's, which a fee charged on the
/// estimate is not. The C++ rebuilds once even when the estimate was exact;
/// this skips that, since it would only draw fresh randomness.
///
/// `destinations` makes the outputs for a plan, so that a changed fee reaches
/// the change output, or a sweep's amount.
pub fn construct_settled(
    inputs: &[SpendableOutput],
    plan: &SpendPlan,
    fee_per_byte: u64,
    payment_id: Option<Hash8>,
    destinations: &dyn Fn(&SpendPlan) -> Vec<Destination>,
    rng: &mut dyn Rng,
) -> std::result::Result<Settled, SettleError> {
    let mut plan = plan.clone();
    let (mut built, mut blob, mut weight) =
        build_measured(inputs, &plan, payment_id, destinations, rng)?;
    let mut needed = fee_from_weight(fee_per_byte, weight);

    let mut rebuilds = 0;
    while needed > plan.fee || (rebuilds == 0 && needed != plan.fee) {
        if rebuilds == FEE_CALCULATION_MAX_RETRIES {
            return Err(SpendError::FeeDidNotSettle(FEE_CALCULATION_MAX_RETRIES).into());
        }
        plan = plan.with_fee(needed)?;
        (built, blob, weight) = build_measured(inputs, &plan, payment_id, destinations, rng)?;
        needed = fee_from_weight(fee_per_byte, weight);
        rebuilds += 1;
    }

    plan.estimated_weight = weight;
    Ok(Settled { built, blob, plan })
}

/// Build, serialize, and weigh.
fn build_measured(
    inputs: &[SpendableOutput],
    plan: &SpendPlan,
    payment_id: Option<Hash8>,
    destinations: &dyn Fn(&SpendPlan) -> Vec<Destination>,
    rng: &mut dyn Rng,
) -> Result<(BuiltTransaction, Vec<u8>, u64)> {
    let built = construct(inputs, &destinations(plan), plan.fee, payment_id, rng)?;
    let mut w = wow_serialize::binary::Writer::with_capacity(8192);
    built.tx.write(&mut w);
    let blob = w.into_vec();
    let weight = wow_types::weight::get_transaction_weight(&built.tx, blob.len());
    Ok((built, blob, weight))
}

/// A pseudo-output commitment per input, with masks summing to the outputs'.
///
/// `sum(pseudo) == sum(out) + fee*H` is what proves the transaction creates no
/// money. The first `n-1` masks are random and the last is whatever makes the
/// sum come out, so no individual input's amount is revealed.
fn pseudo_output_commitments(
    inputs: &[SpendableOutput],
    order: &[usize],
    out_masks: &[Scalar],
    rng: &mut dyn Rng,
) -> Result<Vec<(EcPoint, Scalar)>> {
    let out_sum: Scalar = out_masks.iter().sum();

    let mut masks: Vec<Scalar> = Vec::with_capacity(order.len());
    let mut acc = Scalar::ZERO;
    for _ in 0..order.len().saturating_sub(1) {
        let m = rng.scalar();
        acc += m;
        masks.push(m);
    }
    masks.push(out_sum - acc);

    Ok(order
        .iter()
        .zip(masks)
        .map(|(&i, mask)| (wow_crypto::rct::commit(inputs[i].amount, &mask), mask))
        .collect())
}

/// Absolute global indices to the relative form the wire uses
/// (`specs/05` §2.1): the first absolute, the rest deltas.
fn relative_offsets(absolute: &[u64]) -> Vec<u64> {
    let mut out = Vec::with_capacity(absolute.len());
    let mut prev = 0u64;
    for (i, &a) in absolute.iter().enumerate() {
        out.push(if i == 0 { a } else { a - prev });
        prev = a;
    }
    out
}

/// Everything a verifier checks about the amounts:
/// `sum(pseudoOuts) == sum(outPk) + fee*H`.
///
/// **`outPk` is not always the commitment.** Under RCT type 8 it holds `C / 8`,
/// so the sum has to multiply by eight first; under every other type, including
/// the Wownero-only type 9, it holds `C` and must not be touched
/// (`specs/02` §4.4). `pseudoOuts` is always the full commitment.
///
/// Exposed because it is the cheapest end-to-end check that a built
/// transaction is coherent, and the daemon needs it too (`specs/06` §5.11).
pub fn commitments_balance(rct: &RctSignatures) -> bool {
    let scale_outputs = rct.ty.is_bp_plus_legacy();
    let sum_in = match sum_points(&rct.pseudo_outs, false) {
        Some(s) => s,
        None => return false,
    };
    let sum_out = match sum_points(&rct.out_pk, scale_outputs) {
        Some(s) => s,
        None => return false,
    };
    let fee_point = wow_crypto::rct::scalarmult_h(&Scalar::from(rct.txn_fee));
    sum_in == sum_out + fee_point
}

fn sum_points(
    pts: &[EcPoint],
    times_eight: bool,
) -> Option<curve25519_dalek::edwards::EdwardsPoint> {
    let mut acc = curve25519_dalek::edwards::EdwardsPoint::default();
    for p in pts {
        let q = decode_point(&p.0)?;
        acc += if times_eight {
            wow_crypto::ops::mul8(&q)
        } else {
            q
        };
    }
    Some(acc)
}

/// The transaction hash of a freshly built transaction.
///
/// This re-serializes, which is right here and wrong for a transaction read
/// off the wire — see [`wow_types::hashes::transaction_hash`].
pub fn transaction_hash(tx: &Transaction) -> Hash256 {
    wow_types::hashes::transaction_hash(tx).unwrap_or(wow_crypto::NULL_HASH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{scan_transaction, ScanKeys};
    use crate::subaddress::SubaddressTable;
    use wow_crypto::types::SubaddressIndex;

    /// Deterministic randomness, so a failure is reproducible. A real caller
    /// passes a CSPRNG; see the note on [`Rng`].
    struct Counter(u64);

    impl Rng for Counter {
        fn scalar(&mut self) -> Scalar {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&self.0.to_le_bytes());
            b[8..16].copy_from_slice(&self.0.rotate_left(17).to_le_bytes());
            b[16..24].copy_from_slice(&self.0.rotate_left(33).to_le_bytes());
            Scalar::from_bytes_mod_order(b)
        }
    }

    struct Wallet {
        address: AccountPublicAddress,
        spend: SecretKey,
        view: SecretKey,
        table: SubaddressTable,
    }

    fn wallet(seed: u8) -> Wallet {
        let spend = SecretKey(wow_crypto::ops::sc_reduce32(&[seed; 32]));
        let view = wow_crypto::view_key_from_spend_key(&spend);
        let address = AccountPublicAddress {
            spend_public_key: wow_crypto::secret_key_to_public_key(&spend).expect("valid"),
            view_public_key: wow_crypto::secret_key_to_public_key(&view).expect("valid"),
        };
        let table = SubaddressTable::new(&address, &view, 2, 4);
        Wallet {
            address,
            spend,
            view,
            table,
        }
    }

    impl Wallet {
        fn keys(&self) -> ScanKeys<'_> {
            ScanKeys {
                address: &self.address,
                view_secret_key: &self.view,
                spend_secret_key: Some(&self.spend),
                subaddresses: &self.table,
            }
        }
    }

    /// An owned output with a ring of decoys around it, as the wallet would
    /// have after scanning and asking a daemon for ring members.
    fn spendable(amount: u64, ring_size: usize, real_index: usize, seed: u8) -> SpendableOutput {
        let x = Scalar::from_bytes_mod_order([seed; 32]);
        let public_key = PublicKey(encode_point(&(x * ED25519_BASEPOINT_POINT)));
        let secret_key = SecretKey(x.to_bytes());
        let mask = Scalar::from_bytes_mod_order([seed ^ 0x5a; 32]);
        let key_image = wow_crypto::generate_key_image(&public_key, &secret_key).expect("an image");

        let mut ring = Vec::with_capacity(ring_size);
        let mut global_indices = Vec::with_capacity(ring_size);
        for i in 0..ring_size {
            if i == real_index {
                ring.push(RingMember {
                    dest: public_key,
                    mask: wow_crypto::rct::commit(amount, &mask),
                });
            } else {
                let d = Scalar::from_bytes_mod_order([seed.wrapping_add(i as u8 + 1); 32]);
                let m = Scalar::from_bytes_mod_order([seed.wrapping_add(i as u8 + 100); 32]);
                ring.push(RingMember {
                    dest: PublicKey(encode_point(&(d * ED25519_BASEPOINT_POINT))),
                    mask: wow_crypto::rct::commit(1_000 + i as u64, &m),
                });
            }
            global_indices.push(1_000 + (i as u64) * 37);
        }

        SpendableOutput {
            public_key,
            secret_key,
            mask,
            amount,
            key_image,
            ring,
            global_indices,
            real_index,
        }
    }

    /// Verify a built transaction the way a node would: every ring signature,
    /// the range proof, and the commitment balance.
    fn verify_as_a_node(tx: &Transaction, inputs: &[&SpendableOutput]) {
        let rct = &tx.rct_signatures;
        assert_eq!(rct.ty, RctType::BulletproofPlus);

        // The range proof, with V reconstructed from outPk. Type 8 stores C/8,
        // which is what V already is.
        let wire = &rct.bulletproofs_plus[0];
        let proof = bpp::BulletproofPlus {
            v: rct.out_pk.clone(),
            a: wire.a,
            a1: wire.a1,
            b: wire.b,
            r1: wire.r1,
            s1: wire.s1,
            d1: wire.d1,
            l: wire.l.clone(),
            r: wire.r.clone(),
        };
        bpp::verify(&proof).expect("the range proof verifies");

        // The amounts balance.
        assert!(
            commitments_balance(rct),
            "sum(pseudoOuts) = sum(outPk) + fee*H"
        );

        // Every ring signature, over the same message the builder signed.
        let message = wow_types::hashes::tx_prefix_hash(&tx.prefix);
        let full = wow_types::hashes::pre_mlsag_hash(
            &message,
            rct,
            tx.prefix.vin.len(),
            tx.prefix.vout.len(),
        );
        assert_eq!(rct.clsags.len(), tx.prefix.vin.len());

        for (slot, sig) in rct.clsags.iter().enumerate() {
            let k_image = match &tx.prefix.vin[slot] {
                TxIn::ToKey { k_image, .. } => *k_image,
                other => panic!("input {slot} is {other:?}"),
            };
            // Find the input this slot came from -- the builder sorts by
            // descending key image, so slot order is not input order.
            let inp = inputs
                .iter()
                .find(|i| i.key_image == k_image)
                .expect("every slot matches an input");

            let c = clsag::Clsag {
                s: sig.s.clone(),
                c1: sig.c1,
                d: sig.d,
                i: k_image,
            };
            clsag::verify(&full, &c, &k_image, &inp.ring, &rct.pseudo_outs[slot])
                .unwrap_or_else(|e| panic!("input {slot}: {e}"));
        }
    }

    /// The end-to-end claim: a transaction this builds verifies, and the
    /// recipient finds the money.
    #[test]
    fn a_built_transaction_verifies_and_is_received() {
        let me = wallet(7);
        let them = wallet(9);

        let input = spendable(10_000_000_000, 22, 5, 3);
        let fee = 50_000_000u64;
        let send = 4_000_000_000u64;
        let change = input.amount - send - fee;

        let destinations = vec![
            Destination {
                address: them.address,
                is_subaddress: false,
                amount: send,
            },
            Destination {
                address: me.address,
                is_subaddress: false,
                amount: change,
            },
        ];

        let built = construct(
            std::slice::from_ref(&input),
            &destinations,
            fee,
            None,
            &mut Counter(1),
        )
        .expect("construct");

        verify_as_a_node(&built.tx, &[&input]);

        // The recipient sees their payment, and only theirs.
        let got = scan_transaction(&built.tx, &them.keys()).expect("scan");
        assert_eq!(got.len(), 1, "one output is theirs");
        assert_eq!(got[0].amount, send);
        assert_eq!(got[0].subaddress, SubaddressIndex::MAIN);
        assert!(got[0].key_image.is_some());
        assert!(got[0].had_view_tag, "HF 20 outputs are tagged");

        // And the sender sees their own change.
        let mine = scan_transaction(&built.tx, &me.keys()).expect("scan");
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].amount, change);

        // The two found different outputs.
        assert_ne!(got[0].public_key, mine[0].public_key);
    }

    /// Several inputs and several outputs, which is the ordinary case.
    #[test]
    fn several_inputs_and_outputs() {
        let me = wallet(11);
        let them = wallet(13);

        let inputs = vec![
            spendable(3_000_000_000, 22, 0, 21),
            spendable(5_000_000_000, 22, 21, 22),
            spendable(2_000_000_000, 22, 9, 23),
        ];
        let total: u64 = inputs.iter().map(|i| i.amount).sum();
        let fee = 30_000_000u64;
        let a = 1_500_000_000u64;
        let b = 2_500_000_000u64;

        let destinations = vec![
            Destination {
                address: them.address,
                is_subaddress: false,
                amount: a,
            },
            Destination {
                address: them.address,
                is_subaddress: false,
                amount: b,
            },
            Destination {
                address: me.address,
                is_subaddress: false,
                amount: total - a - b - fee,
            },
        ];

        let built =
            construct(&inputs, &destinations, fee, None, &mut Counter(2)).expect("construct");

        let refs: Vec<&SpendableOutput> = inputs.iter().collect();
        verify_as_a_node(&built.tx, &refs);

        let got = scan_transaction(&built.tx, &them.keys()).expect("scan");
        assert_eq!(got.len(), 2);
        let mut amounts: Vec<u64> = got.iter().map(|r| r.amount).collect();
        amounts.sort_unstable();
        assert_eq!(amounts, vec![a, b]);
    }

    /// Paying a subaddress goes through the additional public keys, and the
    /// recipient learns which of their addresses was paid.
    #[test]
    fn a_payment_to_a_subaddress_arrives() {
        let me = wallet(17);
        let them = wallet(19);
        let index = SubaddressIndex::new(1, 3);
        let sub = wow_crypto::get_subaddress(&them.address, &them.view, index).expect("derivable");

        let input = spendable(8_000_000_000, 22, 4, 31);
        let fee = 20_000_000u64;
        let send = 1_000_000_000u64;

        let destinations = vec![
            Destination {
                address: sub,
                is_subaddress: true,
                amount: send,
            },
            Destination {
                address: me.address,
                is_subaddress: false,
                amount: input.amount - send - fee,
            },
        ];

        let built = construct(
            std::slice::from_ref(&input),
            &destinations,
            fee,
            None,
            &mut Counter(3),
        )
        .expect("construct");

        verify_as_a_node(&built.tx, &[&input]);

        let got = scan_transaction(&built.tx, &them.keys()).expect("scan");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].subaddress, index, "the right subaddress");
        assert_eq!(got[0].amount, send);

        // The sender still finds their change, which shares the transaction
        // with a subaddress output.
        let mine = scan_transaction(&built.tx, &me.keys()).expect("scan");
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].amount, input.amount - send - fee);
    }

    /// Inputs are sorted by descending key image, which `specs/06` §5.7
    /// requires. The builder is given them in an arbitrary order.
    #[test]
    fn inputs_come_out_sorted_by_descending_key_image() {
        let me = wallet(23);
        let them = wallet(29);

        let inputs = vec![
            spendable(1_000_000_000, 11, 0, 41),
            spendable(1_000_000_000, 11, 1, 42),
            spendable(1_000_000_000, 11, 2, 43),
            spendable(1_000_000_000, 11, 3, 44),
        ];
        let total: u64 = inputs.iter().map(|i| i.amount).sum();
        let fee = 10_000_000u64;

        let destinations = vec![
            Destination {
                address: them.address,
                is_subaddress: false,
                amount: 500_000_000,
            },
            Destination {
                address: me.address,
                is_subaddress: false,
                amount: total - 500_000_000 - fee,
            },
        ];

        let built =
            construct(&inputs, &destinations, fee, None, &mut Counter(4)).expect("construct");

        let images: Vec<[u8; 32]> = built
            .tx
            .prefix
            .vin
            .iter()
            .map(|i| match i {
                TxIn::ToKey { k_image, .. } => k_image.0,
                other => panic!("{other:?}"),
            })
            .collect();
        let mut sorted = images.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(images, sorted, "descending key image order");

        let refs: Vec<&SpendableOutput> = inputs.iter().collect();
        verify_as_a_node(&built.tx, &refs);
    }

    /// An integrated address carries an encrypted payment id the recipient can
    /// decrypt with the same derivation that found the output.
    #[test]
    fn an_encrypted_payment_id_round_trips() {
        let me = wallet(31);
        let them = wallet(37);
        let pid: wow_crypto::types::Hash8 = [1, 2, 3, 4, 5, 6, 7, 8];

        let input = spendable(6_000_000_000, 22, 2, 51);
        let fee = 15_000_000u64;
        let send = 2_000_000_000u64;

        let destinations = vec![
            Destination {
                address: them.address,
                is_subaddress: false,
                amount: send,
            },
            Destination {
                address: me.address,
                is_subaddress: false,
                amount: input.amount - send - fee,
            },
        ];

        let built = construct(
            std::slice::from_ref(&input),
            &destinations,
            fee,
            Some(pid),
            &mut Counter(5),
        )
        .expect("construct");

        verify_as_a_node(&built.tx, &[&input]);

        let got = scan_transaction(&built.tx, &them.keys()).expect("scan");
        assert_eq!(got.len(), 1);

        let extra = wow_types::tx_extra::parse_tx_extra(&built.tx.prefix.extra);
        let nonce = extra
            .fields
            .iter()
            .find_map(|f| match f {
                wow_types::tx_extra::TxExtraField::Nonce(n) if n.len() == 9 && n[0] == 0x01 => {
                    Some(n.clone())
                }
                _ => None,
            })
            .expect("an encrypted payment id");

        let enc: wow_crypto::types::Hash8 = nonce[1..].try_into().expect("8 bytes");
        let dec = wow_crypto::keys::encrypt_payment_id(&enc, &got[0].derivation);
        assert_eq!(dec, pid, "the recipient recovers the payment id");
        assert_eq!(
            crate::scan::payment_id(&built.tx, &them.view),
            Some(pid),
            "and a refresh reads it"
        );
    }

    /// The balance check is not advisory. An unbalanced request is refused
    /// rather than producing a transaction a node would reject.
    #[test]
    fn an_unbalanced_transaction_is_refused() {
        let me = wallet(41);
        let them = wallet(43);
        let input = spendable(1_000_000_000, 11, 0, 61);

        let destinations = vec![
            Destination {
                address: them.address,
                is_subaddress: false,
                amount: 900_000_000,
            },
            Destination {
                address: me.address,
                is_subaddress: false,
                // One too many: this plus the fee overshoots the input.
                amount: 200_000_000,
            },
        ];

        let e = construct(
            std::slice::from_ref(&input),
            &destinations,
            10_000_000,
            None,
            &mut Counter(6),
        );
        assert!(matches!(e, Err(TransferError::Unbalanced { .. })), "{e:?}");
    }

    /// The structural rules: at least two outputs, at most sixteen, at least
    /// one input.
    #[test]
    fn the_output_count_rules() {
        let me = wallet(47);
        let them = wallet(53);
        let input = spendable(100_000_000_000, 11, 0, 71);

        let one = vec![Destination {
            address: them.address,
            is_subaddress: false,
            amount: input.amount,
        }];
        assert!(matches!(
            construct(std::slice::from_ref(&input), &one, 0, None, &mut Counter(7)),
            Err(TransferError::TooFewOutputs)
        ));

        let many: Vec<Destination> = (0..17)
            .map(|i| Destination {
                address: if i == 0 { me.address } else { them.address },
                is_subaddress: false,
                amount: input.amount / 17,
            })
            .collect();
        assert!(matches!(
            construct(
                std::slice::from_ref(&input),
                &many,
                0,
                None,
                &mut Counter(8)
            ),
            Err(TransferError::TooManyOutputs(17))
        ));

        assert!(matches!(
            construct(&[], &one, 0, None, &mut Counter(9)),
            Err(TransferError::NoInputs)
        ));
    }

    /// Relative key offsets are the wire form: the first absolute, the rest
    /// deltas.
    #[test]
    fn the_key_offsets_are_relative() {
        assert_eq!(relative_offsets(&[5]), vec![5]);
        assert_eq!(relative_offsets(&[5, 9, 20]), vec![5, 4, 11]);
        assert_eq!(relative_offsets(&[0, 1, 2, 3]), vec![0, 1, 1, 1]);
    }

    /// A transaction survives serialization: the blob parses back to the same
    /// thing, which is what the node will do with it.
    #[test]
    fn a_built_transaction_round_trips_through_its_blob() {
        let me = wallet(59);
        let them = wallet(61);
        let input = spendable(9_000_000_000, 22, 7, 81);
        let fee = 25_000_000u64;
        let send = 3_000_000_000u64;

        let destinations = vec![
            Destination {
                address: them.address,
                is_subaddress: false,
                amount: send,
            },
            Destination {
                address: me.address,
                is_subaddress: false,
                amount: input.amount - send - fee,
            },
        ];

        let built = construct(
            std::slice::from_ref(&input),
            &destinations,
            fee,
            None,
            &mut Counter(10),
        )
        .expect("construct");

        let mut w = wow_serialize::binary::Writer::with_capacity(4096);
        built.tx.write(&mut w);
        let blob = w.into_vec();

        let back = Transaction::from_blob(&blob).expect("the blob parses");
        assert_eq!(back.prefix, built.tx.prefix);
        assert_eq!(back.rct_signatures, built.tx.rct_signatures);

        // And it still verifies after the round trip.
        verify_as_a_node(&back, &[&input]);

        // The hash is stable across the round trip.
        assert_eq!(
            wow_types::hashes::transaction_hash_from_blob(&back, &blob),
            Some(transaction_hash(&built.tx))
        );
    }

    /// The payment id a transaction carries, still encrypted.
    fn encrypted_payment_id(tx: &Transaction) -> Option<Hash8> {
        wow_types::tx_extra::parse_tx_extra(&tx.prefix.extra)
            .fields
            .iter()
            .find_map(|f| match f {
                TxExtraField::Nonce(n) if n.len() == 9 && n[0] == 0x01 => n[1..].try_into().ok(),
                _ => None,
            })
    }

    /// Without a payment id, one destination plus change still carries one: a
    /// dummy the payee decrypts to zeros, which is how the C++ writes "none".
    #[test]
    fn a_transaction_without_a_payment_id_carries_a_dummy() {
        let me = wallet(67);
        let them = wallet(71);
        let input = spendable(6_000_000_000, 22, 3, 91);
        let fee = 15_000_000u64;
        let send = 2_000_000_000u64;

        let destinations = vec![
            Destination {
                address: them.address,
                is_subaddress: false,
                amount: send,
            },
            Destination {
                address: me.address,
                is_subaddress: false,
                amount: input.amount - send - fee,
            },
        ];
        let built = construct(
            std::slice::from_ref(&input),
            &destinations,
            fee,
            None,
            &mut Counter(11),
        )
        .expect("construct");
        verify_as_a_node(&built.tx, &[&input]);

        let enc = encrypted_payment_id(&built.tx).expect("a dummy payment id");
        let got = scan_transaction(&built.tx, &them.keys()).expect("scan");
        assert_eq!(got.len(), 1);
        assert_eq!(
            wow_crypto::keys::encrypt_payment_id(&enc, &got[0].derivation),
            [0u8; 8],
            "the payee reads it as no payment id"
        );
        assert_eq!(crate::scan::payment_id(&built.tx, &them.view), None);
        assert_eq!(
            built.tx.prefix.extra.len(),
            crate::spend::extra_size(2, false, false),
            "the size the estimate assumes"
        );
    }

    /// No dummy past two outputs, nor when a subaddress is paid.
    #[test]
    fn no_dummy_past_two_outputs_or_to_a_subaddress() {
        let me = wallet(73);
        let them = wallet(79);
        let input = spendable(9_000_000_000, 11, 0, 93);
        let fee = 10_000_000u64;

        let three = vec![
            Destination {
                address: them.address,
                is_subaddress: false,
                amount: 1_000_000_000,
            },
            Destination {
                address: them.address,
                is_subaddress: false,
                amount: 2_000_000_000,
            },
            Destination {
                address: me.address,
                is_subaddress: false,
                amount: input.amount - 3_000_000_000 - fee,
            },
        ];
        let built = construct(
            std::slice::from_ref(&input),
            &three,
            fee,
            None,
            &mut Counter(12),
        )
        .expect("construct");
        assert_eq!(encrypted_payment_id(&built.tx), None);
        assert_eq!(
            built.tx.prefix.extra.len(),
            crate::spend::extra_size(3, false, false)
        );

        let sub = wow_crypto::get_subaddress(&them.address, &them.view, SubaddressIndex::new(0, 1))
            .expect("derivable");
        let to_sub = vec![
            Destination {
                address: sub,
                is_subaddress: true,
                amount: 1_000_000_000,
            },
            Destination {
                address: me.address,
                is_subaddress: false,
                amount: input.amount - 1_000_000_000 - fee,
            },
        ];
        let built = construct(
            std::slice::from_ref(&input),
            &to_sub,
            fee,
            None,
            &mut Counter(13),
        )
        .expect("construct");
        assert_eq!(encrypted_payment_id(&built.tx), None);
        assert_eq!(
            built.tx.prefix.extra.len(),
            crate::spend::extra_size(2, false, true)
        );
    }

    /// Outputs for a plan: the payee, then change back to `me`.
    fn pay(
        them: AccountPublicAddress,
        me: AccountPublicAddress,
    ) -> impl Fn(&SpendPlan) -> Vec<Destination> {
        move |p: &SpendPlan| {
            vec![
                Destination {
                    address: them,
                    is_subaddress: false,
                    amount: p.amounts[0],
                },
                Destination {
                    address: me,
                    is_subaddress: false,
                    amount: p.change,
                },
            ]
        }
    }

    /// The fee a built transaction pays is its own weight's, not the
    /// estimate's, and the change takes up the difference.
    #[test]
    fn the_fee_settles_on_the_built_weight() {
        let me = wallet(83);
        let them = wallet(89);
        let input = spendable(10_000_000_000, 22, 6, 95);
        let rate = 260_000u64;
        let send = 1_234_000_000u64;

        let estimate =
            crate::spend::estimate_tx_weight(1, 22, 2, crate::spend::extra_size(2, false, false));
        let fee = fee_from_weight(rate, estimate);
        let plan = SpendPlan {
            inputs: vec![0],
            amounts: vec![send],
            change: input.amount - send - fee,
            fee,
            estimated_weight: estimate,
            sweep: false,
            left_behind: 0,
        };

        let settled = construct_settled(
            std::slice::from_ref(&input),
            &plan,
            rate,
            None,
            &pay(them.address, me.address),
            &mut Counter(14),
        )
        .expect("settles");
        verify_as_a_node(&settled.built.tx, &[&input]);

        let built =
            wow_types::weight::get_transaction_weight(&settled.built.tx, settled.blob.len());
        assert!(built < estimate, "estimated {estimate}, built {built}");
        assert_eq!(settled.plan.estimated_weight, built);
        assert_eq!(settled.plan.fee, fee_from_weight(rate, built));
        assert!(settled.plan.fee < fee);
        assert_eq!(settled.built.tx.rct_signatures.txn_fee, settled.plan.fee);

        assert_eq!(
            settled.plan.amounts[0], send,
            "the payee gets what was asked"
        );
        assert_eq!(settled.plan.change, input.amount - send - settled.plan.fee);
        let mine = scan_transaction(&settled.built.tx, &me.keys()).expect("scan");
        assert_eq!(
            mine[0].amount, settled.plan.change,
            "the change holds the difference"
        );

        let back = Transaction::from_blob(&settled.blob).expect("the blob is the transaction");
        assert_eq!(back.rct_signatures.txn_fee, settled.plan.fee);
    }

    /// A sweep settles the same way, out of the amount sent.
    #[test]
    fn a_sweep_settles_out_of_the_amount() {
        let me = wallet(97);
        let them = wallet(101);
        let input = spendable(10_000_000_000, 22, 1, 97);
        let rate = 260_000u64;

        let estimate =
            crate::spend::estimate_tx_weight(1, 22, 2, crate::spend::extra_size(2, false, false));
        let fee = fee_from_weight(rate, estimate);
        let plan = SpendPlan {
            inputs: vec![0],
            amounts: vec![input.amount - fee],
            change: 0,
            fee,
            estimated_weight: estimate,
            sweep: true,
            left_behind: 0,
        };

        let settled = construct_settled(
            std::slice::from_ref(&input),
            &plan,
            rate,
            None,
            &pay(them.address, me.address),
            &mut Counter(15),
        )
        .expect("settles");
        verify_as_a_node(&settled.built.tx, &[&input]);

        let built =
            wow_types::weight::get_transaction_weight(&settled.built.tx, settled.blob.len());
        assert_eq!(settled.plan.fee, fee_from_weight(rate, built));
        assert_eq!(settled.plan.change, 0);
        assert_eq!(
            settled.plan.amounts[0] + settled.plan.fee,
            input.amount,
            "the fee comes out of the amount"
        );
        let got = scan_transaction(&settled.built.tx, &them.keys()).expect("scan");
        assert_eq!(got[0].amount, settled.plan.amounts[0]);
    }
}
