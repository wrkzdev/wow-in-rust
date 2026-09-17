//! Per-output scanning: deciding whether a transaction paid this wallet.
//!
//! `specs/12` §3.2. `wallet2::process_new_transaction` and
//! `device_default.cpp`.
//!
//! # The order of the checks is the performance
//!
//! Every output of every transaction in the chain goes through this. The steps
//! are arranged cheapest-first and each one throws most candidates away:
//!
//! 1. one `generate_key_derivation` per transaction public key — a scalar
//!    multiplication, amortised over all the outputs,
//! 2. the **view tag** (HF 20+): one hash, and 255 of every 256 outputs stop
//!    here. This is the entire point of tagged keys,
//! 3. `derive_subaddress_public_key` and a hash-map lookup,
//! 4. only for a hit: the amount, the commitment check and the key image.
//!
//! Doing (3) before (2) is correct and roughly two hundred times slower.
//!
//! # Additional public keys
//!
//! A transaction paying a subaddress cannot use one shared `R` for every
//! output, so it writes `TX_EXTRA_TAG_ADDITIONAL_PUBKEYS` with one key per
//! output. The reference tries the main key first and the additional key for
//! that index second, and an output can match on either.

use wow_crypto::types::{
    AccountPublicAddress, Hash8, KeyDerivation, KeyImage, PublicKey, SecretKey, SubaddressIndex,
};
use wow_types::tx::{Transaction, TxOutTarget};

use crate::subaddress::SubaddressTable;

/// What the wallet learned about one output that belongs to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    /// Index within the transaction's output vector.
    pub output_index: u64,
    /// The one-time public key, `P`.
    pub public_key: PublicKey,
    /// Which of the wallet's addresses was paid.
    pub subaddress: SubaddressIndex,
    pub amount: u64,
    /// The commitment blinding factor, needed to spend the output. Zero for a
    /// pre-RingCT output, which has no commitment.
    pub mask: [u8; 32],
    /// `None` for a view-only wallet, which cannot compute it.
    pub key_image: Option<KeyImage>,
    /// The derivation the output matched under, kept so the caller can decrypt
    /// a payment id with it.
    pub derivation: KeyDerivation,
    /// True when the output carried a view tag and it matched. Recorded because
    /// a wallet that never sees one is scanning pre-HF-20 blocks, and that is
    /// worth being able to assert.
    pub had_view_tag: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScanError {
    #[error("the transaction has no public key in tx_extra")]
    NoTxPublicKey,
    #[error("output {0} decoded to an amount its commitment does not match")]
    CommitmentMismatch(u64),
    #[error("output {0} has no matching ecdhInfo entry")]
    MissingEcdhInfo(u64),
    #[error("output {0} has no matching outPk entry")]
    MissingOutPk(u64),
}

/// The keys scanning needs. A view-only wallet leaves `spend_secret_key`
/// `None`, and gets everything except key images.
pub struct ScanKeys<'a> {
    pub address: &'a AccountPublicAddress,
    pub view_secret_key: &'a SecretKey,
    pub spend_secret_key: Option<&'a SecretKey>,
    pub subaddresses: &'a SubaddressTable,
}

/// Scan one transaction for outputs belonging to `keys`.
///
/// Returns the outputs that are ours, in output order. An empty result is the
/// overwhelmingly common case and is not an error; the errors here mean the
/// transaction is malformed or the output is ours but inconsistent.
pub fn scan_transaction(tx: &Transaction, keys: &ScanKeys<'_>) -> Result<Vec<Received>, ScanError> {
    scan_transaction_with(tx, keys, None)
}

/// The key derivations scanning one transaction needs.
///
/// Every scalar multiplication [`scan_transaction`] does, and nothing else.
/// They are a pure function of the transaction's public keys and the view
/// secret key, which is what makes it safe to compute them anywhere — ahead
/// of time, on another thread, for a whole batch at once.
#[derive(Clone, Debug)]
pub struct Derivations {
    main: Option<KeyDerivation>,
    additional: Vec<Option<KeyDerivation>>,
}

/// Compute a transaction's derivations, for [`scan_transaction_with`].
///
/// Returns `None` for a transaction with no public key in `tx_extra`, which
/// [`scan_transaction`] refuses; the refusal is left to it so this can be run
/// over a batch without deciding anything.
pub fn derivations_for(tx: &Transaction, view_secret_key: &SecretKey) -> Option<Derivations> {
    let extra = wow_types::tx_extra::parse_tx_extra(&tx.prefix.extra);
    let tx_pub_key = extra.tx_pubkey()?;
    let additional = extra.additional_pubkeys().unwrap_or(&[]);
    Some(Derivations {
        main: wow_crypto::generate_key_derivation(&tx_pub_key, view_secret_key),
        additional: additional
            .iter()
            .map(|k| wow_crypto::generate_key_derivation(k, view_secret_key))
            .collect(),
    })
}

/// [`scan_transaction`], with the derivations supplied rather than computed.
///
/// `ready` is only ever the value [`derivations_for`] returns for this same
/// transaction and view key, so passing one changes how long the scan takes
/// and nothing about what it finds. A caller that is unsure passes `None`.
pub fn scan_transaction_with(
    tx: &Transaction,
    keys: &ScanKeys<'_>,
    ready: Option<&Derivations>,
) -> Result<Vec<Received>, ScanError> {
    let extra = wow_types::tx_extra::parse_tx_extra(&tx.prefix.extra);
    let tx_pub_key = extra.tx_pubkey().ok_or(ScanError::NoTxPublicKey)?;
    let additional = extra.additional_pubkeys().unwrap_or(&[]);

    // One scalar multiplication for the whole transaction, and one per
    // additional key — most transactions have none, and one that does is
    // paying a subaddress. This is the whole cost of a scan, which is why a
    // caller is allowed to have done it already.
    let computed = ready.is_none().then(|| Derivations {
        main: wow_crypto::generate_key_derivation(&tx_pub_key, keys.view_secret_key),
        additional: additional
            .iter()
            .map(|k| wow_crypto::generate_key_derivation(k, keys.view_secret_key))
            .collect(),
    });
    let d = ready.or(computed.as_ref()).expect("one or the other");
    let main_derivation = d.main;
    let additional_derivations = &d.additional;

    let mut found = Vec::new();
    for (i, out) in tx.prefix.vout.iter().enumerate() {
        let index = i as u64;
        let (out_key, view_tag) = match &out.target {
            TxOutTarget::ToKey { key } => (*key, None),
            TxOutTarget::ToTaggedKey { key, view_tag } => (*key, Some(*view_tag)),
            // Script outputs have never appeared on this chain and cannot be
            // owned by an address.
            _ => continue,
        };

        // The main key first, then this output's additional key.
        let candidates = [
            main_derivation,
            additional_derivations.get(i).copied().flatten(),
        ];

        for d in candidates.into_iter().flatten() {
            // Step 2: the cheap filter.
            if let Some(tag) = view_tag {
                if wow_crypto::derive_view_tag(&d, index) != tag {
                    continue;
                }
            }

            // Step 3: is the implied spend key one of ours?
            let Some(spend) = wow_crypto::derive_subaddress_public_key(&out_key, &d, index) else {
                continue;
            };
            let Some(subaddress) = keys.subaddresses.get(&spend) else {
                continue;
            };

            // Step 4: it is ours. Now the expensive part, once.
            let (amount, mask) = decode_amount(tx, index, &d, out.amount)?;
            // An output of nothing is not money received: `scan_output`
            // skips it, "Invalid output amount". It is what a sender's
            // zero change looks like, and a wallet that kept one would offer
            // it as an input, spending a fee to move nothing.
            if amount == 0 {
                break;
            }
            let key_image = keys
                .spend_secret_key
                .and_then(|s| output_key_image(&out_key, &d, index, subaddress, keys, s));

            found.push(Received {
                output_index: index,
                public_key: out_key,
                subaddress,
                amount,
                mask,
                key_image,
                derivation: d,
                had_view_tag: view_tag.is_some(),
            });
            break;
        }
    }
    Ok(found)
}

/// The payment id a transaction carries, decrypted: `process_new_transaction`.
///
/// Read as the C++ reads it: the first nonce in `extra`, if that is an
/// encrypted id, under the derivation of the transaction's public key -- the
/// main key, also for a payment to a subaddress. Zeros are the dummy a
/// transaction without an id carries, and are none. A plain 32-byte id is not
/// read; the C++ ignores one from block version 12.
pub fn payment_id(tx: &Transaction, view_secret_key: &SecretKey) -> Option<Hash8> {
    let extra = wow_types::tx_extra::parse_tx_extra(&tx.prefix.extra);
    let nonce = extra.fields.iter().find_map(|f| match f {
        wow_types::tx_extra::TxExtraField::Nonce(n) => Some(n),
        _ => None,
    })?;
    let encrypted: Hash8 = match nonce.as_slice() {
        [0x01, id @ ..] => id.try_into().ok()?,
        _ => return None,
    };
    let derivation = wow_crypto::generate_key_derivation(&extra.tx_pubkey()?, view_secret_key)?;
    let id = wow_crypto::keys::encrypt_payment_id(&encrypted, &derivation);
    (id != [0u8; 8]).then_some(id)
}

/// The amount, and the blinding factor needed to spend the output.
///
/// A pre-RingCT output carries its amount in the clear and has no commitment,
/// so there is nothing to decode and nothing to check.
fn decode_amount(
    tx: &Transaction,
    index: u64,
    derivation: &KeyDerivation,
    clear_amount: u64,
) -> Result<(u64, [u8; 32]), ScanError> {
    if tx.prefix.version < 2 || tx.rct_signatures.ty.is_null() {
        return Ok((clear_amount, [0u8; 32]));
    }

    let i = index as usize;
    let ecdh = tx
        .rct_signatures
        .ecdh_info
        .get(i)
        .ok_or(ScanError::MissingEcdhInfo(index))?;
    let out_pk = tx
        .rct_signatures
        .out_pk
        .get(i)
        .ok_or(ScanError::MissingOutPk(index))?;

    let shared = wow_crypto::derivation_to_scalar(derivation, index);

    let (amount, mask) = if tx.rct_signatures.ty.has_short_ecdh() {
        wow_crypto::rct::ecdh_decode_short(&ecdh.amount, &shared)
    } else {
        wow_crypto::rct::ecdh_decode_legacy(&ecdh.mask, &ecdh.amount, &shared)
            .ok_or(ScanError::CommitmentMismatch(index))?
    };

    // `outPk.mask` holds the full commitment for every type **except 8**, where
    // it holds `C / 8` (`specs/02` §4.4). Type 9 — the Wownero-only
    // `BulletproofPlusFullCommit` — exists precisely to undo that, so it is the
    // one type where "bulletproof plus" and "divided by eight" come apart.
    let commitment = if tx.rct_signatures.ty.is_bp_plus_legacy() {
        wow_crypto::rct::scalarmult8(out_pk).ok_or(ScanError::CommitmentMismatch(index))?
    } else {
        *out_pk
    };

    if !wow_crypto::rct::commitment_matches(amount, &mask, &commitment) {
        return Err(ScanError::CommitmentMismatch(index));
    }
    Ok((amount, mask.to_bytes()))
}

/// `x = Hs(D || i) + b [+ m]`, then `I = x * Hp(P)`.
///
/// The subaddress secret `m` is added only when the output went to a
/// subaddress; for the main address the C++ skips it, and adding zero would be
/// the same but the branch mirrors the reference.
fn output_key_image(
    out_key: &PublicKey,
    derivation: &KeyDerivation,
    index: u64,
    subaddress: SubaddressIndex,
    keys: &ScanKeys<'_>,
    spend_secret_key: &SecretKey,
) -> Option<KeyImage> {
    let mut x = wow_crypto::derive_secret_key(derivation, index, spend_secret_key);
    if !subaddress.is_main() {
        let m = wow_crypto::keys::subaddress_secret_key(keys.view_secret_key, subaddress);
        x = SecretKey(wow_crypto::ops::sc_add(&x.0, &m.0));
    }
    wow_crypto::generate_key_image(out_key, &x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use wow_crypto::ops::{encode_point, scalarmult_base};
    use wow_crypto::types::{EcPoint, EcScalar, ViewTag};
    use wow_types::rct::{EcdhInfo, RctSignatures, RctType};
    use wow_types::tx::{TransactionPrefix, TxOut};
    use wow_types::tx_extra::{serialize_tx_extra, TxExtraField};

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
        let table = SubaddressTable::new(&address, &view, 2, 3);
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

        fn watch_only(&self) -> ScanKeys<'_> {
            ScanKeys {
                address: &self.address,
                view_secret_key: &self.view,
                spend_secret_key: None,
                subaddresses: &self.table,
            }
        }
    }

    /// What a sender computes for one output.
    ///
    /// This is the other half of the protocol, written out here so the scan is
    /// tested against an independent construction rather than against itself.
    struct Sent {
        out: TxOut,
        ecdh: EcdhInfo,
        out_pk: EcPoint,
    }

    fn send_to(
        r: &Scalar,
        recipient: &AccountPublicAddress,
        index: u64,
        amount: u64,
        tagged: bool,
    ) -> Sent {
        // For the main address the shared secret is `r * A`; for a subaddress
        // it is `r * C`, where C is that subaddress's own view key.
        let a = wow_crypto::ops::decode_point(&recipient.view_public_key.0).expect("valid");
        let derivation = KeyDerivation(encode_point(&wow_crypto::ops::mul8(&(r * a))));

        // P = Hs(D || i) * G + B
        let hs = wow_crypto::keys::derivation_to_scalar_dalek(&derivation, index);
        let b = wow_crypto::ops::decode_point(&recipient.spend_public_key.0).expect("valid");
        let p = PublicKey(encode_point(&(scalarmult_base(&hs) + b)));

        let target = if tagged {
            TxOutTarget::ToTaggedKey {
                key: p,
                view_tag: wow_crypto::derive_view_tag(&derivation, index),
            }
        } else {
            TxOutTarget::ToKey { key: p }
        };

        // The amount, encoded the short way.
        let shared = wow_crypto::derivation_to_scalar(&derivation, index);
        let mask = wow_crypto::rct::commitment_mask(&shared);
        let pad = wow_crypto::rct::amount_pad(&shared);
        let mut enc = [0u8; 32];
        for (o, (b, p)) in enc
            .iter_mut()
            .zip(amount.to_le_bytes().iter().zip(pad.iter()))
        {
            *o = b ^ p;
        }

        Sent {
            out: TxOut { amount: 0, target },
            ecdh: EcdhInfo {
                mask: EcScalar::ZERO,
                amount: EcScalar(enc),
            },
            out_pk: wow_crypto::rct::commit(amount, &mask),
        }
    }

    fn transaction(sent: Vec<Sent>, extra: Vec<TxExtraField>, ty: RctType) -> Transaction {
        let mut tx = Transaction {
            prefix: TransactionPrefix {
                version: 2,
                unlock_time: 0,
                vin: Vec::new(),
                vout: sent.iter().map(|s| s.out.clone()).collect(),
                extra: serialize_tx_extra(&extra, false),
            },
            rct_signatures: RctSignatures {
                ty,
                ..Default::default()
            },
            ..Default::default()
        };
        for s in &sent {
            tx.rct_signatures.ecdh_info.push(s.ecdh);
            tx.rct_signatures.out_pk.push(s.out_pk);
        }
        tx
    }

    fn tx_key(seed: u8) -> (Scalar, PublicKey) {
        let r = Scalar::from_bytes_mod_order([seed; 32]);
        (r, PublicKey(encode_point(&scalarmult_base(&r))))
    }

    /// One output to the main address: found, with the right amount and a key
    /// image.
    #[test]
    fn it_finds_a_payment_to_the_main_address() {
        let w = wallet(7);
        let (r, big_r) = tx_key(3);
        let sent = send_to(&r, &w.address, 0, 1_234_500_000_000, true);
        let tx = transaction(
            vec![sent],
            vec![TxExtraField::Pubkey(big_r)],
            RctType::BulletproofPlusFullCommit,
        );

        let found = scan_transaction(&tx, &w.keys()).expect("scan");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].amount, 1_234_500_000_000);
        assert_eq!(found[0].subaddress, SubaddressIndex::MAIN);
        assert!(found[0].had_view_tag);
        assert!(found[0].key_image.is_some());

        // Supplying the derivations rather than computing them changes when
        // the scalar multiplications happen and nothing else. That is the
        // whole safety argument for a refresh precomputing a batch of them on
        // every core, so it is asserted rather than assumed.
        let ready = derivations_for(&tx, &w.view).expect("derivations");
        assert_eq!(
            scan_transaction_with(&tx, &w.keys(), Some(&ready)).expect("scan"),
            found
        );
    }

    /// And a wallet the transaction does not pay finds nothing either way.
    /// The empty result is the case that happens millions of times over a
    /// refresh, so it is the one worth pinning.
    #[test]
    fn precomputed_derivations_find_nothing_where_a_scan_finds_nothing() {
        let w = wallet(7);
        let theirs = wallet(8);
        let (r, big_r) = tx_key(4);
        let sent = send_to(&r, &w.address, 0, 5_000, true);
        let tx = transaction(
            vec![sent],
            vec![TxExtraField::Pubkey(big_r)],
            RctType::BulletproofPlus,
        );

        let ready = derivations_for(&tx, &theirs.view).expect("derivations");
        assert!(scan_transaction(&tx, &theirs.keys())
            .expect("scan")
            .is_empty());
        assert!(scan_transaction_with(&tx, &theirs.keys(), Some(&ready))
            .expect("scan")
            .is_empty());
    }

    /// A different wallet sees nothing. This is the case that happens millions
    /// of times per refresh, so it had better be the cheap one and it had
    /// better be right.
    #[test]
    fn another_wallet_sees_nothing() {
        let mine = wallet(7);
        let theirs = wallet(9);
        let (r, big_r) = tx_key(3);
        let sent = send_to(&r, &theirs.address, 0, 5_000, true);
        let tx = transaction(
            vec![sent],
            vec![TxExtraField::Pubkey(big_r)],
            RctType::BulletproofPlusFullCommit,
        );

        assert!(scan_transaction(&tx, &mine.keys())
            .expect("scan")
            .is_empty());
        assert_eq!(
            scan_transaction(&tx, &theirs.keys()).expect("scan").len(),
            1
        );
    }

    /// A payment to a subaddress arrives through the additional public keys,
    /// and the scan reports which subaddress was paid.
    #[test]
    fn it_finds_a_payment_to_a_subaddress() {
        let w = wallet(7);
        let index = SubaddressIndex::new(1, 2);
        let sub = wow_crypto::get_subaddress(&w.address, &w.view, index).expect("derivable");

        // Paying a subaddress, the sender's R is `r * D`, not `r * G`.
        let r = Scalar::from_bytes_mod_order([11u8; 32]);
        let d = wow_crypto::ops::decode_point(&sub.spend_public_key.0).expect("valid");
        let big_r = PublicKey(encode_point(&(r * d)));

        let sent = send_to(&r, &sub, 0, 99, true);
        // A subaddress send still writes a main pubkey; the one that matches is
        // the additional key for this output.
        let (_, decoy) = tx_key(42);
        let tx = transaction(
            vec![sent],
            vec![
                TxExtraField::Pubkey(decoy),
                TxExtraField::AdditionalPubkeys(vec![big_r]),
            ],
            RctType::BulletproofPlusFullCommit,
        );

        let found = scan_transaction(&tx, &w.keys()).expect("scan");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].subaddress, index);
        assert_eq!(found[0].amount, 99);
    }

    /// A subaddress past the lookahead is missed, and appears once the table is
    /// extended. This is why the lookahead exists, and what a wallet that
    /// outruns it loses.
    #[test]
    fn a_subaddress_past_the_lookahead_is_missed() {
        let mut w = wallet(7);
        let index = SubaddressIndex::new(1, 9); // the table covers minor < 3
        let sub = wow_crypto::get_subaddress(&w.address, &w.view, index).expect("derivable");

        let r = Scalar::from_bytes_mod_order([13u8; 32]);
        let d = wow_crypto::ops::decode_point(&sub.spend_public_key.0).expect("valid");
        let big_r = PublicKey(encode_point(&(r * d)));
        let sent = send_to(&r, &sub, 0, 7, true);
        let (_, decoy) = tx_key(42);
        let tx = transaction(
            vec![sent],
            vec![
                TxExtraField::Pubkey(decoy),
                TxExtraField::AdditionalPubkeys(vec![big_r]),
            ],
            RctType::BulletproofPlusFullCommit,
        );

        assert!(scan_transaction(&tx, &w.keys()).expect("scan").is_empty());

        w.table.extend(&w.address, &w.view, 2, 10);
        let found = scan_transaction(&tx, &w.keys()).expect("scan");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].subaddress, index);
    }

    /// Type 8 stores `C / 8`; type 9 stores `C`. The same transaction body
    /// decodes under one and not the other, which is the whole content of
    /// `specs/02` §4.4.
    #[test]
    fn the_type_eight_commitment_is_divided_by_eight() {
        let w = wallet(7);
        let (r, big_r) = tx_key(3);
        let sent = send_to(&r, &w.address, 0, 4_242, true);
        let full = sent.out_pk;

        let tx9 = transaction(
            vec![Sent {
                out: sent.out.clone(),
                ecdh: sent.ecdh,
                out_pk: full,
            }],
            vec![TxExtraField::Pubkey(big_r)],
            RctType::BulletproofPlusFullCommit,
        );
        assert_eq!(
            scan_transaction(&tx9, &w.keys()).expect("scan")[0].amount,
            4_242
        );

        // As type 8, the same bytes are read as `C / 8` and multiplied by
        // eight, so they no longer match the amount.
        let tx8 = transaction(
            vec![Sent {
                out: sent.out,
                ecdh: sent.ecdh,
                out_pk: full,
            }],
            vec![TxExtraField::Pubkey(big_r)],
            RctType::BulletproofPlus,
        );
        assert_eq!(
            scan_transaction(&tx8, &w.keys()),
            Err(ScanError::CommitmentMismatch(0))
        );
    }

    /// A tampered amount is caught by the commitment rather than accepted.
    #[test]
    fn a_forged_amount_is_rejected() {
        let w = wallet(7);
        let (r, big_r) = tx_key(3);
        let mut sent = send_to(&r, &w.address, 0, 1_000, true);
        sent.ecdh.amount.0[0] ^= 0xff;
        let tx = transaction(
            vec![sent],
            vec![TxExtraField::Pubkey(big_r)],
            RctType::BulletproofPlusFullCommit,
        );
        assert_eq!(
            scan_transaction(&tx, &w.keys()),
            Err(ScanError::CommitmentMismatch(0))
        );
    }

    /// A wrong view tag stops the scan before the expensive work. The output
    /// really is ours and only the tag is wrong, so a scanner that ignored tags
    /// would find it.
    #[test]
    fn a_wrong_view_tag_skips_the_output() {
        let w = wallet(7);
        let (r, big_r) = tx_key(3);
        let mut sent = send_to(&r, &w.address, 0, 10, true);
        if let TxOutTarget::ToTaggedKey { key, view_tag } = sent.out.target {
            sent.out.target = TxOutTarget::ToTaggedKey {
                key,
                view_tag: ViewTag(view_tag.0 ^ 0xff),
            };
        }
        let tx = transaction(
            vec![sent],
            vec![TxExtraField::Pubkey(big_r)],
            RctType::BulletproofPlusFullCommit,
        );
        assert!(scan_transaction(&tx, &w.keys()).expect("scan").is_empty());
    }

    /// An output of nothing to this wallet is not recorded, as `scan_output`
    /// skips it, so it can never be picked to spend. The paying output beside
    /// it is found as usual.
    #[test]
    fn an_output_of_nothing_is_not_received() {
        let w = wallet(7);
        let (r, big_r) = tx_key(3);
        let tx = transaction(
            vec![
                send_to(&r, &w.address, 0, 0, true),
                send_to(&r, &w.address, 1, 5_000, true),
            ],
            vec![TxExtraField::Pubkey(big_r)],
            RctType::BulletproofPlusFullCommit,
        );
        let found = scan_transaction(&tx, &w.keys()).expect("scan");
        assert_eq!(found.len(), 1, "only the output that pays");
        assert_eq!((found[0].output_index, found[0].amount), (1, 5_000));
    }

    /// An untagged output — a pre-HF-20 transaction — is still found, just
    /// without the cheap filter in front of it.
    #[test]
    fn an_untagged_output_is_found() {
        let w = wallet(7);
        let (r, big_r) = tx_key(3);
        let sent = send_to(&r, &w.address, 0, 88, false);
        let tx = transaction(
            vec![sent],
            vec![TxExtraField::Pubkey(big_r)],
            RctType::BulletproofPlusFullCommit,
        );
        let found = scan_transaction(&tx, &w.keys()).expect("scan");
        assert_eq!(found.len(), 1);
        assert!(!found[0].had_view_tag);
    }

    /// A watch-only wallet sees the money and cannot compute the key image,
    /// which is the difference between watching and spending.
    #[test]
    fn a_watch_only_wallet_has_no_key_images() {
        let w = wallet(7);
        let (r, big_r) = tx_key(3);
        let sent = send_to(&r, &w.address, 0, 500, true);
        let tx = transaction(
            vec![sent],
            vec![TxExtraField::Pubkey(big_r)],
            RctType::BulletproofPlusFullCommit,
        );

        let full = scan_transaction(&tx, &w.keys()).expect("scan");
        let watch = scan_transaction(&tx, &w.watch_only()).expect("scan");
        assert_eq!(full[0].amount, watch[0].amount);
        assert_eq!(full[0].public_key, watch[0].public_key);
        assert!(full[0].key_image.is_some());
        assert!(watch[0].key_image.is_none());
    }

    /// Several outputs, only some of them ours, at the right indices. The
    /// output index feeds the derivation, so an off-by-one here finds nothing
    /// rather than finding the wrong thing.
    #[test]
    fn it_finds_the_right_indices_among_several_outputs() {
        let mine = wallet(7);
        let theirs = wallet(9);
        let (r, big_r) = tx_key(3);

        let sent = vec![
            send_to(&r, &theirs.address, 0, 1, true),
            send_to(&r, &mine.address, 1, 2_000, true),
            send_to(&r, &theirs.address, 2, 3, true),
            send_to(&r, &mine.address, 3, 4_000, true),
        ];
        let tx = transaction(
            sent,
            vec![TxExtraField::Pubkey(big_r)],
            RctType::BulletproofPlusFullCommit,
        );

        let found = scan_transaction(&tx, &mine.keys()).expect("scan");
        assert_eq!(found.len(), 2);
        assert_eq!((found[0].output_index, found[0].amount), (1, 2_000));
        assert_eq!((found[1].output_index, found[1].amount), (3, 4_000));
    }

    /// A transaction with no public key in `extra` is malformed, and says so
    /// rather than being silently skipped.
    #[test]
    fn a_missing_tx_public_key_is_an_error() {
        let w = wallet(7);
        let tx = transaction(Vec::new(), Vec::new(), RctType::BulletproofPlusFullCommit);
        assert_eq!(
            scan_transaction(&tx, &w.keys()),
            Err(ScanError::NoTxPublicKey)
        );
    }
}
