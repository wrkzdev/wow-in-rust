//! Transaction parser edge cases where the reference does something surprising.
//!
//! Each of these pins a behaviour that a "cleaner" implementation would get
//! wrong in a way no round-trip test would catch.

use wow_crypto::types::{EcPoint, EcScalar, KeyImage, PublicKey, Signature, ViewTag};
use wow_serialize::binary::{Reader, Writer};
use wow_serialize::error::Error;
use wow_types::rct::{Clsag, EcdhInfo, RctSignatures, RctType};
use wow_types::tx::{Transaction, TransactionPrefix, TxIn, TxOut, TxOutTarget};

fn to_key(ring: usize, ki: u8) -> TxIn {
    TxIn::ToKey {
        amount: 0,
        key_offsets: (0..ring).map(|i| i as u64 + 1).collect(),
        k_image: KeyImage([ki; 32]),
    }
}

fn out(tagged: bool) -> TxOut {
    TxOut {
        amount: 0,
        target: if tagged {
            TxOutTarget::ToTaggedKey {
                key: PublicKey([9; 32]),
                view_tag: ViewTag(0x7f),
            }
        } else {
            TxOutTarget::ToKey {
                key: PublicKey([9; 32]),
            }
        },
    }
}

/// `specs/05` §2.1: `key_offsets` are relative, so ring members are a running
/// sum. A wrong conversion picks entirely different decoys — and would still
/// round-trip, so only this test catches it.
#[test]
fn key_offsets_are_relative() {
    let input = TxIn::ToKey {
        amount: 0,
        key_offsets: vec![100, 5, 0, 7],
        k_image: KeyImage([1; 32]),
    };
    assert_eq!(
        input.absolute_key_offsets(),
        Some(vec![100, 105, 105, 112]),
        "absolute[0] = relative[0], then a running sum"
    );
    assert_eq!(input.ring_size(), Some(4));
    assert_eq!(input.signature_size(), 4);

    // Overflow is reported, not wrapped.
    let input = TxIn::ToKey {
        amount: 0,
        key_offsets: vec![u64::MAX, 1],
        k_image: KeyImage([1; 32]),
    };
    assert_eq!(input.absolute_key_offsets(), None);
}

/// `txin_gen` is tag `0xff`, not `0x03` — the one tag whose value is not its
/// position in the variant list (`specs/04` §1.3).
#[test]
fn variant_tags() {
    assert_eq!(TxIn::Gen { height: 0 }.tag(), 0xff);
    assert_eq!(to_key(1, 0).tag(), 0x02);
    assert_eq!(out(false).target.tag(), 0x02);
    assert_eq!(out(true).target.tag(), 0x03);
}

/// The C's `PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(), signatures)`
/// resizes the outer vector to one row per input on load, so a v1 coinbase —
/// whose single `txin_gen` has `get_signature_size() == 0` — still ends up with
/// one (empty) row rather than none.
#[test]
fn v1_signatures_have_one_row_per_input() {
    let prefix = TransactionPrefix {
        version: 1,
        unlock_time: 0,
        vin: vec![TxIn::Gen { height: 7 }, to_key(3, 1)],
        vout: vec![out(false)],
        extra: vec![],
    };
    let tx = Transaction {
        prefix,
        signatures: vec![vec![], vec![Signature::ZERO; 3]],
        rct_signatures: RctSignatures::null(),
        prefix_size: 0,
        unprunable_size: 0,
    };
    let mut w = Writer::new();
    tx.write(&mut w);
    let blob = w.into_vec();

    let parsed = Transaction::from_blob(&blob).unwrap();
    assert_eq!(parsed.signatures.len(), 2, "one row per input");
    assert!(parsed.signatures[0].is_empty(), "txin_gen contributes none");
    assert_eq!(parsed.signatures[1].len(), 3, "one per ring member");
    // No length prefixes anywhere: the blob is prefix + 3 * 64 bytes.
    assert_eq!(blob.len(), parsed.prefix_size + 3 * 64);
    assert_eq!(parsed.unprunable_size, parsed.prefix_size, "v1");
}

/// An **empty** `key_offsets` on `vin[0]` makes the C compute
/// `mixin = key_offsets.size() - 1` in `size_t`, which underflows to `SIZE_MAX`
/// and is then caught by `mixin >= 0xffffffff` in `serialize_rctsig_prunable`.
///
/// Saturating to 0 instead would accept a blob the reference rejects, and then
/// read a one-element CLSAG where the reference read nothing.
#[test]
fn empty_key_offsets_underflow_the_mixin_and_are_rejected() {
    let prefix = TransactionPrefix {
        version: 2,
        unlock_time: 0,
        vin: vec![TxIn::ToKey {
            amount: 0,
            key_offsets: vec![],
            k_image: KeyImage([1; 32]),
        }],
        vout: vec![out(true), out(true)],
        extra: vec![],
    };
    let mut w = Writer::new();
    prefix.write(&mut w);
    let rv = RctSignatures {
        ty: RctType::Clsag,
        txn_fee: 1,
        ecdh_info: vec![EcdhInfo::default(); 2],
        out_pk: vec![EcPoint::ZERO; 2],
        clsags: vec![Clsag {
            s: vec![EcScalar::ZERO],
            ..Default::default()
        }],
        ..Default::default()
    };
    rv.write_base(&mut w, 2);
    rv.write_prunable(&mut w);
    let blob = w.into_vec();

    assert!(
        matches!(
            Transaction::from_blob_base_only(&blob),
            Err(Error::LimitExceeded("rct dimension"))
        ),
        "an empty key_offsets must trip the mixin guard"
    );
}

/// `specs/04` §1.6: version 0 or above `CURRENT_TRANSACTION_VERSION` is a
/// **parse** error, from inside the serializer itself.
#[test]
fn transaction_version_bounds_are_a_parse_error() {
    for v in [0u64, 3, 255] {
        let mut w = Writer::new();
        w.write_varint(v);
        w.write_varint(0); // unlock_time
        w.write_varint(0); // vin
        w.write_varint(0); // vout
        w.write_varint(0); // extra
        assert!(
            matches!(
                Transaction::from_blob(w.as_slice()),
                Err(Error::InvalidValue("transaction version"))
            ),
            "version {v} should not parse"
        );
    }
    // 1 and 2 do parse.
    for v in [1u64, 2] {
        let mut w = Writer::new();
        w.write_varint(v);
        w.write_varint(0);
        w.write_varint(0);
        w.write_varint(0);
        w.write_varint(0);
        assert!(Transaction::from_blob(w.as_slice()).is_ok(), "version {v}");
    }
}

/// `specs/05` §5.2.
#[test]
fn fee_extraction() {
    let mut tx = Transaction {
        prefix: TransactionPrefix {
            version: 2,
            vin: vec![to_key(2, 1)],
            vout: vec![out(true), out(true)],
            ..Default::default()
        },
        rct_signatures: RctSignatures {
            ty: RctType::BulletproofPlus,
            txn_fee: 4242,
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(tx.fee(), Some(4242), "v2 takes rct.txnFee verbatim");

    tx.prefix.version = 1;
    tx.prefix.vin = vec![TxIn::ToKey {
        amount: 1000,
        key_offsets: vec![1],
        k_image: KeyImage([1; 32]),
    }];
    tx.prefix.vout = vec![TxOut {
        amount: 700,
        target: TxOutTarget::ToKey {
            key: PublicKey([2; 32]),
        },
    }];
    assert_eq!(tx.fee(), Some(300), "v1 is inputs minus outputs");

    // Outputs exceeding inputs is reported, not wrapped.
    tx.prefix.vout[0].amount = 2000;
    assert_eq!(tx.fee(), None);
}

/// `specs/05` §2.1: the script input types have never appeared on chain and are
/// rejected by `check_tx_inputs`, but they must still **parse** so blobs
/// round-trip.
#[test]
fn script_inputs_still_roundtrip() {
    let prefix = TransactionPrefix {
        version: 1,
        unlock_time: 0,
        vin: vec![
            TxIn::ToScript {
                prev: [3; 32],
                prevout: 9,
                sigset: vec![1, 2, 3],
            },
            TxIn::ToScriptHash {
                prev: [4; 32],
                prevout: 10,
                script: TxOutTarget::ToScript {
                    keys: vec![PublicKey([5; 32])],
                    script: vec![7, 8],
                },
                sigset: vec![9],
            },
        ],
        vout: vec![TxOut {
            amount: 1,
            target: TxOutTarget::ToScriptHash { hash: [6; 32] },
        }],
        extra: vec![],
    };
    let mut w = Writer::new();
    prefix.write(&mut w);
    let blob = w.into_vec();
    let mut r = Reader::new(&blob);
    assert_eq!(TransactionPrefix::read(&mut r).unwrap(), prefix);
    assert!(r.is_empty());
}

#[test]
fn unknown_variant_tags_are_rejected() {
    let mut w = Writer::new();
    w.write_varint(1); // version
    w.write_varint(0); // unlock_time
    w.write_varint(1); // one input
    w.write_u8(0x42); // not a txin tag
    assert!(matches!(
        Transaction::from_blob(w.as_slice()),
        Err(Error::UnknownVariantTag(0x42))
    ));
}

/// `specs/15` §4.4: the transaction and block parsers are fuzz targets, and a
/// panic in either is a remote crash.
#[test]
fn parsers_never_panic() {
    use wow_types::block::Block;

    let mut x: u64 = 0x243f_6a88_85a3_08d3;
    for len in 0..400usize {
        let mut b = Vec::with_capacity(len);
        for _ in 0..len {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            b.push((x >> 33) as u8);
        }
        let _ = Transaction::from_blob(&b);
        let _ = Transaction::from_blob_base_only(&b);
        let _ = Block::from_blob(&b);
    }

    // Valid-looking prefixes with a garbage tail, one per possible next byte.
    let mut w = Writer::new();
    w.write_varint(2);
    w.write_varint(0);
    w.write_varint(1);
    let base = w.into_vec();
    for tail in 0u16..=255 {
        let mut b = base.clone();
        b.push(tail as u8);
        b.extend_from_slice(&[0xff; 96]);
        let _ = Transaction::from_blob(&b);
        let _ = Block::from_blob(&b);
    }

    // Every RCT type byte, with an empty prunable part.
    for ty in 0u16..=255 {
        let mut w = Writer::new();
        w.write_varint(2); // version
        w.write_varint(0); // unlock_time
        w.write_varint(1); // one input
        w.write_u8(0x02); // txin_to_key
        w.write_varint(0); // amount
        w.write_varint(1); // one key offset
        w.write_varint(5);
        w.write_bytes(&[0u8; 32]); // key image
        w.write_varint(2); // two outputs
        for _ in 0..2 {
            w.write_varint(0);
            w.write_u8(0x02);
            w.write_bytes(&[0u8; 32]);
        }
        w.write_varint(0); // extra
        w.write_u8(ty as u8);
        let _ = Transaction::from_blob(w.as_slice());
    }
}

/// A BulletproofPlus transaction with its prunable half in place, as a blob.
fn bp_plus_blob() -> Vec<u8> {
    let prefix = TransactionPrefix {
        version: 2,
        unlock_time: 0,
        vin: vec![to_key(22, 1)],
        vout: vec![out(true), out(true)],
        extra: vec![1, 2, 3],
    };
    let rv = RctSignatures {
        ty: RctType::BulletproofPlus,
        txn_fee: 1000,
        ecdh_info: vec![EcdhInfo::default(); 2],
        out_pk: vec![EcPoint::ZERO; 2],
        bulletproofs_plus: vec![wow_types::rct::BulletproofPlus {
            l: vec![EcPoint::ZERO; 7],
            r: vec![EcPoint::ZERO; 7],
            ..Default::default()
        }],
        clsags: vec![Clsag {
            s: vec![EcScalar::ZERO; 22],
            ..Default::default()
        }],
        pseudo_outs: vec![EcPoint::ZERO],
        ..Default::default()
    };
    let tx = Transaction {
        prefix,
        signatures: Vec::new(),
        rct_signatures: rv,
        prefix_size: 0,
        unprunable_size: 0,
    };
    let mut w = Writer::new();
    tx.write(&mut w);
    w.into_vec()
}

/// A truncated blob must never be mistaken for the whole one.
///
/// Note it may still *parse*: the reference's `serialize_uvarint` treats
/// running out of input as a successful read of the partial value
/// (`wow_serialize::varint::read_varint_bits`), so e.g. the single byte `0x02`
/// decodes as a complete v2 transaction with no inputs and no outputs. That
/// quirk is reproduced deliberately, so the invariant to pin is the one that
/// matters — a truncated blob never yields the original transaction, and never
/// re-serializes to itself.
#[test]
fn truncation_at_every_offset() {
    let blob = bp_plus_blob();

    // The whole blob parses, and round-trips.
    let parsed = Transaction::from_blob(&blob).unwrap();
    assert_eq!(parsed.rct_signatures.ty, RctType::BulletproofPlus);
    let mut rw = Writer::new();
    parsed.write(&mut rw);
    assert_eq!(rw.as_slice(), &blob[..]);

    let mut accepted = 0usize;
    for cut in 0..blob.len() {
        let short = &blob[..cut];
        let Ok(t) = Transaction::from_blob(short) else {
            continue;
        };
        accepted += 1;
        assert_ne!(
            t, parsed,
            "a blob truncated to {cut} bytes yielded the whole transaction"
        );
        let mut w2 = Writer::new();
        t.write(&mut w2);
        assert_ne!(
            w2.as_slice(),
            short,
            "a blob truncated to {cut} bytes round-tripped"
        );
    }
    // Only the handful of cuts that land inside a run of varints can be
    // accepted at all; if this grows, the EOF tolerance has leaked somewhere
    // it should not have.
    assert!(
        accepted <= 8,
        "{accepted} truncated blobs parsed; expected only the varint-run cuts"
    );
}

/// `parse_and_validate_tx_base_from_blob`: a pruned transaction is its prefix
/// and RingCT base, and parses as that, though as a whole transaction it is
/// cut short. A daemon asked for pruned blocks sends exactly this.
#[test]
fn a_pruned_blob_parses_base_only() {
    let blob = bp_plus_blob();
    let whole = Transaction::from_blob(&blob).unwrap();
    let pruned = &blob[..whole.unprunable_size];

    assert!(
        Transaction::from_blob(pruned).is_err(),
        "not a whole transaction"
    );
    let base = Transaction::from_blob_base_only(pruned).expect("a pruned transaction parses");
    assert_eq!(base.prefix, whole.prefix);
    assert_eq!(base.rct_signatures.ty, whole.rct_signatures.ty);
    assert_eq!(base.rct_signatures.txn_fee, whole.rct_signatures.txn_fee);
    assert_eq!(
        base.rct_signatures.ecdh_info,
        whole.rct_signatures.ecdh_info
    );
    assert_eq!(base.rct_signatures.out_pk, whole.rct_signatures.out_pk);
    assert_eq!(base.unprunable_size, whole.unprunable_size);
    assert!(
        base.rct_signatures.clsags.is_empty(),
        "nothing prunable was read"
    );

    // A whole blob reads to the same fields, and the rest is left unread.
    assert_eq!(Transaction::from_blob_base_only(&blob).unwrap(), base);
}
