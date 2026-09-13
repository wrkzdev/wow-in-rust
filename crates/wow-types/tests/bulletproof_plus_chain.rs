//! A Bulletproof+ from a real chain, verified.
//!
//! Everything in `wow-crypto`'s own Bulletproof+ tests proves the prover and
//! the verifier agree with each other. That is worth having and it is not the
//! question that matters, which is whether either agrees with the C++.
//!
//! `tests/corpus/foreign/bpp_tx_e89415.bin` answers it. It is a **Monero**
//! mainnet transaction (height 2,777,777, txid `e89415b9…`) that the Wownero
//! tree inherited as test data, and its range proof was produced by
//! `bulletproof_plus_PROVE` running on a real node. The Bulletproof+ code is
//! shared between the two chains verbatim — same generators, same domain
//! separators `"bulletproof_plus"` and `"bulletproof_plus_transcript"`, same
//! transcript — so a proof from either verifies under the other.
//!
//! What is *not* shared is the RCT type numbering. Wownero inserted
//! `FullBulletproof = 3` and `SimpleBulletproof = 4`, so Monero's
//! `BulletproofPlus = 6` is Wownero's `Bulletproof2 = 6` and the blob does not
//! parse (`roundtrip.rs` pins that, and it should stay pinned). This test
//! renumbers **that one byte** and nothing else, which is enough to read the
//! same bytes back with the same layout.

use std::path::PathBuf;

use wow_crypto::bulletproofs_plus as bpp;
use wow_types::rct::RctType;
use wow_types::tx::Transaction;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus")
}

/// Read the Monero transaction, renumber its RCT type, and verify the
/// Bulletproof+ inside it.
#[test]
fn a_bulletproof_plus_from_the_monero_chain_verifies() {
    let path = corpus_dir().join("foreign/bpp_tx_e89415.bin");
    let blob = std::fs::read(&path).expect("foreign/bpp_tx_e89415.bin");

    // Find the RCT type byte: it is the first thing after the prefix.
    let mut r = wow_serialize::binary::Reader::new(&blob);
    let prefix = wow_types::tx::TransactionPrefix::read(&mut r).expect("the prefix is shared");
    let type_offset = r.pos();
    assert_eq!(blob[type_offset], 6, "Monero BulletproofPlus is 6");

    let mut renumbered = blob.clone();
    renumbered[type_offset] = RctType::BulletproofPlus as u8; // 8 on Wownero

    let tx = Transaction::from_blob(&renumbered)
        .expect("the layouts match once the type byte is renumbered");
    assert_eq!(tx.rct_signatures.ty, RctType::BulletproofPlus);
    assert_eq!(tx.prefix.vout.len(), prefix.vout.len());
    assert_eq!(
        tx.rct_signatures.bulletproofs_plus.len(),
        1,
        "one aggregated proof covers both outputs"
    );

    // Reconstruct `V`. It is not serialized; the verifier rebuilds it from
    // `outPk.mask`. Monero's mask holds the full commitment, so `V = C / 8`.
    let wire = &tx.rct_signatures.bulletproofs_plus[0];
    let v: Vec<_> = tx
        .rct_signatures
        .out_pk
        .iter()
        .map(|mask| wow_crypto::rct::div8(mask).expect("outPk.mask decodes"))
        .collect();
    assert_eq!(v.len(), 2);

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

    // Two outputs aggregate into M = 2, so logM = 1 and there are 7 rounds.
    assert_eq!(proof.l.len(), 7, "6 + logM rounds");
    assert_eq!(proof.r.len(), 7);

    bpp::verify(&proof).expect("a proof the C++ produced verifies here");
}

/// The same proof with one element disturbed must fail, so the test above is
/// not passing for some degenerate reason.
#[test]
fn the_chain_proof_fails_when_disturbed() {
    let path = corpus_dir().join("foreign/bpp_tx_e89415.bin");
    let blob = std::fs::read(&path).expect("foreign/bpp_tx_e89415.bin");

    let mut r = wow_serialize::binary::Reader::new(&blob);
    wow_types::tx::TransactionPrefix::read(&mut r).expect("the prefix is shared");
    let mut renumbered = blob.clone();
    renumbered[r.pos()] = RctType::BulletproofPlus as u8;
    let tx = Transaction::from_blob(&renumbered).expect("parses");

    let wire = &tx.rct_signatures.bulletproofs_plus[0];
    let v: Vec<_> = tx
        .rct_signatures
        .out_pk
        .iter()
        .map(|mask| wow_crypto::rct::div8(mask).expect("decodes"))
        .collect();

    let good = bpp::BulletproofPlus {
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

    let mut bad = good.clone();
    bad.r1.0[0] ^= 1;
    assert!(bpp::verify(&bad).is_err(), "a tampered r1 must not verify");

    // Forgetting the `/8` on V is the mistake this file exists to catch.
    let mut bad = good.clone();
    bad.v = tx.rct_signatures.out_pk.clone();
    assert!(
        bpp::verify(&bad).is_err(),
        "V is C/8, not the stored mask itself"
    );

    // And swapping the two commitments changes which amount each proves.
    let mut bad = good;
    bad.v.swap(0, 1);
    assert!(bpp::verify(&bad).is_err(), "the commitments are ordered");
}
