//! Cold signing, end to end, through the files.
//!
//! Two wallets that share a view key and nothing else:
//!
//! ```text
//! watch-only                                cold (offline)
//! ----------                                --------------
//! export_outputs      --- outputs file --->  import_outputs
//! import_key_images   <-- key image file --  export_key_images
//! (an unsigned set)   --- unsigned file -->  sign_transfer
//! submit_transfer     <--- signed file ----  (the signed set)
//! ```
//!
//! Everything crosses as a **file**: the bytes the C++ wallet would be handed.
//! The unsigned set is built by hand here rather than by
//! `Session::prepare_unsigned`, because planning needs a daemon for the fee
//! and the output distribution and this test has neither — what is under test
//! is the half that has no network anyway.
//!
//! The last step is the one that matters: the transaction the cold half signs
//! is verified the way a node verifies one — every CLSAG, the range proof and
//! the commitment balance — and then the payee scans it and finds the money.
//! A signature made from the wrong key, a mask that did not survive the file,
//! or a destination read back wrong all show up there.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;

use wow_crypto::bulletproofs_plus as bpp;
use wow_crypto::clsag;
use wow_crypto::ops::encode_point;
use wow_crypto::random::Rng;
use wow_crypto::types::{EcPoint, KeyImage, PublicKey, SecretKey, SubaddressIndex};
use wow_types::rct::RctType;
use wow_types::tx::TxIn;
use wow_types::Network;
use wow_wallet::decoys::RandomSource;
use wow_wallet::cold::{
    ExportedKeyImages, ExportedOutputs, RctConfig, RingEntry, SignedTxSet, TxConstructionData,
    TxDestinationEntry, TxSourceEntry, UnsignedTxSet,
};
use wow_wallet::files::Session;
use wow_wallet::refresh::Transfer;
use wow_wallet::scan::{scan_transaction, ScanKeys};
use wow_wallet::store::MemoryStore;
use wow_wallet::subaddress::SubaddressTable;
use wow_wallet::{transfer, AccountBase};

const AMOUNT: u64 = 10_000_000_000;
const FEE: u64 = 50_000_000;
const CHANGE: u64 = 3_000_000_000;
const PAID: u64 = AMOUNT - CHANGE - FEE;

fn account(seed: u8) -> AccountBase {
    let spend = SecretKey(wow_crypto::ops::sc_reduce32(&[seed; 32]));
    AccountBase::from_spend_key(spend, 0).expect("keys")
}

fn wallet(account: AccountBase, name: &str) -> Session {
    Session::create_in(
        Box::new(MemoryStore::new(name)),
        Network::Mainnet,
        String::new(),
        1,
        account,
        "English",
        0,
    )
    .expect("create")
}

/// One output paid to `to`, as a real transaction pays one: a transaction key
/// `R = r*G`, a derivation `8aR`, and `P = Hs(D||i)*G + B`. The cold half is
/// handed `R` and has to get back to the key from it.
fn paid_output(to: &AccountBase, rng: &mut Rng, index: u64, amount: u64) -> (Transfer, Scalar) {
    let tx_secret = SecretKey(rng.random_scalar());
    let tx_public = wow_crypto::secret_key_to_public_key(&tx_secret).expect("R");
    let derivation =
        wow_crypto::generate_key_derivation(&tx_public, &to.keys.view_secret_key).expect("D");
    let public_key = wow_crypto::derive_public_key(
        &derivation,
        index,
        &to.keys.account_address.spend_public_key,
    )
    .expect("P");
    let mask = Scalar::from_bytes_mod_order(rng.random_scalar());

    (
        Transfer {
            block_height: 500,
            txid: [0x42; 32],
            internal_output_index: index,
            global_output_index: 900_000 + index,
            public_key,
            derivation,
            tx_public_key: tx_public,
            additional_tx_keys: Vec::new(),
            // A watch-only wallet cannot compute one, and wants it.
            key_image: None,
            key_image_request: true,
            mask: mask.to_bytes(),
            amount,
            subaddress: SubaddressIndex::MAIN,
            spent: false,
            spent_height: 0,
            unlock_time: 0,
            is_coinbase: false,
            timestamp: 1_700_000_000,
            payment_id: None,
            frozen: false,
        },
        mask,
    )
}

/// A ring member that is not ours: a key nobody in this test can sign for.
fn decoy(rng: &mut Rng, global_index: u64) -> RingEntry {
    let secret = SecretKey(rng.random_scalar());
    RingEntry {
        global_index,
        public_key: wow_crypto::secret_key_to_public_key(&secret).expect("a decoy"),
        commitment: wow_crypto::rct::commit(
            rng.next_u64() % 1_000_000,
            &Scalar::from_bytes_mod_order(rng.random_scalar()),
        ),
    }
}

/// Everything a node checks about a RingCT transaction.
fn verify_as_a_node(tx: &wow_types::tx::Transaction, rings: &[Vec<clsag::RingMember>]) {
    let rct = &tx.rct_signatures;
    assert_eq!(rct.ty, RctType::BulletproofPlus);

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
    assert!(
        transfer::commitments_balance(rct),
        "sum(pseudoOuts) == sum(outPk) + fee*H"
    );

    let message = wow_types::hashes::tx_prefix_hash(&tx.prefix);
    let full =
        wow_types::hashes::pre_mlsag_hash(&message, rct, tx.prefix.vin.len(), tx.prefix.vout.len());

    for (slot, sig) in rct.clsags.iter().enumerate() {
        let k_image = match &tx.prefix.vin[slot] {
            TxIn::ToKey { k_image, .. } => *k_image,
            other => panic!("input {slot} is {other:?}"),
        };
        let c = clsag::Clsag {
            s: sig.s.clone(),
            c1: sig.c1,
            d: sig.d,
            i: k_image,
        };
        clsag::verify(&full, &c, &k_image, &rings[slot], &rct.pseudo_outs[slot])
            .unwrap_or_else(|e| panic!("input {slot}: {e}"));
    }
}

/// The construction data a watch-only wallet would write: one input, the
/// payee, and change back to the account's main address.
fn construction(
    cold: &AccountBase,
    payee: &AccountBase,
    t: &Transfer,
    mask: Scalar,
    ring: Vec<RingEntry>,
    real_output: u64,
) -> TxConstructionData {
    let change = TxDestinationEntry {
        original: String::new(),
        amount: CHANGE,
        address: cold.keys.account_address,
        is_subaddress: false,
        is_integrated: false,
    };
    let to_payee = TxDestinationEntry {
        original: String::new(),
        amount: PAID,
        address: payee.keys.account_address,
        is_subaddress: false,
        is_integrated: false,
    };
    TxConstructionData {
        sources: vec![TxSourceEntry {
            outputs: ring,
            real_output,
            real_out_tx_key: t.tx_public_key,
            real_out_additional_tx_keys: Vec::new(),
            real_output_in_tx_index: t.internal_output_index,
            amount: t.amount,
            rct: true,
            mask: mask.to_bytes(),
            multisig_klrki: [0u8; 128],
        }],
        change_dts: change.clone(),
        splitted_dsts: vec![to_payee.clone(), change],
        selected_transfers: vec![0],
        extra: Vec::new(),
        unlock_time: 0,
        use_rct: true,
        use_view_tags: true,
        rct_config: RctConfig::default(),
        dests: vec![to_payee],
        subaddr_account: 0,
        subaddr_indices: vec![0],
    }
}

/// The whole round trip, file by file.
#[test]
fn the_whole_cold_signing_path() {
    let mut rng = Rng::deterministic_test_seed();

    let full = account(11);
    let mut view_only = full.clone();
    view_only.forget_spend_key();
    let mut cold = wallet(full.clone(), "cold");
    let mut watch = wallet(view_only, "watch");
    let payee = account(12);

    // The watch-only half has found an output and cannot compute its key
    // image, so its balance is what it has received and no more.
    let (t, mask) = paid_output(&full, &mut rng, 0, AMOUNT);
    watch.state.transfers = vec![t.clone()];
    watch.state.reindex();
    assert!(watch.state.transfers[0].key_image.is_none());

    // 1. Outputs across, as a file.
    let outputs_file = watch
        .export_outputs_to_file(false, 0, u32::MAX)
        .expect("export outputs");
    assert!(outputs_file.starts_with(wow_wallet::cold::OUTPUT_EXPORT_MAGIC));
    assert_eq!(cold.import_outputs_from_file(&outputs_file).expect("import"), 1);

    let key_image = cold.state.transfers[0].key_image.expect("computed");
    assert_eq!(cold.state.transfers[0].public_key, t.public_key);

    // 2. Key images back, as a file. The signature over each one is checked
    //    against the output's public key on the way in.
    let images_file = cold.export_key_images_to_file(false).expect("export images");
    assert!(images_file.starts_with(wow_wallet::cold::KEY_IMAGE_EXPORT_MAGIC));
    let imported = watch
        .import_key_images_from_file(&images_file, false)
        .expect("import images");
    assert_eq!(imported.unspent, AMOUNT);
    assert_eq!(imported.spent, 0);
    assert_eq!(watch.state.transfers[0].key_image, Some(key_image));

    // 3. An unsigned set across. Its ring is built here rather than by
    //    `prepare_unsigned`, which needs a daemon; everything else is what
    //    that would have written.
    let mut ring: Vec<RingEntry> = (0..21)
        .map(|n| decoy(&mut rng, 800_001 + n * 10_000))
        .collect();
    let real = RingEntry {
        global_index: t.global_output_index,
        public_key: t.public_key,
        commitment: wow_crypto::rct::commit(t.amount, &mask),
    };
    // The wire form is relative offsets from an ascending list, so the real
    // output goes in at its sorted place rather than at a chosen index.
    let real_index = ring
        .iter()
        .position(|e| e.global_index > real.global_index)
        .unwrap_or(ring.len());
    ring.insert(real_index, real);
    assert_eq!(ring.len(), 22);
    assert!(ring.windows(2).all(|w| w[0].global_index < w[1].global_index));

    let cd = construction(&full, &payee, &t, mask, ring.clone(), real_index as u64);
    let unsigned = UnsignedTxSet {
        txes: vec![cd.clone()],
        new_transfers: watch
            .export_outputs(true, 0, u32::MAX)
            .expect("outputs again"),
    };
    let unsigned_file = unsigned
        .to_file(&watch.keys_file.account.keys.view_secret_key, &mut rng)
        .expect("write unsigned");
    assert!(unsigned_file.starts_with(wow_wallet::cold::UNSIGNED_TX_MAGIC));

    // What the user is shown before the spend key is used.
    let loaded = cold.load_unsigned(&unsigned_file).expect("load unsigned");
    let described = cold.describe(&loaded.txes).expect("describe");
    assert_eq!(described.summary.amount_in, AMOUNT);
    assert_eq!(described.summary.fee, FEE);
    assert_eq!(described.summary.change_amount, CHANGE);
    assert_eq!(described.txs[0].ring_size, 22);
    assert_eq!(described.txs[0].recipients.len(), 1);
    assert_eq!(described.txs[0].recipients[0].amount, PAID);

    // 4. Sign, and write the signed set.
    let signed = cold.sign_unsigned(&loaded).expect("sign");
    assert!(signed.blob.starts_with(wow_wallet::cold::SIGNED_TX_MAGIC));
    assert_eq!(signed.txids.len(), 1);
    assert_eq!(signed.set.ptx.len(), 1);
    // The transaction key stays here.
    assert_eq!(signed.set.ptx[0].tx_key, SecretKey::ZERO);
    assert_ne!(signed.tx_keys[0][0], SecretKey::ZERO);

    // 5. The watch-only half reads it back, and what it reads verifies as a
    //    node would verify it.
    let back = SignedTxSet::from_file(
        &signed.blob,
        &watch.keys_file.account.keys.view_secret_key,
    )
    .expect("parse signed");
    assert_eq!(back.ptx.len(), 1);
    assert_eq!(back.key_images, vec![key_image]);

    let tx = &back.ptx[0].tx;
    let members: Vec<clsag::RingMember> = ring
        .iter()
        .map(|e| clsag::RingMember {
            dest: e.public_key,
            mask: e.commitment,
        })
        .collect();
    verify_as_a_node(tx, std::slice::from_ref(&members));

    assert_eq!(tx.rct_signatures.txn_fee, FEE);
    match &tx.prefix.vin[0] {
        TxIn::ToKey {
            key_offsets,
            k_image,
            ..
        } => {
            assert_eq!(key_offsets.len(), 22);
            assert_eq!(*k_image, key_image, "it spends the output it was given");
        }
        other => panic!("{other:?}"),
    }

    // 6. And the payee finds the money.
    let their_table = SubaddressTable::new(
        &payee.keys.account_address,
        &payee.keys.view_secret_key,
        1,
        1,
    );
    let got = scan_transaction(
        tx,
        &ScanKeys {
            address: &payee.keys.account_address,
            view_secret_key: &payee.keys.view_secret_key,
            spend_secret_key: Some(&payee.keys.spend_secret_key),
            subaddresses: &their_table,
        },
    )
    .expect("scan");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].amount, PAID);

    // As does the sender, of its change -- and its key image reached the
    // watch-only half in the signed set, before the block did.
    let my_table = SubaddressTable::new(
        &full.keys.account_address,
        &full.keys.view_secret_key,
        1,
        1,
    );
    let mine = scan_transaction(
        tx,
        &ScanKeys {
            address: &full.keys.account_address,
            view_secret_key: &full.keys.view_secret_key,
            spend_secret_key: Some(&full.keys.spend_secret_key),
            subaddresses: &my_table,
        },
    )
    .expect("scan");
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].amount, CHANGE);
    assert_eq!(back.tx_key_images.len(), 1);
    assert_eq!(back.tx_key_images[0].0, mine[0].public_key);
    assert_eq!(Some(back.tx_key_images[0].1), mine[0].key_image);

    // 7. Submitting takes in the key images even without a daemon to relay to.
    assert_eq!(watch.set_key_images(&back.key_images, 0).expect("set"), 1);
    assert!(!watch.state.transfers[0].key_image_request);
}

/// A signed set is sealed under the view key, and the account the outputs are
/// for is checked before anything is parsed.
#[test]
fn the_files_are_for_one_wallet_only() {
    let mut rng = Rng::deterministic_test_seed();
    let full = account(13);
    let mut view_only = full.clone();
    view_only.forget_spend_key();
    let mut watch = wallet(view_only, "watch-only");
    let stranger = wallet(account(14), "stranger");

    let (t, _) = paid_output(&full, &mut rng, 0, AMOUNT);
    watch.state.transfers = vec![t];
    watch.state.reindex();

    let file = watch
        .export_outputs_to_file(false, 0, u32::MAX)
        .expect("export");
    // The magic is in the clear and nothing else is: neither key is in the
    // file as bytes.
    let keys = &watch.keys_file.account.keys;
    let spend_key_bytes: &[u8] = &keys.account_address.spend_public_key.0;
    assert!(
        !file.windows(32).any(|w| w == spend_key_bytes),
        "the account header is inside the ciphertext"
    );

    // Another wallet's view key does not open it.
    assert!(ExportedOutputs::from_file(
        &file,
        &stranger.keys_file.account.keys.account_address,
        &stranger.keys_file.account.keys.view_secret_key,
    )
    .is_err());

    // Nor does a key image file from another wallet import here: a fresh
    // wallet has no outputs to attach them to.
    let theirs = ExportedKeyImages {
        offset: 0,
        images: vec![wow_wallet::cold::SignedKeyImage {
            key_image: KeyImage([9u8; 32]),
            signature: wow_crypto::types::Signature::from_bytes(&[0u8; 64]),
        }],
    };
    let blob = theirs
        .to_file(&keys.account_address, &keys.view_secret_key, &mut rng)
        .expect("write");
    let mut fresh = wallet(account(15), "fresh");
    assert!(fresh.import_key_images_from_file(&blob, false).is_err());
}

/// A one-member ring signature over a key image is what proves it belongs to
/// the output, and a point that is not on the curve is not a public key.
#[test]
fn a_key_image_signature_is_tied_to_its_output() {
    let mut rng = Rng::deterministic_test_seed();
    let secret = SecretKey(rng.random_scalar());
    let public = PublicKey(encode_point(
        &(Scalar::from_bytes_mod_order(secret.0) * ED25519_BASEPOINT_POINT),
    ));
    let image = wow_crypto::generate_key_image(&public, &secret).expect("an image");

    let sig = wow_wallet::cold::sign_key_image(&mut rng, &image, &public, &secret).expect("sign");
    assert!(wow_wallet::cold::check_key_image_signature(
        &image, &public, &sig
    ));

    // The message is the key image itself, so changing it breaks the
    // signature: that is what ties one to the other.
    let other = KeyImage([1u8; 32]);
    assert!(!wow_wallet::cold::check_key_image_signature(
        &other, &public, &sig
    ));

    // And a commitment is not a public key.
    let not_a_key = EcPoint([0xff; 32]);
    assert!(!wow_wallet::cold::check_key_image_signature(
        &image,
        &PublicKey(not_a_key.0),
        &sig
    ));
}
