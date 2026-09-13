//! The whole send path, end to end.
//!
//! Each piece has its own tests. This one runs them in the order a wallet does
//! and checks the result is a transaction a node would accept:
//!
//! ```text
//! spend::plan      pick inputs, settle the fee
//!   -> decoys      pick a ring from the output distribution
//!   -> assemble    turn the daemon's answer into ring members
//!   -> transfer    build, sign, prove
//!   -> verify      every CLSAG, the range proof, the commitment balance
//!   -> scan        and the recipient finds the money
//! ```
//!
//! The chain here is synthetic: a table of output keys and commitments with a
//! plausible distribution, standing in for what `get_outs.bin` and
//! `get_output_distribution.bin` would return. That is enough, because what is
//! being tested is the glue — every cryptographic claim is checked in the
//! crate's own tests, against reference vectors where any exist.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;

use wow_crypto::bulletproofs_plus as bpp;
use wow_crypto::clsag;
use wow_crypto::ops::encode_point;
use wow_crypto::types::{EcPoint, PublicKey, SecretKey, SubaddressIndex};
use wow_types::rct::RctType;
use wow_types::tx::TxIn;
use wow_wallet::decoys::{self, GammaPicker, RandomSource};
use wow_wallet::refresh::Transfer;
use wow_wallet::scan::{scan_transaction, ScanKeys};
use wow_wallet::spend::{self, SpendOptions};
use wow_wallet::subaddress::SubaddressTable;
use wow_wallet::transfer::{self, Destination, SpendableOutput};
use wow_wallet::AccountBase;

/// Deterministic randomness, so a failure is reproducible.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 ^ (self.0 >> 31)
    }

    fn scalar(&mut self) -> Scalar {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&self.next().to_le_bytes());
        b[8..16].copy_from_slice(&self.next().to_le_bytes());
        b[16..24].copy_from_slice(&self.next().to_le_bytes());
        Scalar::from_bytes_mod_order(b)
    }
}

impl RandomSource for Lcg {
    fn next_u64(&mut self) -> u64 {
        self.next()
    }
}

/// A synthetic chain of RingCT outputs, standing in for the daemon's tables.
struct Chain {
    /// `(key, commitment)` by global index.
    outputs: Vec<([u8; 32], [u8; 32])>,
    /// Cumulative count per block.
    offsets: Vec<u64>,
}

impl Chain {
    fn new(blocks: usize, per_block: u64, rng: &mut Lcg) -> Chain {
        let total = blocks as u64 * per_block;
        let outputs = (0..total)
            .map(|_| {
                let x = rng.scalar();
                let m = rng.scalar();
                let amount = rng.next() % 1_000_000;
                (
                    encode_point(&(x * ED25519_BASEPOINT_POINT)),
                    wow_crypto::rct::commit(amount, &m).0,
                )
            })
            .collect();
        Chain {
            outputs,
            offsets: (1..=blocks as u64).map(|i| i * per_block).collect(),
        }
    }

    /// What `get_outs.bin` would answer.
    fn get_outs(&self, indices: &[u64]) -> Vec<([u8; 32], [u8; 32])> {
        indices.iter().map(|i| self.outputs[*i as usize]).collect()
    }
}

fn account(seed: u8) -> AccountBase {
    let spend = SecretKey(wow_crypto::ops::sc_reduce32(&[seed; 32]));
    AccountBase::from_spend_key(spend, 0).expect("valid")
}

fn table(a: &AccountBase) -> SubaddressTable {
    SubaddressTable::new(&a.keys.account_address, &a.keys.view_secret_key, 2, 3)
}

/// An output this wallet owns, placed into the synthetic chain so a ring can be
/// built around it.
fn owned(chain: &mut Chain, amount: u64, index: u64, rng: &mut Lcg) -> (Transfer, Scalar, Scalar) {
    let x = rng.scalar();
    let mask = rng.scalar();
    let public_key = PublicKey(encode_point(&(x * ED25519_BASEPOINT_POINT)));
    let commitment = wow_crypto::rct::commit(amount, &mask);

    chain.outputs[index as usize] = (public_key.0, commitment.0);

    let secret_key = SecretKey(x.to_bytes());
    let key_image = wow_crypto::generate_key_image(&public_key, &secret_key).expect("an image");

    (
        Transfer {
            block_height: 10,
            txid: [1u8; 32],
            derivation: wow_crypto::types::KeyDerivation::ZERO,
            internal_output_index: 0,
            global_output_index: index,
            public_key,
            key_image: Some(key_image),
            mask: mask.to_bytes(),
            amount,
            subaddress: SubaddressIndex::MAIN,
            spent: false,
            spent_height: 0,
            unlock_time: 0,
            is_coinbase: false,
            timestamp: 0,
        },
        x,
        mask,
    )
}

/// Verify a built transaction the way a node would.
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

/// Plan, pick a ring, build, verify, receive.
#[test]
fn the_whole_send_path() {
    let mut rng = Lcg(20_260_913);
    let mut chain = Chain::new(4_000, 4, &mut rng);

    let me = account(7);
    let them = account(9);

    // One spendable output of 10 WOW, sitting somewhere in the middle.
    let (t, x, mask) = owned(&mut chain, 10_000_000_000, 8_000, &mut rng);
    let transfers = vec![t];

    // 1. Plan.
    let options = SpendOptions {
        fee_per_byte: 3,
        chain_height: 1_000,
        now: 1_700_000_000,
        ..Default::default()
    };
    let plan = spend::plan(&transfers, &[4_000_000_000], &options).expect("a plan");
    assert_eq!(plan.inputs, vec![0]);
    assert!(plan.fee > 0);

    // 2. Pick a ring around it.
    let picker = GammaPicker::new(&chain.offsets).expect("a picker");
    let ring = decoys::select_ring(
        &picker,
        &mut rng,
        transfers[0].global_output_index,
        decoys::RING_SIZE,
    )
    .expect("a ring");

    // 3. Ask the "daemon" for the members, and check our own is among them.
    let keys = chain.get_outs(&ring.indices);
    let assembled = decoys::assemble_ring(
        &ring,
        &keys,
        &transfers[0].public_key,
        &wow_crypto::rct::commit(transfers[0].amount, &mask),
    )
    .expect("assembles");

    // 4. Build.
    let input = SpendableOutput {
        public_key: transfers[0].public_key,
        secret_key: SecretKey(x.to_bytes()),
        mask,
        amount: transfers[0].amount,
        key_image: transfers[0].key_image.expect("an image"),
        ring: assembled.members.clone(),
        global_indices: assembled.indices.clone(),
        real_index: assembled.real_index,
    };

    let destinations = vec![
        Destination {
            address: them.keys.account_address,
            is_subaddress: false,
            amount: plan.amounts[0],
        },
        Destination {
            address: me.keys.account_address,
            is_subaddress: false,
            amount: plan.change,
        },
    ];

    let built = transfer::construct(
        std::slice::from_ref(&input),
        &destinations,
        plan.fee,
        None,
        &mut || rng.scalar(),
    )
    .expect("construct");

    // 5. Verify, as a node would.
    verify_as_a_node(&built.tx, std::slice::from_ref(&assembled.members));

    // The ring really is ring-sized, and the input names it.
    match &built.tx.prefix.vin[0] {
        TxIn::ToKey { key_offsets, .. } => {
            assert_eq!(key_offsets.len(), decoys::RING_SIZE);
        }
        other => panic!("{other:?}"),
    }

    // 6. And the recipient finds the money.
    let their_table = table(&them);
    let got = scan_transaction(
        &built.tx,
        &ScanKeys {
            address: &them.keys.account_address,
            view_secret_key: &them.keys.view_secret_key,
            spend_secret_key: Some(&them.keys.spend_secret_key),
            subaddresses: &their_table,
        },
    )
    .expect("scan");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].amount, plan.amounts[0]);

    // As does the sender, of their change.
    let my_table = table(&me);
    let mine = scan_transaction(
        &built.tx,
        &ScanKeys {
            address: &me.keys.account_address,
            view_secret_key: &me.keys.view_secret_key,
            spend_secret_key: Some(&me.keys.spend_secret_key),
            subaddresses: &my_table,
        },
    )
    .expect("scan");
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].amount, plan.change);

    // The fee the plan settled on is what the built transaction declares, and
    // the built transaction is no heavier than the plan assumed — the estimate
    // may run over, never under.
    assert_eq!(built.tx.rct_signatures.txn_fee, plan.fee);
    let mut w = wow_serialize::binary::Writer::with_capacity(8192);
    built.tx.write(&mut w);
    let blob = w.into_vec();
    let actual = wow_types::weight::get_transaction_weight(&built.tx, blob.len());
    assert!(
        actual <= plan.estimated_weight,
        "estimated {} but built {}",
        plan.estimated_weight,
        actual
    );
}

/// A sweep: everything out, fee from the amount, no change.
#[test]
fn a_sweep_goes_through_the_same_path() {
    let mut rng = Lcg(4_242);
    let mut chain = Chain::new(3_000, 4, &mut rng);

    let me = account(11);
    let them = account(13);

    let (t, x, mask) = owned(&mut chain, 7_000_000_000, 5_000, &mut rng);
    let transfers = vec![t];

    let options = SpendOptions {
        fee_per_byte: 5,
        chain_height: 1_000,
        now: 1_700_000_000,
        ..Default::default()
    };
    let plan = spend::plan_sweep(&transfers, &options).expect("a sweep");
    assert_eq!(plan.change, 0);
    assert_eq!(plan.amounts[0] + plan.fee, 7_000_000_000);

    let picker = GammaPicker::new(&chain.offsets).expect("a picker");
    let ring = decoys::select_ring(&picker, &mut rng, 5_000, decoys::RING_SIZE).expect("a ring");
    let keys = chain.get_outs(&ring.indices);
    let assembled = decoys::assemble_ring(
        &ring,
        &keys,
        &transfers[0].public_key,
        &wow_crypto::rct::commit(transfers[0].amount, &mask),
    )
    .expect("assembles");

    let input = SpendableOutput {
        public_key: transfers[0].public_key,
        secret_key: SecretKey(x.to_bytes()),
        mask,
        amount: transfers[0].amount,
        key_image: transfers[0].key_image.expect("an image"),
        ring: assembled.members.clone(),
        global_indices: assembled.indices.clone(),
        real_index: assembled.real_index,
    };

    // A sweep still needs two outputs, so the second is a zero-amount dummy
    // back to the sender (`specs/12` §4.4).
    let destinations = vec![
        Destination {
            address: them.keys.account_address,
            is_subaddress: false,
            amount: plan.amounts[0],
        },
        Destination {
            address: me.keys.account_address,
            is_subaddress: false,
            amount: 0,
        },
    ];

    let built = transfer::construct(
        std::slice::from_ref(&input),
        &destinations,
        plan.fee,
        None,
        &mut || rng.scalar(),
    )
    .expect("construct");

    verify_as_a_node(&built.tx, std::slice::from_ref(&assembled.members));

    let their_table = table(&them);
    let got = scan_transaction(
        &built.tx,
        &ScanKeys {
            address: &them.keys.account_address,
            view_secret_key: &them.keys.view_secret_key,
            spend_secret_key: Some(&them.keys.spend_secret_key),
            subaddresses: &their_table,
        },
    )
    .expect("scan");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].amount, plan.amounts[0], "everything but the fee");
}

/// The ring a wallet signs over is the one the daemon described. If the daemon
/// substitutes a key in our own slot, assembling fails rather than producing a
/// signature nobody can verify.
#[test]
fn a_lying_daemon_is_caught_before_signing() {
    let mut rng = Lcg(77);
    let mut chain = Chain::new(2_000, 4, &mut rng);
    let (t, _x, mask) = owned(&mut chain, 1_000_000, 3_000, &mut rng);

    let picker = GammaPicker::new(&chain.offsets).expect("a picker");
    let ring = decoys::select_ring(&picker, &mut rng, 3_000, decoys::RING_SIZE).expect("a ring");

    let commitment: EcPoint = wow_crypto::rct::commit(t.amount, &mask);
    let good = chain.get_outs(&ring.indices);
    decoys::assemble_ring(&ring, &good, &t.public_key, &commitment).expect("assembles");

    // Our slot, replaced.
    let mut lying = good.clone();
    lying[ring.real_index].0 = [0xffu8; 32];
    assert!(decoys::assemble_ring(&ring, &lying, &t.public_key, &commitment).is_err());

    // Our commitment, replaced.
    let mut lying = good;
    lying[ring.real_index].1 = [0xeeu8; 32];
    assert!(decoys::assemble_ring(&ring, &lying, &t.public_key, &commitment).is_err());
}
