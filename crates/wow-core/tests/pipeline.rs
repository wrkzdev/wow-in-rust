//! The `specs/06` §2 validation pipeline, end to end.
//!
//! `specs/06` §2 opens with "**Order matters because some checks feed later
//! ones**", so these tests are as much about *which step* rejects a block as
//! about whether it is rejected. A block that fails at step 3 rather than step 6
//! means something different for the peer that sent it.
//!
//! The blocks are the committed HF 18+ fixture, so this runs on a fresh
//! checkout.

use std::path::PathBuf;
use std::sync::Arc;

use wow_core::chain::{Blockchain, Step};
use wow_core::error::BlockError;
use wow_core::pow::{PowError, PowVerifier, RandomWowOnly, TrustingVerifier};
use wow_crypto::types::Hash256;
use wow_storage::env::OpenMode;
use wow_storage::lmdb::LmdbDb;
use wow_types::{Block, Network};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("wow-core-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const MAP_SIZE: usize = 64 << 20;

/// Coinbase-only fixture blocks, so a block can be added without supplying
/// separate transactions.
fn fixture_blocks() -> Vec<(u64, Hash256, Vec<u8>)> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/blocks/hf18/index.tsv");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let height: u64 = f.first()?.parse().ok()?;
            let id: Hash256 = wow_crypto::hex::decode(f.get(1)?)?.try_into().ok()?;
            let blob = wow_crypto::hex::decode(f.get(3)?)?;
            let blk = Block::from_blob(&blob).ok()?;
            blk.tx_hashes.is_empty().then_some((height, id, blob))
        })
        .collect()
}

/// Replay happens on **Fakechain**, which carries mainnet's hard-fork schedule
/// but no checkpoints (`wow_consensus::checkpoints::table`).
///
/// Mainnet checkpoints height 1, and a synthetic block can never match a real
/// hash — so replaying there would fail at step 7 for a reason that says
/// nothing about the pipeline. `the_checkpoint_step_rejects_a_wrong_hash`
/// exercises step 7 deliberately, on mainnet, where it means something.
const NET: Network = Network::Fakechain;

/// A chain over a fresh store, with a verifier that does not check PoW.
///
/// The fixture blocks are real mainnet blocks from height 331,169 upward, but
/// they are being replayed from height 0 here — their proofs are for their real
/// heights and their real difficulties, so checking them would be meaningless.
/// `TrustingVerifier` makes that explicit rather than quietly disabling a step.
fn chain(s: &Scratch) -> Blockchain<LmdbDb> {
    chain_with(s, Arc::new(TrustingVerifier))
}

fn chain_with(s: &Scratch, pow: Arc<dyn PowVerifier>) -> Blockchain<LmdbDb> {
    let db = LmdbDb::open_with_map_size(&s.0.join("lmdb"), OpenMode::default(), 4, MAP_SIZE)
        .expect("open");
    Blockchain::new(Arc::new(db), pow, NET).expect("chain")
}

/// The timestamp check compares against the wall clock, and these blocks are
/// from 2022, so "now" has to be after them.
fn now_after(blocks: &[(u64, Hash256, Vec<u8>)]) -> u64 {
    blocks
        .iter()
        .filter_map(|(_, _, b)| Block::from_blob(b).ok())
        .map(|b| b.header.timestamp)
        .max()
        .unwrap_or(0)
        + 1
}

/// A fixture block rewritten to be **valid at `height`** in a replayed chain.
///
/// The fixture is real mainnet blocks from 331,169 upward; replaying them from
/// height 0 means four things have to move with them, and each is a rule in
/// `specs/06`:
///
/// * the major version, to what the hard-fork table requires at `height` (§1);
/// * the minor version, which carries the legacy vote and must be at least the
///   required version (§1);
/// * `prev_id`, to the new parent (§2 step 2);
/// * the coinbase's claimed height and unlock time, the latter following
///   whichever of the three regimes applies (§5.1.1).
fn rehome(blob: &[u8], height: u64, prev: Hash256) -> Block {
    let hf = wow_consensus::hardfork::HardFork::new(NET);
    let version = hf.required_version(height);

    let mut blk = Block::from_blob(blob).expect("parse");
    blk.header.major_version = version;
    blk.header.minor_version = version;
    blk.header.prev_id = prev;
    blk.miner_tx.prefix.vin = vec![wow_types::TxIn::Gen { height }];
    blk.miner_tx.prefix.unlock_time =
        wow_consensus::tx_rules::coinbase_unlock_time(version, height, None);

    // Round-trip through the wire form. The coinbase's `prefix_size` and
    // `unprunable_size` were recorded when the *original* blob was parsed and
    // describe that blob, not this one -- so re-parsing is what makes them
    // consistent again. It is also what a block arriving from a peer looks
    // like, which is the case the store is built for.
    Block::from_blob(&blob_of(&blk)).expect("reparse")
}

fn blob_of(blk: &Block) -> Vec<u8> {
    let mut w = wow_serialize::binary::Writer::with_capacity(2048);
    blk.write(&mut w);
    w.into_vec()
}

#[test]
fn a_chain_starts_empty_and_at_the_weight_floor() {
    let s = Scratch::new("empty");
    let c = chain(&s);

    assert_eq!(c.height(), 0);
    assert_eq!(c.top_hash(), None);
    assert_eq!(c.state().weights.median, 300_000);
    assert_eq!(c.state().weights.limit, 600_000);
    assert_eq!(c.state().already_generated_coins, 0);
    assert_eq!(c.state().cumulative_difficulty, 0);
    assert_eq!(c.next_difficulty().unwrap(), 1, "genesis difficulty is 1");
}

/// The happy path: a block that satisfies every step is added, and the cached
/// state advances.
#[test]
fn a_valid_block_is_added_and_advances_the_state() {
    let s = Scratch::new("happy");
    let mut c = chain(&s);
    let blocks = fixture_blocks();
    let now = now_after(&blocks);

    let blk = rehome(&blocks[0].2, 0, [0u8; 32]);
    let blob = blob_of(&blk);
    let added = c.add_block(&blk, &blob, &[], now).expect("add");

    assert_eq!(added, wow_core::Added::MainChain { height: 0 });
    assert_eq!(c.height(), 1);
    assert_eq!(c.top_hash(), blk.block_id());

    // The coinbase paid something, so the supply moved.
    assert!(c.state().already_generated_coins > 0);
    // And the difficulty accumulated.
    assert_eq!(c.state().cumulative_difficulty, 1);
    // The long-term window now holds one entry.
    assert_eq!(c.state().long_term.len(), 1);
    assert_eq!(c.state().recent_weights.len(), 1);
}

/// Several blocks in a row, each extending the last.
#[test]
fn a_short_chain_builds() {
    let s = Scratch::new("chainbuild");
    let mut c = chain(&s);
    let blocks = fixture_blocks();
    let now = now_after(&blocks);
    let n = blocks.len().min(5);

    let mut prev = [0u8; 32];
    for (i, (_, _, blob)) in blocks.iter().take(n).enumerate() {
        let blk = rehome(blob, i as u64, prev);
        let wire = blob_of(&blk);
        c.add_block(&blk, &wire, &[], now)
            .unwrap_or_else(|e| panic!("block {i}: {e}"));
        prev = blk.block_id().unwrap();
        assert_eq!(c.height(), i as u64 + 1);
        assert_eq!(c.top_hash(), Some(prev));
    }
    assert_eq!(c.state().cumulative_difficulty, n as u128);
}

// ---------------------------------------------------------------------------
// each step rejects for its own reason
// ---------------------------------------------------------------------------

/// **Step 1.** A block already in the chain is refused before anything else.
#[test]
fn step_1_rejects_a_block_already_known() {
    let s = Scratch::new("step1");
    let mut c = chain(&s);
    let blocks = fixture_blocks();
    let now = now_after(&blocks);

    let blk = rehome(&blocks[0].2, 0, [0u8; 32]);
    let blob = blob_of(&blk);
    c.add_block(&blk, &blob, &[], now).unwrap();

    let again = c.add_block(&blk, &blob, &[], now).unwrap_err();
    assert_eq!(again.step, Step::HaveIt);
    assert!(matches!(again.error, BlockError::AlreadyExists { .. }));
}

/// **Step 2.** A block whose parent is not the tip is not an error as such —
/// it is the alt-chain path (`specs/06` §8) — but it must not join the main
/// chain.
#[test]
fn step_2_rejects_a_block_that_does_not_extend_the_tip() {
    let s = Scratch::new("step2");
    let mut c = chain(&s);
    let blocks = fixture_blocks();
    let now = now_after(&blocks);

    let first = rehome(&blocks[0].2, 0, [0u8; 32]);
    c.add_block(&first, &blob_of(&first), &[], now).unwrap();

    // Point the second block at the wrong parent.
    let orphan = rehome(&blocks[1].2, 1, [0x42u8; 32]);
    let e = c
        .add_block(&orphan, &blob_of(&orphan), &[], now)
        .unwrap_err();
    assert_eq!(e.step, Step::ParentIsTip);
    match e.error {
        BlockError::NotOnTip { prev, tip } => {
            assert_eq!(prev, [0x42u8; 32]);
            assert_eq!(Some(tip), first.block_id());
        }
        other => panic!("expected NotOnTip, got {other:?}"),
    }
}

/// **Step 3.** The hard-fork table decides the version, and the check is
/// equality on the major version (`specs/06` §1).
#[test]
fn step_3_rejects_the_wrong_hard_fork_version() {
    let s = Scratch::new("step3");
    let mut c = chain(&s);
    let blocks = fixture_blocks();
    let now = now_after(&blocks);

    let mut blk = rehome(&blocks[0].2, 0, [0u8; 32]);
    assert_eq!(
        blk.header.major_version, 7,
        "rehome sets what height 0 needs"
    );

    // Break it: height 0 requires version 7, so 8 must be refused.
    blk.header.major_version = 8;
    let e = c.add_block(&blk, &blob_of(&blk), &[], now).unwrap_err();
    assert_eq!(e.step, Step::HardFork);
    match e.error {
        BlockError::WrongVersion {
            height,
            found,
            required,
            ..
        } => {
            assert_eq!(height, 0);
            assert_eq!(required, 7, "the table's floor, not ORIGINAL_VERSION");
            assert_eq!(found, 8);
        }
        other => panic!("expected WrongVersion, got {other:?}"),
    }

    // With the right version it gets past step 3.
    blk.header.major_version = 7;
    let e = c.add_block(&blk, &blob_of(&blk), &[], now);
    assert!(
        e.as_ref().err().map(|r| r.step) != Some(Step::HardFork),
        "should have passed the hard-fork check: {e:?}"
    );
}

/// **Step 4.** A timestamp too far ahead of the wall clock is refused, and the
/// limit is the tip's version's (`specs/06` §2.1).
#[test]
fn step_4_rejects_a_timestamp_too_far_in_the_future() {
    let s = Scratch::new("step4");
    let mut c = chain(&s);
    let blocks = fixture_blocks();

    let blk = rehome(&blocks[0].2, 0, [0u8; 32]);
    // The tip version at height 0 is 7, so the limit is 7200 seconds.
    let now = blk.header.timestamp - 7_201;
    let e = c.add_block(&blk, &blob_of(&blk), &[], now).unwrap_err();
    assert_eq!(e.step, Step::Timestamp);

    // One second later and it is inside the window.
    let now = blk.header.timestamp - 7_200;
    let r = c.add_block(&blk, &blob_of(&blk), &[], now);
    assert!(
        r.as_ref().err().map(|x| x.step) != Some(Step::Timestamp),
        "should have passed the timestamp check: {r:?}"
    );
}

/// **Step 6.** A proof of work that does not meet the difficulty is refused.
#[test]
fn step_6_rejects_insufficient_proof_of_work() {
    /// Returns a hash that fails every difficulty above 1.
    struct WorstPossible;
    impl PowVerifier for WorstPossible {
        fn pow_hash(&self, _h: u64, _v: u8, _b: &[u8], _s: &Hash256) -> Result<Hash256, PowError> {
            Ok([0xffu8; 32])
        }
    }

    let s = Scratch::new("step6");
    let blocks = fixture_blocks();
    let now = now_after(&blocks);

    // Difficulty 1 accepts *any* hash -- `check_hash(h, 1)` is `h <= MAX`. So a
    // chain has to get past that before "insufficient work" can mean anything.
    // Blocks sharing a timestamp collapse the difficulty window's time span,
    // which the algorithm clamps to 1 second, and the difficulty climbs.
    let mut prev = [0u8; 32];
    {
        let mut c = chain(&s);
        for i in 0..4u64 {
            let mut blk = rehome(&blocks[i as usize % blocks.len()].2, i, prev);
            blk.header.timestamp = now;
            let blk = Block::from_blob(&blob_of(&blk)).unwrap();
            c.add_block(&blk, &blob_of(&blk), &[], now)
                .unwrap_or_else(|e| panic!("seed block {i}: {e}"));
            prev = blk.block_id().unwrap();
        }
        assert!(
            c.next_difficulty().unwrap() > 1,
            "the seed chain did not raise the difficulty, so this test would \
             prove nothing"
        );
    }

    // Reopen with a verifier whose hash fails everything above difficulty 1.
    let mut c = chain_with(&s, Arc::new(WorstPossible));
    let difficulty = c.next_difficulty().unwrap();
    assert!(difficulty > 1);

    let mut blk = rehome(&blocks[0].2, 4, prev);
    blk.header.timestamp = now;
    let blk = Block::from_blob(&blob_of(&blk)).unwrap();

    let e = c.add_block(&blk, &blob_of(&blk), &[], now).unwrap_err();
    assert_eq!(e.step, Step::ProofOfWork);
    match e.error {
        BlockError::InsufficientPow { difficulty: d } => assert_eq!(d, difficulty),
        other => panic!("expected InsufficientPow, got {other:?}"),
    }
}

/// **Step 6, the other failure.** A pre-HF-13 block needs CryptoNight, which is
/// not implemented — and that must be a loud refusal, not a silent pass.
#[test]
fn step_6_refuses_pre_hf13_rather_than_skipping_the_proof() {
    let s = Scratch::new("step6cn");
    let verifier = RandomWowOnly(|_: &[u8], _: &Hash256| Ok([0u8; 32]));
    let mut c = chain_with(&s, Arc::new(verifier));

    let blocks = fixture_blocks();
    let now = now_after(&blocks);
    let blk = rehome(&blocks[0].2, 0, [0u8; 32]);
    assert_eq!(blk.header.major_version, 7, "pre-RandomWOW");

    let e = c.add_block(&blk, &blob_of(&blk), &[], now).unwrap_err();
    assert_eq!(e.step, Step::ProofOfWork);
    match e.error {
        BlockError::Pow(PowError::CryptoNightNotImplemented { variant, .. }) => {
            assert_eq!(variant, "v1", "version 7 is CryptoNight v1");
        }
        other => panic!("expected CryptoNightNotImplemented, got {other:?}"),
    }
}

/// **Step 8.** The coinbase must claim the height it is at.
#[test]
fn step_8_rejects_a_coinbase_with_the_wrong_height() {
    let s = Scratch::new("step8");
    let mut c = chain(&s);
    let blocks = fixture_blocks();
    let now = now_after(&blocks);

    let mut blk = rehome(&blocks[0].2, 0, [0u8; 32]);
    // Claim a height the block is not at.
    blk.miner_tx.prefix.vin = vec![wow_types::TxIn::Gen { height: 99 }];

    let e = c.add_block(&blk, &blob_of(&blk), &[], now).unwrap_err();
    assert_eq!(e.step, Step::CoinbasePrevalidation);
    assert!(matches!(e.error, BlockError::Coinbase(_)));
}

/// **Step 8, the unlock time.** Below HF 16 the window is a flat 60 blocks, and
/// the fixture's HF 18 value of `height + 288` is wrong there — which is the
/// regime switch in `specs/06` §5.1.1.
#[test]
fn step_8_applies_the_unlock_regime_for_the_height() {
    let s = Scratch::new("step8unlock");
    let mut c = chain(&s);
    let blocks = fixture_blocks();
    let now = now_after(&blocks);

    let mut blk = rehome(&blocks[0].2, 0, [0u8; 32]);
    // Version 7 is the pre-HF-16 regime: a flat 60-block window.
    assert_eq!(blk.miner_tx.prefix.unlock_time, 60);

    // The HF 18 value of height + 288 is wrong here.
    blk.miner_tx.prefix.unlock_time = 288;
    let e = c.add_block(&blk, &blob_of(&blk), &[], now).unwrap_err();
    assert_eq!(e.step, Step::CoinbasePrevalidation);
    match e.error {
        BlockError::Coinbase(wow_consensus::TxError::CoinbaseUnlockTime { expected, .. }) => {
            assert_eq!(expected, 60);
        }
        other => panic!("expected CoinbaseUnlockTime, got {other:?}"),
    }
}

/// **Step 9.** The supplied transactions must match what the block claims.
#[test]
fn step_9_rejects_a_transaction_count_mismatch() {
    let s = Scratch::new("step9");
    let mut c = chain(&s);
    let blocks = fixture_blocks();
    let now = now_after(&blocks);

    let mut blk = rehome(&blocks[0].2, 0, [0u8; 32]);
    // Claim a transaction that is not supplied.
    blk.tx_hashes = vec![[7u8; 32]];

    let e = c.add_block(&blk, &blob_of(&blk), &[], now).unwrap_err();
    assert_eq!(e.step, Step::Transactions);
    assert!(matches!(e.error, BlockError::Malformed(_)));
}

/// **Step 10.** A coinbase claiming more than the reward is refused.
#[test]
fn step_10_rejects_an_overpaying_coinbase() {
    let s = Scratch::new("step10");
    let mut c = chain(&s);
    let blocks = fixture_blocks();
    let now = now_after(&blocks);

    let mut blk = rehome(&blocks[0].2, 0, [0u8; 32]);
    // Pay the miner far more than the subsidy allows.
    for o in blk.miner_tx.prefix.vout.iter_mut() {
        o.amount = u64::MAX / 4;
    }

    let e = c.add_block(&blk, &blob_of(&blk), &[], now).unwrap_err();
    assert_eq!(e.step, Step::CoinbaseAmount);
    assert!(matches!(e.error, BlockError::MinerReward(_)));
}

/// The steps run in order: a block wrong in two ways reports the **earlier**
/// one. This is what makes the step number meaningful.
#[test]
fn the_earliest_failing_step_is_the_one_reported() {
    let s = Scratch::new("order");
    let mut c = chain(&s);
    let blocks = fixture_blocks();
    let now = now_after(&blocks);

    // Wrong version (step 3) *and* a wrong coinbase height (step 8).
    let mut blk = rehome(&blocks[0].2, 0, [0u8; 32]);
    blk.header.major_version = 8;
    blk.miner_tx.prefix.vin = vec![wow_types::TxIn::Gen { height: 99 }];

    let e = c.add_block(&blk, &blob_of(&blk), &[], now).unwrap_err();
    assert_eq!(e.step, Step::HardFork, "step 3 comes before step 8");

    // Fix the version and the later failure surfaces.
    blk.header.major_version = 7;
    let e = c.add_block(&blk, &blob_of(&blk), &[], now).unwrap_err();
    assert_eq!(e.step, Step::CoinbasePrevalidation);
}

/// Reopening a store rebuilds the cached state rather than starting fresh —
/// `specs/06` §3.4's weight medians and `already_generated_coins` are not
/// derivable from the tip alone.
#[test]
fn the_cached_state_survives_a_reopen() {
    let s = Scratch::new("reload");
    let blocks = fixture_blocks();
    let now = now_after(&blocks);
    let dir = s.0.join("lmdb");

    let (coins, difficulty, height) = {
        let db = LmdbDb::open_with_map_size(&dir, OpenMode::default(), 4, MAP_SIZE).unwrap();
        let mut c = Blockchain::new(Arc::new(db), Arc::new(TrustingVerifier), NET).unwrap();

        let mut prev = [0u8; 32];
        for (i, (_, _, blob)) in blocks.iter().take(3).enumerate() {
            let blk = rehome(blob, i as u64, prev);
            c.add_block(&blk, &blob_of(&blk), &[], now).unwrap();
            prev = blk.block_id().unwrap();
        }
        (
            c.state().already_generated_coins,
            c.state().cumulative_difficulty,
            c.height(),
        )
    };

    let db = LmdbDb::open_with_map_size(&dir, OpenMode::default(), 4, MAP_SIZE).unwrap();
    let c = Blockchain::new(Arc::new(db), Arc::new(TrustingVerifier), NET).unwrap();

    assert_eq!(c.height(), height);
    assert_eq!(c.state().already_generated_coins, coins);
    assert_eq!(c.state().cumulative_difficulty, difficulty);
    assert_eq!(c.state().long_term.len(), height as usize);
    assert_eq!(c.state().recent_weights.len(), height as usize);
}

/// **Step 7.** Mainnet checkpoints height 1, so a block that is not the
/// checkpointed one is refused there — `specs/06` §2 step 7.
///
/// This is why the rest of these tests replay on Fakechain: a synthetic block
/// can never match a real checkpoint hash.
#[test]
fn the_checkpoint_step_rejects_a_wrong_hash() {
    let s = Scratch::new("step7");
    let db = LmdbDb::open_with_map_size(&s.0.join("lmdb"), OpenMode::default(), 4, MAP_SIZE)
        .expect("open");
    let mut c =
        Blockchain::new(Arc::new(db), Arc::new(TrustingVerifier), Network::Mainnet).expect("chain");

    let blocks = fixture_blocks();
    let now = now_after(&blocks);
    let hf = wow_consensus::hardfork::HardFork::new(Network::Mainnet);

    // Height 0 is not checkpointed, so it goes in.
    let mut genesis = Block::from_blob(&blocks[0].2).expect("parse");
    genesis.header.major_version = hf.required_version(0);
    genesis.header.minor_version = genesis.header.major_version;
    genesis.header.prev_id = [0u8; 32];
    genesis.miner_tx.prefix.vin = vec![wow_types::TxIn::Gen { height: 0 }];
    genesis.miner_tx.prefix.unlock_time =
        wow_consensus::tx_rules::coinbase_unlock_time(genesis.header.major_version, 0, None);
    let genesis = Block::from_blob(&blob_of(&genesis)).unwrap();
    c.add_block(&genesis, &blob_of(&genesis), &[], now)
        .expect("height 0 is not checkpointed");

    // Height 1 is. The mainnet table's first entry.
    assert!(c.checkpoints().is_checkpointed(1));

    let mut second = Block::from_blob(&blocks[1].2).expect("parse");
    second.header.major_version = hf.required_version(1);
    second.header.minor_version = second.header.major_version;
    second.header.prev_id = genesis.block_id().unwrap();
    second.miner_tx.prefix.vin = vec![wow_types::TxIn::Gen { height: 1 }];
    second.miner_tx.prefix.unlock_time =
        wow_consensus::tx_rules::coinbase_unlock_time(second.header.major_version, 1, None);
    let second = Block::from_blob(&blob_of(&second)).unwrap();

    let e = c
        .add_block(&second, &blob_of(&second), &[], now)
        .unwrap_err();
    assert_eq!(e.step, Step::Checkpoint);
    match e.error {
        BlockError::CheckpointMismatch {
            height, expected, ..
        } => {
            assert_eq!(height, 1);
            assert_eq!(
                expected,
                c.checkpoints().at(1).unwrap().hash,
                "the expected hash is the table's"
            );
        }
        other => panic!("expected CheckpointMismatch, got {other:?}"),
    }
}

/// A verifier that records every height it was asked about, and refuses to
/// compute below a trusted boundary.
struct CountingVerifier {
    asked: std::sync::Mutex<Vec<u64>>,
    trusted_below: u64,
}

impl PowVerifier for CountingVerifier {
    fn may_skip(&self, height: u64) -> bool {
        height < self.trusted_below
    }

    fn pow_hash(
        &self,
        height: u64,
        _major_version: u8,
        _hashing_blob: &[u8],
        _seed_hash: &Hash256,
    ) -> Result<Hash256, PowError> {
        self.asked.lock().expect("lock").push(height);
        Ok([0u8; 32])
    }
}

/// `specs/06` §2 step 6 allows the proof to be skipped where a precomputed hash
/// covers the height, and `may_skip` is how a verifier says so.
///
/// This is the mechanism the reference uses for most of the chain: with
/// `PER_BLOCK_CHECKPOINT` it computes no proof at all below its embedded block
/// hashes (`docs/spec-deltas.md` §23). The test is that the skip is real --
/// `pow_hash` is not called -- rather than a hash computed and then ignored.
#[test]
fn the_proof_is_not_computed_inside_the_trusted_zone() {
    let s = Scratch::new("powskip");
    let pow = Arc::new(CountingVerifier {
        asked: std::sync::Mutex::new(Vec::new()),
        trusted_below: 3,
    });
    let mut c = chain_with(&s, pow.clone());

    let blocks = fixture_blocks();
    let now = now_after(&blocks);
    let n = blocks.len().min(5);
    assert!(n >= 5, "the fixture needs five coinbase-only blocks");

    let mut prev = [0u8; 32];
    for (i, (_, _, blob)) in blocks.iter().take(n).enumerate() {
        let blk = rehome(blob, i as u64, prev);
        let b = blob_of(&blk);
        c.add_block(&blk, &b, &[], now).expect("add");
        prev = blk.block_id().expect("id");
    }

    let asked = pow.asked.lock().expect("lock").clone();
    assert_eq!(
        asked,
        vec![3, 4],
        "heights 0-2 are inside the trusted zone and must not be hashed at all"
    );
}

/// The default is to verify everything. A node that trusted by default would be
/// one flag away from believing whatever it was sent.
#[test]
fn nothing_is_trusted_unless_it_is_asked_for() {
    let s = Scratch::new("notrust");
    let c = chain(&s);
    assert_eq!(c.trusted_below(), 0);
}

/// Setting the boundary is what turns the rules off below it, and it reads back
/// as set -- the daemon derives it from the checkpoint list and reports it, so
/// the value has to be observable.
#[test]
fn the_trusted_boundary_is_observable() {
    let s = Scratch::new("trustset");
    let mut c = chain(&s);
    c.trust_below(838_801);
    assert_eq!(c.trusted_below(), 838_801);
}

/// The cached difficulty window and a freshly rebuilt one must agree.
///
/// `next_difficulty` is served from `ChainState::difficulty_window`, carried
/// forward a block at a time; reopening the chain rebuilds that window from the
/// database instead. If the incremental path and the rebuild path ever
/// disagreed, a node would compute one difficulty while running and a different
/// one after a restart -- and would then reject its own chain. Reopening and
/// comparing is the cheapest way to keep the two honest.
#[test]
fn the_difficulty_window_survives_a_restart() {
    let s = Scratch::new("diffcache");
    let blocks = fixture_blocks();
    let now = now_after(&blocks);
    let n = blocks.len().min(5);
    assert!(n >= 2, "needs at least two blocks");

    let (live, live_state) = {
        let mut c = chain(&s);
        let mut prev = [0u8; 32];
        for (i, (_, _, blob)) in blocks.iter().take(n).enumerate() {
            let blk = rehome(blob, i as u64, prev);
            let b = blob_of(&blk);
            c.add_block(&blk, &b, &[], now).expect("add");
            prev = blk.block_id().expect("id");
        }
        (
            c.next_difficulty().expect("difficulty"),
            c.state().difficulty_window.clone(),
        )
    };

    // Reopen: `reload_state` rebuilds the window from the database.
    let reopened = chain(&s);
    assert_eq!(
        reopened.state().difficulty_window,
        live_state,
        "the rebuilt window must match the one carried forward"
    );
    assert_eq!(
        reopened.next_difficulty().expect("difficulty"),
        live,
        "difficulty must not change across a restart"
    );
    assert_eq!(reopened.state().difficulty_window.len(), n);
}
