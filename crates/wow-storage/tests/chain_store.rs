//! `add_block` / `pop_block` against a real `data.mdb`.
//!
//! `specs/15-testing-and-conformance.md` §3.3 names the two properties that
//! matter most here:
//!
//! * "`add_block` then `pop_block` restores the exact previous state: compare a
//!   hash of every table's full contents before and after."
//! * "Output id ordering: for a block with a coinbase and 3 transactions,
//!   assert the assigned `output_id`s are coinbase-first and dense."
//!
//! The blocks are the committed HF 18+ fixture, so this runs on a fresh
//! checkout with no corpus generation.

use std::path::{Path, PathBuf};

use wow_storage::comparator::ZEROKEY;
use wow_storage::db::BlockchainDb;
use wow_storage::env::{OpenMode, SyncMode};
use wow_storage::lmdb::LmdbDb;
use wow_storage::raw::Db;
use wow_storage::tables::TABLES;
use wow_types::Block;

/// A scratch directory that deletes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("wow-chain-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }

    fn db_dir(&self) -> PathBuf {
        self.0.join("lmdb")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const MAP_SIZE: usize = 64 << 20;

fn open(dir: &Path) -> LmdbDb {
    LmdbDb::open_with_map_size(dir, OpenMode::default(), 4, MAP_SIZE).expect("open")
}

/// The committed HF 18+ fixture, **coinbase-only blocks**:
/// `(height, block_id, blob)`.
///
/// [`add_fixture_block`] passes no separate transactions, so a block whose blob
/// lists `tx_hashes` would be stored incomplete and `pop_block` would rightly
/// fail trying to remove transactions that were never added. Filtering here
/// keeps the test honest about what it exercises rather than papering over it:
/// a fixture block with transactions is skipped, not silently half-stored.
fn fixture_blocks() -> Vec<(u64, [u8; 32], Vec<u8>)> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/blocks/hf18/index.tsv");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let height: u64 = f.first()?.parse().ok()?;
            let id = wow_crypto::hex::decode(f.get(1)?)?;
            let blob = wow_crypto::hex::decode(f.get(3)?)?;
            let blk = Block::from_blob(&blob).ok()?;
            blk.tx_hashes
                .is_empty()
                .then(|| (height, id.try_into().ok().unwrap_or([0u8; 32]), blob))
        })
        .collect()
}

/// A hash of one table's entire contents, in cursor order.
///
/// This is the "hash of every table's full contents" §3.3 asks for. Cursor
/// order means the comparators are part of what is compared — a resort would
/// change the digest even if every record survived.
fn table_digest(db: &LmdbDb, table: Db) -> [u8; 32] {
    let rtxn = db.read_txn().unwrap();
    let mut c = rtxn.cursor(table).unwrap();
    let mut buf: Vec<u8> = Vec::new();
    let mut e = c.first().unwrap();
    while let Some((k, v)) = e {
        buf.extend_from_slice(&(k.len() as u64).to_le_bytes());
        buf.extend_from_slice(k);
        buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
        buf.extend_from_slice(v);
        e = c.next().unwrap();
    }
    wow_crypto::cn_fast_hash(&buf)
}

/// Every table's digest, so a single comparison covers the whole database.
fn all_digests(db: &LmdbDb) -> Vec<(&'static str, [u8; 32])> {
    let d = db.dbs();
    let handles: Vec<(&'static str, Db)> = vec![
        ("blocks", d.blocks),
        ("block_info", d.block_info),
        ("block_heights", d.block_heights),
        ("txs_pruned", d.txs_pruned),
        ("txs_prunable", d.txs_prunable),
        ("txs_prunable_hash", d.txs_prunable_hash),
        ("tx_indices", d.tx_indices),
        ("tx_outputs", d.tx_outputs),
        ("output_txs", d.output_txs),
        ("output_amounts", d.output_amounts),
        ("spent_keys", d.spent_keys),
        ("hf_versions", d.hf_versions),
        ("properties", d.properties),
    ];
    handles
        .into_iter()
        .map(|(n, h)| (n, table_digest(db, h)))
        .collect()
}

/// Add one fixture block.
///
/// Asserts the block really is coinbase-only, so the "no transactions" claim
/// made here cannot silently diverge from the blob.
fn add_fixture_block(db: &LmdbDb, blob: &[u8]) -> u64 {
    let blk = Block::from_blob(blob).expect("parse block");
    assert!(
        blk.tx_hashes.is_empty(),
        "fixture_blocks should have filtered this one out"
    );
    db.add_block(&blk, blob, blob.len() as u64, blob.len() as u64, 1, 0, &[])
        .expect("add_block")
}

#[test]
fn a_block_round_trips_through_the_store() {
    let s = Scratch::new("roundtrip");
    let db = open(&s.db_dir());
    let blocks = fixture_blocks();
    assert!(
        blocks.len() >= 5,
        "only {} coinbase-only fixture blocks",
        blocks.len()
    );

    assert_eq!(db.height(), 0, "a fresh database is empty");

    let (_, id, blob) = &blocks[0];
    let height = add_fixture_block(&db, blob);
    assert_eq!(height, 0, "the first block lands at height 0");
    assert_eq!(db.height(), 1);

    // Every read path agrees about it.
    assert_eq!(&db.get_block_hash(0).unwrap(), id);
    assert_eq!(db.get_block_height(id).unwrap(), 0);
    assert!(db.block_exists(id).unwrap());
    assert_eq!(db.get_block_blob(0).unwrap(), *blob);

    let blk = Block::from_blob(blob).unwrap();
    assert_eq!(db.get_block_timestamp(0).unwrap(), blk.header.timestamp);
    assert_eq!(
        db.get_hard_fork_version(0).unwrap(),
        blk.header.major_version
    );

    let info = db.get_block_info(0).unwrap();
    assert_eq!(info.height, 0);
    assert_eq!(&info.hash, id);
    assert_eq!(info.weight, blob.len() as u64);
}

/// **The §3.3 gate.** Adding a block and popping it must leave every table
/// byte-identical to before.
#[test]
fn add_then_pop_restores_the_exact_previous_state() {
    let s = Scratch::new("addpop");
    let db = open(&s.db_dir());
    let blocks = fixture_blocks();

    // Seed with one block so the "before" state is not trivially empty.
    add_fixture_block(&db, &blocks[0].2);
    let before = all_digests(&db);
    let height_before = db.height();
    let outputs_before = db.get_num_outputs(0).unwrap();

    // Add a second and confirm it actually changed something.
    add_fixture_block(&db, &blocks[1].2);
    let during = all_digests(&db);
    assert_ne!(before, during, "adding a block changed nothing");
    assert_eq!(db.height(), height_before + 1);

    // Pop it.
    let (popped, txs) = db.pop_block().expect("pop_block");
    assert!(txs.is_empty(), "the fixture blocks carry no separate txs");
    assert_eq!(
        popped.block_id().unwrap(),
        blocks[1].1,
        "popped the wrong block"
    );

    let after = all_digests(&db);
    assert_eq!(db.height(), height_before);
    assert_eq!(db.get_num_outputs(0).unwrap(), outputs_before);

    for ((name, b), (_, a)) in before.iter().zip(after.iter()) {
        assert_eq!(b, a, "table `{name}` was not restored by pop_block");
    }
    assert_eq!(before, after);
}

/// Repeated add/pop cycles must be stable, not merely correct once —
/// `specs/15` §3.3 asks for a small randomised add/pop loop with invariants
/// after each step.
#[test]
fn repeated_add_and_pop_cycles_are_stable() {
    let s = Scratch::new("cycles");
    let db = open(&s.db_dir());
    let blocks = fixture_blocks();
    let n = blocks.len().min(6);

    for (_, _, blob) in blocks.iter().take(n) {
        add_fixture_block(&db, blob);
    }
    assert_eq!(db.height(), n as u64);
    let full = all_digests(&db);

    // Wind all the way down, then back up, three times.
    for round in 0..3 {
        for _ in 0..n {
            db.pop_block().expect("pop");
        }
        assert_eq!(db.height(), 0, "round {round}: did not empty");
        assert_eq!(
            db.get_num_outputs(0).unwrap(),
            0,
            "round {round}: outputs survived an empty chain"
        );

        for (_, _, blob) in blocks.iter().take(n) {
            add_fixture_block(&db, blob);
        }
        assert_eq!(db.height(), n as u64, "round {round}");
        assert_eq!(all_digests(&db), full, "round {round}: state diverged");
    }
}

/// `specs/15` §3.3: the invariants that must hold after every step.
/// `block_hashes` is a cursor walk rather than a lookup per height, so it has
/// to agree with `get_block_hash` exactly — including at the edges, where an
/// off-by-one would return the right *number* of hashes for the wrong heights.
#[test]
fn a_bulk_read_of_block_hashes_matches_reading_them_one_at_a_time() {
    let s = Scratch::new("bulk-hashes");
    let db = open(&s.db_dir());
    let blocks = fixture_blocks();
    assert!(blocks.len() >= 5, "the fixture is too small for this test");

    for (_, _, blob) in blocks.iter().take(5) {
        add_fixture_block(&db, blob);
    }
    let height = db.height();
    let one_by_one: Vec<[u8; 32]> = (0..height).map(|h| db.get_block_hash(h).unwrap()).collect();

    assert_eq!(db.block_hashes(0, height).unwrap(), one_by_one);
    assert_eq!(db.block_hashes(2, 4).unwrap(), one_by_one[2..4]);
    assert_eq!(db.block_hashes(height - 1, height).unwrap(), &one_by_one[4..]);

    // An empty range is empty, not an error and not the whole chain.
    assert!(db.block_hashes(0, 0).unwrap().is_empty());
    assert!(db.block_hashes(3, 3).unwrap().is_empty());
    assert!(db.block_hashes(4, 2).unwrap().is_empty());

    // Past the end is a failure, not a short answer: a caller sizing a vector
    // from it would otherwise carry on with the wrong heights.
    assert!(db.block_hashes(0, height + 1).is_err());
    assert!(db.block_hashes(height, height + 1).is_err());
}

#[test]
fn the_entry_count_invariants_hold() {
    let s = Scratch::new("invariants");
    let db = open(&s.db_dir());
    let blocks = fixture_blocks();

    for (i, (_, _, blob)) in blocks.iter().take(5).enumerate() {
        add_fixture_block(&db, blob);

        let rtxn = db.read_txn().unwrap();
        let d = db.dbs();

        // height == mdb_stat(blocks).ms_entries
        assert_eq!(db.height(), i as u64 + 1);
        assert_eq!(rtxn.entries(d.blocks).unwrap(), db.height());

        // Every block writes exactly one block_info, block_heights and
        // hf_versions row.
        assert_eq!(rtxn.entries(d.block_info).unwrap(), db.height());
        assert_eq!(rtxn.entries(d.block_heights).unwrap(), db.height());
        assert_eq!(rtxn.entries(d.hf_versions).unwrap(), db.height());

        // One coinbase per block, so tx_indices and txs_pruned track height.
        assert_eq!(rtxn.entries(d.tx_indices).unwrap(), db.height());
        assert_eq!(rtxn.entries(d.txs_pruned).unwrap(), db.height());

        // num_outputs == the summed output count across blocks, and the dup
        // count under amount 0 must equal it -- every fixture block is a v2
        // coinbase, so all its outputs are filed under zero.
        let total_outputs = rtxn.entries(d.output_txs).unwrap();
        assert_eq!(
            db.get_num_outputs(0).unwrap(),
            total_outputs,
            "output_amounts[0] and output_txs disagree"
        );
    }
}

/// `specs/10` §5.2: a v2 coinbase output is filed under **amount 0** with an
/// identity-mask commitment, so it joins the RingCT set and can be a decoy.
#[test]
fn a_v2_coinbase_output_lands_under_amount_zero() {
    let s = Scratch::new("coinbase");
    let db = open(&s.db_dir());
    let blocks = fixture_blocks();

    let blk = Block::from_blob(&blocks[0].2).unwrap();
    assert_eq!(blk.miner_tx.prefix.version, 2, "the fixture is HF 18+");
    let reward: u64 = blk.miner_tx.prefix.vout.iter().map(|o| o.amount).sum();
    assert!(reward > 0, "a coinbase pays something");

    add_fixture_block(&db, &blocks[0].2);

    // The outputs are under 0, not under the reward.
    assert_eq!(
        db.get_num_outputs(0).unwrap(),
        blk.miner_tx.prefix.vout.len() as u64
    );
    assert_eq!(
        db.get_num_outputs(reward).unwrap(),
        0,
        "the real amount must not be a key"
    );

    // And the stored commitment is the identity-mask one for the real amount.
    let out = db.get_output_key(0, 0, true).unwrap();
    assert_eq!(
        out.commitment,
        Some(wow_crypto::rct::zero_commit(blk.miner_tx.prefix.vout[0].amount).0)
    );
    assert_eq!(out.height, 0);
    assert_eq!(out.unlock_time, blk.miner_tx.prefix.unlock_time);
}

/// `specs/15` §3.3: "the assigned `output_id`s are coinbase-first and dense".
#[test]
fn output_ids_are_dense_and_coinbase_first() {
    let s = Scratch::new("outputids");
    let db = open(&s.db_dir());
    let blocks = fixture_blocks();

    let mut expected_id = 0u64;
    for (_, _, blob) in blocks.iter().take(4) {
        let blk = Block::from_blob(blob).unwrap();
        add_fixture_block(&db, blob);

        // The coinbase is added first, so its outputs take the next ids in
        // order with no gaps.
        for local in 0..blk.miner_tx.prefix.vout.len() as u64 {
            let (tx_hash, idx) = db
                .get_output_tx_and_index_from_global(expected_id)
                .unwrap_or_else(|e| panic!("output {expected_id}: {e}"));
            assert_eq!(idx, local, "local index within the coinbase");
            assert_eq!(
                tx_hash.len(),
                32,
                "every output points back at its transaction"
            );
            expected_id += 1;
        }
    }

    // Dense: the next id does not exist.
    assert!(db.get_output_tx_and_index_from_global(expected_id).is_err());
}

/// The transaction read paths agree with the blob that went in.
#[test]
fn the_coinbase_is_retrievable_by_hash() {
    let s = Scratch::new("txread");
    let db = open(&s.db_dir());
    let blocks = fixture_blocks();
    add_fixture_block(&db, &blocks[0].2);

    let blk = Block::from_blob(&blocks[0].2).unwrap();
    let mut w = wow_serialize::binary::Writer::with_capacity(2048);
    blk.miner_tx.write(&mut w);
    let miner_blob = w.into_vec();
    let hash = wow_types::hashes::transaction_hash_from_blob(&blk.miner_tx, &miner_blob).unwrap();

    assert!(db.tx_exists(&hash).unwrap());
    let data = db.get_tx_data(&hash).unwrap();
    assert_eq!(data.tx_id, 0, "the coinbase of block 0 is transaction 0");
    assert_eq!(data.block_height, 0);
    assert_eq!(data.unlock_time, blk.miner_tx.prefix.unlock_time);

    assert_eq!(db.get_tx_block_height(&hash).unwrap(), 0);
    assert_eq!(db.get_tx_blob(&hash).unwrap(), miner_blob);
}

/// `specs/10` §6.3 and §7: the tip must agree across the three tables, and the
/// genesis hash is what identifies the network.
#[test]
fn the_tip_check_and_genesis_hash_work() {
    let s = Scratch::new("tip");
    let db = open(&s.db_dir());

    assert!(db.genesis_hash().unwrap().is_none(), "empty chain");
    db.check_tip().expect("an empty chain has a consistent tip");

    let blocks = fixture_blocks();
    add_fixture_block(&db, &blocks[0].2);
    add_fixture_block(&db, &blocks[1].2);

    db.check_tip().expect("tip should be consistent");
    assert_eq!(db.genesis_hash().unwrap(), Some(blocks[0].1));
}

/// A popped block comes back whole, so it can be returned to the pool
/// (`specs/06` §7).
#[test]
fn a_popped_block_is_returned_intact() {
    let s = Scratch::new("popped");
    let db = open(&s.db_dir());
    let blocks = fixture_blocks();
    add_fixture_block(&db, &blocks[0].2);

    let (popped, _) = db.pop_block().unwrap();
    assert_eq!(popped.block_id().unwrap(), blocks[0].1);

    // And the store is empty again, including the derived tables.
    assert_eq!(db.height(), 0);
    assert_eq!(db.get_num_outputs(0).unwrap(), 0);
    assert!(!db.block_exists(&blocks[0].1).unwrap());
    assert!(db.pop_block().is_err(), "nothing left to pop");
}

/// A read-only handle can read what a writer wrote, and refuses to write.
#[test]
fn a_read_only_open_can_read_but_not_write() {
    let s = Scratch::new("ro");
    let dir = s.db_dir();
    let blocks = fixture_blocks();
    {
        let db = open(&dir);
        add_fixture_block(&db, &blocks[0].2);
    }

    let ro = LmdbDb::open_with_map_size(
        &dir,
        OpenMode {
            sync: SyncMode::Safe,
            read_only: true,
            salvage: false,
        },
        4,
        MAP_SIZE,
    )
    .expect("open read-only");

    assert_eq!(ro.height(), 1);
    assert_eq!(ro.get_block_hash(0).unwrap(), blocks[0].1);
    assert!(ro.is_read_only());
    assert!(ro.dbs().txs_prunable_tip.is_none());
    assert!(
        ro.writer().is_err(),
        "a read-only handle must refuse writes"
    );
}

/// Every table in the schema is reachable from an open database.
#[test]
fn the_schema_has_all_nineteen_tables() {
    let s = Scratch::new("schema");
    let db = open(&s.db_dir());
    assert_eq!(TABLES.len(), 19);
    let d = db.dbs();
    assert!(d.txs_prunable_tip.is_some(), "writable: both are opened");
    assert!(d.hf_starting_heights.is_some());
    // `properties` holds the version row this open wrote.
    let rtxn = db.read_txn().unwrap();
    assert_eq!(rtxn.entries(d.properties).unwrap(), 1);
    assert_eq!(rtxn.entries(d.blocks).unwrap(), 0);
}

/// The `zerokval` tables really do share one key — `specs/10` §3.2's whole
/// point is that this saves eight bytes a record.
#[test]
fn the_zerokval_tables_use_a_single_key() {
    let s = Scratch::new("zerokval");
    let db = open(&s.db_dir());
    let blocks = fixture_blocks();
    for (_, _, blob) in blocks.iter().take(3) {
        add_fixture_block(&db, blob);
    }

    let rtxn = db.read_txn().unwrap();
    for (name, handle) in [
        ("block_info", db.dbs().block_info),
        ("block_heights", db.dbs().block_heights),
        ("tx_indices", db.dbs().tx_indices),
        ("output_txs", db.dbs().output_txs),
    ] {
        let mut c = rtxn.cursor(handle).unwrap();
        let (k, _) = c.first().unwrap().unwrap_or_else(|| panic!("{name} empty"));
        assert_eq!(k, &ZEROKEY, "{name} is not keyed by the dummy");

        // Every record lives under that one key.
        let mut seen = 0;
        let mut e = c.first().unwrap();
        while let Some((k, _)) = e {
            assert_eq!(k, &ZEROKEY, "{name} has a second key");
            seen += 1;
            e = c.next().unwrap();
        }
        assert!(seen >= 3, "{name} should hold at least one row per block");
    }
}
