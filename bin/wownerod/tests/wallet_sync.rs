//! A wallet syncing against this daemon, over real HTTP.
//!
//! Every other test in this workspace exercises one side of a wire format. This
//! one runs the actual `wownerod` binary, points `wow-daemon-client` at it, and
//! drives `wow-wallet`'s refresh loop until it catches up — so the epee request
//! encoding, the response shapes, the short chain history and the block parsing
//! all have to agree, and a mismatch fails here rather than in the field.
//!
//! The fixture chain is coinbase-only blocks that belong to nobody, so the
//! wallet finds no money. That is the point: what is being tested is that the
//! **sync** works, and a sync that quietly finds nothing is exactly the failure
//! a unit test on either side would miss.

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use wow_daemon_client::DaemonClient;
use wow_storage::db::BlockchainDb;
use wow_storage::env::OpenMode;
use wow_storage::lmdb::LmdbDb;
use wow_types::block::Block;
use wow_types::Network;

const MAP_SIZE: usize = 64 * 1024 * 1024;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let mut p = std::env::temp_dir();
        p.push(format!("wow-wallet-sync-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch dir");
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Daemon {
    child: Child,
    port: u16,
    _scratch: Scratch,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Coinbase-only blocks from the committed HF 18 fixture.
fn fixture_blocks() -> Vec<Vec<u8>> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/blocks/hf18/index.tsv");
    let text = std::fs::read_to_string(&path).expect("fixture");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let blob = wow_crypto::hex::decode(l.split('\t').nth(3)?)?;
            Block::from_blob(&blob)
                .ok()
                .filter(|b| b.tx_hashes.is_empty())
                .map(|_| blob)
        })
        .collect()
}

/// Seed a database and start a daemon serving it. Returns the daemon and the
/// block hashes, genesis first.
fn start(tag: &str, extra: usize) -> (Daemon, Vec<[u8; 32]>) {
    let scratch = Scratch::new(tag);
    let dir = wow_storage::env::db_dir(&scratch.0, Network::Mainnet, false);
    let mut hashes = Vec::new();
    {
        let db = LmdbDb::open_with_map_size(&dir, OpenMode::default(), 2, MAP_SIZE).unwrap();

        let blob = wow_consensus::genesis::genesis_blob(Network::Mainnet);
        let blk = Block::from_blob(&blob).unwrap();
        let mut prev = blk.block_id().unwrap();
        hashes.push(prev);
        let record = wow_consensus::genesis::genesis_record(Network::Mainnet);
        db.add_block(
            &blk,
            &blob,
            record.weight,
            record.long_term_weight,
            record.cumulative_difficulty,
            record.already_generated_coins,
            &[],
        )
        .unwrap();

        let mut cum = 1u128;
        for (i, fixture) in fixture_blocks().into_iter().take(extra).enumerate() {
            let height = i as u64 + 1;
            let mut b = Block::from_blob(&fixture).unwrap();
            b.header.major_version = 7;
            b.header.minor_version = 7;
            b.header.prev_id = prev;
            b.miner_tx.prefix.vin = vec![wow_types::TxIn::Gen { height }];
            b.miner_tx.prefix.unlock_time = height + 60;
            let mut w = wow_serialize::binary::Writer::with_capacity(2048);
            b.write(&mut w);
            let wire = w.into_vec();
            let b = Block::from_blob(&wire).unwrap();

            cum += 1;
            db.add_block(&b, &wire, wire.len() as u64, wire.len() as u64, cum, 0, &[])
                .unwrap();
            prev = b.block_id().unwrap();
            hashes.push(prev);
        }
    }

    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_wownerod"))
        .args([
            "--data-dir",
            scratch.0.to_str().unwrap(),
            "--db-readonly",
            "--serve",
            "--no-zmq",
            "--rpc-bind-port",
            &port.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start wownerod");

    let d = Daemon {
        child,
        port,
        _scratch: scratch,
    };
    wait_ready(port);
    (d, hashes)
}

fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("wownerod did not start listening on {port}");
}

fn client(port: u16) -> DaemonClient {
    DaemonClient::new(format!("127.0.0.1:{port}"))
}

fn wallet(start_height: u64) -> wow_wallet::WalletState {
    let spend = wow_crypto::types::SecretKey(wow_crypto::ops::sc_reduce32(&[7u8; 32]));
    let account = wow_wallet::AccountBase::from_spend_key(spend, 0).expect("valid");
    let table = wow_wallet::SubaddressTable::new(
        &account.keys.account_address,
        &account.keys.view_secret_key,
        2,
        3,
    );
    wow_wallet::WalletState::new(account, table, start_height, Network::Mainnet)
}

/// The whole point: a wallet reaches the daemon's tip, with the daemon's
/// hashes.
#[test]
fn a_wallet_syncs_to_the_daemon_tip() {
    let (d, hashes) = start("sync", 12);
    let c = client(d.port);

    assert_eq!(c.get_height().expect("get_height"), hashes.len() as u64);

    let mut w = wallet(0);
    let summary = w.refresh(&c, 20).expect("refresh");

    assert!(summary.caught_up, "the wallet caught up");
    // The daemon's first block is genesis, which the wallet holds from the
    // start. It is compared, not taken for a split.
    assert_eq!(summary.reorg_to, None);
    assert_eq!(w.scan_height(), hashes.len() as u64);
    assert_eq!(
        w.hashes, hashes,
        "and agrees with the daemon block for block"
    );
    // Nobody's coins, so nothing found — which is the honest answer, not a
    // silent failure: the hashes above prove the blocks really arrived.
    assert_eq!(w.balance(), 0);
    assert_eq!(summary.received, 0);
}

/// A second refresh at the tip is a no-op, rather than re-fetching or looping.
#[test]
fn refreshing_again_does_nothing() {
    let (d, hashes) = start("idempotent", 6);
    let c = client(d.port);

    let mut w = wallet(0);
    w.refresh(&c, 20).expect("refresh");
    let height = w.scan_height();

    let again = w.refresh_once(&c).expect("refresh again");
    assert!(again.caught_up);
    assert_eq!(again.blocks_scanned, 0);
    assert_eq!(w.scan_height(), height);
    assert_eq!(w.hashes.len(), hashes.len());
}

/// A wallet restored above zero names its height once, then goes by its
/// history: synced, it asks again and gets nothing. Naming the height every
/// time would be answered from that height every time.
#[test]
fn a_wallet_restored_above_zero_syncs_and_stays_synced() {
    let (d, hashes) = start("restored", 12);
    let c = client(d.port);

    let mut w = wallet(5);
    let summary = w.refresh(&c, 20).expect("refresh");
    assert!(summary.caught_up);
    assert_eq!(summary.reorg_to, None);
    assert_eq!(w.hashes, hashes[5..]);

    let again = w.refresh_once(&c).expect("refresh again");
    assert!(again.caught_up);
    assert_eq!(again.blocks_scanned, 0);
    assert_eq!(w.hashes, hashes[5..]);
}

/// `get_blocks.bin` answers from the wallet's history, not from a height it was
/// told. A wallet that has already seen some blocks gets the rest, starting at
/// the newest one it has: sent again, as the reference sends it, for the
/// wallet to compare.
#[test]
fn the_daemon_answers_from_the_short_chain_history() {
    let (d, hashes) = start("history", 10);
    let c = client(d.port);

    // Pretend we have the first four blocks already.
    let mut w = wallet(0);
    w.hashes = hashes[..4].to_vec();

    let batch = wow_wallet::refresh::BlockSource::get_blocks(
        &c,
        &w.short_chain_history(),
        0,
        wow_wallet::refresh::MAX_BLOCKS_PER_CALL,
    )
        .expect("get_blocks");
    assert_eq!(batch.start_height, 3, "from the newest block both have");
    assert_eq!(batch.blocks.len(), hashes.len() - 3);
    assert_eq!(batch.current_height, hashes.len() as u64);
}

/// A start height above zero is taken as given, and the history is not read:
/// `find_blockchain_supplement` answers from `req_start_block` when there is
/// one. What stops a wallet skipping blocks it has never seen is the wallet
/// refusing a gap, not the daemon second-guessing the height.
#[test]
fn a_start_height_above_zero_is_taken_as_given() {
    let (d, hashes) = start("given", 8);
    let c = client(d.port);

    let nonsense = vec![[0xabu8; 32], [0xcdu8; 32]];
    let batch = wow_wallet::refresh::BlockSource::get_blocks(
        &c,
        &nonsense,
        5,
        wow_wallet::refresh::MAX_BLOCKS_PER_CALL,
    )
    .expect("get_blocks");
    assert_eq!(batch.start_height, 5, "the height, whatever the history");
    assert_eq!(batch.blocks.len(), hashes.len() - 5);
}

/// At zero, a history that does not end at this chain's genesis is refused, in
/// the reference's word for it.
#[test]
fn a_history_not_ending_at_genesis_is_refused() {
    let (d, _) = start("nogenesis", 8);
    let c = client(d.port);

    let nonsense = vec![[0xabu8; 32], [0xcdu8; 32]];
    let e = c
        .get_blocks(&nonsense, 0, false, false, 0)
        .expect_err("refused");
    assert!(e.to_string().contains("Failed"), "{e}");
}

/// `get_blocks.bin` carries one output-index list per transaction, coinbase
/// first, and it lines up with the blocks.
#[test]
fn output_indices_line_up_with_the_blocks() {
    let (d, hashes) = start("indices", 5);
    let c = client(d.port);

    // A history of genesis alone. The reference refuses an empty one.
    let res = c.get_blocks(&hashes[..1], 0, false, false, 0).expect("get_blocks");
    assert_eq!(res.blocks.len(), 6, "genesis plus five");

    for (h, b) in res.blocks.iter().enumerate() {
        assert!(
            b.txs.is_empty(),
            "the fixture blocks are coinbase-only (height {h})"
        );
        // One entry, for the coinbase.
        assert_eq!(
            b.output_indices.len(),
            1,
            "height {h} has one index list, for the coinbase"
        );
    }

    // Global indices are assigned in order, so a later block's coinbase sits
    // above an earlier one's.
    let first = res.blocks[1].output_indices[0].first().copied();
    let later = res.blocks[4].output_indices[0].first().copied();
    if let (Some(a), Some(b)) = (first, later) {
        assert!(b > a, "global output indices increase with height");
    }
}

/// `/get_o_indexes.bin` agrees with what `get_blocks.bin` already said.
#[test]
fn get_o_indexes_matches_get_blocks() {
    let (d, hashes) = start("oindexes", 4);
    let c = client(d.port);

    let res = c.get_blocks(&hashes[..1], 0, false, false, 0).expect("get_blocks");
    let block = Block::from_blob(&res.blocks[2].block).expect("parses");
    let txid = wow_types::hashes::transaction_hash(&block.miner_tx).expect("a hash");

    let direct = c.get_o_indexes(&txid).expect("get_o_indexes");
    assert_eq!(
        direct, res.blocks[2].output_indices[0],
        "the two endpoints agree"
    );
}

/// `/get_outs.bin` returns the key and commitment a ring member needs.
#[test]
fn get_outs_returns_ring_members() {
    let (d, hashes) = start("outs", 6);
    let c = client(d.port);

    let res = c.get_blocks(&hashes[..1], 0, false, false, 0).expect("get_blocks");
    // A RingCT output is filed under amount zero (`specs/10` §5.1).
    let indices: Vec<u64> = res
        .blocks
        .iter()
        .filter_map(|b| b.output_indices.first().and_then(|i| i.first().copied()))
        .take(3)
        .collect();
    assert!(!indices.is_empty(), "the fixture has outputs to ask about");

    let wanted: Vec<(u64, u64)> = indices.iter().map(|i| (0u64, *i)).collect();
    let outs = c.get_outs(&wanted, true).expect("get_outs");
    assert_eq!(outs.len(), wanted.len());

    for o in &outs {
        assert_ne!(o.key, [0u8; 32], "a real output key");
        assert_ne!(o.mask, [0u8; 32], "a commitment, synthesised if pre-RingCT");
    }
}

/// The pool endpoint answers, and a fresh node's pool is empty.
///
/// This used to assert the endpoint was unimplemented. It is implemented now,
/// and the distinction matters: an empty list from a node *with* a pool means
/// there are no unconfirmed transactions, where the same list from a node
/// without one means nothing at all.
#[test]
fn the_pool_endpoint_answers() {
    let (d, _) = start("pool", 2);
    let c = client(d.port);

    let hashes = c.get_pool_hashes().expect("the pool endpoint answers");
    assert!(hashes.is_empty(), "a fresh node has an empty pool");

    // And `get_info` agrees.
    let info = c.get_info().expect("get_info");
    assert_eq!(info.height, 3);
}

/// A binary endpoint this node really does not serve still says so by name.
#[test]
fn an_unknown_binary_endpoint_reports_itself() {
    let (d, _) = start("unknownbin", 2);
    let c = client(d.port);

    let e = c
        .binary(
            "/get_blocks_by_height.bin",
            &wow_serialize::epee::Section::new(),
        )
        .expect_err("not served");
    assert!(
        e.to_string().contains("not implemented"),
        "the error says what is missing: {e}"
    );
}

/// A height past the tip is refused rather than answered with nothing.
#[test]
fn a_start_height_past_the_tip_is_refused() {
    let (d, hashes) = start("toobig", 3);
    let c = client(d.port);

    let e = c
        .get_blocks(&[], hashes.len() as u64 + 100, false, false, 0)
        .expect_err("past the tip");
    assert!(e.to_string().contains("past the tip"), "{e}");
}

/// `/get_output_distribution.bin` refuses a request without `binary: true`,
/// exactly as `on_get_output_distribution_bin` does.
///
/// This node's own client sent `binary: false` for months. Every test passed,
/// because this daemon did not mind -- and the first real C++ daemon it met
/// answered `Binary only call`, which broke decoy selection and so broke
/// sending. Being lenient where the reference is strict does not make clients
/// work; it hides their bugs until they meet something else.
#[test]
fn the_output_distribution_needs_the_binary_flag() {
    use wow_serialize::epee::{self, Array, Section, Value};

    let (d, _) = start("distflag", 3);
    let c = client(d.port);

    let mut req = Section::new();
    req.insert(
        "amounts".into(),
        Value::Array(Array {
            elem_type: epee::ty::UINT64,
            items: vec![Value::U64(0)],
        }),
    );
    req.insert("from_height".into(), Value::U64(0));
    req.insert("cumulative".into(), Value::Bool(true));

    // Missing entirely.
    let e = c
        .binary("/get_output_distribution.bin", &req)
        .expect_err("refused without the flag");
    assert!(
        e.to_string().contains("Binary only call"),
        "the reference's own wording: {e}"
    );

    // Present and false is the same refusal.
    req.insert("binary".into(), Value::Bool(false));
    let e = c
        .binary("/get_output_distribution.bin", &req)
        .expect_err("refused with the flag false");
    assert!(e.to_string().contains("Binary only call"), "{e}");

    // And with it, an answer.
    req.insert("binary".into(), Value::Bool(true));
    let res = c
        .binary("/get_output_distribution.bin", &req)
        .expect("answered");
    assert!(res.contains_key("distributions"), "{res:?}");
}

/// The typed client asks the way the reference requires, so the round trip
/// works against this daemon and against a real one alike.
#[test]
fn the_client_gets_a_distribution_from_this_daemon() {
    let (d, _) = start("distclient", 3);
    let c = client(d.port);

    let dist = c
        .get_output_distribution(0, 0, 2)
        .expect("the client sends binary: true");
    // Cumulative, so it never decreases.
    let mut prev = 0u64;
    for v in &dist {
        assert!(*v >= prev, "the distribution went backwards: {dist:?}");
        prev = *v;
    }
}
