//! Two daemons syncing over the peer-to-peer network (`specs/08`,
//! `specs/09` §5): real binaries, a store on each side, and every block going
//! through the full validator on the side that receives it.
//!
//! The chain is regtest (Fakechain): mainnet's rules and hard-fork schedule
//! with no checkpoints, so nothing is trusted and each block's proof of work is
//! computed. The blocks are the committed fixture, re-linked on top of the real
//! genesis block, at heights where the difficulty is still 1 -- a real proof
//! against a target any hash meets.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;
use wow_core::{Blockchain, TrustingVerifier};
use wow_crypto::types::Hash256;
use wow_storage::db::BlockchainDb;
use wow_storage::env::OpenMode;
use wow_storage::lmdb::LmdbDb;
use wow_types::{Block, Network};

const NET: Network = Network::Fakechain;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("wownerod-p2p-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running daemon, killed when dropped.
struct Daemon {
    child: Child,
    rpc: u16,
    log: PathBuf,
}

impl Daemon {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Wait for the process to exit on its own.
    fn wait(&mut self, secs: u64) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the daemon did not exit\n--- log ---\n{}", self.log());
    }
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

/// Coinbase-only fixture blocks whose coinbase pays a plain `txout_to_key`.
///
/// Later fixture blocks carry the view-tagged output of HF 20, which the
/// version-7 rules these blocks are replayed under rightly refuse.
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
                .filter(|b| {
                    b.miner_tx
                        .prefix
                        .vout
                        .iter()
                        .all(|o| matches!(o.target, wow_types::TxOutTarget::ToKey { .. }))
                })
                .map(|_| blob)
        })
        .collect()
}

fn blob_of(blk: &Block) -> Vec<u8> {
    let mut w = wow_serialize::binary::Writer::with_capacity(2048);
    blk.write(&mut w);
    w.into_vec()
}

/// A fixture block made valid at `height`: the version the hard-fork table
/// requires, the new parent, and the coinbase height and unlock time.
///
/// The timestamps are spread a million seconds apart. Blocks this far apart
/// keep the difficulty at 1, so the receiving node's real proof-of-work check
/// passes for any hash; with the fixture's own five-minute spacing the
/// difficulty climbs within a few blocks and an unmined block fails -- which
/// the receiving node, rightly, bans the sender for.
fn rehome(blob: &[u8], height: u64, prev: Hash256) -> Block {
    let version = wow_consensus::hardfork::HardFork::new(NET).required_version(height);
    let mut blk = Block::from_blob(blob).unwrap();
    blk.header.major_version = version;
    blk.header.minor_version = version;
    blk.header.prev_id = prev;
    blk.header.timestamp = height * 1_000_000;
    blk.miner_tx.prefix.vin = vec![wow_types::TxIn::Gen { height }];
    blk.miner_tx.prefix.unlock_time =
        wow_consensus::tx_rules::coinbase_unlock_time(version, height, None);
    Block::from_blob(&blob_of(&blk)).unwrap()
}

/// A regtest store: the genesis block as the daemon writes it, then `n`
/// fixture blocks through the validator -- so the stored cumulative
/// difficulties are the ones the receiving node computes for itself.
fn build_chain(data_dir: &Path, n: u64) -> Hash256 {
    let dir = wow_storage::env::db_dir(data_dir, NET, true);
    let db = Arc::new(LmdbDb::open_with_map_size(&dir, OpenMode::default(), 2, 64 << 20).unwrap());

    let genesis = wow_consensus::genesis::genesis_blob(NET);
    let g = Block::from_blob(&genesis).unwrap();
    let record = wow_consensus::genesis::genesis_record(NET);
    db.add_block(
        &g,
        &genesis,
        record.weight,
        record.long_term_weight,
        record.cumulative_difficulty,
        record.already_generated_coins,
        &[],
    )
    .unwrap();

    let mut chain = Blockchain::new(db.clone(), Arc::new(TrustingVerifier), NET).unwrap();
    let blocks = fixture_blocks();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut prev = g.block_id().unwrap();
    for h in 1..=n {
        let blk = rehome(&blocks[(h - 1) as usize], h, prev);
        chain
            .add_block(&blk, &blob_of(&blk), &[], now)
            .unwrap_or_else(|e| panic!("block {h}: {e}"));
        prev = blk.block_id().unwrap();
    }
    prev
}

fn start(log: &Path, data_dir: &Path, rpc: u16, p2p: u16, extra: &[String]) -> Daemon {
    let file = std::fs::File::create(log).unwrap();
    let mut args: Vec<String> = [
        "--regtest",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--serve",
        "--no-zmq",
        "--rpc-bind-port",
        &rpc.to_string(),
        "--p2p-bind-ip",
        "127.0.0.1",
        "--p2p-bind-port",
        &p2p.to_string(),
        "--allow-local-ip",
        "--log-level",
        "1",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend_from_slice(extra);

    let mut d = Daemon {
        child: Command::new(env!("CARGO_BIN_EXE_wownerod"))
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::from(file))
            .spawn()
            .expect("start wownerod"),
        rpc,
        log: log.to_path_buf(),
    };

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", rpc)).is_ok() {
            return d;
        }
        if let Some(status) = d.child.try_wait().unwrap() {
            panic!("wownerod exited with {status}\n--- log ---\n{}", d.log());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("wownerod did not start\n--- log ---\n{}", d.log());
}

fn post(port: u16, path: &str, body: &str) -> Value {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    let (_, body) = raw.split_once("\r\n\r\n").expect("a response");
    serde_json::from_str(body).unwrap_or_else(|e| panic!("bad JSON: {e}\n{body}"))
}

fn rpc(port: u16, method: &str) -> Value {
    let body = format!(r#"{{"jsonrpc":"2.0","id":"0","method":"{method}","params":{{}}}}"#);
    post(port, "/json_rpc", &body)
}

fn wait_for(daemons: &[&Daemon], what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let logs: Vec<String> = daemons
        .iter()
        .enumerate()
        .map(|(i, d)| format!("--- daemon {i} ---\n{}", d.log()))
        .collect();
    panic!("timed out waiting for {what}\n{}", logs.join("\n"));
}

/// **The node end to end.** One daemon holds a chain, the other starts from
/// nothing and is told only where the first one listens. The chain arrives
/// block by block through the validator, both report the connection, the
/// receiver calls itself synchronised, and `stop_daemon` shuts it down with
/// the chain and its peer list on disk.
#[test]
fn two_daemons_sync_a_chain_over_the_peer_protocol() {
    let scratch = Scratch::new("sync");
    let a_dir = scratch.0.join("a");
    let b_dir = scratch.0.join("b");
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::create_dir_all(&b_dir).unwrap();

    let n = fixture_blocks().len().min(12) as u64;
    assert!(n >= 5, "the fixture needs coinbase-only blocks");
    let tip = build_chain(&a_dir, n);

    let (a_rpc, a_p2p, b_rpc, b_p2p) = (free_port(), free_port(), free_port(), free_port());
    let a = start(&scratch.0.join("a.log"), &a_dir, a_rpc, a_p2p, &[]);
    let mut b = start(
        &scratch.0.join("b.log"),
        &b_dir,
        b_rpc,
        b_p2p,
        &["--add-exclusive-node".into(), format!("127.0.0.1:{a_p2p}")],
    );

    wait_for(
        &[&a, &b],
        "the chain to reach the second daemon",
        120,
        || post(b.rpc, "/get_height", "{}")["height"] == n + 1,
    );
    assert_eq!(
        post(b.rpc, "/get_height", "{}")["hash"],
        wow_crypto::hex::encode(&tip)
    );

    wait_for(
        &[&a, &b],
        "the second daemon to call itself synchronised",
        60,
        || post(b.rpc, "/get_info", "{}")["synchronized"] == true,
    );
    let info = post(b.rpc, "/get_info", "{}");
    assert_eq!(info["offline"], false);
    assert_eq!(info["outgoing_connections_count"], 1);
    assert_eq!(info["target_height"], 0, "a synchronised node reports 0");
    assert_eq!(info["untrusted"], false, "synchronised answers are trusted");

    let conns = rpc(a.rpc, "get_connections");
    let list = conns["result"]["connections"]
        .as_array()
        .expect("connections");
    assert_eq!(list.len(), 1, "{conns}");
    assert_eq!(list[0]["incoming"], true);

    let sync = rpc(b.rpc, "sync_info");
    assert_eq!(sync["result"]["height"], n + 1, "{sync}");

    // `stop_daemon` ends the process cleanly, and what it synced is on disk.
    assert_eq!(post(b.rpc, "/stop_daemon", "{}")["status"], "OK");
    let status = b.wait(30);
    assert!(status.success(), "{status}\n{}", b.log());
    assert!(
        b_dir.join(wow_p2p::addressbook::STATE_FILENAME).exists(),
        "the peer lists were saved"
    );

    let out = Command::new(env!("CARGO_BIN_EXE_wownerod"))
        .args([
            "--regtest",
            "--data-dir",
            b_dir.to_str().unwrap(),
            "--db-readonly",
            "--status",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains(&format!("height     {}", n + 1)), "{text}");
}
