//! Mining against the real binary (`specs/09` §6, `specs/11` §4.1, §4.3).
//!
//! Regtest with `--fixed-difficulty 1`, so any hash meets the target: a block
//! costs its template and its validation, and the proof of work is still
//! computed on both sides -- by the miner, and by every node that receives
//! the block -- but never searched for.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use wow_crypto::types::AccountPublicAddress;
use wow_types::address::Address;
use wow_types::Network;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p =
            std::env::temp_dir().join(format!("wownerod-mining-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
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
    rpc: u16,
    log: PathBuf,
}

impl Daemon {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
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

fn base_args(data_dir: &Path, rpc: u16, p2p: u16) -> Vec<String> {
    [
        "--regtest",
        "--fixed-difficulty",
        "1",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--serve",
        "--no-zmq",
        "--non-interactive",
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
    .collect()
}

fn start(log: &Path, data_dir: &Path, rpc: u16, p2p: u16, extra: &[String]) -> Daemon {
    let mut args = base_args(data_dir, rpc, p2p);
    args.extend_from_slice(extra);
    let mut d = Daemon {
        child: Command::new(env!("CARGO_BIN_EXE_wownerod"))
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(log).unwrap()))
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

fn post(port: u16, path: &str, body: &Value) -> Value {
    let body = body.to_string();
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
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

fn rpc(port: u16, method: &str, params: Value) -> Value {
    post(
        port,
        "/json_rpc",
        &json!({"jsonrpc": "2.0", "id": "0", "method": method, "params": params}),
    )
}

fn height(port: u16) -> u64 {
    post(port, "/get_height", &json!({}))["height"]
        .as_u64()
        .unwrap_or(0)
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

/// An account's public keys and its secret spend key in hex.
fn account(seed: u8) -> (AccountPublicAddress, String) {
    let mut rng = wow_crypto::random::Rng::from_state([seed; 200]);
    let (_, spend) = rng.generate_keys();
    let view = wow_crypto::view_key_from_spend_key(&spend);
    let keys = AccountPublicAddress {
        spend_public_key: wow_crypto::secret_key_to_public_key(&spend).unwrap(),
        view_public_key: wow_crypto::secret_key_to_public_key(&view).unwrap(),
    };
    (keys, wow_crypto::hex::encode(&spend.0))
}

fn address(seed: u8) -> String {
    Address::standard(Network::Mainnet, account(seed).0).encode()
}

/// **Mining end to end.** `generateblocks` mines blocks that pay the address
/// and reach a peer through its validator; `get_block_template` describes the
/// next block well enough that submitting it as given is accepted; the
/// built-in miner finds blocks until told to stop, and the peer follows.
#[test]
fn mined_blocks_are_accepted_here_and_by_a_peer() {
    let s = Scratch::new("mine");
    let (a_dir, b_dir) = (s.0.join("a"), s.0.join("b"));
    std::fs::create_dir_all(&a_dir).unwrap();
    std::fs::create_dir_all(&b_dir).unwrap();
    let (a_rpc, a_p2p, b_rpc, b_p2p) = (free_port(), free_port(), free_port(), free_port());
    let a = start(&s.0.join("a.log"), &a_dir, a_rpc, a_p2p, &[]);
    let b = start(
        &s.0.join("b.log"),
        &b_dir,
        b_rpc,
        b_p2p,
        &["--add-exclusive-node".into(), format!("127.0.0.1:{a_p2p}")],
    );
    let miner = address(1);

    // generateblocks.
    let r = rpc(
        a.rpc,
        "generateblocks",
        json!({"amount_of_blocks": 3, "wallet_address": miner}),
    );
    let blocks = r["result"]["blocks"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(blocks.len(), 3, "{r}\n--- log ---\n{}", a.log());
    assert_eq!(r["result"]["height"], 3, "{r}");
    let tip = blocks[2].as_str().unwrap().to_string();
    let h = post(a.rpc, "/get_height", &json!({}));
    assert_eq!(
        (h["height"].as_u64(), h["hash"].as_str()),
        (Some(4), Some(tip.as_str()))
    );
    let header = rpc(a.rpc, "get_last_block_header", json!({}));
    assert!(
        header["result"]["block_header"]["reward"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "the coinbase pays: {header}"
    );
    wait_for(
        &[&a, &b],
        "the generated blocks to reach the peer",
        120,
        || post(b.rpc, "/get_height", &json!({}))["hash"] == tip.as_str(),
    );

    // get_block_template, and the template submitted as it is.
    let r = rpc(
        a.rpc,
        "get_block_template",
        json!({"wallet_address": miner, "reserve_size": 8}),
    );
    let t = &r["result"];
    assert_eq!(t["height"], 4, "{r}");
    assert_eq!(t["prev_hash"], tip.as_str());
    assert_eq!(t["difficulty"], 1, "the fixed difficulty");
    assert_eq!(t["vote"], 0);
    assert!(t["expected_reward"].as_u64().unwrap() > 0);
    let blob = wow_crypto::hex::decode(t["blocktemplate_blob"].as_str().unwrap()).unwrap();
    let offset = t["reserved_offset"].as_u64().unwrap() as usize;
    assert_eq!(&blob[offset..offset + 8], &[0u8; 8], "the reserved bytes");
    assert_eq!(blob[offset - 1], 8, "just after the nonce's length");
    let block = wow_types::Block::from_blob(&blob).unwrap();
    assert_eq!(
        wow_crypto::hex::encode(&block.hashing_blob().unwrap()),
        t["blockhashing_blob"].as_str().unwrap()
    );
    let r = rpc(a.rpc, "submit_block", json!([t["blocktemplate_blob"]]));
    assert_eq!(r["result"]["status"], "OK", "{r}\n--- log ---\n{}", a.log());
    assert_eq!(height(a.rpc), 5);

    // The template's refusals.
    let code = |r: Value| r["error"]["code"].as_i64();
    let ask = |params: Value| rpc(a.rpc, "get_block_template", params);
    assert_eq!(
        code(ask(json!({"wallet_address": miner, "reserve_size": 256}))),
        Some(-3)
    );
    assert_eq!(
        code(ask(json!({"wallet_address": "WWnot-an-address"}))),
        Some(-4)
    );
    let sub = Address::subaddress(Network::Mainnet, account(2).0).encode();
    assert_eq!(code(ask(json!({"wallet_address": sub}))), Some(-12));

    // The built-in miner.
    let r = post(
        a.rpc,
        "/start_mining",
        &json!({"miner_address": miner, "threads_count": 1}),
    );
    assert_eq!(r["status"], "OK", "{r}");
    let again = post(
        a.rpc,
        "/start_mining",
        &json!({"miner_address": miner, "threads_count": 1}),
    );
    assert_eq!(again["status"], "Failed", "one miner at a time: {again}");
    wait_for(&[&a], "the miner to find blocks", 120, || {
        height(a.rpc) >= 8
    });
    let st = post(a.rpc, "/mining_status", &json!({}));
    assert_eq!(st["active"], true, "{st}");
    assert_eq!(st["threads_count"], 1);
    assert_eq!(st["address"], miner.as_str());
    assert_eq!(st["pow_algorithm"], "CNv1 (Cryptonight variant 1)");
    assert_eq!(post(a.rpc, "/stop_mining", &json!({}))["status"], "OK");
    assert_eq!(post(a.rpc, "/mining_status", &json!({}))["active"], false);

    let tip = post(a.rpc, "/get_height", &json!({}))["hash"]
        .as_str()
        .unwrap()
        .to_string();
    wait_for(&[&a, &b], "the mined blocks to reach the peer", 120, || {
        post(b.rpc, "/get_height", &json!({}))["hash"] == tip.as_str()
    });
}

/// A `--spendkey` that is not the mining address's stops the node at start,
/// rather than letting it mine blocks it would sign wrongly.
#[test]
fn a_spend_key_for_another_address_stops_the_node() {
    let s = Scratch::new("wrongkey");
    let (_, other_key) = account(2);
    let mut args = base_args(&s.0, free_port(), free_port());
    args.extend([
        "--offline".to_string(),
        "--start-mining".to_string(),
        address(1),
        "--spendkey".to_string(),
        other_key,
    ]);
    let out = Command::new(env!("CARGO_BIN_EXE_wownerod"))
        .args(&args)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("does not belong"), "{stderr}");
}

/// `generateblocks` belongs to regtest.
#[test]
fn generateblocks_needs_regtest() {
    let s = Scratch::new("mainnet");
    let rpc_port = free_port();
    let mut d = Daemon {
        child: Command::new(env!("CARGO_BIN_EXE_wownerod"))
            .args([
                "--data-dir",
                s.0.to_str().unwrap(),
                "--serve",
                "--no-zmq",
                "--offline",
                "--non-interactive",
                "--rpc-bind-port",
                &rpc_port.to_string(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(s.0.join("d.log")).unwrap(),
            ))
            .spawn()
            .unwrap(),
        rpc: rpc_port,
        log: s.0.join("d.log"),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", d.rpc)).is_err() {
        assert!(Instant::now() < deadline, "no RPC\n{}", d.log());
        assert!(d.child.try_wait().unwrap().is_none(), "exited\n{}", d.log());
        std::thread::sleep(Duration::from_millis(50));
    }
    let r = rpc(
        d.rpc,
        "generateblocks",
        json!({"amount_of_blocks": 1, "wallet_address": address(1)}),
    );
    assert_eq!(r["error"]["code"], -13, "{r}");
}
