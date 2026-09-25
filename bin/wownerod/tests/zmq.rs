//! The ZMQ interface against the real binary (`specs/09` §3.2).
//!
//! Regtest with `--fixed-difficulty 1`, as the mining tests run it, so
//! `generateblocks` makes blocks in milliseconds. On the other end are the REQ
//! and SUB sockets a C++ client would use, from `wow_zmq`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use wow_crypto::types::AccountPublicAddress;
use wow_types::address::Address;
use wow_types::Network;
use wow_zmq::{ReqSocket, SubSocket};

const TIMEOUT: Duration = Duration::from_secs(30);

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("wownerod-zmq-{tag}-{}-{n}", std::process::id()));
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
    zmq: u16,
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

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn start(dir: &Path, extra: &[String]) -> Daemon {
    let (rpc, zmq) = (free_port(), free_port());
    let log = dir.join("wownerod.log");
    let mut d = Daemon {
        child: Command::new(env!("CARGO_BIN_EXE_wownerod"))
            .args([
                "--regtest",
                "--fixed-difficulty",
                "1",
                "--offline",
                "--serve",
                "--non-interactive",
                "--log-level",
                "1",
                "--data-dir",
                dir.to_str().unwrap(),
                "--rpc-bind-port",
                &rpc.to_string(),
                "--zmq-rpc-bind-port",
                &zmq.to_string(),
            ])
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&log).unwrap()))
            .spawn()
            .expect("start wownerod"),
        rpc,
        zmq,
        log,
    };
    let deadline = Instant::now() + TIMEOUT;
    while TcpStream::connect(localhost(rpc)).is_err() || TcpStream::connect(localhost(zmq)).is_err()
    {
        if let Some(status) = d.child.try_wait().unwrap() {
            panic!("wownerod exited with {status}\n--- log ---\n{}", d.log());
        }
        assert!(
            Instant::now() < deadline,
            "wownerod did not start\n--- log ---\n{}",
            d.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    d
}

fn request(d: &Daemon, body: &[u8]) -> Value {
    let mut s = ReqSocket::connect(localhost(d.zmq), TIMEOUT)
        .unwrap_or_else(|e| panic!("connect: {e}\n--- log ---\n{}", d.log()));
    let reply = s
        .request(body)
        .unwrap_or_else(|e| panic!("request: {e}\n--- log ---\n{}", d.log()));
    serde_json::from_slice(&reply).unwrap()
}

fn call(d: &Daemon, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    request(d, body.to_string().as_bytes())
}

fn post(port: u16, path: &str, body: &Value) -> Value {
    let body = body.to_string();
    let mut s = TcpStream::connect(localhost(port)).expect("connect");
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
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

fn address() -> String {
    let mut rng = wow_crypto::random::Rng::from_state([1; 200]);
    let (_, spend) = rng.generate_keys();
    let view = wow_crypto::view_key_from_spend_key(&spend);
    let keys = AccountPublicAddress {
        spend_public_key: wow_crypto::secret_key_to_public_key(&spend).unwrap(),
        view_public_key: wow_crypto::secret_key_to_public_key(&view).unwrap(),
    };
    Address::standard(Network::Mainnet, keys).encode()
}

/// Mine `n` blocks over the HTTP RPC, returning their hashes.
fn generate(d: &Daemon, n: u64) -> Vec<String> {
    let r = post(
        d.rpc,
        "/json_rpc",
        &json!({"jsonrpc": "2.0", "id": "0", "method": "generateblocks",
                "params": {"amount_of_blocks": n, "wallet_address": address()}}),
    );
    r["result"]["blocks"]
        .as_array()
        .unwrap_or_else(|| panic!("{r}\n--- log ---\n{}", d.log()))
        .iter()
        .map(|h| h.as_str().unwrap().to_string())
        .collect()
}

fn height(d: &Daemon) -> u64 {
    post(d.rpc, "/get_height", &json!({}))["height"]
        .as_u64()
        .unwrap()
}

/// **The methods.** Blocks, headers, the chain supplement and node state
/// answer in the C++'s JSON, and a bad request is refused in the C++'s words.
#[test]
fn the_zmq_rpc_answers_as_the_cpp_does() {
    let s = Scratch::new("rpc");
    let d = start(&s.0, &[]);

    let r = call(&d, "get_rpc_version", json!({}));
    assert_eq!(r["jsonrpc"], "2.0");
    assert_eq!(r["id"], 1);
    assert_eq!(r["result"]["version"], 131_072, "{r}");
    assert_eq!(r["result"]["rpc_version"], 131_072);
    assert_eq!(call(&d, "get_height", json!({}))["result"]["height"], 1);

    let mined = generate(&d, 3);
    assert_eq!(mined.len(), 3);
    let genesis = call(&d, "get_block_hash", json!({"height": 0}))["result"]["hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        call(&d, "get_block_hash", json!({"height": 2}))["result"]["hash"],
        mined[1].as_str()
    );
    let e = call(&d, "get_block_hash", json!({"height": 9}));
    assert_eq!(e["error"]["error_str"], "Failed", "{e}");
    assert_eq!(
        e["error"]["message"],
        "height given is higher than current chain height"
    );
    assert_eq!(e["id"], 1);

    // Headers.
    let h = call(
        &d,
        "get_block_headers_by_height",
        json!({"heights": [1, 3]}),
    );
    let headers = h["result"]["headers"].as_array().unwrap();
    assert_eq!(headers[1]["hash"], mined[2].as_str(), "{h}");
    assert_eq!(headers[1]["height"], 3);
    assert_eq!(headers[1]["depth"], 0);
    assert_eq!(headers[0]["difficulty"], 1, "the fixed difficulty");
    assert!(headers[0]["reward"].as_u64().unwrap() > 0);
    assert_eq!(
        call(&d, "get_last_block_header", json!({}))["result"]["header"]["hash"],
        mined[2].as_str()
    );
    assert_eq!(
        call(&d, "get_block_header_by_hash", json!({"hash": mined[0]}))["result"]["header"]
            ["height"],
        1
    );
    let e = call(&d, "get_block_header_by_height", json!({"height": 50}));
    assert_eq!(e["error"]["message"], "Requested block does not exist");

    // `get_blocks_fast` resends the block both sides have, as the C++ does.
    let b = call(
        &d,
        "get_blocks_fast",
        json!({"block_ids": [mined[0], genesis], "start_height": 0, "prune": false}),
    );
    let res = &b["result"];
    assert_eq!(res["start_height"], 1, "{b}");
    assert_eq!(res["current_height"], 4);
    let blocks = res["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 3);
    assert_eq!(
        blocks[0]["block"]["miner_tx"]["inputs"][0]["gen"]["height"],
        1
    );
    assert_eq!(blocks[1]["block"]["prev_id"], mined[0].as_str());
    assert_eq!(blocks[2]["transactions"], json!([]));
    assert_eq!(res["output_indices"].as_array().unwrap().len(), 3);
    assert_eq!(
        res["output_indices"][0].as_array().unwrap().len(),
        1,
        "the coinbase's indices"
    );
    let from_two = call(
        &d,
        "get_blocks_fast",
        json!({"block_ids": [], "start_height": 2, "prune": true}),
    );
    assert_eq!(from_two["result"]["start_height"], 2);
    assert_eq!(from_two["result"]["blocks"].as_array().unwrap().len(), 2);
    let hashes = call(
        &d,
        "get_hashes_fast",
        json!({"known_hashes": [genesis], "start_height": 0}),
    );
    assert_eq!(hashes["result"]["start_height"], 0, "{hashes}");
    assert_eq!(hashes["result"]["hashes"][3], mined[2].as_str());
    let e = call(
        &d,
        "get_hashes_fast",
        json!({"known_hashes": [mined[0]], "start_height": 0}),
    );
    assert_eq!(
        e["error"]["error_str"], "Failed",
        "a history must end at genesis"
    );

    // Node state.
    let info = &call(&d, "get_info", json!({}))["result"]["info"];
    assert_eq!(info["height"], 4, "{info}");
    assert_eq!(info["top_block_height"], 3);
    assert_eq!(info["top_block_hash"], mined[2].as_str());
    assert_eq!(info["difficulty"], 1);
    assert_eq!(info["tx_count"], 0, "coinbases only");
    assert_eq!(info["nettype"], "");
    assert_eq!(
        call(
            &d,
            "key_images_spent",
            json!({"key_images": ["00".repeat(32)]})
        )["result"]["spent_status"],
        json!([0])
    );
    assert_eq!(
        call(&d, "get_transaction_pool", json!({}))["result"]["transactions"],
        json!([])
    );
    assert_eq!(
        call(&d, "mining_status", json!({}))["result"]["active"],
        false
    );
    let dist = call(
        &d,
        "get_output_distribution",
        json!({"amounts": [0], "from_height": 0, "to_height": 0, "cumulative": true}),
    );
    assert_eq!(dist["result"]["status"], "OK", "{dist}");
    assert_eq!(dist["result"]["distributions"][0]["start_height"], 0);
    assert_eq!(
        dist["result"]["distributions"][0]["distribution"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        call(
            &d,
            "get_tx_global_output_indices",
            json!({"tx_hash": "00".repeat(32)})
        )["error"]["message"],
        "core::get_tx_outputs_gindexs() returned false"
    );
    assert_eq!(
        call(
            &d,
            "start_mining",
            json!({"miner_address": "WWnope", "threads_count": 1,
                   "do_background_mining": false, "ignore_battery": false})
        )["error"]["message"],
        "Failed, wrong address"
    );
    assert_eq!(
        call(&d, "stop_mining", json!({}))["result"]["rpc_version"],
        131_072
    );

    // The envelope's refusals.
    let e = call(&d, "get_block_hash", json!({}));
    assert_eq!(e["id"], Value::Null, "{e}");
    assert_eq!(e["error"]["error_str"], "Malformed json");
    assert_eq!(e["error"]["message"], "Key \"height\" missing from object.");
    let e = call(&d, "get_block_hash", json!({"height": "one"}));
    assert_eq!(
        e["error"]["message"],
        "Json value has incorrect type, expected: unsigned integer"
    );
    let e = call(&d, "frobnicate", json!({}));
    assert_eq!(e["error"]["error_str"], "Invalid request type");
    assert_eq!(
        e["error"]["message"],
        "\"frobnicate\" is not a valid request."
    );
    assert_eq!(e["id"], 1);
    let e = request(&d, b"{not json");
    assert_eq!(e["error"]["message"], "Failed to parse the json request");
}

/// **The publisher.** Each block is announced as the C++ announces it --
/// miner data for the new tip, then the block in full and in brief -- and a
/// subscriber hears only the topics it subscribed to.
#[test]
fn the_publisher_announces_each_block_in_the_cpp_order() {
    let s = Scratch::new("pub");
    let pub_port = free_port();
    let d = start(
        &s.0,
        &[
            "--zmq-pub".to_string(),
            format!("tcp://127.0.0.1:{pub_port}"),
        ],
    );

    let mut everything = SubSocket::connect(localhost(pub_port), TIMEOUT).unwrap();
    everything.subscribe(b"json-").unwrap();
    let mut minimal = SubSocket::connect(localhost(pub_port), TIMEOUT).unwrap();
    minimal.subscribe(b"json-minimal").unwrap();

    // A subscription reaches the node on its own time; mine until both have
    // been heard, then drain what that left behind.
    let quiet = Duration::from_millis(700);
    everything.set_timeout(quiet).unwrap();
    minimal.set_timeout(quiet).unwrap();
    let (mut heard_all, mut heard_minimal) = (false, false);
    let deadline = Instant::now() + TIMEOUT;
    while !(heard_all && heard_minimal) {
        assert!(
            Instant::now() < deadline,
            "no announcement arrived\n--- log ---\n{}",
            d.log()
        );
        generate(&d, 1);
        heard_all |= everything.recv().is_ok();
        heard_minimal |= minimal.recv().is_ok();
    }
    while everything.recv().is_ok() {}
    while minimal.recv().is_ok() {}

    let before = height(&d);
    let mined = generate(&d, 2);
    everything.set_timeout(TIMEOUT).unwrap();
    let mut messages = Vec::new();
    for _ in 0..6 {
        let text = String::from_utf8(everything.recv().unwrap()).unwrap();
        let (topic, body) = text.split_once(':').unwrap();
        messages.push((
            topic.to_string(),
            serde_json::from_str::<Value>(body).unwrap(),
        ));
    }
    let topics: Vec<&str> = messages.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(
        topics,
        [
            "json-full-miner_data",
            "json-full-chain_main",
            "json-minimal-chain_main",
            "json-full-miner_data",
            "json-full-chain_main",
            "json-minimal-chain_main",
        ]
    );

    let miner = &messages[0].1;
    assert_eq!(miner["height"], before + 1, "the next block's: {miner}");
    assert_eq!(miner["prev_id"], mined[0].as_str());
    assert_eq!(miner["difficulty"], "0x1");
    assert_eq!(miner["tx_backlog"], json!([]));
    assert_eq!(miner["seed_hash"].as_str().unwrap().len(), 64);
    let full = &messages[1].1;
    assert_eq!(full.as_array().unwrap().len(), 1, "one block a message");
    assert_eq!(full[0]["miner_tx"]["inputs"][0]["gen"]["height"], before);
    let brief = &messages[5].1;
    assert_eq!(brief["first_height"], before + 1);
    assert_eq!(brief["first_prev_id"], mined[0].as_str());
    assert_eq!(brief["ids"], json!([mined[1]]));

    minimal.set_timeout(TIMEOUT).unwrap();
    for (i, hash) in mined.iter().enumerate() {
        let text = String::from_utf8(minimal.recv().unwrap()).unwrap();
        let (topic, body) = text.split_once(':').unwrap();
        assert_eq!(topic, "json-minimal-chain_main");
        let v: Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["first_height"], before + i as u64);
        assert_eq!(v["ids"], json!([hash]));
    }
    minimal.set_timeout(quiet).unwrap();
    assert!(minimal.recv().is_err(), "nothing but the minimal topics");
}

/// **Restricted, and refused.** `--restricted-zmq-rpc` refuses by name and
/// caps the rest; a ZMQ RPC beyond loopback, or a pub endpoint that is not
/// TCP, stops the node before it starts.
#[test]
fn restricted_mode_and_refused_configurations() {
    let s = Scratch::new("restricted");
    let d = start(&s.0, &["--restricted-zmq-rpc".to_string()]);
    let e = call(
        &d,
        "start_mining",
        json!({"miner_address": address(), "threads_count": 1,
               "do_background_mining": false, "ignore_battery": false}),
    );
    assert_eq!(e["error"]["error_str"], "Failed", "{e}");
    assert_eq!(
        e["error"]["message"],
        "\"start_mining\" is not available in restricted mode."
    );
    let e = call(
        &d,
        "get_output_distribution",
        json!({"amounts": [1], "from_height": 0, "to_height": 0, "cumulative": false}),
    );
    assert_eq!(
        e["error"]["message"],
        "Restricted RPC can only get output distribution for rct outputs. Use your own node."
    );
    // `recent_cutoff = 0` is no cutoff, served as over HTTP; the C++ ZMQ path
    // refuses it as "too old".
    let histogram = |recent_cutoff: u64| {
        call(
            &d,
            "get_output_histogram",
            json!({"amounts": [1], "min_count": 0, "max_count": 0,
                   "unlocked": false, "recent_cutoff": recent_cutoff}),
        )
    };
    let r = histogram(0);
    assert!(r.get("error").is_none(), "0 is no cutoff: {r}");
    assert!(r["result"]["histogram"].is_array(), "{r}");
    assert_eq!(histogram(1)["error"]["message"], "Recent cutoff is too old");
    let info = &call(&d, "get_info", json!({}))["result"]["info"];
    assert_eq!(info["version"], "", "restricted hides the version: {info}");
    assert_eq!(call(&d, "get_height", json!({}))["result"]["height"], 1);
    drop(d);

    for (args, expected) in [
        (
            ["--zmq-rpc-bind-ip", "0.0.0.0"],
            "permits inbound unencrypted external connections",
        ),
        (["--zmq-pub", "ipc:///tmp/wownerod"], "ipc://"),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_wownerod"))
            .args(["--data-dir", s.0.to_str().unwrap(), "--regtest", "--serve"])
            .args(args)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?}: {stderr}");
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
    }
}
