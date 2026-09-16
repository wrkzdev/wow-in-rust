//! The RPC server, against a running `wownerod`.
//!
//! `specs/11-daemon-rpc.md`. These start the real binary, talk HTTP to it, and
//! read the JSON back — so what is checked is what a wallet or explorer would
//! see.
//!
//! The field names are the contract (`specs/11` opens with "Field names in this
//! document are exactly the JSON keys"), so the assertions are on names as much
//! as on values.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use wow_storage::db::BlockchainDb;
use wow_storage::env::OpenMode;
use wow_storage::lmdb::LmdbDb;
use wow_types::{Block, Network};

const MAP_SIZE: usize = 32 << 20;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("wownerod-rpc-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running daemon, stopped when dropped.
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

/// An unused port, found by binding and releasing one.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Seed a database with the genesis block plus `extra` coinbase-only blocks
/// from the committed fixture, then start a daemon serving it.
fn start(tag: &str, extra: usize) -> Daemon {
    let scratch = Scratch::new(tag);
    let dir = wow_storage::env::db_dir(&scratch.0, Network::Mainnet, false);
    {
        let db = LmdbDb::open_with_map_size(&dir, OpenMode::default(), 2, MAP_SIZE).unwrap();

        let blob = wow_consensus::genesis::genesis_blob(Network::Mainnet);
        let blk = Block::from_blob(&blob).unwrap();
        let mut prev = blk.block_id().unwrap();
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
    d
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

/// One HTTP request, returning the parsed JSON body.
fn post(port: u16, path: &str, body: &str) -> Value {
    let addr = ("127.0.0.1", port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();

    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    s.flush().unwrap();

    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();

    let (head, body) = raw.split_once("\r\n\r\n").expect("a complete response");
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(head.contains("application/json"), "{head}");
    serde_json::from_str(body).unwrap_or_else(|e| panic!("bad JSON: {e}\n{body}"))
}

/// One raw HTTP exchange, returning the whole response text.
fn raw(port: u16, request: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    s.flush().unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

fn rpc(port: u16, method: &str, params: &str) -> Value {
    let body = format!(r#"{{"jsonrpc":"2.0","id":"0","method":"{method}","params":{params}}}"#);
    post(port, "/json_rpc", &body)
}

// ---------------------------------------------------------------------------
// direct endpoints (specs/11 §3)
// ---------------------------------------------------------------------------

#[test]
fn get_height_reports_the_tip() {
    let d = start("height", 3);
    let v = post(d.port, "/get_height", "{}");

    assert_eq!(v["status"], "OK");
    assert_eq!(v["height"], 4, "genesis plus three");
    assert_eq!(v["hash"].as_str().unwrap().len(), 64);
    // `specs/11` §2: every response carries these.
    assert_eq!(v["untrusted"], true);
    assert_eq!(v["credits"], 0);
    assert_eq!(v["top_hash"], "");
}

/// A request carrying `Origin` came from a web page, and is refused: the
/// text/plain POST a page can send without a CORS preflight would otherwise
/// reach the handler. No response carries a wildcard CORS header either.
#[test]
fn browser_requests_are_refused_and_no_cors_header_is_sent() {
    let d = start("origin", 1);
    let body = "{}";

    let from_a_page = raw(
        d.port,
        &format!(
            "POST /get_height HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://example.com\r\n\
             Content-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(from_a_page.starts_with("HTTP/1.1 403"), "{from_a_page}");
    assert!(!from_a_page.contains("\"height\""), "{from_a_page}");

    let from_a_client = raw(
        d.port,
        &format!(
            "POST /get_height HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(from_a_client.starts_with("HTTP/1.1 200"), "{from_a_client}");
    assert!(
        !from_a_client.contains("Access-Control-Allow-Origin"),
        "{from_a_client}"
    );
}

/// The C++ serves both spellings, and so must this.
#[test]
fn the_endpoint_aliases_work() {
    let d = start("aliases", 1);
    assert_eq!(
        post(d.port, "/get_height", "{}")["height"],
        post(d.port, "/getheight", "{}")["height"]
    );
    assert_eq!(
        post(d.port, "/get_info", "{}")["height"],
        post(d.port, "/getinfo", "{}")["height"]
    );
}

/// `specs/11` §3.2 lists the fields clients depend on. Missing one breaks a
/// wallet that reads it by name.
#[test]
fn get_info_carries_every_documented_field() {
    let d = start("info", 2);
    let v = post(d.port, "/get_info", "{}");

    for field in [
        "height",
        "target_height",
        "difficulty",
        "difficulty_top64",
        "wide_difficulty",
        "target",
        "tx_count",
        "tx_pool_size",
        "alt_blocks_count",
        "outgoing_connections_count",
        "incoming_connections_count",
        "rpc_connections_count",
        "white_peerlist_size",
        "grey_peerlist_size",
        "mainnet",
        "testnet",
        "stagenet",
        "nettype",
        "top_block_hash",
        "cumulative_difficulty",
        "cumulative_difficulty_top64",
        "wide_cumulative_difficulty",
        "block_size_limit",
        "block_weight_limit",
        "block_size_median",
        "block_weight_median",
        "adjusted_time",
        "start_time",
        "free_space",
        "offline",
        "untrusted",
        "bootstrap_daemon_address",
        "height_without_bootstrap",
        "was_bootstrap_ever_used",
        "database_size",
        "update_available",
        "version",
        "synchronized",
        "busy_syncing",
        "restricted",
        "credits",
        "top_hash",
        "status",
    ] {
        assert!(!v[field].is_null(), "get_info is missing `{field}`");
    }

    assert_eq!(v["nettype"], "mainnet");
    assert_eq!(v["mainnet"], true);
    assert_eq!(v["testnet"], false);
    assert_eq!(v["height"], 3);

    // `specs/11` §3.2: the `block_size_*` names are legacy aliases for the
    // weight fields and carry the same values.
    assert_eq!(v["block_size_limit"], v["block_weight_limit"]);
    assert_eq!(v["block_size_median"], v["block_weight_median"]);

    // No peers, so this node is honest about not being synced.
    assert_eq!(v["synchronized"], false);
    assert_eq!(v["untrusted"], true);
    assert_eq!(v["offline"], true);
}

// ---------------------------------------------------------------------------
// JSON-RPC (specs/11 §4)
// ---------------------------------------------------------------------------

#[test]
fn json_rpc_wraps_results_in_the_envelope() {
    let d = start("envelope", 1);
    let v = rpc(d.port, "get_info", "{}");

    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], "0");
    assert_eq!(v["result"]["status"], "OK");
    assert!(v["error"].is_null());
}

/// An unknown method is `UNSUPPORTED_RPC` (-11), not a crash and not a
/// plausible empty answer.
#[test]
fn an_unknown_method_returns_unsupported() {
    let d = start("unknown", 1);
    let v = rpc(d.port, "get_transaction_pool", "{}");

    assert!(v["result"].is_null());
    assert_eq!(v["error"]["code"], -11);
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains("get_transaction_pool"), "{msg}");
}

/// Malformed JSON is an error response, not a dropped connection.
#[test]
fn malformed_json_is_answered_not_dropped() {
    let d = start("badjson", 1);
    let v = post(d.port, "/json_rpc", "{not json");
    assert_eq!(v["error"]["code"], -1);
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("invalid JSON"));
}

/// `specs/11` §4.4. With a zero threshold, `enabled` is purely height-driven.
#[test]
fn hard_fork_info_reports_the_table() {
    let d = start("hardfork", 2);
    let v = rpc(d.port, "hard_fork_info", "{}")["result"].clone();

    assert_eq!(v["status"], "OK");
    assert_eq!(v["version"], 7, "the version at a 3-block chain");
    assert_eq!(v["enabled"], true);
    assert_eq!(v["threshold"], 0, "Wownero votes with a zero threshold");
    assert_eq!(v["earliest_height"], 1, "HF 7 starts at height 1");

    // A specific version can be asked for.
    let v = rpc(d.port, "hard_fork_info", r#"{"version":20}"#)["result"].clone();
    assert_eq!(v["version"], 20);
    assert_eq!(v["earliest_height"], 514_000);
    assert_eq!(v["enabled"], false, "a 3-block chain is not at HF 20");
}

/// `specs/11` §4.6. `vote` is Wownero-specific and must be present —
/// "explorers read it for the on-chain vote tally".
#[test]
fn a_block_header_carries_every_field_including_vote() {
    let d = start("header", 3);
    let v = rpc(d.port, "get_block_header_by_height", r#"{"height":1}"#);
    let h = &v["result"]["block_header"];

    for field in [
        "major_version",
        "minor_version",
        "timestamp",
        "prev_hash",
        "nonce",
        "vote",
        "orphan_status",
        "height",
        "depth",
        "hash",
        "difficulty",
        "difficulty_top64",
        "wide_difficulty",
        "cumulative_difficulty",
        "cumulative_difficulty_top64",
        "wide_cumulative_difficulty",
        "reward",
        "block_size",
        "block_weight",
        "num_txes",
        "long_term_weight",
        "miner_tx_hash",
    ] {
        assert!(!h[field].is_null(), "the header is missing `{field}`");
    }

    assert_eq!(h["height"], 1);
    assert_eq!(h["depth"], 2, "three blocks above height 1 means depth 2");
    assert_eq!(h["orphan_status"], false);
    assert!(h["reward"].as_u64().unwrap() > 0, "a coinbase pays");
    assert_eq!(h["hash"].as_str().unwrap().len(), 64);
    assert_eq!(h["miner_tx_hash"].as_str().unwrap().len(), 64);
}

/// `specs/11` §2.1: three fields per difficulty, and the wide one is hex.
#[test]
fn difficulties_are_emitted_three_ways() {
    let d = start("difficulty", 2);
    let h = rpc(d.port, "get_last_block_header", "{}")["result"]["block_header"].clone();

    let lo = h["cumulative_difficulty"].as_u64().unwrap();
    let hi = h["cumulative_difficulty_top64"].as_u64().unwrap();
    let wide = h["wide_cumulative_difficulty"].as_str().unwrap();

    assert!(wide.starts_with("0x"), "{wide}");
    let parsed = u128::from_str_radix(wide.trim_start_matches("0x"), 16).unwrap();
    assert_eq!(parsed, (u128::from(hi) << 64) | u128::from(lo));
}

#[test]
fn get_last_block_header_is_the_tip() {
    let d = start("lastheader", 3);
    let last = rpc(d.port, "get_last_block_header", "{}")["result"]["block_header"].clone();
    let by_height = rpc(d.port, "get_block_header_by_height", r#"{"height":3}"#)["result"]
        ["block_header"]
        .clone();

    assert_eq!(last["hash"], by_height["hash"]);
    assert_eq!(last["height"], 3);
    assert_eq!(last["depth"], 0, "the tip has depth 0");
}

#[test]
fn a_header_can_be_fetched_by_hash() {
    let d = start("byhash", 2);
    let by_height = rpc(d.port, "get_block_header_by_height", r#"{"height":1}"#)["result"]
        ["block_header"]
        .clone();
    let hash = by_height["hash"].as_str().unwrap();

    let by_hash = rpc(
        d.port,
        "get_block_header_by_hash",
        &format!(r#"{{"hash":"{hash}"}}"#),
    )["result"]["block_header"]
        .clone();
    assert_eq!(by_hash["height"], 1);
    assert_eq!(by_hash["hash"], hash);
}

/// A height past the tip is `TOO_BIG_HEIGHT` (-2), which is a distinct code
/// from a bad parameter.
#[test]
fn a_height_past_the_tip_is_rejected() {
    let d = start("toobig", 1);
    let v = rpc(d.port, "get_block_header_by_height", r#"{"height":9999}"#);
    assert_eq!(v["error"]["code"], -2);

    let v = rpc(d.port, "get_block_hash", "[9999]");
    assert_eq!(v["error"]["code"], -2);

    // A missing parameter is -1, not -2.
    let v = rpc(d.port, "get_block_header_by_height", "{}");
    assert_eq!(v["error"]["code"], -1);
}

/// `get_block_hash` takes the C++'s bare-array form.
#[test]
fn get_block_hash_takes_a_bare_array() {
    let d = start("blockhash", 2);
    let v = rpc(d.port, "get_block_hash", "[0]");
    assert_eq!(
        v["result"], "a3fd635dd5cb55700317783469ba749b5259f0eeac2420ab2c27eb3ff5ffdc5c",
        "height 0 is the mainnet genesis"
    );

    // The object form works too, for clients that send one.
    let v = rpc(d.port, "get_block_hash", r#"{"height":0}"#);
    assert_eq!(
        v["result"],
        "a3fd635dd5cb55700317783469ba749b5259f0eeac2420ab2c27eb3ff5ffdc5c"
    );
}

#[test]
fn get_block_headers_range_returns_a_range() {
    let d = start("range", 4);
    let v = rpc(
        d.port,
        "get_block_headers_range",
        r#"{"start_height":1,"end_height":3}"#,
    );
    let headers = v["result"]["headers"].as_array().unwrap();
    assert_eq!(headers.len(), 3);
    assert_eq!(headers[0]["height"], 1);
    assert_eq!(headers[2]["height"], 3);

    // An inverted range is refused rather than returning nothing.
    let v = rpc(
        d.port,
        "get_block_headers_range",
        r#"{"start_height":3,"end_height":1}"#,
    );
    assert_eq!(v["error"]["code"], -1);

    // And the range is capped, so a response cannot be unbounded.
    let v = rpc(
        d.port,
        "get_block_headers_range",
        r#"{"start_height":0,"end_height":5000}"#,
    );
    assert_eq!(v["error"]["code"], -1);
    assert!(v["error"]["message"].as_str().unwrap().contains("exceeds"));
}

#[test]
fn get_block_returns_the_blob_and_tx_hashes() {
    let d = start("getblock", 2);
    let v = rpc(d.port, "get_block", r#"{"height":0}"#)["result"].clone();

    assert_eq!(v["status"], "OK");
    assert_eq!(v["block_header"]["height"], 0);
    assert!(v["tx_hashes"].as_array().unwrap().is_empty());

    // The blob round-trips to the same block.
    let blob = wow_crypto::hex::decode(v["blob"].as_str().unwrap()).unwrap();
    let blk = Block::from_blob(&blob).unwrap();
    assert_eq!(
        wow_crypto::hex::encode(&blk.block_id().unwrap()),
        v["block_header"]["hash"].as_str().unwrap()
    );
}

/// `specs/11` §4.5. The four tiers map to wallet priorities 1..4.
#[test]
fn get_fee_estimate_returns_the_tiers() {
    let d = start("fee", 2);
    let v = rpc(d.port, "get_fee_estimate", "{}")["result"].clone();

    assert_eq!(v["status"], "OK");
    assert!(v["fee"].as_u64().unwrap() > 0);
    assert_eq!(v["quantization_mask"], 1000, "Wownero's 11 decimals");

    let fees = v["fees"].as_array().unwrap();
    assert_eq!(fees.len(), 4, "the four 2021-scaling tiers");
    for w in fees.windows(2) {
        assert!(
            w[0].as_u64().unwrap() <= w[1].as_u64().unwrap(),
            "the tiers must be ordered: {fees:?}"
        );
    }
}

#[test]
fn get_version_lists_the_hard_forks() {
    let d = start("version", 1);
    let v = rpc(d.port, "get_version", "{}")["result"].clone();

    assert_eq!(v["status"], "OK");
    let forks = v["hard_forks"].as_array().unwrap();
    assert_eq!(forks.len(), 14, "the mainnet table");
    assert_eq!(forks[0]["hf_version"], 7);
    assert_eq!(forks[0]["height"], 1);
    assert_eq!(forks[13]["hf_version"], 20);
    assert_eq!(forks[13]["height"], 514_000);
}

/// The checkpoint check, over RPC rather than as a command-line run.
#[test]
fn get_checkpoints_reports_what_it_compared() {
    let d = start("checkpoints", 2);
    let v = post(d.port, "/get_checkpoints", "{}");

    assert_eq!(v["status"], "OK");
    assert_eq!(v["total"], 39, "the mainnet table");
    assert_eq!(
        v["checked"], 1,
        "only the height-1 checkpoint is below a 3-block chain"
    );
    // The fixture blocks are not the real chain, so it must report a mismatch
    // rather than passing.
    assert_eq!(v["matched"], 0);
    assert_eq!(v["checkpoints"][0]["matches"], false);
}

/// The body limit from `specs/11` §1.1 is enforced by the running server.
#[test]
fn an_oversized_request_is_refused() {
    let d = start("toolarge", 1);
    let addr = ("127.0.0.1", d.port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();

    // Declare more than MAX_RPC_CONTENT_LENGTH without sending it.
    let req = "POST /json_rpc HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\n";
    s.write_all(req.as_bytes()).unwrap();
    s.flush().unwrap();

    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    assert!(raw.starts_with("HTTP/1.1 413"), "{raw}");
}
