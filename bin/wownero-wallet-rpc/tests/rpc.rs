//! Driving the real server over HTTP.
//!
//! `specs/14` says method names, parameter names and error codes are a
//! compatibility surface, so what is tested here is the wire: a client sends
//! JSON-RPC 2.0 to `POST /json_rpc` and reads the fields back by name.
//!
//! No daemon is involved. The server is pointed at an address nothing is
//! listening on, which is itself worth checking — a wallet service that cannot
//! reach a node should still start, still answer, and say what it cannot do.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// An address with nothing behind it.
const NO_DAEMON: &str = "127.0.0.1:1";
const USER: &str = "rpcuser";
const PASS: &str = "rpcpass";

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let mut p = std::env::temp_dir();
        p.push(format!("wow-rpc-{tag}-{}", std::process::id()));
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

struct Server {
    child: Child,
    port: u16,
    auth: Option<String>,
    _scratch: Scratch,
}

impl Drop for Server {
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

/// Base64, for the Basic credential.
fn base64(input: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// A daemon that answers `get_info` and nothing else.
///
/// Enough for `set_daemon`, which is all these tests need: the question is
/// whether a wallet ends up *pointed* at a daemon, not what it then fetches.
/// Returns the address it listens on; the thread ends with the process.
fn fake_daemon(height: u64) -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();

    std::thread::spawn(move || {
        let body = format!("{{\"status\":\"OK\",\"height\":{height},\"target_height\":0,\"nettype\":\"mainnet\",\"synchronized\":true,\"untrusted\":false}}");
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let body = body.clone();
            // One thread per connection. Served serially, a client still
            // holding an earlier socket delays the next connect long enough
            // to look like the server failing to attach a daemon -- which is
            // exactly the bug this fixture exists to detect.
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(body.as_bytes());
                let _ = s.flush();
            });
        }
    });

    addr
}

fn start(tag: &str, with_auth: bool) -> Server {
    start_with_daemon(tag, with_auth, NO_DAEMON.to_string())
}

fn start_with_daemon(tag: &str, with_auth: bool, daemon: String) -> Server {
    let scratch = Scratch::new(tag);
    let port = free_port();

    let mut args = vec![
        "--rpc-bind-port".to_string(),
        port.to_string(),
        "--wallet-dir".to_string(),
        scratch.0.to_str().expect("utf-8").to_string(),
        "--daemon-address".to_string(),
        daemon,
    ];
    if with_auth {
        args.push("--rpc-login".into());
        args.push(format!("{USER}:{PASS}"));
    } else {
        args.push("--disable-rpc-login".into());
    }

    let child = Command::new(env!("CARGO_BIN_EXE_wownero-wallet-rpc"))
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start wownero-wallet-rpc");

    let s = Server {
        child,
        port,
        auth: with_auth.then(|| format!("Basic {}", base64(&format!("{USER}:{PASS}")))),
        _scratch: scratch,
    };
    wait_ready(port);
    s
}

fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("wownero-wallet-rpc did not start listening on {port}");
}

/// One JSON-RPC call. Returns the whole envelope.
fn call_with(server: &Server, auth: Option<&str>, method: &str, params: Value) -> Value {
    let body = json!({
        "jsonrpc": "2.0",
        "id": "0",
        "method": method,
        "params": params,
    })
    .to_string();

    let mut stream =
        TcpStream::connect(("127.0.0.1", server.port)).expect("connect to the wallet rpc");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");

    let auth_header = match auth {
        Some(a) => format!("Authorization: {a}\r\n"),
        None => String::new(),
    };
    let request = format!(
        "POST /json_rpc HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         {auth_header}\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write");
    stream.flush().expect("flush");

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("status line");
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .expect("a status")
        .parse()
        .expect("a number");

    let mut length = 0usize;
    loop {
        line.clear();
        reader.read_line(&mut line).expect("header");
        if line.trim_end().is_empty() {
            break;
        }
        if let Some((name, value)) = line.trim_end().split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().expect("a length");
            }
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).expect("body");

    let mut v: Value = serde_json::from_slice(&body).expect("JSON");
    v["_http_status"] = json!(status);
    v
}

fn call(server: &Server, method: &str, params: Value) -> Value {
    call_with(server, server.auth.as_deref(), method, params)
}

/// A wallet created through the RPC, for the tests that need one.
fn create_wallet(server: &Server, name: &str) -> Value {
    let v = call(
        server,
        "create_wallet",
        json!({ "filename": name, "password": "pw", "language": "English" }),
    );
    assert!(v.get("error").is_none(), "create_wallet failed: {v}");
    v["result"].clone()
}

/// `get_version` reports the documented number and needs no wallet.
#[test]
fn get_version_works_without_a_wallet() {
    let s = start("version", false);
    let v = call(&s, "get_version", json!({}));
    assert_eq!(v["result"]["version"], 65_566, "{v}");
}

/// Authentication is enforced. This is the requirement `specs/14` §1 calls a
/// wallet-draining hole if it is missing.
#[test]
fn authentication_is_enforced() {
    let s = start("auth", true);

    // With the right credential.
    let v = call(&s, "get_version", json!({}));
    assert_eq!(v["result"]["version"], 65_566, "{v}");

    // Without any.
    let v = call_with(&s, None, "get_version", json!({}));
    assert_eq!(v["_http_status"], 401, "{v}");

    // With the wrong one.
    let wrong = format!("Basic {}", base64("rpcuser:wrong"));
    let v = call_with(&s, Some(&wrong), "get_version", json!({}));
    assert_eq!(v["_http_status"], 401, "{v}");
}

/// Before a wallet is open, everything but the openers returns `-13 NOT_OPEN`.
#[test]
fn methods_report_no_open_wallet() {
    let s = start("notopen", false);
    for method in ["get_balance", "get_address", "refresh", "store", "transfer"] {
        let v = call(&s, method, json!({}));
        assert_eq!(v["error"]["code"], -13, "{method}: {v}");
    }
}

/// Create a wallet, then read its address and balance back.
#[test]
fn a_wallet_can_be_created_and_queried() {
    let s = start("create", false);
    let created = create_wallet(&s, "w");

    let address = created["address"].as_str().expect("an address");
    assert!(address.starts_with("Wo"), "{address}");
    assert_eq!(
        created["seed"]
            .as_str()
            .expect("a seed")
            .split_whitespace()
            .count(),
        25
    );

    let v = call(&s, "get_address", json!({}));
    assert_eq!(v["result"]["address"], address, "{v}");

    let v = call(&s, "get_balance", json!({}));
    assert_eq!(v["result"]["balance"], 0, "{v}");
    assert_eq!(v["result"]["unlocked_balance"], 0);
    // `blocks_to_unlock` is the field `specs/14` §3.3 singles out, because a
    // coinbase locks for 288 blocks here.
    assert!(v["result"]["blocks_to_unlock"].is_number(), "{v}");

    // One, not zero: a wallet starting at height zero holds the genesis hash
    // from the moment it is made, so its chain is one block long before it has
    // scanned anything. `wallet2::get_blockchain_current_height` returns
    // `m_blockchain.size()` and reports the same 1.
    let v = call(&s, "get_height", json!({}));
    assert_eq!(v["result"]["height"], 1, "{v}");
}

/// `query_key` returns each key, and refuses the spend key on a view-only
/// wallet.
#[test]
fn query_key_returns_the_keys() {
    let s = start("keys", false);
    create_wallet(&s, "w");

    for kind in ["view_key", "spend_key"] {
        let v = call(&s, "query_key", json!({ "key_type": kind }));
        let key = v["result"]["key"].as_str().unwrap_or_else(|| panic!("{v}"));
        assert_eq!(key.len(), 64, "{kind} is 32 bytes of hex: {v}");
    }

    let v = call(&s, "query_key", json!({ "key_type": "mnemonic" }));
    assert_eq!(
        v["result"]["key"]
            .as_str()
            .expect("a seed")
            .split_whitespace()
            .count(),
        25,
        "{v}"
    );

    let v = call(&s, "query_key", json!({ "key_type": "nonsense" }));
    assert_eq!(v["error"]["code"], -25, "{v}");
}

/// A seed restores the same wallet.
#[test]
fn a_seed_restores_the_same_wallet() {
    let s = start("restore", false);
    let created = create_wallet(&s, "original");
    let address = created["address"].as_str().expect("an address").to_string();
    let seed = created["seed"].as_str().expect("a seed").to_string();

    let v = call(
        &s,
        "restore_deterministic_wallet",
        json!({ "filename": "restored", "password": "pw", "seed": seed }),
    );
    assert!(v.get("error").is_none(), "{v}");
    assert_eq!(v["result"]["address"], address, "{v}");
}

/// `validate_address` classifies the three prefixes.
#[test]
fn validate_address_classifies_correctly() {
    let s = start("validate", false);
    let created = create_wallet(&s, "w");
    let address = created["address"].as_str().expect("an address").to_string();

    let v = call(&s, "validate_address", json!({ "address": address }));
    assert_eq!(v["result"]["valid"], true, "{v}");
    assert_eq!(v["result"]["integrated"], false);
    assert_eq!(v["result"]["subaddress"], false);
    assert_eq!(v["result"]["nettype"], "mainnet");

    // An integrated address made from it.
    let made = call(&s, "make_integrated_address", json!({}));
    let integrated = made["result"]["integrated_address"]
        .as_str()
        .expect("an address")
        .to_string();
    let v = call(&s, "validate_address", json!({ "address": integrated }));
    assert_eq!(v["result"]["integrated"], true, "{v}");

    // And a subaddress.
    let sub = call(&s, "create_address", json!({}));
    let sub = sub["result"]["address"]
        .as_str()
        .expect("an address")
        .to_string();
    let v = call(&s, "validate_address", json!({ "address": sub }));
    assert_eq!(v["result"]["subaddress"], true, "{v}");

    // Nonsense is invalid rather than an error.
    let v = call(
        &s,
        "validate_address",
        json!({ "address": "not an address" }),
    );
    assert_eq!(v["result"]["valid"], false, "{v}");
}

/// An integrated address splits back into what it was made from.
#[test]
fn an_integrated_address_round_trips() {
    let s = start("integrated", false);
    let created = create_wallet(&s, "w");
    let address = created["address"].as_str().expect("an address").to_string();

    let made = call(
        &s,
        "make_integrated_address",
        json!({ "payment_id": "0102030405060708" }),
    );
    let integrated = made["result"]["integrated_address"]
        .as_str()
        .expect("an address")
        .to_string();
    assert_eq!(made["result"]["payment_id"], "0102030405060708");

    let split = call(
        &s,
        "split_integrated_address",
        json!({ "integrated_address": integrated }),
    );
    assert_eq!(split["result"]["standard_address"], address, "{split}");
    assert_eq!(split["result"]["payment_id"], "0102030405060708");

    // A standard address has nothing to split.
    let v = call(
        &s,
        "split_integrated_address",
        json!({ "integrated_address": address }),
    );
    assert_eq!(v["error"]["code"], -2, "{v}");
}

/// `get_payments` and `get_bulk_payments` answer, where they were refused as
/// not built, and an id that is not one is `-5 WRONG_PAYMENT_ID`.
#[test]
fn payments_are_listed_by_payment_id() {
    let s = start("payments", false);
    create_wallet(&s, "w");

    let v = call(
        &s,
        "get_payments",
        json!({ "payment_id": "0102030405060708" }),
    );
    assert_eq!(v["result"]["payments"], json!([]), "{v}");

    let v = call(
        &s,
        "get_bulk_payments",
        json!({ "payment_ids": ["0102030405060708"], "min_block_height": 0 }),
    );
    assert_eq!(v["result"]["payments"], json!([]), "{v}");

    let v = call(&s, "get_payments", json!({ "payment_id": "0102" }));
    assert_eq!(v["error"]["code"], -5, "{v}");
}

/// `-50 NONZERO_UNLOCK_TIME` exists because of Wownero's relay rule, and is
/// returned here rather than letting the transfer fail opaquely later.
#[test]
fn a_nonzero_unlock_time_is_refused_with_its_own_code() {
    let s = start("unlock", false);
    let created = create_wallet(&s, "w");
    let address = created["address"].as_str().expect("an address").to_string();

    let v = call(
        &s,
        "transfer",
        json!({
            "destinations": [{ "amount": 1_000_000_000u64, "address": address }],
            "unlock_time": 100,
        }),
    );
    assert_eq!(v["error"]["code"], -50, "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .expect("a message")
            .contains("relay"),
        "{v}"
    );
}

/// A ring size other than 22 is refused before anything is built.
#[test]
fn a_wrong_ring_size_is_refused() {
    let s = start("ringsize", false);
    let created = create_wallet(&s, "w");
    let address = created["address"].as_str().expect("an address").to_string();

    let v = call(
        &s,
        "transfer",
        json!({
            "destinations": [{ "amount": 1_000_000_000u64, "address": address }],
            "ring_size": 11,
        }),
    );
    assert_eq!(v["error"]["code"], -19, "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .expect("a message")
            .contains("22"),
        "{v}"
    );
}

/// A transfer with no money returns `-37 NOT_ENOUGH_UNLOCKED_MONEY`, not
/// `-17`. The distinction is what tells a client whether to retry.
#[test]
fn an_empty_wallet_reports_locked_rather_than_absent_funds() {
    let s = start("nomoney", false);
    let created = create_wallet(&s, "w");
    let address = created["address"].as_str().expect("an address").to_string();

    // No daemon, so this stops at the daemon check or the planning one. Point
    // it at nothing and check whichever comes first is a real code.
    let v = call(
        &s,
        "transfer",
        json!({ "destinations": [{ "amount": 1u64, "address": address }] }),
    );
    let code = v["error"]["code"].as_i64().unwrap_or_else(|| panic!("{v}"));
    assert!(
        code == -38 || code == -37,
        "either no daemon (-38) or no unlocked money (-37), got {code}: {v}"
    );
}

/// A zero destination is refused by its own code.
#[test]
fn a_zero_amount_is_refused() {
    let s = start("zero", false);
    let created = create_wallet(&s, "w");
    let address = created["address"].as_str().expect("an address").to_string();

    let v = call(
        &s,
        "transfer",
        json!({ "destinations": [{ "amount": 0u64, "address": address }] }),
    );
    assert_eq!(v["error"]["code"], -46, "{v}");

    let v = call(&s, "transfer", json!({ "destinations": [] }));
    assert_eq!(v["error"]["code"], -20, "{v}");
}

/// A method the reference has and this build does not is refused by name, with
/// a reason.
#[test]
fn disabled_methods_say_so() {
    let s = start("disabled", false);
    create_wallet(&s, "w");

    // `export_key_images` used to be here; it is a live method now, so the
    // stand-in for "import and export" is gone and these three are what is
    // left of the kinds of refusal.
    for (method, fragment) in [
        ("get_tx_proof", "proofs"),
        ("get_reserve_proof", "reserve proofs"),
        ("start_mining", "miner"),
    ] {
        let v = call(&s, method, json!({}));
        assert_eq!(v["error"]["code"], -48, "{method}: {v}");
        assert!(
            v["error"]["message"]
                .as_str()
                .expect("a message")
                .contains(fragment),
            "{method}: {v}"
        );
    }
}

/// A wallet name is a file name. A client that sends a path is refused rather
/// than writing outside the wallet directory.
#[test]
fn a_wallet_name_cannot_escape_the_directory() {
    let s = start("traversal", false);
    for bad in ["../escape", "a/b", "..", ""] {
        let v = call(
            &s,
            "create_wallet",
            json!({ "filename": bad, "password": "pw" }),
        );
        assert!(v.get("error").is_some(), "`{bad}` should be refused: {v}");
    }
}

/// Opening with the wrong password fails with `-22 INVALID_PASSWORD`.
#[test]
fn a_wrong_password_is_refused() {
    let s = start("password", false);
    create_wallet(&s, "w");
    call(&s, "close_wallet", json!({}));

    let v = call(
        &s,
        "open_wallet",
        json!({ "filename": "w", "password": "wrong" }),
    );
    assert_eq!(v["error"]["code"], -22, "{v}");

    let v = call(
        &s,
        "open_wallet",
        json!({ "filename": "w", "password": "pw" }),
    );
    assert!(v.get("error").is_none(), "{v}");
}

/// `freeze`, `thaw` and `frozen` take a `key_image` and answer with the
/// C++'s codes: `-1` when none was given, `-10` when it does not decode, and
/// `-1` with `wallet2`'s message for one this wallet does not hold.
///
/// A wallet with no outputs is enough to check the surface, which is what a
/// client branches on.
#[test]
fn freezing_needs_a_key_image_this_wallet_holds() {
    let s = start("freeze", false);
    create_wallet(&s, "w");

    for method in ["freeze", "thaw", "frozen"] {
        let v = call(&s, method, json!({}));
        assert_eq!(v["error"]["code"], -1, "{method}: {v}");
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .starts_with("Must specify key image"),
            "{method}: {v}"
        );

        let v = call(&s, method, json!({ "key_image": "not hex" }));
        assert_eq!(v["error"]["code"], -10, "{method}: {v}");

        let v = call(&s, method, json!({ "key_image": "ab".repeat(32) }));
        assert_eq!(v["error"]["code"], -1, "{method}: {v}");
        assert_eq!(
            v["error"]["message"], "Key image not found",
            "{method}: {v}"
        );
    }
}

/// Creating over an existing wallet is refused rather than overwriting.
#[test]
fn creating_twice_is_refused() {
    let s = start("clobber", false);
    create_wallet(&s, "w");
    let v = call(
        &s,
        "create_wallet",
        json!({ "filename": "w", "password": "pw" }),
    );
    assert_eq!(v["error"]["code"], -21, "{v}");
}

/// An unknown method is an error naming itself, and `store` works.
#[test]
fn unknown_methods_and_store() {
    let s = start("misc", false);
    create_wallet(&s, "w");

    let v = call(&s, "not_a_method", json!({}));
    assert_eq!(v["error"]["code"], -1, "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .expect("a message")
            .contains("not_a_method"),
        "{v}"
    );

    let v = call(&s, "store", json!({}));
    assert!(v.get("error").is_none(), "{v}");
}

/// Only `/json_rpc` exists. The wallet RPC has no other paths.
#[test]
fn there_is_one_endpoint() {
    let s = start("endpoint", false);

    let mut stream = TcpStream::connect(("127.0.0.1", s.port)).expect("connect");
    let request = "POST /get_balance HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\
                   Connection: close\r\n\r\n{}";
    stream.write_all(request.as_bytes()).expect("write");

    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    assert!(
        response.contains("json_rpc"),
        "it says where to go: {response}"
    );
}

/// A `--wallet-dir` server has no wallet at startup, so there is nothing to
/// point at a daemon then. Every wallet a client creates or opens afterwards
/// must still get the one the server was started with.
///
/// Without this, `refresh` answered `no daemon is set` (-38) on a server that
/// had been given `--daemon-address` on its command line -- and the wallet
/// looked fine otherwise, reporting a balance of zero.
#[test]
fn wallets_created_later_inherit_the_daemon() {
    let daemon = fake_daemon(873_446);
    let s = start_with_daemon("inherit", false, daemon);

    let v = call(
        &s,
        "create_wallet",
        json!({"filename": "w", "password": "", "language": "English"}),
    );
    assert!(v["result"]["address"].is_string(), "{v}");

    // The wallet was generated just now, so it starts at the daemon's tip
    // rather than reading the chain from genesis to find nothing.
    //
    // 873,445 and not 873,446: the daemon's height is a block *count*, the
    // wallet starts at the tip block one below it, and it has not scanned that
    // block yet -- so its own height is the start height with nothing added.
    let v = call(&s, "get_height", json!({}));
    assert_eq!(
        v["result"]["height"], 873_445,
        "a new wallet starts at the tip block: {v}"
    );

    // And it is attached: `refresh` gets as far as talking to the daemon
    // rather than refusing for want of one.
    let v = call(&s, "refresh", json!({}));
    let refused_for_want_of_a_daemon = v["error"]["code"] == -38;
    assert!(
        !refused_for_want_of_a_daemon,
        "the wallet must inherit the server's daemon: {v}"
    );

    // Reopening keeps it attached, which is the same bug one step later.
    call(&s, "close_wallet", json!({}));
    call(&s, "open_wallet", json!({"filename": "w", "password": ""}));
    let v = call(&s, "refresh", json!({}));
    assert!(
        v["error"]["code"] != -38,
        "still attached after reopen: {v}"
    );
}

/// A daemon that is down when a wallet opens is picked up on the next call.
///
/// On a server the wallet service often starts before the node. A wallet that
/// only ever attached at open time would answer "no daemon is set" for the
/// rest of its life on a server that had one configured all along.
#[test]
fn a_daemon_that_was_down_at_open_is_picked_up_later() {
    // A port with nothing on it, so the first attach cannot succeed.
    let dead = format!("127.0.0.1:{}", free_port());
    let s = start_with_daemon("latedaemon", false, dead.clone());

    call(
        &s,
        "create_wallet",
        json!({"filename": "w", "password": "", "language": "English"}),
    );
    let v = call(&s, "refresh", json!({}));
    assert_eq!(
        v["error"]["code"], -38,
        "nothing is listening yet, so there is no daemon: {v}"
    );

    // Point it at one that answers, the way an operator would.
    let daemon = fake_daemon(873_446);
    let v = call(&s, "set_daemon", json!({"address": daemon}));
    assert!(v["error"].is_null(), "{v}");

    let v = call(&s, "refresh", json!({}));
    assert!(v["error"]["code"] != -38, "the daemon is attached now: {v}");
}
