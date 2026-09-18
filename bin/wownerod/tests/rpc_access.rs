//! Who may talk to the RPC server, against the real binary (`specs/11` §1.2,
//! §1.3, `specs/09` §3).
//!
//! HTTP Digest login, the restricted second listener, web origins, the config
//! file and the pid file -- each through a daemon started for the test, with
//! requests written byte for byte so what is checked is what a client sees.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use wow_storage::db::BlockchainDb;
use wow_storage::env::OpenMode;
use wow_storage::lmdb::LmdbDb;
use wow_types::{Block, Network};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p =
            std::env::temp_dir().join(format!("wownerod-access-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        // A genesis-only mainnet store to serve.
        let dir = wow_storage::env::db_dir(&p, Network::Mainnet, false);
        let db = LmdbDb::open_with_map_size(&dir, OpenMode::default(), 2, 32 << 20).unwrap();
        let blob = wow_consensus::genesis::genesis_blob(Network::Mainnet);
        let blk = Block::from_blob(&blob).unwrap();
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
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(data_dir: &Path, args: &[&str], ports: &[u16]) -> Daemon {
    let child = Command::new(env!("CARGO_BIN_EXE_wownerod"))
        .args([
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--serve",
            "--no-zmq",
        ])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start wownerod");
    let mut d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if ports
            .iter()
            .all(|p| TcpStream::connect(("127.0.0.1", *p)).is_ok())
        {
            return d;
        }
        if let Some(status) = d.0.try_wait().unwrap() {
            panic!("wownerod exited early: {status}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("wownerod did not start listening");
}

/// One request, returning the status code, the head and the body.
fn exchange(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\
         Connection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").expect("a response");
    let code = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .expect("a status code");
    (code, head.to_string(), body.to_string())
}

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// The value of `key` in a Digest challenge.
fn challenge_param(challenge: &str, key: &str) -> String {
    let at = challenge.find(&format!("{key}=\"")).expect(key) + key.len() + 2;
    challenge[at..].split('"').next().unwrap().to_string()
}

fn digest(user: &str, pass: &str, method: &str, uri: &str, challenge: &str, nc: &str) -> String {
    let realm = challenge_param(challenge, "realm");
    let nonce = challenge_param(challenge, "nonce");
    let md5 = |s: String| wow_crypto::md5::md5_hex(s.as_bytes());
    let ha1 = md5(format!("{user}:{realm}:{pass}"));
    let ha2 = md5(format!("{method}:{uri}"));
    let response = md5(format!("{ha1}:{nonce}:{nc}:deadbeef:auth:{ha2}"));
    format!(
        "Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", \
         algorithm=MD5, response=\"{response}\", qop=auth, nc={nc}, cnonce=\"deadbeef\""
    )
}

/// **`--rpc-login`.** Without credentials the answer is 401 and a Digest
/// challenge; answering it gets in; a wrong password and a replayed header do
/// not.
#[test]
fn a_login_is_required_and_digest_answers_it() {
    let s = Scratch::new("login");
    let port = free_port();
    let _d = start(
        &s.0,
        &[
            "--db-readonly",
            "--rpc-bind-port",
            &port.to_string(),
            "--rpc-login",
            "alice:hunter2",
        ],
        &[port],
    );

    let (code, head, _) = exchange(port, "POST", "/get_height", &[], "{}");
    assert_eq!(code, 401, "{head}");
    let challenge = header_value(&head, "WWW-Authenticate").expect("a challenge");
    assert!(challenge.starts_with("Digest "), "{challenge}");
    assert!(challenge.contains("qop=\"auth\""), "{challenge}");

    let auth = digest(
        "alice",
        "hunter2",
        "POST",
        "/get_height",
        &challenge,
        "00000001",
    );
    let (code, head, body) = exchange(
        port,
        "POST",
        "/get_height",
        &[("Authorization", &auth)],
        "{}",
    );
    assert_eq!(code, 200, "{head}\n{body}");
    assert!(body.contains("\"height\":1"), "{body}");

    let (code, _, _) = exchange(
        port,
        "POST",
        "/get_height",
        &[("Authorization", &auth)],
        "{}",
    );
    assert_eq!(code, 401, "the same header twice is a replay");

    let (_, head, _) = exchange(port, "POST", "/get_height", &[], "{}");
    let challenge = header_value(&head, "WWW-Authenticate").unwrap();
    let wrong = digest(
        "alice",
        "wrong",
        "POST",
        "/get_height",
        &challenge,
        "00000001",
    );
    let (code, _, _) = exchange(
        port,
        "POST",
        "/get_height",
        &[("Authorization", &wrong)],
        "{}",
    );
    assert_eq!(code, 401);
}

/// **`--rpc-restricted-bind-port`.** The second listener serves what a public
/// node may, and routes nothing marked **R**; the main one keeps everything.
#[test]
fn the_restricted_port_leaves_out_what_is_restricted() {
    let s = Scratch::new("restricted");
    let (main, restricted) = (free_port(), free_port());
    let _d = start(
        &s.0,
        &[
            "--db-readonly",
            "--rpc-bind-port",
            &main.to_string(),
            "--rpc-restricted-bind-port",
            &restricted.to_string(),
        ],
        &[main, restricted],
    );

    let (code, _, body) = exchange(restricted, "POST", "/get_height", &[], "{}");
    assert_eq!(code, 200);
    assert!(body.contains("\"height\":1"), "{body}");

    let (_, _, body) = exchange(restricted, "POST", "/get_net_stats", &[], "{}");
    assert!(body.contains("\"code\":-11"), "restricted: {body}");
    let (_, _, body) = exchange(main, "POST", "/get_net_stats", &[], "{}");
    assert!(body.contains("\"start_time\""), "unrestricted: {body}");

    let rpc = r#"{"jsonrpc":"2.0","id":"0","method":"get_bans","params":{}}"#;
    let (_, _, body) = exchange(restricted, "POST", "/json_rpc", &[], rpc);
    assert!(body.contains("-11"), "{body}");

    // `get_info` says what the C++'s restricted listener says: it is
    // restricted, whatever `--restricted-rpc` says, and it keeps the node's
    // counters and exact disk use to itself.
    let (_, _, body) = exchange(restricted, "POST", "/get_info", &[], "{}");
    let info: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(info["restricted"], true, "{info}");
    assert_eq!(info["start_time"], 0);
    assert_eq!(info["rpc_connections_count"], 0);
    assert_eq!(info["height_without_bootstrap"], 0);
    assert_eq!(info["free_space"], u64::MAX);
    assert_eq!(
        info["database_size"].as_u64().unwrap() % (5 << 30),
        0,
        "rounded to 5 GiB: {info}"
    );
    let (_, _, body) = exchange(main, "POST", "/get_info", &[], "{}");
    let info: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(info["restricted"], false, "{info}");
    assert_ne!(info["start_time"], 0);

    // And it caps what one call may ask, in `status` as the C++ answers.
    let hashes = vec![format!("\"{}\"", "00".repeat(32)); 101].join(",");
    let request = format!("{{\"txs_hashes\":[{hashes}]}}");
    let (_, _, body) = exchange(restricted, "POST", "/get_transactions", &[], &request);
    assert!(
        body.contains("Too many transactions requested in restricted mode"),
        "{body}"
    );
    let (_, _, body) = exchange(main, "POST", "/get_transactions", &[], &request);
    assert!(body.contains("\"missed_tx\""), "unrestricted: {body}");

    let images = vec![format!("\"{}\"", "00".repeat(32)); 5_001].join(",");
    let request = format!("{{\"key_images\":[{images}]}}");
    let (_, _, body) = exchange(restricted, "POST", "/is_key_image_spent", &[], &request);
    assert!(
        body.contains("Too many key images queried in restricted mode"),
        "{body}"
    );
}

/// **`--confirm-external-bind`.** A main RPC on a non-loopback address is
/// refused without it, as the C++ refuses it -- even restricted, even behind
/// a login -- and started with it.
#[test]
fn an_external_rpc_bind_needs_confirming() {
    let s = Scratch::new("external");
    let port = free_port();
    let out = Command::new(env!("CARGO_BIN_EXE_wownerod"))
        .args([
            "--data-dir",
            s.0.to_str().unwrap(),
            "--serve",
            "--no-zmq",
            "--db-readonly",
            "--non-interactive",
            "--rpc-bind-port",
            &port.to_string(),
            "--rpc-bind-ip",
            "0.0.0.0",
            "--restricted-rpc",
            "--rpc-login",
            "alice:hunter2",
        ])
        .output()
        .expect("run wownerod");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("--confirm-external-bind"), "{stderr}");

    let _d = start(
        &s.0,
        &[
            "--db-readonly",
            "--rpc-bind-port",
            &port.to_string(),
            "--rpc-bind-ip",
            "0.0.0.0",
            "--restricted-rpc",
            "--confirm-external-bind",
        ],
        &[port],
    );
    let (code, _, _) = exchange(port, "POST", "/get_height", &[], "{}");
    assert_eq!(code, 200);
}

/// **`--rpc-access-control-origins`.** A listed origin gets its preflight
/// answered and CORS headers on the real request; any other is refused.
#[test]
fn listed_web_origins_are_let_in_and_others_are_not() {
    let s = Scratch::new("origins");
    let port = free_port();
    let _d = start(
        &s.0,
        &[
            "--db-readonly",
            "--rpc-bind-port",
            &port.to_string(),
            "--rpc-login",
            "alice:hunter2",
            "--rpc-access-control-origins",
            "https://wallet.example",
        ],
        &[port],
    );

    let (code, head, _) = exchange(
        port,
        "OPTIONS",
        "/json_rpc",
        &[("Origin", "https://wallet.example")],
        "",
    );
    assert_eq!(code, 200, "{head}");
    assert_eq!(
        header_value(&head, "Access-Control-Allow-Origin").as_deref(),
        Some("https://wallet.example")
    );
    assert!(header_value(&head, "Access-Control-Allow-Headers")
        .unwrap()
        .contains("Authorization"));

    let (code, head, _) = exchange(
        port,
        "POST",
        "/get_height",
        &[("Origin", "https://wallet.example")],
        "{}",
    );
    assert_eq!(code, 401, "a listed origin still has to log in");
    assert!(header_value(&head, "Access-Control-Allow-Origin").is_some());

    let (code, head, _) = exchange(
        port,
        "POST",
        "/get_height",
        &[("Origin", "https://evil.example")],
        "{}",
    );
    assert_eq!(code, 403, "{head}");
}

/// **`wownero.conf`** in the data directory configures the daemon, and the
/// pid file is written while it runs and removed when it stops.
#[test]
fn the_config_file_and_the_pid_file_work() {
    let s = Scratch::new("conf");
    let port = free_port();
    let pid = s.0.join("wownerod.pid");
    std::fs::write(
        s.0.join("wownero.conf"),
        format!(
            "# written by the test\nrpc-bind-port={port}\ndb-readonly=1\npidfile={}\n",
            pid.display()
        ),
    )
    .unwrap();

    let mut d = start(&s.0, &[], &[port]);
    let (code, _, body) = exchange(port, "POST", "/get_height", &[], "{}");
    assert_eq!(code, 200, "the port came from the file: {body}");

    let written = std::fs::read_to_string(&pid).expect("the pid file");
    assert_eq!(written.trim(), d.0.id().to_string());

    let (_, _, body) = exchange(port, "POST", "/stop_daemon", &[], "{}");
    assert!(body.contains("OK"), "{body}");
    let deadline = Instant::now() + Duration::from_secs(20);
    while d.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the daemon did not stop");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!pid.exists(), "the pid file is removed on the way out");
}
