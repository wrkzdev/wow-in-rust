//! The RPC server on IPv6, against the real binary (`specs/09` §3.2).
//!
//! `--rpc-use-ipv6` adds an IPv6 listener on the RPC port beside the IPv4
//! one, and `--rpc-ignore-ipv4` lets the server start on IPv6 alone when the
//! IPv4 side cannot bind -- the C++'s `init_server` rules. Skipped on a host
//! without an IPv6 loopback.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use wow_storage::db::BlockchainDb;
use wow_storage::env::OpenMode;
use wow_storage::lmdb::LmdbDb;
use wow_types::{Block, Network};

struct Scratch(PathBuf);

impl Scratch {
    /// A genesis-only mainnet store.
    fn new(tag: &str) -> Scratch {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p =
            std::env::temp_dir().join(format!("wownerod-ipv6-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        let dir = wow_storage::env::db_dir(&p, Network::Mainnet, false);
        let db = LmdbDb::open_with_map_size(&dir, OpenMode::default(), 2, 32 << 20).unwrap();
        let blob = wow_consensus::genesis::genesis_blob(Network::Mainnet);
        let blk = Block::from_blob(&blob).unwrap();
        db.add_block(&blk, &blob, blob.len() as u64, blob.len() as u64, 1, 0, &[])
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

fn ipv6_loopback() -> bool {
    std::net::TcpListener::bind("[::1]:0").is_ok()
}

fn args(data_dir: &Path, port: u16, extra: &[&str]) -> Vec<String> {
    let mut a: Vec<String> = [
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--serve",
        "--no-zmq",
        "--db-readonly",
        "--non-interactive",
        "--rpc-bind-port",
        &port.to_string(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.extend(extra.iter().map(|s| s.to_string()));
    a
}

fn spawn(args: &[String]) -> Daemon {
    Daemon(
        Command::new(env!("CARGO_BIN_EXE_wownerod"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start wownerod"),
    )
}

fn wait_listening(d: &mut Daemon, addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        if let Some(status) = d.0.try_wait().unwrap() {
            panic!("wownerod exited early: {status}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("wownerod did not start listening on {addr}");
}

/// `/get_height` at `addr`, as the response body.
fn get_height(addr: SocketAddr) -> String {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(b"POST /get_height HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")
        .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    raw.split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn v4(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn v6(port: u16) -> SocketAddr {
    SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))
}

/// `--rpc-use-ipv6`: the same answers on `[::1]` and `127.0.0.1`, on one port.
#[test]
fn the_rpc_answers_on_ipv6_and_ipv4_at_once() {
    if !ipv6_loopback() {
        eprintln!("skipped: no IPv6 loopback on this host");
        return;
    }
    let s = Scratch::new("both");
    let port = free_port();
    let mut d = spawn(&args(&s.0, port, &["--rpc-use-ipv6"]));
    wait_listening(&mut d, v4(port));
    wait_listening(&mut d, v6(port));

    assert!(get_height(v4(port)).contains("\"height\":1"));
    assert!(get_height(v6(port)).contains("\"height\":1"));
}

/// Without `--rpc-use-ipv6` there is no IPv6 listener.
#[test]
fn ipv6_is_off_unless_asked_for() {
    if !ipv6_loopback() {
        eprintln!("skipped: no IPv6 loopback on this host");
        return;
    }
    let s = Scratch::new("off");
    let port = free_port();
    let mut d = spawn(&args(&s.0, port, &[]));
    wait_listening(&mut d, v4(port));
    assert!(TcpStream::connect(v6(port)).is_err());
}

/// The IPv4 port is taken: the server refuses to start, unless
/// `--rpc-ignore-ipv4` lets it run on IPv6 alone.
#[test]
fn ignore_ipv4_lets_the_rpc_start_on_ipv6_alone() {
    if !ipv6_loopback() {
        eprintln!("skipped: no IPv6 loopback on this host");
        return;
    }
    let s = Scratch::new("v6only");
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();

    let out = Command::new(env!("CARGO_BIN_EXE_wownerod"))
        .args(args(&s.0, port, &["--rpc-use-ipv6"]))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("cannot listen"), "{stderr}");

    let mut d = spawn(&args(&s.0, port, &["--rpc-use-ipv6", "--rpc-ignore-ipv4"]));
    wait_listening(&mut d, v6(port));
    assert!(get_height(v6(port)).contains("\"height\":1"));
    drop(taken);
}
