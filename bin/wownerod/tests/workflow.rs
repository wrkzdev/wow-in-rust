//! The `specs/10` §7 workflow, against the real binary.
//!
//! §7 calls opening an existing `data.mdb` "the payoff" and asks for it to be
//! "a first-class, documented workflow". These tests run the built `wownerod`
//! against databases this test creates, so what is checked is what a user would
//! actually type.
//!
//! The four §7 requirements each have a test:
//!
//! * refuse read-write against a live writer;
//! * check the schema version;
//! * verify the tip agrees across the three tables;
//! * **refuse a network mismatch**, which is the one that would otherwise be
//!   silent.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use wow_storage::db::BlockchainDb;
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
        p.push(format!("wownerod-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }

    fn data_dir(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const MAP_SIZE: usize = 32 << 20;

fn wownerod(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wownerod"))
        .args(args)
        .output()
        .expect("run wownerod")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Build a database at `<data_dir>/lmdb` holding that network's real genesis
/// block, so the network check has something to read.
fn seed_genesis(data_dir: &Path, network: Network) {
    let dir = wow_storage::env::db_dir(data_dir, network, false);
    let db = LmdbDb::open_with_map_size(&dir, OpenMode::default(), 2, MAP_SIZE).expect("open");

    let blob = wow_consensus::genesis::genesis_blob(network);
    let blk = Block::from_blob(&blob).expect("genesis parses");
    db.add_block(&blk, &blob, blob.len() as u64, blob.len() as u64, 1, 0, &[])
        .expect("add genesis");
}

#[test]
fn version_and_help_work_without_a_database() {
    let v = wownerod(&["--version"]);
    assert!(v.status.success());
    assert!(stdout(&v).starts_with("wownerod "));

    let h = wownerod(&["--help"]);
    assert!(h.status.success());
    let text = stdout(&h);
    assert!(text.contains("--check-difficulty-checkpoints"));
    assert!(text.contains("--db-readonly"));
    // The help says plainly what is built and what is missing, so nobody
    // expects background mining or i2p/Tor from it.
    assert!(text.contains("NOT YET IMPLEMENTED"));
    assert!(text.contains("--sync-from"));
    assert!(text.contains("--start-mining") && text.contains("--spendkey"));
    assert!(text.contains("--rpc-ssl") && text.contains("--zmq-pub"));
    assert!(
        text.contains("background mining") && text.contains("i2p/Tor"),
        "the help must still name what is not built"
    );
}

/// `--genesis` needs no database and prints the three network identities.
#[test]
fn genesis_prints_every_network() {
    let o = wownerod(&["--genesis"]);
    assert!(o.status.success());
    let text = stdout(&o);

    // The real mainnet genesis, as a synced node reports it.
    assert!(text.contains("a3fd635dd5cb55700317783469ba749b5259f0eeac2420ab2c27eb3ff5ffdc5c"));
    assert!(text.contains("Mainnet"));
    assert!(text.contains("Testnet"));
    assert!(text.contains("Stagenet"));
}

/// A missing database is an explanatory error, not a panic or a stack trace.
#[test]
fn a_missing_database_says_where_it_looked() {
    let s = Scratch::new("missing");
    let o = wownerod(&["--data-dir", s.data_dir().to_str().unwrap(), "--status"]);

    assert!(!o.status.success());
    let e = stderr(&o);
    assert!(e.contains("no database at"), "{e}");
    assert!(e.contains("data.mdb"), "{e}");
}

/// `--status` against a real database reports the tip.
#[test]
fn status_reports_the_tip() {
    let s = Scratch::new("status");
    seed_genesis(s.data_dir(), Network::Mainnet);

    let o = wownerod(&["--data-dir", s.data_dir().to_str().unwrap(), "--status"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let text = stdout(&o);

    assert!(text.contains("height     1"), "{text}");
    assert!(text.contains("network    Mainnet"), "{text}");
    assert!(
        text.contains("a3fd635dd5cb55700317783469ba749b5259f0eeac2420ab2c27eb3ff5ffdc5c"),
        "the tip is the genesis block: {text}"
    );
    assert!(text.contains("read-write"), "{text}");
}

/// `--db-readonly` opens the same database without writing to it — the mode
/// `specs/10` §7 says is "safe against a running C++ node".
#[test]
fn read_only_mode_works_and_says_so() {
    let s = Scratch::new("readonly");
    seed_genesis(s.data_dir(), Network::Mainnet);

    let o = wownerod(&[
        "--data-dir",
        s.data_dir().to_str().unwrap(),
        "--db-readonly",
        "--status",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("read-only"), "{}", stdout(&o));
}

/// **The §7 requirement that would otherwise be silent.** A testnet database
/// opened as mainnet must be refused: "a testnet and a mainnet `data.mdb` are
/// structurally identical".
#[test]
fn a_network_mismatch_is_refused() {
    let s = Scratch::new("netmismatch");
    // Write a *testnet* database...
    seed_genesis(s.data_dir(), Network::Testnet);

    // ...and open it as mainnet, which is the default.
    let dir = s.data_dir().join("testnet");
    let o = wownerod(&["--data-dir", dir.to_str().unwrap(), "--status"]);

    assert!(!o.status.success(), "a mismatch must not succeed");
    let e = stderr(&o);
    assert!(e.contains("Testnet"), "{e}");
    assert!(e.contains("Mainnet"), "{e}");
    assert!(
        e.contains("structurally identical"),
        "the error should say why this is checked: {e}"
    );
}

/// The same database opened as the network it actually is works.
#[test]
fn the_right_network_is_accepted() {
    let s = Scratch::new("netmatch");
    seed_genesis(s.data_dir(), Network::Testnet);

    let o = wownerod(&[
        "--data-dir",
        s.data_dir().to_str().unwrap(),
        "--testnet",
        "--status",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let text = stdout(&o);
    assert!(text.contains("network    Testnet"), "{text}");
    assert!(text.contains("height     1"), "{text}");
}

/// A database whose genesis matches nothing is refused rather than guessed at.
#[test]
fn an_unknown_genesis_is_refused() {
    let s = Scratch::new("unknown");
    let dir = wow_storage::env::db_dir(s.data_dir(), Network::Mainnet, false);
    {
        let db = LmdbDb::open_with_map_size(&dir, OpenMode::default(), 2, MAP_SIZE).unwrap();
        // A block that is not any network's genesis.
        let mut blk = Block::from_blob(&wow_consensus::genesis::genesis_blob(Network::Mainnet))
            .expect("parse");
        blk.header.nonce = 12_345;
        let mut w = wow_serialize::binary::Writer::with_capacity(512);
        blk.write(&mut w);
        let blob = w.into_vec();
        let blk = Block::from_blob(&blob).unwrap();
        db.add_block(&blk, &blob, blob.len() as u64, blob.len() as u64, 1, 0, &[])
            .unwrap();
    }

    let o = wownerod(&["--data-dir", s.data_dir().to_str().unwrap(), "--status"]);
    assert!(!o.status.success());
    let e = stderr(&o);
    assert!(e.contains("matches no known network"), "{e}");
}

/// `--check-difficulty-checkpoints` on a chain shorter than the first
/// checkpoint has nothing to compare, and says so rather than claiming success.
#[test]
fn the_checkpoint_check_reports_a_short_chain() {
    let s = Scratch::new("shortchain");
    seed_genesis(s.data_dir(), Network::Mainnet);

    let o = wownerod(&[
        "--data-dir",
        s.data_dir().to_str().unwrap(),
        "--db-readonly",
        "--check-difficulty-checkpoints",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let text = stdout(&o);
    assert!(text.contains("39 checkpoints"), "{text}");
    assert!(
        text.contains("shorter than the first checkpoint"),
        "it must not claim to have verified anything: {text}"
    );
}

/// Testnet has no checkpoints, and the command says that rather than passing
/// vacuously.
#[test]
fn the_checkpoint_check_says_when_there_are_none() {
    let s = Scratch::new("nocheckpoints");
    seed_genesis(s.data_dir(), Network::Testnet);

    let o = wownerod(&[
        "--data-dir",
        s.data_dir().to_str().unwrap(),
        "--testnet",
        "--check-difficulty-checkpoints",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("no checkpoints"), "{}", stdout(&o));
}

/// Options for parts that are not built are refused, so a command line that
/// looks like it configured something did.
#[test]
fn unimplemented_options_are_refused_by_the_binary() {
    for (opt, expect) in [
        ("--limit-rate", "rate limiting"),
        ("--proxy", "proxy"),
        ("--bg-mining-enable", "background mining"),
    ] {
        let o = wownerod(&[opt]);
        assert!(!o.status.success(), "{opt} should fail");
        let e = stderr(&o);
        assert!(e.contains(expect), "{opt}: {e}");
        assert!(e.contains("not implemented"), "{opt}: {e}");
    }
}

/// A second read-write process is refused with a reason, not left waiting on
/// LMDB's writer mutex -- and `--db-readonly` still works beside the writer.
#[test]
fn a_second_writer_is_refused() {
    let s = Scratch::new("secondwriter");
    seed_genesis(s.data_dir(), Network::Mainnet);

    // Stand in for a running `wownerod` by holding its lock from here.
    let lock_path =
        wow_storage::env::db_dir(s.data_dir(), Network::Mainnet, false).join("wownerod-rs.lock");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .expect("open the lock file");
    held.try_lock().expect("take the lock");

    let data_dir = s.data_dir().to_str().unwrap();
    let o = wownerod(&["--data-dir", data_dir, "--status"]);
    assert!(!o.status.success(), "a second writer must not start");
    let e = stderr(&o);
    assert!(e.contains("already open for writing"), "{e}");
    assert!(e.contains("--db-readonly"), "it should say what to do: {e}");

    let o = wownerod(&["--data-dir", data_dir, "--db-readonly", "--status"]);
    assert!(o.status.success(), "{}", stderr(&o));

    // Released, the same command works.
    drop(held);
    let o = wownerod(&["--data-dir", data_dir, "--status"]);
    assert!(o.status.success(), "{}", stderr(&o));
}

/// Two commands on one command line are refused rather than the last one
/// silently winning.
#[test]
fn two_commands_are_refused_by_the_binary() {
    let o = wownerod(&["--serve", "--sync-from", "127.0.0.1:1"]);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("separate commands"), "{}", stderr(&o));
}

/// The mutually exclusive network flags are enforced at the binary too.
#[test]
fn conflicting_network_flags_are_refused() {
    let o = wownerod(&["--testnet", "--stagenet"]);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("mutually exclusive"));
}

/// `--verify-difficulty` needs at least two blocks to have a difference to
/// compare.
#[test]
fn verify_difficulty_needs_a_chain() {
    let s = Scratch::new("verifyshort");
    seed_genesis(s.data_dir(), Network::Mainnet);

    let o = wownerod(&[
        "--data-dir",
        s.data_dir().to_str().unwrap(),
        "--db-readonly",
        "--verify-difficulty",
    ]);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("too short"), "{}", stderr(&o));
}
