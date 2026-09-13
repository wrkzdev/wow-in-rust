//! Driving the real binary.
//!
//! `specs/13` §3 asks for `--command`, "which is how scripts drive the wallet".
//! These tests use it, so what is exercised is the binary a user runs — option
//! parsing, the keys file on disk, the cache, and the exit status — rather than
//! the library underneath it.
//!
//! No daemon is involved. Every test passes a daemon address nothing is
//! listening on, so the wallet reports it cannot connect and carries on
//! offline, which is itself worth checking: a wallet that cannot reach a node
//! should still open and show its address.

use std::path::PathBuf;
use std::process::{Command, Output};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let mut p = std::env::temp_dir();
        p.push(format!("wow-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch dir");
        Scratch(p)
    }

    fn wallet(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An address with nothing behind it, so the wallet stays offline.
const NO_DAEMON: &str = "127.0.0.1:1";

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wownero-wallet-cli"))
        .args(args)
        .output()
        .expect("run the wallet")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn all_output(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Create a wallet, then run a command against it.
fn create(scratch: &Scratch, name: &str, extra: &[&str]) -> Output {
    let path = scratch.wallet(name);
    let mut args = vec![
        "--generate-new-wallet",
        path.to_str().expect("utf-8 path"),
        "--password",
        "hunter2",
        "--daemon-address",
        NO_DAEMON,
    ];
    args.extend_from_slice(extra);
    cli(&args)
}

fn run_in(scratch: &Scratch, name: &str, command: &[&str]) -> Output {
    let path = scratch.wallet(name);
    let mut args = vec![
        "--wallet-file",
        path.to_str().expect("utf-8 path"),
        "--password",
        "hunter2",
        "--daemon-address",
        NO_DAEMON,
        "--command",
    ];
    args.extend_from_slice(command);
    cli(&args)
}

/// A new wallet writes its three files and prints a seed the user can write
/// down.
#[test]
fn creating_a_wallet_writes_its_files_and_a_seed() {
    let s = Scratch::new("create");
    let out = create(&s, "w", &["--command", "address"]);
    let text = stdout(&out);

    assert!(s.wallet("w.keys").exists(), "a keys file: {text}");
    assert!(s.wallet("w.rscache").exists(), "and a cache");
    assert!(s.wallet("w.address.txt").exists(), "and an address file");

    assert!(text.contains("Write this down"), "{text}");
    // A 25-word seed.
    let seed_line = text
        .lines()
        .find(|l| l.split_whitespace().count() == 25)
        .unwrap_or_else(|| panic!("no 25-word seed in:\n{text}"));
    assert_eq!(seed_line.split_whitespace().count(), 25);

    // The address file holds the same address the command printed.
    let written = std::fs::read_to_string(s.wallet("w.address.txt")).expect("address file");
    assert!(text.contains(written.trim()), "{text}");
    assert!(written.starts_with("Wo"), "a mainnet address: {written}");
}

/// The wallet reopens with the right password, and does not with the wrong
/// one.
#[test]
fn a_wallet_reopens_only_with_its_password() {
    let s = Scratch::new("password");
    create(&s, "w", &["--command", "address"]);

    let ok = run_in(&s, "w", &["address"]);
    assert!(ok.status.success(), "{}", all_output(&ok));
    assert!(stdout(&ok).contains("primary"));

    let path = s.wallet("w");
    let bad = cli(&[
        "--wallet-file",
        path.to_str().expect("utf-8"),
        "--password",
        "wrong",
        "--daemon-address",
        NO_DAEMON,
        "--command",
        "address",
    ]);
    assert!(!bad.status.success(), "a wrong password must fail");
    assert!(
        all_output(&bad).contains("cannot open"),
        "{}",
        all_output(&bad)
    );
}

/// A seed restores the same wallet: same address, same keys.
#[test]
fn a_seed_restores_the_same_wallet() {
    let s = Scratch::new("restore");
    let created = stdout(&create(&s, "original", &["--command", "address"]));

    let seed = created
        .lines()
        .find(|l| l.split_whitespace().count() == 25)
        .expect("a seed")
        .trim()
        .to_string();
    let original_address = std::fs::read_to_string(s.wallet("original.address.txt"))
        .expect("address file")
        .trim()
        .to_string();

    let restored = s.wallet("restored");
    let out = cli(&[
        "--generate-new-wallet",
        restored.to_str().expect("utf-8"),
        "--restore-deterministic-wallet",
        "--electrum-seed",
        &seed,
        "--password",
        "hunter2",
        "--daemon-address",
        NO_DAEMON,
        "--command",
        "address",
    ]);
    assert!(out.status.success(), "{}", all_output(&out));
    assert!(
        stdout(&out).contains(&original_address),
        "the restored wallet has the same address\n{}",
        stdout(&out)
    );
}

/// The keys the wallet reports are consistent with each other: the view key is
/// the hash of the spend key, which is what makes the wallet deterministic.
#[test]
fn the_keys_are_deterministic() {
    let s = Scratch::new("keys");
    create(&s, "w", &["--command", "address"]);

    let info = stdout(&run_in(&s, "w", &["wallet_info"]));
    assert!(info.contains("deterministic"), "{info}");
    assert!(!info.contains("non-deterministic"), "{info}");

    let view = stdout(&run_in(&s, "w", &["viewkey"]));
    let spend = stdout(&run_in(&s, "w", &["spendkey"]));
    let view = view.split_whitespace().last().expect("a key").to_string();
    let spend = spend.split_whitespace().last().expect("a key").to_string();

    let spend_bytes: [u8; 32] = wow_crypto::hex::decode(&spend)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let derived = wow_crypto::view_key_from_spend_key(&wow_crypto::types::SecretKey(spend_bytes));
    assert_eq!(wow_crypto::hex::encode(&derived.0), view);
}

/// Subaddresses are derivable and differ from the primary address.
#[test]
fn subaddresses_are_distinct() {
    let s = Scratch::new("subaddress");
    create(&s, "w", &["--command", "address"]);

    let primary = stdout(&run_in(&s, "w", &["address"]));
    let sub = stdout(&run_in(&s, "w", &["address", "0", "1"]));

    let primary_line = primary
        .lines()
        .find(|l| l.contains("primary"))
        .expect("one");
    let sub_line = sub.lines().find(|l| l.contains("(0, 1)")).expect("one");
    assert_ne!(primary_line, sub_line);
    // A subaddress has its own base58 prefix: `CRYPTONOTE_PUBLIC_SUBADDRESS_
    // BASE58_PREFIX` is 12,208 where a standard address is 4,146, so the two
    // are distinguishable at a glance (`specs/01`).
    assert!(primary_line.starts_with("Wo"), "{primary_line}");
    assert!(
        sub_line.starts_with("WW"),
        "a subaddress is not a standard address: {sub_line}"
    );
}

/// A fresh wallet has nothing in it, and says so plainly rather than printing
/// an empty table.
#[test]
fn a_fresh_wallet_is_empty() {
    let s = Scratch::new("empty");
    create(&s, "w", &["--command", "balance"]);

    let out = run_in(&s, "w", &["balance"]);
    assert!(stdout(&out).contains("0.00000000000"), "{}", stdout(&out));

    let out = run_in(&s, "w", &["incoming_transfers"]);
    assert!(stdout(&out).contains("(none)"), "{}", stdout(&out));

    let out = run_in(&s, "w", &["bc_height"]);
    // Just the height on stdout -- diagnostics go to stderr, which is what
    // makes `--command` usable from a script.
    //
    // One, not zero: the wallet holds the genesis hash from the moment it is
    // made, so its chain is one block long before it has scanned anything.
    // `wallet2::get_blockchain_current_height` returns `m_blockchain.size()`
    // and reports the same 1.
    assert_eq!(stdout(&out).trim(), "1", "{}", all_output(&out));
}

/// A command that fails exits non-zero, which is what lets a script tell.
#[test]
fn a_failing_command_exits_non_zero() {
    let s = Scratch::new("status");
    create(&s, "w", &["--command", "address"]);

    let ok = run_in(&s, "w", &["balance"]);
    assert!(ok.status.success());

    let bad = run_in(&s, "w", &["not_a_command"]);
    assert!(!bad.status.success(), "an unknown command fails");
    assert!(stdout(&bad).contains("unknown command"), "{}", stdout(&bad));

    // Sending with no daemon fails rather than pretending.
    let bad = run_in(&s, "w", &["transfer", "Wo1nonsense", "1.0"]);
    assert!(!bad.status.success());
}

/// A ring size other than 22 is refused before anything is built.
#[test]
fn a_wrong_ring_size_is_refused() {
    let s = Scratch::new("ringsize");
    create(&s, "w", &["--command", "address"]);

    let out = run_in(&s, "w", &["transfer", "11", "Wo1abc", "1.0"]);
    let text = stdout(&out);
    assert!(text.contains("exactly 22"), "{text}");
    assert!(!out.status.success());
}

/// Commands the spec names but this build does not implement are refused by
/// name, with a reason (`specs/13` §2).
#[test]
fn unimplemented_commands_say_so() {
    let s = Scratch::new("unimplemented");
    create(&s, "w", &["--command", "address"]);

    for (command, fragment) in [
        ("get_tx_key", "proofs"),
        ("export_key_images", "import/export"),
        ("setup_background_sync", "background sync"),
        ("start_mining", "miner"),
    ] {
        let out = run_in(&s, "w", &[command]);
        let text = stdout(&out);
        assert!(
            text.contains("not available in this build") && text.contains(fragment),
            "`{command}` should explain itself, got:\n{text}"
        );
        // Refusing a known-but-unbuilt command is not a failure.
        assert!(out.status.success(), "`{command}` should exit zero");
    }
}

/// A wallet with no daemon still opens, and says what it could not do.
#[test]
fn an_unreachable_daemon_does_not_stop_the_wallet() {
    let s = Scratch::new("offline");
    let out = create(&s, "w", &["--command", "address"]);
    let text = all_output(&out);

    assert!(out.status.success(), "{text}");
    assert!(text.contains("cannot reach"), "it says so: {text}");
    assert!(text.contains("carrying on offline"), "{text}");
    assert!(text.contains("primary"), "and still prints the address");
}

/// Settings persist to the keys file and survive a reopen.
#[test]
fn a_setting_persists() {
    let s = Scratch::new("set");
    create(&s, "w", &["--command", "address"]);

    let out = run_in(&s, "w", &["set", "refresh-from-block-height", "12345"]);
    assert!(out.status.success(), "{}", all_output(&out));

    let out = run_in(&s, "w", &["restore_height"]);
    assert_eq!(
        stdout(&out).trim(),
        "12345",
        "the setting was written: {}",
        all_output(&out)
    );
}

/// Creating over an existing wallet is refused rather than overwriting it.
#[test]
fn creating_over_an_existing_wallet_is_refused() {
    let s = Scratch::new("clobber");
    create(&s, "w", &["--command", "address"]);
    let before = std::fs::read(s.wallet("w.keys")).expect("keys");

    let out = create(&s, "w", &["--command", "address"]);
    assert!(!out.status.success(), "must not overwrite");
    assert!(
        all_output(&out).contains("refusing to overwrite"),
        "{}",
        all_output(&out)
    );

    let after = std::fs::read(s.wallet("w.keys")).expect("keys");
    assert_eq!(before, after, "the wallet was left alone");
}

/// A view-only wallet opens, shows its address, and refuses to spend.
#[test]
fn a_view_only_wallet_cannot_spend() {
    let s = Scratch::new("viewonly");
    create(&s, "full", &["--command", "address"]);

    let address = std::fs::read_to_string(s.wallet("full.address.txt"))
        .expect("address")
        .trim()
        .to_string();
    let view = stdout(&run_in(&s, "full", &["viewkey"]));
    let view = view.split_whitespace().last().expect("a key").to_string();

    let watch = s.wallet("watch");
    let out = cli(&[
        "--generate-new-wallet",
        watch.to_str().expect("utf-8"),
        "--restore-from-keys",
        "--address",
        &address,
        "--viewkey",
        &view,
        "--password",
        "hunter2",
        "--daemon-address",
        NO_DAEMON,
        "--command",
        "wallet_info",
    ]);
    assert!(out.status.success(), "{}", all_output(&out));
    assert!(stdout(&out).contains("view-only"), "{}", stdout(&out));

    // It has no spend key and no seed.
    let path = s.wallet("watch");
    let no_spend = cli(&[
        "--wallet-file",
        path.to_str().expect("utf-8"),
        "--password",
        "hunter2",
        "--daemon-address",
        NO_DAEMON,
        "--command",
        "spendkey",
    ]);
    assert!(
        stdout(&no_spend).contains("no spend key"),
        "{}",
        stdout(&no_spend)
    );

    let no_seed = cli(&[
        "--wallet-file",
        path.to_str().expect("utf-8"),
        "--password",
        "hunter2",
        "--daemon-address",
        NO_DAEMON,
        "--command",
        "seed",
    ]);
    assert!(stdout(&no_seed).contains("no seed"), "{}", stdout(&no_seed));
}

/// `--help` explains itself and exits zero.
#[test]
fn help_exits_zero() {
    let out = cli(&["--help"]);
    assert!(out.status.success());
    let text = all_output(&out);
    assert!(text.contains("--generate-new-wallet"), "{text}");
    assert!(text.contains("--command"), "{text}");
}

/// A testnet wallet cannot be opened as mainnet. The addresses would be
/// re-encoded under the wrong prefix and look like someone else's.
#[test]
fn a_wallet_knows_its_own_network() {
    let s = Scratch::new("network");
    let path = s.wallet("t");
    let out = cli(&[
        "--generate-new-wallet",
        path.to_str().expect("utf-8"),
        "--testnet",
        "--password",
        "hunter2",
        "--daemon-address",
        NO_DAEMON,
        "--command",
        "address",
    ]);
    assert!(out.status.success(), "{}", all_output(&out));

    let wrong = cli(&[
        "--wallet-file",
        path.to_str().expect("utf-8"),
        "--password",
        "hunter2",
        "--daemon-address",
        NO_DAEMON,
        "--command",
        "address",
    ]);
    assert!(!wrong.status.success(), "mainnet must not open it");
    assert!(
        all_output(&wrong).contains("testnet"),
        "{}",
        all_output(&wrong)
    );
}
