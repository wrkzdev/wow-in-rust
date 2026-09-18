//! The commands (`specs/13` §2).
//!
//! The M4 minimum set from `specs/13` §4. A command in the spec that is not
//! built says so by name rather than being absent — a wallet that answers
//! "unknown command" to `export_outputs` tells a user nothing about whether it
//! will ever work.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use wow_daemon_client::KeyImageStatus;
use wow_types::address::Address;
use wow_wallet::decoys;
use wow_wallet::history::{EntryKind, PROPAGATION_TIMEOUT};
use wow_wallet::priority::{self, PrioritySettings};
use wow_wallet::send::SendRequest;
use wow_wallet::spend;
use wow_wallet::{AskPassword, PoolCheck, RefreshEvent};

use crate::fmt;
use crate::progress::Progress;
use crate::session::{balance_line, now, Session};
use crate::term;

/// What running a command produced.
pub enum Outcome {
    Continue,
    Quit,
}

/// Commands named in `specs/13` §2 that this build does not implement.
///
/// Listed so they can be refused by name. `specs/13` §2 is explicit that every
/// handler "MUST be present (or explicitly reject as unsupported)".
const NOT_IMPLEMENTED: &[(&str, &str)] = &[
    ("get_tx_key", "transaction proofs are not built yet"),
    ("get_tx_proof", "transaction proofs are not built yet"),
    ("check_tx_proof", "transaction proofs are not built yet"),
    ("get_reserve_proof", "reserve proofs are not built yet"),
    ("check_reserve_proof", "reserve proofs are not built yet"),
    ("sign", "message signing is not built yet"),
    ("verify", "message signing is not built yet"),
    ("start_mining", "this wallet does not drive a miner"),
    ("stop_mining", "this wallet does not drive a miner"),
    (
        "mark_output_spent",
        "this wallet keeps no shared database of spent outputs",
    ),
    (
        "mark_output_unspent",
        "this wallet keeps no shared database of spent outputs",
    ),
    (
        "is_output_spent",
        "this wallet keeps no shared database of spent outputs",
    ),
    (
        "sweep_unmixable",
        "there are no unmixable outputs on this chain",
    ),
    ("address_book", "the address book is not built yet"),
    ("account", "multiple accounts are not built yet"),
    ("donate", "the donation address is not wired up"),
    ("show_qr_code", "QR rendering is not built yet"),
    (
        "setup_background_sync",
        "background sync is not supported by this build",
    ),
    (
        "start_background_sync",
        "background sync is not supported by this build",
    ),
    (
        "stop_background_sync",
        "background sync is not supported by this build",
    ),
];

/// `m_last_activity_time`: when a command last ran, in seconds since 1970.
///
/// Zero until the first one, so a wallet that has just opened is never taken
/// to have been left alone.
static LAST_ACTIVITY: AtomicU64 = AtomicU64::new(0);

/// `m_locked`: set by `lock`, and by the wallet having been left alone for
/// `inactivity-lock-timeout`. Cleared when its password is typed again.
static LOCKED: AtomicBool = AtomicBool::new(false);

/// Run one command line, printing any error.
///
/// Returns whether to carry on, and whether the command failed — `--command`
/// exits non-zero on a failure, which is what lets a script tell.
///
/// `simple_wallet::on_command` wraps every command this way: it notes the
/// time either side, and locks the wallet first if it has been sitting
/// untouched.
pub fn run(session: &mut Session, line: &str) -> (Outcome, bool) {
    if left_alone(session) {
        LOCKED.store(true, Ordering::Relaxed);
    }
    touch();
    if let Err(e) = check_for_inactivity_lock(session, false) {
        // Nobody is there to type the password, so there is nothing to carry
        // on with: the wallet stays locked and this stops.
        println!("Error: {e}");
        return (Outcome::Quit, true);
    }

    let outcome = match run_one(session, line) {
        Ok(outcome) => (outcome, false),
        Err(e) => {
            println!("Error: {e}");
            (Outcome::Continue, true)
        }
    };
    touch();
    outcome
}

/// Note that something happened just now, so the inactivity lock counts from
/// here: `m_last_activity_time = time(NULL)`.
fn touch() {
    LAST_ACTIVITY.store(now(), Ordering::Relaxed);
}

/// `simple_wallet::check_inactivity`: whether the wallet has been sitting
/// untouched for longer than `inactivity-lock-timeout`. Zero turns it off.
///
/// The C++ asks this on an idle thread, so its wallet locks while nobody is
/// looking. There is no idle thread here, so it is asked when the next
/// command arrives — the first moment at which the lock can make a
/// difference.
fn left_alone(session: &Session) -> bool {
    let timeout = session.keys_file.inactivity_lock_timeout();
    let last = LAST_ACTIVITY.load(Ordering::Relaxed);
    timeout != 0 && last != 0 && now().saturating_sub(last) >= timeout
}

/// `simple_wallet::check_for_inactivity_lock`: while the wallet is locked,
/// nothing runs until its password is typed again.
///
/// `user` is true when `lock` asked for it; the C++ only scolds when the
/// wallet locked itself. The screen is cleared either way, because what is on
/// it is the wallet's — its balance, its addresses, whatever `seed` printed.
///
/// The C++ loops here forever. This gives up at end of input instead: a
/// script that cannot answer would otherwise spin rather than stop.
fn check_for_inactivity_lock(session: &Session, user: bool) -> Result<(), String> {
    if !LOCKED.load(Ordering::Relaxed) {
        return Ok(());
    }
    term::clear_screen();
    if !user {
        println!("tis, tis.. you left the wallet unattended. you will be punished.");
    }
    println!("The wallet password is required to unlock the console.");
    loop {
        let password = term::read_password("Wallet password: ")
            .ok_or("no password given; the wallet stays locked")?;
        if session.verify_password(&password) {
            break;
        }
        println!("invalid password");
    }
    LOCKED.store(false, Ordering::Relaxed);
    touch();
    Ok(())
}

/// `SCOPED_WALLET_UNLOCK`: ask for the wallet's password before a command
/// that shows a secret key or spends.
///
/// The C++ is
/// `if (m_wallet->ask_password() && !(pwd_container = get_and_verify_password()))`,
/// so `ask-password` 0 asks nothing and 1 and 2 both ask. Level 2 also keeps
/// the secret keys encrypted in memory between commands, which this build
/// does not do, so the two behave alike here.
fn unlock(session: &Session) -> Result<(), String> {
    if session.keys_file.ask_password() == AskPassword::Never {
        return Ok(());
    }
    let password = term::read_password("Wallet password: ").ok_or("no password given")?;
    if !session.verify_password(&password) {
        // `get_and_verify_password`'s wording.
        return Err("invalid password".into());
    }
    Ok(())
}

/// Run one command line, returning the error instead of printing it.
pub fn run_one(session: &mut Session, line: &str) -> Result<Outcome, String> {
    let mut parts = line.split_whitespace();
    let Some(name) = parts.next() else {
        return Ok(Outcome::Continue);
    };
    let args: Vec<&str> = parts.collect();
    // The name only: an argument can be a password, a seed or a key.
    wow_log::debug!("wallet.simplewallet", "command `{name}`");

    if let Some((_, why)) = NOT_IMPLEMENTED.iter().find(|(n, _)| *n == name) {
        println!("`{name}` is not available in this build: {why}.");
        return Ok(Outcome::Continue);
    }

    let result = match name {
        "help" => {
            print_help();
            Ok(())
        }
        "version" => {
            println!("wownero-wallet-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "exit" | "quit" | "q" => return Ok(Outcome::Quit),

        "address" => address(session, &args),
        "integrated_address" => integrated_address(session, &args),
        "balance" => balance(session),
        "bc_height" => bc_height(session),
        "status" => status(session),
        "seed" => seed(session, &args),
        "viewkey" => viewkey(session),
        "spendkey" => spendkey(session),
        "wallet_info" => wallet_info(session),
        "save" => save(session),
        "set_daemon" => set_daemon(session, &args),
        "refresh" => refresh(session),
        "rescan_bc" | "rescan_blockchain" => rescan(session),
        "restore_height" => {
            println!("{}", session.keys_file.refresh_height());
            Ok(())
        }
        "incoming_transfers" => incoming_transfers(session, &args),
        "show_transfers" => show_transfers(session, &args),
        "payments" => payments(session, &args),
        "unspent_outputs" => unspent_outputs(session),
        "freeze" => freeze_thaw(session, &args, true),
        "thaw" => freeze_thaw(session, &args, false),
        "frozen" => frozen(session, &args),
        "fee" => fee(session),
        "transfer" => transfer_cmd(session, &args),
        "sweep_all" => sweep_all(session, &args),
        "sweep_single" => sweep_single(session, &args),
        "export_outputs" => export_outputs(session, &args),
        "import_outputs" => import_outputs(session, &args),
        "export_key_images" => export_key_images(session, &args),
        "import_key_images" => import_key_images(session, &args),
        "sign_transfer" => sign_transfer(session, &args),
        "submit_transfer" => submit_transfer(session),

        "print_ring" => print_ring(session, &args),
        "set_ring" => set_ring(session, &args),
        "unset_ring" => unset_ring(session, &args),
        "save_known_rings" => Err("save_known_rings is deprecated".into()),
        "set" => set(session, &args),
        "lock" => lock(session),

        other => Err(format!("unknown command `{other}`. Try `help`.")),
    };

    result.map(|()| Outcome::Continue)
}

fn print_help() {
    println!(
        "\
Wallet
  address [<major> [<minor>]]   show an address
  integrated_address [<id>]     make an integrated address
  balance                       balance and unlocked balance
  seed [<language>]             the 25-word seed
  viewkey / spendkey            the secret keys
  wallet_info                   what kind of wallet this is
  save                          write the keys file and cache

Chain
  set_daemon <address> [trusted|untrusted] [<user>:<pass>]
                                point at a daemon: host:port, or https://host:port.
                                One on this machine is trusted unless told not.
                                A login is needed for one started with --rpc-login
  refresh                       scan up to the daemon's tip
  rescan_bc                     forget what was scanned and start over
  bc_height / status            where the wallet and the daemon are
  restore_height                where this wallet started scanning

History
  incoming_transfers [available|unavailable]
  show_transfers [in|out|pending|failed|coinbase|all] [<min_height> [<max_height>]]
  payments <payment_id> [<payment_id> ...]
  unspent_outputs

Frozen outputs
  freeze <key_image>            set one output aside, so nothing spends it
  thaw <key_image>              let it be spent again
  frozen [<key_image>]          whether that output is set aside, or, given
                                none, every output that is

Sending
  fee                           the current fee estimate
  transfer <address> <amount> [<payment_id>]
  sweep_all <address>           send everything
  sweep_single <key_image> <address>
                                send one output, by the key image
                                unspent_outputs prints

Cold signing (the spend key on a machine with no network)
  export_outputs [all] <filename>
                                on the watch-only half: its outputs, for the
                                half that can compute their key images
  import_outputs <filename>     on the cold half
  export_key_images [all] <filename>
                                on the cold half: the key images, signed
  import_key_images <filename>  on the watch-only half; needs a trusted daemon
  sign_transfer [export_raw] [<filename>]
                                on the cold half: sign an unsigned transfer
                                set, default `unsigned_wownero_tx`, and write
                                `signed_wownero_tx`
  submit_transfer               on the watch-only half: relay
                                `signed_wownero_tx`
                                A watch-only wallet's `transfer` writes
                                `unsigned_wownero_tx` instead of sending

Rings
  print_ring <key_image> | <txid>
                                the ring(s) a key image or a sent transaction
                                was spent with
  set_ring <filename> | ( <key_image> absolute|relative <index> [<index>...] )
                                keep a ring for a key image, to spend it with
                                again on another chain
  unset_ring <txid> | ( <key_image> [<key_image>...] )
                                forget the ring(s)

Settings
  set <option> <value>          persisted to the keys file
  lock                          hold the console until the password is typed
                                again. It is held by itself after
                                inactivity-lock-timeout seconds, 300 by default
  help / version / exit"
    );
}

// -- wallet ----------------------------------------------------------------

fn address(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let major: u32 = parse_index(args.first(), 0)?;
    let minor: u32 = parse_index(args.get(1), 0)?;
    let a = session
        .address_at(major, minor)
        .ok_or("that subaddress could not be derived")?;
    if major == 0 && minor == 0 {
        println!("{a}  (primary)");
    } else {
        println!("{a}  ({major}, {minor})");
    }
    Ok(())
}

fn integrated_address(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let pid: [u8; 8] = match args.first() {
        Some(hex) => wow_crypto::hex::decode(hex)
            .ok_or("the payment id is not hex")?
            .try_into()
            .map_err(|_| "a payment id is 8 bytes (16 hex characters)".to_string())?,
        None => {
            let mut rng = term::seeded_rng()?;
            let mut b = [0u8; 8];
            rng.fill(&mut b);
            b
        }
    };
    let a = Address::integrated(
        session.network,
        session.keys_file.account.keys.account_address,
        pid,
    );
    println!("{}", a.encode());
    println!("payment id: {}", wow_crypto::hex::encode(&pid));
    Ok(())
}

fn balance(session: &mut Session) -> Result<(), String> {
    let (balance, unlocked) = session.balances();
    println!("{}", balance_line(balance, unlocked));
    // `simplewallet`'s own note: a wallet that cannot compute key images
    // cannot tell a spent output from an unspent one, so its balance is
    // whatever it has ever received until the exchange below has happened.
    if session.state.transfers.iter().any(|t| t.key_image.is_none()) {
        println!(
            " (Some owned outputs have missing key images - export_outputs, import_outputs, \
             export_key_images, and import_key_images needed)"
        );
    }
    println!("{}", session.describe_progress());
    if session.state.scan_height() < session.chain_height() {
        println!("(not fully synced; run `refresh`)");
    }
    Ok(())
}

fn bc_height(session: &mut Session) -> Result<(), String> {
    println!("{}", session.state.scan_height());
    Ok(())
}

fn status(session: &mut Session) -> Result<(), String> {
    println!("{}", session.describe_progress());
    match &session.daemon {
        Some(d) => println!("daemon: {}", d.address()),
        None if session.offline => println!("daemon: none, and none will be used (--offline)"),
        None => println!("daemon: none set (`set_daemon <host:port>`)"),
    }
    println!("network: {}", session.network.name());
    if session.is_view_only() {
        println!(
            "this is a view-only wallet: it can watch, and it can write an unsigned transfer \
             for a wallet that holds the spend key (`transfer`, then `sign_transfer` there)"
        );
    }
    Ok(())
}

fn seed(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let language = args
        .first()
        .copied()
        .or_else(|| session.keys_file.seed_language())
        .unwrap_or("English")
        .to_string();
    // `print_seed` finds out that a wallet is view-only before it asks for
    // anything, and finds out that it has no seed only after. Keeping that
    // order means a view-only wallet is not asked for a password to be told
    // it has nothing to show.
    if session.is_view_only() {
        return Err("a view-only wallet has no seed".into());
    }
    unlock(session)?;
    println!("{}", session.seed(&language)?);
    Ok(())
}

fn viewkey(session: &mut Session) -> Result<(), String> {
    unlock(session)?;
    println!(
        "secret view key: {}",
        wow_crypto::hex::encode(&session.keys_file.account.keys.view_secret_key.0)
    );
    Ok(())
}

fn spendkey(session: &mut Session) -> Result<(), String> {
    if session.is_view_only() {
        return Err("a view-only wallet has no spend key".into());
    }
    unlock(session)?;
    println!(
        "secret spend key: {}",
        wow_crypto::hex::encode(&session.keys_file.account.keys.spend_secret_key.0)
    );
    Ok(())
}

fn wallet_info(session: &mut Session) -> Result<(), String> {
    println!("file: {}", session.location());
    println!("network: {}", session.network.name());
    println!("address: {}", session.primary_address());
    let keys = &session.keys_file.account.keys;
    println!(
        "kind: {}",
        if keys.is_view_only() {
            "view-only"
        } else if keys.is_deterministic() {
            "deterministic (has a seed phrase)"
        } else {
            "non-deterministic (restored from keys; no seed phrase)"
        }
    );
    let (major, minor) = session.keys_file.subaddress_lookahead();
    println!("subaddress lookahead: {major} accounts x {minor} addresses");
    println!("restore height: {}", session.keys_file.refresh_height());
    Ok(())
}

fn save(session: &mut Session) -> Result<(), String> {
    session.save()?;
    session.dirty = false;
    println!("Saved.");
    Ok(())
}

// -- chain -----------------------------------------------------------------

fn set_daemon(session: &mut Session, args: &[&str]) -> Result<(), String> {
    if session.offline {
        // `simplewallet`'s own wording when a connection is asked for and
        // `--offline` was given.
        return Err(
            "wallet failed to connect to daemon, because it is set to offline mode".into(),
        );
    }
    let address = args
        .first()
        .ok_or("usage: set_daemon <host:port> [trusted|untrusted] [<user>:<password>]")?;
    // `simple_wallet::set_daemon`'s trust word, and this build's login. A login
    // given here replaces whatever --daemon-login set; one left out keeps it,
    // so pointing at a second node on the same box does not mean typing the
    // password again.
    let mut trusted = None;
    for arg in &args[1..] {
        match *arg {
            "trusted" => trusted = Some(true),
            "untrusted" | "this-is-probably-a-spy-node" => trusted = Some(false),
            text => {
                let c = wow_daemon_client::digest::Credentials::parse(text).ok_or(
                    "expected trusted, untrusted or this-is-probably-a-spy-node, or a daemon login \
                     as <user>:<password>",
                )?;
                session.daemon_login = Some(c);
            }
        }
    }
    let client = session.client_for(address);
    let info = client
        .get_info()
        .map_err(|e| format!("cannot reach {address}: {e}"))?;

    // A wallet pointed at the wrong network would scan a chain its keys mean
    // nothing on, and report a balance of zero forever.
    let expected = session.network.name();
    if !info.nettype.is_empty() && info.nettype != expected {
        return Err(format!(
            "that daemon is on {}, but this is a {expected} wallet",
            info.nettype
        ));
    }

    // Not told: trusted when it is on this machine, as `make_basic` and
    // `set_daemon` both decide.
    let trusted = trusted.unwrap_or_else(|| {
        let local = wow_daemon_client::is_local_address(address);
        if local {
            wow_log::info!("wallet.simplewallet", "Daemon is local, assuming trusted");
        }
        local
    });
    eprintln!(
        "Connected to {address}: height {}, {}, {}, {}",
        info.height,
        if info.synchronized {
            "synced"
        } else {
            "still syncing"
        },
        if trusted { "trusted" } else { "untrusted" },
        describe_security(client.security())
    );
    session.daemon_height = info.height;
    session.daemon = Some(client);
    session.state.trusted_daemon = trusted;
    Ok(())
}

/// How the node was reached, said where it is seen: a fallback to plain HTTP
/// is also logged, but the log is not the terminal.
fn describe_security(security: Option<wow_daemon_client::Security>) -> &'static str {
    use wow_daemon_client::Security;
    match security {
        Some(Security::Tls { verified: true }) => "over TLS",
        Some(Security::Tls { verified: false }) => {
            "over TLS, though the node's certificate does not check out, so nothing says who \
             is at the other end"
        }
        Some(Security::Plain { fell_back: false }) | None => "over plain HTTP",
        Some(Security::Plain { fell_back: true }) => {
            "over plain HTTP, because the node did not answer TLS: what this wallet asks it can \
             be read on the way (--daemon-ssl enabled refuses that)"
        }
    }
}

fn refresh(session: &mut Session) -> Result<(), String> {
    // `wallet2::refresh` returns straight away when `m_offline` is set, rather
    // than failing: there is nothing to scan and nothing went wrong.
    if session.offline {
        println!("This wallet is offline (--offline); there is nothing to refresh.");
        return Ok(());
    }
    let client = session
        .daemon
        .clone()
        .ok_or("no daemon set; use `set_daemon <host:port>`")?;

    let start = session.state.scan_height();
    let started = Instant::now();
    let mut progress = Progress::new();
    let (mut received, mut received_amount) = (0usize, 0u64);
    let (mut spent, mut spent_amount) = (0usize, 0u64);

    loop {
        let s = session
            .state
            .refresh_once(&client)
            .map_err(|e| e.to_string())?;
        received += s.received;
        spent += s.spent;
        // The daemon's height as it grows, so a long refresh aims at the tip
        // it will reach rather than the one there was when it started.
        if s.current_height > 0 {
            session.daemon_height = s.current_height;
        }

        if let Some(h) = s.reorg_to {
            progress.clear();
            println!("Reorganisation: the chain changed below height {h}; rescanned from there.");
        }
        for e in &s.events {
            match *e {
                RefreshEvent::Received { amount, burnt, .. } => received_amount += amount - burnt,
                RefreshEvent::Spent { amount, .. } => spent_amount += amount,
            }
            progress.clear();
            println!("{}", describe_event(e));
        }
        if s.blocks_scanned > 0 {
            // From where scanning starts: the hashes begin lower, where every
            // wallet's do.
            progress.update(
                session.state.refresh_from_height,
                session.state.scan_height(),
                session.chain_height(),
            );
        }
        if s.caught_up {
            break;
        }
    }
    progress.clear();

    if let Ok(info) = client.get_info() {
        session.daemon_height = info.height;
    }
    session.dirty = true;
    println!("  {}", session.describe_progress());

    // Caught up, so a sent transaction missing from both the chain and the
    // pool really is missing.
    match session.check_pending() {
        Ok(check) => report_pool(session, &check),
        Err(e) => eprintln!("{e}"),
    }

    let scanned = session.state.scan_height().saturating_sub(start);
    let elapsed = started.elapsed();
    if elapsed.as_secs() > 0 && scanned > 0 {
        println!(
            "Scanned {scanned} block(s) in {} ({:.0} blocks/s).",
            fmt::duration(elapsed.as_secs()),
            scanned as f64 / elapsed.as_secs_f64()
        );
    } else {
        println!("Scanned {scanned} block(s).");
    }
    if received > 0 {
        println!(
            "Received {received} new output(s), {} in all.",
            fmt::amount(received_amount)
        );
    }
    if spent > 0 {
        println!(
            "{spent} of this wallet's outputs were spent, {} in all.",
            fmt::amount(spent_amount)
        );
    }
    let (balance, unlocked) = session.balances();
    println!("{}", balance_line(balance, unlocked));
    Ok(())
}

/// A payment found or a spend of this wallet's, as
/// `simple_wallet::on_money_received` and `on_money_spent` print them.
fn describe_event(e: &RefreshEvent) -> String {
    match *e {
        RefreshEvent::Received {
            height,
            txid,
            amount,
            burnt,
            subaddress,
        } => {
            let burn = if burnt > 0 {
                format!(
                    " ({} yet {} was burnt)",
                    fmt::amount(amount),
                    fmt::amount(burnt)
                )
            } else {
                String::new()
            };
            format!(
                "Height {height}, txid {}, {}{burn}, idx {}/{}",
                wow_crypto::hex::encode(&txid),
                fmt::amount(amount - burnt),
                subaddress.major,
                subaddress.minor
            )
        }
        RefreshEvent::Spent {
            height,
            txid,
            amount,
            subaddress,
        } => format!(
            "Height {height}, txid {}, spent {}, idx {}/{}",
            wow_crypto::hex::encode(&txid),
            fmt::amount(amount),
            subaddress.major,
            subaddress.minor
        ),
    }
}

/// What the daemon's pool showed about this wallet's money.
fn report_pool(session: &Session, check: &PoolCheck) {
    for txid in &check.noted {
        let Some(s) = session.state.sent.iter().find(|s| s.txid == *txid) else {
            continue;
        };
        println!(
            "Transaction {} in the daemon's pool spends {} of this wallet's outputs, {} in all. \
             It was not sent from this wallet file; those outputs count as spent while it waits \
             for a block.",
            wow_crypto::hex::encode(txid),
            s.key_images.len(),
            fmt::amount(s.amount_in)
        );
    }
    for txid in &check.failed {
        println!(
            "Transaction {} is in neither a block nor the daemon's pool {PROPAGATION_TIMEOUT} \
             seconds after this wallet sent it or first saw it. Marked failed; its inputs can be \
             spent again.",
            wow_crypto::hex::encode(txid)
        );
    }
}

fn rescan(session: &mut Session) -> Result<(), String> {
    if !term::confirm("Forget everything scanned and start again from the restore height?") {
        println!("Left alone.");
        return Ok(());
    }
    let from = session.keys_file.refresh_height();
    session.state.rescan_from(from);
    session.dirty = true;
    println!("Cleared. Run `refresh` to scan from height {from}.");
    Ok(())
}

// -- history ---------------------------------------------------------------

fn incoming_transfers(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let height = session.chain_height();
    let now = now();
    let filter = args.first().copied().unwrap_or("all");

    let mut shown = 0usize;
    println!(
        "{:<12} {:>20}  {:<8} {:<66}",
        "height", "amount", "state", "key image"
    );
    for t in session.transfers() {
        let unlocked = t.unlocked(height, now);
        // `show_incoming_transfers` prints `[frozen]` where it would otherwise
        // print unlocked or locked: an output set aside is not available
        // however old it is.
        let state = if t.spent {
            "spent"
        } else if t.frozen {
            "frozen"
        } else if unlocked {
            "available"
        } else {
            "locked"
        };
        let keep = match filter {
            "available" => !t.spent && unlocked,
            "unavailable" => !t.spent && !unlocked,
            _ => true,
        };
        if !keep {
            continue;
        }
        shown += 1;
        println!(
            "{:<12} {:>20}  {:<8} {}",
            t.block_height,
            fmt::amount(t.amount),
            state,
            t.key_image
                .map(|k| wow_crypto::hex::encode(&k.0))
                .unwrap_or_else(|| "(view-only)".into())
        );
    }
    if shown == 0 {
        println!("(none)");
    }
    Ok(())
}

fn show_transfers(session: &mut Session, args: &[&str]) -> Result<(), String> {
    use EntryKind::*;
    const ALL: &[EntryKind] = &[In, Coinbase, Out, Pending, Failed];

    // `simple_wallet::get_transfers`: a word to narrow what is shown, then a
    // height range.
    let (kinds, rest): (&[EntryKind], &[&str]) = match args.first().copied() {
        Some("in" | "incoming") => (&[In, Coinbase], &args[1..]),
        Some("out" | "outgoing") => (&[Out, Pending, Failed], &args[1..]),
        Some("pending") => (&[Pending], &args[1..]),
        Some("failed") => (&[Failed], &args[1..]),
        Some("coinbase") => (&[Coinbase], &args[1..]),
        Some("pool") => {
            println!("(this build does not track incoming transactions in the pool)");
            return Ok(());
        }
        Some("all" | "both") => (ALL, &args[1..]),
        _ => (ALL, args),
    };
    let height_arg = |i: usize, default: u64| match rest.get(i) {
        Some(s) => s.parse().map_err(|_| format!("`{s}` is not a height")),
        None => Ok(default),
    };
    let (min, max) = (height_arg(0, 0)?, height_arg(1, u64::MAX)?);

    let chain_height = session.chain_height();
    let now = now();
    let mut shown = 0usize;
    for e in session.state.history() {
        if !kinds.contains(&e.kind) {
            continue;
        }
        // Above the lower height and up to the upper, as the C++ has it.
        if let Some(h) = e.height {
            if (min > 0 && h <= min) || h > max {
                continue;
            }
        }
        shown += 1;

        let received = matches!(e.kind, In | Coinbase);
        let block = match e.height {
            Some(h) => format!("{h:08}"),
            None => e.kind.name().to_string(),
        };
        let direction = match e.kind {
            In => "in",
            Coinbase => "block",
            _ => "out",
        };
        let unlocked = if !received {
            "-"
        } else if e.unlocked(chain_height, now) {
            "unlocked"
        } else {
            "locked"
        };
        let destinations = if received {
            // The subaddress it came in on, cut short as the C++ cuts it.
            let minor = e.minors.first().copied().unwrap_or(0);
            let address = session.address_at(e.account, minor).unwrap_or_default();
            format!(
                "{}:{}",
                &address[..address.len().min(6)],
                fmt::amount(e.amount)
            )
        } else if e.destinations.is_empty() {
            "-".to_string()
        } else {
            e.destinations
                .iter()
                .map(|d| format!("{}:{}", d.address, fmt::amount(d.amount)))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let indices = e
            .minors
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let payment_id = e
            .payment_id
            .map_or_else(|| "0".repeat(16), |p| wow_crypto::hex::encode(&p));
        println!(
            "{block:>8} {direction:>6} {unlocked:>8} {:>25.25} {:>20.20} {} {payment_id} {:>14.14} \
             {destinations} {indices} -",
            fmt::timestamp(e.timestamp),
            fmt::amount(e.amount),
            wow_crypto::hex::encode(&e.txid),
            fmt::amount(e.fee),
        );
    }
    if shown == 0 {
        println!("(none)");
    }
    Ok(())
}

/// `simple_wallet::show_payments`: the payments received with each id given.
fn payments(session: &mut Session, args: &[&str]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: payments <payment_id> [<payment_id> ...]".into());
    }
    let received = session.state.payments(0);
    println!(
        "{:<16}  {:<64}  {:>8}  {:>20}  {:>11}  {:>10}",
        "payment", "transaction", "height", "amount", "unlock time", "addr index"
    );
    for arg in args {
        let Some(key) = wow_wallet::history::parse_payment_key(arg) else {
            println!("`{arg}` is not a payment id: 16 or 64 hex characters");
            continue;
        };
        let mut found = false;
        for e in received
            .iter()
            .filter(|e| wow_wallet::history::payment_key(e.payment_id) == key)
        {
            found = true;
            println!(
                "{:<16}  {}  {:>8}  {:>20}  {:>11}  {:>10}",
                arg,
                wow_crypto::hex::encode(&e.txid),
                e.height.unwrap_or(0),
                fmt::amount(e.amount),
                e.unlock_time,
                e.minors.first().copied().unwrap_or(0),
            );
        }
        if !found {
            println!("No payments with id {arg}");
        }
    }
    Ok(())
}

fn unspent_outputs(session: &mut Session) -> Result<(), String> {
    let height = session.chain_height();
    let now = now();
    let mut total = 0u64;
    for t in session.transfers().iter().filter(|t| !t.spent) {
        total += t.amount;
        println!(
            "{:>20}  height {:<10} index {:<10} {}",
            fmt::amount(t.amount),
            t.block_height,
            t.global_output_index,
            if t.unlocked(height, now) {
                "unlocked"
            } else {
                "locked"
            }
        );
    }
    println!("{} unspent", fmt::amount(total));
    Ok(())
}

// -- frozen outputs --------------------------------------------------------

/// `simple_wallet::freeze_thaw`: set one output aside by its key image, or let
/// it be spent again.
///
/// The defence against a dust attack. A stranger pays a wallet a tiny output
/// and watches for it to be spent alongside real ones, which says the two
/// belong to one wallet; freezing it means nothing will pick it. The key image
/// is what `incoming_transfers` prints in its last column.
///
/// The C++ takes a key image and nothing else. Its usage line also mentions a
/// public key and `wallet2` has a `freeze(size_t)` that takes an index, but
/// `freeze_thaw` only ever runs `hex_to_pod` into a `key_image`, so neither
/// form reaches the prompt there, and neither is accepted here.
fn freeze_thaw(session: &mut Session, args: &[&str], freeze: bool) -> Result<(), String> {
    let what = if freeze { "freeze" } else { "thaw" };
    let Some(text) = args.first() else {
        return Err(format!("usage: {what} <key_image>|<pubkey>"));
    };
    let key_image = key_image_arg(text)?;
    if freeze {
        session.state.freeze(&key_image)?;
    } else {
        session.state.thaw(&key_image)?;
    }
    // `wallet2::freeze` sets the flag and nothing else: the C++ writes it out
    // at the next `save`, or when the wallet closes. So does this, as
    // `set_ring` does with a ring.
    session.dirty = true;
    Ok(())
}

/// `simple_wallet::frozen`: whether one output is set aside, or, given
/// nothing, every output that is, with what it holds.
fn frozen(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let Some(text) = args.first() else {
        for t in session.transfers().iter().filter(|t| t.frozen) {
            let key_image = t
                .key_image
                .map(|k| wow_crypto::hex::encode(&k.0))
                .unwrap_or_else(|| "(view-only)".into());
            println!("Frozen: {key_image} {}", fmt::amount(t.amount));
        }
        return Ok(());
    };
    // The key image as it was parsed, not as it was typed: the C++ prints the
    // `crypto::key_image` it decoded, which is always lower case.
    let key_image = key_image_arg(text)?;
    let hex = wow_crypto::hex::encode(&key_image.0);
    if session.state.frozen(&key_image)? {
        println!("Frozen: {hex}");
    } else {
        println!("Not frozen: {hex}");
    }
    Ok(())
}

/// A key image as `freeze`, `thaw` and `frozen` take one: 64 hex characters,
/// and the C++'s message for anything `epee::string_tools::hex_to_pod`
/// refuses.
fn key_image_arg(text: &str) -> Result<wow_crypto::types::KeyImage, String> {
    parse_hash(text)
        .map(wow_crypto::types::KeyImage)
        .ok_or_else(|| "failed to parse key image".to_string())
}

// -- sending ---------------------------------------------------------------

fn fee(session: &mut Session) -> Result<(), String> {
    let client = session
        .daemon
        .as_ref()
        .ok_or("no daemon set; use `set_daemon <host:port>`")?;
    let tiers = client
        .get_fee_estimate(priority::FEE_ESTIMATE_GRACE_BLOCKS)
        .map_err(|e| format!("cannot get a fee estimate: {e}"))?;

    println!("Fee per byte, by priority:");
    for (i, t) in tiers.iter().enumerate() {
        println!("  {}: {}", tier_name(i as u32 + 1), fmt::amount(*t));
    }

    // What a transfer given no priority pays now, for an ordinary one.
    let settings = PrioritySettings::from_keys_file(&session.keys_file);
    let chosen = priority::adjust_priority(
        client,
        settings.default_priority,
        settings,
        session.state.scan_height(),
        &tiers,
    );
    let weight =
        spend::estimate_tx_weight(1, decoys::RING_SIZE, 2, spend::extra_size(2, false, false));
    println!(
        "A transfer given no priority pays the {} rate now. A one-input, two-output transaction \
         weighs about {weight} bytes, so it would cost {}.",
        tier_name(chosen),
        fmt::amount(spend::fee_from_weight(
            priority::fee_per_byte(&tiers, chosen),
            weight
        ))
    );
    Ok(())
}

/// The name of the tier a priority pays. A 0 left unadjusted pays the lowest.
fn tier_name(p: u32) -> &'static str {
    priority::PRIORITY_NAMES[p.clamp(1, 4) as usize]
}

fn transfer_cmd(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let mut rest: Vec<&str> = args.to_vec();
    let priority = take_priority(&mut rest, session.keys_file.default_priority());
    let ring_size = take_ring_size(&mut rest)?;

    let address = rest
        .first()
        .ok_or("usage: transfer [<priority>] [<ring_size>] <address> <amount> [<payment_id>]")?;
    let amount_text = rest.get(1).ok_or("an amount is required")?;
    let amount = fmt::parse_amount(amount_text)?;
    let payment_id = rest.get(2).copied();

    send(
        session,
        &[(address.to_string(), amount)],
        priority,
        ring_size,
        payment_id,
        false,
        None,
    )
}

fn sweep_all(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let mut rest: Vec<&str> = args.to_vec();
    // `simple_wallet::sweep_main` starts from 0, not the default priority.
    let priority = take_priority(&mut rest, 0);
    let ring_size = take_ring_size(&mut rest)?;
    let address = rest
        .first()
        .ok_or("usage: sweep_all [<priority>] [<ring_size>] <address> [<payment_id>]")?;
    let payment_id = rest.get(1).copied();

    send(
        session,
        &[(address.to_string(), 0)],
        priority,
        ring_size,
        payment_id,
        true,
        None,
    )
}

/// `sweep_single [<priority>] [<ring_size>] <key_image> <address> [<payment_id>]`
///
/// Sends exactly one output, named by its key image, which is what
/// `unspent_outputs` prints in its last column. Somebody doing this is usually
/// separating that output from the rest of the wallet on purpose.
fn sweep_single(session: &mut Session, args: &[&str]) -> Result<(), String> {
    const USAGE: &str =
        "usage: sweep_single [<priority>] [<ring_size>] <key_image> <address> [<payment_id>]";
    let mut rest: Vec<&str> = args.to_vec();
    // As `sweep_all` does, and for the same reason: `simple_wallet::sweep_main`
    // starts from 0 rather than the wallet's default priority.
    let priority = take_priority(&mut rest, 0);
    let ring_size = take_ring_size(&mut rest)?;

    let image_text = rest.first().ok_or(USAGE)?;
    let bytes = wow_crypto::hex::decode(image_text)
        .ok_or("a key image is 64 hex characters; `unspent_outputs` prints them")?;
    let image: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "a key image is 64 hex characters".to_string())?;
    let address = rest.get(1).ok_or(USAGE)?;
    let payment_id = rest.get(2).copied();

    send(
        session,
        &[(address.to_string(), 0)],
        priority,
        ring_size,
        payment_id,
        true,
        Some(wow_crypto::types::KeyImage(image)),
    )
}

/// Build, confirm and relay.
fn send(
    session: &mut Session,
    destinations: &[(String, u64)],
    priority: u32,
    ring_size: usize,
    payment_id: Option<&str>,
    sweep: bool,
    sweep_output: Option<wow_crypto::types::KeyImage>,
) -> Result<(), String> {
    if session.daemon.is_none() {
        return Err("no daemon set; use `set_daemon <host:port>`".into());
    }
    // Where `transfer_main` unlocks: after the daemon check and the arguments,
    // before anything is built. Spending is what a password is for, and being
    // asked for it after a failed connection would be asking for nothing.
    unlock(session)?;

    let (address_text, amount) = &destinations[0];
    let explicit_pid: Option<[u8; 8]> = match payment_id {
        Some(hex) => Some(
            wow_crypto::hex::decode(hex)
                .ok_or("the payment id is not hex")?
                .try_into()
                .map_err(|_| "a payment id is 8 bytes (16 hex characters)".to_string())?,
        ),
        None => None,
    };

    let request = SendRequest {
        address: address_text,
        amount: (!sweep).then_some(*amount),
        priority,
        ring_size,
        payment_id: explicit_pid,
        sweep_output,
        // This build has one account in the CLI, and spends from every
        // subaddress in it, or sweeps one at random, as `transfer` and
        // `sweep_all` do without `index=`.
        account: 0,
        subaddr_indices: Vec::new(),
        below_amount: 0,
    };

    // A watch-only wallet writes the transaction out instead of sending it,
    // for the half that holds the spend key to sign: `simplewallet::transfer`
    // does `if (m_wallet->watch_only()) { save_tx(ptx_vector,
    // "unsigned_wownero_tx"); }` and never calls `commit_tx`.
    if session.is_view_only() {
        return write_unsigned(session, &request, address_text, ring_size);
    }

    let prepared = session.prepare_send(&request).map_err(|e| e.to_string())?;

    // Spends of this wallet's outputs that preparing found in the pool.
    if let Some(e) = &prepared.pool_unread {
        eprintln!("{e}");
    }
    report_pool(
        session,
        &PoolCheck {
            noted: prepared.noted_in_pool.clone(),
            failed: Vec::new(),
        },
    );

    let plan = &prepared.plan;
    let txid = prepared.txid;
    println!();
    println!("Sending  {}", fmt::amount(plan.amounts[0]));
    println!("     to  {address_text}");
    println!(
        "    fee  {} ({})",
        fmt::amount(plan.fee),
        tier_name(prepared.priority)
    );
    if plan.change > 0 {
        println!(" change  {}", fmt::amount(plan.change));
    }
    println!(
        " inputs  {}, ring size {ring_size}, {} bytes",
        plan.inputs.len(),
        plan.estimated_weight
    );
    if plan.left_behind > 0 {
        println!();
        println!(
            "This does NOT sweep everything: {} more output(s) would make the \
             transaction too heavy for a node to relay, so the largest {} are being \
             swept and the rest are left. Run sweep_all again afterwards to take them.",
            plan.left_behind,
            plan.inputs.len()
        );
    }
    if let Some(p) = prepared.payment_id {
        println!("payment id  {}", wow_crypto::hex::encode(&p));
    }
    if !term::confirm("Send?") {
        println!("Cancelled.");
        return Ok(());
    }

    let relayed = session.commit_send(&prepared).map_err(|e| e.to_string())?;
    let result = relayed.result;

    if result.accepted() {
        // Saved at once: a wallet that forgot this send would offer the same
        // inputs to the next one, and the daemon would refuse it.
        match session.save() {
            Ok(()) => session.dirty = false,
            Err(e) => eprintln!("Sent, but the wallet could not be saved: {e}"),
        }
        println!("Sent. Transaction {}", wow_crypto::hex::encode(&txid));
        println!(
            "(the change is in the balance now, and can be spent once the transaction is mined \
             and four blocks have passed)"
        );
        if plan.left_behind > 0 {
            println!(
                "{} output(s) were left behind; run sweep_all again to take them.",
                plan.left_behind
            );
        }
    } else {
        println!("The daemon rejected the transaction.");
        if !result.reason.is_empty() {
            println!("  reason: {}", result.reason);
        }
        for (flag, what) in [
            (result.double_spend, "an input was already spent"),
            (result.invalid_input, "an input was not accepted"),
            (result.invalid_output, "an output was not accepted"),
            (result.low_mixin, "the ring size is wrong"),
            (result.too_big, "the transaction is too large"),
            (result.overspend, "the amounts do not balance"),
            (result.fee_too_low, "the fee is too low"),
        ] {
            if flag {
                println!("  {what}");
            }
        }
        println!("  status: {}", result.status);
        if result.double_spend {
            explain_double_spend(session, &relayed.noted_in_pool, plan);
        }
    }
    Ok(())
}

/// After a refusal as a double spend: say which input was spent, and where.
/// Spends found in the pool are already held back by the time this runs.
fn explain_double_spend(
    session: &Session,
    noted: &[wow_crypto::types::Hash256],
    plan: &spend::SpendPlan,
) {
    report_pool(
        session,
        &PoolCheck {
            noted: noted.to_vec(),
            failed: Vec::new(),
        },
    );
    let Some(client) = session.daemon.clone() else {
        return;
    };
    // Asking which of these key images are spent tells the daemon they are
    // this wallet's: `rescan_spent` and `import_key_images` refuse to ask an
    // untrusted one.
    if !session.state.trusted_daemon {
        println!(
            "  This wallet does not ask an untrusted daemon which input was spent: the question \
             would tell it which outputs are this wallet's. `rescan_bc` finds a spend in a block; \
             a daemon you run can be asked, with --trusted-daemon."
        );
        return;
    }

    let inputs: Vec<(usize, [u8; 32])> = plan
        .inputs
        .iter()
        .filter_map(|&i| Some((i, session.state.transfers[i].key_image?.0)))
        .collect();
    let images: Vec<[u8; 32]> = inputs.iter().map(|(_, k)| *k).collect();
    let status = match client.is_key_image_spent(&images) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  cannot ask the daemon which input was spent: {e}");
            return;
        }
    };
    for ((i, image), status) in inputs.iter().zip(status) {
        let t = &session.state.transfers[*i];
        let what = format!(
            "  the {} output with key image {}",
            fmt::amount(t.amount),
            wow_crypto::hex::encode(image)
        );
        match status {
            KeyImageStatus::SpentInPool if t.spent => println!(
                "{what} is being spent by a transaction in the daemon's pool. It counts as spent \
                 now; send again to use other outputs."
            ),
            KeyImageStatus::SpentInPool => println!(
                "{what} is being spent by a transaction in the daemon's pool, which the daemon \
                 does not list, so this wallet cannot hold the output back."
            ),
            KeyImageStatus::SpentInChain => println!(
                "{what} was spent in a block, and this wallet's scan did not see it go. \
                 `rescan_bc` scans again."
            ),
            KeyImageStatus::Unspent => {}
        }
    }
}

// -- cold signing ----------------------------------------------------------

/// The file a watch-only `transfer` writes, which the reference hard-codes.
const UNSIGNED_FILENAME: &str = "unsigned_wownero_tx";

/// The file both halves agree on for the signed set, likewise.
const SIGNED_FILENAME: &str = "signed_wownero_tx";

/// A watch-only wallet's `transfer`: plan it, show it, and write it out for
/// the half that can sign.
///
/// Nothing is recorded as spent. The reference does not either: the inputs are
/// marked when the signed set comes back and `submit_transfer` relays it, so a
/// set that is never signed leaves the wallet as it was.
fn write_unsigned(
    session: &mut Session,
    request: &SendRequest<'_>,
    address_text: &str,
    ring_size: usize,
) -> Result<(), String> {
    let unsigned = session
        .prepare_unsigned(request)
        .map_err(|e| e.to_string())?;

    if let Some(e) = &unsigned.pool_unread {
        eprintln!("{e}");
    }
    report_pool(
        session,
        &PoolCheck {
            noted: unsigned.noted_in_pool.clone(),
            failed: Vec::new(),
        },
    );

    let plan = &unsigned.plan;
    println!();
    println!("Sending  {}", fmt::amount(plan.amounts[0]));
    println!("     to  {address_text}");
    println!(
        "    fee  {} ({})",
        fmt::amount(plan.fee),
        tier_name(unsigned.priority)
    );
    if plan.change > 0 {
        println!(" change  {}", fmt::amount(plan.change));
    }
    println!(
        " inputs  {}, ring size {ring_size}, {} bytes",
        plan.inputs.len(),
        plan.estimated_weight
    );
    if let Some(p) = unsigned.payment_id {
        println!("payment id  {}", wow_crypto::hex::encode(&p));
    }
    println!();
    println!(
        "This is a watch-only wallet: it cannot sign. The transaction will be written to \
         {UNSIGNED_FILENAME} for the wallet that holds the spend key."
    );
    if !term::confirm("Write it?") {
        println!("Cancelled.");
        return Ok(());
    }

    write_export(session, UNSIGNED_FILENAME, &unsigned.blob)?;
    // The rings chosen while planning are kept, so a second attempt at the
    // same outputs hides them among the same decoys.
    save_after(session);
    println!("Unsigned transaction(s) successfully written to file: {UNSIGNED_FILENAME}");
    Ok(())
}

/// `export_outputs [all] <filename>`.
fn export_outputs(session: &mut Session, args: &[&str]) -> Result<(), String> {
    const USAGE: &str = "usage: export_outputs [all] <filename>";
    let (all, rest) = leading_all(args);
    let filename = one_file(&rest, USAGE)?;

    let blob = session
        .export_outputs_to_file(all, 0, u32::MAX)
        .map_err(|e| format!("Error exporting outputs: {e}"))?;
    write_export(session, &filename, &blob)?;
    println!("Outputs exported to {filename}");
    Ok(())
}

/// `import_outputs <filename>`.
fn import_outputs(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let filename = one_file(args, "usage: import_outputs <filename>")?;
    let blob = read_file(&filename)?;
    let n = session
        .import_outputs_from_file(&blob)
        .map_err(|e| format!("Failed to import outputs {filename}: {e}"))?;
    save_after(session);
    println!("{n} outputs imported");
    Ok(())
}

/// `export_key_images [all] <filename>`.
fn export_key_images(session: &mut Session, args: &[&str]) -> Result<(), String> {
    const USAGE: &str = "usage: export_key_images [all] <filename>";
    let (all, rest) = leading_all(args);
    let filename = one_file(&rest, USAGE)?;

    let blob = session
        .export_key_images_to_file(all)
        .map_err(|e| format!("Error exporting key images: {e}"))?;
    write_export(session, &filename, &blob)?;
    println!("Signed key images exported to {filename}");
    Ok(())
}

/// `import_key_images <filename>`.
///
/// Gated on a trusted daemon, as `simplewallet` gates it: importing asks the
/// node whether each of this wallet's key images is spent, which hands it the
/// wallet's whole output set.
fn import_key_images(session: &mut Session, args: &[&str]) -> Result<(), String> {
    if !session.state.trusted_daemon {
        return Err(
            "this command requires a trusted daemon. Enable with --trusted-daemon".into(),
        );
    }
    let filename = one_file(args, "usage: import_key_images <filename>")?;
    let blob = read_file(&filename)?;
    let imported = session
        .import_key_images_from_file(&blob, true)
        .map_err(|e| format!("Failed to import key images: {e}"))?;
    save_after(session);
    println!(
        "Signed key images imported to height {}, {} spent, {} unspent",
        imported.height,
        fmt::amount(imported.spent),
        fmt::amount(imported.unspent)
    );
    Ok(())
}

/// `sign_transfer [export_raw] [<filename>]`.
///
/// Reads `unsigned_wownero_tx` unless told otherwise and always writes
/// `signed_wownero_tx`, as `simplewallet` does. `export_raw` also writes the
/// transaction as hex, for `/sendrawtransaction`.
fn sign_transfer(session: &mut Session, args: &[&str]) -> Result<(), String> {
    const USAGE: &str = "usage: sign_transfer [export_raw] [<filename>]";
    if session.is_view_only() {
        return Err("This is a watch only wallet".into());
    }

    let mut export_raw = false;
    let mut unsigned_filename = UNSIGNED_FILENAME.to_string();
    match args {
        [] => {}
        ["export_raw"] => export_raw = true,
        [one] => unsigned_filename = (*one).to_string(),
        ["export_raw", name] => {
            export_raw = true;
            unsigned_filename = (*name).to_string();
        }
        _ => return Err(USAGE.into()),
    }

    let blob = read_file(&unsigned_filename)?;
    let set = session
        .load_unsigned(&blob)
        .map_err(|e| format!("Failed to sign transaction: {e}"))?;

    // `accept_loaded_tx`: what is being signed, before the spend key is used.
    let extra = if set.new_transfers.outputs.is_empty() {
        String::new()
    } else {
        format!("{} outputs to import. ", set.new_transfers.outputs.len())
    };
    if !accept_loaded(session, &set.txes, &extra)? {
        println!("Cancelled.");
        return Ok(());
    }

    let signed = session
        .sign_unsigned(&set)
        .map_err(|e| format!("Failed to sign transaction: {e}"))?;
    write_export(session, SIGNED_FILENAME, &signed.blob)?;
    save_after(session);

    let txids: Vec<String> = signed
        .txids
        .iter()
        .map(|t| wow_crypto::hex::encode(t))
        .collect();
    println!(
        "Transaction successfully signed to file {SIGNED_FILENAME}, txid {}",
        txids.join(", ")
    );
    if export_raw {
        let mut names = Vec::with_capacity(signed.raw.len());
        for (i, blob) in signed.raw.iter().enumerate() {
            let name = if signed.raw.len() == 1 {
                format!("{SIGNED_FILENAME}_raw")
            } else {
                format!("{SIGNED_FILENAME}_raw_{i}")
            };
            write_export(session, &name, wow_crypto::hex::encode(blob).as_bytes())?;
            names.push(name);
        }
        println!("Transaction raw hex data exported to {}", names.join(", "));
    }
    Ok(())
}

/// `submit_transfer`.
///
/// Takes no arguments and always reads `signed_wownero_tx`, as
/// `simplewallet::submit_transfer` does — it ignores its arguments entirely.
fn submit_transfer(session: &mut Session) -> Result<(), String> {
    if session.daemon.is_none() {
        return Err("no daemon set; use `set_daemon <host:port>`".into());
    }
    let blob = read_file(SIGNED_FILENAME)?;
    let set = session
        .load_signed(&blob)
        .map_err(|e| format!("Failed to load transaction from file: {e}"))?;

    let txes: Vec<wow_wallet::cold::TxConstructionData> = set
        .ptx
        .iter()
        .map(|p| p.construction_data.clone())
        .collect();
    let extra = if set.key_images.is_empty() {
        String::new()
    } else {
        format!("{} key images to import. ", set.key_images.len())
    };
    if !accept_loaded(session, &txes, &extra)? {
        println!("Cancelled.");
        return Ok(());
    }

    let submitted = session
        .submit_signed(&set)
        .map_err(|e| format!("Failed to submit signed tx: {e}"))?;
    save_after(session);

    for (txid, result) in submitted.txids.iter().zip(&submitted.results) {
        let txid = wow_crypto::hex::encode(txid);
        if result.accepted() {
            println!("Transaction successfully submitted, transaction {txid}");
            println!("You can check its status by using the `show_transfers` command.");
        } else {
            println!("The daemon rejected transaction {txid}.");
            if !result.reason.is_empty() {
                println!("  reason: {}", result.reason);
            }
            println!("  status: {}", result.status);
        }
    }
    Ok(())
}

/// `simple_wallet::accept_loaded_tx`: describe the set and ask.
///
/// The prompt is the reference's, field for field, because it is the one thing
/// standing between a user and signing something they did not mean to:
/// "Loaded N transactions, for <in>, fee <fee>, <destinations>, <change>, with
/// min ring size N, <payment id>. <extra>Is this okay?". Note that "for" is
/// what the *inputs* hold, not what is being sent — `print_money(amount)`
/// where `amount` is the sum of `cd.sources[s].amount`.
fn accept_loaded(
    session: &Session,
    txes: &[wow_wallet::cold::TxConstructionData],
    extra_message: &str,
) -> Result<bool, String> {
    let described = session.describe(txes).map_err(|e| e.to_string())?;
    let summary = &described.summary;

    // The destinations and then the outputs of nothing, both, as the reference
    // appends them; "with no destinations" only when there is neither.
    let mut parts: Vec<String> = summary
        .recipients
        .iter()
        .map(|r| format!("sending {} to {}", fmt::amount(r.amount), r.address))
        .collect();
    let dummies: u32 = described.txs.iter().map(|t| t.dummy_outputs).sum();
    if dummies > 0 {
        parts.push(format!("{dummies} dummy output(s)"));
    }
    let dest_string = if parts.is_empty() {
        "with no destinations".to_string()
    } else {
        parts.join(", ")
    };

    let change_string = if summary.change_amount > 0 {
        format!(
            "{} change to {}",
            fmt::amount(summary.change_amount),
            summary.change_address
        )
    } else {
        "no change".to_string()
    };

    // A payment id with no integrated destination to have come from is the
    // dummy every transaction carries, and is named as one rather than shown.
    let mut ids: Vec<String> = Vec::new();
    for cd in txes {
        if let Some(id) = wow_wallet::offline::payment_id_from_extra(&cd.extra) {
            if cd.dests.iter().any(|d| d.is_integrated) {
                ids.push(format!(
                    "encrypted payment ID {}",
                    wow_crypto::hex::encode(&id)
                ));
            } else {
                ids.push("dummy encrypted payment ID".to_string());
            }
        }
    }
    let payment_id_string = if ids.is_empty() {
        "no payment ID".to_string()
    } else {
        ids.join(", ")
    };

    let min_ring_size = described
        .txs
        .iter()
        .map(|t| t.ring_size)
        .min()
        .unwrap_or(u32::MAX);

    let prompt = format!(
        "Loaded {} transactions, for {}, fee {}, {dest_string}, {change_string}, with min ring \
         size {min_ring_size}, {payment_id_string}. {extra_message}Is this okay?",
        described.txs.len(),
        fmt::amount(summary.amount_in),
        fmt::amount(summary.fee),
    );
    Ok(term::confirm(&prompt))
}

/// A leading `all`, as `export_outputs` and `export_key_images` take it.
///
/// It counts only when something follows it: `if (args.size() >= 2 && args[0]
/// == "all")`. So `export_outputs all` on its own exports incrementally to a
/// file called "all", which is the reference's behaviour and not worth
/// departing from.
fn leading_all<'a>(args: &[&'a str]) -> (bool, Vec<&'a str>) {
    if args.len() >= 2 && args[0] == "all" {
        (true, args[1..].to_vec())
    } else {
        (false, args.to_vec())
    }
}

fn one_file(args: &[&str], usage: &str) -> Result<String, String> {
    match args {
        [name] => Ok((*name).to_string()),
        _ => Err(usage.to_string()),
    }
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("failed to read file {path}: {e}"))
}

/// Write one of these files, wrapped in PEM armour when the wallet is set to
/// `export-format ascii`.
///
/// `wallet2::save_to_file` does the wrapping, not the `*_to_str` that made the
/// bytes, which is why the RPC never wraps and this does. Reading needs no
/// such switch: [`wow_wallet::cold::unwrap_ascii`] takes either.
fn write_export(session: &Session, path: &str, data: &[u8]) -> Result<(), String> {
    if session.export_ascii() {
        write_file(path, &wow_wallet::cold::wrap_ascii(data))
    } else {
        write_file(path, data)
    }
}

/// Write a file, refusing to overwrite one: `check_file_overwrite` asks, and a
/// wallet driven by `--command` has nobody to ask.
fn write_file(path: &str, data: &[u8]) -> Result<(), String> {
    if std::path::Path::new(path).exists() {
        if !term::interactive() {
            return Err(format!("File {path} already exists."));
        }
        if path.ends_with(".keys") {
            return Err(format!(
                "File {path} likely stores wallet private keys! Use a different file name."
            ));
        }
        if !term::confirm(&format!(
            "File {path} already exists. Are you sure to overwrite it?"
        )) {
            return Err("Cancelled.".into());
        }
    }
    std::fs::write(path, data).map_err(|e| format!("failed to save file {path}: {e}"))
}

/// Save at once after anything that changed what the wallet knows about its
/// own outputs: a wallet that forgot an import would ask for the same key
/// images again.
fn save_after(session: &mut Session) {
    match session.save() {
        Ok(()) => session.dirty = false,
        Err(e) => eprintln!("The wallet could not be saved: {e}"),
    }
}

// -- rings -----------------------------------------------------------------

/// Thirty-two bytes of hex: a key image, or a transaction id.
fn parse_hash(text: &str) -> Option<[u8; 32]> {
    wow_crypto::hex::decode(text)?.try_into().ok()
}

/// `simple_wallet::print_ring`: the ring a key image was spent with, or the
/// rings of a transaction this wallet sent, in the form `set_ring` reads
/// back.
fn print_ring(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let [arg] = args else {
        return Err("usage: print_ring <key_image> | <txid>".into());
    };
    let bytes = parse_hash(arg).ok_or("Invalid key image")?;
    let key_image = wow_crypto::types::KeyImage(bytes);

    let rings: Vec<(wow_crypto::types::KeyImage, Vec<u64>)> =
        if let Some(ring) = session.state.rings.get(&key_image) {
            vec![(key_image, ring.to_vec())]
        } else if let Some(sent) = session.state.sent.iter().find(|s| s.txid == bytes) {
            // The C++ keeps each sent transaction's rings with it. This wallet
            // keeps them by key image, and a sent transaction knows its own.
            sent.key_images
                .iter()
                .filter_map(|k| Some((*k, session.state.rings.get(k)?.to_vec())))
                .collect()
        } else {
            return Err("Key image either not spent, or spent with ring size 1".into());
        };
    for (k, ring) in rings {
        let indices: String = ring.iter().map(|i| format!("{i} ")).collect();
        // "absolute" is not translated: the line is input to `set_ring`.
        println!("{} absolute {indices}", wow_crypto::hex::encode(&k.0));
    }
    Ok(())
}

/// `simple_wallet::set_ring`: keep a ring for a key image, from the command
/// line or from a file of lines `print_ring` wrote.
fn set_ring(session: &mut Session, args: &[&str]) -> Result<(), String> {
    const USAGE: &str =
        "usage: set_ring <filename> | ( <key_image> absolute|relative <index> [<index>...] )";

    if let [filename] = args {
        let text = std::fs::read_to_string(filename).map_err(|_| "File doesn't exist")?;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            match ring_from_line(line) {
                Ok((key_image, ring, relative)) => {
                    session.state.rings.set_ring(key_image, &ring, relative);
                    session.dirty = true;
                }
                // A bad line is reported and the rest are read, as the C++
                // reads them.
                Err(e) => println!("Error: {e}"),
            }
        }
        return Ok(());
    }

    let [image, kind, indices @ ..] = args else {
        return Err(USAGE.into());
    };
    if indices.is_empty() {
        return Err(USAGE.into());
    }
    let key_image = wow_crypto::types::KeyImage(parse_hash(image).ok_or("Invalid key image")?);
    let relative = match *kind {
        "absolute" => false,
        "relative" => true,
        _ => return Err("Missing absolute or relative keyword".into()),
    };

    let mut ring: Vec<u64> = Vec::with_capacity(indices.len());
    let mut sum = 0u64;
    for text in indices {
        let index: u64 = text
            .parse()
            .map_err(|_| "invalid index: must be a strictly positive unsigned integer")?;
        if relative {
            if !ring.is_empty() && index == 0 {
                return Err("invalid index: must be a strictly positive unsigned integer".into());
            }
            sum = sum
                .checked_add(index)
                .ok_or("invalid index: indices wrap")?;
        } else if ring.last().is_some_and(|last| *last >= index) {
            return Err("invalid index: indices should be in strictly ascending order".into());
        }
        ring.push(index);
    }
    session.state.rings.set_ring(key_image, &ring, relative);
    session.dirty = true;
    Ok(())
}

/// One line of a `set_ring` file: `<key_image> absolute|relative <index>...`,
/// checked as `simple_wallet::set_ring` checks a file's lines.
fn ring_from_line(line: &str) -> Result<(wow_crypto::types::KeyImage, Vec<u64>, bool), String> {
    let mut words = line.split_whitespace();
    let image = words
        .next()
        .and_then(parse_hash)
        .ok_or_else(|| format!("Invalid key image: {line}"))?;
    let relative = match words.next() {
        Some("absolute") => false,
        Some("relative") => true,
        _ => return Err(format!("Invalid ring type, expected relative or absolute: {line}")),
    };
    let ring = words
        .map(str::parse::<u64>)
        .collect::<Result<Vec<u64>, _>>()
        .map_err(|_| format!("Error reading line: {line}"))?;
    if ring.is_empty() {
        return Err(format!("Invalid ring: {line}"));
    }
    let valid = if relative {
        ring[1..].iter().all(|i| *i > 0)
    } else {
        ring.windows(2).all(|w| w[0] < w[1])
    };
    if !valid {
        let kind = if relative { "relative" } else { "absolute" };
        return Err(format!("Invalid {kind} ring: {line}"));
    }
    Ok((wow_crypto::types::KeyImage(image), ring, relative))
}

/// `simple_wallet::unset_ring`: forget the rings of key images, or of the
/// inputs of a transaction this wallet sent.
///
/// The C++ tries its arguments as key images first, and as a transaction id
/// only if that fails, which with a ring database open it never does: a
/// transaction id given alone is quietly no key image. Here one argument that
/// forgets no key image's ring is looked up as a sent transaction.
fn unset_ring(session: &mut Session, args: &[&str]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: unset_ring <txid> | ( <key_image> [<key_image>...] )".into());
    }
    let hashes: Vec<[u8; 32]> = args
        .iter()
        .map(|a| parse_hash(a).ok_or("Invalid key image or txid"))
        .collect::<Result<_, _>>()?;
    let key_images: Vec<wow_crypto::types::KeyImage> = hashes
        .iter()
        .map(|h| wow_crypto::types::KeyImage(*h))
        .collect();

    let mut forgotten = session.state.rings.unset(&key_images);
    if forgotten == 0 && hashes.len() == 1 {
        if let Some(sent) = session.state.sent.iter().find(|s| s.txid == hashes[0]) {
            let inputs = sent.key_images.clone();
            forgotten = session.state.rings.unset(&inputs);
        }
    }
    if forgotten > 0 {
        session.dirty = true;
    }
    Ok(())
}

// -- settings --------------------------------------------------------------

/// `simple_wallet::lock`: hold the console until the wallet's password is
/// typed again.
///
/// The C++ sets `m_locked` and calls `check_for_inactivity_lock(true)` at
/// once, so the prompt is held from here rather than from the next command.
fn lock(session: &mut Session) -> Result<(), String> {
    LOCKED.store(true, Ordering::Relaxed);
    check_for_inactivity_lock(session, true)
}

fn set(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let Some(option) = args.first() else {
        println!("usage: set <option> <value>");
        println!(
            "known: refresh-from-block-height, subaddress-lookahead, seed-language, store-tx-info, \
             priority, auto-low-priority, ignore-outputs-above, ignore-outputs-below, \
             inactivity-lock-timeout"
        );
        return Ok(());
    };
    let value = args.get(1).ok_or("a value is required")?;

    match *option {
        "refresh-from-block-height" => {
            let h: u64 = value.parse().map_err(|_| "that is not a height")?;
            session.keys_file.set_refresh_height(h);
        }
        "seed-language" => {
            wow_crypto::mnemonic::by_name(value).ok_or("unknown language")?;
            session
                .keys_file
                .settings
                .insert("seed_language".into(), serde_json::Value::from(*value));
        }
        "subaddress-lookahead" => {
            let (major, minor) = value
                .split_once(':')
                .ok_or("usage: set subaddress-lookahead <major>:<minor>")?;
            let major: u64 = major.parse().map_err(|_| "not a number")?;
            let minor: u64 = minor.parse().map_err(|_| "not a number")?;
            session
                .keys_file
                .settings
                .insert("subaddress_lookahead_major".into(), major.into());
            session
                .keys_file
                .settings
                .insert("subaddress_lookahead_minor".into(), minor.into());
        }
        "store-tx-info" => {
            if session.is_view_only() {
                return Err("a view-only wallet sends nothing, so it has nothing to record".into());
            }
            let on = match *value {
                "1" | "true" | "on" => true,
                "0" | "false" | "off" => false,
                _ => return Err("store-tx-info is 0 or 1".into()),
            };
            session.keys_file.set_store_tx_info(on);
        }
        "priority" => {
            let p = priority::parse_priority(value).ok_or(
                "priority is 0, 1, 2, 3 or 4, or one of: default, unimportant, normal, elevated, \
                 priority",
            )?;
            session.keys_file.set_default_priority(p);
        }
        "auto-low-priority" => {
            let on = match *value {
                "1" | "true" | "on" => true,
                "0" | "false" | "off" => false,
                _ => return Err("auto-low-priority is 0 or 1".into()),
            };
            session.keys_file.set_auto_low_priority(on);
        }
        // `set_ignore_outputs_above` and `set_ignore_outputs_below`: keep an
        // output out of everyday sends by what it is worth. Somebody who was
        // paid one very large output does not want it picked to pay for
        // coffee, because that one output is recognisable.
        //
        // "Value 0 is translated to the maximum value (18 million) which
        // disables this filter" -- on this chain the maximum is `MONEY_SUPPLY`,
        // the whole `u64` range.
        "ignore-outputs-above" => {
            let amount = fmt::parse_amount(value).map_err(|_| "Invalid amount")?;
            let amount = if amount == 0 { u64::MAX } else { amount };
            session.keys_file.set_ignore_outputs_above(amount);
        }
        "ignore-outputs-below" => {
            let amount = fmt::parse_amount(value).map_err(|_| "Invalid amount")?;
            session.keys_file.set_ignore_outputs_below(amount);
        }
        // `set_inactivity_lock_timeout`, whose hint is "unsigned integer
        // (seconds, 0 to disable)".
        "inactivity-lock-timeout" => {
            let seconds: u64 = value
                .parse()
                .map_err(|_| "inactivity-lock-timeout is a number of seconds; 0 disables it")?;
            session.keys_file.set_inactivity_lock_timeout(seconds);
        }
        other => return Err(format!("`{other}` is not a setting this build knows")),
    }

    session.dirty = true;
    println!("Set. Run `save` to persist it.");
    Ok(())
}

// -- argument helpers ------------------------------------------------------

fn parse_index(arg: Option<&&str>, default: u32) -> Result<u32, String> {
    match arg {
        None => Ok(default),
        Some(s) => s.parse().map_err(|_| format!("`{s}` is not an index")),
    }
}

/// A leading priority word or digit, if present; `default` otherwise.
///
/// `default` and `0` are 0, which `adjust_priority` turns into a tier later.
/// They are not "normal".
fn take_priority(args: &mut Vec<&str>, default: u32) -> u32 {
    match args.first().and_then(|a| priority::parse_priority(a)) {
        Some(p) => {
            args.remove(0);
            p
        }
        None => default,
    }
}

/// A ring size, which must be 22.
///
/// `specs/13` §2.4: the exact-ring-size rule from HF 15 means any other value
/// produces a transaction the chain will reject, so it is refused here with a
/// reason rather than built and relayed to a refusal.
fn take_ring_size(args: &mut Vec<&str>) -> Result<usize, String> {
    let Some(first) = args.first().copied() else {
        return Ok(decoys::RING_SIZE);
    };
    let Ok(n) = first.parse::<usize>() else {
        return Ok(decoys::RING_SIZE);
    };
    // A bare number here is only a ring size if it is not also an amount, and
    // amounts come after the address, so position settles it.
    args.remove(0);
    if n != decoys::RING_SIZE {
        return Err(format!(
            "ring size {n} would be rejected: from HF 15 every input must have exactly {} \
             members",
            decoys::RING_SIZE
        ));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priorities_parse_both_ways() {
        let mut a = vec!["elevated", "rest"];
        assert_eq!(take_priority(&mut a, 0), 3);
        assert_eq!(a, vec!["rest"]);

        let mut a = vec!["4", "rest"];
        assert_eq!(take_priority(&mut a, 0), 4);

        // `default` is 0, for `adjust_priority` to settle, whatever the
        // wallet's default priority.
        let mut a = vec!["default", "rest"];
        assert_eq!(take_priority(&mut a, 3), 0);
        assert_eq!(a, vec!["rest"]);

        // Not a priority: left alone, the default returned.
        let mut a = vec!["Wo1abc", "5"];
        assert_eq!(take_priority(&mut a, 0), 0);
        assert_eq!(take_priority(&mut a, 3), 3);
        assert_eq!(a.len(), 2);
    }

    /// A ring size other than 22 is refused with a reason. Building it would
    /// waste a round trip and confuse the user with a daemon-side rejection.
    #[test]
    fn a_wrong_ring_size_is_refused_here() {
        let mut a = vec!["11", "address"];
        let e = take_ring_size(&mut a).expect_err("11 is not allowed");
        assert!(e.contains("exactly 22"), "{e}");

        let mut a = vec!["22", "address"];
        assert_eq!(take_ring_size(&mut a).expect("22 is fine"), 22);
        assert_eq!(a, vec!["address"]);

        let mut a = vec!["address"];
        assert_eq!(take_ring_size(&mut a).expect("absent"), 22);
        assert_eq!(a, vec!["address"]);
    }

    /// A `set_ring` file's line is read as `print_ring` writes one, and a ring
    /// that could not be real is refused with the line.
    #[test]
    fn a_ring_file_line_is_read_as_print_ring_writes_it() {
        let image = "ab".repeat(32);
        let (k, ring, relative) =
            ring_from_line(&format!("{image} absolute 3 9 20 ")).expect("a ring");
        assert_eq!(k.0, [0xab; 32]);
        assert_eq!((ring, relative), (vec![3, 9, 20], false));

        let (_, ring, relative) =
            ring_from_line(&format!("{image} relative 3 6 11")).expect("a ring");
        assert_eq!((ring, relative), (vec![3, 6, 11], true));

        for bad in [
            format!("{image} absolute 9 3"),
            format!("{image} relative 3 0"),
            format!("{image} sideways 1 2"),
            format!("{image} absolute"),
            format!("{image} absolute 1 x"),
            "abcd absolute 1 2".to_string(),
        ] {
            assert!(ring_from_line(&bad).is_err(), "{bad}");
        }
    }

    /// `freeze`, `thaw` and `frozen` take 64 hex characters and nothing else,
    /// and say what the C++ says about anything else.
    #[test]
    fn a_key_image_is_read_as_the_cpp_reads_one() {
        let image = "ab".repeat(32);
        assert_eq!(key_image_arg(&image).expect("a key image").0, [0xab; 32]);
        // Upper case decodes to the same bytes, which is what is printed back.
        let upper = image.to_uppercase();
        assert_eq!(key_image_arg(&upper).expect("a key image").0, [0xab; 32]);

        let short = "ab".repeat(31);
        let long = "ab".repeat(33);
        for bad in ["", "3", "not hex", short.as_str(), long.as_str()] {
            let e = key_image_arg(bad).expect_err("not a key image");
            assert_eq!(e, "failed to parse key image", "`{bad}`");
        }
    }

    /// Every unimplemented command in the list is refused by name, which
    /// `specs/13` §2 requires.
    #[test]
    fn unimplemented_commands_are_named() {
        assert!(NOT_IMPLEMENTED.iter().any(|(n, _)| *n == "get_tx_key"));
        assert!(NOT_IMPLEMENTED
            .iter()
            .any(|(n, _)| *n == "setup_background_sync"));
        for (_, why) in NOT_IMPLEMENTED {
            assert!(!why.is_empty(), "every refusal gives a reason");
        }
        // The cold-signing commands are built now, so none of them is here.
        for name in [
            "export_outputs",
            "import_outputs",
            "export_key_images",
            "import_key_images",
            "sign_transfer",
            "submit_transfer",
        ] {
            assert!(
                !NOT_IMPLEMENTED.iter().any(|(n, _)| *n == name),
                "{name} is built"
            );
        }
    }

    /// `export_outputs [all] <filename>`: `all` counts only when something
    /// follows it, as `args.size() >= 2 && args[0] == "all"` says, so
    /// `export_outputs all` names a file called "all".
    #[test]
    fn a_leading_all_needs_something_after_it() {
        assert_eq!(leading_all(&["all", "outs"]), (true, vec!["outs"]));
        assert_eq!(leading_all(&["outs"]), (false, vec!["outs"]));
        assert_eq!(leading_all(&["all"]), (false, vec!["all"]));

        assert_eq!(one_file(&["outs"], "usage"), Ok("outs".to_string()));
        assert!(one_file(&["a", "b"], "usage").is_err());
        assert!(one_file(&[], "usage").is_err());
    }
}
