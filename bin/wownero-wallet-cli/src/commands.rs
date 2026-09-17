//! The commands (`specs/13` §2).
//!
//! The M4 minimum set from `specs/13` §4. A command in the spec that is not
//! built says so by name rather than being absent — a wallet that answers
//! "unknown command" to `export_outputs` tells a user nothing about whether it
//! will ever work.

use std::time::Instant;

use wow_daemon_client::KeyImageStatus;
use wow_types::address::Address;
use wow_wallet::decoys;
use wow_wallet::history::{EntryKind, PROPAGATION_TIMEOUT};
use wow_wallet::priority::{self, PrioritySettings};
use wow_wallet::send::SendRequest;
use wow_wallet::spend;
use wow_wallet::{PoolCheck, RefreshEvent};

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
    ("export_outputs", "import/export is not built yet"),
    ("import_outputs", "import/export is not built yet"),
    ("export_key_images", "import/export is not built yet"),
    ("import_key_images", "import/export is not built yet"),
    ("sign_transfer", "cold signing is not built yet"),
    ("submit_transfer", "cold signing is not built yet"),
    ("start_mining", "this wallet does not drive a miner"),
    ("stop_mining", "this wallet does not drive a miner"),
    (
        "set_ring",
        "ring management needs a trusted daemon and is not built yet",
    ),
    (
        "get_ring",
        "ring management needs a trusted daemon and is not built yet",
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

/// Run one command line, printing any error.
///
/// Returns whether to carry on, and whether the command failed — `--command`
/// exits non-zero on a failure, which is what lets a script tell.
pub fn run(session: &mut Session, line: &str) -> (Outcome, bool) {
    match run_one(session, line) {
        Ok(outcome) => (outcome, false),
        Err(e) => {
            println!("Error: {e}");
            (Outcome::Continue, true)
        }
    }
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
        "fee" => fee(session),
        "transfer" => transfer_cmd(session, &args),
        "sweep_all" => sweep_all(session, &args),
        "sweep_single" => sweep_single(session, &args),
        "set" => set(session, &args),

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
  set_daemon <address> [<user>:<pass>]
                                point at a daemon: host:port, or https://host:port.
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

Sending
  fee                           the current fee estimate
  transfer <address> <amount> [<payment_id>]
  sweep_all <address>           send everything
  sweep_single <key_image> <address>
                                send one output, by the key image
                                unspent_outputs prints

Settings
  set <option> <value>          persisted to the keys file
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
        None => println!("daemon: none set (`set_daemon <host:port>`)"),
    }
    println!("network: {}", session.network.name());
    if session.is_view_only() {
        println!("this is a view-only wallet: it can watch, not spend");
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
    println!("{}", session.seed(&language)?);
    Ok(())
}

fn viewkey(session: &mut Session) -> Result<(), String> {
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
    let address = args
        .first()
        .ok_or("usage: set_daemon <host:port> [<user>:<password>]")?;
    // A login given here replaces whatever --daemon-login set; one left out
    // keeps it, so pointing at a second node on the same box does not mean
    // typing the password again.
    if let Some(text) = args.get(1) {
        let c = wow_daemon_client::digest::Credentials::parse(text)
            .ok_or("a daemon login is <user>:<password>")?;
        session.daemon_login = Some(c);
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

    eprintln!(
        "Connected to {address}: height {}, {}, {}",
        info.height,
        if info.synchronized {
            "synced"
        } else {
            "still syncing"
        },
        describe_security(client.security())
    );
    session.daemon_height = info.height;
    session.daemon = Some(client);
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
        let state = if t.spent {
            "spent"
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
    if session.is_view_only() {
        return Err("a view-only wallet cannot spend: it has no spend key".into());
    }
    if session.daemon.is_none() {
        return Err("no daemon set; use `set_daemon <host:port>`".into());
    }

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
    };
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

    let relayed = session
        .commit_send(&prepared, false)
        .map_err(|e| e.to_string())?;
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

// -- settings --------------------------------------------------------------

fn set(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let Some(option) = args.first() else {
        println!("usage: set <option> <value>");
        println!(
            "known: refresh-from-block-height, subaddress-lookahead, seed-language, store-tx-info, \
             priority, auto-low-priority"
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
    }
}
