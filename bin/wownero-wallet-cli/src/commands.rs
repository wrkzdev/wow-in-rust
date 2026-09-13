//! The commands (`specs/13` §2).
//!
//! The M4 minimum set from `specs/13` §4. A command in the spec that is not
//! built says so by name rather than being absent — a wallet that answers
//! "unknown command" to `export_outputs` tells a user nothing about whether it
//! will ever work.

use wow_types::address::{Address, AddressKind};
use wow_wallet::decoys::{self, GammaPicker};
use wow_wallet::spend::{self, SpendOptions};
use wow_wallet::transfer::{self, Destination, SpendableOutput};

use crate::fmt;
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
    ("payments", "payment-id history is not built yet"),
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
        "unspent_outputs" => unspent_outputs(session),
        "fee" => fee(session),
        "transfer" => transfer_cmd(session, &args),
        "sweep_all" => sweep_all(session, &args),
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
  set_daemon <host:port>        point at a daemon
  refresh                       scan up to the daemon's tip
  rescan_bc                     forget what was scanned and start over
  bc_height / status            where the wallet and the daemon are
  restore_height                where this wallet started scanning

History
  incoming_transfers [available|unavailable]
  show_transfers [in|out|all]
  unspent_outputs

Sending
  fee                           the current fee estimate
  transfer <address> <amount> [<payment_id>]
  sweep_all <address>           send everything

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
    println!("file: {}", session.paths.keys().display());
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
    let address = args.first().ok_or("usage: set_daemon <host:port>")?;
    let client = wow_daemon_client::DaemonClient::new(*address);
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
        "Connected to {address}: height {}, {}",
        info.height,
        if info.synchronized {
            "synced"
        } else {
            "still syncing"
        }
    );
    session.daemon_height = info.height;
    session.daemon = Some(client);
    Ok(())
}

fn refresh(session: &mut Session) -> Result<(), String> {
    let client = session
        .daemon
        .clone()
        .ok_or("no daemon set; use `set_daemon <host:port>`")?;

    let start = session.state.scan_height();
    let mut received = 0usize;
    let mut spent = 0usize;

    loop {
        let s = session
            .state
            .refresh_once(&client)
            .map_err(|e| e.to_string())?;
        received += s.received;
        spent += s.spent;

        if let Some(h) = s.reorg_to {
            println!("Reorganisation: the chain changed below height {h}; rescanned from there.");
        }
        if s.blocks_scanned > 0 {
            println!("  {}", session.describe_progress());
        }
        if s.caught_up {
            break;
        }
    }

    if let Ok(info) = client.get_info() {
        session.daemon_height = info.height;
    }
    session.dirty = true;

    let scanned = session.state.scan_height().saturating_sub(start);
    println!("Scanned {scanned} block(s).");
    if received > 0 {
        println!("Received {received} new output(s).");
    }
    if spent > 0 {
        println!("{spent} of this wallet's outputs were spent.");
    }
    let (balance, unlocked) = session.balances();
    println!("{}", balance_line(balance, unlocked));
    Ok(())
}

fn rescan(session: &mut Session) -> Result<(), String> {
    if !term::confirm("Forget everything scanned and start again from the restore height?") {
        println!("Left alone.");
        return Ok(());
    }
    let from = session.keys_file.refresh_height();
    session.state.hashes.clear();
    session.state.transfers.clear();
    session.state.by_key_image.clear();
    session.state.start_height = from;
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
    let filter = args.first().copied().unwrap_or("all");
    let mut shown = 0usize;
    for t in session.transfers() {
        let direction = if t.spent { "out" } else { "in" };
        if filter != "all" && filter != direction {
            continue;
        }
        shown += 1;
        println!(
            "{:<4} {:<10} {:>20}  {}",
            direction,
            t.block_height,
            fmt::amount(t.amount),
            wow_crypto::hex::encode(&t.txid)
        );
    }
    if shown == 0 {
        println!("(none)");
    }
    // An outgoing transfer is inferred from an output being spent, which is
    // not the same as a record of what was sent. Saying so beats letting a
    // user believe the history is complete.
    println!(
        "(outgoing entries are this wallet's own outputs being spent; a record of destinations \
         needs store-tx-info, which is not built yet)"
    );
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
        .get_fee_estimate(0)
        .map_err(|e| format!("cannot get a fee estimate: {e}"))?;

    println!("Fee per byte, by priority:");
    for (i, t) in tiers.iter().enumerate() {
        println!("  {}: {}", priority_name(i as u32 + 1), fmt::amount(*t));
    }
    // What that means for an ordinary transaction.
    let weight = spend::estimate_tx_weight(1, decoys::RING_SIZE, 2, 44);
    println!(
        "A one-input, two-output transaction weighs about {weight} bytes, so at normal priority \
         it would cost {}.",
        fmt::amount(spend::fee_from_weight(
            tiers.get(1).copied().unwrap_or(tiers[0]),
            weight
        ))
    );
    Ok(())
}

fn priority_name(p: u32) -> &'static str {
    match p {
        1 => "unimportant",
        2 => "normal",
        3 => "elevated",
        _ => "priority",
    }
}

fn transfer_cmd(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let mut rest: Vec<&str> = args.to_vec();
    let priority = take_priority(&mut rest);
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
    )
}

fn sweep_all(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let mut rest: Vec<&str> = args.to_vec();
    let priority = take_priority(&mut rest);
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
) -> Result<(), String> {
    if session.is_view_only() {
        return Err("a view-only wallet cannot spend: it has no spend key".into());
    }
    let client = session
        .daemon
        .clone()
        .ok_or("no daemon set; use `set_daemon <host:port>`")?;

    // The destination, decoded against this wallet's network.
    let (address_text, amount) = &destinations[0];
    let decoded = Address::decode_for(address_text, session.network).map_err(|e| {
        format!(
            "that address is not valid for {}: {e}",
            session.network.name()
        )
    })?;

    let explicit_pid: Option<[u8; 8]> = match payment_id {
        Some(hex) => Some(
            wow_crypto::hex::decode(hex)
                .ok_or("the payment id is not hex")?
                .try_into()
                .map_err(|_| "a payment id is 8 bytes (16 hex characters)".to_string())?,
        ),
        None => None,
    };
    // An integrated address carries its own payment id, and giving a second one
    // is ambiguous rather than additive.
    let pid = match (decoded.payment_id, explicit_pid) {
        (Some(_), Some(_)) => {
            return Err("that is an integrated address; it already carries a payment id".into())
        }
        (Some(p), None) => Some(p),
        (None, other) => other,
    };

    // Fees, from the daemon.
    let tiers = client
        .get_fee_estimate(0)
        .map_err(|e| format!("cannot get a fee estimate: {e}"))?;
    let fee_per_byte = tiers
        .get(priority.saturating_sub(1) as usize)
        .or(tiers.first())
        .copied()
        .unwrap_or(0);

    let options = SpendOptions {
        ring_size,
        fee_per_byte,
        extra_size: if pid.is_some() { 44 + 11 } else { 44 },
        chain_height: session.chain_height(),
        now: now(),
        ..Default::default()
    };

    let plan = if sweep {
        spend::plan_sweep(session.transfers(), &options)
    } else {
        spend::plan(session.transfers(), &[*amount], &options)
    }
    .map_err(|e| e.to_string())?;

    // Rings, one per input.
    let distribution = client
        .get_output_distribution(0, 0, session.chain_height().saturating_sub(1))
        .map_err(|e| format!("cannot get the output distribution: {e}"))?;
    let picker = GammaPicker::new(&distribution).map_err(|e| e.to_string())?;
    let mut rng = term::seeded_rng()?;

    let mut inputs = Vec::with_capacity(plan.inputs.len());
    for &i in &plan.inputs {
        let t = &session.state.transfers[i];
        let ring = decoys::select_ring(&picker, &mut rng, t.global_output_index, ring_size)
            .map_err(|e| format!("cannot build a ring: {e}"))?;

        let wanted: Vec<(u64, u64)> = ring.indices.iter().map(|i| (0u64, *i)).collect();
        let outs = client
            .get_outs(&wanted, false)
            .map_err(|e| format!("cannot fetch ring members: {e}"))?;
        let keys: Vec<([u8; 32], [u8; 32])> = outs.iter().map(|o| (o.key, o.mask)).collect();

        let mask = wow_crypto::ops::decode_scalar(&t.mask)
            .ok_or("this output's stored mask is not a valid scalar")?;
        let assembled = decoys::assemble_ring(
            &ring,
            &keys,
            &t.public_key,
            &wow_crypto::rct::commit(t.amount, &mask),
        )
        .map_err(|e| format!("the daemon's ring members do not match ours: {e}"))?;

        // The one-time secret key for this output.
        let secret = one_time_secret(session, t)?;

        inputs.push(SpendableOutput {
            public_key: t.public_key,
            secret_key: secret,
            mask,
            amount: t.amount,
            key_image: t.key_image.ok_or("this output has no key image")?,
            ring: assembled.members,
            global_indices: assembled.indices,
            real_index: assembled.real_index,
        });
    }

    // Destinations: the payee, then change back to ourselves.
    let change_to = session.keys_file.account.keys.account_address;
    let mut dests = vec![Destination {
        address: decoded.keys,
        is_subaddress: decoded.kind == AddressKind::Subaddress,
        amount: plan.amounts[0],
    }];
    dests.push(Destination {
        address: change_to,
        is_subaddress: false,
        amount: plan.change,
    });

    println!();
    println!("Sending  {}", fmt::amount(plan.amounts[0]));
    println!("     to  {address_text}");
    println!("    fee  {}", fmt::amount(plan.fee));
    if plan.change > 0 {
        println!(" change  {}", fmt::amount(plan.change));
    }
    println!(
        " inputs  {}, ring size {ring_size}, about {} bytes",
        plan.inputs.len(),
        plan.estimated_weight
    );
    if let Some(p) = pid {
        println!("payment id  {}", wow_crypto::hex::encode(&p));
    }
    if !term::confirm("Send?") {
        println!("Cancelled.");
        return Ok(());
    }

    let built = transfer::construct(&inputs, &dests, plan.fee, pid, &mut || {
        use wow_wallet::decoys::RandomSource;
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
        b[8..16].copy_from_slice(&rng.next_u64().to_le_bytes());
        b[16..24].copy_from_slice(&rng.next_u64().to_le_bytes());
        b[24..].copy_from_slice(&rng.next_u64().to_le_bytes());
        curve25519_dalek::scalar::Scalar::from_bytes_mod_order(b)
    })
    .map_err(|e| format!("cannot build the transaction: {e}"))?;

    let mut w = wow_serialize::binary::Writer::with_capacity(8192);
    built.tx.write(&mut w);
    let blob = w.into_vec();
    let txid = transfer::transaction_hash(&built.tx);

    let result = client
        .send_raw_transaction(&blob, false)
        .map_err(|e| format!("cannot reach the daemon to relay: {e}"))?;

    if result.accepted() {
        println!("Sent. Transaction {}", wow_crypto::hex::encode(&txid));
        println!("(it will appear in the balance once it is mined and four blocks have passed)");
        session.dirty = true;
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
    }
    Ok(())
}

/// The one-time secret key for an output, recomputed rather than stored.
fn one_time_secret(
    session: &Session,
    t: &wow_wallet::refresh::Transfer,
) -> Result<wow_crypto::types::SecretKey, String> {
    wow_wallet::refresh::one_time_secret_key(&session.keys_file.account, t)
        .ok_or_else(|| "a view-only wallet has no spend key".to_string())
}

// -- settings --------------------------------------------------------------

fn set(session: &mut Session, args: &[&str]) -> Result<(), String> {
    let Some(option) = args.first() else {
        println!("usage: set <option> <value>");
        println!("known: refresh-from-block-height, subaddress-lookahead, seed-language");
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

/// A leading priority word or digit, if present.
fn take_priority(args: &mut Vec<&str>) -> u32 {
    let Some(first) = args.first().copied() else {
        return 2;
    };
    let p = match first {
        "default" | "0" => Some(2),
        "unimportant" | "1" => Some(1),
        "normal" | "2" => Some(2),
        "elevated" | "3" => Some(3),
        "priority" | "4" => Some(4),
        _ => None,
    };
    match p {
        Some(p) => {
            args.remove(0);
            p
        }
        None => 2,
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
        assert_eq!(take_priority(&mut a), 3);
        assert_eq!(a, vec!["rest"]);

        let mut a = vec!["4", "rest"];
        assert_eq!(take_priority(&mut a), 4);

        // Not a priority: left alone, default returned.
        let mut a = vec!["Wo1abc", "5"];
        assert_eq!(take_priority(&mut a), 2);
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
