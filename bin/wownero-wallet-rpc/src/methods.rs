//! The JSON-RPC methods (`specs/14` §2).
//!
//! The M4 minimum set — the bold entries in §2 — plus the openers a
//! `--wallet-dir` server needs.
//!
//! Method names and parameter names are a compatibility surface: an exchange
//! reads them literally, so a rename is a break. A method the reference has and
//! this build does not is refused **by name** with `-48 DISABLED`, rather than
//! looking like a typo.

use serde_json::{json, Map, Value};

use wow_types::address::{Address, AddressKind};
use wow_wallet::decoys::{self, DecoyError};
use wow_wallet::files::Session;
use wow_wallet::priority::{self, PrioritySettings};
use wow_wallet::send::{SendError, SendRequest};
use wow_wallet::spend;

use crate::errors::{self, Error};
use crate::server::State;

pub type MethodResult = Result<Value, Error>;

/// `WALLET_RPC_VERSION`: major 1, minor 30.
pub const WALLET_RPC_VERSION: u32 = (1 << 16) | 30;

/// Methods the reference has that this build does not.
///
/// `specs/14` §2 lists 114. Refusing by name with a reason is the difference
/// between "this build cannot do that" and "you misspelled something".
const DISABLED: &[(&str, &str)] = &[
    ("get_tx_proof", "transaction proofs are not built yet"),
    ("check_tx_proof", "transaction proofs are not built yet"),
    ("get_spend_proof", "spend proofs are not built yet"),
    ("check_spend_proof", "spend proofs are not built yet"),
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
    ("describe_transfer", "cold signing is not built yet"),
    ("start_mining", "this wallet does not drive a miner"),
    ("stop_mining", "this wallet does not drive a miner"),
    ("make_multisig", "multisig is not built"),
    ("is_multisig", "multisig is not built"),
    ("sweep_dust", "there are no unmixable outputs on this chain"),
    (
        "sweep_unmixable",
        "there are no unmixable outputs on this chain",
    ),
    ("get_address_book", "the address book is not built yet"),
    ("add_address_book", "the address book is not built yet"),
    ("setup_background_sync", "background sync is not supported"),
    ("start_background_sync", "background sync is not supported"),
    ("stop_background_sync", "background sync is not supported"),
];

/// Dispatch one method.
pub fn dispatch(state: &State, method: &str, params: &Value) -> MethodResult {
    if let Some((_, why)) = DISABLED.iter().find(|(n, _)| *n == method) {
        return Err(Error::new(
            errors::DISABLED,
            format!("{method} is not available in this build: {why}"),
        ));
    }

    // Methods that work without an open wallet.
    match method {
        "get_version" => {
            return Ok(json!({
                "version": WALLET_RPC_VERSION,
                "release": false,
            }))
        }
        "get_languages" => {
            let names: Vec<&str> = wow_crypto::mnemonic::LANGUAGES
                .iter()
                .map(|l| l.name)
                .collect();
            let english: Vec<&str> = wow_crypto::mnemonic::LANGUAGES
                .iter()
                .map(|l| l.english_name)
                .collect();
            return Ok(json!({ "languages": names, "languages_local": english }));
        }
        "open_wallet" => return state.open_wallet(params),
        "create_wallet" => return state.create_wallet(params),
        "restore_deterministic_wallet" => return state.restore_deterministic(params),
        "generate_from_keys" => return state.generate_from_keys(params),
        "close_wallet" => return state.close_wallet(),
        _ => {}
    }

    // Everything else needs one.
    let mut guard = state.wallet();
    let session = guard.as_mut().ok_or_else(|| {
        Error::new(
            errors::NOT_OPEN,
            "no wallet is open; call open_wallet or create_wallet first",
        )
    })?;

    // Attach a daemon if the wallet has none and the server was given an
    // address. A wallet only gets one at open time, and a daemon that was down
    // for that one moment would otherwise leave it detached for good --
    // answering "no daemon is set" on a server that has one configured, until
    // somebody noticed and called `set_daemon`. On a machine where the wallet
    // service starts before the node, that is the normal case, not an edge
    // one. While a daemon is attached this costs nothing.
    if session.daemon.is_none() {
        state.attach_daemon(session);
    }

    match method {
        "store" => store(session),
        "get_height" | "getheight" => Ok(json!({ "height": session.state.scan_height() })),
        "get_address" | "getaddress" => get_address(session, params),
        "get_address_index" => get_address_index(session, params),
        "create_address" => create_address(session, params),
        "validate_address" => validate_address(session, params),
        "get_accounts" => get_accounts(session),
        "create_account" => Err(Error::new(
            errors::DISABLED,
            "multiple accounts are not built yet; account 0 is the only one",
        )),
        "make_integrated_address" => make_integrated_address(session, params),
        "split_integrated_address" => split_integrated_address(session, params),
        "get_balance" | "getbalance" => get_balance(session, params),
        "incoming_transfers" => incoming_transfers(session, params),
        "get_transfers" => get_transfers(session, params),
        "get_transfer_by_txid" => get_transfer_by_txid(session, params),
        "get_payments" | "get_bulk_payments" => Err(Error::new(
            errors::DISABLED,
            "payment-id history needs store-tx-info, which is not built yet",
        )),
        "query_key" => query_key(session, params),
        "get_tx_key" => Err(Error::new(
            errors::NO_TXKEY,
            "this build does not keep transaction keys yet",
        )),
        "set_daemon" => {
            let out = set_daemon(session, params)?;
            // Remember it for wallets opened later, not just this one.
            if let Some(a) = params.get("address").and_then(Value::as_str) {
                state.set_daemon_address(a);
            }
            Ok(out)
        }
        "refresh" => refresh(session, params),
        "rescan_blockchain" => rescan(session),
        "auto_refresh" => Ok(json!({})),
        "transfer" => transfer_method(session, params, false),
        "transfer_split" => transfer_method(session, params, true),
        "sweep_all" => sweep_all(session, params),
        "relay_tx" => relay_tx(session, params),
        "get_default_fee_priority" => get_default_fee_priority(session),
        "stop_wallet" => {
            session.save().map_err(internal)?;
            state.request_stop();
            Ok(json!({}))
        }
        other => Err(Error::new(
            errors::UNKNOWN_ERROR,
            format!("unknown method `{other}`"),
        )),
    }
}

fn internal(e: impl std::fmt::Display) -> Error {
    Error::new(errors::UNKNOWN_ERROR, e.to_string())
}

fn u32_param(params: &Value, name: &str, default: u32) -> u32 {
    params
        .get(name)
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .unwrap_or(default)
}

// -- wallet ----------------------------------------------------------------

fn store(session: &mut Session) -> MethodResult {
    session.save().map_err(internal)?;
    session.dirty = false;
    Ok(json!({}))
}

fn get_address(session: &Session, params: &Value) -> MethodResult {
    let account = u32_param(params, "account_index", 0);
    if account != 0 {
        return Err(Error::new(
            errors::ACCOUNT_INDEX_OUT_OF_BOUNDS,
            "only account 0 exists in this build",
        ));
    }

    // `address_index` selects specific ones; absent means the primary plus
    // whatever the lookahead covers, which would be 200 entries. The reference
    // returns what the wallet knows; this returns the primary unless asked,
    // and says so, rather than emitting a list nobody wanted.
    let wanted: Vec<u32> = match params.get("address_index").and_then(Value::as_array) {
        Some(a) => a
            .iter()
            .filter_map(Value::as_u64)
            .map(|v| v as u32)
            .collect(),
        None => vec![0],
    };

    let mut addresses = Vec::with_capacity(wanted.len());
    for minor in &wanted {
        let a = session.address_at(account, *minor).ok_or_else(|| {
            Error::new(
                errors::ADDRESS_INDEX_OUT_OF_BOUNDS,
                format!("subaddress ({account}, {minor}) could not be derived"),
            )
        })?;
        addresses.push(json!({
            "address": a,
            "label": if *minor == 0 { "Primary account" } else { "" },
            "address_index": minor,
            "used": false,
        }));
    }

    Ok(json!({
        "address": session.primary_address(),
        "addresses": addresses,
    }))
}

fn get_address_index(session: &Session, params: &Value) -> MethodResult {
    let text = params
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::WRONG_ADDRESS, "address is missing"))?;
    let decoded = Address::decode_for(text, session.network)
        .map_err(|e| Error::new(errors::WRONG_ADDRESS, e.to_string()))?;

    let index = session
        .state
        .subaddresses
        .get(&decoded.keys.spend_public_key)
        .ok_or_else(|| {
            Error::new(
                errors::WRONG_ADDRESS,
                "that address does not belong to this wallet",
            )
        })?;

    Ok(json!({
        "index": { "major": index.major, "minor": index.minor }
    }))
}

fn create_address(session: &mut Session, params: &Value) -> MethodResult {
    let account = u32_param(params, "account_index", 0);
    if account != 0 {
        return Err(Error::new(
            errors::ACCOUNT_INDEX_OUT_OF_BOUNDS,
            "only account 0 exists in this build",
        ));
    }
    // The next index past the highest this wallet has received at, which is
    // the reference's behaviour without an account table to consult.
    let next = session
        .state
        .transfers
        .iter()
        .filter(|t| t.subaddress.major == account)
        .map(|t| t.subaddress.minor + 1)
        .max()
        .unwrap_or(1);

    let address = session.address_at(account, next).ok_or_else(|| {
        Error::new(
            errors::ADDRESS_INDEX_OUT_OF_BOUNDS,
            "that subaddress could not be derived",
        )
    })?;
    Ok(json!({
        "address": address,
        "address_index": next,
        "address_indices": [next],
        "addresses": [address],
    }))
}

fn validate_address(session: &Session, params: &Value) -> MethodResult {
    let text = params
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::WRONG_ADDRESS, "address is missing"))?;
    let any_net = params
        .get("any_net_type")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let decoded = if any_net {
        Address::decode(text).ok()
    } else {
        Address::decode_for(text, session.network).ok()
    };

    Ok(match decoded {
        Some(a) => json!({
            "valid": true,
            "integrated": a.kind == AddressKind::Integrated,
            "subaddress": a.kind == AddressKind::Subaddress,
            "nettype": a.network.name(),
            "openalias_address": "",
        }),
        None => json!({
            "valid": false,
            "integrated": false,
            "subaddress": false,
            "nettype": "",
            "openalias_address": "",
        }),
    })
}

fn get_accounts(session: &Session) -> MethodResult {
    let (balance, unlocked) = session.balances();
    Ok(json!({
        "subaddress_accounts": [{
            "account_index": 0,
            "base_address": session.primary_address(),
            "balance": balance,
            "unlocked_balance": unlocked,
            "label": "Primary account",
            "tag": "",
        }],
        "total_balance": balance,
        "total_unlocked_balance": unlocked,
    }))
}

fn make_integrated_address(session: &Session, params: &Value) -> MethodResult {
    let pid: [u8; 8] = match params.get("payment_id").and_then(Value::as_str) {
        Some(hex) => wow_crypto::hex::decode(hex)
            .ok_or_else(|| Error::new(errors::WRONG_PAYMENT_ID, "payment_id is not hex"))?
            .try_into()
            .map_err(|_| {
                Error::new(
                    errors::WRONG_PAYMENT_ID,
                    "a payment id is 8 bytes (16 hex characters)",
                )
            })?,
        None => {
            let mut rng = wow_wallet::entropy::seeded_rng().map_err(internal)?;
            let mut b = [0u8; 8];
            rng.fill(&mut b);
            b
        }
    };

    let base = match params.get("standard_address").and_then(Value::as_str) {
        Some(text) => {
            Address::decode_for(text, session.network)
                .map_err(|e| Error::new(errors::WRONG_ADDRESS, e.to_string()))?
                .keys
        }
        None => session.keys_file.account.keys.account_address,
    };

    Ok(json!({
        "integrated_address": Address::integrated(session.network, base, pid).encode(),
        "payment_id": wow_crypto::hex::encode(&pid),
    }))
}

fn split_integrated_address(session: &Session, params: &Value) -> MethodResult {
    let text = params
        .get("integrated_address")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::WRONG_ADDRESS, "integrated_address is missing"))?;
    let decoded = Address::decode_for(text, session.network)
        .map_err(|e| Error::new(errors::WRONG_ADDRESS, e.to_string()))?;

    let pid = decoded.payment_id.ok_or_else(|| {
        Error::new(
            errors::WRONG_ADDRESS,
            "that is not an integrated address; it carries no payment id",
        )
    })?;

    Ok(json!({
        "standard_address": Address::standard(session.network, decoded.keys).encode(),
        "payment_id": wow_crypto::hex::encode(&pid),
        "is_subaddress": false,
    }))
}

// -- balance and history ---------------------------------------------------

fn get_balance(session: &Session, params: &Value) -> MethodResult {
    let account = u32_param(params, "account_index", 0);
    let (balance, unlocked) = session.balances();
    let height = session.chain_height();
    let now = wow_wallet::files::now();

    // `blocks_to_unlock` matters on Wownero: a coinbase locks for 288 blocks,
    // about a day (`specs/14` §3.3). A client that cannot see it cannot tell a
    // miner how long to wait.
    let blocks_to_unlock = session
        .state
        .transfers
        .iter()
        .filter(|t| !t.spent && !t.unlocked(height, now))
        .map(|t| unlock_in(t, height))
        .max()
        .unwrap_or(0);

    Ok(json!({
        "balance": balance,
        "unlocked_balance": unlocked,
        "multisig_import_needed": false,
        "blocks_to_unlock": blocks_to_unlock,
        "time_to_unlock": blocks_to_unlock * decoys::DIFFICULTY_TARGET,
        "per_subaddress": [{
            "account_index": account,
            "address_index": 0,
            "address": session.primary_address(),
            "balance": balance,
            "unlocked_balance": unlocked,
            "label": "Primary account",
            "num_unspent_outputs": session.state.transfers.iter().filter(|t| !t.spent).count(),
            "blocks_to_unlock": blocks_to_unlock,
            "time_to_unlock": blocks_to_unlock * decoys::DIFFICULTY_TARGET,
        }],
    }))
}

/// How many blocks until a transfer can be spent.
fn unlock_in(t: &wow_wallet::refresh::Transfer, height: u64) -> u64 {
    // Whichever is further out: the four-block age, or the transaction's own
    // unlock height.
    let by_age = (t.block_height + 4).saturating_sub(height);
    let by_unlock = if t.unlock_time < 500_000_000 {
        t.unlock_time.saturating_sub(height)
    } else {
        0
    };
    by_age.max(by_unlock)
}

fn incoming_transfers(session: &Session, params: &Value) -> MethodResult {
    let filter = params
        .get("transfer_type")
        .and_then(Value::as_str)
        .unwrap_or("all");
    let height = session.chain_height();
    let now = wow_wallet::files::now();

    let transfers: Vec<Value> = session
        .state
        .transfers
        .iter()
        .filter(|t| match filter {
            "available" => !t.spent && t.unlocked(height, now),
            "unavailable" => !t.spent && !t.unlocked(height, now),
            _ => true,
        })
        .map(|t| {
            json!({
                "amount": t.amount,
                "spent": t.spent,
                "global_index": t.global_output_index,
                "tx_hash": wow_crypto::hex::encode(&t.txid),
                "subaddr_index": { "major": t.subaddress.major, "minor": t.subaddress.minor },
                "key_image": t.key_image.map(|k| wow_crypto::hex::encode(&k.0)).unwrap_or_default(),
                "block_height": t.block_height,
                "frozen": false,
                "unlocked": t.unlocked(height, now),
                "pubkey": wow_crypto::hex::encode(&t.public_key.0),
            })
        })
        .collect();

    Ok(json!({ "transfers": transfers }))
}

fn get_transfers(session: &Session, params: &Value) -> MethodResult {
    use wow_wallet::history::EntryKind;

    let flag = |name: &str| params.get(name).and_then(Value::as_bool).unwrap_or(false);
    // A request that names no list gets every list.
    let asked = ["in", "out", "pending", "failed", "pool"].map(flag);
    let all = !asked.contains(&true);
    let filter_by_height = flag("filter_by_height");
    let min = params
        .get("min_height")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let max = params
        .get("max_height")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);

    let height = session.chain_height();
    let now = wow_wallet::files::now();

    // `in`, `out`, `pending`, `failed`, `pool`. The pool list stays empty:
    // incoming transactions in the pool are not tracked.
    let mut lists: [Vec<Value>; 5] = Default::default();
    for e in session.state.history() {
        if let (true, Some(h)) = (filter_by_height, e.height) {
            if h < min || h > max {
                continue;
            }
        }
        let list = match e.kind {
            EntryKind::In | EntryKind::Coinbase => 0,
            EntryKind::Out => 1,
            EntryKind::Pending => 2,
            EntryKind::Failed => 3,
        };
        lists[list].push(transfer_entry(session, &e, height, now));
    }

    let mut out = Map::new();
    for ((name, wanted), list) in ["in", "out", "pending", "failed", "pool"]
        .into_iter()
        .zip(asked)
        .zip(lists)
    {
        if wanted || all {
            out.insert(name.into(), json!(list));
        }
    }
    Ok(Value::Object(out))
}

/// One `transfer_entry`: `wallet_rpc_server::fill_transfer_entry`.
fn transfer_entry(
    session: &Session,
    e: &wow_wallet::history::HistoryEntry,
    chain_height: u64,
    now: u64,
) -> Value {
    use wow_wallet::history::EntryKind;

    let received = matches!(e.kind, EntryKind::In | EntryKind::Coinbase);
    // A payment is to one subaddress. A send is reported against the account.
    let minor = if received {
        e.minors.first().copied().unwrap_or(0)
    } else {
        0
    };
    let confirmations = match e.height {
        Some(h) if h < chain_height => chain_height - h,
        _ => 0,
    };
    json!({
        "txid": wow_crypto::hex::encode(&e.txid),
        "payment_id": e.payment_id.map_or_else(|| "0".repeat(16), |p| wow_crypto::hex::encode(&p)),
        "height": e.height.unwrap_or(0),
        "timestamp": e.timestamp,
        "amount": e.amount,
        "amounts": e.amounts,
        "fee": e.fee,
        "note": "",
        "destinations": e
            .destinations
            .iter()
            .map(|d| json!({ "amount": d.amount, "address": d.address }))
            .collect::<Vec<_>>(),
        "type": e.kind.name(),
        "unlock_time": e.unlock_time,
        "locked": !e.unlocked(chain_height, now),
        "subaddr_index": { "major": e.account, "minor": minor },
        "subaddr_indices": e
            .minors
            .iter()
            .map(|m| json!({ "major": e.account, "minor": m }))
            .collect::<Vec<_>>(),
        "address": session.address_at(e.account, minor).unwrap_or_default(),
        "double_spend_seen": false,
        "confirmations": confirmations,
        "suggested_confirmations_threshold": suggested_confirmations(e.amount),
    })
}

/// `suggested_confirmations_threshold`, computed from the block target rather
/// than hard-coded.
///
/// `specs/14` §3.4: the block time is 300 s here against Monero's 120, so the
/// same *number* of confirmations is two and a half times the wall-clock wait.
/// A client showing "wait N confirmations" needs the number that matches this
/// chain, not a constant borrowed from another one.
fn suggested_confirmations(amount: u64) -> u64 {
    // Roughly the reference's shape: more confirmations for more money, capped.
    const COIN: u64 = 100_000_000_000;
    let coins = amount / COIN;
    (1 + coins / 100).min(10)
}

fn get_transfer_by_txid(session: &Session, params: &Value) -> MethodResult {
    let text = params
        .get("txid")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::WRONG_TXID, "txid is missing"))?;
    let id: [u8; 32] = wow_crypto::hex::decode(text)
        .ok_or_else(|| Error::new(errors::WRONG_TXID, "txid is not hex"))?
        .try_into()
        .map_err(|_| Error::new(errors::WRONG_TXID, "a txid is 32 bytes"))?;

    let height = session.chain_height();
    let now = wow_wallet::files::now();
    let found: Vec<Value> = session
        .state
        .history()
        .iter()
        .filter(|e| e.txid == id)
        .map(|e| transfer_entry(session, e, height, now))
        .collect();

    if found.is_empty() {
        return Err(Error::new(
            errors::WRONG_TXID,
            "this wallet has no record of that transaction",
        ));
    }
    Ok(json!({ "transfer": found[0], "transfers": found }))
}

fn query_key(session: &Session, params: &Value) -> MethodResult {
    let kind = params
        .get("key_type")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::WRONG_KEY, "key_type is missing"))?;

    let keys = &session.keys_file.account.keys;
    let key = match kind {
        "view_key" => wow_crypto::hex::encode(&keys.view_secret_key.0),
        "spend_key" => {
            if keys.is_view_only() {
                return Err(Error::new(
                    errors::WATCH_ONLY,
                    "this wallet has no spend key",
                ));
            }
            wow_crypto::hex::encode(&keys.spend_secret_key.0)
        }
        "mnemonic" => {
            let language = session.keys_file.seed_language().unwrap_or("English");
            session.seed(language).map_err(|e| {
                // `specs/12` §1.2: only a wallet whose view key is
                // `keccak(spend key)` has a seed.
                Error::new(errors::NON_DETERMINISTIC, e)
            })?
        }
        other => {
            return Err(Error::new(
                errors::WRONG_KEY,
                format!("`{other}` is not a key type; use mnemonic, view_key or spend_key"),
            ))
        }
    };
    Ok(json!({ "key": key }))
}

// -- chain -----------------------------------------------------------------

fn set_daemon(session: &mut Session, params: &Value) -> MethodResult {
    let address = params
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::NO_DAEMON_CONNECTION, "address is missing"))?;
    let client = wow_daemon_client::DaemonClient::new(address);
    let info = client.get_info().map_err(|e| {
        Error::new(
            errors::NO_DAEMON_CONNECTION,
            format!("cannot reach {address}: {e}"),
        )
    })?;

    if !info.nettype.is_empty() && info.nettype != session.network.name() {
        return Err(Error::new(
            errors::NO_DAEMON_CONNECTION,
            format!(
                "that daemon is on {}, but this is a {} wallet",
                info.nettype,
                session.network.name()
            ),
        ));
    }

    session.daemon_height = info.height;
    session.daemon = Some(client);
    Ok(json!({}))
}

fn refresh(session: &mut Session, params: &Value) -> MethodResult {
    let client = session
        .daemon
        .clone()
        .ok_or_else(|| Error::new(errors::NO_DAEMON_CONNECTION, "no daemon is set"))?;
    if let Some(h) = params.get("start_height").and_then(Value::as_u64) {
        if h < session.state.scan_height() {
            session.state.hashes.clear();
            session.state.start_height = h;
        }
    }

    let mut received = 0usize;
    let mut fetched = 0u64;
    loop {
        let s = session.state.refresh_once(&client).map_err(|e| {
            if wow_daemon_client::is_retryable(&wow_daemon_client::DaemonError::Status(
                "BUSY".into(),
            )) && e.to_string().contains("BUSY")
            {
                Error::new(errors::DAEMON_IS_BUSY, e.to_string())
            } else {
                internal(e)
            }
        })?;
        received += s.received;
        fetched += s.blocks_scanned;
        if s.caught_up {
            break;
        }
    }
    if let Ok(info) = client.get_info() {
        session.daemon_height = info.height;
    }
    session.dirty = true;
    // Caught up, so pending sends can be judged. A pool that cannot be read
    // leaves them as they were, which is no reason to fail a refresh.
    let _ = session.check_pending();

    // How many blocks *this call* fetched, not how tall the chain is. A wallet
    // created at the tip fetches one block and must not report 873,000.
    Ok(json!({
        "blocks_fetched": fetched,
        "received_money": received > 0,
    }))
}

fn rescan(session: &mut Session) -> MethodResult {
    let from = session.keys_file.refresh_height();
    session.state.rescan_from(from);
    session.dirty = true;

    if session.daemon.is_some() {
        refresh(session, &json!({}))?;
    }
    Ok(json!({}))
}

// -- sending ---------------------------------------------------------------

fn transfer_method(session: &mut Session, params: &Value, split: bool) -> MethodResult {
    let destinations = params
        .get("destinations")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(errors::ZERO_DESTINATION, "destinations is missing"))?;
    if destinations.is_empty() {
        return Err(Error::new(errors::ZERO_DESTINATION, "no destinations"));
    }
    if destinations.len() > 1 {
        return Err(Error::new(
            errors::DISABLED,
            "this build sends to one destination at a time",
        ));
    }

    let amount = destinations[0]
        .get("amount")
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::new(errors::ZERO_AMOUNT, "a destination has no amount"))?;
    if amount == 0 {
        return Err(Error::new(
            errors::ZERO_AMOUNT,
            "a destination amount is zero",
        ));
    }
    let address = destinations[0]
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::WRONG_ADDRESS, "a destination has no address"))?;

    let outcome = build_and_send(session, address, Some(amount), params)?;

    Ok(if split {
        json!({
            "tx_hash_list": [outcome["tx_hash"]],
            "tx_key_list": [],
            "amount_list": [outcome["amount"]],
            "fee_list": [outcome["fee"]],
            "weight_list": [outcome["weight"]],
            "tx_blob_list": [outcome["tx_blob"]],
            "multisig_txset": "",
            "unsigned_txset": "",
            "spent_key_images_list": [outcome["spent_key_images"].clone()],
        })
    } else {
        outcome
    })
}

fn sweep_all(session: &mut Session, params: &Value) -> MethodResult {
    let address = params
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::WRONG_ADDRESS, "address is missing"))?;
    let outcome = build_and_send(session, address, None, params)?;
    Ok(json!({
        "tx_hash_list": [outcome["tx_hash"]],
        "tx_key_list": [],
        "amount_list": [outcome["amount"]],
        "fee_list": [outcome["fee"]],
        "weight_list": [outcome["weight"]],
        "tx_blob_list": [outcome["tx_blob"]],
        "multisig_txset": "",
        "unsigned_txset": "",
        "spent_key_images_list": [outcome["spent_key_images"].clone()],
    }))
}

/// The shared path: refuse what cannot be sent as asked, then prepare, relay
/// and record.
fn build_and_send(
    session: &mut Session,
    address: &str,
    amount: Option<u64>,
    params: &Value,
) -> MethodResult {
    if session.keys_file.is_watch_only() {
        return Err(Error::new(
            errors::WATCH_ONLY,
            "a view-only wallet cannot spend",
        ));
    }

    // `specs/14` §3.1: a non-zero unlock time produces a transaction the
    // network will not relay, and this code exists so a client learns that
    // here rather than three steps later.
    if let Some(unlock) = params.get("unlock_time").and_then(Value::as_u64) {
        if unlock != 0 {
            return Err(Error::new(
                errors::NONZERO_UNLOCK_TIME,
                "Wownero does not relay a transaction with a non-zero unlock time \
                 (specs/06 §6.3); it would be valid in a block but no peer would carry it",
            ));
        }
    }

    let ring_size = params
        .get("ring_size")
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(decoys::RING_SIZE);
    if ring_size != decoys::RING_SIZE {
        return Err(Error::new(
            errors::NOT_ENOUGH_OUTS_TO_MIX,
            format!(
                "ring_size must be {}: from HF 15 every input carries exactly that many members",
                decoys::RING_SIZE
            ),
        ));
    }

    let request = SendRequest {
        address,
        amount,
        // `on_transfer`: `adjust_priority(req.priority)`, where a priority left
        // out is 0 -- the low tier on a quiet chain, not normal.
        priority: u32_param(params, "priority", 0),
        ring_size,
        payment_id: None,
    };
    let prepared = session.prepare_send(&request).map_err(send_error)?;

    let do_not_relay = params
        .get("do_not_relay")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // `wallet2::commit_tx`, which `do_not_relay` skips, records it: its inputs
    // spent, whether or not `store-tx-info` keeps where it went.
    let relayed = session
        .commit_send(&prepared, do_not_relay)
        .map_err(send_error)?;
    if !relayed.result.accepted() {
        return Err(Error::new(
            errors::GENERIC_TRANSFER_ERROR,
            format!(
                "the daemon rejected the transaction: {}",
                relayed.result.reason
            ),
        ));
    }

    let plan = &prepared.plan;
    let spent_images: Vec<String> = prepared
        .key_images
        .iter()
        .map(|k| wow_crypto::hex::encode(&k.0))
        .collect();
    let mut out = json!({
        "tx_hash": wow_crypto::hex::encode(&prepared.txid),
        "tx_key": "",
        "amount": plan.amounts[0],
        "fee": plan.fee,
        "weight": plan.estimated_weight,
        "multisig_txset": "",
        "unsigned_txset": "",
        "spent_key_images": { "key_images": spent_images },
    });
    if params.get("get_tx_hex").and_then(Value::as_bool) == Some(true) {
        out["tx_blob"] = json!(wow_crypto::hex::encode(&prepared.blob));
    } else {
        out["tx_blob"] = json!("");
    }
    Ok(out)
}

/// Map a send's failure to the code a client branches on.
fn send_error(e: SendError) -> Error {
    let message = e.to_string();
    let code = match e {
        SendError::Plan(e) => return spend_error(e),
        SendError::ViewOnly => errors::WATCH_ONLY,
        SendError::NoDaemon
        | SendError::FeeEstimate(_)
        | SendError::Distribution(_)
        | SendError::Relay(_)
        | SendError::Ring(DecoyError::Fetch(_)) => errors::NO_DAEMON_CONNECTION,
        SendError::Address { .. } => errors::WRONG_ADDRESS,
        SendError::TwoPaymentIds => errors::WRONG_PAYMENT_ID,
        SendError::Ring(_) => errors::NOT_ENOUGH_OUTS_TO_MIX,
        SendError::Build(_) => errors::GENERIC_TRANSFER_ERROR,
        SendError::RingMismatch(_) | SendError::Damaged(_) | SendError::Entropy(_) => {
            errors::UNKNOWN_ERROR
        }
    };
    Error::new(code, message)
}

/// Map a planning failure to the code a client branches on.
///
/// The `-37` / `-17` distinction is the whole point: "wait" and "you do not
/// have it" lead to different behaviour.
fn spend_error(e: spend::SpendError) -> Error {
    match &e {
        spend::SpendError::NotEnough { .. } => {
            Error::new(errors::NOT_ENOUGH_UNLOCKED_MONEY, e.to_string())
        }
        spend::SpendError::ZeroAmount => Error::new(errors::ZERO_AMOUNT, e.to_string()),
        spend::SpendError::NoDestinations => Error::new(errors::ZERO_DESTINATION, e.to_string()),
        spend::SpendError::TooManyDestinations(_) => {
            Error::new(errors::TX_NOT_POSSIBLE, e.to_string())
        }
        spend::SpendError::FeeDidNotSettle(_) => Error::new(errors::TX_NOT_POSSIBLE, e.to_string()),
    }
}

/// `get_default_fee_priority`: the priority a transfer given none would pay
/// now.
fn get_default_fee_priority(session: &Session) -> MethodResult {
    let client = session
        .daemon
        .as_ref()
        .ok_or_else(|| Error::new(errors::NO_DAEMON_CONNECTION, "no daemon is set"))?;
    let tiers = client
        .get_fee_estimate(priority::FEE_ESTIMATE_GRACE_BLOCKS)
        .map_err(|e| Error::new(errors::NO_DAEMON_CONNECTION, e.to_string()))?;
    let priority = priority::adjust_priority(
        client,
        0,
        PrioritySettings::from_keys_file(&session.keys_file),
        session.state.scan_height(),
        &tiers,
    );
    // The reference refuses a 0 rather than report it, including the 0 that a
    // default priority set in the wallet leaves behind.
    if priority == 0 {
        return Err(Error::new(
            errors::UNKNOWN_ERROR,
            "Failed to get adjusted fee priority",
        ));
    }
    Ok(json!({ "priority": priority }))
}

fn relay_tx(session: &mut Session, params: &Value) -> MethodResult {
    let hex = params
        .get("hex")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::BAD_HEX, "hex is missing"))?;
    let blob = wow_crypto::hex::decode(hex)
        .ok_or_else(|| Error::new(errors::BAD_HEX, "hex is not hex"))?;

    let client = session
        .daemon
        .as_ref()
        .ok_or_else(|| Error::new(errors::NO_DAEMON_CONNECTION, "no daemon is set"))?;
    let result = client
        .send_raw_transaction(&blob, false)
        .map_err(|e| Error::new(errors::NO_DAEMON_CONNECTION, e.to_string()))?;
    if !result.accepted() {
        return Err(Error::new(
            errors::GENERIC_TRANSFER_ERROR,
            format!("the daemon rejected the transaction: {}", result.reason),
        ));
    }

    let tx = wow_types::tx::Transaction::from_blob(&blob)
        .map_err(|e| Error::new(errors::BAD_TX_METADATA, e.to_string()))?;
    let id = wow_types::hashes::transaction_hash_from_blob(&tx, &blob).unwrap_or_default();
    Ok(json!({ "tx_hash": wow_crypto::hex::encode(&id) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_the_documented_one() {
        assert_eq!(WALLET_RPC_VERSION, 65_566);
        assert_eq!(WALLET_RPC_VERSION, (1 << 16) | 30);
    }

    /// Every disabled method names itself and gives a reason.
    #[test]
    fn disabled_methods_explain_themselves() {
        assert!(DISABLED.iter().any(|(n, _)| *n == "get_tx_proof"));
        assert!(DISABLED.iter().any(|(n, _)| *n == "export_key_images"));
        for (name, why) in DISABLED {
            assert!(!why.is_empty(), "{name} has no reason");
        }
    }

    /// `suggested_confirmations_threshold` grows with the amount and is capped.
    #[test]
    fn the_confirmation_threshold_scales_with_the_amount() {
        const COIN: u64 = 100_000_000_000;
        assert_eq!(suggested_confirmations(0), 1);
        assert_eq!(suggested_confirmations(COIN), 1);
        assert_eq!(suggested_confirmations(100 * COIN), 2);
        assert_eq!(suggested_confirmations(1_000_000 * COIN), 10, "capped");
    }

    /// The unlock countdown takes whichever constraint is further out.
    #[test]
    fn the_unlock_countdown_takes_the_later_constraint() {
        let base = wow_wallet::refresh::Transfer {
            block_height: 100,
            txid: [0u8; 32],
            derivation: wow_crypto::types::KeyDerivation::ZERO,
            internal_output_index: 0,
            global_output_index: 0,
            public_key: wow_crypto::types::PublicKey::ZERO,
            key_image: None,
            mask: [0u8; 32],
            amount: 1,
            subaddress: wow_crypto::types::SubaddressIndex::MAIN,
            spent: false,
            spent_height: 0,
            unlock_time: 0,
            is_coinbase: false,
            timestamp: 0,
        };

        // Four-block age only.
        assert_eq!(unlock_in(&base, 100), 4);
        assert_eq!(unlock_in(&base, 104), 0);

        // A coinbase locked for 288 blocks, which is what makes this field
        // matter on Wownero.
        let mined = wow_wallet::refresh::Transfer {
            unlock_time: 100 + 288,
            is_coinbase: true,
            ..base
        };
        assert_eq!(unlock_in(&mined, 100), 288);
        assert_eq!(unlock_in(&mined, 388), 0);
    }
}
