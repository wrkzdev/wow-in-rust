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
    // The name only: parameters can be a password, a seed or a key.
    wow_log::debug!("wallet.rpc", "{method}");
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
        "freeze" => freeze_thaw(session, params, true),
        "thaw" => freeze_thaw(session, params, false),
        "frozen" => frozen(session, params),
        "get_transfers" => get_transfers(session, params),
        "get_transfer_by_txid" => get_transfer_by_txid(session, params),
        "get_payments" => get_payments(session, params),
        "get_bulk_payments" => get_bulk_payments(session, params),
        "query_key" => query_key(session, params),
        "get_tx_key" => Err(Error::new(
            errors::NO_TXKEY,
            "this build does not keep transaction keys yet",
        )),
        "set_daemon" => {
            let out = set_daemon(session, params, state.has_proxy_option())?;
            // Remember it for wallets opened later, not just this one.
            if let Some(a) = params.get("address").and_then(Value::as_str) {
                state.set_daemon_address(a);
            }
            state.set_daemon_options(session.daemon_options.clone());
            state.set_trusted_daemon(Some(session.state.trusted_daemon));
            Ok(out)
        }
        "refresh" => refresh(session, params),
        "rescan_blockchain" => rescan(session),
        "auto_refresh" => Ok(json!({})),
        "transfer" => transfer_method(session, params, false),
        "transfer_split" => transfer_method(session, params, true),
        "sweep_all" => sweep_all(session, params),
        "sweep_single" => sweep_single(session, params),
        "relay_tx" => relay_tx(session, params),
        "export_outputs" => export_outputs(session, params),
        "import_outputs" => import_outputs(session, params),
        "export_key_images" => export_key_images(session, params),
        "import_key_images" => import_key_images(session, params),
        "sign_transfer" => sign_transfer(session, params),
        "submit_transfer" => submit_transfer(session, params),
        "describe_transfer" => describe_transfer(session, params),
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
                "frozen": t.frozen,
                "unlocked": t.unlocked(height, now),
                "pubkey": wow_crypto::hex::encode(&t.public_key.0),
            })
        })
        .collect();

    Ok(json!({ "transfers": transfers }))
}

/// `on_freeze` and `on_thaw`: set one output aside by its key image, so that
/// nothing spends it and no balance counts it, or give it back.
///
/// The response carries nothing, as `COMMAND_RPC_FREEZE::response` does.
fn freeze_thaw(session: &mut Session, params: &Value, freeze: bool) -> MethodResult {
    let key_image = key_image_param(params, if freeze { "freeze" } else { "thaw" })?;
    let outcome = if freeze {
        session.state.freeze(&key_image)
    } else {
        session.state.thaw(&key_image)
    };
    // `handle_rpc_exception(..., WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR)`: what
    // `wallet2::get_transfer_details` throws has no code of its own.
    outcome.map_err(|e| Error::new(errors::UNKNOWN_ERROR, e))?;
    // As in the CLI: the flag is written out by the next `store`, which the
    // C++ RPC also leaves to its caller.
    session.dirty = true;
    Ok(json!({}))
}

/// `on_frozen`: whether one output is set aside.
fn frozen(session: &Session, params: &Value) -> MethodResult {
    let key_image = key_image_param(params, "check if frozen")?;
    let frozen = session
        .state
        .frozen(&key_image)
        .map_err(|e| Error::new(errors::UNKNOWN_ERROR, e))?;
    Ok(json!({ "frozen": frozen }))
}

/// `key_image`, as `freeze`, `thaw` and `frozen` take it.
///
/// Absent or empty is `-1` with the C++'s wording, which names the method
/// (`"Must specify key image to freeze"`); anything else that is not 64 hex
/// characters is `-10 WRONG_KEY_IMAGE`.
fn key_image_param(params: &Value, what: &str) -> Result<wow_crypto::types::KeyImage, Error> {
    let text = params
        .get("key_image")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if text.is_empty() {
        return Err(Error::new(
            errors::UNKNOWN_ERROR,
            format!("Must specify key image to {what}"),
        ));
    }
    wow_crypto::hex::decode(text)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(wow_crypto::types::KeyImage)
        .ok_or_else(|| Error::new(errors::WRONG_KEY_IMAGE, "failed to parse key image"))
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

/// `on_get_payments`: the payments received with one payment id.
fn get_payments(session: &Session, params: &Value) -> MethodResult {
    let text = params
        .get("payment_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let key = payment_key_param(text)?;

    let height = session.chain_height();
    let now = wow_wallet::files::now();
    let payments: Vec<Value> = session
        .state
        .payments(0)
        .iter()
        .filter(|e| wow_wallet::history::payment_key(e.payment_id) == key)
        .map(|e| payment_details(session, e, text, height, now))
        .collect();
    Ok(json!({ "payments": payments }))
}

/// `on_get_bulk_payments`: the payments received with any of `payment_ids`,
/// or every payment when it is empty, in blocks above `min_block_height`.
fn get_bulk_payments(session: &Session, params: &Value) -> MethodResult {
    let min_height = params
        .get("min_block_height")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let ids: Vec<&str> = params
        .get("payment_ids")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let height = session.chain_height();
    let now = wow_wallet::files::now();
    let received = session.state.payments(min_height);

    let mut payments = Vec::new();
    if ids.is_empty() {
        // Each under its whole key, 64 characters, as the C++ prints it here.
        for e in &received {
            let key = wow_crypto::hex::encode(&wow_wallet::history::payment_key(e.payment_id));
            payments.push(payment_details(session, e, &key, height, now));
        }
    }
    for text in ids {
        let key = payment_key_param(text)?;
        for e in received
            .iter()
            .filter(|e| wow_wallet::history::payment_key(e.payment_id) == key)
        {
            payments.push(payment_details(session, e, text, height, now));
        }
    }
    Ok(json!({ "payments": payments }))
}

/// A payment id a request names, as the key payments are filed under.
fn payment_key_param(text: &str) -> Result<[u8; 32], Error> {
    wow_wallet::history::parse_payment_key(text).ok_or_else(|| {
        Error::new(
            errors::WRONG_PAYMENT_ID,
            format!("`{text}` is not a payment id: 16 or 64 hex characters"),
        )
    })
}

/// One `payment_details`, reported under `payment_id`.
fn payment_details(
    session: &Session,
    e: &wow_wallet::history::HistoryEntry,
    payment_id: &str,
    chain_height: u64,
    now: u64,
) -> Value {
    let minor = e.minors.first().copied().unwrap_or(0);
    json!({
        "payment_id": payment_id,
        "tx_hash": wow_crypto::hex::encode(&e.txid),
        "amount": e.amount,
        "block_height": e.height.unwrap_or(0),
        "unlock_time": e.unlock_time,
        "locked": !e.unlocked(chain_height, now),
        "subaddr_index": { "major": e.account, "minor": minor },
        "address": session.address_at(e.account, minor).unwrap_or_default(),
    })
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

/// `set_daemon`'s TLS parameters, by the C++'s names.
const SSL_PARAMS: [&str; 6] = [
    "ssl_support",
    "ssl_private_key_path",
    "ssl_certificate_path",
    "ssl_ca_file",
    "ssl_allowed_fingerprints",
    "ssl_allow_any_cert",
];

fn set_daemon(session: &mut Session, params: &Value, proxy_option: bool) -> MethodResult {
    if session.offline {
        return Err(Error::new(
            errors::NO_DAEMON_CONNECTION,
            "this server was started with --offline and will not connect to a daemon",
        ));
    }
    let address = params
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::NO_DAEMON_CONNECTION, "address is missing"))?;
    // `proxy`: one for this daemon alone, which `--proxy` rules out, as
    // `on_set_daemon` rules it out.
    let proxy = match params
        .get("proxy")
        .and_then(Value::as_str)
        .filter(|p| !p.is_empty())
    {
        Some(_) if proxy_option => {
            return Err(Error::new(
                errors::PROXY_ALREADY_DEFINED,
                "It is not possible to set daemon specific proxy when --proxy is defined.",
            ))
        }
        Some(text) => {
            let proxy = wow_daemon_client::Proxy::parse(text)
                .map_err(|e| Error::new(errors::NO_DAEMON_CONNECTION, e))?;
            let mut token = [0u8; 16];
            wow_wallet::entropy::seeded_rng()
                .map_err(internal)?
                .fill(&mut token);
            Some(proxy.isolated(&token))
        }
        None => None,
    };
    // A request that names none of the TLS parameters keeps how the node is
    // reached now: what the server was started with, which its own
    // `set_daemon` at startup does not repeat. Taken on only once the node
    // has answered, so a refused request changes nothing.
    let mut options = if SSL_PARAMS.iter().any(|p| params.get(*p).is_some()) {
        daemon_options(params, address)?
    } else {
        session.daemon_options.clone()
    };
    options.proxy = if proxy_option {
        session.daemon_options.proxy.clone()
    } else {
        proxy
    };
    let kept = std::mem::replace(&mut session.daemon_options, options);
    let client = session.client_for(address);
    let options = std::mem::replace(&mut session.daemon_options, kept);
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
    session.daemon_options = options;
    // `trusted`, false unless given, as `wallet2::set_daemon` takes it.
    session.state.trusted_daemon = params
        .get("trusted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(json!({}))
}

/// `on_set_daemon`'s TLS parameters, made sense of as it makes sense of them:
/// `ssl_support` is `autodetect` unless given, and a CA file or fingerprints
/// accept only what they name.
fn daemon_options(
    params: &Value,
    address: &str,
) -> Result<wow_daemon_client::ConnectOptions, Error> {
    let text = |name: &str| {
        params
            .get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    };
    let path = |name: &str| text(name).map(std::path::PathBuf::from);
    let flags = wow_daemon_client::SslFlags {
        ssl: Some(text("ssl_support").unwrap_or("autodetect").to_string()),
        private_key: path("ssl_private_key_path"),
        certificate: path("ssl_certificate_path"),
        ca_certificates: path("ssl_ca_file"),
        allowed_fingerprints: params
            .get("ssl_allowed_fingerprints")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        allow_any_cert: params
            .get("ssl_allow_any_cert")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        allow_chained: false,
    };
    let options = wow_daemon_client::ConnectOptions::from_flags(&flags)
        .map_err(|e| Error::new(errors::NO_DAEMON_CONNECTION, e))?;
    if options.lacks_strong_verification(address) {
        return Err(Error::new(
            errors::NO_DAEMON_CONNECTION,
            "SSL is enabled but no user certificate or fingerprints were provided",
        ));
    }
    Ok(options)
}

fn refresh(session: &mut Session, params: &Value) -> MethodResult {
    // `wallet2::refresh` returns straight away when `m_offline` is set,
    // reporting nothing fetched rather than failing.
    if session.offline {
        return Ok(json!({ "blocks_fetched": 0, "received_money": false }));
    }
    let client = session
        .daemon
        .clone()
        .ok_or_else(|| Error::new(errors::NO_DAEMON_CONNECTION, "no daemon is set"))?;
    if let Some(h) = params.get("start_height").and_then(Value::as_u64) {
        if h < session.state.scan_height() {
            session.state.hashes.clear();
            session.state.start_height = h;
            // Scanned from there, whatever the restore height; the hashes
            // below it are listed again from where every wallet's begin.
            session.state.refresh_from_height = h;
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
            "tx_metadata_list": [outcome["tx_metadata"]],
            "multisig_txset": "",
            "unsigned_txset": "",
            "spent_key_images_list": [outcome["spent_key_images"].clone()],
        })
    } else {
        outcome
    })
}

/// `sweep_single`: one output, named by its key image.
fn sweep_single(session: &mut Session, params: &Value) -> MethodResult {
    let address = params
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::WRONG_ADDRESS, "address is missing"))?;
    // `WRONG_KEY_IMAGE` for both, as the reference: a missing `key_image` is
    // an empty string to it, and fails the same parse.
    let image_text = params
        .get("key_image")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::WRONG_KEY_IMAGE, "key_image is missing"))?;
    let image: [u8; 32] = wow_crypto::hex::decode(image_text)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Error::new(errors::WRONG_KEY_IMAGE, "key_image is 64 hex characters"))?;

    // One transaction, and answered as one: `COMMAND_RPC_SWEEP_SINGLE`'s
    // response has `tx_hash`, `fee` and the rest, not lists of them.
    let mut outcome = build_and_send_output(
        session,
        address,
        Some(wow_crypto::types::KeyImage(image)),
        params,
    )?;
    if let Some(fields) = outcome.as_object_mut() {
        fields.remove("outputs_left_behind");
    }
    Ok(outcome)
}

fn sweep_all(session: &mut Session, params: &Value) -> MethodResult {
    let address = params
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::WRONG_ADDRESS, "address is missing"))?;
    let outcome = build_and_send_output(session, address, None, params)?;
    Ok(json!({
        "tx_hash_list": [outcome["tx_hash"]],
        "tx_key_list": [],
        "amount_list": [outcome["amount"]],
        "fee_list": [outcome["fee"]],
        "weight_list": [outcome["weight"]],
        "tx_blob_list": [outcome["tx_blob"]],
        "tx_metadata_list": [outcome["tx_metadata"]],
        "multisig_txset": "",
        "unsigned_txset": "",
        "spent_key_images_list": [outcome["spent_key_images"].clone()],
        // See `build_and_send`: non-zero means this swept as much as one
        // transaction can carry and `sweep_all` should be called again.
        "outputs_left_behind": outcome["outputs_left_behind"],
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
    build_and_send_inner(session, address, amount, None, params)
}

/// [`build_and_send`] for a sweep of one named output.
fn build_and_send_output(
    session: &mut Session,
    address: &str,
    sweep_output: Option<wow_crypto::types::KeyImage>,
    params: &Value,
) -> MethodResult {
    build_and_send_inner(session, address, None, sweep_output, params)
}

fn build_and_send_inner(
    session: &mut Session,
    address: &str,
    amount: Option<u64>,
    sweep_output: Option<wow_crypto::types::KeyImage>,
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

    // `account_index` and `subaddr_indices`, as `create_transactions_2` and
    // `_all` take them. `subaddr_indices_all` names every index in the account,
    // and the ones holding outputs are all that can matter.
    let account = u32_param(params, "account_index", 0);
    let subaddr_indices: Vec<u32> =
        if params.get("subaddr_indices_all").and_then(Value::as_bool) == Some(true) {
            let all: std::collections::BTreeSet<u32> = session
                .state
                .transfers
                .iter()
                .filter(|t| t.subaddress.major == account)
                .map(|t| t.subaddress.minor)
                .collect();
            all.into_iter().collect()
        } else {
            params
                .get("subaddr_indices")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_u64)
                        .map(|i| i as u32)
                        .collect()
                })
                .unwrap_or_default()
        };

    let request = SendRequest {
        address,
        amount,
        // `on_transfer`: `adjust_priority(req.priority)`, where a priority left
        // out is 0 -- the low tier on a quiet chain, not normal.
        priority: u32_param(params, "priority", 0),
        ring_size,
        payment_id: None,
        sweep_output,
        account,
        subaddr_indices,
        below_amount: params
            .get("below_amount")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    };
    let prepared = session.prepare_send(&request).map_err(send_error)?;

    let flag = |name: &str| params.get(name).and_then(Value::as_bool) == Some(true);
    // `wallet_rpc_server::fill_response`: `do_not_relay` skips
    // `wallet2::commit_tx` entirely. No node is shown the transaction, not
    // even to check it, and nothing is recorded: its inputs stay unspent, and
    // `relay_tx` is how it is sent later. Otherwise `commit_tx` relays it and
    // records it, its inputs spent whether or not `store-tx-info` keeps where
    // it went.
    if !flag("do_not_relay") {
        let relayed = session.commit_send(&prepared).map_err(send_error)?;
        if !relayed.result.accepted() {
            return Err(Error::new(
                errors::GENERIC_TRANSFER_ERROR,
                format!(
                    "the daemon rejected the transaction: {}",
                    relayed.result.reason
                ),
            ));
        }
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
        // Not a C++ field. The reference's `sweep_all` splits across as many
        // transactions as it needs and returns them all; this builds one, so a
        // client has to be told when there is more to take. Zero on every
        // other call.
        "outputs_left_behind": plan.left_behind,
    });
    // Each only when asked for, as `fill_response` fills them.
    let blob_hex = wow_crypto::hex::encode(&prepared.blob);
    let tx_blob = if flag("get_tx_hex") {
        blob_hex.as_str()
    } else {
        ""
    };
    // The C++ writes its own `pending_tx` here, which only a C++ wallet can
    // read back. This build's `relay_tx` takes the transaction itself, so
    // that is what its metadata is.
    let tx_metadata = if flag("get_tx_metadata") {
        blob_hex.as_str()
    } else {
        ""
    };
    out["tx_blob"] = json!(tx_blob);
    out["tx_metadata"] = json!(tx_metadata);
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
        SendError::TwoPaymentIds | SendError::PaymentIdToSubaddress => errors::WRONG_PAYMENT_ID,
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
        // A transaction no node would relay, and a sweep_single naming an
        // output this wallet cannot spend: all of them are "not possible"
        // rather than a bad parameter, because the request was well formed and
        // the wallet is what cannot satisfy it.
        spend::SpendError::TooHeavy { .. }
        | spend::SpendError::NoSuchOutput
        | spend::SpendError::OutputSpent
        | spend::SpendError::OutputLocked
        | spend::SpendError::NothingToSpend => Error::new(errors::TX_NOT_POSSIBLE, e.to_string()),
        // An exception from inside `transfer_selected_rct`, which
        // `handle_rpc_exception` reports under the transfer's default code.
        spend::SpendError::MultipleAccounts => {
            Error::new(errors::GENERIC_TRANSFER_ERROR, e.to_string())
        }
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

/// `relay_tx`: send what a `do_not_relay` transfer handed back, and record it
/// as `wallet2::commit_tx` does.
///
/// `hex` is that transfer's `tx_metadata`, which in this build is the
/// transaction itself. It is parsed before any node is asked, as the C++
/// parses its metadata first. Once a node has taken it, it is recorded as a
/// spend of this wallet's outputs waiting for a block, the way one found in
/// the pool is: its inputs spent from now, its change counted by scanning it,
/// and its inputs given back if it never reaches a block. Where it went is
/// not known here, because the metadata does not say.
fn relay_tx(session: &mut Session, params: &Value) -> MethodResult {
    let hex = params
        .get("hex")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::BAD_HEX, "hex is missing"))?;
    let blob = wow_crypto::hex::decode(hex)
        .ok_or_else(|| Error::new(errors::BAD_HEX, "Failed to parse hex."))?;
    let tx = wow_types::tx::Transaction::from_blob(&blob)
        .map_err(|e| Error::new(errors::BAD_TX_METADATA, e.to_string()))?;
    let id = wow_types::hashes::transaction_hash_from_blob(&tx, &blob)
        .ok_or_else(|| Error::new(errors::BAD_TX_METADATA, "Failed to parse tx metadata."))?;

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

    let now = wow_wallet::files::now();
    let sent = wow_wallet::PooledTx {
        txid: id,
        tx,
        receive_time: now,
    };
    session
        .state
        .note_pool_spends(std::slice::from_ref(&sent), now);
    session.dirty = true;
    Ok(json!({ "tx_hash": wow_crypto::hex::encode(&id) }))
}

// -- cold signing ----------------------------------------------------------

/// `export_outputs`: `all`, `start`, `count` in, `outputs_data_hex` out.
///
/// The hex is the whole file, magic and all, as `export_outputs_to_str`
/// returns it — so a caller can write it to disk and a C++ wallet will read
/// it.
fn export_outputs(session: &mut Session, params: &Value) -> MethodResult {
    let all = params.get("all").and_then(Value::as_bool).unwrap_or(false);
    let start = u32_param(params, "start", 0);
    let count = u32_param(params, "count", u32::MAX);
    let blob = session
        .export_outputs_to_file(all, start, count)
        .map_err(offline_error)?;
    Ok(json!({ "outputs_data_hex": wow_crypto::hex::encode(&blob) }))
}

/// `import_outputs`: `outputs_data_hex` in, `num_imported` out.
fn import_outputs(session: &mut Session, params: &Value) -> MethodResult {
    let blob = hex_param(params, "outputs_data_hex")?;
    let n = session
        .import_outputs_from_file(&blob)
        .map_err(offline_error)?;
    session.save().map_err(internal)?;
    session.dirty = false;
    Ok(json!({ "num_imported": n }))
}

/// `export_key_images`: `all` in, `offset` and `signed_key_images` out.
///
/// This one does **not** go through the file container: the reference's
/// handler calls `export_key_images(req.all)` and hexes each pair, so there is
/// no magic, no encryption and no four-byte offset header — the offset is a
/// plain JSON number.
fn export_key_images(session: &mut Session, params: &Value) -> MethodResult {
    let all = params.get("all").and_then(Value::as_bool).unwrap_or(false);
    let exported = session.export_key_images(all).map_err(offline_error)?;
    let images: Vec<Value> = exported
        .images
        .iter()
        .map(|i| {
            json!({
                "key_image": wow_crypto::hex::encode(&i.key_image.0),
                "signature": wow_crypto::hex::encode(&i.signature.to_bytes()),
            })
        })
        .collect();
    Ok(json!({ "offset": exported.offset, "signed_key_images": images }))
}

/// `import_key_images`: `offset` and `signed_key_images` in, `height`, `spent`
/// and `unspent` out.
fn import_key_images(session: &mut Session, params: &Value) -> MethodResult {
    let offset = u32_param(params, "offset", 0) as usize;
    let list = params
        .get("signed_key_images")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Error::new(
                errors::WRONG_KEY_IMAGE,
                "signed_key_images is missing or not a list",
            )
        })?;

    let mut images = Vec::with_capacity(list.len());
    for entry in list {
        let key_image = entry
            .get("key_image")
            .and_then(Value::as_str)
            .and_then(wow_crypto::hex::decode)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(wow_crypto::types::KeyImage)
            .ok_or_else(|| Error::new(errors::WRONG_KEY_IMAGE, "failed to parse key image"))?;
        let signature = entry
            .get("signature")
            .and_then(Value::as_str)
            .and_then(wow_crypto::hex::decode)
            .and_then(|b| wow_crypto::types::Signature::from_slice(&b))
            .ok_or_else(|| Error::new(errors::WRONG_SIGNATURE, "failed to parse signature"))?;
        images.push(wow_wallet::cold::SignedKeyImage {
            key_image,
            signature,
        });
    }

    let imported = session
        .import_key_images(&images, offset, true)
        .map_err(offline_error)?;
    session.save().map_err(internal)?;
    session.dirty = false;
    Ok(json!({
        "height": imported.height,
        "spent": imported.spent,
        "unspent": imported.unspent,
    }))
}

/// `sign_transfer`: `unsigned_txset` in, `signed_txset`, `tx_hash_list`,
/// `tx_raw_list` and `tx_key_list` out.
fn sign_transfer(session: &mut Session, params: &Value) -> MethodResult {
    if session.keys_file.is_watch_only() {
        return Err(Error::new(
            errors::WATCH_ONLY,
            "command not supported by watch-only wallet",
        ));
    }
    let blob = hex_param(params, "unsigned_txset")?;
    let export_raw = params
        .get("export_raw")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let get_tx_keys = params
        .get("get_tx_keys")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let set = session.load_unsigned(&blob).map_err(|e| {
        Error::new(
            errors::BAD_UNSIGNED_TX_DATA,
            format!("cannot load unsigned_txset: {e}"),
        )
    })?;
    // No confirmation on this path: `on_sign_transfer` passes no accept
    // callback, because there is nobody at the other end of one.
    let signed = session.sign_unsigned(&set).map_err(|e| {
        Error::new(
            errors::SIGN_UNSIGNED,
            format!("Failed to sign unsigned tx: {e}"),
        )
    })?;
    session.save().map_err(internal)?;
    session.dirty = false;

    let hashes: Vec<String> = signed
        .txids
        .iter()
        .map(|t| wow_crypto::hex::encode(t))
        .collect();
    let raw: Vec<String> = if export_raw {
        signed
            .raw
            .iter()
            .map(|b| wow_crypto::hex::encode(b))
            .collect()
    } else {
        Vec::new()
    };
    // One entry per transaction: its key, and then its per-output keys,
    // concatenated as the reference concatenates them.
    let keys: Vec<String> = if get_tx_keys {
        signed
            .tx_keys
            .iter()
            .map(|ks| {
                ks.iter()
                    .map(|k| wow_crypto::hex::encode(&k.0))
                    .collect::<String>()
            })
            .collect()
    } else {
        Vec::new()
    };

    Ok(json!({
        "signed_txset": wow_crypto::hex::encode(&signed.blob),
        "tx_hash_list": hashes,
        "tx_raw_list": raw,
        "tx_key_list": keys,
    }))
}

/// `submit_transfer`: `tx_data_hex` in, `tx_hash_list` out.
fn submit_transfer(session: &mut Session, params: &Value) -> MethodResult {
    let blob = hex_param(params, "tx_data_hex")?;
    let set = session.load_signed(&blob).map_err(|e| {
        Error::new(
            errors::BAD_SIGNED_TX_DATA,
            format!("Failed to parse signed tx: {e}"),
        )
    })?;
    let submitted = session.submit_signed(&set).map_err(|e| {
        Error::new(
            errors::SIGNED_SUBMISSION,
            format!("Failed to submit signed tx: {e}"),
        )
    })?;
    session.save().map_err(internal)?;
    session.dirty = false;

    // A node that refused one of them is an error, not a hash list with a gap
    // in it: the reference's `commit_tx` throws, and this is the same answer.
    if let Some(bad) = submitted.results.iter().find(|r| !r.accepted()) {
        return Err(Error::new(
            errors::SIGNED_SUBMISSION,
            format!("Failed to submit signed tx: {}", bad.reason),
        ));
    }
    let hashes: Vec<String> = submitted
        .txids
        .iter()
        .map(|t| wow_crypto::hex::encode(t))
        .collect();
    Ok(json!({ "tx_hash_list": hashes }))
}

/// `describe_transfer`: `unsigned_txset` in, `summary` and `desc` out.
fn describe_transfer(session: &mut Session, params: &Value) -> MethodResult {
    if params
        .get("multisig_txset")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
    {
        return Err(Error::new(
            errors::BAD_MULTISIG_TX_DATA,
            "cannot load multisig_txset: multisig is not built",
        ));
    }
    let hex = params
        .get("unsigned_txset")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if hex.is_empty() {
        return Err(Error::new(errors::UNKNOWN_ERROR, "no txset provided"));
    }
    let blob = wow_crypto::hex::decode(hex)
        .ok_or_else(|| Error::new(errors::BAD_HEX, "Failed to parse hex."))?;
    let set = session.load_unsigned(&blob).map_err(|e| {
        Error::new(
            errors::BAD_UNSIGNED_TX_DATA,
            format!("cannot load unsigned_txset: {e}"),
        )
    })?;
    let described = session.describe(&set.txes).map_err(|e| {
        Error::new(
            errors::BAD_UNSIGNED_TX_DATA,
            format!("failed to parse unsigned transfers: {e}"),
        )
    })?;

    let recipients = |rs: &[wow_wallet::offline::DescribedRecipient]| -> Vec<Value> {
        rs.iter()
            .map(|r| json!({ "address": r.address, "amount": r.amount }))
            .collect()
    };
    let desc: Vec<Value> = described
        .txs
        .iter()
        .map(|d| {
            json!({
                "amount_in": d.amount_in,
                "amount_out": d.amount_out,
                "ring_size": d.ring_size,
                "unlock_time": d.unlock_time,
                "sources": d
                    .sources
                    .iter()
                    .map(|s| json!({
                        "amount": s.amount,
                        "global_index": s.global_index,
                        "rct": s.rct,
                        "pubkey": wow_crypto::hex::encode(&s.public_key.0),
                    }))
                    .collect::<Vec<_>>(),
                "recipients": recipients(&d.recipients),
                "payment_id": d.payment_id,
                "change_amount": d.change_amount,
                "change_address": d.change_address,
                "fee": d.fee,
                "dummy_outputs": d.dummy_outputs,
                "extra": wow_crypto::hex::encode(&d.extra),
            })
        })
        .collect();

    Ok(json!({
        "summary": {
            "amount_in": described.summary.amount_in,
            "amount_out": described.summary.amount_out,
            "recipients": recipients(&described.summary.recipients),
            "change_amount": described.summary.change_amount,
            "change_address": described.summary.change_address,
            "fee": described.summary.fee,
        },
        "desc": desc,
    }))
}

/// A required hex parameter, refused with `-26 BAD_HEX` as the reference
/// refuses one: "Failed to parse hex."
fn hex_param(params: &Value, name: &str) -> Result<Vec<u8>, Error> {
    let text = params
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(errors::BAD_HEX, format!("{name} is missing")))?;
    wow_crypto::hex::decode(text).ok_or_else(|| Error::new(errors::BAD_HEX, "Failed to parse hex."))
}

/// Map a cold-signing failure to the code a client branches on.
fn offline_error(e: wow_wallet::offline::OfflineError) -> Error {
    use wow_wallet::offline::OfflineError as E;
    let message = e.to_string();
    let code = match e {
        E::WatchOnly => errors::WATCH_ONLY,
        // The reference's own wording for the untrusted case is
        // "This command requires a trusted daemon.", under -1.
        E::UntrustedDaemon => errors::UNKNOWN_ERROR,
        E::NoDaemon | E::Daemon(_) => errors::NO_DAEMON_CONNECTION,
        E::Cold(_) | E::HotWallet => errors::BAD_UNSIGNED_TX_DATA,
        E::KeyImageDomain(..) => errors::WRONG_KEY_IMAGE,
        E::BadSignature(..) => errors::WRONG_SIGNATURE,
        E::ChangeNotPaid | E::ChangeTooLarge | E::ChangeToManyAddresses => {
            errors::BAD_UNSIGNED_TX_DATA
        }
        E::NonzeroUnlockTime => errors::NONZERO_UNLOCK_TIME,
        E::Send(e) => return send_error(e),
        _ => errors::UNKNOWN_ERROR,
    };
    Error::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_the_documented_one() {
        assert_eq!(WALLET_RPC_VERSION, 65_566);
        assert_eq!(WALLET_RPC_VERSION, (1 << 16) | 30);
    }

    /// Every disabled method names itself and gives a reason, and the
    /// cold-signing ones are not among them any more.
    #[test]
    fn disabled_methods_explain_themselves() {
        assert!(DISABLED.iter().any(|(n, _)| *n == "get_tx_proof"));
        for (name, why) in DISABLED {
            assert!(!why.is_empty(), "{name} has no reason");
        }
        for name in [
            "export_outputs",
            "import_outputs",
            "export_key_images",
            "import_key_images",
            "sign_transfer",
            "submit_transfer",
            "describe_transfer",
        ] {
            assert!(
                !DISABLED.iter().any(|(n, _)| *n == name),
                "{name} is built now"
            );
        }
    }

    /// The hex parameters give `-26 BAD_HEX` with the reference's wording, for
    /// a missing one as well as a malformed one.
    #[test]
    fn a_bad_hex_parameter_is_named() {
        let params = json!({ "unsigned_txset": "not hex" });
        let e = hex_param(&params, "unsigned_txset").expect_err("not hex");
        assert_eq!(e.code, errors::BAD_HEX);
        assert_eq!(e.message, "Failed to parse hex.");

        let e = hex_param(&params, "tx_data_hex").expect_err("missing");
        assert_eq!(e.code, errors::BAD_HEX);

        // `.ok()` rather than `.expect()`: `errors::Error` has no `Debug`, on
        // purpose, so an RPC error cannot reach a log through a `{:?}`.
        assert_eq!(
            hex_param(&json!({ "a": "0a0b" }), "a").ok(),
            Some(vec![0x0a, 0x0b])
        );
    }

    /// The codes a cold-signing client branches on: a watch-only wallet asked
    /// to sign, and a set whose claimed change is not change.
    #[test]
    fn cold_signing_failures_get_their_own_codes() {
        use wow_wallet::offline::OfflineError as E;
        assert_eq!(offline_error(E::WatchOnly).code, errors::WATCH_ONLY);
        assert_eq!(
            offline_error(E::ChangeNotPaid).code,
            errors::BAD_UNSIGNED_TX_DATA
        );
        assert_eq!(
            offline_error(E::NonzeroUnlockTime).code,
            errors::NONZERO_UNLOCK_TIME
        );
        assert_eq!(
            offline_error(E::NoDaemon).code,
            errors::NO_DAEMON_CONNECTION
        );
        assert_eq!(
            offline_error(E::BadSignature(0, wow_crypto::types::KeyImage::ZERO)).code,
            errors::WRONG_SIGNATURE
        );
        // "Hot wallets cannot import outputs" is about the wallet, not the
        // file, but it is the answer to an import and shares its code.
        assert_eq!(
            offline_error(E::HotWallet).code,
            errors::BAD_UNSIGNED_TX_DATA
        );
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
            payment_id: None,
            frozen: false,
            tx_public_key: wow_crypto::types::PublicKey::ZERO,
            additional_tx_keys: Vec::new(),
            key_image_request: false,
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
