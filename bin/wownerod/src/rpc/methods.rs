//! The RPC method implementations.
//!
//! `specs/11-daemon-rpc.md` §3 and §4. Field names here are exactly the JSON
//! keys — a client reads them by name, so a rename is a break.
//!
//! # What is implemented
//!
//! `specs/11` §7's minimum set. Anything not built returns
//! `UNSUPPORTED_RPC` rather than a plausible-looking empty answer. A wallet
//! that got `{"status":"OK"}` from a method that did nothing would draw the
//! wrong conclusion. The node-management endpoints are in [`super::admin`], the
//! mining ones in [`super::mining`].

use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{json, Value};
use wow_consensus::checkpoints::Checkpoints;
use wow_consensus::hardfork::HardFork;
use wow_storage::db::BlockchainDb;
use wow_storage::lmdb::LmdbDb;
use wow_types::Network;

use crate::cli::Config;
use crate::mempool::{Rejection, RelayMethod};

/// `specs/11` §6. Note there is no `-8`.
pub mod error {
    pub const WRONG_PARAM: i32 = -1;
    pub const TOO_BIG_HEIGHT: i32 = -2;
    pub const TOO_BIG_RESERVE_SIZE: i32 = -3;
    pub const WRONG_WALLET_ADDRESS: i32 = -4;
    pub const INTERNAL_ERROR: i32 = -5;
    pub const WRONG_BLOCKBLOB: i32 = -6;
    pub const BLOCK_NOT_ACCEPTED: i32 = -7;
    pub const CORE_BUSY: i32 = -9;
    pub const UNSUPPORTED_RPC: i32 = -11;
    pub const MINING_TO_SUBADDRESS: i32 = -12;
    pub const REGTEST_REQUIRED: i32 = -13;
    /// Most restricted endpoints are not routed at all (`specs/11` §1.3) and so
    /// answer as unsupported. This code is for the ones that *are* routed and
    /// refuse only some arguments, such as `get_output_distribution` for an
    /// amount other than 0.
    pub const RESTRICTED: i32 = -19;
}

/// A method failed.
#[derive(Debug)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i32, message: impl Into<String>) -> RpcError {
        RpcError {
            code,
            message: message.into(),
        }
    }

    /// A method this node does not route: not implemented, or restricted.
    pub fn unsupported(method: &str) -> RpcError {
        RpcError::new(
            error::UNSUPPORTED_RPC,
            format!(
                "{method} is not available on this node: it is either not \
                 implemented yet (see `wownerod --help`) or restricted"
            ),
        )
    }
}

pub type RpcResult = Result<Value, RpcError>;

/// `specs/11` §2.1: a difficulty is emitted as **three** fields.
///
/// A client reading only `difficulty` silently truncates above 2^64, which is
/// why `store_difficulty()` writes all three.
fn difficulty_fields(prefix: &str, d: u128) -> Vec<(String, Value)> {
    vec![
        (prefix.to_string(), json!(d as u64)),
        (format!("{prefix}_top64"), json!((d >> 64) as u64)),
        (format!("wide_{prefix}"), json!(format!("{d:#x}"))),
    ]
}

pub(crate) fn with_difficulty(
    mut obj: serde_json::Map<String, Value>,
    prefix: &str,
    d: u128,
) -> Value {
    for (k, v) in difficulty_fields(prefix, d) {
        obj.insert(k, v);
    }
    Value::Object(obj)
}

/// `specs/11` §2: every response carries `status` and `untrusted`, and
/// `credits` / `top_hash` so clients that read them do not break.
pub(crate) fn base(status: &str, untrusted: bool) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("status".into(), json!(status));
    m.insert("untrusted".into(), json!(untrusted));
    m.insert("credits".into(), json!(0));
    m.insert("top_hash".into(), json!(""));
    m
}

/// `nettype` as `specs/11` §3.2 spells it.
fn nettype(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Stagenet => "stagenet",
        Network::Fakechain => "fakechain",
    }
}

/// Whether answers are `untrusted` right now.
///
/// `specs/11` §2 defines the flag as "true if the answer came from a bootstrap
/// daemon **or the node is not yet synced**". Reporting `false` from a node
/// still catching up would tell a wallet the tip is authoritative, so this
/// stays true until the peer-to-peer node says it is synchronised. The router
/// refreshes it on every request.
static UNTRUSTED: AtomicBool = AtomicBool::new(true);

pub(crate) fn set_untrusted(untrusted: bool) {
    UNTRUSTED.store(untrusted, Ordering::Relaxed);
}

pub(crate) fn untrusted() -> bool {
    UNTRUSTED.load(Ordering::Relaxed)
}

/// `target_height` as the C++ reports it: zero once caught up, which is how a
/// wallet tells that it is.
pub(crate) fn target_height(sync: &wow_p2p::node::SyncStatus) -> u64 {
    if sync.synchronized || sync.target_height <= sync.height {
        0
    } else {
        sync.target_height
    }
}

/// The fee inputs for a node with no chain state of its own -- a read-only
/// server: the protocol floor for the weight limits.
pub(crate) fn floor_fee_context(db: &LmdbDb, network: Network) -> wow_consensus::fee::FeeContext {
    let height = db.height();
    wow_consensus::fee::FeeContext {
        version: HardFork::new(network).required_version(height.saturating_sub(1)),
        cumulative_weight_limit: 600_000,
        long_term_effective_median: 300_000,
        already_generated_coins: match height {
            0 => 0,
            h => db.get_block_info(h - 1).map(|i| i.coins).unwrap_or(0),
        },
    }
}

pub(crate) fn hex(h: &[u8]) -> String {
    wow_crypto::hex::encode(h)
}

/// `/get_height` (`specs/11` §3).
pub fn get_height(db: &LmdbDb) -> RpcResult {
    let height = db.height();
    let mut m = base("OK", untrusted());
    m.insert("height".into(), json!(height));
    m.insert(
        "hash".into(),
        json!(if height == 0 {
            String::new()
        } else {
            hex(&db.get_block_hash(height - 1).map_err(internal)?)
        }),
    );
    Ok(Value::Object(m))
}

pub(crate) fn internal(e: impl std::fmt::Display) -> RpcError {
    RpcError::new(error::INTERNAL_ERROR, e.to_string())
}

/// `/get_info` and the `get_info` JSON-RPC method (`specs/11` §3.2).
///
/// Every field clients depend on is emitted. The ones this node cannot know
/// -- bootstrap state, update checks -- are zero or false, which is accurate
/// for a node with neither, not a placeholder.
///
/// `restricted` is the listener's, and a restricted one says what the C++'s
/// says (`core_rpc_server::on_get_info`): only the public pool transactions
/// are counted, and what tells one node from another or says how it is
/// connected -- its start time, its peer, RPC and alternative block counts,
/// its peer lists -- is zero, its free space the largest number there is and
/// its database size rounded up to the next 5 GiB.
pub fn get_info(server: &super::Server, restricted: bool) -> RpcResult {
    let db = server.db();
    let cfg = server.config();
    let height = db.height();
    let sync = server.sync_status();
    let fee = server.fee_context();

    let (top_hash, cumulative_difficulty, difficulty) = if height == 0 {
        (String::new(), 0u128, 0u128)
    } else {
        let tip = db.get_block_info(height - 1).map_err(internal)?;
        let prev = if height >= 2 {
            db.get_block_info(height - 2)
                .map_err(internal)?
                .cumulative_difficulty
        } else {
            0
        };
        (
            hex(&tip.hash),
            tip.cumulative_difficulty,
            tip.cumulative_difficulty.saturating_sub(prev),
        )
    };
    let (block_weight_limit, block_weight_median) = (fee.cumulative_weight_limit, fee.median());
    let (white, grey) = server
        .p2p()
        .filter(|_| !restricted)
        .map(|p| {
            let (w, g) = p.peer_lists();
            (w.len(), g.len())
        })
        .unwrap_or((0, 0));
    let (start_time, alt_blocks, outgoing, incoming, rpc_connections) = if restricted {
        (0, 0, 0, 0, 0)
    } else {
        (
            server.start_time(),
            db.get_alt_block_count().unwrap_or(0),
            sync.outgoing,
            sync.incoming,
            server.rpc_connections(),
        )
    };
    let db_size = database_size(cfg);
    let db_size = if restricted {
        round_up(db_size, DATABASE_SIZE_QUANTUM)
    } else {
        db_size
    };

    let mut m = base("OK", untrusted());
    m.insert("height".into(), json!(height));
    m.insert("target_height".into(), json!(target_height(&sync)));
    m.insert(
        "target".into(),
        json!(wow_consensus::constants::DIFFICULTY_TARGET_V2),
    );
    m.insert("top_block_hash".into(), json!(top_hash));
    m.insert("top_hash".into(), json!(""));

    // The store keeps no transaction count this node can read cheaply.
    m.insert("tx_count".into(), json!(0));
    m.insert("tx_pool_size".into(), json!(server.pool_size(!restricted)));
    m.insert("alt_blocks_count".into(), json!(alt_blocks));
    m.insert("outgoing_connections_count".into(), json!(outgoing));
    m.insert("incoming_connections_count".into(), json!(incoming));
    m.insert("rpc_connections_count".into(), json!(rpc_connections));
    m.insert("white_peerlist_size".into(), json!(white));
    m.insert("grey_peerlist_size".into(), json!(grey));

    m.insert("mainnet".into(), json!(cfg.network == Network::Mainnet));
    m.insert("testnet".into(), json!(cfg.network == Network::Testnet));
    m.insert("stagenet".into(), json!(cfg.network == Network::Stagenet));
    m.insert("nettype".into(), json!(nettype(cfg.network)));

    // `specs/11` §3.2: the `block_size_*` names are legacy aliases for the
    // weight fields; emit both with the same values.
    m.insert("block_weight_limit".into(), json!(block_weight_limit));
    m.insert("block_size_limit".into(), json!(block_weight_limit));
    m.insert("block_weight_median".into(), json!(block_weight_median));
    m.insert("block_size_median".into(), json!(block_weight_median));

    m.insert("start_time".into(), json!(start_time));
    m.insert("adjusted_time".into(), json!(now()));
    // Not measured here, so zero -- but the largest number on a restricted
    // listener, where the C++ puts it whatever the disk holds.
    m.insert(
        "free_space".into(),
        json!(if restricted { u64::MAX } else { 0 }),
    );
    m.insert("database_size".into(), json!(db_size));
    m.insert("offline".into(), json!(server.p2p().is_none()));
    m.insert("bootstrap_daemon_address".into(), json!(""));
    m.insert(
        "height_without_bootstrap".into(),
        json!(if restricted { 0 } else { height }),
    );
    m.insert("was_bootstrap_ever_used".into(), json!(false));
    m.insert("update_available".into(), json!(false));
    m.insert("version".into(), json!(crate::cli::VERSION));
    m.insert("synchronized".into(), json!(sync.synchronized));
    m.insert("busy_syncing".into(), json!(sync.busy_syncing));
    // The listener's, not `--restricted-rpc`'s: a restricted second port on
    // an unrestricted node is restricted.
    m.insert("restricted".into(), json!(restricted));

    let m = match with_difficulty(m, "difficulty", difficulty) {
        Value::Object(m) => m,
        _ => unreachable!("with_difficulty returns an object"),
    };
    Ok(with_difficulty(
        m,
        "cumulative_difficulty",
        cumulative_difficulty,
    ))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn database_size(cfg: &Config) -> u64 {
    let dir = wow_storage::env::db_dir(&cfg.data_dir, cfg.network, cfg.regtest);
    std::fs::metadata(dir.join("data.mdb"))
        .map(|m| m.len())
        .unwrap_or(0)
}

/// The step a restricted `get_info` rounds the database size up to: 5 GiB.
const DATABASE_SIZE_QUANTUM: u64 = 5 * 1024 * 1024 * 1024;

/// `round_up`: `value` up to the next multiple of `quantum`.
fn round_up(value: u64, quantum: u64) -> u64 {
    value.div_ceil(quantum).saturating_mul(quantum)
}

/// `get_version` (`specs/11` §4).
pub fn get_version(server: &super::Server) -> RpcResult {
    let db = server.db();
    let cfg = server.config();
    let hf = HardFork::new(cfg.network);
    let forks: Vec<Value> = hf
        .forks()
        .iter()
        .map(|f| json!({"hf_version": f.version, "height": f.height}))
        .collect();

    let mut m = base("OK", untrusted());
    // The C++ packs major/minor into one integer; keep the same shape.
    m.insert("version".into(), json!((3u32 << 16) | 14));
    m.insert("release".into(), json!(false));
    m.insert("current_height".into(), json!(db.height()));
    m.insert(
        "target_height".into(),
        json!(target_height(&server.sync_status())),
    );
    m.insert("hard_forks".into(), json!(forks));
    Ok(Value::Object(m))
}

/// `hard_fork_info` (`specs/11` §4.4).
///
/// "With `threshold = 0` in the Wownero table, `enabled` is purely
/// height-driven."
pub fn hard_fork_info(db: &LmdbDb, cfg: &Config, params: &Value) -> RpcResult {
    let hf = HardFork::new(cfg.network);
    let height = db.height();
    let current = hf.required_version(height.saturating_sub(1));

    let requested = params.get("version").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
    let version = if requested == 0 { current } else { requested };

    let earliest = hf.earliest_height(version).unwrap_or(0);
    let enabled = hf.is_active(version, height.saturating_sub(1));

    let mut m = base("OK", untrusted());
    m.insert("version".into(), json!(version));
    m.insert("enabled".into(), json!(enabled));
    // The vote window exists in the C++ but is inert with a zero threshold.
    m.insert("window".into(), json!(10_080));
    m.insert("votes".into(), json!(0));
    m.insert("threshold".into(), json!(0));
    m.insert("voting".into(), json!(hf.ideal_version_top()));
    m.insert("state".into(), json!(if enabled { 2 } else { 0 }));
    m.insert("earliest_height".into(), json!(earliest));
    Ok(Value::Object(m))
}

/// `get_fee_estimate` (`specs/11` §4.5, `specs/06` §6.4).
///
/// From the chain's cached weight state when the node holds the chain; a
/// read-only server has none, and reports the floor, which is what it can
/// honestly say.
pub fn get_fee_estimate(server: &super::Server, params: &Value) -> RpcResult {
    use wow_consensus::fee;

    let grace = params
        .get("grace_blocks")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if grace > wow_consensus::constants::CRYPTONOTE_REWARD_BLOCKS_WINDOW as u64 {
        return Err(RpcError::new(
            error::WRONG_PARAM,
            "grace_blocks exceeds the reward window",
        ));
    }

    let ctx = server.fee_context();
    let base_reward = ctx.base_reward().map_err(|e| internal(format!("{e:?}")))?;
    let per_byte = fee::get_dynamic_base_fee(base_reward, ctx.fee_median(), ctx.version);
    let tiers = fee::fee_tiers_2021(base_reward, ctx.median(), ctx.long_term_effective_median);

    let mut m = base("OK", untrusted());
    m.insert("fee".into(), json!(per_byte));
    m.insert(
        "fees".into(),
        json!([tiers.low, tiers.normal, tiers.medium, tiers.high]),
    );
    m.insert(
        "quantization_mask".into(),
        json!(fee::FEE_QUANTIZATION_MASK),
    );
    Ok(Value::Object(m))
}

/// `rpc_access_info` (`specs/11` §4).
///
/// RPC payment is not built here, and the reference answers this method
/// whether or not it has one: with `m_rpc_payment == NULL` it returns `OK` and
/// zeroes (`core_rpc_server.cpp`, `on_rpc_access_info`). Answering "no such
/// method" was not a missing feature but a broken connection -- **any**
/// `error.code` makes epee's `invoke_http_json_rpc` return false, and
/// `wallet2` reports that as "Failed to connect to daemon".
///
/// The wallet reads `diff == 0` as "no payment required" and then leaves the
/// hashing blob and both seed hashes alone, so the empty strings here are what
/// it expects (`node_rpc_proxy.cpp`, `get_rpc_payment_info`).
pub fn rpc_access_info() -> RpcResult {
    let mut m = base("OK", untrusted());
    m.insert("hashing_blob".into(), json!(""));
    m.insert("seed_height".into(), json!(0));
    m.insert("seed_hash".into(), json!(""));
    m.insert("next_seed_hash".into(), json!(""));
    m.insert("cookie".into(), json!(0));
    m.insert("diff".into(), json!(0));
    m.insert("credits_per_hash_found".into(), json!(0));
    m.insert("height".into(), json!(0));
    Ok(Value::Object(m))
}

/// `OUTPUT_HISTOGRAM_RECENT_CUTOFF_RESTRICTION`: three days.
const HISTOGRAM_RECENT_CUTOFF_RESTRICTION: u64 = 3 * 86_400;

/// `get_output_histogram` (`specs/11` §4).
///
/// A wallet asks for this only when a ring it is building has pre-RingCT
/// amounts in it; for a wallet whose outputs are all RingCT the amount list
/// comes out empty and the method is never called. The restricted limits are
/// `on_get_output_histogram`'s own.
pub fn get_output_histogram(db: &LmdbDb, params: &Value, restricted: bool) -> RpcResult {
    let amounts: Vec<u64> = params
        .get("amounts")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
        .unwrap_or_default();
    if restricted && amounts.is_empty() {
        return Err(RpcError::new(
            error::WRONG_PARAM,
            "Restricted RPC will not serve histograms on the whole blockchain. Use your own node.",
        ));
    }

    let number = |name: &str| params.get(name).and_then(|v| v.as_u64()).unwrap_or(0);
    let unlocked = params
        .get("unlocked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let recent_cutoff = number("recent_cutoff");
    if restricted
        && recent_cutoff > 0
        && recent_cutoff < now().saturating_sub(HISTOGRAM_RECENT_CUTOFF_RESTRICTION)
    {
        return Err(RpcError::new(
            error::WRONG_PARAM,
            "Recent cutoff is too old",
        ));
    }
    let min_count = number("min_count");
    let max_count = number("max_count");

    let rows = db
        .get_output_histogram(&amounts, unlocked, recent_cutoff, min_count)
        .map_err(internal)?;

    // The reference filters again after the lookup, on both bounds, with
    // `max_count == 0` meaning no upper bound at all.
    let histogram: Vec<Value> = rows
        .into_iter()
        .filter(|(_, (total, _, _))| *total >= min_count && (max_count == 0 || *total <= max_count))
        .map(|(amount, (total, unlocked, recent))| {
            json!({
                "amount": amount,
                "total_instances": total,
                "unlocked_instances": unlocked,
                "recent_instances": recent,
            })
        })
        .collect();

    let mut m = base("OK", untrusted());
    m.insert("histogram".into(), json!(histogram));
    Ok(Value::Object(m))
}

/// `get_txpool_backlog` (`specs/11` §4), as rendered JSON.
///
/// `backlog` is a `KV_SERIALIZE_CONTAINER_POD_AS_BLOB` of
/// `{ uint64 weight; uint64 fee; uint64 time_in_pool; }`, so the answer puts
/// raw bytes inside a JSON string and no `serde_json::Value` can hold it. The
/// result object is therefore rendered here and the router wraps it
/// ([`object_with_blob`]).
///
/// `time_in_pool` is `now - receive_time`, as `get_transaction_backlog`
/// computes it.
pub fn txpool_backlog(server: &super::Server, restricted: bool) -> Vec<u8> {
    let now = now();
    let pool = server.pool();
    let mut packed = Vec::new();
    for (_, e) in pool.entries() {
        if restricted && !e.is_public() {
            continue;
        }
        packed.extend_from_slice(&e.weight.to_le_bytes());
        packed.extend_from_slice(&e.fee.to_le_bytes());
        packed.extend_from_slice(&now.saturating_sub(e.receive_time).to_le_bytes());
    }
    object_with_blob(&base("OK", untrusted()), "backlog", &packed)
}

/// One amount's answer while it waits to be rendered: the fields `serde_json`
/// can hold, the name of the field that holds raw bytes, and those bytes --
/// empty and `None` when `binary: false` put the counts in `fields` already.
type PendingDistribution = (
    serde_json::Map<String, Value>,
    &'static str,
    Option<Vec<u8>>,
);

/// `get_output_distribution` over JSON-RPC (`specs/11` §4), as rendered JSON.
///
/// The same answer as `/get_output_distribution.bin`, which is where a wallet
/// usually asks for it; the counts come from one shared computation
/// ([`super::binary::distribution_for`]) so the two forms cannot drift. Only
/// the packing differs: `binary` -- the default, as `KV_SERIALIZE_OPT(binary,
/// true)` makes it -- puts the counts in a string of little-endian `u64`s, and
/// `binary: false` sends a plain JSON array. The binary form is why this is
/// rendered rather than built: the raw bytes sit inside the array, nested one
/// deeper than [`object_with_blob`] alone can reach.
pub fn output_distribution_json(
    db: &LmdbDb,
    cfg: &Config,
    params: &Value,
    restricted: bool,
) -> Result<Vec<u8>, RpcError> {
    let amounts: Vec<u64> = params
        .get("amounts")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
        .unwrap_or_default();
    // "Restricted RPC can only get output distribution for rct outputs."
    if restricted && amounts != [0u64] {
        return Err(RpcError::new(
            error::RESTRICTED,
            "Restricted RPC can only get output distribution for rct outputs. Use your own node.",
        ));
    }

    let flag = |name: &str, default: bool| {
        params
            .get(name)
            .and_then(|v| v.as_bool())
            .unwrap_or(default)
    };
    let binary = flag("binary", true);
    let compress = flag("compress", false);
    let cumulative = flag("cumulative", false);
    let number = |name: &str| params.get(name).and_then(|v| v.as_u64()).unwrap_or(0);
    let from = number("from_height");
    let height = db.height();
    // "0 is placeholder for the whole chain".
    let to = match number("to_height") {
        0 => height.saturating_sub(1),
        t => t,
    };

    // Each entry is its ordinary fields and, for a binary answer, the one
    // field that is a string of bytes.
    let mut entries: Vec<PendingDistribution> = Vec::with_capacity(amounts.len());
    for amount in amounts {
        let d = super::binary::distribution_for(db, cfg.network, amount, from, to, cumulative)?;
        let mut fields = serde_json::Map::new();
        fields.insert("amount".into(), json!(amount));
        fields.insert("start_height".into(), json!(d.start_height));
        fields.insert("binary".into(), json!(binary));
        fields.insert("compress".into(), json!(compress));
        fields.insert("base".into(), json!(d.base));
        if !binary {
            fields.insert("distribution".into(), json!(d.data));
            entries.push((fields, "", None));
            continue;
        }
        let packed: Vec<u8> = if compress {
            // `compress_integer_array`: base-128 varints back to back.
            let mut p = Vec::with_capacity(d.data.len());
            for v in &d.data {
                wow_serialize::varint::write_varint(&mut p, *v);
            }
            p
        } else {
            d.data.iter().flat_map(|v| v.to_le_bytes()).collect()
        };
        let name = if compress {
            "compressed_data"
        } else {
            "distribution"
        };
        entries.push((fields, name, Some(packed)));
    }

    let mut out = Vec::new();
    out.push(b'{');
    for (key, value) in base("OK", untrusted()) {
        out.extend_from_slice(Value::String(key).to_string().as_bytes());
        out.push(b':');
        out.extend_from_slice(value.to_string().as_bytes());
        out.push(b',');
    }
    out.extend_from_slice(b"\"distributions\":[");
    for (n, (fields, name, blob)) in entries.iter().enumerate() {
        if n > 0 {
            out.push(b',');
        }
        match blob {
            Some(bytes) => out.extend_from_slice(&object_with_blob(fields, name, &bytes[..])),
            None => out.extend_from_slice(Value::Object(fields.clone()).to_string().as_bytes()),
        }
    }
    out.extend_from_slice(b"]}");
    Ok(out)
}

/// A JSON object: `fields` as `serde_json` renders them, plus one more whose
/// value is a string of **raw bytes**.
///
/// This is what a `KV_SERIALIZE_CONTAINER_POD_AS_BLOB` looks like once epee
/// writes it as JSON. epee escapes only `\b \f \n \r \t \v " \ /` and puts
/// every other byte in as it stands
/// (`contrib/epee/src/parserse_base_utils.cpp`, `transform_to_escape_sequence`),
/// and its reader is the mirror of that. A `\u00XX` escape would not do:
/// epee's `match_string2` decodes one into **UTF-8**, so any byte above `0x7f`
/// would come back as two.
pub(crate) fn object_with_blob(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    blob: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(blob.len() * 2 + 128);
    out.push(b'{');
    for (key, value) in fields {
        out.extend_from_slice(Value::String(key.clone()).to_string().as_bytes());
        out.push(b':');
        out.extend_from_slice(value.to_string().as_bytes());
        out.push(b',');
    }
    out.extend_from_slice(Value::String(name.to_string()).to_string().as_bytes());
    out.extend_from_slice(b":\"");
    for &b in blob {
        match b {
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x0b => out.extend_from_slice(b"\\v"),
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'/' => out.extend_from_slice(b"\\/"),
            other => out.push(other),
        }
    }
    out.extend_from_slice(b"\"}");
    out
}

/// `get_block_hash` (`specs/11` §4).
pub fn get_block_hash(db: &LmdbDb, params: &Value) -> RpcResult {
    // The C++ takes a bare array: `"params":[height]`.
    let height = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_u64())
        .or_else(|| params.get("height").and_then(|v| v.as_u64()))
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "expected a height"))?;

    if height >= db.height() {
        return Err(RpcError::new(
            error::TOO_BIG_HEIGHT,
            format!("height {height} is past the tip ({})", db.height()),
        ));
    }
    Ok(json!(hex(&db.get_block_hash(height).map_err(internal)?)))
}

/// `fill_block_header_response` (`specs/11` §4.6).
///
/// `vote` is Wownero-specific and **must** be present: "explorers read it for
/// the on-chain vote tally".
fn block_header(db: &LmdbDb, cfg: &Config, height: u64) -> Result<Value, RpcError> {
    let chain_height = db.height();
    if height >= chain_height {
        return Err(RpcError::new(
            error::TOO_BIG_HEIGHT,
            format!("height {height} is past the tip ({chain_height})"),
        ));
    }

    let info = db.get_block_info(height).map_err(internal)?;
    let blob = db.get_block_blob(height).map_err(internal)?;
    let blk = wow_types::Block::from_blob(&blob)
        .map_err(|e| internal(format!("block {height} does not parse: {e:?}")))?;

    let prev_cum = if height == 0 {
        0
    } else {
        db.get_block_info(height - 1)
            .map_err(internal)?
            .cumulative_difficulty
    };
    let difficulty = info.cumulative_difficulty.saturating_sub(prev_cum);

    let reward: u64 = blk.miner_tx.prefix.vout.iter().map(|o| o.amount).sum();
    let mut miner_w = wow_serialize::binary::Writer::with_capacity(2048);
    blk.miner_tx.write(&mut miner_w);
    let miner_blob = miner_w.into_vec();
    let miner_tx_hash = wow_types::hashes::transaction_hash_from_blob(&blk.miner_tx, &miner_blob)
        .map(|h| hex(&h))
        .unwrap_or_default();

    let mut m = serde_json::Map::new();
    m.insert("major_version".into(), json!(blk.header.major_version));
    m.insert("minor_version".into(), json!(blk.header.minor_version));
    m.insert("timestamp".into(), json!(blk.header.timestamp));
    m.insert("prev_hash".into(), json!(hex(&blk.header.prev_id)));
    m.insert("nonce".into(), json!(blk.header.nonce));
    // Wownero-specific; explorers read it.
    m.insert("vote".into(), json!(blk.header.vote));
    m.insert("orphan_status".into(), json!(false));
    m.insert("height".into(), json!(height));
    m.insert("depth".into(), json!(chain_height - height - 1));
    m.insert("hash".into(), json!(hex(&info.hash)));
    m.insert("reward".into(), json!(reward));
    m.insert("block_size".into(), json!(info.weight));
    m.insert("block_weight".into(), json!(info.weight));
    m.insert(
        "long_term_weight".into(),
        json!(info.long_term_block_weight),
    );
    m.insert("num_txes".into(), json!(blk.tx_hashes.len()));
    m.insert("miner_tx_hash".into(), json!(miner_tx_hash));
    let _ = cfg;

    let m = match with_difficulty(m, "difficulty", difficulty) {
        Value::Object(m) => m,
        _ => unreachable!(),
    };
    Ok(with_difficulty(
        m,
        "cumulative_difficulty",
        info.cumulative_difficulty,
    ))
}

/// `get_last_block_header`.
pub fn get_last_block_header(db: &LmdbDb, cfg: &Config) -> RpcResult {
    let height = db.height();
    if height == 0 {
        return Err(RpcError::new(error::INTERNAL_ERROR, "the chain is empty"));
    }
    let mut m = base("OK", untrusted());
    m.insert("block_header".into(), block_header(db, cfg, height - 1)?);
    Ok(Value::Object(m))
}

/// `get_block_header_by_height`.
pub fn get_block_header_by_height(db: &LmdbDb, cfg: &Config, params: &Value) -> RpcResult {
    let height = params
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "expected `height`"))?;
    let mut m = base("OK", untrusted());
    m.insert("block_header".into(), block_header(db, cfg, height)?);
    Ok(Value::Object(m))
}

/// `get_block_header_by_hash`.
pub fn get_block_header_by_hash(db: &LmdbDb, cfg: &Config, params: &Value) -> RpcResult {
    let hash_hex = params
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "expected `hash`"))?;
    let hash: [u8; 32] = wow_crypto::hex::decode(hash_hex)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "`hash` is not 32 hex bytes"))?;

    let height = db
        .get_block_height(&hash)
        .map_err(|_| RpcError::new(error::WRONG_PARAM, "no block with that hash"))?;
    let mut m = base("OK", untrusted());
    m.insert("block_header".into(), block_header(db, cfg, height)?);
    Ok(Value::Object(m))
}

/// `get_block_headers_range`.
///
/// The C++ caps a restricted range at `RESTRICTED_BLOCK_HEADER_RANGE` (1000);
/// the same cap is applied here whether or not the server is restricted,
/// because the response is otherwise unbounded.
pub fn get_block_headers_range(db: &LmdbDb, cfg: &Config, params: &Value) -> RpcResult {
    const MAX_RANGE: u64 = 1000;

    let start = params
        .get("start_height")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "expected `start_height`"))?;
    let end = params
        .get("end_height")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "expected `end_height`"))?;

    if end < start {
        return Err(RpcError::new(
            error::WRONG_PARAM,
            "end_height is before start_height",
        ));
    }
    if end - start + 1 > MAX_RANGE {
        return Err(RpcError::new(
            error::WRONG_PARAM,
            format!("range of {} exceeds {MAX_RANGE}", end - start + 1),
        ));
    }

    let mut headers = Vec::with_capacity((end - start + 1) as usize);
    for h in start..=end {
        headers.push(block_header(db, cfg, h)?);
    }
    let mut m = base("OK", untrusted());
    m.insert("headers".into(), json!(headers));
    Ok(Value::Object(m))
}

/// `get_block` — the header plus the blob and tx hashes.
pub fn get_block(db: &LmdbDb, cfg: &Config, params: &Value) -> RpcResult {
    let height = match params.get("height").and_then(|v| v.as_u64()) {
        Some(h) => h,
        None => {
            let hash_hex = params
                .get("hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "expected `height` or `hash`"))?;
            let hash: [u8; 32] = wow_crypto::hex::decode(hash_hex)
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "`hash` is not 32 hex bytes"))?;
            db.get_block_height(&hash)
                .map_err(|_| RpcError::new(error::WRONG_PARAM, "no block with that hash"))?
        }
    };

    let header = block_header(db, cfg, height)?;
    let blob = db.get_block_blob(height).map_err(internal)?;
    let blk = wow_types::Block::from_blob(&blob).map_err(|e| internal(format!("{e:?}")))?;

    let mut m = base("OK", untrusted());
    m.insert("block_header".into(), header);
    m.insert("blob".into(), json!(hex(&blob)));
    m.insert(
        "tx_hashes".into(),
        json!(blk.tx_hashes.iter().map(|h| hex(h)).collect::<Vec<_>>()),
    );
    Ok(Value::Object(m))
}

/// `get_checkpoints` — not a C++ method, but the check `specs/07` §6
/// recommends, exposed so it can be run without restarting the daemon.
pub fn get_checkpoints(db: &LmdbDb, cfg: &Config) -> RpcResult {
    let cps = Checkpoints::new(cfg.network);
    let height = db.height();
    let mut rows = Vec::new();
    let mut matched = 0u64;

    for cp in cps.all() {
        if cp.height >= height {
            break;
        }
        let stored = db.get_block_hash(cp.height).map_err(internal)?;
        let stored_diff = db
            .get_block_cumulative_difficulty(cp.height)
            .map_err(internal)?;
        let ok = stored == cp.hash && stored_diff == cp.cumulative_difficulty;
        if ok {
            matched += 1;
        }
        rows.push(json!({
            "height": cp.height,
            "hash": hex(&cp.hash),
            "matches": ok,
            "expected_cumulative_difficulty": cp.cumulative_difficulty.to_string(),
            "stored_cumulative_difficulty": stored_diff.to_string(),
        }));
    }

    let mut m = base("OK", untrusted());
    m.insert("total".into(), json!(cps.all().len()));
    m.insert("checked".into(), json!(rows.len()));
    m.insert("matched".into(), json!(matched));
    m.insert("checkpoints".into(), json!(rows));
    Ok(Value::Object(m))
}

/// `/send_raw_transaction` (`specs/11` §3.1).
///
/// Returns the whole response rather than a `RpcResult`, because a rejected
/// transaction is a **successful** call that says no. A wallet reads the flags
/// to learn which rule it broke, and wrapping that in an RPC error would throw
/// them away.
pub fn send_raw_transaction(server: &super::Server, body: &[u8]) -> String {
    let request: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return json!({
                "status": "Failed",
                "reason": format!("invalid JSON: {e}"),
                "untrusted": true,
            })
            .to_string()
        }
    };

    let Some(hex) = request.get("tx_as_hex").and_then(Value::as_str) else {
        return failed_relay("tx_as_hex is missing", None);
    };
    let Some(blob) = wow_crypto::hex::decode(hex) else {
        return failed_relay("tx_as_hex is not hex", None);
    };
    let do_not_relay = request
        .get("do_not_relay")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let db = server.db();
    let fee_context = server.fee_context();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Marked as this node's own from the moment it is in the pool, so nothing
    // that walks the pool before the relay below can take it for public.
    let method = if do_not_relay {
        RelayMethod::None
    } else {
        RelayMethod::Local
    };
    // The pool guard ends with this statement: relaying marks the entry, which
    // takes the pool lock again.
    let added = server.pool().add(db, &blob, &fee_context, now, method);
    match added {
        Ok(admitted) => {
            // Announced as the C++ announces it (`core::add_new_tx`): one kept
            // from relay now, one going out once it is public.
            if let Some(core) = server.core() {
                core.announce_pool_txs(&[admitted.id]);
            }
            if admitted.relay == RelayMethod::None {
                return not_relayed();
            }
            // Handed to the peer-to-peer layer whenever the caller allows it,
            // whether or not a peer can take it this moment. One that reaches
            // nobody stays unrelayed in the pool, which offers it again until
            // one does; `not_relayed` still says whether it went out now.
            if let Some(p) = server.p2p() {
                p.relay_transaction(admitted.id, blob.clone());
            }
            let mut m = relay_flags(None);
            m.insert("status".into(), json!("OK"));
            m.insert("reason".into(), json!(""));
            m.insert("not_relayed".into(), json!(!server.relays()));
            m.insert(
                "tx_hash".into(),
                json!(wow_crypto::hex::encode(&admitted.id)),
            );
            Value::Object(m).to_string()
        }
        // Held already, publicly or kept from relay, or on the chain. Not a
        // failure: the C++ answers OK and relays nothing. Checked before the
        // key images, a transaction sent twice was answered as a double spend
        // of its own inputs, naming itself as the spender.
        Err(Rejection::AlreadyInPool) => not_relayed(),
        Err(rejection) => failed_relay(&rejection.reason(), Some(&rejection)),
    }
}

/// Accepted, and going nowhere: kept back as asked, or known already.
fn not_relayed() -> String {
    let mut m = relay_flags(None);
    m.insert("status".into(), json!("OK"));
    m.insert("reason".into(), json!("Not relayed"));
    m.insert("not_relayed".into(), json!(true));
    Value::Object(m).to_string()
}

fn failed_relay(reason: &str, rejection: Option<&Rejection>) -> String {
    let mut m = relay_flags(rejection);
    m.insert("status".into(), json!("Failed"));
    m.insert("reason".into(), json!(reason));
    m.insert("not_relayed".into(), json!(true));
    Value::Object(m).to_string()
}

/// Every rejection flag `specs/11` §3.1 requires, present whether set or not.
fn relay_flags(rejection: Option<&Rejection>) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    match rejection {
        Some(r) => {
            for (name, set) in r.flags() {
                m.insert(name.into(), json!(set));
            }
            m.insert("tx_extra_too_big".into(), json!(r.tx_extra_too_big()));
        }
        None => {
            for name in [
                "low_mixin",
                "double_spend",
                "invalid_input",
                "invalid_output",
                "too_big",
                "overspend",
                "fee_too_low",
                "too_few_outputs",
                "nonzero_unlock_time",
                "tx_extra_too_big",
            ] {
                m.insert(name.into(), json!(false));
            }
        }
    }
    // Not implemented, and reported as such rather than silently absent.
    m.insert("sanity_check_failed".into(), json!(false));
    m.insert("untrusted".into(), json!(untrusted()));
    m.insert("credits".into(), json!(0));
    m.insert("top_hash".into(), json!(""));
    m
}

/// `RESTRICTED_TRANSACTIONS_COUNT`: the most transactions one
/// `get_transactions` may ask a restricted listener for.
const RESTRICTED_TRANSACTIONS_COUNT: usize = 100;

/// `/get_transactions` — pool and chain transactions by hash.
///
/// On a restricted listener a private pool transaction is not there at all,
/// and a public one's receive time is zero, as the C++ answers
/// (`get_transaction_info` without sensitive data): when a node first saw a
/// transaction is a timing leak about where it came from. Nor may one call
/// ask it for more than [`RESTRICTED_TRANSACTIONS_COUNT`].
pub fn get_transactions(server: &super::Server, body: &[u8], restricted: bool) -> RpcResult {
    let request: Value = serde_json::from_slice(body)
        .map_err(|e| RpcError::new(error::WRONG_PARAM, format!("invalid JSON: {e}")))?;
    let wanted = request
        .get("txs_hashes")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "txs_hashes is missing"))?;
    if restricted && wanted.len() > RESTRICTED_TRANSACTIONS_COUNT {
        // In `status`, as the C++ answers it.
        let m = base(
            "Too many transactions requested in restricted mode",
            untrusted(),
        );
        return Ok(Value::Object(m));
    }

    let db = server.db();
    let pool = server.pool();
    let mut found = Vec::new();
    let mut missing = Vec::new();

    for h in wanted {
        let Some(text) = h.as_str() else { continue };
        let Some(bytes) = wow_crypto::hex::decode(text) else {
            missing.push(json!(text));
            continue;
        };
        let Ok(id) = <[u8; 32]>::try_from(bytes) else {
            missing.push(json!(text));
            continue;
        };

        // The pool first: an unconfirmed transaction is the one a wallet is
        // usually asking after.
        if let Some(entry) = pool.get(&id).filter(|e| !restricted || e.is_public()) {
            let received = if restricted { 0 } else { entry.receive_time };
            found.push(json!({
                "tx_hash": text,
                "as_hex": wow_crypto::hex::encode(&entry.blob),
                "in_pool": true,
                "double_spend_seen": entry.double_spend_seen,
                "block_height": 0,
                "received_timestamp": received,
                "relayed": entry.relayed,
            }));
            continue;
        }
        match db.get_tx_blob(&id) {
            Ok(blob) => found.push(json!({
                "tx_hash": text,
                "as_hex": wow_crypto::hex::encode(&blob),
                "in_pool": false,
                "double_spend_seen": false,
                "block_height": db.get_tx_block_height(&id).unwrap_or(0),
            })),
            Err(_) => missing.push(json!(text)),
        }
    }

    let mut m = base("OK", untrusted());
    m.insert("txs".into(), json!(found));
    m.insert("missed_tx".into(), json!(missing));
    Ok(Value::Object(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The blob field is a JSON string of **raw bytes**, escaped exactly as
    /// epee's writer escapes one, because epee's reader is the only thing that
    /// reads it back. Anything else here is a wallet that cannot parse the
    /// answer, which `wallet2` reports as no connection at all.
    #[test]
    fn a_blob_field_is_escaped_the_way_epee_escapes_one() {
        let mut fields = serde_json::Map::new();
        fields.insert("status".into(), json!("OK"));

        // One of every byte epee escapes, and two it leaves alone: `0x80` is
        // above ASCII, and `0x01` is a control byte epee still passes through.
        let blob = [0x08, 0x0c, b'\n', b'\r', b'\t', 0x0b, b'"', b'\\', b'/'];
        let out = object_with_blob(&fields, "tx_hashes", &blob);
        assert_eq!(
            String::from_utf8(out).expect("ASCII here"),
            r#"{"status":"OK","tx_hashes":"\b\f\n\r\t\v\"\\\/"}"#
        );

        let out = object_with_blob(&fields, "tx_hashes", &[0x80, 0xff, 0x01]);
        assert!(
            out.ends_with(&[b'"', 0x80, 0xff, 0x01, b'"', b'}']),
            "bytes above ASCII go in as they stand: {out:?}"
        );
        assert!(
            std::str::from_utf8(&out).is_err(),
            "which is why this cannot be a String"
        );
    }

    /// An empty pool still gives a whole object, not a truncated one.
    #[test]
    fn a_blob_field_with_nothing_in_it_is_an_empty_string() {
        let out = object_with_blob(&base("OK", false), "tx_hashes", &[]);
        let text = String::from_utf8(out).expect("ASCII here");
        assert!(text.ends_with(r#""tx_hashes":""}"#), "{text}");
        assert!(text.starts_with('{'), "{text}");
        // And it is ordinary JSON as long as the blob is empty, so a general
        // parser agrees with epee about this case at least.
        let back: Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(back["status"], json!("OK"));
        assert_eq!(back["tx_hashes"], json!(""));
    }

    /// `rpc_access_info` has to answer `OK` rather than an error: `wallet2`
    /// turns any `error.code` into "Failed to connect to daemon".
    #[test]
    fn rpc_access_info_answers_ok_with_no_payment_required() {
        let v = rpc_access_info().expect("answers");
        assert_eq!(v["status"], json!("OK"));
        assert_eq!(v["diff"], json!(0), "zero means no payment required");
        assert_eq!(v["credits_per_hash_found"], json!(0));
        assert_eq!(v["hashing_blob"], json!(""));
        assert_eq!(v["seed_hash"], json!(""));
        assert_eq!(v["next_seed_hash"], json!(""));
    }

    /// `specs/11` §2.1: three fields per difficulty, and the wide one is the
    /// full 128-bit value as hex.
    #[test]
    fn a_difficulty_is_emitted_three_ways() {
        let d: u128 = (7u128 << 64) | 0x1234_5678;
        let fields = difficulty_fields("difficulty", d);

        assert_eq!(fields[0].0, "difficulty");
        assert_eq!(fields[0].1, json!(0x1234_5678u64));
        assert_eq!(fields[1].0, "difficulty_top64");
        assert_eq!(fields[1].1, json!(7u64));
        assert_eq!(fields[2].0, "wide_difficulty");
        assert_eq!(fields[2].1, json!("0x70000000012345678"));
    }

    /// A value above 2^64 must not be reported by `difficulty` alone — that is
    /// the whole reason for the other two fields.
    #[test]
    fn a_wide_difficulty_does_not_fit_the_narrow_field() {
        let d = u128::from(u64::MAX) + 1;
        let fields = difficulty_fields("difficulty", d);
        assert_eq!(fields[0].1, json!(0u64), "the low word is zero");
        assert_eq!(fields[1].1, json!(1u64), "the high word carries it");
        assert_eq!(fields[2].1, json!("0x10000000000000000"));
    }

    /// A restricted `get_info` rounds the database size up to the next 5 GiB,
    /// as the C++'s `round_up` does, so the exact size cannot tell one node
    /// from another.
    #[test]
    fn a_restricted_database_size_is_rounded_up() {
        let gib = 1024 * 1024 * 1024;
        let q = DATABASE_SIZE_QUANTUM;
        assert_eq!(q, 5 * gib);
        assert_eq!(round_up(0, q), 0);
        assert_eq!(round_up(1, q), 5 * gib);
        assert_eq!(round_up(5 * gib, q), 5 * gib);
        assert_eq!(round_up(6_640 * 1024 * 1024, q), 10 * gib);
        assert_eq!(RESTRICTED_TRANSACTIONS_COUNT, 100);
    }

    #[test]
    fn the_base_fields_are_always_present() {
        let m = base("OK", true);
        assert_eq!(m["status"], json!("OK"));
        assert_eq!(m["untrusted"], json!(true));
        // `specs/11` §2: emit these even without RPC payments, so clients that
        // read them do not break.
        assert_eq!(m["credits"], json!(0));
        assert_eq!(m["top_hash"], json!(""));
    }

    #[test]
    fn the_nettype_strings_match_the_spec() {
        assert_eq!(nettype(Network::Mainnet), "mainnet");
        assert_eq!(nettype(Network::Testnet), "testnet");
        assert_eq!(nettype(Network::Stagenet), "stagenet");
        assert_eq!(nettype(Network::Fakechain), "fakechain");
    }

    /// `specs/11` §6: the error codes, and there is no -8.
    #[test]
    fn the_error_codes_match_the_spec() {
        assert_eq!(error::WRONG_PARAM, -1);
        assert_eq!(error::TOO_BIG_HEIGHT, -2);
        assert_eq!(error::INTERNAL_ERROR, -5);
        assert_eq!(error::UNSUPPORTED_RPC, -11);
        assert_eq!(error::RESTRICTED, -19);
    }

    /// An unimplemented method says so rather than returning a plausible empty
    /// answer, which a wallet would read as fact.
    #[test]
    fn an_unsupported_method_explains_itself() {
        let e = RpcError::unsupported("get_miner_data");
        assert_eq!(e.code, error::UNSUPPORTED_RPC);
        assert!(e.message.contains("get_miner_data"));
        assert!(
            e.message.contains("not implemented") && e.message.contains("restricted"),
            "the message should say why: {}",
            e.message
        );
    }
}
