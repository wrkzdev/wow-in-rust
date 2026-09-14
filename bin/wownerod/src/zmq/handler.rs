//! The ZMQ JSON-RPC methods (`src/rpc/daemon_handler.cpp`).
//!
//! # The envelope
//!
//! A request is `{"jsonrpc", "id", "method", "params"}`, every one required.
//! A success is `{"jsonrpc": "2.0", "id", "result": {"rpc_version": 131072,
//! ...}}`. A failure is not a JSON-RPC error code but `{"error": {"code": 1,
//! "error_str", "message"}}`, where `error_str` is `Failed`, `Invalid request
//! type` for a method that does not exist, or `Malformed json` -- with a null
//! id -- for a request that does not convert. The texts are the C++'s.
//!
//! # Restricted
//!
//! `--restricted-zmq-rpc` refuses the methods in `zmq_restricted_methods.h` by
//! name, before looking them up, and caps what the others may ask for.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};
use wow_consensus::fee;
use wow_consensus::hardfork::gates::{
    HF_VERSION_BLOCK_HEADER_MINER_SIG, HF_VERSION_DYNAMIC_FEE, HF_VERSION_PER_BYTE_FEE,
};
use wow_consensus::hardfork::HardFork;
use wow_crypto::types::{Hash256, KeyImage};
use wow_storage::db::BlockchainDb;
use wow_storage::lmdb::LmdbDb;
use wow_types::address::{Address, AddressKind};
use wow_types::block::Block;
use wow_types::tx::{Transaction, TxIn};
use wow_types::Network;

use super::json::{self, field, JsonError};
use crate::mempool::Rejection;
use crate::rpc::Server;

/// `DAEMON_RPC_VERSION_ZMQ`: 2.0.
pub const RPC_VERSION: u32 = 2 << 16;

/// `COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT` and `..._MAX_TX_COUNT`.
const MAX_BLOCK_COUNT: usize = 1_000;
const MAX_TX_COUNT: usize = 20_000;
/// `BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT`.
const MAX_HASHES: u64 = 10_000;

const RESTRICTED_MAX_FAKE_OUTS: usize = 5_000;
const RESTRICTED_HISTOGRAM_CUTOFF_SECS: u64 = 3 * 86_400;
const RESTRICTED_MAX_TXS: usize = 100;
const RESTRICTED_MAX_KEY_IMAGES: usize = 5_000;
const RESTRICTED_MAX_BLOCK_HEADERS: usize = 1_000;

/// `zmq_restricted_methods.h`.
const RESTRICTED_METHODS: &[&str] = &[
    "flush_txpool",
    "get_peer_list",
    "mining_status",
    "relay_tx",
    "save_bc",
    "set_log_categories",
    "set_log_level",
    "start_mining",
    "stop_mining",
];

/// Why a method gave no result.
#[derive(Debug)]
enum Error {
    /// The request did not convert: `Malformed json`.
    Json(JsonError),
    /// `status = Failed`, with its details.
    Failed(String),
}

impl From<JsonError> for Error {
    fn from(e: JsonError) -> Self {
        Error::Json(e)
    }
}

/// A method's result fields, or why there are none.
type Answer = Result<Map<String, Value>, Error>;

fn failed<T>(details: impl Into<String>) -> Result<T, Error> {
    Err(Error::Failed(details.into()))
}

fn db_failed(e: impl std::fmt::Display) -> Error {
    Error::Failed(e.to_string())
}

fn fields(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The methods, over the node the HTTP RPC serves.
pub struct Handler {
    server: Arc<Server>,
    restricted: bool,
}

impl Handler {
    pub fn new(server: Arc<Server>, restricted: bool) -> Handler {
        Handler { server, restricted }
    }

    /// A request in, its response out. Whatever arrives gets a response.
    pub fn handle(&self, request: &[u8]) -> Vec<u8> {
        respond(request, self.restricted, |method, params| {
            self.dispatch(method, params)
        })
        .into_bytes()
    }

    fn dispatch(&self, method: &str, p: &Value) -> Option<Answer> {
        Some(match method {
            "get_block_hash" => self.get_block_hash(p),
            "get_block_header_by_hash" => self.get_block_header_by_hash(p),
            "get_block_header_by_height" => self.get_block_header_by_height(p),
            "get_block_headers_by_height" => self.get_block_headers_by_height(p),
            "get_blocks_fast" => self.get_blocks_fast(p),
            "get_dynamic_fee_estimate" => self.get_dynamic_fee_estimate(p),
            "get_hashes_fast" => self.get_hashes_fast(p),
            "get_height" => Ok(fields(json!({"height": self.server.db().height()}))),
            "get_info" => self.get_info(),
            "get_last_block_header" => self.get_last_block_header(),
            "get_output_distribution" => self.get_output_distribution(p),
            "get_output_histogram" => self.get_output_histogram(p),
            "get_output_keys" => self.get_output_keys(p),
            // Routed but never written in the C++ either.
            "get_peer_list" => failed("RPC method not yet implemented."),
            "get_rpc_version" => Ok(fields(json!({"version": RPC_VERSION}))),
            "get_transaction_pool" => self.get_transaction_pool(),
            "get_transactions" => self.get_transactions(p),
            "get_tx_global_output_indices" => self.get_tx_global_output_indices(p),
            "hard_fork_info" => self.hard_fork_info(p),
            "key_images_spent" => self.key_images_spent(p),
            "mining_status" => self.mining_status(),
            "save_bc" => self.save_bc(),
            "send_raw_tx" => self.send_raw_tx(p),
            "send_raw_tx_hex" => self.send_raw_tx_hex(p),
            "set_log_level" => self.set_log_level(p),
            "start_mining" => self.start_mining(p),
            "stop_mining" => {
                self.server.stop_mining();
                Ok(Map::new())
            }
            _ => return None,
        })
    }

    // ------------------------------------------------------------ blocks

    fn get_block_hash(&self, p: &Value) -> Answer {
        let height = json::u64_of(field(p, "height")?)?;
        let db = self.server.db();
        if height >= db.height() {
            return failed("height given is higher than current chain height");
        }
        let hash = db.get_block_hash(height).map_err(db_failed)?;
        Ok(fields(json!({"hash": json::hex(&hash)})))
    }

    /// `getBlockHeaderByHash`: a main-chain block, or an alternative one.
    fn header(&self, hash: &Hash256) -> Option<Value> {
        let db = self.server.db();
        let blob = match db.get_block_height(hash) {
            Ok(h) => db.get_block_blob(h).ok()?,
            Err(_) => db.get_alt_block(hash).ok()?.1,
        };
        let block = Block::from_blob(&blob).ok()?;
        let height = match block.miner_tx.prefix.vin.as_slice() {
            [TxIn::Gen { height }] => *height,
            _ => return None,
        };
        let h = &block.header;
        let reward = block
            .miner_tx
            .prefix
            .vout
            .iter()
            .fold(0u64, |sum, o| sum.wrapping_add(o.amount));
        Some(json!({
            // Filled in only from the fork that signs headers, as the C++ does.
            "vote": if h.major_version >= HF_VERSION_BLOCK_HEADER_MINER_SIG { h.vote } else { 0 },
            "major_version": h.major_version,
            "minor_version": h.minor_version,
            "timestamp": h.timestamp,
            "prev_id": json::hex(&h.prev_id),
            "nonce": h.nonce,
            "height": height,
            "depth": db.height().saturating_sub(height + 1),
            "hash": json::hex(hash),
            "difficulty": block_difficulty(db, height) as u64,
            "reward": reward,
        }))
    }

    fn get_last_block_header(&self) -> Answer {
        let db = self.server.db();
        let tip = db
            .height()
            .checked_sub(1)
            .and_then(|h| db.get_block_hash(h).ok());
        match tip.and_then(|h| self.header(&h)) {
            Some(header) => Ok(fields(json!({"header": header}))),
            None => failed("Requested block does not exist"),
        }
    }

    fn get_block_header_by_hash(&self, p: &Value) -> Answer {
        let hash = json::pod::<32>(field(p, "hash")?)?;
        match self.header(&hash) {
            Some(header) => Ok(fields(json!({"header": header}))),
            None => failed("Requested block does not exist"),
        }
    }

    fn get_block_header_by_height(&self, p: &Value) -> Answer {
        let height = json::u64_of(field(p, "height")?)?;
        let hash = self.server.db().get_block_hash(height).ok();
        match hash.and_then(|h| self.header(&h)) {
            Some(header) => Ok(fields(json!({"header": header}))),
            None => failed("Requested block does not exist"),
        }
    }

    fn get_block_headers_by_height(&self, p: &Value) -> Answer {
        let heights = json::vec_of(field(p, "heights")?, json::u64_of)?;
        if self.restricted && heights.len() > RESTRICTED_MAX_BLOCK_HEADERS {
            return failed("Too many block headers requested in restricted mode");
        }
        let db = self.server.db();
        let mut headers = Vec::with_capacity(heights.len());
        for height in heights {
            let header = db.get_block_hash(height).ok().and_then(|h| self.header(&h));
            match header {
                Some(h) => headers.push(h),
                None => return failed("A requested block does not exist"),
            }
        }
        Ok(fields(json!({"headers": headers})))
    }

    /// Blocks with their transactions as JSON, from where the caller's chain
    /// meets this one -- **including** the block both have, as the C++ sends
    /// it -- or from `start_height` when that is not 0.
    fn get_blocks_fast(&self, p: &Value) -> Answer {
        let ids = json::vec_of(field(p, "block_ids")?, json::pod::<32>)?;
        let start_height = json::u64_of(field(p, "start_height")?)?;
        let prune = json::bool_of(field(p, "prune")?)?;

        const NO_SUPPLEMENT: &str = "core::find_blockchain_supplement() returned false";
        let db = self.server.db();
        let height = db.height();
        let from = if start_height > 0 {
            if start_height >= height {
                return failed(NO_SUPPLEMENT);
            }
            start_height
        } else {
            match supplement_start(db, &ids) {
                Some(h) => h,
                None => return failed(NO_SUPPLEMENT),
            }
        };

        let mut blocks = Vec::new();
        let mut indices = Vec::new();
        let mut txs_total = 0usize;
        for h in from..height {
            if blocks.len() >= MAX_BLOCK_COUNT {
                break;
            }
            let blob = db.get_block_blob(h).map_err(db_failed)?;
            let Ok(block) = Block::from_blob(&blob) else {
                return failed("failed retrieving a requested block");
            };
            if !blocks.is_empty() && txs_total + block.tx_hashes.len() > MAX_TX_COUNT {
                break;
            }
            txs_total += block.tx_hashes.len();

            let miner_tx = wow_types::hashes::transaction_hash(&block.miner_tx).unwrap_or_default();
            let mut per_tx = vec![output_indices(db, &miner_tx)?];
            let mut txs = Vec::with_capacity(block.tx_hashes.len());
            for id in &block.tx_hashes {
                let Ok(tx_blob) = db.get_tx_blob(id) else {
                    return failed("incorrect number of transactions retrieved for block");
                };
                let parsed = if prune {
                    Transaction::from_blob_base_only(&tx_blob)
                } else {
                    Transaction::from_blob(&tx_blob)
                };
                let Ok(tx) = parsed else {
                    return failed("failed retrieving a requested transaction");
                };
                txs.push(json::transaction(&tx, prune));
                per_tx.push(output_indices(db, id)?);
            }
            blocks.push(json!({"block": json::block(&block), "transactions": txs}));
            indices.push(json!(per_tx));
        }
        Ok(fields(json!({
            "blocks": blocks,
            "start_height": from,
            "current_height": height,
            "output_indices": indices,
        })))
    }

    fn get_hashes_fast(&self, p: &Value) -> Answer {
        let known = json::vec_of(field(p, "known_hashes")?, json::pod::<32>)?;
        // Read, because the C++ requires it, and then overwritten by the
        // split as the C++ overwrites it.
        json::u64_of(field(p, "start_height")?)?;

        let db = self.server.db();
        let Some(from) = supplement_start(db, &known) else {
            return failed("Blockchain::find_blockchain_supplement() returned false");
        };
        let height = db.height();
        let hashes = (from..height.min(from.saturating_add(MAX_HASHES)))
            .map(|h| db.get_block_hash(h).map(|x| json::hex(&x)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_failed)?;
        Ok(fields(json!({
            "hashes": hashes,
            "start_height": from,
            "current_height": height,
        })))
    }

    fn get_info(&self) -> Answer {
        let server = &self.server;
        let db = server.db();
        let cfg = server.config();
        let restricted = self.restricted;
        let height = db.height();
        let top = height.saturating_sub(1);
        let sync = server.sync_status();
        let fee = server.fee_context();

        // The next block's difficulty, as `get_difficulty_for_next_block`
        // gives it; a read-only server has no chain state to ask, and gives
        // the tip's.
        let difficulty = match server.core() {
            Some(core) => core.next_block().map(|n| n.difficulty).unwrap_or(0),
            None => block_difficulty(db, top),
        };
        let cumulative = db.get_block_cumulative_difficulty(top).unwrap_or(0);
        let (white, grey) = server
            .p2p()
            .filter(|_| !restricted)
            .map(|p| {
                let (w, g) = p.peer_lists();
                (w.len(), g.len())
            })
            .unwrap_or((0, 0));
        let pool_size = server
            .pool()
            .entries()
            .filter(|(_, e)| !restricted || !e.do_not_relay)
            .count();

        let info = json::object_of([
            ("height", json!(height)),
            ("target_height", json!(sync.target_height.max(height))),
            ("top_block_height", json!(top)),
            ("difficulty", json!(difficulty as u64)),
            ("difficulty_top64", json!((difficulty >> 64) as u64)),
            (
                "target",
                json!(wow_consensus::constants::DIFFICULTY_TARGET_V2),
            ),
            (
                "tx_count",
                json!(total_transactions(db).saturating_sub(height)),
            ),
            ("tx_pool_size", json!(pool_size)),
            (
                "alt_blocks_count",
                json!(if restricted {
                    0
                } else {
                    db.get_alt_block_count().unwrap_or(0)
                }),
            ),
            (
                "outgoing_connections_count",
                json!(if restricted { 0 } else { sync.outgoing }),
            ),
            (
                "incoming_connections_count",
                json!(if restricted { 0 } else { sync.incoming }),
            ),
            ("white_peerlist_size", json!(white)),
            ("grey_peerlist_size", json!(grey)),
            ("mainnet", json!(cfg.network == Network::Mainnet)),
            ("testnet", json!(cfg.network == Network::Testnet)),
            ("stagenet", json!(cfg.network == Network::Stagenet)),
            // The C++ never fills it in.
            ("nettype", json!("")),
            (
                "top_block_hash",
                json::hex(&db.get_block_hash(top).unwrap_or_default()),
            ),
            ("cumulative_difficulty", json!(cumulative as u64)),
            (
                "cumulative_difficulty_top64",
                json!((cumulative >> 64) as u64),
            ),
            ("block_size_limit", json!(fee.cumulative_weight_limit)),
            ("block_weight_limit", json!(fee.cumulative_weight_limit)),
            ("block_size_median", json!(fee.median())),
            ("block_weight_median", json!(fee.median())),
            ("adjusted_time", json!(unix_now())),
            (
                "start_time",
                json!(if restricted { 0 } else { server.start_time() }),
            ),
            (
                "version",
                json!(if restricted { "" } else { crate::cli::VERSION }),
            ),
        ]);
        Ok(fields(json!({"info": info})))
    }

    fn hard_fork_info(&self, p: &Value) -> Answer {
        let requested = json::u8_of(field(p, "version")?)?;
        let hf = HardFork::new(self.server.config().network);
        let top = self.server.db().height().saturating_sub(1);
        let version = if requested > 0 {
            requested
        } else {
            hf.ideal_version_top()
        };
        let enabled = hf.is_active(version, top);
        // As the HTTP `hard_fork_info`: with a zero threshold nothing is voted
        // on, and a fork is on by height alone.
        Ok(fields(json!({"info": {
            "version": hf.required_version(top),
            "enabled": enabled,
            "window": 10_080,
            "votes": 0,
            "threshold": 0,
            "voting": hf.ideal_version_top(),
            "state": if enabled { 2 } else { 0 },
            "earliest_height": hf.earliest_height(version).unwrap_or(0),
        }})))
    }

    fn get_dynamic_fee_estimate(&self, p: &Value) -> Answer {
        let grace = json::u64_of(field(p, "num_grace_blocks")?)?;
        let ctx = self.server.fee_context();
        let base_reward = ctx
            .base_reward()
            .map_err(|e| Error::Failed(format!("{e:?}")))?;
        if ctx.version < HF_VERSION_PER_BYTE_FEE {
            return Ok(fields(json!({
                "fees": [],
                "estimated_base_fee": fee::get_dynamic_base_fee(base_reward, ctx.fee_median(), ctx.version),
                "fee_mask": 1,
                "size_scale": 1024,
                "hard_fork_version": ctx.version,
            })));
        }
        // A `CHECK_AND_ASSERT_THROW_MES` in the C++, whose handler reports
        // the exception as malformed JSON.
        if grace > wow_consensus::constants::CRYPTONOTE_REWARD_BLOCKS_WINDOW as u64 {
            return Err(Error::Json(JsonError(
                "Grace blocks invalid In 2021 fee scaling estimate.".into(),
            )));
        }
        let tiers = fee::fee_tiers_2021(base_reward, ctx.median(), ctx.long_term_effective_median);
        Ok(fields(json!({
            "fees": [tiers.low, tiers.normal, tiers.medium, tiers.high],
            "estimated_base_fee": tiers.low,
            "fee_mask": fee::FEE_QUANTIZATION_MASK,
            "size_scale": 1,
            "hard_fork_version": ctx.version,
        })))
    }

    // ----------------------------------------------------------- outputs

    fn get_tx_global_output_indices(&self, p: &Value) -> Answer {
        let id = json::pod::<32>(field(p, "tx_hash")?)?;
        let indices = output_indices(self.server.db(), &id)?;
        Ok(fields(json!({"output_indices": indices})))
    }

    fn get_output_keys(&self, p: &Value) -> Answer {
        let outputs = json::vec_of(field(p, "outputs")?, |o| {
            Ok((
                json::u64_of(field(o, "amount")?)?,
                json::u64_of(field(o, "index")?)?,
            ))
        })?;
        if self.restricted && outputs.len() > RESTRICTED_MAX_FAKE_OUTS {
            return failed("Too many outs requested");
        }
        let db = self.server.db();
        let (height, now) = (db.height(), unix_now());
        let mut keys = Vec::with_capacity(outputs.len());
        for (amount, index) in outputs {
            let o = db.get_output_key(amount, index, true).map_err(db_failed)?;
            keys.push(json!({
                "key": json::hex(&o.pubkey),
                "mask": json::hex(&o.commitment.unwrap_or_default()),
                "unlocked": wow_consensus::timestamp::is_tx_spendtime_unlocked(o.unlock_time, height, now),
            }));
        }
        Ok(fields(json!({"keys": keys})))
    }

    fn get_output_histogram(&self, p: &Value) -> Answer {
        let amounts = json::vec_of(field(p, "amounts")?, json::u64_of)?;
        let min_count = json::u64_of(field(p, "min_count")?)?;
        let max_count = json::u64_of(field(p, "max_count")?)?;
        let unlocked = json::bool_of(field(p, "unlocked")?)?;
        let recent_cutoff = json::u64_of(field(p, "recent_cutoff")?)?;
        if self.restricted && amounts.is_empty() {
            return failed(
                "Restricted RPC will not serve histograms on the whole blockchain. Use your own node.",
            );
        }
        if self.restricted
            && unix_now().saturating_sub(recent_cutoff) > RESTRICTED_HISTOGRAM_CUTOFF_SECS
        {
            return failed("Recent cutoff is too old");
        }

        let rows = self
            .server
            .db()
            .get_output_histogram(&amounts, unlocked, recent_cutoff, 0)
            .map_err(db_failed)?;
        let histogram: Vec<Value> = rows
            .into_iter()
            .filter(|(_, (total, _, _))| {
                *total >= min_count && (*total <= max_count || max_count == 0)
            })
            .map(|(amount, (total, unlocked, recent))| {
                json!({
                    "amount": amount,
                    "total_count": total,
                    "unlocked_count": unlocked,
                    "recent_count": recent,
                })
            })
            .collect();
        Ok(fields(json!({"histogram": histogram})))
    }

    fn get_output_distribution(&self, p: &Value) -> Answer {
        let amounts = json::vec_of(field(p, "amounts")?, json::u64_of)?;
        let from = json::u64_of(field(p, "from_height")?)?;
        let to = json::u64_of(field(p, "to_height")?)?;
        let cumulative = json::bool_of(field(p, "cumulative")?)?;
        if self.restricted && amounts != [0] {
            return failed(
                "Restricted RPC can only get output distribution for rct outputs. Use your own node.",
            );
        }

        let db = self.server.db();
        let to = if to > 0 {
            to
        } else {
            db.height().saturating_sub(1)
        };
        let network = self.server.config().network;
        let mut distributions = Vec::with_capacity(amounts.len());
        for amount in amounts {
            let Some((start, mut d, base)) = output_distribution(db, network, amount, from, to)
            else {
                return failed("Failed to get output distribution");
            };
            // `RpcHandler::get_output_distribution`: trimmed to the range
            // asked for, then made per-block unless a running total was.
            if to >= from {
                let offset = from.max(start);
                if offset <= to && ((to - offset + 1) as usize) < d.len() {
                    d.truncate((to - offset + 1) as usize);
                }
            }
            if !cumulative && !d.is_empty() {
                for n in (1..d.len()).rev() {
                    d[n] = d[n].wrapping_sub(d[n - 1]);
                }
                d[0] = d[0].wrapping_sub(base);
            }
            distributions.push(json!({
                "distribution": d,
                "amount": amount,
                "start_height": start,
                "base": base,
            }));
        }
        Ok(fields(
            json!({"status": "OK", "distributions": distributions}),
        ))
    }

    // -------------------------------------------------------------- pool

    fn get_transactions(&self, p: &Value) -> Answer {
        let wanted = json::vec_of(field(p, "tx_hashes")?, json::pod::<32>)?;
        if self.restricted && wanted.len() > RESTRICTED_MAX_TXS {
            return failed("Too many transactions requested in restricted mode");
        }
        let db = self.server.db();
        let pool = self.server.pool();
        let mut txs = Map::new();
        let mut missed = Vec::new();
        for id in &wanted {
            let key = wow_crypto::hex::encode(id);
            let on_chain = db
                .get_tx_blob(id)
                .ok()
                .and_then(|b| Transaction::from_blob(&b).ok());
            if let Some(tx) = on_chain {
                txs.insert(
                    key,
                    json!({
                        "height": db.get_tx_block_height(id).unwrap_or(0),
                        "in_pool": false,
                        "transaction": json::transaction(&tx, false),
                    }),
                );
            } else if let Some(tx) = pool
                .get(id)
                .and_then(|e| Transaction::from_blob(&e.blob).ok())
            {
                txs.insert(
                    key,
                    json!({
                        "height": u64::MAX,
                        "in_pool": true,
                        "transaction": json::transaction(&tx, false),
                    }),
                );
            } else {
                missed.push(json::hex(id));
            }
        }
        Ok(fields(json!({"txs": txs, "missed_hashes": missed})))
    }

    fn key_images_spent(&self, p: &Value) -> Answer {
        let images = json::vec_of(field(p, "key_images")?, json::pod::<32>)?;
        if self.restricted && images.len() > RESTRICTED_MAX_KEY_IMAGES {
            return failed("Too many key images queried in restricted mode");
        }
        let db = self.server.db();
        let pool = self.server.pool();
        let status: Vec<u64> = images
            .into_iter()
            .map(|ki| {
                let ki = KeyImage(ki);
                if db.has_key_image(&ki).unwrap_or(false) {
                    1
                } else if pool.spends(&ki) {
                    2
                } else {
                    0
                }
            })
            .collect();
        Ok(fields(json!({"spent_status": status})))
    }

    fn get_transaction_pool(&self) -> Answer {
        let pool = self.server.pool();
        let zero = json::hex(&[0u8; 32]);
        let transactions: Vec<Value> = pool
            .entries()
            .filter_map(|(id, e)| {
                let tx = Transaction::from_blob(&e.blob).ok()?;
                Some(json::object_of([
                    ("tx", json::transaction(&tx, false)),
                    ("tx_hash", json::hex(id)),
                    ("blob_size", json!(e.blob.len())),
                    ("weight", json!(e.weight)),
                    ("fee", json!(e.fee)),
                    ("max_used_block_hash", zero.clone()),
                    ("max_used_block_height", json!(0)),
                    ("kept_by_block", json!(e.kept_by_block)),
                    ("last_failed_block_hash", zero.clone()),
                    ("last_failed_block_height", json!(0)),
                    ("receive_time", json!(e.receive_time)),
                    ("last_relayed_time", json!(0)),
                    ("relayed", json!(e.relayed)),
                    ("do_not_relay", json!(e.do_not_relay)),
                    ("double_spend_seen", json!(e.double_spend_seen)),
                ]))
            })
            .collect();
        let mut key_images: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for (ki, id) in pool.spent_key_images() {
            key_images
                .entry(wow_crypto::hex::encode(&ki.0))
                .or_default()
                .push(json::hex(&id));
        }
        Ok(fields(
            json!({"transactions": transactions, "key_images": key_images}),
        ))
    }

    fn send_raw_tx(&self, p: &Value) -> Answer {
        let tx = json::transaction_from(field(p, "tx")?)?;
        let relay = json::bool_of(field(p, "relay")?)?;
        self.send(json::transaction_blob(&tx), relay)
    }

    fn send_raw_tx_hex(&self, p: &Value) -> Answer {
        let text = json::str_of(field(p, "tx_as_hex")?)?;
        let relay = json::bool_of(field(p, "relay")?)?;
        match wow_crypto::hex::decode(text) {
            Some(blob) => self.send(blob, relay),
            None => failed("Invalid hex"),
        }
    }

    /// `handleTxBlob`. `relayed` says the transaction went to the peer-to-peer
    /// layer: asked to, accepted, and a layer there to take it.
    fn send(&self, blob: Vec<u8>, relay: bool) -> Answer {
        let server = &self.server;
        if !server.sync_status().synchronized {
            return failed("Not ready to accept transactions; try again later");
        }
        let fee = server.fee_context();
        // The pool guard ends with this statement: relaying takes it again.
        let added = server
            .pool()
            .add(server.db(), &blob, &fee, unix_now(), !relay);
        let id = match added {
            Ok(id) => id,
            // Known already: not a failure in the C++, only nothing to relay.
            Err(Rejection::AlreadyInPool) => return Ok(fields(json!({"relayed": false}))),
            Err(r) => return failed(rejection_details(&r)),
        };
        if !relay {
            return Ok(fields(json!({"relayed": false})));
        }
        if let Some(core) = server.core() {
            core.announce_pool_txs(&[id]);
        }
        let relayed = match server.p2p() {
            Some(p2p) => {
                p2p.relay_transaction(id, blob);
                true
            }
            None => false,
        };
        Ok(fields(json!({"relayed": relayed})))
    }

    // ------------------------------------------------------------- admin

    fn start_mining(&self, p: &Value) -> Answer {
        let address = json::str_of(field(p, "miner_address")?)?;
        let threads = json::u64_of(field(p, "threads_count")?)?;
        let background = json::bool_of(field(p, "do_background_mining")?)?;
        json::bool_of(field(p, "ignore_battery")?)?;

        match Address::decode_for(address, self.server.config().network) {
            Err(_) => return failed("Failed, wrong address"),
            Ok(a) if a.kind == AddressKind::Subaddress => {
                return failed("Failed, mining to subaddress isn't supported yet")
            }
            Ok(_) => {}
        }
        let limit = std::thread::available_parallelism()
            .map(|n| n.get() as u64 * 4)
            .unwrap_or(257);
        if threads > limit {
            return failed("Failed, too many threads relative to CPU cores.");
        }
        // There is no background mining here, so a request for it is a miner
        // that does not start.
        if background {
            return failed("Failed, mining not started");
        }
        if let Err(e) = crate::rpc::mining::start(&self.server, address, threads.max(1) as usize) {
            wow_log::info!("miner", "ZMQ start_mining: {}", e.message);
            return failed("Failed, mining not started");
        }
        Ok(Map::new())
    }

    fn mining_status(&self) -> Answer {
        let status = self
            .server
            .miner()
            .as_ref()
            .map(crate::miner::Miner::status)
            .unwrap_or_default();
        let active = status.active;
        Ok(fields(json!({
            "active": active,
            "speed": if active { status.speed } else { 0 },
            "threads_count": if active { status.threads } else { 0 },
            "address": if active { status.address } else { String::new() },
            "is_background_mining_enabled": false,
        })))
    }

    fn save_bc(&self) -> Answer {
        let server = &self.server;
        if server.core().is_some() {
            let pool_saved = server.pool().save(server.db()).is_ok();
            if !pool_saved || server.db().sync().is_err() {
                return failed("Error storing the blockchain");
            }
        }
        Ok(Map::new())
    }

    fn set_log_level(&self, p: &Value) -> Answer {
        let level = json::i8_of(field(p, "level")?)?;
        match u8::try_from(level).ok().filter(|l| *l <= 4) {
            Some(l) => {
                let _ = wow_log::set_level(l);
                Ok(Map::new())
            }
            None => failed("Error: log level not valid"),
        }
    }
}

/// The envelope around a method, apart from the node, so it can be tested
/// without one. `dispatch` answers `None` for a method it does not know.
fn respond(
    request: &[u8],
    restricted: bool,
    dispatch: impl FnOnce(&str, &Value) -> Option<Answer>,
) -> String {
    let doc: Value = match serde_json::from_slice::<Value>(request) {
        Ok(v) if v.is_object() => v,
        _ => return bad_json("Failed to parse the json request"),
    };
    if doc.get("jsonrpc").is_none() {
        return bad_json(&json::missing("jsonrpc").0);
    }
    let method = match doc.get("method") {
        Some(Value::String(m)) => m.as_str(),
        Some(_) => return bad_json(&json::wrong_type("Expected string").0),
        None => return bad_json(&json::missing("method").0),
    };
    let Some(params) = doc.get("params") else {
        return bad_json(&json::missing("params").0);
    };
    let Some(id) = doc.get("id") else {
        return bad_json(&json::missing("id").0);
    };
    if restricted && RESTRICTED_METHODS.contains(&method) {
        return failure(
            id,
            "Failed",
            &format!("\"{method}\" is not available in restricted mode."),
        );
    }
    match dispatch(method, params) {
        None => failure(
            id,
            "Invalid request type",
            &format!("\"{method}\" is not a valid request."),
        ),
        Some(Ok(fields)) => {
            let mut result = Map::new();
            result.insert("rpc_version".into(), json!(RPC_VERSION));
            result.extend(fields);
            json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
        }
        Some(Err(Error::Failed(details))) => failure(id, "Failed", &details),
        Some(Err(Error::Json(e))) => bad_json(&e.0),
    }
}

fn failure(id: &Value, status: &str, details: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": 1, "error_str": status, "message": details},
    })
    .to_string()
}

/// `BAD_JSON`: no id to answer to.
fn bad_json(details: &str) -> String {
    failure(&Value::Null, "Malformed json", details)
}

/// `handleTxBlob`'s `error_details`: every rule broken, in the C++'s order
/// and words, joined with " and ".
fn rejection_details(r: &Rejection) -> String {
    let set = |name: &str| r.flags().iter().any(|(n, on)| *n == name && *on);
    let mut parts: Vec<&str> = [
        ("low_mixin", "mixin too low"),
        ("double_spend", "double spend"),
        ("invalid_input", "invalid input"),
        ("invalid_output", "invalid output"),
        ("too_big", "too big"),
        ("overspend", "overspend"),
        ("fee_too_low", "fee too low"),
        ("too_few_outputs", "too few outputs"),
    ]
    .into_iter()
    .filter(|(flag, _)| set(flag))
    .map(|(_, words)| words)
    .collect();
    if r.tx_extra_too_big() {
        parts.push("tx_extra too long");
    }
    if set("nonzero_unlock_time") {
        parts.push("non-zero unlock time");
    }
    if parts.is_empty() {
        "an unknown issue was found with the transaction".into()
    } else {
        parts.join(" and ")
    }
}

/// `Blockchain::find_blockchain_supplement`'s split: the height of the first
/// hash this chain has, from a history that must end at its genesis.
///
/// Inclusive, as the C++ has it. The HTTP `get_blocks.bin` here starts one
/// past it.
fn supplement_start(db: &LmdbDb, ids: &[Hash256]) -> Option<u64> {
    let genesis = db.get_block_hash(0).ok()?;
    if ids.last() != Some(&genesis) {
        return None;
    }
    ids.iter().find_map(|id| db.get_block_height(id).ok())
}

/// `get_tx_outputs_gindexs`: a transaction's output indices.
fn output_indices(db: &LmdbDb, id: &Hash256) -> Result<Vec<u64>, Error> {
    let fail = || Error::Failed("core::get_tx_outputs_gindexs() returned false".into());
    let data = db.get_tx_data(id).map_err(|_| fail())?;
    db.get_tx_amount_output_indices(data.tx_id, 1)
        .map_err(|_| fail())?
        .into_iter()
        .next()
        .ok_or_else(fail)
}

/// `Blockchain::block_difficulty`: the step in cumulative difficulty there.
fn block_difficulty(db: &LmdbDb, height: u64) -> u128 {
    let Ok(cumulative) = db.get_block_cumulative_difficulty(height) else {
        return 0;
    };
    let before = match height {
        0 => 0,
        h => db.get_block_cumulative_difficulty(h - 1).unwrap_or(0),
    };
    cumulative.saturating_sub(before)
}

/// Transactions on the chain, coinbases included: one past the id of the
/// tip's last one.
fn total_transactions(db: &LmdbDb) -> u64 {
    let Some(top) = db.height().checked_sub(1) else {
        return 0;
    };
    db.get_block_blob(top)
        .ok()
        .and_then(|b| Block::from_blob(&b).ok())
        .and_then(|b| match b.tx_hashes.last() {
            Some(h) => Some(*h),
            None => wow_types::hashes::transaction_hash(&b.miner_tx),
        })
        .and_then(|h| db.get_tx_data(&h).ok())
        .map(|d| d.tx_id + 1)
        .unwrap_or(0)
}

/// `Blockchain::get_output_distribution`: `(start_height, running totals,
/// base)`, or nothing for a range the chain cannot answer.
///
/// Only amount 0 -- RingCT outputs -- is kept as a running total, and no
/// wallet asks for the others; they fail, as a range past the tip does.
fn output_distribution(
    db: &LmdbDb,
    network: Network,
    amount: u64,
    from: u64,
    to: u64,
) -> Option<(u64, Vec<u64>, u64)> {
    // RingCT outputs do not exist before version 4, except on a test chain.
    let earliest = if amount == 0 && network != Network::Fakechain {
        HardFork::new(network)
            .earliest_height(HF_VERSION_DYNAMIC_FEE)
            .unwrap_or(0)
    } else {
        0
    };
    if to > 0 && to < from {
        return None;
    }
    let start = earliest.max(from);
    let height = db.height();
    if height == 0 || start >= height || to >= height || amount != 0 || start > to {
        return None;
    }
    let heights: Vec<u64> = (start.saturating_sub(1)..=to).collect();
    let mut d = db.get_block_cumulative_rct_outputs(&heights).ok()?;
    let base = if start > 0 {
        if d.is_empty() {
            return None;
        }
        d.remove(0)
    } else {
        0
    };
    Some((start, d, base))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(request: &str, restricted: bool) -> Value {
        let text = respond(
            request.as_bytes(),
            restricted,
            |method, params| match method {
                "get_height" => Some(Ok(fields(json!({"height": 7})))),
                "get_block_hash" => Some(
                    field(params, "height")
                        .and_then(json::u64_of)
                        .map_err(Error::Json)
                        .and_then(|_| failed("height given is higher than current chain height")),
                ),
                _ => None,
            },
        );
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn a_result_carries_the_rpc_version_and_the_id() {
        let r = answer(
            r#"{"jsonrpc":"2.0","id":"a1","method":"get_height","params":{}}"#,
            false,
        );
        assert_eq!(r["jsonrpc"], "2.0");
        assert_eq!(r["id"], "a1");
        assert_eq!(r["result"]["height"], 7);
        assert_eq!(r["result"]["rpc_version"], 131_072);
        assert!(r.get("error").is_none());
    }

    #[test]
    fn failures_are_worded_as_in_the_cpp() {
        let r = answer(
            r#"{"jsonrpc":"2.0","id":3,"method":"get_block_hash","params":{"height":9}}"#,
            false,
        );
        assert_eq!(
            r["error"],
            json!({"code": 1, "error_str": "Failed", "message": "height given is higher than current chain height"})
        );
        assert_eq!(r["id"], 3);

        let r = answer(
            r#"{"jsonrpc":"2.0","id":3,"method":"get_block_hash","params":{}}"#,
            false,
        );
        assert_eq!(r["id"], Value::Null, "a request that does not convert");
        assert_eq!(r["error"]["error_str"], "Malformed json");
        assert_eq!(r["error"]["message"], "Key \"height\" missing from object.");

        let r = answer(
            r#"{"jsonrpc":"2.0","id":3,"method":"nope","params":{}}"#,
            false,
        );
        assert_eq!(r["error"]["error_str"], "Invalid request type");
        assert_eq!(r["error"]["message"], "\"nope\" is not a valid request.");
        assert_eq!(r["id"], 3);

        for (request, message) in [
            ("{not json", "Failed to parse the json request"),
            ("[1]", "Failed to parse the json request"),
            (
                r#"{"id":1,"method":"get_height","params":{}}"#,
                "Key \"jsonrpc\" missing from object.",
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":5,"params":{}}"#,
                "Json value has incorrect type, expected: Expected string",
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"get_height"}"#,
                "Key \"params\" missing from object.",
            ),
            (
                r#"{"jsonrpc":"2.0","method":"get_height","params":{}}"#,
                "Key \"id\" missing from object.",
            ),
        ] {
            let r = answer(request, false);
            assert_eq!(r["error"]["error_str"], "Malformed json", "{request}");
            assert_eq!(r["error"]["message"], message, "{request}");
            assert_eq!(r["id"], Value::Null);
        }
    }

    /// Restricted methods are refused by name, before they are looked up.
    #[test]
    fn restricted_methods_are_refused_by_name() {
        for method in ["start_mining", "relay_tx"] {
            let r = answer(
                &format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{}}}}"#),
                true,
            );
            assert_eq!(r["error"]["error_str"], "Failed");
            assert_eq!(
                r["error"]["message"],
                format!("\"{method}\" is not available in restricted mode.")
            );
        }
        let r = answer(
            r#"{"jsonrpc":"2.0","id":1,"method":"get_height","params":{}}"#,
            true,
        );
        assert_eq!(r["result"]["height"], 7);
    }

    #[test]
    fn a_rejection_names_every_rule_broken() {
        assert_eq!(
            rejection_details(&Rejection::DoubleSpend {
                key_image: KeyImage([0; 32]),
                in_pool: None,
            }),
            "double spend"
        );
        assert_eq!(
            rejection_details(&Rejection::TxExtraTooBig { len: 2_000 }),
            "tx_extra too long"
        );
        assert_eq!(
            rejection_details(&Rejection::NotParseable("x".into())),
            "an unknown issue was found with the transaction"
        );
    }
}
