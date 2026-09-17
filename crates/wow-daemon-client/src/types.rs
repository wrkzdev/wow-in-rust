//! The endpoints a wallet needs, typed.
//!
//! `specs/11` §3 and §5, checked field by field against
//! `src/rpc/core_rpc_server_commands_defs.h` and
//! `src/cryptonote_protocol/cryptonote_protocol_defs.h`.
//!
//! # Two ways a `Vec<u64>` reaches the wire
//!
//! epee has no single "list of integers". Which form a field takes depends on
//! the macro the C++ used, and the two are not interchangeable:
//!
//! | Macro | On the wire |
//! |---|---|
//! | `KV_SERIALIZE(v)` | an **array** of `UINT64`, one entry each |
//! | `KV_SERIALIZE_CONTAINER_POD_AS_BLOB(v)` | one **string** of packed little-endian values |
//!
//! `block_ids` in a `get_blocks.bin` request is the second kind; `indices` and
//! `o_indexes` in the responses are the first. Getting it backwards produces a
//! request the daemon parses as empty — which looks like "the daemon rescanned
//! from genesis" rather than like an error.

use serde_json::{json, Value as Json};
use wow_crypto::types::Hash256;
use wow_serialize::epee::{self, Array, Section, Value};

use crate::{DaemonClient, DaemonError};

type Result<T> = std::result::Result<T, DaemonError>;

/// `COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT`: the most blocks one
/// `getblocks.bin` answer carries, whatever the request asks.
const GET_BLOCKS_MAX_BLOCK_COUNT: u64 = 1_000;

/// One block as `get_blocks.bin` returns it: the block blob and its
/// transactions' blobs, unparsed.
///
/// Parsing is the caller's, in `wow-types`, because a blob that does not parse
/// is a fact about the daemon and the caller is what decides to drop the peer.
#[derive(Clone, Debug, Default)]
pub struct BlockEntry {
    pub block: Vec<u8>,
    pub txs: Vec<Vec<u8>>,
    pub block_weight: u64,
    pub pruned: bool,
    /// Global amount-output indices, one list per transaction in the block,
    /// **coinbase first** and then `tx_hashes` order (`specs/11` §5.1).
    pub output_indices: Vec<Vec<u64>>,
}

/// The useful part of a `get_blocks.bin` response.
#[derive(Clone, Debug, Default)]
pub struct GetBlocks {
    pub blocks: Vec<BlockEntry>,
    pub start_height: u64,
    pub current_height: u64,
    pub daemon_time: u64,
}

/// What `gethashes.bin` answers: block hashes, from `start_height` up.
#[derive(Clone, Debug, Default)]
pub struct GetHashes {
    pub hashes: Vec<Hash256>,
    pub start_height: u64,
    pub current_height: u64,
}

/// One transaction in the pool, as `get_txpool_backlog` reports it:
/// `tx_backlog_entry`. No id and no blob, which is the point of asking this
/// rather than for the pool.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BacklogEntry {
    pub weight: u64,
    pub fee: u64,
    pub time_in_pool: u64,
}

/// One ring member, as `get_outs.bin` returns it.
#[derive(Clone, Copy, Debug)]
pub struct OutKey {
    pub key: [u8; 32],
    /// The amount commitment. For a pre-RingCT output the daemon synthesises
    /// one (`specs/10` §4.5).
    pub mask: [u8; 32],
    pub unlocked: bool,
    pub height: u64,
    pub txid: Hash256,
}

/// What `get_info` says that a wallet cares about.
#[derive(Clone, Debug, Default)]
pub struct Info {
    pub height: u64,
    pub target_height: u64,
    pub hard_fork_version: u8,
    pub nettype: String,
    pub synchronized: bool,
    pub top_block_hash: String,
    /// Twice the median the fee tiers come from; half of it is the full
    /// reward zone. 0 when the daemon does not say.
    pub block_weight_limit: u64,
}

/// The outcome of a relay attempt.
#[derive(Clone, Debug, Default)]
pub struct SendResult {
    pub status: String,
    pub reason: String,
    pub not_relayed: bool,
    pub double_spend: bool,
    pub invalid_input: bool,
    pub invalid_output: bool,
    pub low_mixin: bool,
    pub too_big: bool,
    pub overspend: bool,
    pub fee_too_low: bool,
}

impl SendResult {
    pub fn accepted(&self) -> bool {
        self.status == "OK"
    }
}

/// One transaction in the daemon's pool, as `/get_transaction_pool` lists it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolTx {
    pub id: Hash256,
    pub blob: Vec<u8>,
    /// When the daemon received it.
    pub receive_time: u64,
    pub relayed: bool,
    pub double_spend_seen: bool,
}

/// `COMMAND_RPC_IS_KEY_IMAGE_SPENT::STATUS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyImageStatus {
    Unspent,
    /// In a block.
    SpentInChain,
    /// By a transaction in the pool.
    SpentInPool,
}

impl DaemonClient {
    // -- direct JSON --------------------------------------------------------

    /// `/get_height`.
    pub fn get_height(&self) -> Result<u64> {
        let v = self.direct("/get_height", json!({}))?;
        u64_of(&v, "height")
    }

    /// `/get_info` (`specs/11` §3.2).
    pub fn get_info(&self) -> Result<Info> {
        let v = self.direct("/get_info", json!({}))?;
        Ok(Info {
            height: u64_of(&v, "height")?,
            // A node that is fully synced reports `target_height` as 0, which
            // would read as "the chain is empty" if taken at face value.
            target_height: v
                .get("target_height")
                .and_then(Json::as_u64)
                .unwrap_or(0)
                .max(u64_of(&v, "height")?),
            hard_fork_version: v
                .get("hard_fork_version")
                .and_then(Json::as_u64)
                .unwrap_or(0) as u8,
            nettype: v
                .get("nettype")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
            synchronized: v
                .get("synchronized")
                .and_then(Json::as_bool)
                .unwrap_or(false),
            top_block_hash: v
                .get("top_block_hash")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
            // `NodeRPCProxy::get_block_weight_limit` falls back to the name
            // from before weights replaced sizes.
            block_weight_limit: v
                .get("block_weight_limit")
                .or_else(|| v.get("block_size_limit"))
                .and_then(Json::as_u64)
                .unwrap_or(0),
        })
    }

    /// `/sendrawtransaction` (`specs/11` §3.1).
    ///
    /// `do_not_relay` submits without broadcasting, which is how a wallet
    /// checks a transaction would be accepted before committing to it.
    ///
    /// By the name and with the fields `wallet2::commit_tx` sends, so a node
    /// sees the request a C++ wallet makes: `do_not_relay` and
    /// `do_sanity_checks` are `KV_SERIALIZE_OPT`, which epee leaves out at
    /// their defaults, false and true. `client` is left out altogether: it is
    /// a signature under a key the C++ wallet keeps in its cache
    /// (`m_rpc_client_secret_key`), which names the wallet across sessions
    /// rather than being a fingerprint worth copying.
    pub fn send_raw_transaction(&self, blob: &[u8], do_not_relay: bool) -> Result<SendResult> {
        let mut params = json!({ "tx_as_hex": wow_crypto::hex::encode(blob) });
        if do_not_relay {
            params["do_not_relay"] = Json::Bool(true);
        }
        // The status here is the *transaction's*, not the daemon's, so a
        // rejection must come back as a value rather than an error.
        let body = params.to_string();
        let raw = self.endpoint_post("/sendrawtransaction", body.as_bytes())?;
        let v: Json = serde_json::from_slice(&raw)?;

        Ok(SendResult {
            status: str_of(&v, "status"),
            reason: str_of(&v, "reason"),
            not_relayed: bool_of(&v, "not_relayed"),
            double_spend: bool_of(&v, "double_spend"),
            invalid_input: bool_of(&v, "invalid_input"),
            invalid_output: bool_of(&v, "invalid_output"),
            low_mixin: bool_of(&v, "low_mixin"),
            too_big: bool_of(&v, "too_big"),
            overspend: bool_of(&v, "overspend"),
            fee_too_low: bool_of(&v, "fee_too_low"),
        })
    }

    /// `get_fee_estimate` (`specs/11` §4.5). Returns the four priority tiers
    /// when the daemon offers them, and one-element fallback when it does not.
    pub fn get_fee_estimate(&self, grace_blocks: u64) -> Result<Vec<u64>> {
        let v = self.json_rpc("get_fee_estimate", json!({ "grace_blocks": grace_blocks }))?;
        if let Some(a) = v.get("fees").and_then(Json::as_array) {
            let tiers: Vec<u64> = a.iter().filter_map(Json::as_u64).collect();
            if !tiers.is_empty() {
                return Ok(tiers);
            }
        }
        Ok(vec![u64_of(&v, "fee")?])
    }

    /// `getblockheadersrange`, down to the one field a wallet reads from it:
    /// the weight of each block from `start_height` to `end_height` inclusive.
    pub fn get_block_weights(&self, start_height: u64, end_height: u64) -> Result<Vec<u64>> {
        let v = self.json_rpc(
            "getblockheadersrange",
            json!({ "start_height": start_height, "end_height": end_height }),
        )?;
        v.get("headers")
            .and_then(Json::as_array)
            .ok_or(DaemonError::Missing("headers"))?
            .iter()
            .map(|h| u64_of(h, "block_weight"))
            .collect()
    }

    // -- binary -------------------------------------------------------------

    /// `/getblocks.bin` — the refresh workhorse (`specs/11` §5.1).
    ///
    /// `block_ids` is the wallet's short chain history, newest first, genesis
    /// last. The daemon answers from the newest block in it that it has, that
    /// block included, which is how a reorg is detected without the wallet
    /// asking.
    ///
    /// `max_block_count` caps the reply below the daemon's own limit of 1000,
    /// and 0 leaves it there. A daemon that predates the field ignores it.
    ///
    /// The request is the one `wallet2::pull_blocks` sends, by the name it
    /// uses: `no_miner_tx` and `max_block_count` are `KV_SERIALIZE_OPT`, so
    /// epee leaves them out at their defaults, and `wallet2` never sets the
    /// second at all. It is only sent here below the daemon's limit, after a
    /// reply was cut short, when asking for fewer is worth being told apart
    /// by. `client` is left out: `send_raw_transaction` says why.
    pub fn get_blocks(
        &self,
        block_ids: &[Hash256],
        start_height: u64,
        prune: bool,
        no_miner_tx: bool,
        max_block_count: u64,
    ) -> Result<GetBlocks> {
        let mut req = Section::new();
        // CONTAINER_POD_AS_BLOB: one string, not an array.
        req.insert(
            "block_ids".into(),
            Value::String(block_ids.iter().flatten().copied().collect()),
        );
        req.insert("start_height".into(), Value::U64(start_height));
        req.insert("prune".into(), Value::Bool(prune));
        if no_miner_tx {
            req.insert("no_miner_tx".into(), Value::Bool(true));
        }
        if max_block_count > 0 && max_block_count < GET_BLOCKS_MAX_BLOCK_COUNT {
            req.insert("max_block_count".into(), Value::U64(max_block_count));
        }

        let res = self.binary("/getblocks.bin", &req)?;
        parse_get_blocks(&res)
    }

    /// `/gethashes.bin` — block hashes, from the newest hash in `block_ids`
    /// the daemon has, that block included (`find_blockchain_supplement`), up
    /// to the daemon's limit per call.
    ///
    /// How a wallet fills in the hashes below where it starts scanning without
    /// downloading the blocks, as `wallet2::fast_refresh` does. `start_height`
    /// is sent at zero, as `pull_hashes` sends it: `on_get_hashes` overwrites
    /// it with the split it finds.
    pub fn get_hashes(&self, block_ids: &[Hash256]) -> Result<GetHashes> {
        let mut req = Section::new();
        req.insert(
            "block_ids".into(),
            Value::String(block_ids.iter().flatten().copied().collect()),
        );
        // `KV_SERIALIZE`, not `_OPT`: written even at zero.
        req.insert("start_height".into(), Value::U64(0));
        let res = self.binary("/gethashes.bin", &req)?;
        parse_get_hashes(&res)
    }

    /// `/get_o_indexes.bin` — the global output indices of one transaction.
    pub fn get_o_indexes(&self, txid: &Hash256) -> Result<Vec<u64>> {
        let mut req = Section::new();
        req.insert("txid".into(), Value::String(txid.to_vec()));
        let res = self.binary("/get_o_indexes.bin", &req)?;
        Ok(u64_list(res.get("o_indexes")))
    }

    /// `/get_outs.bin` — the ring members for a set of `(amount, index)` pairs.
    pub fn get_outs(&self, wanted: &[(u64, u64)], get_txid: bool) -> Result<Vec<OutKey>> {
        let items: Vec<Value> = wanted
            .iter()
            .map(|(amount, index)| {
                let mut s = Section::new();
                s.insert("amount".into(), Value::U64(*amount));
                s.insert("index".into(), Value::U64(*index));
                Value::Object(s)
            })
            .collect();

        let mut req = Section::new();
        req.insert(
            "outputs".into(),
            Value::Array(Array {
                elem_type: epee::ty::OBJECT,
                items,
            }),
        );
        req.insert("get_txid".into(), Value::Bool(get_txid));

        let res = self.binary("/get_outs.bin", &req)?;
        let outs = res
            .get("outs")
            .and_then(Value::as_array)
            .ok_or(DaemonError::Missing("outs"))?;

        let mut v = Vec::with_capacity(outs.items.len());
        for item in &outs.items {
            let s = item.as_object().ok_or(DaemonError::BadField("outs"))?;
            v.push(OutKey {
                key: fixed32(s, "key")?,
                mask: fixed32(s, "mask")?,
                unlocked: s.get("unlocked").and_then(Value::as_bool).unwrap_or(false),
                height: s.get("height").and_then(Value::as_u64).unwrap_or(0),
                txid: fixed32(s, "txid").unwrap_or([0u8; 32]),
            });
        }
        Ok(v)
    }

    /// `/get_output_distribution.bin` — the per-block RingCT output counts
    /// decoy selection is built on (`specs/12` §4.3).
    ///
    /// Returns the **cumulative** count per block from `from_height`, plus the
    /// `base` count below the window. The gamma picker wants a single
    /// cumulative series, so the base is added back here rather than left for
    /// the caller to forget.
    pub fn get_output_distribution(
        &self,
        amount: u64,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<u64>> {
        let mut req = Section::new();
        req.insert(
            "amounts".into(),
            Value::Array(Array {
                elem_type: epee::ty::UINT64,
                items: vec![Value::U64(amount)],
            }),
        );
        req.insert("from_height".into(), Value::U64(from_height));
        req.insert("to_height".into(), Value::U64(to_height));
        req.insert("cumulative".into(), Value::Bool(true));
        // `binary: true` is **required** on the `.bin` endpoint --
        // `on_get_output_distribution_bin` answers `status: "Binary only call"`
        // and nothing else without it:
        //
        // ```cpp
        // if (!req.binary) { res.status = "Binary only call"; return false; }
        // ```
        //
        // It also changes the answer's shape: `distribution` comes back as
        // `CONTAINER_POD_AS_BLOB`, one string of little-endian u64s, rather
        // than an epee array. `u64_list` reads either.
        req.insert("binary".into(), Value::Bool(true));
        // `compress` would pack it with the reference's own varint scheme
        // (`compress_integer_array`), which is a second format to implement for
        // a saving that does not matter on one call per transaction.
        req.insert("compress".into(), Value::Bool(false));

        let res = self.binary("/get_output_distribution.bin", &req)?;
        let first = res
            .get("distributions")
            .and_then(Value::as_array)
            .and_then(|a| a.items.first())
            .and_then(Value::as_object)
            .ok_or(DaemonError::Missing("distributions"))?;

        let base = first.get("base").and_then(Value::as_u64).unwrap_or(0);
        let mut d = u64_list(first.get("distribution"));
        if base > 0 {
            for x in d.iter_mut() {
                *x += base;
            }
        }
        Ok(d)
    }

    /// `/get_transaction_pool_hashes.bin`.
    pub fn get_pool_hashes(&self) -> Result<Vec<Hash256>> {
        let res = self.binary("/get_transaction_pool_hashes.bin", &Section::new())?;
        // CONTAINER_POD_AS_BLOB: packed 32-byte hashes.
        let blob = res
            .get("tx_hashes")
            .and_then(Value::as_bytes)
            .unwrap_or(&[]);
        if !blob.len().is_multiple_of(32) {
            return Err(DaemonError::BadField("tx_hashes"));
        }
        Ok(blob.as_chunks::<32>().0.to_vec())
    }

    /// `/get_transaction_pool`: every transaction in the pool, with its blob.
    ///
    /// A restricted C++ node leaves out what was submitted with
    /// `do_not_relay`, which is nothing a wallet on another machine could
    /// have sent.
    pub fn get_transaction_pool(&self) -> Result<Vec<PoolTx>> {
        let v = self.direct("/get_transaction_pool", json!({}))?;
        parse_transaction_pool(&v)
    }

    /// `get_txpool_backlog`: the weight and fee of each transaction in the
    /// pool, and nothing else about them. What `wallet2::estimate_backlog`
    /// asks when it chooses a fee.
    ///
    /// Not through [`DaemonClient::json_rpc`]: the answer is not JSON a strict
    /// parser takes. [`parse_txpool_backlog`] says why.
    pub fn get_txpool_backlog(&self) -> Result<Vec<BacklogEntry>> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_txpool_backlog",
            "params": {},
        })
        .to_string();
        let raw = self.raw_post("/json_rpc", crate::JSON_CONTENT_TYPE, body.as_bytes())?;
        parse_txpool_backlog(&raw)
    }

    /// `/is_key_image_spent`, one status per key image, in order.
    pub fn is_key_image_spent(&self, key_images: &[[u8; 32]]) -> Result<Vec<KeyImageStatus>> {
        let hex: Vec<String> = key_images
            .iter()
            .map(|k| wow_crypto::hex::encode(k))
            .collect();
        let v = self.direct("/is_key_image_spent", json!({ "key_images": hex }))?;
        let status = v
            .get("spent_status")
            .and_then(Json::as_array)
            .ok_or(DaemonError::Missing("spent_status"))?;
        if status.len() != key_images.len() {
            return Err(DaemonError::BadField("spent_status"));
        }
        status
            .iter()
            .map(|s| match s.as_u64() {
                Some(0) => Ok(KeyImageStatus::Unspent),
                Some(1) => Ok(KeyImageStatus::SpentInChain),
                Some(2) => Ok(KeyImageStatus::SpentInPool),
                _ => Err(DaemonError::BadField("spent_status")),
            })
            .collect()
    }

    /// A `POST` that returns the raw body regardless of the `status` field.
    fn endpoint_post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        Ok(self.raw_post(path, crate::JSON_CONTENT_TYPE, body)?)
    }
}

/// Pull a `gethashes.bin` response apart.
fn parse_get_hashes(res: &Section) -> Result<GetHashes> {
    // CONTAINER_POD_AS_BLOB: packed 32-byte hashes.
    let blob = res
        .get("m_block_ids")
        .and_then(Value::as_bytes)
        .unwrap_or(&[]);
    if !blob.len().is_multiple_of(32) {
        return Err(DaemonError::BadField("m_block_ids"));
    }
    Ok(GetHashes {
        hashes: blob.as_chunks::<32>().0.to_vec(),
        start_height: res.get("start_height").and_then(Value::as_u64).unwrap_or(0),
        current_height: res
            .get("current_height")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    })
}

/// The bytes of one `tx_backlog_entry`: three `uint64_t`, little-endian.
const BACKLOG_ENTRY_BYTES: usize = 24;

/// Pull a `get_txpool_backlog` answer apart.
///
/// `backlog` is `KV_SERIALIZE_CONTAINER_POD_AS_BLOB`: the entries' own bytes,
/// put into a JSON string by epee's writer, which escapes nine characters
/// (`transform_to_escape_sequence`) and passes every other byte through as it
/// is. So the answer is not UTF-8, and a raw control byte makes it JSON no
/// strict parser takes. The string is cut out and unescaped here, and only
/// what is left, with an empty string in its place, goes to `serde_json`.
fn parse_txpool_backlog(raw: &[u8]) -> Result<Vec<BacklogEntry>> {
    let (blob, rest) = match cut_string(raw, b"\"backlog\"") {
        Some(cut) => cut,
        // An empty pool can come back without the field.
        None => (Vec::new(), raw.to_vec()),
    };
    let v: Json = serde_json::from_slice(&rest)?;
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        return Err(DaemonError::Rpc {
            code: err.get("code").and_then(Json::as_i64).unwrap_or(0),
            message: err
                .get("message")
                .and_then(Json::as_str)
                .unwrap_or("no message")
                .to_string(),
        });
    }
    let result = v.get("result").ok_or(DaemonError::Missing("result"))?;
    crate::check_status(result)?;
    if !blob.len().is_multiple_of(BACKLOG_ENTRY_BYTES) {
        return Err(DaemonError::BadField("backlog"));
    }
    Ok(blob
        .chunks_exact(BACKLOG_ENTRY_BYTES)
        .map(|e| {
            let word = |i: usize| {
                let mut b = [0u8; 8];
                b.copy_from_slice(&e[i * 8..i * 8 + 8]);
                u64::from_le_bytes(b)
            };
            BacklogEntry {
                weight: word(0),
                fee: word(1),
                time_in_pool: word(2),
            }
        })
        .collect())
}

/// Find the string value of `key` in raw epee JSON, and return its bytes
/// unescaped along with the document with that string emptied.
///
/// `None` when `key` is not followed by a string. The escapes are epee's, and
/// `\u00XX` besides, which is how a writer that does escape control
/// characters writes them.
fn cut_string(raw: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let at = raw.windows(key.len()).position(|w| w == key)?;
    let skip_space = |mut i: usize| {
        while raw.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        i
    };
    let mut i = skip_space(at + key.len());
    if raw.get(i) != Some(&b':') {
        return None;
    }
    i = skip_space(i + 1);
    if raw.get(i) != Some(&b'"') {
        return None;
    }
    let open = i;
    i += 1;
    let mut bytes = Vec::new();
    loop {
        let b = *raw.get(i)?;
        i += 1;
        match b {
            b'"' => break,
            b'\\' => {
                let escaped = *raw.get(i)?;
                i += 1;
                bytes.push(match escaped {
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'v' => 0x0b,
                    b'u' => {
                        let hex = std::str::from_utf8(raw.get(i..i + 4)?).ok()?;
                        i += 4;
                        u8::try_from(u16::from_str_radix(hex, 16).ok()?).ok()?
                    }
                    // `"`, `\` and `/` stand for themselves.
                    other => other,
                });
            }
            other => bytes.push(other),
        }
    }
    let mut rest = Vec::with_capacity(raw.len());
    rest.extend_from_slice(&raw[..open]);
    rest.extend_from_slice(b"\"\"");
    rest.extend_from_slice(&raw[i..]);
    Some((bytes, rest))
}

/// Pull a `get_blocks.bin` response apart.
fn parse_get_blocks(res: &Section) -> Result<GetBlocks> {
    // A caught-up wallet gets a response with **no `blocks` field at all**.
    // epee omits empty containers rather than writing an empty array, so
    // "nothing new since your last block" and "malformed answer" look
    // identical on the wire -- and treating the absence as an error is what
    // stopped a synced wallet from being able to refresh at all.
    //
    // `current_height` below still tells the caller where the daemon is, so
    // an empty answer is informative rather than a dead end.
    static EMPTY: Array = Array {
        elem_type: wow_serialize::epee::ty::OBJECT,
        items: Vec::new(),
    };
    let blocks = match res.get("blocks") {
        None => &EMPTY,
        Some(v) => v.as_array().ok_or(DaemonError::BadField("blocks"))?,
    };

    // `output_indices` is parallel to `blocks`. A daemon that omits it is
    // answering a `no_miner_tx`/pool-only call, so absence is not an error —
    // but a *shorter* list than `blocks` is, because it would silently
    // misalign every index after the gap.
    let out_idx = res.get("output_indices").and_then(Value::as_array);
    if let Some(o) = out_idx {
        if !o.items.is_empty() && o.items.len() != blocks.items.len() {
            return Err(DaemonError::BadField("output_indices"));
        }
    }

    let mut out = Vec::with_capacity(blocks.items.len());
    for (i, item) in blocks.items.iter().enumerate() {
        let s = item.as_object().ok_or(DaemonError::BadField("blocks"))?;
        let block = s
            .get("block")
            .and_then(Value::as_bytes)
            .ok_or(DaemonError::Missing("block"))?
            .to_vec();

        let txs = match s.get("txs") {
            None => Vec::new(),
            Some(Value::Array(a)) => a
                .items
                .iter()
                .map(|t| match t {
                    // Unpruned: a plain blob. Pruned: a section with `blob`.
                    Value::String(b) => Ok(b.clone()),
                    Value::Object(o) => Ok(o
                        .get("blob")
                        .and_then(Value::as_bytes)
                        .unwrap_or(&[])
                        .to_vec()),
                    _ => Err(DaemonError::BadField("txs")),
                })
                .collect::<Result<Vec<_>>>()?,
            Some(_) => return Err(DaemonError::BadField("txs")),
        };

        let output_indices = match out_idx.and_then(|o| o.items.get(i)) {
            None => Vec::new(),
            Some(v) => {
                let per_block = v
                    .as_object()
                    .and_then(|b| b.get("indices"))
                    .and_then(Value::as_array);
                match per_block {
                    None => Vec::new(),
                    Some(a) => a
                        .items
                        .iter()
                        .map(|t| u64_list(t.as_object().and_then(|s| s.get("indices"))))
                        .collect(),
                }
            }
        };

        out.push(BlockEntry {
            block,
            txs,
            block_weight: s.get("block_weight").and_then(Value::as_u64).unwrap_or(0),
            pruned: s.get("pruned").and_then(Value::as_bool).unwrap_or(false),
            output_indices,
        });
    }

    Ok(GetBlocks {
        blocks: out,
        start_height: res.get("start_height").and_then(Value::as_u64).unwrap_or(0),
        current_height: res
            .get("current_height")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        daemon_time: res.get("daemon_time").and_then(Value::as_u64).unwrap_or(0),
    })
}

/// A `Vec<u64>` in either of the two forms epee admits.
///
/// `KV_SERIALIZE` gives an array; `KV_SERIALIZE_CONTAINER_POD_AS_BLOB` gives a
/// packed string. The responses here use the first, but accepting both costs
/// nothing and means a daemon that changed its mind is still readable.
fn u64_list(v: Option<&Value>) -> Vec<u64> {
    match v {
        Some(Value::Array(a)) => a.items.iter().filter_map(Value::as_u64).collect(),
        Some(Value::String(b)) => b
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
            .collect(),
        _ => Vec::new(),
    }
}

/// Pull a `/get_transaction_pool` response apart.
///
/// An empty pool comes back with no `transactions` field at all: epee omits an
/// empty container, in JSON as in binary.
fn parse_transaction_pool(v: &Json) -> Result<Vec<PoolTx>> {
    let Some(txs) = v.get("transactions") else {
        return Ok(Vec::new());
    };
    let txs = txs
        .as_array()
        .ok_or(DaemonError::BadField("transactions"))?;
    txs.iter()
        .map(|t| {
            let id = wow_crypto::hex::decode(&str_of(t, "id_hash"))
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or(DaemonError::BadField("id_hash"))?;
            let blob = wow_crypto::hex::decode(&str_of(t, "tx_blob"))
                .filter(|b| !b.is_empty())
                .ok_or(DaemonError::BadField("tx_blob"))?;
            Ok(PoolTx {
                id,
                blob,
                receive_time: t.get("receive_time").and_then(Json::as_u64).unwrap_or(0),
                relayed: bool_of(t, "relayed"),
                double_spend_seen: bool_of(t, "double_spend_seen"),
            })
        })
        .collect()
}

fn fixed32(s: &Section, field: &'static str) -> Result<[u8; 32]> {
    s.get(field)
        .and_then(Value::as_bytes)
        .ok_or(DaemonError::Missing(field))?
        .try_into()
        .map_err(|_| DaemonError::BadField(field))
}

fn u64_of(v: &Json, field: &'static str) -> Result<u64> {
    v.get(field)
        .and_then(Json::as_u64)
        .ok_or(DaemonError::Missing(field))
}

fn str_of(v: &Json, field: &str) -> String {
    v.get(field)
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_string()
}

fn bool_of(v: &Json, field: &str) -> bool {
    v.get(field).and_then(Json::as_bool).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the shape a daemon sends, and read it back.
    /// A caught-up wallet gets a response with no `blocks` field, because epee
    /// omits empty containers rather than writing an empty array.
    ///
    /// Reading that as a malformed answer is what stopped an already-synced
    /// wallet from refreshing at all -- it could sync once and then never
    /// again, reporting "the response has no `blocks`" against a daemon that
    /// was working perfectly.
    #[test]
    fn a_response_with_no_blocks_means_nothing_new() {
        let mut res = Section::new();
        res.insert("status".into(), Value::String(b"OK".to_vec()));
        res.insert("current_height".into(), Value::U64(873_427));
        res.insert("start_height".into(), Value::U64(0));

        let got = parse_get_blocks(&res).expect("an empty answer is not an error");
        assert!(got.blocks.is_empty());
        assert_eq!(
            got.current_height, 873_427,
            "the daemon's height still comes through, so the caller learns where it is"
        );
    }

    /// A `blocks` field of the wrong *type* is still a fault. Absence means
    /// "none"; a string where an array belongs means the answer is not what it
    /// claims to be.
    #[test]
    fn a_blocks_field_of_the_wrong_type_is_refused() {
        let mut res = Section::new();
        res.insert("blocks".into(), Value::String(b"not an array".to_vec()));
        assert!(matches!(
            parse_get_blocks(&res),
            Err(DaemonError::BadField("blocks"))
        ));
    }

    #[test]
    fn a_get_blocks_response_parses() {
        let mut tx_indices = Section::new();
        tx_indices.insert(
            "indices".into(),
            Value::Array(Array {
                elem_type: epee::ty::UINT64,
                items: vec![Value::U64(10), Value::U64(11)],
            }),
        );
        let mut coinbase_indices = Section::new();
        coinbase_indices.insert(
            "indices".into(),
            Value::Array(Array {
                elem_type: epee::ty::UINT64,
                items: vec![Value::U64(7)],
            }),
        );

        let mut block_indices = Section::new();
        block_indices.insert(
            "indices".into(),
            Value::Array(Array {
                elem_type: epee::ty::OBJECT,
                items: vec![Value::Object(coinbase_indices), Value::Object(tx_indices)],
            }),
        );

        let mut entry = Section::new();
        entry.insert("block".into(), Value::String(vec![1, 2, 3]));
        entry.insert(
            "txs".into(),
            Value::Array(Array {
                elem_type: epee::ty::STRING,
                items: vec![Value::String(vec![4, 5])],
            }),
        );
        entry.insert("block_weight".into(), Value::U64(300));

        let mut res = Section::new();
        res.insert(
            "blocks".into(),
            Value::Array(Array {
                elem_type: epee::ty::OBJECT,
                items: vec![Value::Object(entry)],
            }),
        );
        res.insert(
            "output_indices".into(),
            Value::Array(Array {
                elem_type: epee::ty::OBJECT,
                items: vec![Value::Object(block_indices)],
            }),
        );
        res.insert("start_height".into(), Value::U64(100));
        res.insert("current_height".into(), Value::U64(4242));

        let got = parse_get_blocks(&res).expect("parses");
        assert_eq!(got.start_height, 100);
        assert_eq!(got.current_height, 4242);
        assert_eq!(got.blocks.len(), 1);
        assert_eq!(got.blocks[0].block, vec![1, 2, 3]);
        assert_eq!(got.blocks[0].txs, vec![vec![4, 5]]);
        assert_eq!(got.blocks[0].block_weight, 300);
        // Coinbase first, then the transactions.
        assert_eq!(got.blocks[0].output_indices, vec![vec![7], vec![10, 11]]);
    }

    /// `output_indices` shorter than `blocks` would misalign every index after
    /// the gap, so it is rejected rather than zipped.
    #[test]
    fn a_short_output_indices_list_is_rejected() {
        let mut entry = Section::new();
        entry.insert("block".into(), Value::String(vec![1]));

        let mut res = Section::new();
        res.insert(
            "blocks".into(),
            Value::Array(Array {
                elem_type: epee::ty::OBJECT,
                items: vec![Value::Object(entry.clone()), Value::Object(entry)],
            }),
        );
        res.insert(
            "output_indices".into(),
            Value::Array(Array {
                elem_type: epee::ty::OBJECT,
                items: vec![Value::Object(Section::new())],
            }),
        );

        assert!(matches!(
            parse_get_blocks(&res),
            Err(DaemonError::BadField("output_indices"))
        ));
    }

    /// Absent `output_indices` is fine — a pool-only or `no_miner_tx` call.
    #[test]
    fn absent_output_indices_is_not_an_error() {
        let mut entry = Section::new();
        entry.insert("block".into(), Value::String(vec![9]));
        let mut res = Section::new();
        res.insert(
            "blocks".into(),
            Value::Array(Array {
                elem_type: epee::ty::OBJECT,
                items: vec![Value::Object(entry)],
            }),
        );

        let got = parse_get_blocks(&res).expect("parses");
        assert!(got.blocks[0].output_indices.is_empty());
    }

    /// Both epee spellings of a `Vec<u64>` are read.
    #[test]
    fn both_integer_list_forms_are_read() {
        let as_array = Value::Array(Array {
            elem_type: epee::ty::UINT64,
            items: vec![Value::U64(1), Value::U64(2), Value::U64(3)],
        });
        assert_eq!(u64_list(Some(&as_array)), vec![1, 2, 3]);

        let mut packed = Vec::new();
        for n in [1u64, 2, 3] {
            packed.extend_from_slice(&n.to_le_bytes());
        }
        assert_eq!(u64_list(Some(&Value::String(packed))), vec![1, 2, 3]);

        assert!(u64_list(None).is_empty());
        assert!(u64_list(Some(&Value::Bool(true))).is_empty());
    }

    /// A missing block blob is an error rather than an empty block.
    #[test]
    fn a_block_without_a_blob_is_an_error() {
        let mut res = Section::new();
        res.insert(
            "blocks".into(),
            Value::Array(Array {
                elem_type: epee::ty::OBJECT,
                items: vec![Value::Object(Section::new())],
            }),
        );
        assert!(matches!(
            parse_get_blocks(&res),
            Err(DaemonError::Missing("block"))
        ));
    }

    /// A fully synced daemon reports `target_height` as 0. Taken at face value
    /// that reads as an empty chain, so it is floored at the height.
    #[test]
    fn a_zero_target_height_means_synced() {
        let v = json!({"height": 500_000, "target_height": 0});
        let info = Info {
            height: v.get("height").and_then(Json::as_u64).unwrap(),
            target_height: v
                .get("target_height")
                .and_then(Json::as_u64)
                .unwrap_or(0)
                .max(500_000),
            ..Default::default()
        };
        assert_eq!(info.target_height, 500_000);
    }

    /// A pool listing is read with its blobs, and an empty pool -- which epee
    /// sends with no `transactions` field -- is an empty list, not an error.
    #[test]
    fn a_pool_listing_parses_and_an_empty_one_is_empty() {
        let id = "3a".repeat(32);
        let v = json!({
            "status": "OK",
            "transactions": [{
                "id_hash": id,
                "tx_blob": "0201ff",
                "receive_time": 1_700_000_000u64,
                "relayed": true,
                "double_spend_seen": false,
            }],
        });
        let pool = parse_transaction_pool(&v).expect("parses");
        assert_eq!(pool.len(), 1);
        assert_eq!(pool[0].id, [0x3a; 32]);
        assert_eq!(pool[0].blob, vec![0x02, 0x01, 0xff]);
        assert_eq!(pool[0].receive_time, 1_700_000_000);
        assert!(pool[0].relayed);

        assert!(parse_transaction_pool(&json!({"status": "OK"}))
            .expect("parses")
            .is_empty());
        assert!(matches!(
            parse_transaction_pool(&json!({"transactions": [{"id_hash": "zz", "tx_blob": "00"}]})),
            Err(DaemonError::BadField("id_hash"))
        ));
    }

    /// Hashes come back packed, from the height the daemon found, and a blob
    /// that is not whole hashes is refused.
    #[test]
    fn a_hashes_response_parses() {
        let mut res = Section::new();
        let mut packed = vec![1u8; 32];
        packed.extend_from_slice(&[2u8; 32]);
        res.insert("m_block_ids".into(), Value::String(packed));
        res.insert("start_height".into(), Value::U64(838_800));
        res.insert("current_height".into(), Value::U64(880_000));
        let got = parse_get_hashes(&res).expect("parses");
        assert_eq!(got.hashes, vec![[1u8; 32], [2u8; 32]]);
        assert_eq!(got.start_height, 838_800);
        assert_eq!(got.current_height, 880_000);

        res.insert("m_block_ids".into(), Value::String(vec![0u8; 33]));
        assert!(matches!(
            parse_get_hashes(&res),
            Err(DaemonError::BadField("m_block_ids"))
        ));
    }

    /// epee's JSON writer as `transform_to_escape_sequence` has it: nine
    /// characters escaped, every other byte as it is.
    fn epee_escape(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for &b in bytes {
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
        out
    }

    /// The backlog is read from the raw bytes epee writes into a JSON string:
    /// escapes, a NUL, bytes that are not UTF-8 and a quote among them.
    #[test]
    fn a_backlog_is_read_from_the_bytes_epee_writes() {
        let entries = [
            BacklogEntry {
                weight: 0x2f5c_220a,
                fee: 0x0d0b_0c09_0800_ff80,
                time_in_pool: 12,
            },
            BacklogEntry {
                weight: 1_500,
                fee: 390_000_000,
                time_in_pool: 0,
            },
        ];
        let mut blob = Vec::new();
        for e in &entries {
            blob.extend_from_slice(&e.weight.to_le_bytes());
            blob.extend_from_slice(&e.fee.to_le_bytes());
            blob.extend_from_slice(&e.time_in_pool.to_le_bytes());
        }
        let mut raw = b"{\r\n  \"id\": \"0\",\r\n  \"jsonrpc\": \"2.0\",\r\n  \"result\": {\r\n    \"backlog\": \"".to_vec();
        raw.extend_from_slice(&epee_escape(&blob));
        raw.extend_from_slice(
            b"\",\r\n    \"credits\": 0,\r\n    \"status\": \"OK\",\r\n    \"top_hash\": \"\",\r\n    \"untrusted\": false\r\n  }\r\n}",
        );
        assert!(serde_json::from_slice::<Json>(&raw).is_err(), "not JSON as it stands");
        assert_eq!(parse_txpool_backlog(&raw).expect("parses"), entries);

        // An empty pool, with the field or without it.
        let empty = br#"{"id": "0", "jsonrpc": "2.0", "result": {"backlog": "", "status": "OK"}}"#;
        assert!(parse_txpool_backlog(empty).expect("parses").is_empty());
        let absent = br#"{"id": "0", "jsonrpc": "2.0", "result": {"status": "OK"}}"#;
        assert!(parse_txpool_backlog(absent).expect("parses").is_empty());

        // A node that does not serve it says so as an error, not as a backlog.
        let refused = br#"{"id": "0", "jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}}"#;
        assert!(matches!(
            parse_txpool_backlog(refused),
            Err(DaemonError::Rpc { code: -32601, .. })
        ));
        let busy = br#"{"id": "0", "jsonrpc": "2.0", "result": {"status": "BUSY"}}"#;
        assert!(matches!(parse_txpool_backlog(busy), Err(DaemonError::Status(_))));
        let torn = br#"{"id": "0", "jsonrpc": "2.0", "result": {"backlog": "abc", "status": "OK"}}"#;
        assert!(matches!(
            parse_txpool_backlog(torn),
            Err(DaemonError::BadField("backlog"))
        ));
    }
}
