//! The binary endpoints (`specs/11` §5).
//!
//! Request and response are **epee portable storage**, not JSON. These are the
//! wallet sync path and where essentially all the volume is, which is why the
//! reference uses a binary format for them at all.
//!
//! # `get_blocks.bin` is a chain-split search, not a range request
//!
//! A wallet does not ask for a height. It sends a **short chain history** —
//! its last ten block hashes, then exponentially spaced ones, then genesis —
//! and this endpoint answers from the first hash it recognises. A wallet on a
//! chain that no longer exists gets blocks from before the split without ever
//! having to ask whether there was one.
//!
//! `start_height` in the request is a fallback for a wallet with no history
//! yet. When the history matches nothing, the reference restarts from genesis
//! rather than honouring `start_height`, and so does this: honouring it would
//! let a wallet skip blocks it has never seen, which is how money goes missing.
//!
//! # Two ways a `Vec<u64>` reaches the wire
//!
//! epee has no single "list of integers", and which form a field takes is
//! fixed by the C++ macro that wrote it:
//!
//! | Macro | On the wire |
//! |---|---|
//! | `KV_SERIALIZE(v)` | an **array** of `UINT64` |
//! | `KV_SERIALIZE_CONTAINER_POD_AS_BLOB(v)` | one **string** of packed values |
//!
//! `block_ids` is the second kind; `indices` and `o_indexes` are the first.
//! These were read off `core_rpc_server_commands_defs.h`, field by field,
//! because a mismatch here does not look like an error — it looks like a
//! wallet that decided to rescan.

use wow_serialize::epee::{self, Array, Section, Value};
use wow_storage::db::BlockchainDb;
use wow_storage::lmdb::LmdbDb;

use super::methods::{error, RpcError};

/// `COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT`.
const MAX_BLOCK_COUNT: usize = 1_000;
/// `COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT`.
const MAX_TX_COUNT: usize = 20_000;
/// `COMMAND_RPC_GET_OUTPUTS_BIN_MAX_COUNT` — how many ring members one call may
/// ask for.
const MAX_OUTPUTS_COUNT: usize = 5_000;
/// A cap on how many hashes a wallet's history may contain, so a hostile
/// request cannot make the node search forever.
const MAX_BLOCK_IDS: usize = 256;

pub type BinaryResult = Result<Section, RpcError>;

/// Dispatch a binary endpoint.
pub fn dispatch(server: &super::Server, path: &str, body: &[u8]) -> BinaryResult {
    let request = epee::from_bytes(body)
        .map_err(|e| RpcError::new(error::WRONG_PARAM, format!("malformed epee request: {e}")))?;
    let db = server.db();

    match path {
        "/get_blocks.bin" | "/getblocks.bin" => get_blocks(db, &request),
        "/get_hashes.bin" | "/gethashes.bin" => get_hashes(db, &request),
        "/get_o_indexes.bin" => get_o_indexes(db, &request),
        "/get_outs.bin" => get_outs(db, &request),
        "/get_output_distribution.bin" => get_output_distribution(db, &request),
        "/get_transaction_pool_hashes.bin" => get_pool_hashes(server),
        other => Err(RpcError::unsupported(other)),
    }
}

/// The fields every response carries (`specs/11` §2).
fn base_response() -> Section {
    let mut s = Section::new();
    s.insert("status".into(), Value::String(b"OK".to_vec()));
    s.insert("untrusted".into(), Value::Bool(false));
    s.insert("credits".into(), Value::U64(0));
    s.insert("top_hash".into(), Value::String(Vec::new()));
    s
}

fn db_error(e: impl std::fmt::Display) -> RpcError {
    RpcError::new(error::INTERNAL_ERROR, e.to_string())
}

/// Where the wallet's history and our chain agree, as a height to resume from.
///
/// Returns one past the highest hash we recognise, or 0 when we recognise
/// none — which means "start from genesis", not "start from wherever the
/// request suggested".
fn split_height(db: &LmdbDb, block_ids: &[u8]) -> Result<u64, RpcError> {
    if block_ids.len() % 32 != 0 {
        return Err(RpcError::new(
            error::WRONG_PARAM,
            "block_ids is not a whole number of hashes",
        ));
    }
    let count = block_ids.len() / 32;
    if count > MAX_BLOCK_IDS {
        return Err(RpcError::new(
            error::WRONG_PARAM,
            format!("block_ids has {count} entries, more than {MAX_BLOCK_IDS}"),
        ));
    }

    // Newest first, so the first match is the deepest agreement.
    for chunk in block_ids.chunks_exact(32) {
        let hash: [u8; 32] = chunk.try_into().expect("32 bytes");
        if let Ok(h) = db.get_block_height(&hash) {
            return Ok(h + 1);
        }
    }
    Ok(0)
}

/// `/get_blocks.bin` (`specs/11` §5.1).
fn get_blocks(db: &LmdbDb, request: &Section) -> BinaryResult {
    let block_ids = request
        .get("block_ids")
        .and_then(Value::as_bytes)
        .unwrap_or(&[]);
    let no_miner_tx = request
        .get("no_miner_tx")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let height = db.height();
    let mut from = split_height(db, block_ids)?;
    // A wallet with no history at all may name a starting height.
    if block_ids.is_empty() {
        from = request
            .get("start_height")
            .and_then(Value::as_u64)
            .unwrap_or(0);
    }
    if from > height {
        return Err(RpcError::new(
            error::TOO_BIG_HEIGHT,
            format!("asked to start at {from}, past the tip at {height}"),
        ));
    }

    let mut blocks = Vec::new();
    let mut output_indices = Vec::new();
    let mut tx_budget = MAX_TX_COUNT;

    for h in from..height {
        if blocks.len() >= MAX_BLOCK_COUNT {
            break;
        }
        let blob = db.get_block_blob(h).map_err(db_error)?;
        let block = wow_types::block::Block::from_blob(&blob).map_err(db_error)?;

        // The transaction budget is checked *before* adding, so a block is
        // never returned with only some of its transactions — a wallet would
        // scan the gap as if it were empty.
        if !blocks.is_empty() && block.tx_hashes.len() > tx_budget {
            break;
        }
        tx_budget = tx_budget.saturating_sub(block.tx_hashes.len());

        let mut tx_blobs = Vec::with_capacity(block.tx_hashes.len());
        for txid in &block.tx_hashes {
            tx_blobs.push(Value::String(db.get_tx_blob(txid).map_err(db_error)?));
        }

        // Global output indices, coinbase first then `tx_hashes` order
        // (`specs/11` §5.1, `specs/10` §5.1).
        let per_tx = block_output_indices(db, &block, no_miner_tx)?;

        let mut entry = Section::new();
        entry.insert("block".into(), Value::String(blob));
        entry.insert(
            "txs".into(),
            Value::Array(Array {
                elem_type: epee::ty::STRING,
                items: tx_blobs,
            }),
        );
        entry.insert("pruned".into(), Value::Bool(false));
        entry.insert(
            "block_weight".into(),
            Value::U64(db.get_block_weight(h).unwrap_or(0)),
        );
        blocks.push(Value::Object(entry));
        output_indices.push(per_tx);
    }

    let mut res = base_response();
    res.insert(
        "blocks".into(),
        Value::Array(Array {
            elem_type: epee::ty::OBJECT,
            items: blocks,
        }),
    );
    res.insert(
        "output_indices".into(),
        Value::Array(Array {
            elem_type: epee::ty::OBJECT,
            items: output_indices,
        }),
    );
    res.insert("start_height".into(), Value::U64(from));
    res.insert("current_height".into(), Value::U64(height));
    res.insert("daemon_time".into(), Value::U64(now()));
    res.insert("pool_info_extent".into(), Value::U8(0));
    Ok(res)
}

/// `block_output_indices` for one block: a section holding an array of
/// per-transaction sections, each holding an array of `u64`.
fn block_output_indices(
    db: &LmdbDb,
    block: &wow_types::block::Block,
    no_miner_tx: bool,
) -> Result<Value, RpcError> {
    let mut per_tx: Vec<Value> = Vec::with_capacity(block.tx_hashes.len() + 1);

    let mut push = |indices: Vec<u64>| {
        let mut s = Section::new();
        s.insert(
            "indices".into(),
            Value::Array(Array {
                elem_type: epee::ty::UINT64,
                items: indices.into_iter().map(Value::U64).collect(),
            }),
        );
        per_tx.push(Value::Object(s));
    };

    // The coinbase still occupies a slot when it is suppressed, because the
    // slots are positional: dropping it would shift every transaction's
    // indices by one.
    if !no_miner_tx {
        let txid = wow_types::hashes::transaction_hash(&block.miner_tx).unwrap_or_default();
        push(tx_output_indices(db, &txid)?);
    } else {
        push(Vec::new());
    }
    for txid in &block.tx_hashes {
        push(tx_output_indices(db, txid)?);
    }

    let mut s = Section::new();
    s.insert(
        "indices".into(),
        Value::Array(Array {
            elem_type: epee::ty::OBJECT,
            items: per_tx,
        }),
    );
    Ok(Value::Object(s))
}

fn tx_output_indices(db: &LmdbDb, txid: &[u8; 32]) -> Result<Vec<u64>, RpcError> {
    let data = match db.get_tx_data(txid) {
        Ok(d) => d,
        // A transaction we cannot find has no indices. That is a real
        // condition for a coinbase in a block the miner_tx hash does not
        // resolve for, and an empty list is the honest answer.
        Err(_) => return Ok(Vec::new()),
    };
    let got = db
        .get_tx_amount_output_indices(data.tx_id, 1)
        .map_err(db_error)?;
    Ok(got.into_iter().next().unwrap_or_default())
}

/// `/get_hashes.bin` — block hashes from a short history, for a fast sync.
fn get_hashes(db: &LmdbDb, request: &Section) -> BinaryResult {
    let block_ids = request
        .get("block_ids")
        .and_then(Value::as_bytes)
        .unwrap_or(&[]);
    let from = split_height(db, block_ids)?;
    let height = db.height();

    let mut packed = Vec::new();
    for h in from..height.min(from + MAX_BLOCK_COUNT as u64) {
        packed.extend_from_slice(&db.get_block_hash(h).map_err(db_error)?);
    }

    let mut res = base_response();
    // CONTAINER_POD_AS_BLOB.
    res.insert("m_block_ids".into(), Value::String(packed));
    res.insert("start_height".into(), Value::U64(from));
    res.insert("current_height".into(), Value::U64(height));
    Ok(res)
}

/// `/get_o_indexes.bin` (`specs/11` §5.2).
fn get_o_indexes(db: &LmdbDb, request: &Section) -> BinaryResult {
    let txid: [u8; 32] = request
        .get("txid")
        .and_then(Value::as_bytes)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "txid is missing"))?
        .try_into()
        .map_err(|_| RpcError::new(error::WRONG_PARAM, "txid is not 32 bytes"))?;

    let indices = tx_output_indices(db, &txid)?;

    let mut res = base_response();
    res.insert(
        "o_indexes".into(),
        Value::Array(Array {
            elem_type: epee::ty::UINT64,
            items: indices.into_iter().map(Value::U64).collect(),
        }),
    );
    Ok(res)
}

/// `/get_outs.bin` — the ring members a wallet needs to build a transaction.
fn get_outs(db: &LmdbDb, request: &Section) -> BinaryResult {
    let wanted = request
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "outputs is missing"))?;

    if wanted.items.len() > MAX_OUTPUTS_COUNT {
        return Err(RpcError::new(
            error::WRONG_PARAM,
            format!(
                "{} outputs requested, more than {MAX_OUTPUTS_COUNT}",
                wanted.items.len()
            ),
        ));
    }

    let mut outs = Vec::with_capacity(wanted.items.len());
    for item in &wanted.items {
        let s = item
            .as_object()
            .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "outputs entry is not a section"))?;
        let amount = s.get("amount").and_then(Value::as_u64).unwrap_or(0);
        let index = s.get("index").and_then(Value::as_u64).unwrap_or(0);

        let data = db
            .get_output_key(amount, index, true)
            .map_err(|e| RpcError::new(error::WRONG_PARAM, e.to_string()))?;
        let (txid, _) = db
            .get_output_tx_and_index(amount, index)
            .unwrap_or(([0u8; 32], 0));

        let mut o = Section::new();
        o.insert("key".into(), Value::String(data.pubkey.to_vec()));
        o.insert(
            "mask".into(),
            Value::String(data.commitment.unwrap_or([0u8; 32]).to_vec()),
        );
        o.insert(
            "unlocked".into(),
            Value::Bool(wow_consensus::timestamp::is_tx_spendtime_unlocked(
                data.unlock_time,
                db.height(),
                now(),
            )),
        );
        o.insert("height".into(), Value::U64(data.height));
        o.insert("txid".into(), Value::String(txid.to_vec()));
        outs.push(Value::Object(o));
    }

    let mut res = base_response();
    res.insert(
        "outs".into(),
        Value::Array(Array {
            elem_type: epee::ty::OBJECT,
            items: outs,
        }),
    );
    Ok(res)
}

/// `/get_output_distribution.bin` — what decoy selection is built on
/// (`specs/12` §4.3).
fn get_output_distribution(db: &LmdbDb, request: &Section) -> BinaryResult {
    // The reference refuses this endpoint without `binary: true`:
    //
    // ```cpp
    // if (!req.binary) { res.status = "Binary only call"; return false; }
    // ```
    //
    // Accepting it anyway is the more forgiving thing to do and the wrong one.
    // This node's own client sent `binary: false` for months; every test passed
    // because this handler did not mind, and the first real daemon it met
    // answered "Binary only call" and broke decoy selection -- which is to say,
    // broke sending. A daemon that is lenient where the reference is strict
    // does not make clients work, it makes their bugs invisible until they meet
    // something else.
    let binary = request
        .get("binary")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !binary {
        return Err(RpcError::new(error::WRONG_PARAM, "Binary only call"));
    }

    let amounts = request
        .get("amounts")
        .and_then(Value::as_array)
        .map(|a| a.items.iter().filter_map(Value::as_u64).collect::<Vec<_>>())
        .unwrap_or_else(|| vec![0]);
    let from = request
        .get("from_height")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let height = db.height();
    let to = request
        .get("to_height")
        .and_then(Value::as_u64)
        .filter(|t| *t != 0)
        .unwrap_or(height.saturating_sub(1))
        .min(height.saturating_sub(1));

    let mut entries = Vec::with_capacity(amounts.len());
    for amount in amounts {
        let d = db
            .get_output_distribution(amount, from, to)
            .map_err(db_error)?;
        // The cumulative count below the window, which is what turns a
        // per-block distribution into global indices.
        let base = if from > 0 {
            db.get_output_distribution(amount, 0, from.saturating_sub(1))
                .map_err(db_error)?
                .last()
                .copied()
                .unwrap_or(0)
        } else {
            0
        };

        let mut s = Section::new();
        s.insert("amount".into(), Value::U64(amount));
        s.insert("start_height".into(), Value::U64(from));
        s.insert("base".into(), Value::U64(base));
        // Uncompressed. The reference can send a compressed form; a wallet
        // reads whichever it is given, and the compressed encoding buys
        // bandwidth this node does not need yet.
        s.insert(
            "distribution".into(),
            Value::Array(Array {
                elem_type: epee::ty::UINT64,
                items: d.into_iter().map(Value::U64).collect(),
            }),
        );
        s.insert("binary".into(), Value::Bool(true));
        s.insert("compress".into(), Value::Bool(false));
        entries.push(Value::Object(s));
    }

    let mut res = base_response();
    res.insert(
        "distributions".into(),
        Value::Array(Array {
            elem_type: epee::ty::OBJECT,
            items: entries,
        }),
    );
    Ok(res)
}

/// `/get_transaction_pool_hashes.bin`.
fn get_pool_hashes(server: &super::Server) -> BinaryResult {
    // `CONTAINER_POD_AS_BLOB`: one string of packed 32-byte hashes, not an
    // array (`specs/04` §2).
    let mut packed = Vec::new();
    for id in server.pool().ids() {
        packed.extend_from_slice(&id);
    }

    let mut res = base_response();
    res.insert("tx_hashes".into(), Value::String(packed));
    Ok(res)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// An epee error response for a binary endpoint.
pub fn error_response(e: &RpcError) -> Vec<u8> {
    let mut s = Section::new();
    s.insert(
        "status".into(),
        Value::String(e.message.as_bytes().to_vec()),
    );
    s.insert("untrusted".into(), Value::Bool(true));
    s.insert("credits".into(), Value::U64(0));
    s.insert("top_hash".into(), Value::String(Vec::new()));
    epee::to_bytes(&s).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The limits are the ones `specs/01` gives.
    #[test]
    fn the_limits_are_the_documented_ones() {
        assert_eq!(MAX_BLOCK_COUNT, 1_000);
        assert_eq!(MAX_TX_COUNT, 20_000);
    }

    /// An error response is well-formed epee that a client can parse, so a
    /// failure reaches the wallet as a message rather than as a decode error.
    #[test]
    fn an_error_response_is_parseable_epee() {
        let raw = error_response(&RpcError::new(error::TOO_BIG_HEIGHT, "past the tip"));
        let s = epee::from_bytes(&raw).expect("parses");
        assert_eq!(
            s.get("status").and_then(Value::as_bytes),
            Some(&b"past the tip"[..])
        );
        assert_eq!(s.get("untrusted").and_then(Value::as_bool), Some(true));
    }

    /// A base response carries the four fields `specs/11` §2 requires.
    #[test]
    fn the_base_response_has_the_common_fields() {
        let s = base_response();
        assert_eq!(s.get("status").and_then(Value::as_bytes), Some(&b"OK"[..]));
        assert!(s.contains_key("untrusted"));
        assert!(s.contains_key("credits"));
        assert!(s.contains_key("top_hash"));
    }
}
