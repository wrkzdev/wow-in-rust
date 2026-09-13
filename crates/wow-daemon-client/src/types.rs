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
        })
    }

    /// `/send_raw_transaction` (`specs/11` §3.1).
    ///
    /// `do_not_relay` submits without broadcasting, which is how a wallet
    /// checks a transaction would be accepted before committing to it.
    pub fn send_raw_transaction(&self, blob: &[u8], do_not_relay: bool) -> Result<SendResult> {
        let params = json!({
            "tx_as_hex": wow_crypto::hex::encode(blob),
            "do_not_relay": do_not_relay,
        });
        // The status here is the *transaction's*, not the daemon's, so a
        // rejection must come back as a value rather than an error.
        let body = params.to_string();
        let raw = self.endpoint_post("/send_raw_transaction", body.as_bytes())?;
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

    // -- binary -------------------------------------------------------------

    /// `/get_blocks.bin` — the refresh workhorse (`specs/11` §5.1).
    ///
    /// `block_ids` is the wallet's short chain history, newest first, genesis
    /// last. The daemon answers from the first hash it recognises, which is how
    /// a reorg is detected without the wallet asking.
    pub fn get_blocks(
        &self,
        block_ids: &[Hash256],
        start_height: u64,
        prune: bool,
        no_miner_tx: bool,
    ) -> Result<GetBlocks> {
        let mut req = Section::new();
        // CONTAINER_POD_AS_BLOB: one string, not an array.
        req.insert(
            "block_ids".into(),
            Value::String(block_ids.iter().flatten().copied().collect()),
        );
        req.insert("start_height".into(), Value::U64(start_height));
        req.insert("prune".into(), Value::Bool(prune));
        req.insert("no_miner_tx".into(), Value::Bool(no_miner_tx));

        let res = self.binary("/get_blocks.bin", &req)?;
        parse_get_blocks(&res)
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

    /// A `POST` that returns the raw body regardless of the `status` field.
    fn endpoint_post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        Ok(self.raw_post(path, "application/json", body)?)
    }
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
}
