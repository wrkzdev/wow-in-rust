//! The ZMQ interface's JSON forms (`src/serialization/json_object.cpp`).
//!
//! Not the HTTP RPC's. A transaction here is an object field by field rather
//! than a hex blob; hashes, keys and signatures are lowercase hex strings; a
//! byte vector is one hex string. Every field of a request is mandatory, as
//! `GET_FROM_JSON_OBJECT` makes it, and the errors for a missing or mistyped
//! one are the C++'s word for word, since a client may match on them.

use serde_json::{json, Map, Value};
use wow_crypto::types::{EcPoint, EcScalar, KeyImage, PublicKey, Signature, ViewTag};
use wow_types::block::Block;
use wow_types::rct::{
    Bulletproof, BulletproofPlus, Clsag, EcdhInfo, MgSig, RangeSig, RctSignatures, RctType,
};
use wow_types::tx::{Transaction, TransactionPrefix, TxIn, TxOut, TxOutTarget};

/// A request that does not convert, in the C++'s words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonError(pub String);

pub type Result<T> = std::result::Result<T, JsonError>;

/// `MISSING_KEY`.
pub fn missing(key: &str) -> JsonError {
    JsonError(format!("Key \"{key}\" missing from object."))
}

/// `WRONG_TYPE`.
pub fn wrong_type(expected: &str) -> JsonError {
    JsonError(format!(
        "Json value has incorrect type, expected: {expected}"
    ))
}

/// `BAD_INPUT`: the right type, but not a value that converts, such as hex of
/// the wrong length.
pub fn bad_input() -> JsonError {
    JsonError("An item failed to convert from json object to native object".into())
}

pub fn object(v: &Value) -> Result<&Map<String, Value>> {
    v.as_object().ok_or_else(|| wrong_type("json object"))
}

/// A field that must be there.
pub fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
    object(v)?.get(key).ok_or_else(|| missing(key))
}

pub fn u64_of(v: &Value) -> Result<u64> {
    v.as_u64().ok_or_else(|| wrong_type("unsigned integer"))
}

/// A narrower unsigned integer: rapidjson's `IsUint`, then the range check.
fn uint_of(v: &Value, max: u64) -> Result<u64> {
    let n = v
        .as_u64()
        .filter(|n| *n <= u64::from(u32::MAX))
        .ok_or_else(|| wrong_type("unsigned integer"))?;
    if n > max {
        return Err(wrong_type("numeric overflow"));
    }
    Ok(n)
}

pub fn u8_of(v: &Value) -> Result<u8> {
    uint_of(v, u8::MAX.into()).map(|n| n as u8)
}

pub fn i8_of(v: &Value) -> Result<i8> {
    let n = v
        .as_i64()
        .filter(|n| i32::try_from(*n).is_ok())
        .ok_or_else(|| wrong_type("integer"))?;
    i8::try_from(n).map_err(|_| {
        wrong_type(if n < 0 {
            "numeric underflow"
        } else {
            "numeric overflow"
        })
    })
}

pub fn bool_of(v: &Value) -> Result<bool> {
    v.as_bool().ok_or_else(|| wrong_type("boolean"))
}

pub fn str_of(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| wrong_type("string"))
}

pub fn vec_of<T>(v: &Value, item: impl Fn(&Value) -> Result<T>) -> Result<Vec<T>> {
    v.as_array()
        .ok_or_else(|| wrong_type("json array"))?
        .iter()
        .map(item)
        .collect()
}

/// A fixed-size value as hex: a hash, a key, a signature.
pub fn pod<const N: usize>(v: &Value) -> Result<[u8; N]> {
    wow_crypto::hex::decode_array(str_of(v)?).ok_or_else(bad_input)
}

pub fn bytes_of(v: &Value) -> Result<Vec<u8>> {
    wow_crypto::hex::decode(str_of(v)?).ok_or_else(bad_input)
}

fn point(v: &Value) -> Result<EcPoint> {
    pod(v).map(EcPoint)
}

fn scalar(v: &Value) -> Result<EcScalar> {
    pod(v).map(EcScalar)
}

fn public_key(v: &Value) -> Result<PublicKey> {
    pod(v).map(PublicKey)
}

// ------------------------------------------------------------ to JSON

pub fn hex(b: &[u8]) -> Value {
    Value::String(wow_crypto::hex::encode(b))
}

pub fn hexes<T: AsRef<[u8]>>(items: &[T]) -> Value {
    Value::Array(items.iter().map(|i| hex(i.as_ref())).collect())
}

/// An object from its fields in order, for objects too long for `json!`.
pub fn object_of<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// A transaction. `pruned` leaves out what a pruned one does not have: the
/// signatures and the prunable RingCT data.
pub fn transaction(tx: &Transaction, pruned: bool) -> Value {
    let p = &tx.prefix;
    let mut m = Map::new();
    m.insert("version".into(), json!(p.version));
    m.insert("unlock_time".into(), json!(p.unlock_time));
    m.insert(
        "inputs".into(),
        Value::Array(p.vin.iter().map(input).collect()),
    );
    m.insert(
        "outputs".into(),
        Value::Array(p.vout.iter().map(output).collect()),
    );
    m.insert("extra".into(), hex(&p.extra));
    if !pruned {
        let rows = tx
            .signatures
            .iter()
            .map(|row| Value::Array(row.iter().map(|s| hex(&s.to_bytes())).collect()))
            .collect();
        m.insert("signatures".into(), Value::Array(rows));
    }
    m.insert("ringct".into(), ringct(&tx.rct_signatures, pruned));
    Value::Object(m)
}

pub fn block(b: &Block) -> Value {
    let h = &b.header;
    json!({
        "major_version": h.major_version,
        "minor_version": h.minor_version,
        "timestamp": h.timestamp,
        "prev_id": hex(&h.prev_id),
        "nonce": h.nonce,
        "signature": hex(&h.signature.to_bytes()),
        "vote": h.vote,
        "miner_tx": transaction(&b.miner_tx, false),
        "tx_hashes": hexes(&b.tx_hashes),
    })
}

fn input(i: &TxIn) -> Value {
    match i {
        TxIn::Gen { height } => json!({"gen": {"height": height}}),
        TxIn::ToKey {
            amount,
            key_offsets,
            k_image,
        } => json!({"to_key": {
            "amount": amount,
            "key_offsets": key_offsets,
            "key_image": hex(&k_image.0),
        }}),
        TxIn::ToScript {
            prev,
            prevout,
            sigset,
        } => json!({"to_script": {
            "prev": hex(prev),
            "prevout": prevout,
            "sigset": hex(sigset),
        }}),
        TxIn::ToScriptHash {
            prev,
            prevout,
            script,
            sigset,
        } => json!({"to_scripthash": {
            "prev": hex(prev),
            "prevout": prevout,
            "script": script_json(script),
            "sigset": hex(sigset),
        }}),
    }
}

/// A `txout_to_script`, which is all a script-hash input can carry.
fn script_json(target: &TxOutTarget) -> Value {
    match target {
        TxOutTarget::ToScript { keys, script } => {
            json!({"keys": hexes(keys), "script": hex(script)})
        }
        _ => json!({"keys": [], "script": ""}),
    }
}

fn output(o: &TxOut) -> Value {
    let (name, target) = match &o.target {
        TxOutTarget::ToKey { key } => ("to_key", json!({"key": hex(&key.0)})),
        TxOutTarget::ToTaggedKey { key, view_tag } => (
            "to_tagged_key",
            json!({"key": hex(&key.0), "view_tag": hex(&[view_tag.0])}),
        ),
        TxOutTarget::ToScript { .. } => ("to_script", script_json(&o.target)),
        TxOutTarget::ToScriptHash { hash } => ("to_scripthash", json!({"hash": hex(hash)})),
    };
    let mut m = Map::new();
    m.insert("amount".into(), json!(o.amount));
    m.insert(name.into(), target);
    Value::Object(m)
}

fn ringct(rv: &RctSignatures, pruned: bool) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), json!(rv.ty as u8));
    if !rv.ty.is_null() {
        let encrypted = rv
            .ecdh_info
            .iter()
            .map(|e| json!({"mask": hex(&e.mask.0), "amount": hex(&e.amount.0)}))
            .collect();
        m.insert("encrypted".into(), Value::Array(encrypted));
        m.insert("commitments".into(), hexes(&rv.out_pk));
        m.insert("fee".into(), json!(rv.txn_fee));
    }

    let pseudo_outs = rv.effective_pseudo_outs();
    let prunable = !rv.bulletproofs.is_empty()
        || !rv.bulletproofs_plus.is_empty()
        || !rv.range_sigs.is_empty()
        || !rv.mgs.is_empty()
        || !pseudo_outs.is_empty();
    if !pruned && prunable {
        m.insert(
            "prunable".into(),
            json!({
                "range_proofs": rv.range_sigs.iter().map(range_sig).collect::<Vec<_>>(),
                "bulletproofs": rv.bulletproofs.iter().map(bulletproof).collect::<Vec<_>>(),
                "bulletproofs_plus": rv.bulletproofs_plus.iter().map(bulletproof_plus).collect::<Vec<_>>(),
                "mlsags": rv.mgs.iter().map(|g| json!({
                    "ss": g.ss.iter().map(|row| hexes(row)).collect::<Vec<_>>(),
                    "cc": hex(&g.cc.0),
                })).collect::<Vec<_>>(),
                "clsags": rv.clsags.iter().map(|c| json!({
                    "s": hexes(&c.s),
                    "c1": hex(&c.c1.0),
                    "D": hex(&c.d.0),
                })).collect::<Vec<_>>(),
                "pseudo_outs": hexes(pseudo_outs),
            }),
        );
    }
    Value::Object(m)
}

fn range_sig(r: &RangeSig) -> Value {
    json!({
        "asig": {"s0": hexes(&r.asig_s0), "s1": hexes(&r.asig_s1), "ee": hex(&r.asig_ee.0)},
        "Ci": hexes(&r.ci),
    })
}

/// `V` is not on the wire -- it is rebuilt from the commitments -- so it is
/// empty, as it is for a C++ transaction parsed from a blob.
fn bulletproof(b: &Bulletproof) -> Value {
    json!({
        "V": [],
        "A": hex(&b.a.0),
        "S": hex(&b.s.0),
        "T1": hex(&b.t1.0),
        "T2": hex(&b.t2.0),
        "taux": hex(&b.taux.0),
        "mu": hex(&b.mu.0),
        "L": hexes(&b.l),
        "R": hexes(&b.r),
        "a": hex(&b.a_scalar.0),
        "b": hex(&b.b.0),
        "t": hex(&b.t.0),
    })
}

fn bulletproof_plus(b: &BulletproofPlus) -> Value {
    json!({
        "V": [],
        "A": hex(&b.a.0),
        "A1": hex(&b.a1.0),
        "B": hex(&b.b.0),
        "r1": hex(&b.r1.0),
        "s1": hex(&b.s1.0),
        "d1": hex(&b.d1.0),
        "L": hexes(&b.l),
        "R": hexes(&b.r),
    })
}

// ---------------------------------------------------------- from JSON

/// A transaction from its JSON, for `send_raw_tx`. It is checked no further
/// than the C++ checks it here: the pool verifies the blob it becomes.
pub fn transaction_from(v: &Value) -> Result<Transaction> {
    object(v)?;
    let version = u64_of(field(v, "version")?)?;
    let unlock_time = u64_of(field(v, "unlock_time")?)?;
    let vin = vec_of(field(v, "inputs")?, input_from)?;
    let vout = vec_of(field(v, "outputs")?, output_from)?;
    let extra = bytes_of(field(v, "extra")?)?;
    let rct_signatures = ringct_from(field(v, "ringct")?)?;
    let signatures = match v.get("signatures") {
        Some(rows) => vec_of(rows, |row| {
            vec_of(row, |s| pod::<64>(s).map(|b| Signature::from_bytes(&b)))
        })?,
        None => Vec::new(),
    };
    Ok(Transaction {
        prefix: TransactionPrefix {
            version,
            unlock_time,
            vin,
            vout,
            extra,
        },
        signatures,
        rct_signatures,
        prefix_size: 0,
        unprunable_size: 0,
    })
}

/// A transaction's blob.
pub fn transaction_blob(tx: &Transaction) -> Vec<u8> {
    let mut w = wow_serialize::binary::Writer::with_capacity(2048);
    tx.write(&mut w);
    w.into_vec()
}

fn input_from(v: &Value) -> Result<TxIn> {
    let members = object(v)?;
    if members.len() != 1 {
        return Err(missing("Invalid input object"));
    }
    let Some((name, body)) = members.iter().next() else {
        return Err(missing("Invalid input object"));
    };
    Ok(match name.as_str() {
        "to_key" => TxIn::ToKey {
            amount: u64_of(field(body, "amount")?)?,
            key_offsets: vec_of(field(body, "key_offsets")?, u64_of)?,
            k_image: KeyImage(pod(field(body, "key_image")?)?),
        },
        "gen" => TxIn::Gen {
            height: u64_of(field(body, "height")?)?,
        },
        "to_script" => TxIn::ToScript {
            prev: pod(field(body, "prev")?)?,
            prevout: u64_of(field(body, "prevout")?)?,
            sigset: bytes_of(field(body, "sigset")?)?,
        },
        "to_scripthash" => TxIn::ToScriptHash {
            prev: pod(field(body, "prev")?)?,
            prevout: u64_of(field(body, "prevout")?)?,
            script: script_from(field(body, "script")?)?,
            sigset: bytes_of(field(body, "sigset")?)?,
        },
        // The C++ leaves the variant as it was constructed: a coinbase input
        // at height 0, which the pool then refuses.
        _ => TxIn::Gen { height: 0 },
    })
}

fn script_from(v: &Value) -> Result<TxOutTarget> {
    Ok(TxOutTarget::ToScript {
        keys: vec_of(field(v, "keys")?, public_key)?,
        script: bytes_of(field(v, "script")?)?,
    })
}

fn output_from(v: &Value) -> Result<TxOut> {
    let members = object(v)?;
    if members.len() != 2 {
        return Err(missing("Invalid input object"));
    }
    let mut out = TxOut {
        amount: 0,
        target: TxOutTarget::ToScript {
            keys: Vec::new(),
            script: Vec::new(),
        },
    };
    for (name, body) in members {
        match name.as_str() {
            "amount" => out.amount = u64_of(body)?,
            "to_key" => {
                out.target = TxOutTarget::ToKey {
                    key: public_key(field(body, "key")?)?,
                }
            }
            "to_tagged_key" => {
                out.target = TxOutTarget::ToTaggedKey {
                    key: public_key(field(body, "key")?)?,
                    view_tag: ViewTag(pod::<1>(field(body, "view_tag")?)?[0]),
                }
            }
            "to_script" => out.target = script_from(body)?,
            "to_scripthash" => {
                out.target = TxOutTarget::ToScriptHash {
                    hash: pod(field(body, "hash")?)?,
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

fn ringct_from(v: &Value) -> Result<RctSignatures> {
    object(v)?;
    let ty = RctType::from_u8(u8_of(field(v, "type")?)?).map_err(|_| bad_input())?;
    let mut rv = RctSignatures {
        ty,
        ..Default::default()
    };
    if !ty.is_null() {
        rv.ecdh_info = vec_of(field(v, "encrypted")?, ecdh_from)?;
        rv.out_pk = vec_of(field(v, "commitments")?, point)?;
        rv.txn_fee = u64_of(field(v, "fee")?)?;
    }
    if let Some(p) = v.get("prunable") {
        rv.range_sigs = vec_of(field(p, "range_proofs")?, range_sig_from)?;
        rv.bulletproofs = vec_of(field(p, "bulletproofs")?, bulletproof_from)?;
        rv.bulletproofs_plus = vec_of(field(p, "bulletproofs_plus")?, bulletproof_plus_from)?;
        rv.mgs = vec_of(field(p, "mlsags")?, mg_from)?;
        rv.clsags = vec_of(field(p, "clsags")?, clsag_from)?;
        let pseudo_outs = vec_of(field(p, "pseudo_outs")?, point)?;
        // `get_pseudo_outs()`: the base keeps them for type Simple only.
        if ty == RctType::Simple {
            rv.pseudo_outs_base = pseudo_outs;
        } else {
            rv.pseudo_outs = pseudo_outs;
        }
    }
    Ok(rv)
}

fn ecdh_from(v: &Value) -> Result<EcdhInfo> {
    Ok(EcdhInfo {
        mask: scalar(field(v, "mask")?)?,
        amount: scalar(field(v, "amount")?)?,
    })
}

/// A Borromean array, which has exactly 64 entries.
fn key64<T>(v: &Value, item: fn(&Value) -> Result<T>) -> Result<Vec<T>> {
    let items = vec_of(v, item)?;
    if items.len() != 64 {
        return Err(wrong_type("key64 (rct::key[64])"));
    }
    Ok(items)
}

fn range_sig_from(v: &Value) -> Result<RangeSig> {
    let ci = object(v)?.get("Ci").ok_or_else(|| missing("Ci"))?;
    let asig = field(v, "asig")?;
    object(asig)?;
    Ok(RangeSig {
        asig_s0: key64(field(asig, "s0")?, scalar)?,
        asig_s1: key64(field(asig, "s1")?, scalar)?,
        asig_ee: scalar(field(asig, "ee")?)?,
        ci: key64(ci, point)?,
    })
}

fn bulletproof_from(v: &Value) -> Result<Bulletproof> {
    vec_of(field(v, "V")?, point)?;
    Ok(Bulletproof {
        a: point(field(v, "A")?)?,
        s: point(field(v, "S")?)?,
        t1: point(field(v, "T1")?)?,
        t2: point(field(v, "T2")?)?,
        taux: scalar(field(v, "taux")?)?,
        mu: scalar(field(v, "mu")?)?,
        l: vec_of(field(v, "L")?, point)?,
        r: vec_of(field(v, "R")?, point)?,
        a_scalar: scalar(field(v, "a")?)?,
        b: scalar(field(v, "b")?)?,
        t: scalar(field(v, "t")?)?,
    })
}

fn bulletproof_plus_from(v: &Value) -> Result<BulletproofPlus> {
    vec_of(field(v, "V")?, point)?;
    Ok(BulletproofPlus {
        a: point(field(v, "A")?)?,
        a1: point(field(v, "A1")?)?,
        b: point(field(v, "B")?)?,
        r1: scalar(field(v, "r1")?)?,
        s1: scalar(field(v, "s1")?)?,
        d1: scalar(field(v, "d1")?)?,
        l: vec_of(field(v, "L")?, point)?,
        r: vec_of(field(v, "R")?, point)?,
    })
}

fn mg_from(v: &Value) -> Result<MgSig> {
    Ok(MgSig {
        ss: vec_of(field(v, "ss")?, |row| vec_of(row, scalar))?,
        cc: scalar(field(v, "cc")?)?,
    })
}

fn clsag_from(v: &Value) -> Result<Clsag> {
    Ok(Clsag {
        s: vec_of(field(v, "s")?, scalar)?,
        c1: scalar(field(v, "c1")?)?,
        d: point(field(v, "D")?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus_tx(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/../../tests/corpus/txs/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    /// **The JSON carries the whole transaction.** A mainnet transaction,
    /// written out and read back, is the same blob: nothing a `send_raw_tx`
    /// client sends is lost on the way to the pool.
    #[test]
    fn a_transaction_survives_json_both_ways() {
        for name in ["TX1", "TX2"] {
            let blob = corpus_tx(name);
            let tx = Transaction::from_blob(&blob).unwrap();
            let text = transaction(&tx, false).to_string();
            let back = transaction_from(&serde_json::from_str(&text).unwrap()).unwrap();
            assert_eq!(transaction_blob(&back), blob, "{name}");
        }
    }

    /// A pruned transaction has neither signatures nor prunable data.
    #[test]
    fn a_pruned_transaction_leaves_out_what_pruning_removes() {
        // TX2 spends; TX1 is a coinbase, which has nothing to prune.
        let tx = Transaction::from_blob(&corpus_tx("TX2")).unwrap();
        let full = transaction(&tx, false);
        assert!(full.get("signatures").is_some());
        assert!(full["ringct"].get("prunable").is_some(), "{full}");
        let pruned = transaction(&tx, true);
        assert!(pruned.get("signatures").is_none());
        assert!(pruned["ringct"].get("prunable").is_none());
        assert_eq!(pruned["ringct"]["fee"], full["ringct"]["fee"]);
    }

    /// The C++'s error texts, which a client may match.
    #[test]
    fn conversion_errors_are_worded_as_in_the_cpp() {
        assert_eq!(
            transaction_from(&json!({})).unwrap_err().0,
            "Key \"version\" missing from object."
        );
        assert_eq!(
            u64_of(&json!("1")).unwrap_err().0,
            "Json value has incorrect type, expected: unsigned integer"
        );
        assert_eq!(
            u8_of(&json!(256)).unwrap_err().0,
            "Json value has incorrect type, expected: numeric overflow"
        );
        assert_eq!(
            i8_of(&json!(-129)).unwrap_err().0,
            "Json value has incorrect type, expected: numeric underflow"
        );
        assert_eq!(
            pod::<32>(&json!("abcd")).unwrap_err().0,
            "An item failed to convert from json object to native object"
        );
        assert_eq!(
            field(&json!([]), "x").unwrap_err(),
            wrong_type("json object")
        );
        assert_eq!(
            input_from(&json!({"gen": {"height": 1}, "to_key": {}})).unwrap_err(),
            missing("Invalid input object")
        );
        assert_eq!(i8_of(&json!(4)).unwrap(), 4);
    }

    #[test]
    fn a_block_names_its_fields_as_the_cpp_does() {
        let tx = Transaction::from_blob(&corpus_tx("TX1")).unwrap();
        let b = Block {
            header: Default::default(),
            miner_tx: tx,
            tx_hashes: vec![[7u8; 32]],
        };
        let v = block(&b);
        for key in [
            "major_version",
            "minor_version",
            "timestamp",
            "prev_id",
            "nonce",
            "signature",
            "vote",
            "miner_tx",
            "tx_hashes",
        ] {
            assert!(v.get(key).is_some(), "{key}");
        }
        assert_eq!(v["signature"].as_str().unwrap().len(), 128);
        assert_eq!(v["tx_hashes"][0], "07".repeat(32));
    }
}
