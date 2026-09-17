//! Node administration and inspection endpoints (`specs/11` §3, §4).
//!
//! Most of these are marked **R** -- removed in restricted mode -- and the
//! router enforces that. Several need the peer-to-peer node or a writable
//! chain; on a read-only or offline server they say what is missing instead of
//! returning empty lists that would read as "no peers" or "no bans".
//!
//! Field names are the C++'s (`core_rpc_server_commands_defs.h`): a client
//! reads them by name.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde_json::{json, Value};
use wow_crypto::types::KeyImage;
use wow_p2p::addressbook::{is_public, BanTarget, PeerRecord};
use wow_p2p::node::{ConnectionInfo, Node};
use wow_storage::db::BlockchainDb;

use super::methods::{base, error, hex, internal, untrusted, RpcError, RpcResult};
use super::Server;
use crate::mempool::PoolEntry;

pub(crate) fn body_json(body: &[u8]) -> Result<Value, RpcError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(json!({}));
    }
    serde_json::from_slice(body)
        .map_err(|e| RpcError::new(error::WRONG_PARAM, format!("invalid JSON: {e}")))
}

fn p2p(server: &Server) -> Result<&Node, RpcError> {
    server.p2p().ok_or_else(|| {
        RpcError::new(
            error::UNSUPPORTED_RPC,
            "this node is not on the peer-to-peer network (it is offline or read-only)",
        )
    })
}

fn hash_of(v: &Value, what: &str) -> Result<[u8; 32], RpcError> {
    v.as_str()
        .and_then(wow_crypto::hex::decode)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, format!("{what} is not 32 hex bytes")))
}

fn hashes_of(params: &Value, name: &str) -> Result<Vec<[u8; 32]>, RpcError> {
    match params.get(name) {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => a.iter().map(|v| hash_of(v, name)).collect(),
        Some(_) => Err(RpcError::new(
            error::WRONG_PARAM,
            format!("{name} is not an array"),
        )),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// An IPv4 address as the C++ packs it into a `uint32_t`: the octets in wire
/// order, read little-endian. Zero for anything else.
fn packed_ipv4(ip: IpAddr) -> u32 {
    match ip {
        IpAddr::V4(v) => u32::from_le_bytes(v.octets()),
        IpAddr::V6(_) => 0,
    }
}

// ---------------------------------------------------------------- peers

/// `connection_info`.
fn connection_json(c: &ConnectionInfo) -> Value {
    let live = c.live_time.max(1);
    json!({
        "incoming": c.incoming,
        "localhost": c.address.ip().is_loopback(),
        "local_ip": !is_public(c.address.ip()),
        "address": c.address.to_string(),
        "host": c.address.ip().to_string(),
        "ip": c.address.ip().to_string(),
        "port": c.address.port().to_string(),
        "rpc_port": c.rpc_port,
        "rpc_credits_per_hash": 0,
        "peer_id": format!("{:016x}", c.peer_id),
        "recv_count": c.recv_bytes,
        "recv_idle_time": c.last_recv,
        "send_count": c.send_bytes,
        "send_idle_time": c.last_recv,
        "state": c.state,
        "live_time": c.live_time,
        "avg_download": c.recv_bytes / live / 1024,
        "current_download": 0,
        "avg_upload": c.send_bytes / live / 1024,
        "current_upload": 0,
        "support_flags": c.support_flags,
        "connection_id": format!("{:032x}", c.id),
        "height": c.height,
        "pruning_seed": c.pruning_seed,
        "address_type": if c.address.is_ipv4() { 1 } else { 2 },
    })
}

/// `get_connections` **R**.
pub fn get_connections(server: &Server) -> RpcResult {
    let conns: Vec<Value> = p2p(server)?
        .connections()
        .iter()
        .map(connection_json)
        .collect();
    let mut m = base("OK", untrusted());
    m.insert("connections".into(), json!(conns));
    Ok(Value::Object(m))
}

/// `sync_info` **R**.
pub fn sync_info(server: &Server) -> RpcResult {
    let node = p2p(server)?;
    let s = node.sync_status();
    let peers: Vec<Value> = node
        .connections()
        .iter()
        .map(|c| json!({ "info": connection_json(c) }))
        .collect();
    // `block_queue::foreach` in the C++, field for field.
    let spans: Vec<Value> = node
        .spans()
        .iter()
        .map(|sp| {
            json!({
                "start_block_height": sp.start_height,
                "nblocks": sp.nblocks,
                "connection_id": format!("{:032x}", sp.connection_id),
                "rate": sp.rate.round() as u64,
                "speed": (100.0 * sp.speed).round() as u64,
                "size": sp.size,
                "remote_address": sp.remote_address.to_string(),
            })
        })
        .collect();
    let mut m = base("OK", untrusted());
    m.insert("height".into(), json!(s.height));
    m.insert(
        "target_height".into(),
        json!(super::methods::target_height(&s)),
    );
    m.insert("next_needed_pruning_seed".into(), json!(0));
    m.insert("overview".into(), json!(node.queue_overview()));
    m.insert("peers".into(), json!(peers));
    m.insert("spans".into(), json!(spans));
    Ok(Value::Object(m))
}

/// `peer` in `get_peer_list`.
fn peer_json(r: &PeerRecord) -> Value {
    json!({
        "id": r.id,
        "host": r.addr.ip().to_string(),
        "ip": packed_ipv4(r.addr.ip()),
        "port": r.addr.port(),
        "rpc_port": r.rpc_port,
        "rpc_credits_per_hash": 0,
        "last_seen": r.last_seen,
        "pruning_seed": r.pruning_seed,
    })
}

/// `/get_peer_list` **R**.
pub fn get_peer_list(server: &Server) -> RpcResult {
    let (white, gray) = p2p(server)?.peer_lists();
    let mut m = base("OK", untrusted());
    m.insert(
        "white_list".into(),
        json!(white.iter().map(peer_json).collect::<Vec<_>>()),
    );
    m.insert(
        "gray_list".into(),
        json!(gray.iter().map(peer_json).collect::<Vec<_>>()),
    );
    Ok(Value::Object(m))
}

/// `/get_public_nodes`: peers that advertised an RPC port.
pub fn get_public_nodes(server: &Server, body: &[u8]) -> RpcResult {
    let req = body_json(body)?;
    let want_white = req.get("white").and_then(Value::as_bool).unwrap_or(true);
    let want_gray = req.get("gray").and_then(Value::as_bool).unwrap_or(false);
    let (white, gray) = p2p(server)?.peer_lists();
    let public = |list: &[PeerRecord]| -> Vec<Value> {
        list.iter()
            .filter(|r| r.rpc_port != 0)
            .map(|r| {
                json!({
                    "host": r.addr.ip().to_string(),
                    "last_seen": r.last_seen,
                    "rpc_port": r.rpc_port,
                    "rpc_credits_per_hash": 0,
                })
            })
            .collect()
    };
    let mut m = base("OK", untrusted());
    m.insert(
        "white".into(),
        json!(if want_white {
            public(&white)
        } else {
            Vec::new()
        }),
    );
    m.insert(
        "gray".into(),
        json!(if want_gray { public(&gray) } else { Vec::new() }),
    );
    Ok(Value::Object(m))
}

fn peer_limit(
    server: &Server,
    body: &[u8],
    name: &str,
    get: fn(&Node) -> usize,
    set: fn(&Node, usize),
) -> RpcResult {
    let node = p2p(server)?;
    let req = body_json(body)?;
    if req.get("set").and_then(Value::as_bool).unwrap_or(true) {
        let n = req
            .get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| RpcError::new(error::WRONG_PARAM, format!("{name} is missing")))?;
        set(node, n as usize);
    }
    let mut m = base("OK", untrusted());
    m.insert(name.into(), json!(get(node).min(u32::MAX as usize)));
    Ok(Value::Object(m))
}

/// `/in_peers` **R**.
pub fn in_peers(server: &Server, body: &[u8]) -> RpcResult {
    peer_limit(server, body, "in_peers", Node::in_peers, Node::set_in_peers)
}

/// `/out_peers` **R**.
pub fn out_peers(server: &Server, body: &[u8]) -> RpcResult {
    peer_limit(
        server,
        body,
        "out_peers",
        Node::out_peers,
        Node::set_out_peers,
    )
}

/// `/get_net_stats` **R**. The totals cover the connections open now.
pub fn get_net_stats(server: &Server) -> RpcResult {
    let conns = server.p2p().map(Node::connections).unwrap_or_default();
    let mut m = base("OK", untrusted());
    m.insert("start_time".into(), json!(server.start_time()));
    m.insert("total_packets_in".into(), json!(0));
    m.insert(
        "total_bytes_in".into(),
        json!(conns.iter().map(|c| c.recv_bytes).sum::<u64>()),
    );
    m.insert("total_packets_out".into(), json!(0));
    m.insert(
        "total_bytes_out".into(),
        json!(conns.iter().map(|c| c.send_bytes).sum::<u64>()),
    );
    Ok(Value::Object(m))
}

// ----------------------------------------------------------------- bans

fn target_of(entry: &Value) -> Result<BanTarget, RpcError> {
    let host = entry.get("host").and_then(Value::as_str).unwrap_or("");
    if !host.is_empty() {
        return BanTarget::parse(host).ok_or_else(|| {
            RpcError::new(
                error::WRONG_PARAM,
                format!("`{host}` is not an address or subnet"),
            )
        });
    }
    let ip = entry
        .get("ip")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "a ban names neither host nor ip"))?;
    Ok(BanTarget::Host(IpAddr::V4(Ipv4Addr::from(
        (ip as u32).to_le_bytes(),
    ))))
}

/// `get_bans` **R**.
pub fn get_bans(server: &Server) -> RpcResult {
    let bans: Vec<Value> = p2p(server)?
        .bans()
        .into_iter()
        .map(|(t, seconds)| {
            let ip = match t {
                BanTarget::Host(ip) => packed_ipv4(ip),
                BanTarget::Subnet(_) => 0,
            };
            json!({
                "host": t.to_string(),
                "ip": ip,
                "seconds": seconds.min(u64::from(u32::MAX)),
            })
        })
        .collect();
    let mut m = base("OK", untrusted());
    m.insert("bans".into(), json!(bans));
    Ok(Value::Object(m))
}

/// `set_bans` **R**.
pub fn set_bans(server: &Server, params: &Value) -> RpcResult {
    let node = p2p(server)?;
    let list = params
        .get("bans")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "bans is missing"))?;
    // Check every entry before applying any, so a bad one does not leave the
    // list half done.
    let parsed: Vec<(BanTarget, bool, u64)> = list
        .iter()
        .map(|b| {
            Ok((
                target_of(b)?,
                b.get("ban").and_then(Value::as_bool).unwrap_or(false),
                b.get("seconds").and_then(Value::as_u64).unwrap_or(0),
            ))
        })
        .collect::<Result<_, RpcError>>()?;
    for (target, ban, seconds) in parsed {
        if ban {
            node.ban(target, seconds);
        } else {
            node.unban(&target);
        }
    }
    Ok(Value::Object(base("OK", untrusted())))
}

/// `banned` **R**.
pub fn banned(server: &Server, params: &Value) -> RpcResult {
    let text = params
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "address is missing"))?;
    let ip: IpAddr = text
        .parse()
        .or_else(|_| text.parse::<SocketAddr>().map(|a| a.ip()))
        .map_err(|_| RpcError::new(error::WRONG_PARAM, format!("`{text}` is not an address")))?;
    let hit = p2p(server)?.bans().into_iter().find(|(t, _)| t.covers(ip));
    let mut m = base("OK", untrusted());
    m.insert("banned".into(), json!(hit.is_some()));
    m.insert("seconds".into(), json!(hit.map(|(_, s)| s).unwrap_or(0)));
    Ok(Value::Object(m))
}

// ----------------------------------------------------------------- pool

/// `flush_txpool` **R**: the named transactions, or all of them.
pub fn flush_txpool(server: &Server, params: &Value) -> RpcResult {
    let ids = hashes_of(params, "txids")?;
    let n = server.pool().flush(&ids);
    wow_log::info!("txpool", "flushed {n} transaction(s)");
    Ok(Value::Object(base("OK", untrusted())))
}

/// `relay_tx` **R**: send pooled transactions out again.
///
/// As the C++ does: one the network already has as fluff, and one still
/// private through the stem. Stemming a public one again showed its stem
/// peer what looks like a loop, and fluffing a private one would publish it
/// from this node.
pub fn relay_tx(server: &Server, params: &Value) -> RpcResult {
    let node = p2p(server)?;
    let ids = hashes_of(params, "txids")?;
    if ids.is_empty() {
        return Err(RpcError::new(error::WRONG_PARAM, "txids is empty"));
    }
    for id in ids {
        // The guard is dropped before relaying: relaying marks the pool entry,
        // which takes the pool lock again.
        let found = server
            .pool()
            .get(&id)
            .map(|e| (e.blob.clone(), e.is_public()));
        let (blob, public) = found.ok_or_else(|| {
            RpcError::new(
                error::WRONG_PARAM,
                format!("transaction {} is not in the pool", hex(&id)),
            )
        })?;
        if public {
            node.fluff_transaction(id, blob);
        } else {
            node.relay_transaction(id, blob);
        }
    }
    Ok(Value::Object(base("OK", untrusted())))
}

/// `/get_transaction_pool`.
///
/// On a restricted listener, the public transactions only, their receive
/// times zeroed, and only the key images they spend -- the C++'s answer
/// without sensitive data.
pub fn get_transaction_pool(server: &Server, restricted: bool) -> RpcResult {
    let pool = server.pool();
    let zero = hex(&[0u8; 32]);
    let txs: Vec<Value> = pool
        .entries()
        .filter(|(_, e)| !restricted || e.is_public())
        .map(|(id, e)| {
            json!({
                "id_hash": hex(id),
                "tx_json": "",
                "blob_size": e.blob.len(),
                "weight": e.weight,
                "fee": e.fee,
                "max_used_block_id_hash": zero,
                "max_used_block_height": 0,
                "kept_by_block": e.kept_by_block(),
                "last_failed_height": 0,
                "last_failed_id_hash": zero,
                "receive_time": if restricted { 0 } else { e.receive_time },
                "relayed": e.relayed,
                "last_relayed_time": 0,
                "do_not_relay": e.do_not_relay(),
                "double_spend_seen": e.double_spend_seen,
                "tx_blob": hex(&e.blob),
            })
        })
        .collect();
    let spent: Vec<Value> = pool
        .spent_key_images(!restricted)
        .into_iter()
        .map(|(ki, id)| json!({"id_hash": hex(&ki.0), "txs_hashes": [hex(&id)]}))
        .collect();
    let mut m = base("OK", untrusted());
    m.insert("transactions".into(), json!(txs));
    m.insert("spent_key_images".into(), json!(spent));
    Ok(Value::Object(m))
}

/// `/get_transaction_pool_hashes`: the public ones only, on a restricted
/// listener.
pub fn get_transaction_pool_hashes(server: &Server, restricted: bool) -> RpcResult {
    let ids: Vec<String> = server
        .pool()
        .ids(!restricted)
        .iter()
        .map(|h| hex(h))
        .collect();
    let mut m = base("OK", untrusted());
    m.insert("tx_hashes".into(), json!(ids));
    Ok(Value::Object(m))
}

/// `/get_transaction_pool_stats`: over the public transactions only, on a
/// restricted listener.
pub fn get_transaction_pool_stats(server: &Server, restricted: bool) -> RpcResult {
    let pool = server.pool();
    let now = unix_now();
    let visible: Vec<&PoolEntry> = pool
        .entries()
        .map(|(_, e)| e)
        .filter(|e| !restricted || e.is_public())
        .collect();
    let mut sizes: Vec<u64> = visible.iter().map(|e| e.blob.len() as u64).collect();
    sizes.sort_unstable();
    let median = wow_consensus::emission::median(&mut sizes.clone());
    let stats = json!({
        "bytes_total": sizes.iter().sum::<u64>(),
        "bytes_min": sizes.first().copied().unwrap_or(0),
        "bytes_max": sizes.last().copied().unwrap_or(0),
        "bytes_med": median,
        "fee_total": visible.iter().map(|e| e.fee).sum::<u64>(),
        "oldest": visible.iter().map(|e| e.receive_time).min().unwrap_or(0),
        "txs_total": visible.len(),
        "num_failing": 0,
        "num_10m": visible.iter().filter(|e| now.saturating_sub(e.receive_time) > 600).count(),
        "num_not_relayed": visible.iter().filter(|e| !e.relayed).count(),
        "histo_98pc": 0,
        "histo": [],
        "num_double_spends": visible.iter().filter(|e| e.double_spend_seen).count(),
    });
    let mut m = base("OK", untrusted());
    m.insert("pool_stats".into(), stats);
    Ok(Value::Object(m))
}

/// `/is_key_image_spent`: 0 unspent, 1 spent on chain, 2 spent in the pool --
/// by a public transaction, on a restricted listener.
pub fn is_key_image_spent(server: &Server, body: &[u8], restricted: bool) -> RpcResult {
    let req = body_json(body)?;
    let images = req
        .get("key_images")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "key_images is missing"))?;
    let parsed: Vec<[u8; 32]> = images
        .iter()
        .map(|v| hash_of(v, "a key image"))
        .collect::<Result<_, _>>()?;

    let db = server.db();
    let pool = server.pool();
    let status: Vec<u8> = parsed
        .into_iter()
        .map(|ki| {
            let ki = KeyImage(ki);
            if db.has_key_image(&ki).unwrap_or(false) {
                1
            } else if pool.spends(&ki, !restricted) {
                2
            } else {
                0
            }
        })
        .collect();
    let mut m = base("OK", untrusted());
    m.insert("spent_status".into(), json!(status));
    Ok(Value::Object(m))
}

// ----------------------------------------------------------------- node

/// `submit_block` / `submitblock` (`specs/11` §4.2): a block from outside the
/// peer network, put through the same validation as any other and announced
/// to peers once it joins the main chain.
///
/// As in the C++, only joining the main chain counts as accepted: a block kept
/// as an alternative is `BLOCK_NOT_ACCEPTED`, because a miner submitting it
/// wants to know it did not extend the chain.
pub fn submit_block(server: &Server, params: &Value) -> RpcResult {
    let core = server.core().ok_or_else(|| {
        RpcError::new(
            error::UNSUPPORTED_RPC,
            "the database is open read-only, so no block can be added",
        )
    })?;
    let wrong_blob = || RpcError::new(error::WRONG_BLOCKBLOB, "Wrong block blob");
    let text = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "expected [\"<block blob hex>\"]"))?;
    let blob = wow_crypto::hex::decode(text).ok_or_else(wrong_blob)?;
    let id = wow_types::Block::from_blob(&blob)
        .ok()
        .and_then(|b| b.block_id())
        .ok_or_else(wrong_blob)?;

    // `CORE_BUSY` while syncing, which a miner retries on (`specs/11` §6).
    if server.sync_status().busy_syncing {
        return Err(RpcError::new(error::CORE_BUSY, "Core is busy"));
    }

    let (verdict, relay) = core.submit_block(&blob);
    match verdict {
        wow_p2p::node::BlockVerdict::Added => {
            wow_log::info!("global", "submitted block {} added", hex(&id));
            if let (Some(p), Some(entry)) = (server.p2p(), relay) {
                p.relay_block(&entry);
            }
        }
        other => {
            return Err(RpcError::new(
                error::BLOCK_NOT_ACCEPTED,
                format!("Block not accepted: {other:?}"),
            ))
        }
    }
    let mut m = base("OK", untrusted());
    m.insert("block_id".into(), json!(hex(&id)));
    Ok(Value::Object(m))
}

/// `/stop_daemon` **R**.
pub fn stop_daemon(server: &Server) -> RpcResult {
    wow_log::info!("global", "stop requested over RPC");
    server.request_stop();
    Ok(Value::Object(base("OK", untrusted())))
}

/// `/save_bc` **R**: write the pool and flush the store.
pub fn save_bc(server: &Server) -> RpcResult {
    if server.core().is_some() {
        server.pool().save(server.db()).map_err(internal)?;
        server.db().sync().map_err(internal)?;
    }
    Ok(Value::Object(base("OK", untrusted())))
}

/// `/pop_blocks` **R**.
pub fn pop_blocks(server: &Server, body: &[u8]) -> RpcResult {
    let req = body_json(body)?;
    let n = req
        .get("nblocks")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "nblocks is missing"))?;
    let core = server.core().ok_or_else(|| {
        RpcError::new(
            error::UNSUPPORTED_RPC,
            "the database is open read-only, so no blocks can be popped",
        )
    })?;
    core.pop_blocks(n).map_err(internal)?;
    let mut m = base("OK", untrusted());
    m.insert("height".into(), json!(server.db().height()));
    Ok(Value::Object(m))
}

/// `/set_log_level` **R**.
pub fn set_log_level(body: &[u8]) -> RpcResult {
    let req = body_json(body)?;
    let level = req
        .get("level")
        .and_then(Value::as_i64)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "level is missing"))?;
    let level = u8::try_from(level)
        .map_err(|_| RpcError::new(error::WRONG_PARAM, format!("log level {level} is not 0-4")))?;
    wow_log::set_level(level).map_err(|e| RpcError::new(error::WRONG_PARAM, e))?;
    Ok(Value::Object(base("OK", untrusted())))
}

/// `/set_log_categories` **R**. An empty list reports the current one.
pub fn set_log_categories(body: &[u8]) -> RpcResult {
    let req = body_json(body)?;
    if let Some(spec) = req.get("categories").and_then(Value::as_str) {
        if !spec.is_empty() {
            wow_log::set_categories(spec).map_err(|e| RpcError::new(error::WRONG_PARAM, e))?;
        }
    }
    let mut m = base("OK", untrusted());
    m.insert("categories".into(), json!(wow_log::categories()));
    Ok(Value::Object(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv4 address packs the way the C++'s `uint32_t` does: wire order,
    /// read little-endian.
    #[test]
    fn an_ipv4_address_packs_like_the_reference() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(packed_ipv4(ip), u32::from_le_bytes([1, 2, 3, 4]));
        let back = BanTarget::Host(IpAddr::V4(Ipv4Addr::from(packed_ipv4(ip).to_le_bytes())));
        assert_eq!(back, BanTarget::Host(ip));
        assert_eq!(packed_ipv4("::1".parse().unwrap()), 0);
    }

    #[test]
    fn a_ban_names_a_host_or_an_ip() {
        assert_eq!(
            target_of(&json!({"host": "10.0.0.0/8"}))
                .unwrap()
                .to_string(),
            "10.0.0.0/8"
        );
        assert_eq!(
            target_of(&json!({"ip": u32::from_le_bytes([9, 9, 9, 9])}))
                .unwrap()
                .to_string(),
            "9.9.9.9"
        );
        assert!(target_of(&json!({"host": "nonsense"})).is_err());
        assert!(target_of(&json!({})).is_err());
    }

    #[test]
    fn an_empty_body_is_an_empty_object() {
        assert_eq!(body_json(b"").unwrap(), json!({}));
        assert_eq!(body_json(b"  \n").unwrap(), json!({}));
        assert!(body_json(b"{").is_err());
    }
}
