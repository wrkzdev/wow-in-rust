//! The daemon RPC server.
//!
//! `specs/11-daemon-rpc.md`. Three transports (§1), of which two are here:
//! `POST /json_rpc` for the JSON-RPC 2.0 dispatch table (§4) and `POST /<name>`
//! for the direct endpoints (§3). The binary `.bin` endpoints (§5) speak epee
//! portable storage and are for wallet and peer sync, neither of which this
//! build supports.
//!
//! # Threading
//!
//! One thread per connection, with a hard cap. `specs/11` §1.2 gives
//! `DEFAULT_RPC_MAX_CONNECTIONS (100)`; exceeding it drops the connection
//! rather than spawning unboundedly. There is no async runtime here: the work
//! is a read transaction and a serialisation, both short, and LMDB readers are
//! cheap.
//!
//! # Restricted mode
//!
//! `specs/11` §1.3: in restricted mode the endpoints marked **R** are "not
//! routed at all". Every method this build implements is read-only and
//! unrestricted, so the flag currently only affects `get_info`'s `restricted`
//! field — but the routing is written so adding an **R** method means adding it
//! to one list.

pub mod binary;
mod http;
pub mod methods;

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use wow_storage::db::BlockchainDb;
use wow_storage::lmdb::LmdbDb;

use crate::cli::Config;
use methods::{RpcError, RpcResult};

/// `DEFAULT_RPC_MAX_CONNECTIONS` (`specs/11` §1.2).
const MAX_CONNECTIONS: usize = 100;

/// Methods that would be removed in restricted mode (`specs/11` §1.3).
///
/// Empty today: everything implemented is read-only and unrestricted. Kept so a
/// method that *is* restricted has one place to be listed.
const RESTRICTED_METHODS: &[&str] = &[];

pub(crate) struct Server {
    db: Arc<LmdbDb>,
    cfg: Config,
    start_time: u64,
    connections: AtomicUsize,
    /// The transaction pool.
    ///
    /// A `Mutex` rather than anything cleverer: admission verifies ring
    /// signatures and a range proof, which is milliseconds, and the pool is
    /// touched once per RPC call. Contention here is not where a node spends
    /// its time.
    pool: std::sync::Mutex<crate::mempool::TxPool>,
}

impl Server {
    pub fn db(&self) -> &LmdbDb {
        &self.db
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn pool(&self) -> std::sync::MutexGuard<'_, crate::mempool::TxPool> {
        // A poisoned pool means a panic during admission. Recovering the guard
        // keeps the node serving rather than failing every later request for a
        // fault that has already been reported.
        self.pool.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn pool_size(&self) -> usize {
        self.pool().len()
    }
}

/// Run the server until the process is stopped.
pub fn serve(db: LmdbDb, cfg: &Config) -> Result<(), String> {
    let addr = format!("{}:{}", cfg.rpc_bind_ip, cfg.rpc_bind_port);

    // `specs/11` §1.2: a non-loopback bind without TLS needs explicit consent.
    if !is_loopback(&cfg.rpc_bind_ip) && !cfg.confirm_external_bind {
        return Err(format!(
            "refusing to bind {addr}: this build has no TLS and no RPC \
             authentication, so binding a non-loopback address exposes the node \
             to the network in the clear.\n\
             Pass --confirm-external-bind if that is what you want, or put a \
             reverse proxy in front of 127.0.0.1."
        ));
    }

    let listener = TcpListener::bind(&addr).map_err(|e| format!("cannot bind {addr}: {e}"))?;

    let server = Arc::new(Server {
        db: Arc::new(db),
        cfg: cfg.clone(),
        start_time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        connections: AtomicUsize::new(0),
        pool: std::sync::Mutex::new(crate::mempool::TxPool::new()),
    });

    eprintln!("wownerod: RPC listening on http://{addr}");
    eprintln!("wownerod: height {}", server.db.height());
    eprintln!("wownerod: try  curl -s -X POST http://{addr}/get_info | head -c 400");
    if cfg.restricted_rpc {
        eprintln!("wownerod: restricted mode");
    }

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("wownerod: accept failed: {e}");
                continue;
            }
        };

        let open = server.connections.fetch_add(1, Ordering::SeqCst);
        if open >= MAX_CONNECTIONS {
            server.connections.fetch_sub(1, Ordering::SeqCst);
            // Drop it rather than queueing: the cap is the backpressure.
            continue;
        }

        let server = Arc::clone(&server);
        std::thread::spawn(move || {
            handle(&server, stream);
            server.connections.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

fn is_loopback(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>()
        .map(|a| a.is_loopback())
        .unwrap_or(false)
}

fn handle(server: &Server, mut stream: TcpStream) {
    let req = match http::read_request(&stream) {
        Ok(r) => r,
        Err(http::HttpError::Closed) => return,
        Err(e) => {
            let body = json!({"status": "Failed", "error": e.to_string()}).to_string();
            let code = match e {
                http::HttpError::BodyTooLarge { .. } => 413,
                _ => 400,
            };
            let _ = http::write_json(&mut stream, code, &body);
            return;
        }
    };

    // The C++ accepts POST for everything; GET is allowed here for the direct
    // endpoints so they can be poked at from a browser.
    if req.method != "POST" && req.method != "GET" {
        let body = json!({"status": "Failed", "error": "use POST"}).to_string();
        let _ = http::write_json(&mut stream, 405, &body);
        return;
    }

    let path = req.path.split('?').next().unwrap_or("/");

    // The binary endpoints answer in epee, not JSON, so they branch before the
    // JSON writer (`specs/11` §5).
    if path.ends_with(".bin") {
        let body = match binary::dispatch(server, path, &req.body) {
            Ok(section) => wow_serialize::epee::to_bytes(&section).unwrap_or_else(|e| {
                binary::error_response(&RpcError::new(
                    methods::error::INTERNAL_ERROR,
                    e.to_string(),
                ))
            }),
            Err(e) => binary::error_response(&e),
        };
        let _ = http::write_binary(&mut stream, 200, &body);
        return;
    }

    let body = if path == "/json_rpc" {
        json_rpc(server, &req.body)
    } else {
        direct(server, path, &req.body)
    };

    let _ = http::write_json(&mut stream, 200, &body);
}

/// `POST /json_rpc` — the JSON-RPC 2.0 envelope (`specs/11` §1).
fn json_rpc(server: &Server, body: &[u8]) -> String {
    let request: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return json!({
            "jsonrpc": "2.0",
            "id": "0",
            "error": {"code": methods::error::WRONG_PARAM, "message": format!("invalid JSON: {e}")}
        })
        .to_string(),
    };

    let id = request.get("id").cloned().unwrap_or(json!("0"));
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(json!({}));

    if server.cfg.restricted_rpc && RESTRICTED_METHODS.contains(&method) {
        return error_envelope(
            &id,
            &RpcError::new(
                methods::error::RESTRICTED,
                format!("{method} is not available in restricted mode"),
            ),
        );
    }

    match dispatch(server, method, &params) {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string(),
        Err(e) => error_envelope(&id, &e),
    }
}

fn error_envelope(id: &Value, e: &RpcError) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": e.code, "message": e.message}
    })
    .to_string()
}

fn dispatch(server: &Server, method: &str, params: &Value) -> RpcResult {
    let db = &server.db;
    let cfg = &server.cfg;
    match method {
        // `specs/11` §4, with the C++'s aliases.
        "get_info" => methods::get_info(db, cfg, server.start_time, server.pool_size()),
        "get_version" => methods::get_version(db, cfg),
        "hard_fork_info" => methods::hard_fork_info(db, cfg, params),
        "get_fee_estimate" => methods::get_fee_estimate(db, cfg, params),

        "get_block_hash" | "on_get_block_hash" | "on_getblockhash" => {
            methods::get_block_hash(db, params)
        }
        "get_last_block_header" | "getlastblockheader" => methods::get_last_block_header(db, cfg),
        "get_block_header_by_height" | "getblockheaderbyheight" => {
            methods::get_block_header_by_height(db, cfg, params)
        }
        "get_block_header_by_hash" | "getblockheaderbyhash" => {
            methods::get_block_header_by_hash(db, cfg, params)
        }
        "get_block_headers_range" | "getblockheadersrange" => {
            methods::get_block_headers_range(db, cfg, params)
        }
        "get_block" | "getblock" => methods::get_block(db, cfg, params),

        // Not a C++ method: the check `specs/07` §6 recommends, over RPC.
        "get_checkpoints" => methods::get_checkpoints(db, cfg),

        "" => Err(RpcError::new(
            methods::error::WRONG_PARAM,
            "no `method` in the request",
        )),
        other => Err(RpcError::unsupported(other)),
    }
}

/// `POST /<name>` — the direct endpoints (`specs/11` §3).
///
/// These return the result object at the top level, not wrapped in a JSON-RPC
/// envelope.
fn direct(server: &Server, path: &str, body: &[u8]) -> String {
    let db = &server.db;
    let cfg = &server.cfg;

    let result = match path {
        "/get_height" | "/getheight" => methods::get_height(db),
        "/get_info" | "/getinfo" => {
            methods::get_info(db, cfg, server.start_time, server.pool_size())
        }
        "/get_checkpoints" => methods::get_checkpoints(db, cfg),
        "/send_raw_transaction" | "/sendrawtransaction" => {
            return methods::send_raw_transaction(server, body);
        }
        "/get_transactions" | "/gettransactions" => methods::get_transactions(server, body),
        other => Err(RpcError::unsupported(other)),
    };

    match result {
        Ok(v) => v.to_string(),
        // A direct endpoint has no envelope, so the error goes in `status`
        // (`specs/11` §2).
        Err(e) => json!({
            "status": "Failed",
            "untrusted": true,
            "credits": 0,
            "top_hash": "",
            "error": e.message,
            "code": e.code,
        })
        .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_recognised() {
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("::1"));
        assert!(!is_loopback("0.0.0.0"));
        assert!(!is_loopback("192.168.1.5"));
        // A name is not an address, so it is treated as external.
        assert!(!is_loopback("localhost"));
    }

    /// The connection cap is `specs/11` §1.2's number.
    #[test]
    fn the_connection_cap_is_the_documented_one() {
        assert_eq!(MAX_CONNECTIONS, 100);
    }
}
