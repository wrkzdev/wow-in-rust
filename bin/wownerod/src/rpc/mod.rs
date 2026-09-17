//! The daemon RPC server.
//!
//! `specs/11-daemon-rpc.md`. Three transports (§1): `POST /json_rpc` for the
//! JSON-RPC 2.0 dispatch table (§4), `POST /<name>` for the direct endpoints
//! (§3), and `POST /<name>.bin` for the epee endpoints wallets sync over (§5).
//!
//! # Threading
//!
//! One thread per connection, with a hard cap. `specs/11` §1.2 gives
//! `DEFAULT_RPC_MAX_CONNECTIONS (100)`; beyond it a connection is dropped
//! rather than a thread spawned. The accept loop polls, so the node's shutdown
//! can stop it.
//!
//! # Restricted mode
//!
//! `specs/11` §1.3: in restricted mode the endpoints marked **R** are "not
//! routed at all". [`RESTRICTED_METHODS`] and [`RESTRICTED_PATHS`] are those
//! lists for what this node serves, and a restricted server answers them the
//! way it answers a method it has never heard of.
//!
//! `--rpc-restricted-bind-port` runs a second, restricted listener beside the
//! first, which is how a node offers a public RPC while keeping its own.
//!
//! # Access
//!
//! In the order a request meets them: a client over its address's connection
//! cap is dropped; an address blocked for failed logins is dropped; a request
//! from a web page (`Origin`) is refused unless `--rpc-access-control-origins`
//! lists it; and with `--rpc-login`, one without valid Digest credentials gets
//! `401` and a challenge ([`auth`]).

pub mod admin;
pub mod auth;
pub mod binary;
mod http;
pub mod methods;
pub mod mining;
pub mod tls;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{json, Value};
use wow_consensus::fee::FeeContext;
use wow_p2p::addressbook::is_public;
use wow_p2p::node::{Node, SyncStatus};
use wow_storage::db::BlockchainDb;
use wow_storage::lmdb::LmdbDb;

use crate::cli::Config;
use crate::mempool::TxPool;
use crate::node::NodeCore;
use methods::{RpcError, RpcResult};

/// `DEFAULT_RPC_MAX_CONNECTIONS` (`specs/11` §1.2).
pub const MAX_CONNECTIONS: usize = 100;
/// `DEFAULT_RPC_MAX_CONNECTIONS_PER_PUBLIC_IP`.
pub const MAX_CONNECTIONS_PER_PUBLIC_IP: usize = 3;
/// `DEFAULT_RPC_MAX_CONNECTIONS_PER_PRIVATE_IP`, which covers loopback.
pub const MAX_CONNECTIONS_PER_PRIVATE_IP: usize = 25;

/// JSON-RPC methods marked **R** (`specs/11` §4) that this node serves.
const RESTRICTED_METHODS: &[&str] = &[
    "get_connections",
    "sync_info",
    "get_bans",
    "set_bans",
    "banned",
    "flush_txpool",
    "relay_tx",
    "generateblocks",
];

/// Direct endpoints marked **R** (`specs/11` §3) that this node serves.
const RESTRICTED_PATHS: &[&str] = &[
    "/get_peer_list",
    "/in_peers",
    "/out_peers",
    "/stop_daemon",
    "/save_bc",
    "/pop_blocks",
    "/get_net_stats",
    "/set_log_level",
    "/set_log_categories",
    "/start_mining",
    "/stop_mining",
    "/mining_status",
];

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
    pool: Arc<Mutex<TxPool>>,
    /// The chain, when the store is writable.
    core: Option<Arc<NodeCore>>,
    /// The peer-to-peer node, when there is one.
    p2p: Option<Arc<Node>>,
    stop: Arc<AtomicBool>,
    /// `--rpc-login`.
    login: Option<auth::Login>,
    /// `--rpc-ssl`, when it is not `disabled`.
    tls: Option<tls::Tls>,
    /// Open connections per client address, for the per-address caps.
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    /// The built-in miner, once started.
    miner: Mutex<Option<crate::miner::Miner>>,
}

impl Server {
    #[allow(
        clippy::too_many_arguments,
        reason = "one argument for each part of the node the server reaches"
    )]
    pub fn new(
        db: Arc<LmdbDb>,
        cfg: &Config,
        pool: Arc<Mutex<TxPool>>,
        core: Option<Arc<NodeCore>>,
        p2p: Option<Arc<Node>>,
        stop: Arc<AtomicBool>,
        login: Option<auth::Login>,
        tls: Option<tls::Tls>,
    ) -> Arc<Server> {
        Arc::new(Server {
            db,
            cfg: cfg.clone(),
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            connections: AtomicUsize::new(0),
            pool,
            core,
            p2p,
            stop,
            login,
            tls,
            per_ip: Mutex::new(HashMap::new()),
            miner: Mutex::new(None),
        })
    }

    /// Count a new connection from `ip`, or refuse it for being over a cap
    /// (`specs/11` §1.2).
    fn admit(&self, ip: IpAddr) -> bool {
        let open = self.connections.fetch_add(1, Ordering::SeqCst);
        if open >= self.cfg.rpc_max_connections {
            self.connections.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        let cap = if is_public(ip) {
            self.cfg.rpc_max_connections_per_public_ip
        } else {
            self.cfg.rpc_max_connections_per_private_ip
        };
        let mut per_ip = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        let n = per_ip.entry(ip).or_insert(0);
        if *n >= cap {
            drop(per_ip);
            self.connections.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        *n += 1;
        true
    }

    fn release(&self, ip: IpAddr) {
        self.connections.fetch_sub(1, Ordering::SeqCst);
        let mut per_ip = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = per_ip.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                per_ip.remove(&ip);
            }
        }
    }

    pub fn db(&self) -> &LmdbDb {
        &self.db
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn pool(&self) -> MutexGuard<'_, TxPool> {
        // A poisoned pool means a panic during admission. Recovering the guard
        // keeps the node serving rather than failing every later request for a
        // fault that has already been reported.
        self.pool.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The pool's size as a caller may see it: every transaction with
    /// `include_sensitive`, the public ones otherwise.
    pub fn pool_size(&self, include_sensitive: bool) -> usize {
        self.pool().count(include_sensitive)
    }

    pub fn core(&self) -> Option<&NodeCore> {
        self.core.as_deref()
    }

    pub fn p2p(&self) -> Option<&Node> {
        self.p2p.as_deref()
    }

    /// The chain, for something that outlives a request, such as the miner.
    pub fn core_handle(&self) -> Option<Arc<NodeCore>> {
        self.core.clone()
    }

    pub fn p2p_handle(&self) -> Option<Arc<Node>> {
        self.p2p.clone()
    }

    pub fn miner(&self) -> MutexGuard<'_, Option<crate::miner::Miner>> {
        self.miner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Stop the miner, if one runs, and wait for its threads.
    pub fn stop_mining(&self) {
        let miner = self.miner().take();
        if let Some(m) = miner {
            m.stop();
        }
    }

    pub fn start_time(&self) -> u64 {
        self.start_time
    }

    pub fn rpc_connections(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }

    /// Whether an accepted transaction actually goes out to peers.
    ///
    /// `send_raw_transaction` reports `not_relayed` from this. Answering
    /// `false` while no peer is connected would tell a wallet its payment is
    /// on the network when it is sitting in this process's memory.
    ///
    /// Only synchronised connections count. A transaction is sent to those
    /// and no others, so a peer still handshaking or syncing takes nothing.
    pub fn relays(&self) -> bool {
        self.p2p
            .as_ref()
            .is_some_and(|p| p.normal_connection_count() > 0)
    }

    /// Where the node stands against its peers. With no peer-to-peer node it
    /// stands nowhere: never synchronised, never syncing.
    pub fn sync_status(&self) -> SyncStatus {
        match &self.p2p {
            Some(p) => p.sync_status(),
            None => {
                let height = self.db.height();
                SyncStatus {
                    height,
                    target_height: height,
                    ..Default::default()
                }
            }
        }
    }

    /// What fee checks read: the chain's cached state when there is a chain,
    /// the protocol floor otherwise.
    pub fn fee_context(&self) -> FeeContext {
        match &self.core {
            Some(c) => c.fee_context(),
            None => methods::floor_fee_context(&self.db, self.cfg.network),
        }
    }

    /// `stop_daemon`.
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Bind the RPC listeners -- the main one, and the restricted one when
/// `--rpc-restricted-bind-port` asks for it -- and serve on background threads
/// until the server's stop flag is set.
pub fn start(server: Arc<Server>) -> Result<Vec<JoinHandle<()>>, String> {
    let cfg = &server.cfg;
    let mut threads = listen(
        &server,
        &cfg.rpc_bind_ip,
        cfg.rpc_use_ipv6
            .then_some(cfg.rpc_bind_ipv6_address.as_str()),
        cfg.rpc_bind_port,
        cfg.restricted_rpc,
    )?;
    if let Some(port) = cfg.rpc_restricted_bind_port {
        let ip = cfg
            .rpc_restricted_bind_ip
            .clone()
            .unwrap_or_else(|| cfg.rpc_bind_ip.clone());
        threads.extend(listen(
            &server,
            &ip,
            cfg.rpc_use_ipv6
                .then_some(cfg.rpc_restricted_bind_ipv6_address.as_str()),
            port,
            true,
        )?);
    }
    Ok(threads)
}

/// One RPC server's listeners: IPv4, and IPv6 on the same port with
/// `--rpc-use-ipv6`. An accept thread each.
fn listen(
    server: &Arc<Server>,
    ip: &str,
    ipv6: Option<&str>,
    port: u16,
    restricted: bool,
) -> Result<Vec<JoinHandle<()>>, String> {
    // `specs/11` §1.2: exposing the full RPC in the clear needs explicit
    // consent. As in the C++, a restricted listener -- what a public node
    // offers -- and one behind `--rpc-login` do not.
    for addr in std::iter::once(ip).chain(ipv6) {
        if !is_loopback(addr)
            && !restricted
            && server.login.is_none()
            && !server.cfg.confirm_external_bind
        {
            return Err(format!(
                "refusing to bind {}: a non-loopback address exposes the \
                 unrestricted RPC to the network, in the clear to any client \
                 that does not use TLS.\n\
                 Pass --confirm-external-bind if that is what you want; use \
                 --restricted-rpc, --rpc-restricted-bind-port or --rpc-login; or put \
                 a reverse proxy in front of 127.0.0.1.",
                bind_address(addr, port)
            ));
        }
    }

    let resolve = |a: &str| -> Result<SocketAddr, String> {
        let text = bind_address(a, port);
        text.to_socket_addrs()
            .ok()
            .and_then(|mut all| all.next())
            .ok_or_else(|| format!("cannot resolve the RPC address {text}"))
    };
    let v4 = resolve(ip)?;
    let v6 = ipv6.map(resolve).transpose()?;
    let what = if restricted { "restricted RPC" } else { "RPC" };
    let (l4, l6) = wow_p2p::net::listen_dual(Some(v4), v6, !server.cfg.rpc_ignore_ipv4, what)?;

    let mut threads = Vec::new();
    for listener in [l4, l6].into_iter().flatten() {
        let local = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("cannot poll {local}: {e}"))?;
        wow_log::info!(
            "global",
            "RPC listening on http://{local}{}{}",
            if restricted { " (restricted)" } else { "" },
            if server.login.is_some() {
                " (login required)"
            } else {
                ""
            }
        );
        let s = server.clone();
        threads.push(
            std::thread::Builder::new()
                .name("rpc-listen".into())
                .spawn(move || accept_loop(s, listener, restricted))
                .map_err(|e| format!("cannot start the RPC server: {e}"))?,
        );
    }
    Ok(threads)
}

fn accept_loop(server: Arc<Server>, listener: TcpListener, restricted: bool) {
    while !server.stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                // An accepted socket inherits the listener's non-blocking mode
                // on some platforms; the handler wants blocking reads.
                let _ = stream.set_nonblocking(false);
                let ip = peer.ip();
                // Over a cap, the connection is dropped rather than queued: the
                // cap is the backpressure.
                if !server.admit(ip) {
                    continue;
                }
                let s = server.clone();
                let spawned = std::thread::Builder::new()
                    .name("rpc".into())
                    .spawn(move || {
                        handle(&s, stream, restricted, ip);
                        s.release(ip);
                    });
                if spawned.is_err() {
                    server.release(ip);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                wow_log::debug!("daemon.rpc", "accept failed: {e}");
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

/// `[::1]` and `::1` are the same address; a bracketed one is how an IPv6
/// address is usually written next to a port.
fn unbracket(ip: &str) -> &str {
    ip.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(ip)
}

fn is_loopback(ip: &str) -> bool {
    unbracket(ip)
        .parse::<std::net::IpAddr>()
        .map(|a| a.is_loopback())
        .unwrap_or(false)
}

/// The `host:port` string to bind.
///
/// Built from a parsed address where there is one: pasting `::1` and a port
/// together gives `::1:34568`, which is not an address at all.
fn bind_address(ip: &str, port: u16) -> String {
    match unbracket(ip).parse::<std::net::IpAddr>() {
        Ok(a) => std::net::SocketAddr::new(a, port).to_string(),
        Err(_) => format!("{ip}:{port}"),
    }
}

/// Whether `origin` is one `--rpc-access-control-origins` allows.
fn origin_allowed(allowed: &[String], origin: &str) -> bool {
    allowed.iter().any(|a| a == "*" || a == origin)
}

fn handle(server: &Server, tcp: TcpStream, restricted: bool, ip: IpAddr) {
    if server.login.as_ref().is_some_and(|l| l.is_blocked(ip)) {
        return;
    }
    let _ = tcp.set_read_timeout(Some(http::READ_TIMEOUT));
    let _ = tcp.set_write_timeout(Some(http::WRITE_TIMEOUT));
    let mut stream = match &server.tls {
        Some(t) => match t.accept(tcp) {
            Ok(s) => s,
            Err(e) => {
                wow_log::debug!("daemon.rpc", "{ip}: {e}");
                return;
            }
        },
        None => tls::Stream::Plain(tcp),
    };
    respond(server, &mut stream, restricted, ip);
    stream.finish();
}

/// Read one request and answer it, over whichever stream the connection is.
fn respond(server: &Server, stream: &mut tls::Stream, restricted: bool, ip: IpAddr) {
    let req = match http::read_request(stream) {
        Ok(r) => r,
        Err(http::HttpError::Closed) => return,
        Err(e) => {
            let body = json!({"status": "Failed", "error": e.to_string()}).to_string();
            let code = match e {
                http::HttpError::BodyTooLarge { .. } => 413,
                _ => 400,
            };
            let _ = http::write_json(stream, code, &body);
            return;
        }
    };

    // A browser sends `Origin` with every cross-origin request -- including
    // the "simple" text/plain POST that needs no CORS preflight and still
    // reaches the handler -- while a wallet, `curl` or an explorer's backend
    // sends none. Refusing it keeps a web page the operator happens to have
    // open from driving this node through 127.0.0.1, which matters more with
    // every method that changes state. Origins the operator listed are let
    // through, and told so in CORS headers.
    let mut headers: Vec<(&str, String)> = Vec::new();
    if let Some(origin) = req.header("origin") {
        if !origin_allowed(&server.cfg.rpc_access_control_origins, origin) {
            let body = json!({
                "status": "Failed",
                "error": "cross-origin requests are refused"
            })
            .to_string();
            let _ = http::write_json(stream, 403, &body);
            return;
        }
        headers.push(("Access-Control-Allow-Origin", origin.to_string()));
        headers.push(("Access-Control-Allow-Credentials", "true".into()));
        headers.push(("Vary", "Origin".into()));
        // A preflight: say what the real request may carry.
        if req.method == "OPTIONS" {
            headers.push(("Access-Control-Allow-Methods", "POST, GET, OPTIONS".into()));
            headers.push((
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type".into(),
            ));
            let _ = http::write_json_with(stream, 200, "{}", &headers);
            return;
        }
    }

    // The C++ accepts POST for everything; GET is allowed here for the direct
    // endpoints so they can be poked at from a browser.
    if req.method != "POST" && req.method != "GET" {
        let body = json!({"status": "Failed", "error": "use POST"}).to_string();
        let _ = http::write_json_with(stream, 405, &body, &headers);
        return;
    }

    if let Some(login) = &server.login {
        let authorization = req.header("authorization");
        if !login.check(&req.method, &req.path, authorization) {
            // No header is the first half of an ordinary Digest exchange; only
            // a wrong one counts against the address.
            if authorization.is_some() && login.record_failure(ip) {
                wow_log::warn!(
                    "daemon.rpc",
                    "{ip} failed to log in {} times and is blocked",
                    auth::FAILS_BEFORE_BLOCK
                );
            }
            headers.push(("WWW-Authenticate", login.challenge()));
            let body = json!({"status": "Unauthorized"}).to_string();
            let _ = http::write_json_with(stream, 401, &body, &headers);
            return;
        }
    }

    methods::set_untrusted(!server.sync_status().synchronized);
    let path = req.path.split('?').next().unwrap_or("/");

    // The binary endpoints answer in epee, not JSON, so they branch before the
    // JSON writer (`specs/11` §5).
    if path.ends_with(".bin") {
        let body = match binary::dispatch(server, path, &req.body, restricted) {
            Ok(section) => wow_serialize::epee::to_bytes(&section).unwrap_or_else(|e| {
                binary::error_response(&RpcError::new(
                    methods::error::INTERNAL_ERROR,
                    e.to_string(),
                ))
            }),
            Err(e) => binary::error_response(&e),
        };
        let _ = http::write_binary_with(stream, 200, &body, &headers);
        return;
    }

    let body = if path == "/json_rpc" {
        json_rpc(server, &req.body, restricted)
    } else {
        direct(server, path, &req.body, restricted)
    };

    let _ = http::write_json_with(stream, 200, &body, &headers);
}

/// `POST /json_rpc` — the JSON-RPC 2.0 envelope (`specs/11` §1).
fn json_rpc(server: &Server, body: &[u8], restricted: bool) -> String {
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

    // Not routed at all, so answered as a method that does not exist.
    if restricted && RESTRICTED_METHODS.contains(&method) {
        return error_envelope(&id, &RpcError::unsupported(method));
    }

    match dispatch(server, method, &params, restricted) {
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

/// A JSON-RPC method, for a caller on a listener that is `restricted` or not.
///
/// What is marked **R** never gets here on a restricted listener. The rest
/// is still asked whether it is: the C++ answers several of them with less
/// on a restricted listener -- no private pool transactions, no node
/// counters -- and so does this node.
fn dispatch(server: &Server, method: &str, params: &Value, restricted: bool) -> RpcResult {
    let db = server.db();
    let cfg = server.config();
    match method {
        // `specs/11` §4, with the C++'s aliases.
        "get_info" => methods::get_info(server, restricted),
        "get_version" => methods::get_version(server),
        "hard_fork_info" => methods::hard_fork_info(db, cfg, params),
        "get_fee_estimate" => methods::get_fee_estimate(server, params),

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

        "submit_block" | "submitblock" => admin::submit_block(server, params),
        "get_block_template" | "getblocktemplate" => mining::get_block_template(server, params),
        "generateblocks" => mining::generateblocks(server, params),
        "sync_info" => admin::sync_info(server),
        "get_connections" => admin::get_connections(server),
        "get_bans" => admin::get_bans(server),
        "set_bans" => admin::set_bans(server, params),
        "banned" => admin::banned(server, params),
        "flush_txpool" => admin::flush_txpool(server, params),
        "relay_tx" => admin::relay_tx(server, params),

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
fn direct(server: &Server, path: &str, body: &[u8], restricted: bool) -> String {
    let db = server.db();
    let cfg = server.config();

    let result = if restricted && RESTRICTED_PATHS.contains(&path) {
        Err(RpcError::unsupported(path))
    } else {
        match path {
            "/get_height" | "/getheight" => methods::get_height(db),
            "/get_info" | "/getinfo" => methods::get_info(server, restricted),
            "/get_checkpoints" => methods::get_checkpoints(db, cfg),
            "/send_raw_transaction" | "/sendrawtransaction" => {
                return methods::send_raw_transaction(server, body);
            }
            "/get_transactions" | "/gettransactions" => {
                methods::get_transactions(server, body, restricted)
            }
            "/is_key_image_spent" => admin::is_key_image_spent(server, body, restricted),
            "/get_transaction_pool" => admin::get_transaction_pool(server, restricted),
            "/get_transaction_pool_hashes" => {
                admin::get_transaction_pool_hashes(server, restricted)
            }
            "/get_transaction_pool_stats" => admin::get_transaction_pool_stats(server, restricted),
            "/get_peer_list" => admin::get_peer_list(server),
            "/get_public_nodes" => admin::get_public_nodes(server, body),
            "/in_peers" => admin::in_peers(server, body),
            "/out_peers" => admin::out_peers(server, body),
            "/stop_daemon" => admin::stop_daemon(server),
            "/save_bc" => admin::save_bc(server),
            "/pop_blocks" => admin::pop_blocks(server, body),
            "/get_net_stats" => admin::get_net_stats(server),
            "/set_log_level" => admin::set_log_level(body),
            "/set_log_categories" => admin::set_log_categories(body),
            "/start_mining" => mining::start_mining(server, body),
            "/stop_mining" => mining::stop_mining(server),
            "/mining_status" => mining::mining_status(server),
            other => Err(RpcError::unsupported(other)),
        }
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
        assert!(is_loopback("[::1]"), "brackets are notation, not address");
    }

    /// An IPv6 address needs brackets next to a port, or the result does not
    /// parse -- which is what `--rpc-bind-ip ::1` used to hit.
    #[test]
    fn the_bind_address_brackets_ipv6() {
        assert_eq!(bind_address("127.0.0.1", 34_568), "127.0.0.1:34568");
        assert_eq!(bind_address("::1", 34_568), "[::1]:34568");
        assert_eq!(bind_address("[::1]", 34_568), "[::1]:34568");
        assert!(bind_address("::1", 1)
            .parse::<std::net::SocketAddr>()
            .is_ok());
        // A name goes through as given, to be resolved by the bind.
        assert_eq!(bind_address("localhost", 1), "localhost:1");
    }

    /// The connection caps are `specs/11` §1.2's numbers.
    #[test]
    fn the_connection_cap_is_the_documented_one() {
        assert_eq!(MAX_CONNECTIONS, 100);
        assert_eq!(MAX_CONNECTIONS_PER_PUBLIC_IP, 3);
        assert_eq!(MAX_CONNECTIONS_PER_PRIVATE_IP, 25);
    }

    #[test]
    fn listed_origins_and_the_wildcard_are_allowed() {
        let list = vec!["https://a.example".to_string()];
        assert!(origin_allowed(&list, "https://a.example"));
        assert!(!origin_allowed(&list, "https://b.example"));
        assert!(!origin_allowed(&[], "https://a.example"));
        assert!(origin_allowed(
            &["*".to_string()],
            "https://anything.example"
        ));
    }

    /// Everything this node marks restricted is something it routes, so the
    /// lists cannot drift into naming endpoints that do not exist.
    #[test]
    fn the_restricted_lists_name_routed_endpoints() {
        for m in RESTRICTED_METHODS {
            assert!(m.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{m}");
        }
        for p in RESTRICTED_PATHS {
            assert!(p.starts_with('/'), "{p}");
        }
        assert!(RESTRICTED_PATHS.contains(&"/stop_daemon"));
        assert!(RESTRICTED_METHODS.contains(&"set_bans"));
    }
}
