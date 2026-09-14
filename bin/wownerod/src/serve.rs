//! `--serve`: the long-running node (`specs/09` §1).
//!
//! The order is `specs/09` §1's. The store is open and its height known before
//! peers hear about it. The peer-to-peer node and the RPC server run on their
//! own threads while this one waits for a signal or `stop_daemon`. On the way
//! down (§9) the peers go first, then the pool is written out, and the store is
//! synced **last**, so nothing writes after it.
//!
//! What runs depends on how the store was opened:
//!
//! * read-write: the whole node -- sync, serve peers, relay, RPC;
//! * read-only (`--db-readonly`): RPC over the store, nothing else, since there
//!   is nothing a node that cannot write may do with a new block;
//! * `--offline`: read-write, but no peer-to-peer.

use std::io::IsTerminal;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wow_p2p::addressbook::{parse_ban_list, STATE_FILENAME};
use wow_p2p::node::{Core, Node, SyncStatus};
use wow_storage::db::BlockchainDb;
use wow_storage::lmdb::LmdbDb;

use crate::cli::Config;
use crate::mempool::TxPool;
use crate::node::NodeCore;
use crate::{netsync, rpc, signal};

const LOG: &str = "global";

/// How often the node looks at how its sync is going.
const STATUS_EVERY: Duration = Duration::from_secs(5);
/// How often a node that is behind says how far.
const PROGRESS_EVERY: Duration = Duration::from_secs(30);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `--pidfile`: the process id, written at start and removed on the way out.
struct PidFile(PathBuf);

impl PidFile {
    fn create(path: &Path) -> Result<PidFile, String> {
        std::fs::write(path, format!("{}\n", std::process::id()))
            .map_err(|e| format!("cannot write --pidfile {}: {e}", path.display()))?;
        Ok(PidFile(path.to_path_buf()))
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn run(db: LmdbDb, cfg: &Config) -> Result<(), String> {
    if let Err(e) = signal::install() {
        wow_log::warn!(LOG, "{e}; stop the node with the stop_daemon RPC instead");
    }
    let _pidfile = cfg.pidfile.as_deref().map(PidFile::create).transpose()?;

    // TLS first: a certificate that cannot be read or made stops the node
    // before anything else has started. The generated one is kept beside the
    // database, where the C++ keeps its own.
    let data_dir = wow_storage::env::db_dir(&cfg.data_dir, cfg.network, cfg.regtest)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cfg.data_dir.clone());
    let tls = rpc::tls::Tls::from_config(cfg, &data_dir)?;
    if let Some(t) = &tls {
        wow_log::info!(
            LOG,
            "RPC TLS {}; certificate SHA-256 {}",
            if t.is_required() {
                "required"
            } else {
                "offered (autodetect)"
            },
            rpc::tls::fingerprint_hex(&t.fingerprint())
        );
    }

    // The ZMQ sockets are bound now for the same reason: a port in use stops
    // the node here.
    let zmq_bound = if cfg.no_zmq {
        if !cfg.zmq_pub.is_empty() {
            wow_log::warn!(LOG, "--zmq-pub has no effect because --no-zmq was given");
        }
        None
    } else {
        Some(crate::zmq::bind(cfg)?)
    };

    let db = Arc::new(db);
    let mut pool = if cfg.read_only {
        TxPool::new()
    } else {
        let pool = TxPool::load(&db, unix_now());
        if pool.len() > 0 {
            wow_log::info!(
                "txpool",
                "{} transaction(s) restored from the last run",
                pool.len()
            );
        }
        pool
    };
    pool.set_max_weight(cfg.max_txpool_weight);
    let pool = Arc::new(Mutex::new(pool));

    let core = if cfg.read_only {
        None
    } else {
        // The C++ drops alternative blocks on start unless asked to keep them;
        // their transactions were only ever in memory here anyway.
        if !cfg.keep_alt_blocks {
            let _ = db.drop_alt_blocks();
        }
        let core = NodeCore::new(db.clone(), cfg.network, pool.clone())?;
        if let Some(d) = cfg.fixed_difficulty {
            core.set_fixed_difficulty(Some(d));
            wow_log::warn!(
                LOG,
                "--fixed-difficulty {d}: every block after genesis needs only that"
            );
        }
        let trusted = core.trusted_below();
        if trusted > db.height() {
            wow_log::info!(
                LOG,
                "blocks below {trusted} are covered by hard-coded checkpoints: their proof of \
                 work and transaction rules are not re-checked, as the C++ node does not \
                 re-check them either (docs/spec-deltas.md §23)"
            );
        }
        Some(core)
    };

    let p2p = match (&core, cfg.offline) {
        (Some(core), false) => Some(Arc::new(start_p2p(cfg, core.clone())?)),
        _ => None,
    };

    let login = match &cfg.rpc_login {
        None => None,
        Some((user, pass)) => {
            let pass = match pass {
                Some(p) => p.clone(),
                None => {
                    // The C++ generates one too when none is given. It is
                    // printed, once, because nobody could log in otherwise.
                    let mut bytes = [0u8; 16];
                    netsync::seeded_rng()?.fill(&mut bytes);
                    let generated = wow_crypto::hex::encode(&bytes);
                    println!("RPC login: {user}:{generated}");
                    generated
                }
            };
            Some(rpc::auth::Login::new(
                user,
                &pass,
                !cfg.disable_rpc_ban,
                netsync::seeded_rng()?,
            ))
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    let server = rpc::Server::new(
        db.clone(),
        cfg,
        pool.clone(),
        core.clone(),
        p2p.clone(),
        stop.clone(),
        login,
        tls,
    );
    let rpc_threads = rpc::start(server.clone())?;
    let zmq = zmq_bound
        .map(|b| crate::zmq::start(b, server.clone(), core.as_deref(), cfg.restricted_zmq_rpc))
        .transpose()?;
    // Dropped as `run` returns, which puts the terminal back.
    let _terminal = (!cfg.non_interactive && std::io::stdin().is_terminal())
        .then(|| crate::console::spawn(server.clone()));

    // A miner that cannot start stops the node, the way a bad option would --
    // but through the shutdown below, so peers and the pool are still saved.
    let mut failure = None;
    if let Some(address) = &cfg.start_mining {
        if let Err(e) = rpc::mining::start(&server, address, cfg.mining_threads) {
            failure = Some(format!("--start-mining: {}", e.message));
            stop.store(true, Ordering::SeqCst);
        }
    }

    wow_log::info!(
        LOG,
        "{} at height {}{}",
        crate::cli::VERSION,
        db.height(),
        match (&p2p, cfg.read_only) {
            (_, true) => " (read-only: serving RPC only)",
            (None, false) => " (offline)",
            (Some(_), false) => "",
        }
    );

    let mut last_expire = Instant::now();
    let mut last_status = Instant::now();
    let mut progress = Progress::new(db.height(), last_status);
    while !signal::stop_requested() && !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));

        if last_expire.elapsed() >= Duration::from_secs(60) {
            last_expire = Instant::now();
            let gone = pool
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .expire(unix_now());
            if gone > 0 {
                wow_log::debug!("txpool", "{gone} transaction(s) expired");
            }
        }

        if last_status.elapsed() >= STATUS_EVERY {
            last_status = Instant::now();
            if let Some(p) = &p2p {
                if let Some(line) = progress.observe(&p.sync_status(), last_status) {
                    wow_log::info!(LOG, "{line}");
                }
            }
        }
    }

    wow_log::info!(LOG, "stopping");
    stop.store(true, Ordering::SeqCst);
    // The miner first: it submits to the chain and relays to peers.
    server.stop_mining();
    if let Some(z) = &zmq {
        z.stop();
    }
    if let Some(p) = &p2p {
        p.stop();
    }
    for t in rpc_threads {
        let _ = t.join();
    }
    if core.is_some() {
        match pool.lock().unwrap_or_else(|e| e.into_inner()).save(&db) {
            Ok(n) => wow_log::info!("txpool", "{n} transaction(s) saved"),
            Err(e) => wow_log::error!("txpool", "{e}"),
        }
        db.sync()
            .map_err(|e| format!("cannot flush the database: {e}"))?;
    }
    wow_log::info!(LOG, "stopped at height {}", db.height());
    signal::finished();
    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// What the node says about its sync as it goes.
struct Progress {
    /// The height at the last progress line, and when, for the rate.
    last: Option<(u64, Instant)>,
    /// Whether the node was synchronised when last looked at.
    synchronized: bool,
}

impl Progress {
    fn new(height: u64, now: Instant) -> Progress {
        Progress {
            last: Some((height, now)),
            synchronized: false,
        }
    }

    /// The line to log for `s`, when one is due: once on catching up with the
    /// network, and every [`PROGRESS_EVERY`] while behind it.
    fn observe(&mut self, s: &SyncStatus, now: Instant) -> Option<String> {
        if s.synchronized {
            self.last = None;
            let caught_up = !std::mem::replace(&mut self.synchronized, true);
            return caught_up
                .then(|| format!("synchronised with the network at height {}", s.height));
        }
        self.synchronized = false;
        let added = match self.last {
            Some((_, at)) if now.duration_since(at) < PROGRESS_EVERY => return None,
            Some((height, at)) => Some((s.height.saturating_sub(height), now.duration_since(at))),
            None => None,
        };
        self.last = Some((s.height, now));
        Some(progress_line(s, added))
    }
}

/// Where the chain stands against its peers, how fast it is closing the gap,
/// and with how many peers. `added` is the blocks added since the last line
/// and how long that took.
///
/// ```text
/// syncing: height 63300 of 873597 (7.2%), 810297 to go at 45.0 blocks/s, about 5 h 00 min left; 8 out, 0 in
/// ```
fn progress_line(s: &SyncStatus, added: Option<(u64, Duration)>) -> String {
    if s.outgoing + s.incoming == 0 {
        return format!("height {}, waiting for peers", s.height);
    }
    let peers = format!("{} out, {} in", s.outgoing, s.incoming);
    if s.target_height <= s.height {
        return format!("height {}; {peers}", s.height);
    }
    let left = s.target_height - s.height;
    let percent = s.height as f64 * 100.0 / s.target_height as f64;
    let pace = match added {
        None => String::new(),
        Some((0, took)) => format!(", no blocks added in {}", approx(took.as_secs())),
        Some((n, took)) => {
            let rate = n as f64 / took.as_secs_f64().max(0.001);
            format!(
                " at {rate:.1} blocks/s, about {} left",
                approx((left as f64 / rate) as u64)
            )
        }
    };
    format!(
        "syncing: height {} of {} ({percent:.1}%), {left} to go{pace}; {peers}",
        s.height, s.target_height
    )
}

/// A duration in its largest units: `45 s`, `12 min`, `3 h 05 min`, `2 d 7 h`.
fn approx(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs} s"),
        60..3_600 => format!("{} min", secs / 60),
        3_600..86_400 => format!("{} h {:02} min", secs / 3_600, secs % 3_600 / 60),
        _ => format!("{} d {} h", secs / 86_400, secs % 86_400 / 3_600),
    }
}

/// Resolve `host[:port]`, with the network's port when none is given.
fn resolve(s: &str, default_port: u16) -> Result<Vec<SocketAddr>, String> {
    let with_port = if s
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
        && !s.ends_with(']')
    {
        s.to_string()
    } else {
        format!("{s}:{default_port}")
    };
    with_port
        .to_socket_addrs()
        .map(|a| a.collect())
        .map_err(|e| format!("cannot resolve `{s}`: {e}"))
}

fn resolve_all(list: &[String], default_port: u16) -> Result<Vec<SocketAddr>, String> {
    let mut out = Vec::new();
    for s in list {
        out.extend(resolve(s, default_port)?.into_iter().take(1));
    }
    Ok(out)
}

fn start_p2p(cfg: &Config, core: Arc<NodeCore>) -> Result<Node, String> {
    let default_port = wow_p2p::messages::default_port(cfg.network);
    let mut p = wow_p2p::node::Config::new(cfg.network);

    let ip: std::net::IpAddr = cfg
        .p2p_bind_ip
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .map_err(|_| format!("--p2p-bind-ip: `{}` is not an address", cfg.p2p_bind_ip))?;
    p.listen = Some(SocketAddr::new(ip, cfg.p2p_bind_port));
    if cfg.p2p_use_ipv6 {
        let bare = cfg
            .p2p_bind_ipv6_address
            .trim_start_matches('[')
            .trim_end_matches(']');
        let ip6: std::net::Ipv6Addr = bare.parse().map_err(|_| {
            format!(
                "--p2p-bind-ipv6-address: `{}` is not an IPv6 address",
                cfg.p2p_bind_ipv6_address
            )
        })?;
        p.listen_v6 = Some(SocketAddr::new(ip6.into(), cfg.p2p_bind_port_ipv6));
    }
    p.require_ipv4 = !cfg.p2p_ignore_ipv4;
    p.external_port = cfg.p2p_external_port;
    p.hide_my_port = cfg.hide_my_port;
    p.out_peers = cfg.out_peers;
    p.in_peers = cfg.in_peers;
    p.max_connections_per_ip = cfg.max_connections_per_ip;
    if !cfg.seed_nodes.is_empty() {
        p.seed_nodes = resolve_all(&cfg.seed_nodes, default_port)?;
    }
    p.add_peers = resolve_all(&cfg.add_peers, default_port)?;
    p.priority_nodes = resolve_all(&cfg.priority_nodes, default_port)?;
    p.exclusive_nodes = resolve_all(&cfg.exclusive_nodes, default_port)?;
    p.allow_local_ip = cfg.allow_local_ip;
    p.no_sync = cfg.no_sync;
    // `--public-node` advertises the RPC peers may use: the restricted one.
    p.rpc_port = if cfg.public_node {
        cfg.rpc_restricted_bind_port.unwrap_or(cfg.rpc_bind_port)
    } else {
        0
    };
    p.state_file = wow_storage::env::db_dir(&cfg.data_dir, cfg.network, cfg.regtest)
        .parent()
        .map(|d| d.join(STATE_FILENAME));
    if let Some(path) = &cfg.ban_list {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read --ban-list {}: {e}", path.display()))?;
        p.ban_list =
            parse_ban_list(&text).map_err(|e| format!("--ban-list {}: {e}", path.display()))?;
    }
    if p.seed_nodes.is_empty() && p.exclusive_nodes.is_empty() && p.add_peers.is_empty() {
        wow_log::warn!(
            LOG,
            "{:?} has no seed nodes; give --add-peer or --add-exclusive-node to find peers",
            cfg.network
        );
    }

    let rng = netsync::seeded_rng()?;
    let core: Arc<dyn Core> = core;
    Node::start(p, core, rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(height: u64, target_height: u64, outgoing: usize) -> SyncStatus {
        SyncStatus {
            height,
            target_height,
            synchronized: false,
            busy_syncing: true,
            outgoing,
            incoming: 0,
        }
    }

    #[test]
    fn a_progress_line_says_how_far_how_fast_and_how_long() {
        let s = status(63_300, 873_597, 8);
        assert_eq!(
            progress_line(&s, None),
            "syncing: height 63300 of 873597 (7.2%), 810297 to go; 8 out, 0 in"
        );
        assert_eq!(
            progress_line(&s, Some((1_350, Duration::from_secs(30)))),
            "syncing: height 63300 of 873597 (7.2%), 810297 to go at 45.0 blocks/s, \
             about 5 h 00 min left; 8 out, 0 in"
        );
        assert_eq!(
            progress_line(&s, Some((0, Duration::from_secs(30)))),
            "syncing: height 63300 of 873597 (7.2%), 810297 to go, no blocks added in 30 s; \
             8 out, 0 in"
        );
        assert_eq!(
            progress_line(&status(5, 0, 0), None),
            "height 5, waiting for peers"
        );
        assert_eq!(
            progress_line(&status(5, 5, 2), None),
            "height 5; 2 out, 0 in"
        );
    }

    #[test]
    fn durations_read_in_their_largest_units() {
        assert_eq!(approx(45), "45 s");
        assert_eq!(approx(720), "12 min");
        assert_eq!(approx(3 * 3_600 + 5 * 60 + 9), "3 h 05 min");
        assert_eq!(approx(2 * 86_400 + 7 * 3_600), "2 d 7 h");
    }

    /// Behind, a line every thirty seconds with the rate since the last one;
    /// caught up, one line, once.
    #[test]
    fn progress_is_reported_while_behind_and_catching_up_is_said_once() {
        let t0 = Instant::now();
        let mut p = Progress::new(100, t0);
        assert_eq!(
            p.observe(&status(100, 1_000, 3), t0 + STATUS_EVERY),
            None,
            "not due yet"
        );
        let line = p
            .observe(&status(400, 1_000, 3), t0 + PROGRESS_EVERY)
            .expect("due");
        assert!(line.contains(" at 10.0 blocks/s"), "{line}");
        assert_eq!(
            p.observe(&status(450, 1_000, 3), t0 + PROGRESS_EVERY + STATUS_EVERY),
            None
        );

        let mut synced = status(1_000, 1_000, 3);
        synced.synchronized = true;
        synced.busy_syncing = false;
        let later = t0 + 2 * PROGRESS_EVERY;
        assert_eq!(
            p.observe(&synced, later).as_deref(),
            Some("synchronised with the network at height 1000")
        );
        assert_eq!(p.observe(&synced, later + STATUS_EVERY), None, "said once");

        // Falling behind again is reported straight away.
        assert!(p
            .observe(&status(1_000, 1_200, 3), later + 2 * STATUS_EVERY)
            .is_some());
    }

    #[test]
    fn an_address_without_a_port_gets_the_networks() {
        assert_eq!(
            resolve("127.0.0.1", 34_567).unwrap(),
            vec!["127.0.0.1:34567".parse().unwrap()]
        );
        assert_eq!(
            resolve("127.0.0.1:1234", 34_567).unwrap(),
            vec!["127.0.0.1:1234".parse().unwrap()]
        );
        assert_eq!(
            resolve("[::1]", 28_080).unwrap(),
            vec!["[::1]:28080".parse().unwrap()]
        );
        assert!(resolve("not a host name!", 1).is_err());
    }
}
