//! Anonymity zones: Tor and i2p, each with its own peers and connections
//! (`specs/08` §7.4).
//!
//! The C++ keeps one `network_zone` per network (`net_node.h`), each with its
//! own connections, peer list, relay state and configuration; the public zone
//! is the one whose addresses are clearnet. This module is the other kind: a
//! zone reached through a SOCKS5 proxy, where an address is a hidden service's
//! name and only three commands are spoken.
//!
//! # What a zone does, and what it does not
//!
//! `is_filtered_command` (`net_node.cpp`) lets only `COMMAND_HANDSHAKE`,
//! `COMMAND_TIMED_SYNC` and `NOTIFY_NEW_TRANSACTIONS` through in a non-public
//! zone; everything else is answered with
//! `LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED`. There is no syncing over Tor
//! -- no chain requests, no blocks, no fluffy blocks, no pool complement -- so
//! a zone is a small thing beside [`crate::node`]: it dials peers through the
//! proxy, handshakes, keeps its peer list current, carries this node's own
//! transactions out, and hands what arrives to the core.
//!
//! # Peer id 1, and no port
//!
//! `config_t`'s peer id is 1 and only the public zone replaces it with a
//! random one (`init_config`), so every node in an anonymity zone calls itself
//! 1. An id is how the public network notices a connection to itself; over Tor
//! it would only tie one hidden service to another. For the same reason
//! `my_port` and `rpc_port` go out as 0, the self-connection check is skipped
//! (`handle_handshake` tests it "only in the public zone"), and nobody is
//! pinged back -- there is no address to ping.
//!
//! # Noise
//!
//! Without `disable_noise`, each of `CRYPTONOTE_NOISE_CHANNELS` channels holds
//! one outgoing connection and sends a frame of exactly
//! `CRYPTONOTE_NOISE_BYTES` every 10 to 15 seconds whether or not there is
//! anything to say ([`crate::levin::noise_notify`]). A transaction goes out as
//! fragments of that same size ([`crate::levin::fragmented_notify`]), so
//! nothing about the traffic changes when this node sends one. `disable_noise`
//! gives that up and fluffs to the zone's outgoing connections on Poisson
//! timers instead: cheaper, and much less private.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wow_crypto::random::Rng;
use wow_crypto::types::Hash256;
use wow_types::Network;

use crate::frame::{encode, FrameReader};
use crate::levin::{self, command, Header, Kind};
use crate::messages::{
    self, BasicNodeData, HandshakeRequest, HandshakeResponse, NetworkAddress, NewTransactions,
    PeerlistEntry, TimedSync,
};
use crate::node::{lock, poisson_from, Core, StemMap, TxBatch, TxRelay, TxVerdict};
use crate::socks::{self, Proxy};

const LOG: &str = "net.p2p.tx";

/// `CRYPTONOTE_NOISE_BYTES`: the size of every frame a noise channel sends.
pub const NOISE_BYTES: usize = 3 * 1024;
/// `CRYPTONOTE_NOISE_CHANNELS`: outgoing connections a zone sends over.
pub const NOISE_CHANNELS: usize = 2;
/// `CRYPTONOTE_NOISE_MIN_DELAY`.
const NOISE_MIN_DELAY: Duration = Duration::from_secs(10);
/// `CRYPTONOTE_NOISE_DELAY_RANGE`.
const NOISE_DELAY_RANGE_SECS: u64 = 5;
/// `CRYPTONOTE_NOISE_MIN_EPOCH`.
const NOISE_MIN_EPOCH: Duration = Duration::from_secs(5 * 60);
/// `CRYPTONOTE_NOISE_EPOCH_RANGE`.
const NOISE_EPOCH_RANGE_SECS: u64 = 30;
/// `CRYPTONOTE_MAX_FRAGMENTS`: a covert message longer than this many frames
/// is refused rather than sent, since a peer would reject it.
const MAX_FRAGMENTS: usize = 20;
/// `P2P_DEFAULT_CONNECTIONS_COUNT`, the default for `--tx-proxy`'s
/// `max_connections`.
pub const DEFAULT_MAX_OUT: usize = 12;
/// `P2P_DEFAULT_HANDSHAKE_INTERVAL`.
const TIMED_SYNC_INTERVAL: Duration = Duration::from_secs(60);
/// `P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT`: how long an inbound connection has
/// to send its handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(5_000);
/// `P2P_DEFAULT_INVOKE_TIMEOUT`: a timed sync unanswered this long drops the
/// peer.
const INVOKE_TIMEOUT: Duration = Duration::from_secs(120);
/// How often the zone's own thread looks at its timers.
const TICK: Duration = Duration::from_millis(250);
/// How long a connection's reader waits before looking up from its socket.
const READ_TICK: Duration = Duration::from_millis(250);
/// How long a write to a peer may take before the connection is given up on.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Frames a connection may have waiting before it is too slow to keep.
const OUTBOX_CAPACITY: usize = 64;
/// How long before a peer that would not connect is tried again.
const RETRY_AFTER: Duration = Duration::from_secs(60);
/// `P2P_LOCAL_WHITE_PEERLIST_LIMIT`: as many hidden addresses as the C++
/// keeps white ones.
const MAX_PEERS: usize = 1_000;
/// The flush average for an outgoing connection in quarter seconds
/// (`fluff_average_out`), for a zone with noise disabled.
const FLUSH_QUARTERS_OUT: u64 = 10;

/// `epee::net_utils::zone`.
///
/// The order is the C++'s, and it matters: `send_txs` walks the zones in it
/// and takes the first anonymity zone that can carry a transaction, so i2p
/// comes before Tor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Zone {
    Public,
    I2p,
    Tor,
}

impl Zone {
    /// `zone_to_string`.
    pub fn name(self) -> &'static str {
        match self {
            Zone::Public => "public",
            Zone::I2p => "i2p",
            Zone::Tor => "tor",
        }
    }

    /// `zone_from_string`: what `--tx-proxy`'s first field may name.
    pub fn parse(s: &str) -> Option<Zone> {
        match s {
            "public" => Some(Zone::Public),
            "i2p" => Some(Zone::I2p),
            "tor" => Some(Zone::Tor),
            _ => None,
        }
    }

    /// `epee::net_utils::address_type` for this zone's addresses: 3 for i2p,
    /// 4 for Tor. The public zone's are 1 and 2, one per family.
    fn address_type(self) -> Option<u8> {
        match self {
            Zone::Public => None,
            Zone::I2p => Some(3),
            Zone::Tor => Some(4),
        }
    }
}

impl std::fmt::Display for Zone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The base32 alphabet both `tor_address.cpp` and `i2p_address.cpp` check
/// against, in either case.
const BASE32: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz234567";
/// `tor_address.cpp`'s `v2_length`.
const TOR_V2_LEN: usize = 16;
/// `tor_address.cpp`'s `v3_length`.
const TOR_V3_LEN: usize = 56;
/// `i2p_address.cpp`'s `b32_length`.
const I2P_B32_LEN: usize = 52;
/// `i2p_address::port()`, which is always 1: an i2p address has no port, and
/// the C++ reports and stores 1 so older clients see a valid one.
const I2P_PORT: u16 = 1;

/// A hidden service's address: `x.onion[:port]` or `y.b32.i2p`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HiddenAddr {
    pub zone: Zone,
    /// The host with its suffix, in the case it was written in --
    /// `host_check` accepts either, and the C++ keeps what it was given.
    pub host: String,
    /// Tor's port, or [`I2P_PORT`].
    pub port: u16,
}

impl HiddenAddr {
    /// Parse an address, taking `default_port` when none is given.
    ///
    /// `net::get_network_address` splits the host from the port at the last
    /// colon -- there is no bracketed form here -- and hands `.onion` to
    /// `tor_address::make` and `.i2p` to `i2p_address::make`. Those check the
    /// length and the alphabet of the part before the suffix; a v3 checksum is
    /// not verified, which the C++ leaves as a to-do as well.
    pub fn parse(value: &str, default_port: u16) -> Result<HiddenAddr, String> {
        let (host, port) = match value.rsplit_once(':') {
            Some((h, p)) => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| format!("`{value}`: `{p}` is not a port"))?;
                (h, Some(port))
            }
            None => (value, None),
        };
        let bad = |what: &str| format!("`{value}` is not {what}");

        if host.ends_with(".i2p") {
            let Some(b32) = host.strip_suffix(".b32.i2p") else {
                return Err(bad("a .b32.i2p address"));
            };
            if b32.len() != I2P_B32_LEN || !is_base32(b32) {
                return Err(bad("a .b32.i2p address"));
            }
            // An i2p address carries no port of its own.
            return Ok(HiddenAddr {
                zone: Zone::I2p,
                host: host.to_string(),
                port: I2P_PORT,
            });
        }
        if let Some(b32) = host.strip_suffix(".onion") {
            if (b32.len() != TOR_V2_LEN && b32.len() != TOR_V3_LEN) || !is_base32(b32) {
                return Err(bad("a .onion address"));
            }
            return Ok(HiddenAddr {
                zone: Zone::Tor,
                host: host.to_string(),
                port: port.unwrap_or(default_port),
            });
        }
        Err(bad("a .onion or .b32.i2p address"))
    }

    /// `tor_address::unknown()`: the peer at the other end of an inbound
    /// connection, whose address the proxy does not pass on.
    ///
    /// The C++ hands the same placeholder to `set_default_remote`, and the
    /// host it uses is what this prints. Such an address is never dialled and
    /// never goes into a peer list.
    pub fn unknown(zone: Zone) -> HiddenAddr {
        let host = match zone {
            Zone::I2p => "<unknown i2p host>",
            _ => "<unknown tor host>",
        };
        HiddenAddr {
            zone,
            host: host.to_string(),
            port: 0,
        }
    }

    /// Whether this is [`HiddenAddr::unknown`], which is not an address.
    pub fn is_unknown(&self) -> bool {
        self.host.starts_with('<')
    }

    /// Whether `value` looks like an address for one of these networks, so a
    /// caller can tell it from a clearnet one before parsing.
    pub fn is_hidden(value: &str) -> bool {
        let host = match value.rsplit_once(':') {
            Some((h, _)) => h,
            None => value,
        };
        host.ends_with(".onion") || host.ends_with(".i2p")
    }

    /// The wire form (`specs/08` §3.1): type 4 with a host and a port for
    /// Tor, type 3 for i2p.
    pub fn to_network_address(&self) -> NetworkAddress {
        NetworkAddress::Hidden {
            kind: self.zone.address_type().unwrap_or(0),
            host: self.host.clone(),
            port: self.port,
        }
    }

    /// The address a peer list carried, when it is one of these and its
    /// pieces agree.
    pub fn from_network_address(addr: &NetworkAddress) -> Option<HiddenAddr> {
        let NetworkAddress::Hidden { kind, host, port } = addr else {
            return None;
        };
        let parsed = HiddenAddr::parse(host, *port).ok()?;
        // A Tor address under i2p's type, or the other way about, is not an
        // address this node will dial.
        if parsed.zone.address_type() != Some(*kind) {
            return None;
        }
        Some(parsed)
    }
}

impl std::fmt::Display for HiddenAddr {
    /// `tor_address::str`: the host, and the port after it when there is one.
    /// An i2p address, and one with no port at all, print as the host alone.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.zone {
            Zone::I2p => f.write_str(&self.host),
            _ if self.port == 0 => f.write_str(&self.host),
            _ => write!(f, "{}:{}", self.host, self.port),
        }
    }
}

fn is_base32(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| BASE32.contains(c))
}

/// `P2P_DEFAULT_PEERS_IN_HANDSHAKE`: what a timed sync may carry, this node's
/// own address included.
const MAX_PEERS_IN_SYNC: usize = messages::MAX_PEERS_IN_HANDSHAKE;

/// `ours` put at position `at` of `peers`, with the list one shorter to make
/// room for it.
///
/// The C++ inserts it rather than appending so that its place says nothing:
/// "Insert into `local_peerlist_new` so that it is only sent once like the
/// other peers."
fn with_our_address(
    mut peers: Vec<PeerlistEntry>,
    ours: &HiddenAddr,
    at: usize,
) -> Vec<PeerlistEntry> {
    peers.truncate(MAX_PEERS_IN_SYNC - 1);
    let entry = PeerlistEntry {
        address: ours.to_network_address(),
        // `zone.m_config.m_peer_id`, which is 1 in every anonymity zone.
        id: 1,
        last_seen: 0,
        pruning_seed: 0,
        rpc_port: 0,
    };
    let at = at.min(peers.len());
    peers.insert(at, entry);
    peers
}

/// One zone's configuration: what `--tx-proxy` says about it.
#[derive(Clone, Debug)]
pub struct ZoneConfig {
    pub zone: Zone,
    /// The SOCKS5 proxy this zone's peers are reached through. A zone without
    /// one never dials (`network_zone::m_connect == nullptr`).
    pub proxy: Option<Proxy>,
    /// `--tx-proxy`'s `max_connections`.
    pub max_out: usize,
    /// Whether this zone sends over noise channels; `disable_noise` clears it.
    pub noise: bool,
    /// `--pad-transactions`, which a zone without noise pads its fluffs with.
    pub pad_transactions: bool,
    /// The peers to dial: the `--add-peer` and `--add-exclusive-node`
    /// addresses in this zone. Wownero has no Tor or i2p seed nodes, so
    /// without these a zone has nowhere to start.
    pub peers: Vec<HiddenAddr>,
    /// `--anonymous-inbound`'s hidden address: what this node is called on
    /// this network.
    ///
    /// It goes out in the peer list of a timed sync answered on an outgoing
    /// connection, and nowhere else. A peer reached through a proxy cannot see
    /// the address it is talking to, so this is the only way it can pass it
    /// on.
    pub our_address: Option<HiddenAddr>,
    /// Where the hidden service forwards its connections, which is where the
    /// zone listens (`network_zone::m_bind_ip` and `m_port`).
    pub bind: Option<SocketAddr>,
    /// `--anonymous-inbound`'s `max_connections`. `usize::MAX` for the
    /// C++'s default of no limit.
    pub max_in: usize,
}

impl ZoneConfig {
    /// The defaults for `zone` behind `proxy`: the C++'s connection count,
    /// noise on, no peers, and no inbound service.
    pub fn new(zone: Zone, proxy: Proxy) -> ZoneConfig {
        ZoneConfig {
            proxy: Some(proxy),
            ..ZoneConfig::inbound_only(zone)
        }
    }

    /// A zone with no proxy: it takes the connections `--anonymous-inbound`
    /// forwards and dials nothing, as a zone whose `m_connect` is null.
    pub fn inbound_only(zone: Zone) -> ZoneConfig {
        ZoneConfig {
            zone,
            proxy: None,
            max_out: DEFAULT_MAX_OUT,
            noise: true,
            pad_transactions: false,
            peers: Vec::new(),
            our_address: None,
            bind: None,
            max_in: usize::MAX,
        }
    }
}

/// `notify::status`: what a zone can do with a transaction right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneStatus {
    /// The zone sends over noise channels.
    pub has_noise: bool,
    /// Every noise channel has a connection.
    pub connections_filled: bool,
    /// There is at least one outgoing connection to send over.
    pub has_outgoing: bool,
}

/// One noise channel: an outgoing connection, the message being sent over it
/// a frame at a time, and the ones waiting.
struct Channel {
    /// The connection this channel sends on, `None` when its slot is empty.
    conn: Option<u64>,
    /// What is left of the message in flight.
    active: VecDeque<Vec<u8>>,
    /// Whole messages waiting, each already cut into frames.
    queue: VecDeque<VecDeque<Vec<u8>>>,
    /// When the next frame goes.
    next: Instant,
}

impl Channel {
    fn new(now: Instant) -> Channel {
        Channel {
            conn: None,
            active: VecDeque::new(),
            queue: VecDeque::new(),
            next: now,
        }
    }
}

/// One connection in a zone.
struct ZoneConn {
    id: u64,
    peer: HiddenAddr,
    incoming: bool,
    /// What the peer's handshake or last timed sync said its chain height is.
    height: AtomicU64,
    /// Frames waiting for the connection's own thread to write.
    outbox: Mutex<VecDeque<Vec<u8>>>,
    /// A handle on the socket, to shut it down from another thread.
    socket: TcpStream,
    closed: AtomicBool,
    /// When the timed sync still unanswered went out (`m_in_timedsync`).
    timed_sync_sent: Mutex<Option<Instant>>,
}

impl ZoneConn {
    fn closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self.socket.shutdown(Shutdown::Both);
        }
    }

    /// Queue a frame. False when the connection is gone, or so far behind
    /// that keeping it would only hold the sender up.
    fn send(&self, frame: Vec<u8>) -> bool {
        if self.closed() {
            return false;
        }
        let mut outbox = lock(&self.outbox);
        if outbox.len() >= OUTBOX_CAPACITY {
            drop(outbox);
            wow_log::debug!(LOG, "{}: outbox full, disconnecting", self.peer);
            self.close();
            return false;
        }
        outbox.push_back(frame);
        true
    }

    fn notify(&self, cmd: u32, body: &[u8]) -> bool {
        self.send(encode(&Header::notification(cmd, body.len() as u64), body))
    }

    fn request(&self, cmd: u32, body: &[u8]) -> bool {
        self.send(encode(&Header::request(cmd, body.len() as u64), body))
    }

    fn respond(&self, cmd: u32, code: i32, body: &[u8]) -> bool {
        self.send(encode(
            &Header::response(cmd, body.len() as u64, code),
            body,
        ))
    }
}

/// A zone's state, shared by its threads.
struct ZoneShared {
    cfg: ZoneConfig,
    core: Arc<dyn Core>,
    network: Network,
    rng: Mutex<Rng>,
    stopping: AtomicBool,
    /// The addresses this zone knows, its own peer list.
    peers: Mutex<Vec<HiddenAddr>>,
    conns: Mutex<HashMap<u64, Arc<ZoneConn>>>,
    next_id: AtomicU64,
    /// Peers being dialled, and when each was last tried.
    dialing: Mutex<Vec<HiddenAddr>>,
    tried: Mutex<HashMap<HiddenAddr, Instant>>,
    /// The noise channels, empty when this zone has noise disabled.
    channels: Mutex<Vec<Channel>>,
    /// `net::dandelionpp::connection_map`: which connection each channel
    /// holds, mended a slot at a time.
    map: Mutex<StemMap>,
    epoch_ends: Mutex<Instant>,
    /// Per-connection fluff queues, for a zone with noise disabled.
    queued: Mutex<HashMap<u64, (Instant, TxBatch)>>,
    /// Transactions that arrived over this zone and are the node's to pass on
    /// over the public network.
    arrived: Mutex<Vec<(Hash256, Vec<u8>, TxRelay)>>,
    /// One noise frame, cloned for every send.
    noise: Vec<u8>,
}

/// One running anonymity zone.
pub struct AnonZone {
    shared: Arc<ZoneShared>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl AnonZone {
    /// Start the zone: its peer list from the configuration, its noise
    /// channels, and the thread that keeps its connections up.
    ///
    /// `rng` must be seeded from the operating system, as the node's is: the
    /// noise timers and the channels' connections come from it.
    pub fn start(
        cfg: ZoneConfig,
        network: Network,
        core: Arc<dyn Core>,
        rng: Rng,
    ) -> Result<Arc<AnonZone>, String> {
        let now = Instant::now();
        let mut noise = Vec::new();
        let mut channels = Vec::new();
        if cfg.noise {
            noise = levin::noise_notify(NOISE_BYTES).ok_or("the noise frame is too small")?;
            channels = (0..NOISE_CHANNELS).map(|_| Channel::new(now)).collect();
        }
        let mut peers = cfg.peers.clone();
        peers.retain(|p| p.zone == cfg.zone);
        peers.sort();
        peers.dedup();

        let shared = Arc::new(ZoneShared {
            cfg,
            core,
            network,
            rng: Mutex::new(rng),
            stopping: AtomicBool::new(false),
            peers: Mutex::new(peers),
            conns: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            dialing: Mutex::new(Vec::new()),
            tried: Mutex::new(HashMap::new()),
            channels: Mutex::new(channels),
            map: Mutex::new(StemMap::default()),
            epoch_ends: Mutex::new(now),
            queued: Mutex::new(HashMap::new()),
            arrived: Mutex::new(Vec::new()),
            noise,
        });

        let zone = Arc::new(AnonZone {
            shared: shared.clone(),
            threads: Mutex::new(Vec::new()),
        });

        // `--anonymous-inbound`: the hidden service forwards to this address,
        // so this is where the zone listens.
        if let Some(bind) = shared.cfg.bind {
            let listener = crate::net::listen(bind)
                .map_err(|e| format!("cannot listen for {} peers on {bind}: {e}", zone.zone()))?;
            let s = shared.clone();
            let name = format!("p2p-{}-listen", shared.cfg.zone.name());
            let thread = std::thread::Builder::new()
                .name(name)
                .spawn(move || accept_loop(s, listener))
                .map_err(|e| format!("cannot start the zone's listener: {e}"))?;
            lock(&zone.threads).push(thread);
            let ours = shared.cfg.our_address.clone();
            wow_log::info!(
                LOG,
                "listening for {} peers on {bind} as {}",
                shared.cfg.zone,
                ours.map(|a| a.to_string()).unwrap_or_default()
            );
        }

        let name = format!("p2p-{}", shared.cfg.zone.name());
        let thread = std::thread::Builder::new()
            .name(name)
            .spawn(move || maintain(shared))
            .map_err(|e| format!("cannot start the zone's thread: {e}"))?;
        lock(&zone.threads).push(thread);
        Ok(zone)
    }

    pub fn zone(&self) -> Zone {
        self.shared.cfg.zone
    }

    /// `notify::get_status`, which `send_txs` picks a zone with.
    pub fn status(&self) -> ZoneStatus {
        let mut filled = false;
        if self.shared.cfg.noise {
            let channels = lock(&self.shared.channels);
            filled = channels.iter().all(|c| c.conn.is_some());
        }
        ZoneStatus {
            has_noise: self.shared.cfg.noise,
            connections_filled: filled,
            has_outgoing: !self.shared.outgoing().is_empty(),
        }
    }

    /// Send this node's own transactions over the zone
    /// (`notify::send_txs`). Returns whether they were taken.
    ///
    /// Either way the core is told `Local` and not `Fluff`: a transaction
    /// that went out over Tor is not the network's to see yet, and marking it
    /// public here would show it to everyone asking this node's pool.
    pub fn send_txs(&self, txs: &TxBatch) -> bool {
        if txs.is_empty() {
            return true;
        }
        if self.shared.cfg.noise {
            self.shared.covert_send(txs)
        } else {
            self.shared.fluff(txs)
        }
    }

    /// The transactions that arrived over this zone since the last call, with
    /// how each goes on: `Forward` for one to hold back and then stem on the
    /// public network, `Fluff` for one whose sender had noise disabled and
    /// fluffed it.
    pub fn take_arrived(&self) -> Vec<(Hash256, Vec<u8>, TxRelay)> {
        let mut arrived = lock(&self.shared.arrived);
        std::mem::take(&mut *arrived)
    }

    /// Connections, for the log and the status line.
    pub fn connection_count(&self) -> usize {
        lock(&self.shared.conns).len()
    }

    /// Addresses this zone knows.
    pub fn peer_count(&self) -> usize {
        lock(&self.shared.peers).len()
    }

    /// Stop the zone's threads and close its connections.
    pub fn stop(&self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        for c in lock(&self.shared.conns).values() {
            c.close();
        }
        let threads: Vec<JoinHandle<()>> = lock(&self.threads).drain(..).collect();
        for t in threads {
            let _ = t.join();
        }
    }
}

impl ZoneShared {
    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }

    fn rand_u64(&self) -> u64 {
        let mut b = [0u8; 8];
        lock(&self.rng).fill(&mut b);
        u64::from_le_bytes(b)
    }

    fn rand_below(&self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.rand_u64() % n as u64) as usize
        }
    }

    /// `basic_node_data` for this zone: peer id 1, and no port of any kind.
    fn node_data(&self) -> BasicNodeData {
        BasicNodeData {
            network_id: messages::network_id(self.network),
            // `config_t::m_peer_id`, which only the public zone replaces.
            peer_id: 1,
            my_port: 0,
            rpc_port: 0,
            rpc_credits_per_hash: 0,
            // "only set in public zone".
            support_flags: 0,
        }
    }

    fn snapshot(&self) -> Vec<Arc<ZoneConn>> {
        lock(&self.conns).values().cloned().collect()
    }

    /// `get_out_connections`: the outgoing connections a channel may hold,
    /// which are those whose peer is not behind this node.
    ///
    /// The C++ compares against `max(local height, median remote height)`
    /// while it is still syncing; this layer knows only what the core says its
    /// height is, and uses that.
    fn outgoing(&self) -> Vec<u64> {
        let height = self.core.sync_data().current_height;
        self.snapshot()
            .iter()
            .filter(|c| !c.incoming && !c.closed())
            .filter(|c| c.height.load(Ordering::Relaxed) >= height)
            .map(|c| c.id)
            .collect()
    }

    /// A random pick of this zone's peers for a handshake or timed sync,
    /// `last_seen` zeroed as `get_peerlist_head(..., anonymize)` zeroes it.
    ///
    /// Every id is 1: in an anonymity zone that is the only id there is.
    fn peer_list(&self) -> Vec<PeerlistEntry> {
        let mut addrs = lock(&self.peers).clone();
        let take = messages::MAX_PEERS_IN_HANDSHAKE.min(addrs.len());
        for i in 0..take {
            let j = i + self.rand_below(addrs.len() - i);
            addrs.swap(i, j);
        }
        addrs.truncate(take);
        addrs
            .iter()
            .map(|a| PeerlistEntry {
                address: a.to_network_address(),
                id: 1,
                last_seen: 0,
                pruning_seed: 0,
                rpc_port: 0,
            })
            .collect()
    }

    /// The peer list a timed sync is answered with.
    ///
    /// On an **outgoing** connection, this node's own hidden address goes in
    /// with the rest (`handle_timed_sync`): a peer reached through a proxy
    /// cannot see the address it is talking to, so this is the only way it
    /// learns one to pass on. Nothing is told to an inbound peer, which
    /// reached this node by that address already.
    fn sync_peers(&self, incoming: bool) -> Vec<PeerlistEntry> {
        let peers = self.peer_list();
        let Some(ours) = self.cfg.our_address.clone() else {
            return peers;
        };
        if incoming {
            return peers;
        }
        let at = self.rand_below(peers.len().min(MAX_PEERS_IN_SYNC - 1) + 1);
        with_our_address(peers, &ours, at)
    }

    /// Take what a peer list offered, dropping what belongs to another zone.
    ///
    /// The C++ drops the whole list in that case ("sent peerlist from another
    /// zone, dropping"); this keeps the entries that do belong, which is the
    /// same for an honest peer and less brittle for a peer that is confused
    /// rather than hostile.
    fn merge_peers(&self, entries: &[PeerlistEntry]) {
        let fresh: Vec<HiddenAddr> = entries
            .iter()
            .filter_map(|e| HiddenAddr::from_network_address(&e.address))
            .filter(|a| a.zone == self.cfg.zone && !a.is_unknown())
            // A peer that hands this node its own address back is not a peer
            // to dial.
            .filter(|a| self.cfg.our_address.as_ref() != Some(a))
            .collect();
        if fresh.is_empty() {
            return;
        }
        let mut peers = lock(&self.peers);
        for addr in fresh {
            if peers.len() >= MAX_PEERS {
                break;
            }
            if !peers.contains(&addr) {
                peers.push(addr);
            }
        }
    }

    /// The next peer to dial, or `None` when there is nothing to try.
    fn candidate(&self) -> Option<HiddenAddr> {
        let now = Instant::now();
        let connected: Vec<HiddenAddr> = self.snapshot().iter().map(|c| c.peer.clone()).collect();
        let dialing = lock(&self.dialing).clone();
        let tried = lock(&self.tried).clone();
        let peers = lock(&self.peers);
        let usable: Vec<HiddenAddr> = peers
            .iter()
            .filter(|a| !connected.contains(*a) && !dialing.contains(*a))
            .filter(|a| {
                tried
                    .get(*a)
                    .is_none_or(|t| now.duration_since(*t) >= RETRY_AFTER)
            })
            .cloned()
            .collect();
        drop(peers);
        if usable.is_empty() {
            return None;
        }
        Some(usable[self.rand_below(usable.len())].clone())
    }

    /// `notify::send_txs`'s noise branch: the message, cut into frames of
    /// [`NOISE_BYTES`], queued on every channel.
    ///
    /// No padding: the frames are all one size already, so `--pad-transactions`
    /// would only make the message longer ("Padding is not useful when using
    /// noise mode"). The fluff flag is off, so the peer that gets it stems it
    /// on.
    fn covert_send(&self, txs: &TxBatch) -> bool {
        let blobs = txs.iter().map(|(_, blob)| blob.clone()).collect();
        let body = NewTransactions {
            txs: blobs,
            dandelionpp_fluff: false,
        }
        .to_bytes();
        let cmd = command::NEW_TRANSACTIONS;
        let Some(message) = levin::fragmented_notify(NOISE_BYTES, cmd, &body) else {
            wow_log::error!(LOG, "a noise frame too small for a transaction message");
            return false;
        };
        if message.len() > MAX_FRAGMENTS * NOISE_BYTES {
            wow_log::error!(
                LOG,
                "{} transaction(s) exceed the covert fragment size; not sent",
                txs.len()
            );
            return false;
        }
        let frames: VecDeque<Vec<u8>> = message.chunks(NOISE_BYTES).map(<[u8]>::to_vec).collect();

        let mut channels = lock(&self.channels);
        let mut waiting = 0;
        for channel in channels.iter_mut() {
            if channel.conn.is_none() {
                continue;
            }
            channel.queue.push_back(frames.clone());
            waiting += 1;
        }
        drop(channels);
        if waiting == 0 {
            // `queue_covert_notify`'s warning: the transactions stay in the
            // pool, which offers them again once a channel has a connection.
            wow_log::warn!(
                LOG,
                "no {} connection to send {} transaction(s) over yet",
                self.cfg.zone,
                txs.len()
            );
            return false;
        }
        let ids: Vec<Hash256> = txs.iter().map(|(id, _)| *id).collect();
        self.core.tx_relayed(&ids, TxRelay::Local);
        true
    }

    /// `fluff_notify` for a zone with noise disabled: queued to the zone's
    /// outgoing connections, each on its own Poisson timer.
    fn fluff(&self, txs: &TxBatch) -> bool {
        let targets = self.outgoing();
        if targets.is_empty() {
            wow_log::warn!(
                LOG,
                "no {} connection to send {} transaction(s) over yet",
                self.cfg.zone,
                txs.len()
            );
            return false;
        }
        let now = Instant::now();
        let mut queued = lock(&self.queued);
        for t in targets {
            let queue = queued
                .entry(t)
                .or_insert_with(|| (now + self.flush_delay(), Vec::new()));
            queue.1.extend(txs.iter().cloned());
        }
        drop(queued);
        let ids: Vec<Hash256> = txs.iter().map(|(id, _)| *id).collect();
        self.core.tx_relayed(&ids, TxRelay::Local);
        true
    }

    /// The wait before a connection's queue goes out, Poisson about 2.5 s in
    /// quarter seconds, as the C++ draws an outgoing connection's.
    fn flush_delay(&self) -> Duration {
        let quarters = poisson_from(&mut lock(&self.rng), FLUSH_QUARTERS_OUT);
        Duration::from_millis(250 * quarters)
    }
}

// ---------------------------------------------------------------------------
// threads
// ---------------------------------------------------------------------------

/// The zone's own thread: connections, epochs, noise, and the fluff queues.
fn maintain(shared: Arc<ZoneShared>) {
    let mut last_timed_sync: Option<Instant> = None;
    while !shared.stopping() {
        reap(&shared);
        make_connections(&shared);
        if last_timed_sync.is_none_or(|t| t.elapsed() >= TIMED_SYNC_INTERVAL) {
            last_timed_sync = Some(Instant::now());
            timed_sync_all(&shared);
        }
        if shared.cfg.noise {
            epoch(&shared);
            fill_channels(&shared);
            noise_tick(&shared);
        } else {
            flush_tick(&shared);
        }
        std::thread::sleep(TICK);
    }
}

/// Forget connections whose threads have finished.
fn reap(shared: &Arc<ZoneShared>) {
    let gone: Vec<u64> = lock(&shared.conns)
        .iter()
        .filter(|(_, c)| c.closed())
        .map(|(id, _)| *id)
        .collect();
    if gone.is_empty() {
        return;
    }
    let mut conns = lock(&shared.conns);
    for id in &gone {
        conns.remove(id);
    }
    drop(conns);
    let mut queued = lock(&shared.queued);
    for id in &gone {
        queued.remove(id);
    }
}

/// Keep the zone's outgoing connections at `max_out`.
fn make_connections(shared: &Arc<ZoneShared>) {
    let Some(proxy) = shared.cfg.proxy.clone() else {
        return;
    };
    let outgoing = shared
        .snapshot()
        .iter()
        .filter(|c| !c.incoming)
        .count()
        .saturating_add(lock(&shared.dialing).len());
    if outgoing >= shared.cfg.max_out {
        return;
    }
    let Some(peer) = shared.candidate() else {
        return;
    };
    lock(&shared.tried).insert(peer.clone(), Instant::now());
    lock(&shared.dialing).push(peer.clone());

    let s = shared.clone();
    let dialling = peer.clone();
    let name = format!("p2p-{}-out", shared.cfg.zone.name());
    let spawned = std::thread::Builder::new().name(name).spawn(move || {
        let result = dial(&s, &proxy, &dialling);
        lock(&s.dialing).retain(|p| p != &dialling);
        match result {
            Ok((conn, stream, reader)) => run_connection(s, conn, stream, reader),
            Err(e) => wow_log::debug!(LOG, "{dialling}: {e}"),
        }
    });
    if spawned.is_err() {
        lock(&shared.dialing).retain(|p| p != &peer);
    }
}

/// Take the connections the hidden service forwards (`--anonymous-inbound`).
fn accept_loop(shared: Arc<ZoneShared>, listener: TcpListener) {
    if listener.set_nonblocking(true).is_err() {
        wow_log::error!(
            LOG,
            "cannot poll the {} listener; not accepting connections",
            shared.cfg.zone
        );
        return;
    }
    while !shared.stopping() {
        match listener.accept() {
            Ok((stream, _)) => {
                let s = shared.clone();
                let name = format!("p2p-{}-in", shared.cfg.zone.name());
                let _ = std::thread::Builder::new()
                    .name(name)
                    .spawn(move || inbound(s, stream));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                wow_log::debug!(LOG, "{} accept failed: {e}", shared.cfg.zone);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// One forwarded connection: the handshake, then the connection itself.
///
/// The peer's address is not known and cannot be -- the proxy does not pass
/// it on -- so there is nothing to ban, nothing to ping back and nothing to
/// put in a peer list. Two hidden peers are also indistinguishable by id,
/// since every id in a zone is 1, so the public zone's rule of one connection
/// per peer id has no place here.
fn inbound(shared: Arc<ZoneShared>, mut stream: TcpStream) {
    let taken = shared.snapshot().iter().filter(|c| c.incoming).count();
    if taken >= shared.cfg.max_in {
        return;
    }
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);
    if stream.set_read_timeout(Some(READ_TICK)).is_err() {
        return;
    }
    if stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err() {
        return;
    }

    let mut reader = FrameReader::new(levin::INITIAL_MAX_PACKET_SIZE);
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let request = loop {
        if Instant::now() >= deadline {
            return;
        }
        match reader.poll(&mut stream) {
            // A zone speaks nothing before a handshake, so anything else
            // ends the connection rather than waiting for one.
            Ok(Some((h, body))) => {
                if h.command != command::HANDSHAKE || h.kind() != Kind::Request {
                    return;
                }
                match HandshakeRequest::parse(&body) {
                    Ok(r) => break r,
                    Err(e) => {
                        wow_log::debug!(LOG, "a malformed inbound handshake: {e}");
                        return;
                    }
                }
            }
            Ok(None) => {}
            Err(_) => return,
        }
    };
    if request.node_data.network_id != messages::network_id(shared.network) {
        return;
    }

    let peers = shared.peer_list();
    let sync = shared.core.sync_data();
    let body = messages::handshake_response(&shared.node_data(), &sync, &peers);
    let header = Header::response(command::HANDSHAKE, body.len() as u64, 1);
    if stream.write_all(&encode(&header, &body)).is_err() {
        return;
    }
    // A handshake request carries no peer list, so there is nothing to merge.
    reader.set_limit(levin::DEFAULT_MAX_PACKET_SIZE);

    let Ok(socket) = stream.try_clone() else {
        return;
    };
    let conn = Arc::new(ZoneConn {
        id: shared.next_id.fetch_add(1, Ordering::Relaxed),
        peer: HiddenAddr::unknown(shared.cfg.zone),
        incoming: true,
        height: AtomicU64::new(request.payload_data.current_height),
        outbox: Mutex::new(VecDeque::new()),
        socket,
        closed: AtomicBool::new(false),
        timed_sync_sent: Mutex::new(None),
    });
    lock(&shared.conns).insert(conn.id, conn.clone());
    wow_log::info!(
        LOG,
        "an inbound {} connection, at height {}",
        shared.cfg.zone,
        request.payload_data.current_height
    );
    run_connection(shared, conn, stream, reader);
}

/// Dial a peer through the proxy and handshake with it.
///
/// The address goes to the proxy as a **name**: a hidden service has no
/// address this node could look up, and asking a resolver about it would
/// defeat the point.
fn dial(
    shared: &Arc<ZoneShared>,
    proxy: &Proxy,
    peer: &HiddenAddr,
) -> Result<(Arc<ZoneConn>, TcpStream, FrameReader), String> {
    let target = socks::Target::Host(&peer.host, peer.port);
    let mut stream = socks::connect(proxy, target, socks::CONNECT_TIMEOUT)
        .map_err(|e| format!("through the proxy at {proxy}: {e}"))?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|e| e.to_string())?;

    let body = messages::handshake_request(&shared.node_data(), &shared.core.sync_data());
    let header = Header::request(command::HANDSHAKE, body.len() as u64);
    stream
        .write_all(&encode(&header, &body))
        .map_err(|e| e.to_string())?;

    let mut reader = FrameReader::new(levin::INITIAL_MAX_PACKET_SIZE);
    stream
        .set_read_timeout(Some(READ_TICK))
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + socks::CONNECT_TIMEOUT;
    let response = loop {
        if Instant::now() >= deadline {
            return Err("the handshake timed out".into());
        }
        match reader.poll(&mut stream) {
            Ok(Some((h, body))) => {
                if h.command != command::HANDSHAKE || h.kind() != Kind::Response {
                    continue;
                }
                if h.return_code < 0 {
                    return Err(format!("the handshake was refused ({})", h.return_code));
                }
                break HandshakeResponse::parse(&body).map_err(|e| e.to_string())?;
            }
            Ok(None) => {}
            Err(e) => return Err(e.to_string()),
        }
    };
    if response.node_data.network_id != messages::network_id(shared.network) {
        return Err("that peer is on another network".into());
    }
    // No self-connection check: every peer id in this zone is 1, and the C++
    // compares them "only in the public zone" for the same reason.
    reader.set_limit(levin::DEFAULT_MAX_PACKET_SIZE);
    shared.merge_peers(&response.peers);

    let socket = stream.try_clone().map_err(|e| e.to_string())?;
    let conn = Arc::new(ZoneConn {
        id: shared.next_id.fetch_add(1, Ordering::Relaxed),
        peer: peer.clone(),
        incoming: false,
        height: AtomicU64::new(response.payload_data.current_height),
        outbox: Mutex::new(VecDeque::new()),
        socket,
        closed: AtomicBool::new(false),
        timed_sync_sent: Mutex::new(None),
    });
    lock(&shared.conns).insert(conn.id, conn.clone());
    wow_log::info!(
        LOG,
        "connected to {peer} over {} at height {}",
        shared.cfg.zone,
        response.payload_data.current_height
    );
    Ok((conn, stream, reader))
}

/// Run a handshaken connection until it ends: write what is queued, read what
/// arrives, and answer it.
fn run_connection(
    shared: Arc<ZoneShared>,
    conn: Arc<ZoneConn>,
    mut stream: TcpStream,
    mut reader: FrameReader,
) {
    let _ = stream.set_read_timeout(Some(READ_TICK));
    while !shared.stopping() && !conn.closed() {
        let queued: Vec<Vec<u8>> = lock(&conn.outbox).drain(..).collect();
        for frame in queued {
            if stream.write_all(&frame).is_err() {
                conn.close();
                break;
            }
        }
        if conn.closed() {
            break;
        }
        match reader.poll(&mut stream) {
            Ok(Some((header, body))) => handle(&shared, &conn, &header, &body),
            Ok(None) => {}
            Err(e) => {
                wow_log::debug!(LOG, "{}: {e}", conn.peer);
                break;
            }
        }
        let overdue = lock(&conn.timed_sync_sent).is_some_and(|t| t.elapsed() > INVOKE_TIMEOUT);
        if overdue {
            wow_log::debug!(LOG, "{}: did not answer a timed sync", conn.peer);
            break;
        }
    }
    conn.close();
    lock(&shared.conns).remove(&conn.id);
    lock(&shared.queued).remove(&conn.id);
}

/// One message from a peer in this zone.
///
/// `is_filtered_command`: only the handshake, the timed sync and new
/// transactions are spoken here. Anything else that expects an answer gets
/// `LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED`, as the C++'s invoke map
/// returns for a filtered command.
fn handle(shared: &Arc<ZoneShared>, conn: &Arc<ZoneConn>, header: &Header, body: &[u8]) {
    match (header.kind(), header.command) {
        (Kind::Request, command::TIMED_SYNC) => {
            match TimedSync::parse(body) {
                Ok(sync) => {
                    conn.height
                        .store(sync.payload_data.current_height, Ordering::Relaxed);
                    shared.merge_peers(&sync.peers);
                }
                Err(e) => {
                    wow_log::debug!(LOG, "{}: malformed timed sync: {e}", conn.peer);
                    conn.close();
                    return;
                }
            }
            let peers = shared.sync_peers(conn.incoming);
            let sync = shared.core.sync_data();
            let out = messages::timed_sync_response_with_peers(&sync, &peers);
            conn.respond(command::TIMED_SYNC, 1, &out);
        }
        (Kind::Response, command::TIMED_SYNC) => {
            *lock(&conn.timed_sync_sent) = None;
            match TimedSync::parse(body) {
                Ok(sync) => {
                    conn.height
                        .store(sync.payload_data.current_height, Ordering::Relaxed);
                    shared.merge_peers(&sync.peers);
                }
                Err(e) => wow_log::debug!(LOG, "{}: malformed timed sync: {e}", conn.peer),
            }
        }
        (Kind::Notification, command::NEW_TRANSACTIONS) => {
            on_new_transactions(shared, conn, body);
        }
        (Kind::Request, _) => {
            wow_log::debug!(
                LOG,
                "{}: filtered command {} over {}",
                conn.peer,
                header.command,
                shared.cfg.zone
            );
            let code = levin::ERROR_CONNECTION_HANDLER_NOT_DEFINED;
            conn.respond(header.command, code, &messages::empty_body());
        }
        _ => wow_log::debug!(
            LOG,
            "{}: ignored command {} over {}",
            conn.peer,
            header.command,
            shared.cfg.zone
        ),
    }
}

/// Transactions from a peer in this zone.
///
/// `handle_notify_new_transactions` picks the relay method from the zone: a
/// transaction over Tor or i2p is a **forward**, held back and then stemmed on
/// the public network, unless the sender set the fluff flag -- which a hidden
/// service with noise disabled does, and which says to fluff it at once.
///
/// Either way this zone does not send it on. It goes to the node, which has
/// the public connections.
fn on_new_transactions(shared: &Arc<ZoneShared>, conn: &Arc<ZoneConn>, body: &[u8]) {
    let message = match NewTransactions::parse(body) {
        Ok(m) => m,
        Err(e) => {
            wow_log::debug!(LOG, "{}: malformed transactions: {e}", conn.peer);
            conn.close();
            return;
        }
    };
    if message.txs.is_empty() {
        return;
    }
    let fluff = message.dandelionpp_fluff;
    let verdicts = shared.core.incoming_txs_anonymous(&message.txs, fluff);
    let mut arrived = Vec::new();
    for (verdict, blob) in verdicts.iter().zip(message.txs.iter()) {
        match verdict {
            TxVerdict::Accepted { id, how: Some(how) } => {
                arrived.push((*id, blob.clone(), *how));
            }
            TxVerdict::Accepted { .. } | TxVerdict::Known { .. } => {}
            TxVerdict::Rejected { reason, ban } => {
                // There is nothing to ban in an anonymity zone -- no address
                // to ban, and a hidden service is free to make another
                // connection -- so a bad peer is dropped and no more.
                wow_log::debug!(LOG, "{}: a refused transaction: {reason}", conn.peer);
                if *ban {
                    conn.close();
                    return;
                }
            }
        }
    }
    if !arrived.is_empty() {
        lock(&shared.arrived).extend(arrived);
    }
}

/// A timed sync on every connection, as the C++ sends one per
/// `P2P_DEFAULT_HANDSHAKE_INTERVAL`.
fn timed_sync_all(shared: &Arc<ZoneShared>) {
    let body = messages::timed_sync_request(&shared.core.sync_data());
    for c in shared.snapshot() {
        let mut sent = lock(&c.timed_sync_sent);
        if sent.is_some_and(|t| t.elapsed() < INVOKE_TIMEOUT) {
            continue;
        }
        *sent = Some(Instant::now());
        drop(sent);
        c.request(command::TIMED_SYNC, &body);
    }
}

/// `start_epoch`: every 5 minutes and a bit, the channels take a fresh pick of
/// the outgoing connections.
fn epoch(shared: &Arc<ZoneShared>) {
    let now = Instant::now();
    if now < *lock(&shared.epoch_ends) {
        return;
    }
    let candidates = shared.outgoing();
    let mut rand = |n: usize| shared.rand_below(n);
    let map = StemMap::new(candidates, NOISE_CHANNELS, &mut rand);
    let range = shared.rand_u64() % NOISE_EPOCH_RANGE_SECS;
    *lock(&shared.epoch_ends) = now + NOISE_MIN_EPOCH + Duration::from_secs(range);
    let mut channels = lock(&shared.channels);
    for (i, channel) in channels.iter_mut().enumerate() {
        set_channel(channel, map.slot(i));
    }
    drop(channels);
    *lock(&shared.map) = map;
    wow_log::debug!(LOG, "a new {} noise epoch", shared.cfg.zone);
}

/// `update_channel`: a channel's connection changed.
///
/// Whatever was in flight is dropped rather than finished on the new
/// connection: the C++ is emphatic that sending the rest of a message after a
/// channel moves would show that the frames were a message and not noise.
fn set_channel(channel: &mut Channel, conn: Option<u64>) {
    if channel.conn == conn {
        return;
    }
    channel.conn = conn;
    channel.active.clear();
    if conn.is_none() {
        channel.queue.clear();
    }
}

/// `notify::new_out_connection`: a channel whose slot is empty takes a
/// connection as soon as there is one to take, rather than waiting out the
/// epoch. `connection_map::update` refills the empty slots alone, so the
/// channels that are already sending are not disturbed.
fn fill_channels(shared: &Arc<ZoneShared>) {
    if lock(&shared.channels).iter().all(|c| c.conn.is_some()) {
        return;
    }
    let candidates = shared.outgoing();
    if candidates.is_empty() {
        return;
    }
    let mut rand = |n: usize| shared.rand_below(n);
    let mut map = lock(&shared.map);
    if !map.update(candidates, &mut rand) {
        return;
    }
    let mut channels = lock(&shared.channels);
    for (i, channel) in channels.iter_mut().enumerate() {
        set_channel(channel, map.slot(i));
    }
}

/// `send_noise`: one frame per channel per timer, real or not.
fn noise_tick(shared: &Arc<ZoneShared>) {
    let now = Instant::now();
    let conns = lock(&shared.conns).clone();
    let mut channels = lock(&shared.channels);
    for channel in channels.iter_mut() {
        if now < channel.next {
            continue;
        }
        let spread = Duration::from_secs(shared.rand_u64() % NOISE_DELAY_RANGE_SECS);
        channel.next = now + NOISE_MIN_DELAY + spread;
        let Some(conn) = channel.conn.and_then(|id| conns.get(&id)) else {
            continue;
        };
        if channel.active.is_empty() {
            if let Some(next) = channel.queue.pop_front() {
                channel.active = next;
            }
        }
        let frame = match channel.active.pop_front() {
            Some(frame) => frame,
            None => shared.noise.clone(),
        };
        // A connection that has gone leaves its slot empty; the next tick's
        // [`fill_channels`] finds another.
        if !conn.send(frame) {
            set_channel(channel, None);
        }
    }
}

/// `fluff_flush` for a zone with noise disabled: the queues whose timers have
/// run out, each sorted so the order says nothing about when they arrived.
fn flush_tick(shared: &Arc<ZoneShared>) {
    let now = Instant::now();
    let due: Vec<(u64, TxBatch)> = {
        let mut queued = lock(&shared.queued);
        let ids: Vec<u64> = queued
            .iter()
            .filter(|(_, (at, _))| *at <= now)
            .map(|(id, _)| *id)
            .collect();
        ids.into_iter()
            .filter_map(|id| queued.remove(&id).map(|(_, txs)| (id, txs)))
            .collect()
    };
    if due.is_empty() {
        return;
    }
    let conns = lock(&shared.conns).clone();
    for (id, mut txs) in due {
        let Some(conn) = conns.get(&id) else {
            continue;
        };
        crate::node::flush_order(&mut txs);
        let blobs = txs.into_iter().map(|(_, blob)| blob).collect();
        // "Always send with `fluff` flag, even over i2p/tor. The hidden
        // service will disable the forwarding delay and immediately fluff."
        let message = NewTransactions {
            txs: blobs,
            dandelionpp_fluff: true,
        };
        let body = if shared.cfg.pad_transactions {
            message.to_padded_bytes()
        } else {
            message.to_bytes()
        };
        conn.notify(command::NEW_TRANSACTIONS, &body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION_V3: &str = "vv7pabgs6cqsegvhdexrhrfhhsqmqrmqhqfxfkxhqgqjqvkzg6eyd6qd.onion";
    const ONION_V2: &str = "rveahdfho7wo4b2m.onion";
    const I2P: &str = "cmeua5767mz2q5jsaelk2rxhf67agrwuetaso5dzbenyzwlbkg2q.b32.i2p";

    #[test]
    fn a_zone_is_named_as_the_cpp_names_it() {
        assert_eq!(Zone::parse("tor"), Some(Zone::Tor));
        assert_eq!(Zone::parse("i2p"), Some(Zone::I2p));
        assert_eq!(Zone::parse("public"), Some(Zone::Public));
        assert_eq!(Zone::parse("Tor"), None, "the C++ compares exactly");
        assert_eq!(Zone::parse("onion"), None);
        assert_eq!(Zone::Tor.to_string(), "tor");

        // i2p before tor, which is the order `send_txs` prefers them in.
        assert!(Zone::Public < Zone::I2p && Zone::I2p < Zone::Tor);
        assert_eq!(Zone::I2p.address_type(), Some(3));
        assert_eq!(Zone::Tor.address_type(), Some(4));
    }

    /// v2 and v3 onion addresses and b32 i2p addresses, with the lengths and
    /// the alphabet `host_check` insists on.
    #[test]
    fn a_hidden_address_is_checked_as_host_check_checks_it() {
        let a = HiddenAddr::parse(ONION_V3, 34_567).expect("a v3 address");
        assert_eq!(a.zone, Zone::Tor);
        assert_eq!(a.port, 34_567, "the default port when none is given");
        assert_eq!(a.to_string(), format!("{ONION_V3}:34567"));

        let with_port = format!("{ONION_V2}:28083");
        let a = HiddenAddr::parse(&with_port, 34_567).expect("a v2 address");
        assert_eq!((a.zone, a.port), (Zone::Tor, 28_083));

        let a = HiddenAddr::parse(I2P, 34_567).expect("an i2p address");
        assert_eq!(a.zone, Zone::I2p);
        assert_eq!(a.port, I2P_PORT, "an i2p address has no port of its own");
        assert_eq!(a.to_string(), I2P);

        for bad in [
            "short.onion",
            "rveahdfho7wo4b2!.onion",
            "rveahdfho7wo4b2m.oniona",
            "cmeua5767mz2q5jsaelk2rxhf67agrwuetaso5dzbenyzwlbkg2q.i2p",
            "example.com:34567",
            "1.2.3.4:34567",
            "rveahdfho7wo4b2m.onion:notaport",
        ] {
            assert!(
                HiddenAddr::parse(bad, 34_567).is_err(),
                "`{bad}` should be refused"
            );
        }
        assert!(HiddenAddr::is_hidden(&with_port));
        assert!(HiddenAddr::is_hidden(I2P));
        assert!(!HiddenAddr::is_hidden("example.com:34567"));
    }

    /// The wire form a peer list carries, and back: type 4 for Tor with its
    /// port, type 3 for i2p with the 1 the C++ stores.
    #[test]
    fn a_hidden_address_round_trips_through_a_peer_list() {
        for text in [ONION_V3, ONION_V2, I2P] {
            let addr = HiddenAddr::parse(text, 34_567).expect("an address");
            let wire = addr.to_network_address();
            assert_eq!(wire.socket_addr(), None, "nothing to dial directly");
            let back = HiddenAddr::from_network_address(&wire).expect("the address back");
            assert_eq!(back, addr);
        }

        // A type that disagrees with the host is not an address to dial.
        let crossed = NetworkAddress::Hidden {
            kind: 3,
            host: ONION_V2.to_string(),
            port: 28_083,
        };
        assert_eq!(HiddenAddr::from_network_address(&crossed), None);
        let clearnet = NetworkAddress::V4 {
            ip: 1,
            port: 34_567,
        };
        assert_eq!(HiddenAddr::from_network_address(&clearnet), None);
    }

    /// An inbound connection's peer has no address at all, and the C++ says
    /// so in the same words.
    #[test]
    fn an_inbound_peer_has_no_address() {
        let tor = HiddenAddr::unknown(Zone::Tor);
        assert!(tor.is_unknown());
        assert_eq!(tor.to_string(), "<unknown tor host>");
        let i2p = HiddenAddr::unknown(Zone::I2p);
        assert!(i2p.is_unknown());
        assert_eq!(i2p.to_string(), "<unknown i2p host>");

        let real = HiddenAddr::parse(ONION_V2, 0).expect("an address");
        assert!(!real.is_unknown());
        // `tor_address::str` leaves a zero port off, which is what
        // `--anonymous-inbound x.onion` with no port gives.
        assert_eq!(real.to_string(), ONION_V2);
    }

    /// **What `--anonymous-inbound` is for.** A timed sync answered on an
    /// outgoing connection carries this node's own hidden address among the
    /// peers, since the peer cannot see the address it is talking to.
    #[test]
    fn a_timed_sync_carries_this_nodes_hidden_address() {
        let ours = HiddenAddr::parse("rveahdfho7wo4b2m.onion:28083", 0).expect("ours");
        let other = HiddenAddr::parse(ONION_V3, 34_567).expect("a peer");
        let entry = |a: &HiddenAddr| PeerlistEntry {
            address: a.to_network_address(),
            id: 1,
            last_seen: 0,
            pruning_seed: 0,
            rpc_port: 0,
        };

        let peers = vec![entry(&other), entry(&other)];
        let with = with_our_address(peers.clone(), &ours, 1);
        assert_eq!(with.len(), 3);
        assert_eq!(with[1].address, ours.to_network_address());
        assert_eq!(with[1].id, 1, "every node in a zone is peer 1");
        assert_eq!(with[1].last_seen, 0);

        // At either end, and never past it.
        let first = with_our_address(peers.clone(), &ours, 0);
        assert_eq!(first[0].address, ours.to_network_address());
        let end = with_our_address(peers.clone(), &ours, 99);
        assert_eq!(end[2].address, ours.to_network_address());

        // The list is one shorter to make room, so a sync still carries at
        // most `P2P_DEFAULT_PEERS_IN_HANDSHAKE` of them.
        let many = vec![entry(&other); MAX_PEERS_IN_SYNC];
        assert_eq!(with_our_address(many, &ours, 0).len(), MAX_PEERS_IN_SYNC);
    }

    /// A channel that moves drops what it was sending: the rest of a message
    /// on a new connection would say the frames were a message.
    #[test]
    fn a_channel_that_moves_drops_what_was_in_flight() {
        let now = Instant::now();
        let mut channel = Channel::new(now);
        channel.active.push_back(vec![1u8; NOISE_BYTES]);
        channel.queue.push_back(VecDeque::from(vec![vec![2u8; 8]]));

        set_channel(&mut channel, Some(7));
        assert_eq!(channel.conn, Some(7));
        assert!(channel.active.is_empty(), "what was in flight is dropped");
        assert_eq!(channel.queue.len(), 1, "what was queued still waits");

        set_channel(&mut channel, Some(7));
        assert_eq!(channel.queue.len(), 1, "the same connection: no change");

        set_channel(&mut channel, None);
        assert!(channel.conn.is_none());
        assert!(channel.queue.is_empty(), "with no connection, none waits");
    }
}
