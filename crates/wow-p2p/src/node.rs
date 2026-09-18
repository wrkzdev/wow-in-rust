//! A peer-to-peer node: the listener, outgoing connections, and the protocol
//! each of them speaks (`specs/08`, `specs/09` §5).
//!
//! # Threads, not tasks
//!
//! Each connection is two threads. The **reader** owns the socket's read side
//! and runs the protocol: it answers requests, follows the sync, and wakes
//! once a second to notice a peer that has stopped answering. The **writer**
//! drains a bounded outbox, so anything -- another connection relaying a
//! transaction, the RPC server announcing a block, the maintenance thread's
//! timed syncs -- can send to a peer without waiting on its socket. A peer too
//! slow to keep its outbox from filling is disconnected rather than allowed to
//! hold up the senders.
//!
//! At the connection counts a node runs with (a dozen outgoing, some tens
//! incoming) that is well within what threads do comfortably, and it keeps
//! [`crate::frame`] and the rest of this crate synchronous.
//!
//! # A sync spread across peers
//!
//! `specs/08` §5.6's span queue ([`crate::queue`]). Every connection whose
//! peer is ahead reserves a span of blocks no other connection has asked for
//! and fetches it; one applier thread adds finished spans to the chain in
//! height order. A connection with nothing left to reserve waits in *standby*,
//! and takes over the span the chain needs next if its owner has not delivered
//! it in time.
//!
//! # What the node does not decide
//!
//! Whether a block or a transaction is valid belongs to [`Core`], which the
//! daemon implements over its chain and pool. This module moves messages,
//! enforces the protocol, and decides whom to ban -- on the core's say-so for
//! anything about consensus. The same split as [`crate::sync::ChainTip`]: a
//! protocol fault and a consensus rejection are different problems, and a layer
//! that mixed them would blame the peer for this node's bug or the reverse.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wow_crypto::random::Rng;
use wow_crypto::types::Hash256;
use wow_types::Network;

use crate::addressbook::{AddressBook, BanTarget, PeerRecord, ANCHOR_CONNECTIONS, IP_BLOCKTIME};
use crate::frame::{encode, FrameReader};
use crate::levin::{self, command, Header, Kind};
use crate::messages::{
    self, BasicNodeData, BlockEntry, ChainEntry, ChainRequest, CoreSyncData, FluffyMissingTxs,
    HandshakeRequest, HandshakeResponse, NewBlock, NewTransactions, ObjectsRequest,
    ObjectsResponse, PeerlistEntry, PingResponse, TimedSync, TxpoolComplement,
    SUPPORT_FLAG_FLUFFY_BLOCKS,
};
use crate::queue::{self, BlockQueue, SpanInfo};
use crate::socks::{self, Proxy};
use crate::sync::BatchSize;

const LOG: &str = "net.p2p";

/// `P2P_DEFAULT_CONNECTION_TIMEOUT`.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(5_000);
/// `P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(5_000);
/// `P2P_DEFAULT_PING_CONNECTION_TIMEOUT`.
const PING_TIMEOUT: Duration = Duration::from_millis(2_000);
/// `P2P_DEFAULT_INVOKE_TIMEOUT`: a sync request unanswered this long drops the
/// peer.
const INVOKE_TIMEOUT: Duration = Duration::from_secs(120);
/// `P2P_DEFAULT_HANDSHAKE_INTERVAL`: the timed-sync period.
const TIMED_SYNC_INTERVAL: Duration = Duration::from_secs(60);
/// `P2P_IDLE_CONNECTION_KILL_INTERVAL`.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// How often a reader thread looks up from its socket.
const TICK: Duration = Duration::from_secs(1);
/// How often the maintenance thread runs.
const MAINTENANCE_TICK: Duration = Duration::from_millis(250);
/// Frames a peer may have waiting before it is too slow to keep.
const OUTBOX_CAPACITY: usize = 1_024;
/// How long before an address that failed, or that is dialled from
/// configuration, is tried again.
const RETRY_AFTER: Duration = Duration::from_secs(30);
/// Outgoing dials in flight at once.
const MAX_DIALING: usize = 8;
/// How often the peer lists are written out while running.
const SAVE_EVERY: Duration = Duration::from_secs(30 * 60);
/// `P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT`: the share of outgoing
/// connections dialled from the white list before the gray list comes first.
const WHITELIST_CONNECTIONS_PERCENT: usize = 70;
/// How often one gray-list address is checked
/// (`m_gray_peerlist_housekeeping_interval`).
const GRAY_HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(60);
/// How long the applier first waits before retrying blocks that failed through
/// no fault of their sender. The wait doubles each time the failure recurs.
const STALL_RETRY: Duration = Duration::from_secs(1);
/// The longest it waits.
const STALL_RETRY_MAX: Duration = Duration::from_secs(60);
/// The same failure again within this long is logged at debug level rather
/// than warned about again.
const STALL_QUIET: Duration = Duration::from_secs(5 * 60);

/// `CRYPTONOTE_DANDELIONPP_STEMS`.
const DANDELION_STEMS: usize = 2;
/// `CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY`, in percent.
const DANDELION_FLUFF_PERCENT: usize = 20;
/// `CRYPTONOTE_DANDELIONPP_MIN_EPOCH`.
const DANDELION_MIN_EPOCH: Duration = Duration::from_secs(10 * 60);
/// `CRYPTONOTE_DANDELIONPP_EPOCH_RANGE`.
const DANDELION_EPOCH_RANGE_SECS: u64 = 30;
/// `CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE`.
const DANDELION_EMBARGO_AVERAGE: Duration = Duration::from_secs(39);
/// `CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE`.
const DANDELION_FLUSH_AVERAGE: Duration = Duration::from_secs(5);
/// The flush average for an incoming connection in the quarter seconds the
/// C++ draws it in (`fluff_average_in`): 20.
const FLUSH_QUARTERS_IN: u64 = DANDELION_FLUSH_AVERAGE.as_secs() * 4;
/// Half that for an outgoing connection (`fluff_average_out`), as Bitcoin
/// Core halves it: the operator chose those peers.
const FLUSH_QUARTERS_OUT: u64 = FLUSH_QUARTERS_IN / 2;

/// The hard-coded mainnet seed nodes (`specs/01` §12.2). Wownero has no DNS
/// seeds, and testnet and stagenet have no seeds of their own.
pub fn seed_nodes(network: Network) -> Vec<SocketAddr> {
    match network {
        Network::Mainnet => [
            "192.99.8.110:34567",
            "37.187.74.171:34567",
            "88.99.195.15:34567",
            "158.69.60.225:34567",
            "195.94.188.201:34567",
            "45.237.33.156:34567",
        ]
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect(),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// the core seam
// ---------------------------------------------------------------------------

/// What happened to a block, as far as the network needs to know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockVerdict {
    /// On the main chain now, possibly by way of a reorganisation.
    Added,
    /// Kept as an alternative block.
    Alternative,
    AlreadyHave,
    /// The parent is unknown: ask the peer for its chain.
    Orphan,
    /// Indices into `tx_hashes` of transactions neither the message nor the
    /// pool supplied.
    MissingTxs(Vec<u64>),
    /// Refused. `ban` when the block shows the sender misbehaved; not when
    /// this node merely could not check it.
    Rejected {
        reason: String,
        ban: bool,
    },
}

/// How a transaction goes on through the network: the part of the C++'s
/// `relay_method` this layer acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRelay {
    /// Submitted to this node. Always through a stem, whatever the epoch.
    Local,
    /// Received through a stem: on through one, unless this epoch fluffs.
    Stem,
    /// To every peer.
    Fluff,
}

/// What happened to a transaction a peer sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxVerdict {
    /// Taken by the pool: new to it, or held privately until now and moved
    /// on by this copy. `how` it goes on, `None` for not at all.
    Accepted { id: Hash256, how: Option<TxRelay> },
    /// Already held publicly, or on the chain.
    Known { id: Hash256 },
    /// Refused. `ban` only for a transaction that could not be honest;
    /// relay-policy refusals never ban (`specs/08` §8.2).
    Rejected { reason: String, ban: bool },
}

/// An answer to `NOTIFY_REQUEST_CHAIN`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainReply {
    pub start_height: u64,
    pub total_height: u64,
    pub cumulative_difficulty: u128,
    pub block_ids: Vec<Hash256>,
    pub block_weights: Vec<u64>,
    pub first_block: Vec<u8>,
}

/// The chain and pool, as the network sees them.
///
/// Every method is `&self`; an implementation serialises access to its own
/// state. The node calls these from many threads at once.
pub trait Core: Send + Sync {
    /// What this node says about its chain.
    fn sync_data(&self) -> CoreSyncData;
    /// The short chain history (`specs/08` §5.2).
    fn short_history(&self) -> Vec<Hash256>;
    /// Whether a block is known, on the main chain or as an alternative.
    fn have_block(&self, id: &Hash256) -> bool;
    /// `find_blockchain_supplement`: block ids from the most recent entry of
    /// `history` this node has, or `None` when it has none of them.
    fn chain_reply(&self, history: &[Hash256]) -> Option<ChainReply>;
    /// Blocks with their transactions, and the ids this node does not have.
    fn blocks(&self, ids: &[Hash256]) -> (Vec<BlockEntry>, Vec<Hash256>);
    /// Blocks from a sync response, applied in order. Returns how many were
    /// taken -- added, or already held -- and the verdict that stopped the
    /// rest, if one did.
    fn apply_blocks(&self, blocks: &[BlockEntry]) -> (usize, Option<BlockVerdict>);
    /// A block a peer announced.
    fn new_block(&self, entry: &BlockEntry) -> BlockVerdict;
    /// A block on the main chain with only the transactions at `indices`, for
    /// a peer reconstructing a fluffy block.
    fn block_with_txs(&self, id: &Hash256, indices: &[u64]) -> Option<BlockEntry>;
    /// Transactions a peer sent, one verdict each. `fluff` is the message's
    /// `dandelionpp_fluff`: false for a stem.
    fn incoming_txs(&self, txs: &[Vec<u8>], fluff: bool) -> Vec<TxVerdict>;
    /// Public pool transactions -- fluffed or mined -- whose hashes are not in
    /// `known` (`get_complement`). Never one still private: a peer asking is
    /// not a peer the stem chose.
    fn pool_txs_except(&self, known: &HashSet<Hash256>) -> Vec<Vec<u8>>;
    /// The hashes of the public pool transactions, for this node's own
    /// complement request.
    fn pool_hashes(&self) -> Vec<Hash256>;
    /// These transactions have gone out to at least one peer: `Stem` when
    /// through a stem, `Fluff` otherwise (`on_transactions_relayed`).
    fn tx_relayed(&self, ids: &[Hash256], how: TxRelay);
    /// Pool transactions due to go out again, and how: never sent, or sent
    /// long enough ago (`tx_memory_pool::get_relayable_transactions`). Asked
    /// on every maintenance tick, so an implementation keeps its own pace; the
    /// default is a core with nothing to send again.
    fn due_for_relay(&self) -> Vec<(Hash256, Vec<u8>, TxRelay)> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

/// How the node runs.
#[derive(Clone, Debug)]
pub struct Config {
    pub network: Network,
    /// Where to accept connections; `None` for none.
    pub listen: Option<SocketAddr>,
    /// Where to accept IPv6 connections as well (`--p2p-use-ipv6`). The
    /// listener takes IPv6 only, so it can share `listen`'s port.
    pub listen_v6: Option<SocketAddr>,
    /// Refuse to start when `listen` cannot bind; `--p2p-ignore-ipv4` clears
    /// it, and then an IPv6 listener alone will do.
    pub require_ipv4: bool,
    /// The port to advertise when it differs from the listener's, as behind
    /// NAT (`--p2p-external-port`).
    pub external_port: Option<u16>,
    /// Advertise port zero, so peers do not list this node (`--hide-my-port`).
    pub hide_my_port: bool,
    /// Outgoing connections to keep (`--out-peers`).
    pub out_peers: usize,
    /// Incoming connections to allow (`--in-peers`).
    pub in_peers: usize,
    /// Connections from one address (`--max-connections-per-ip`). Loopback is
    /// exempt, so several local nodes can talk.
    pub max_connections_per_ip: usize,
    pub seed_nodes: Vec<SocketAddr>,
    /// `--add-peer`.
    pub add_peers: Vec<SocketAddr>,
    /// `--add-priority-node`: kept connected alongside the rest.
    pub priority_nodes: Vec<SocketAddr>,
    /// `--add-exclusive-node`: when any are given, the only outgoing
    /// connections.
    pub exclusive_nodes: Vec<SocketAddr>,
    /// `--allow-local-ip`.
    pub allow_local_ip: bool,
    /// `--no-sync`: serve and relay, but do not download blocks.
    pub no_sync: bool,
    /// Where the peer lists are kept between runs.
    pub state_file: Option<PathBuf>,
    /// `--ban-list`, banned indefinitely.
    pub ban_list: Vec<BanTarget>,
    /// The RPC port to advertise; zero unless the operator opted in.
    pub rpc_port: u16,
    /// `--pad-transactions`: relay transactions in messages padded to a
    /// multiple of a kilobyte, against traffic volume analysis.
    pub pad_transactions: bool,
    /// `--proxy`: dial every outgoing connection through this SOCKS5 proxy.
    ///
    /// The listener is unaffected -- a node behind a proxy can still be
    /// reached at a port it forwards -- but nothing it says advertises an
    /// address any more, and it stops pinging back incoming peers, because
    /// the address they see is the proxy's (`m_can_pingback`).
    pub proxy: Option<Proxy>,
}

impl Config {
    /// The defaults for `network`: listen on every interface at its P2P port,
    /// twelve outgoing peers, and its seed nodes.
    pub fn new(network: Network) -> Config {
        Config {
            network,
            listen: Some(SocketAddr::from((
                [0, 0, 0, 0],
                messages::default_port(network),
            ))),
            listen_v6: None,
            require_ipv4: true,
            external_port: None,
            hide_my_port: false,
            out_peers: 12,
            in_peers: 128,
            max_connections_per_ip: 1,
            seed_nodes: seed_nodes(network),
            add_peers: Vec::new(),
            priority_nodes: Vec::new(),
            exclusive_nodes: Vec::new(),
            allow_local_ip: false,
            no_sync: false,
            state_file: None,
            ban_list: Vec::new(),
            rpc_port: 0,
            pad_transactions: false,
            proxy: None,
        }
    }
}

// ---------------------------------------------------------------------------
// what the node reports
// ---------------------------------------------------------------------------

/// Where this node stands against its peers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncStatus {
    pub height: u64,
    /// The highest height any connected peer reports.
    pub target_height: u64,
    /// Caught up with the network, as far as its peers show.
    pub synchronized: bool,
    /// A sync is in progress.
    pub busy_syncing: bool,
    pub outgoing: usize,
    pub incoming: usize,
}

/// One open connection, for `get_connections`.
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub id: u64,
    pub address: SocketAddr,
    pub incoming: bool,
    pub peer_id: u64,
    pub height: u64,
    pub cumulative_difficulty: u128,
    pub state: &'static str,
    /// Seconds since the handshake.
    pub live_time: u64,
    /// Seconds since anything arrived.
    pub last_recv: u64,
    pub recv_bytes: u64,
    pub send_bytes: u64,
    pub support_flags: u32,
    pub rpc_port: u16,
    pub pruning_seed: u32,
}

// ---------------------------------------------------------------------------
// connections
// ---------------------------------------------------------------------------

const STATE_HANDSHAKE: u8 = 0;
const STATE_SYNCHRONIZING: u8 = 1;
const STATE_STANDBY: u8 = 2;
const STATE_NORMAL: u8 = 3;

fn state_name(s: u8) -> &'static str {
    match s {
        STATE_HANDSHAKE => "before_handshake",
        STATE_SYNCHRONIZING => "synchronizing",
        STATE_STANDBY => "standby",
        _ => "normal",
    }
}

struct Conn {
    id: u64,
    addr: SocketAddr,
    incoming: bool,
    peer_id: u64,
    rpc_port: u16,
    support_flags: AtomicU32,
    connected: Instant,
    sync: Mutex<CoreSyncData>,
    state: AtomicU8,
    outbox: SyncSender<Vec<u8>>,
    /// A handle on the socket, to shut it down from any thread.
    socket: TcpStream,
    closed: Arc<AtomicBool>,
    recv_bytes: AtomicU64,
    sent_bytes: Arc<AtomicU64>,
    last_recv: Mutex<Instant>,
    /// When the timed sync still unanswered went out (`m_in_timedsync`).
    timed_sync_sent: Mutex<Option<Instant>>,
}

impl Conn {
    fn send(&self, frame: Vec<u8>) -> bool {
        if self.closed.load(Ordering::Relaxed) {
            return false;
        }
        match self.outbox.try_send(frame) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                wow_log::debug!(LOG, "{}: outbox full, disconnecting", self.addr);
                self.close();
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    fn notify(&self, cmd: u32, body: &[u8]) -> bool {
        self.send(encode(&Header::notification(cmd, body.len() as u64), body))
    }

    fn request(&self, cmd: u32, body: &[u8]) -> bool {
        self.send(encode(&Header::request(cmd, body.len() as u64), body))
    }

    /// A response. The C++ puts its handler's result in `return_code`, which
    /// is 1 on success.
    fn respond(&self, cmd: u32, code: i32, body: &[u8]) -> bool {
        self.send(encode(
            &Header::response(cmd, body.len() as u64, code),
            body,
        ))
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self.socket.shutdown(Shutdown::Both);
        }
    }

    fn state(&self) -> u8 {
        self.state.load(Ordering::Relaxed)
    }

    fn set_state(&self, s: u8) {
        self.state.store(s, Ordering::Relaxed);
    }

    fn peer_sync(&self) -> CoreSyncData {
        lock(&self.sync).clone()
    }

    fn fluffy(&self) -> bool {
        self.support_flags.load(Ordering::Relaxed) & SUPPORT_FLAG_FLUFFY_BLOCKS != 0
    }
}

/// Why a connection ended from this side.
struct Fault {
    reason: String,
    ban: bool,
}

impl Fault {
    fn drop(reason: impl Into<String>) -> Fault {
        Fault {
            reason: reason.into(),
            ban: false,
        }
    }

    fn ban(reason: impl Into<String>) -> Fault {
        Fault {
            reason: reason.into(),
            ban: true,
        }
    }
}

/// What this connection has asked its peer for, and when.
enum Pending {
    Chain(Instant),
    /// A span of the block queue, reserved at `start`.
    Objects {
        sent: Instant,
        start: u64,
        ids: Vec<Hash256>,
    },
}

impl Pending {
    fn sent(&self) -> Instant {
        match self {
            Pending::Chain(t) | Pending::Objects { sent: t, .. } => *t,
        }
    }
}

/// One connection's protocol state, owned by its reader thread.
struct Proto {
    pending: Option<Pending>,
    /// The block ids from the peer's last chain entry that this node does not
    /// have yet, and the height of the first.
    chain: Vec<Hash256>,
    chain_start: u64,
    /// The queue generation `chain` was read against.
    generation: u64,
    batch: BatchSize,
    /// When a peer whose chain entry offered nothing new may be asked again.
    chain_again_at: Instant,
    next_housekeeping: Instant,
    /// The addresses this peer has been given in a peer list
    /// (`sent_addresses` in the C++'s connection context).
    sent_addresses: HashSet<SocketAddr>,
}

impl Proto {
    fn new(sent_addresses: HashSet<SocketAddr>) -> Proto {
        let now = Instant::now();
        Proto {
            pending: None,
            chain: Vec::new(),
            chain_start: 0,
            generation: 0,
            batch: BatchSize::default(),
            chain_again_at: now,
            next_housekeeping: now,
            sent_addresses,
        }
    }
}

// ---------------------------------------------------------------------------
// relay state
// ---------------------------------------------------------------------------

/// Transactions with their ids, going to a peer together.
type TxBatch = Vec<(Hash256, Vec<u8>)>;

struct Relay {
    epoch_ends: Instant,
    /// Whether this epoch fluffs what arrives through a stem, rather than
    /// passing it on through one (`zone::fluffing`). Drawn once an epoch, as
    /// the C++ draws it: a per-transaction draw fluffed a fifth of every
    /// stem, where Dandelion++ has a fifth of the nodes fluff everything for
    /// ten minutes.
    fluffing: bool,
    /// This epoch's stems, and which one each source is sent to.
    stems: StemMap,
    /// Stem transactions waiting to be seen fluffed, with their deadline.
    embargo: HashMap<Hash256, (Instant, Vec<u8>)>,
    /// Fluff transactions waiting for each connection's next flush.
    queued: HashMap<u64, (Instant, TxBatch)>,
}

/// `net::dandelionpp::connection_map`: this epoch's stem connections, and the
/// stem each source's transactions go to.
///
/// The mapping is sticky. Every transaction from one peer -- and every one
/// this node originates, whose source is `None` -- takes the same stem for
/// the whole epoch, and a new source takes the least used, so the stems
/// split the sources between them. A transaction's path therefore says
/// nothing about it that its source does not, where choosing afresh for each
/// one let a stem peer that saw several correlate them. A stem that goes away
/// leaves its slot empty; [`StemMap::update`] refills that slot alone, and a
/// source mapped to it is moved on the next time it sends.
#[derive(Debug, Default)]
struct StemMap {
    /// `out_mapping_`: the connection in each stem slot, `None` where one
    /// went away.
    out: Vec<Option<u64>>,
    /// `in_mapping_`: the slot each source is sent to.
    sources: HashMap<Option<u64>, usize>,
    /// `usage_count_`: how many sources each slot has, one entry a stem.
    usage: Vec<usize>,
}

impl StemMap {
    /// `connection_map(out_connections, stems)`: `stems` of `connections`,
    /// chosen at random.
    fn new(
        mut connections: Vec<u64>,
        stems: usize,
        rand: &mut impl FnMut(usize) -> usize,
    ) -> StemMap {
        if stems < connections.len() {
            for i in 0..stems {
                let j = i + rand(connections.len() - i);
                connections.swap(i, j);
            }
            connections.truncate(stems);
        } else {
            for i in (1..connections.len()).rev() {
                let j = rand(i + 1);
                connections.swap(i, j);
            }
        }
        StemMap {
            out: connections.into_iter().map(Some).collect(),
            sources: HashMap::new(),
            usage: vec![0; stems],
        }
    }

    /// `connection_map::update`: merge in the connections a stem may use
    /// now. A slot whose connection is not among them is emptied, and empty
    /// slots -- or ones never filled, for a map made with fewer connections
    /// than stems -- take a connection not already a stem. Returns whether
    /// anything changed.
    fn update(&mut self, mut current: Vec<u64>, rand: &mut impl FnMut(usize) -> usize) -> bool {
        current.sort_unstable();
        let mut replace = false;
        for slot in &mut self.out {
            match slot.map(|id| current.binary_search(&id)) {
                // Already a stem, so not a candidate for another slot.
                Some(Ok(at)) => {
                    current.remove(at);
                }
                _ => {
                    *slot = None;
                    replace = true;
                }
            }
        }
        if !replace && self.out.len() == self.usage.len() {
            return false;
        }
        let existing = self.out.len();
        for i in 0..self.usage.len() {
            if current.is_empty() {
                break;
            }
            let grow = self.out.len() <= i;
            if grow || self.out[i].is_none() {
                let last = current.len() - 1;
                let pick = rand(current.len());
                current.swap(last, pick);
                let id = current.pop();
                if grow {
                    self.out.push(id);
                } else {
                    self.out[i] = id;
                }
            }
        }
        replace || existing < self.out.len()
    }

    /// `connection_map::get_stem`: the stem for transactions from `source`,
    /// or `None` when no stem is left.
    fn get_stem(
        &mut self,
        source: Option<u64>,
        rand: &mut impl FnMut(usize) -> usize,
    ) -> Option<u64> {
        let slot = match self.sources.get(&source).copied() {
            Some(slot) if self.out[slot].is_some() => slot,
            mapped => {
                // Never mapped, or mapped to a stem that has gone.
                if let Some(old) = mapped {
                    self.usage[old] = self.usage[old].saturating_sub(1);
                }
                let Some(slot) = self.least_used(rand) else {
                    self.sources.remove(&source);
                    return None;
                };
                self.sources.insert(source, slot);
                self.usage[slot] += 1;
                slot
            }
        };
        self.out[slot]
    }

    /// `select_stem`: a live slot with the fewest sources, at random among
    /// equals.
    fn least_used(&self, rand: &mut impl FnMut(usize) -> usize) -> Option<usize> {
        let mut lowest = usize::MAX;
        let mut choices = Vec::new();
        for (i, slot) in self.out.iter().enumerate() {
            if slot.is_none() {
                continue;
            }
            match self.usage[i].cmp(&lowest) {
                std::cmp::Ordering::Less => {
                    lowest = self.usage[i];
                    choices.clear();
                    choices.push(i);
                }
                std::cmp::Ordering::Equal => choices.push(i),
                std::cmp::Ordering::Greater => {}
            }
        }
        match choices.len() {
            0 => None,
            1 => Some(choices[0]),
            n => Some(choices[rand(n)]),
        }
    }
}

/// A Poisson-distributed count with the given mean, from uniform draws in
/// (0, 1]: Knuth's method, multiplying draws until the product falls to
/// e^-mean.
///
/// The C++'s Dandelion++ timers are `std::poisson_distribution` in whole units
/// (`crypto::random_poisson_duration`): seconds for an embargo, quarter
/// seconds for a flush. An exponential delay with the same mean, which this
/// used, spreads far wider -- a fifth of the embargoes under 9 s where the
/// C++'s almost never go under 27 -- and the spread is what an observer
/// times. At the means used here it takes as many draws as the mean.
fn poisson(mean: u64, mut uniform: impl FnMut() -> f64) -> u64 {
    let floor = (-(mean as f64)).exp();
    let mut product = uniform();
    let mut k = 0;
    while product > floor {
        k += 1;
        product *= uniform();
    }
    k
}

/// Sorted by blob, each once: the order a peer is sent transactions in must
/// not be the order this node received them (`fluff_flush`).
fn flush_order(txs: &mut TxBatch) {
    txs.sort_by(|(_, a), (_, b)| a.cmp(b));
    txs.dedup_by(|(_, a), (_, b)| a == b);
}

// ---------------------------------------------------------------------------
// the node
// ---------------------------------------------------------------------------

struct Shared {
    cfg: Config,
    core: Arc<dyn Core>,
    peer_id: u64,
    my_port: u32,
    book: Mutex<AddressBook>,
    conns: Mutex<HashMap<u64, Arc<Conn>>>,
    next_id: AtomicU64,
    /// The spans of the sync in flight (`specs/08` §5.6).
    queue: Mutex<BlockQueue>,
    /// Bumped when the queue is thrown away, so connections read their peers'
    /// chains afresh.
    generation: AtomicU64,
    /// Set, with a notification, when a span arrives for the applier.
    apply_wake: (Mutex<bool>, Condvar),
    ever_synced: AtomicBool,
    /// Whether the next connection to settle once the node is synchronised
    /// asks its peer for the pool's complement (`m_ask_for_txpool_complement`):
    /// set at start, and again when the last connection goes.
    ask_complement: AtomicBool,
    stopping: AtomicBool,
    rng: Mutex<Rng>,
    relay: Mutex<Relay>,
    out_peers: AtomicUsize,
    in_peers: AtomicUsize,
    dialing: Mutex<HashSet<SocketAddr>>,
    tried: Mutex<HashMap<SocketAddr, Instant>>,
}

/// A running peer-to-peer node.
pub struct Node {
    shared: Arc<Shared>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    local_addr: Option<SocketAddr>,
    local_addr_v6: Option<SocketAddr>,
}

impl Node {
    /// Bind the listener, load the peer lists, and start connecting.
    ///
    /// `rng` must be seeded from the operating system: the peer id comes from
    /// it, and so does every Dandelion++ choice.
    pub fn start(cfg: Config, core: Arc<dyn Core>, mut rng: Rng) -> Result<Node, String> {
        let (listener, listener_v6) =
            crate::net::listen_dual(cfg.listen, cfg.listen_v6, cfg.require_ipv4, "peers")?;
        let local_addr = listener.as_ref().and_then(|l| l.local_addr().ok());
        let local_addr_v6 = listener_v6.as_ref().and_then(|l| l.local_addr().ok());
        // A peer pings back the advertised port at whichever address it
        // reached this node on. The C++ advertises its IPv4 listener's; with
        // only an IPv6 listener, that one's is the port there is.
        let my_port = match (
            cfg.hide_my_port,
            cfg.external_port,
            local_addr.or(local_addr_v6),
        ) {
            (true, _, _) => 0,
            (false, Some(p), _) => u32::from(p),
            (false, None, Some(a)) => u32::from(a.port()),
            (false, None, None) => 0,
        };

        let mut id = [0u8; 8];
        rng.fill(&mut id);

        let mut book = match &cfg.state_file {
            Some(p) => AddressBook::load(p, cfg.allow_local_ip).unwrap_or_else(|e| {
                wow_log::warn!(LOG, "starting with empty peer lists: {e}");
                AddressBook::new(cfg.allow_local_ip)
            }),
            None => AddressBook::new(cfg.allow_local_ip),
        };
        for addr in &cfg.add_peers {
            // A random id, as the C++ gives each `--add-peer` entry
            // (`crypto::rand<uint64_t>()`). The id goes out in peer lists,
            // and zero is an id no node has.
            let mut peer_id = [0u8; 8];
            rng.fill(&mut peer_id);
            book.add_white(
                PeerRecord {
                    addr: *addr,
                    id: u64::from_le_bytes(peer_id),
                    last_seen: 0,
                    pruning_seed: 0,
                    rpc_port: 0,
                },
                false,
            );
        }
        for target in &cfg.ban_list {
            book.ban(*target, u64::MAX, 0);
        }

        let shared = Arc::new(Shared {
            out_peers: AtomicUsize::new(cfg.out_peers),
            in_peers: AtomicUsize::new(cfg.in_peers),
            cfg,
            core,
            peer_id: u64::from_le_bytes(id),
            my_port,
            book: Mutex::new(book),
            conns: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            queue: Mutex::new(BlockQueue::new()),
            generation: AtomicU64::new(0),
            apply_wake: (Mutex::new(false), Condvar::new()),
            ever_synced: AtomicBool::new(false),
            ask_complement: AtomicBool::new(true),
            stopping: AtomicBool::new(false),
            rng: Mutex::new(rng),
            relay: Mutex::new(Relay {
                epoch_ends: Instant::now(),
                fluffing: false,
                stems: StemMap::default(),
                embargo: HashMap::new(),
                queued: HashMap::new(),
            }),
            dialing: Mutex::new(HashSet::new()),
            tried: Mutex::new(HashMap::new()),
        });

        let mut threads = Vec::new();
        if let Some(proxy) = &shared.cfg.proxy {
            wow_log::info!(LOG, "dialling peers through the proxy at {proxy}");
        }
        for listener in [listener, listener_v6].into_iter().flatten() {
            if let Ok(a) = listener.local_addr() {
                wow_log::info!(LOG, "listening for peers on {a}");
            }
            let s = shared.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("p2p-listen".into())
                    .spawn(move || accept_loop(s, listener))
                    .map_err(|e| format!("cannot start the listener: {e}"))?,
            );
        }
        let s = shared.clone();
        threads.push(
            std::thread::Builder::new()
                .name("p2p-maintain".into())
                .spawn(move || maintenance(s))
                .map_err(|e| format!("cannot start the connection manager: {e}"))?,
        );
        let s = shared.clone();
        threads.push(
            std::thread::Builder::new()
                .name("p2p-apply".into())
                .spawn(move || apply_loop(s))
                .map_err(|e| format!("cannot start the block applier: {e}"))?,
        );

        Ok(Node {
            shared,
            threads: Mutex::new(threads),
            local_addr,
            local_addr_v6,
        })
    }

    /// The listener's address, when there is one.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// The IPv6 listener's address, when there is one.
    pub fn local_addr_v6(&self) -> Option<SocketAddr> {
        self.local_addr_v6
    }

    pub fn peer_id(&self) -> u64 {
        self.shared.peer_id
    }

    /// Close every connection, remember the outgoing ones as anchors, and save
    /// the peer lists.
    pub fn stop(&self) {
        if self.shared.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        let conns: Vec<Arc<Conn>> = lock(&self.shared.conns).values().cloned().collect();
        {
            let mut book = lock(&self.shared.book);
            book.clear_anchors();
            for c in conns.iter().filter(|c| !c.incoming) {
                book.add_anchor(PeerRecord {
                    addr: c.addr,
                    id: c.peer_id,
                    last_seen: unix_now() as i64,
                    pruning_seed: c.peer_sync().pruning_seed,
                    rpc_port: c.rpc_port,
                });
            }
        }
        for c in &conns {
            c.close();
        }
        for t in lock(&self.threads).drain(..) {
            let _ = t.join();
        }
        self.shared.save_state();
    }

    pub fn sync_status(&self) -> SyncStatus {
        self.shared.sync_status()
    }

    pub fn connections(&self) -> Vec<ConnectionInfo> {
        let now = Instant::now();
        let mut out: Vec<ConnectionInfo> = lock(&self.shared.conns)
            .values()
            .map(|c| {
                let sync = c.peer_sync();
                ConnectionInfo {
                    id: c.id,
                    address: c.addr,
                    incoming: c.incoming,
                    peer_id: c.peer_id,
                    height: sync.current_height,
                    cumulative_difficulty: sync.cumulative_difficulty,
                    state: state_name(c.state()),
                    live_time: now.duration_since(c.connected).as_secs(),
                    last_recv: now.duration_since(*lock(&c.last_recv)).as_secs(),
                    recv_bytes: c.recv_bytes.load(Ordering::Relaxed),
                    send_bytes: c.sent_bytes.load(Ordering::Relaxed),
                    support_flags: c.support_flags.load(Ordering::Relaxed),
                    rpc_port: c.rpc_port,
                    pruning_seed: sync.pruning_seed,
                }
            })
            .collect();
        out.sort_by_key(|c| c.id);
        out
    }

    /// `(white, gray)`.
    pub fn peer_lists(&self) -> (Vec<PeerRecord>, Vec<PeerRecord>) {
        let book = lock(&self.shared.book);
        (book.white(), book.gray())
    }

    /// The bans in force, with seconds left.
    pub fn bans(&self) -> Vec<(BanTarget, u64)> {
        lock(&self.shared.book).bans(unix_now())
    }

    /// Ban for `seconds`, closing any connection the ban covers.
    pub fn ban(&self, target: BanTarget, seconds: u64) {
        self.shared.ban(target, seconds);
    }

    pub fn unban(&self, target: &BanTarget) -> bool {
        lock(&self.shared.book).unban(target)
    }

    pub fn out_peers(&self) -> usize {
        self.shared.out_peers.load(Ordering::Relaxed)
    }

    pub fn in_peers(&self) -> usize {
        self.shared.in_peers.load(Ordering::Relaxed)
    }

    /// Change the outgoing target; surplus connections are closed.
    pub fn set_out_peers(&self, n: usize) {
        self.shared.out_peers.store(n, Ordering::Relaxed);
        self.shared.trim_connections(false, n);
    }

    /// Change the incoming limit; surplus connections are closed.
    pub fn set_in_peers(&self, n: usize) {
        self.shared.in_peers.store(n, Ordering::Relaxed);
        self.shared.trim_connections(true, n);
    }

    /// Send a transaction this node originated. It starts in the Dandelion++
    /// stem phase (`specs/08` §7.2).
    pub fn relay_transaction(&self, id: Hash256, blob: Vec<u8>) {
        self.shared.relay_txs(None, vec![(id, blob)], TxRelay::Local);
    }

    /// Send a transaction the network already has to every peer, as the
    /// `relay_tx` RPC does for a public one: stemming it again would only
    /// look like a loop to the stem.
    pub fn fluff_transaction(&self, id: Hash256, blob: Vec<u8>) {
        self.shared.relay_txs(None, vec![(id, blob)], TxRelay::Fluff);
    }

    /// Announce a block this node added itself, such as one submitted over
    /// RPC.
    pub fn relay_block(&self, entry: &BlockEntry) {
        self.shared.relay_block(entry, None);
    }

    /// Connections that have completed a handshake.
    pub fn connection_count(&self) -> usize {
        lock(&self.shared.conns).len()
    }

    /// Connections in the normal state: synchronised, and so the ones a
    /// transaction or a block is sent to.
    pub fn normal_connection_count(&self) -> usize {
        self.shared
            .snapshot()
            .iter()
            .filter(|c| c.state() == STATE_NORMAL)
            .count()
    }

    /// The block queue's spans, lowest first, for `sync_info`.
    pub fn spans(&self) -> Vec<SpanInfo> {
        lock(&self.shared.queue).info()
    }

    /// The block queue drawn as `sync_info`'s `overview`.
    pub fn queue_overview(&self) -> String {
        let height = self.shared.core.sync_data().current_height;
        lock(&self.shared.queue).overview(height)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Shared {
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

    /// A [`poisson`] count with the given mean, drawn from the node's CSPRNG
    /// as `crypto::random_poisson_duration` draws from `crypto::random_device`.
    fn poisson_draw(&self, mean: u64) -> u64 {
        let mut rng = lock(&self.rng);
        poisson(mean, || {
            let mut b = [0u8; 8];
            rng.fill(&mut b);
            // 53 random bits, shifted off zero: a draw in (0, 1].
            ((u64::from_le_bytes(b) >> 11) + 1) as f64 / (1u64 << 53) as f64
        })
    }

    /// An embargo (`tx_pool.cpp`'s `embargo_duration`): whole seconds, Poisson
    /// about `CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE`.
    fn embargo(&self) -> Duration {
        Duration::from_secs(self.poisson_draw(DANDELION_EMBARGO_AVERAGE.as_secs()))
    }

    /// The wait before a connection's first queued fluff goes (`fluff_notify`):
    /// quarter seconds, Poisson about 5 s for an incoming connection and 2.5 s
    /// for an outgoing one.
    fn flush_delay(&self, incoming: bool) -> Duration {
        let mean = if incoming {
            FLUSH_QUARTERS_IN
        } else {
            FLUSH_QUARTERS_OUT
        };
        Duration::from_millis(250 * self.poisson_draw(mean))
    }

    /// `network_zone::m_can_pingback`: whether a peer could reach this node
    /// at the address the connection came from.
    ///
    /// False behind `--proxy`, where the address a peer sees is the proxy's.
    /// A node that cannot be pinged back advertises no port and no RPC port,
    /// and does not ping back the peers that reach it.
    fn can_pingback(&self) -> bool {
        self.cfg.proxy.is_none()
    }

    fn node_data(&self) -> BasicNodeData {
        let pingback = self.can_pingback();
        BasicNodeData {
            network_id: messages::network_id(self.cfg.network),
            peer_id: self.peer_id,
            my_port: if pingback { self.my_port } else { 0 },
            rpc_port: if pingback { self.cfg.rpc_port } else { 0 },
            rpc_credits_per_hash: 0,
            support_flags: SUPPORT_FLAG_FLUFFY_BLOCKS,
        }
    }

    fn handshake_peers(&self) -> Vec<messages::PeerlistEntry> {
        let book = lock(&self.book);
        let mut rand = |n: usize| self.rand_below(n);
        book.handshake_peers(messages::MAX_PEERS_IN_HANDSHAKE, &mut rand)
    }

    fn snapshot(&self) -> Vec<Arc<Conn>> {
        lock(&self.conns).values().cloned().collect()
    }

    fn counts(&self) -> (usize, usize) {
        let conns = lock(&self.conns);
        let incoming = conns.values().filter(|c| c.incoming).count();
        (conns.len() - incoming, incoming)
    }

    /// `needs_new_sync_connections`: not known to be caught up, and short of
    /// outgoing connections.
    ///
    /// The C++ compares its height with the target height peers have given it
    /// over time. This node goes by the heights its connected peers report,
    /// and with no peer to report one it is not known to be caught up.
    fn needs_new_sync_connections(&self) -> bool {
        let conns = self.snapshot();
        let target = conns
            .iter()
            .map(|c| c.peer_sync().current_height)
            .max()
            .unwrap_or(0);
        if target != 0 && target <= self.core.sync_data().current_height {
            return false;
        }
        let outgoing = conns.iter().filter(|c| !c.incoming).count();
        outgoing < self.out_peers.load(Ordering::Relaxed)
    }

    fn save_state(&self) {
        if let Some(path) = &self.cfg.state_file {
            if let Err(e) = lock(&self.book).save(path) {
                wow_log::warn!(LOG, "cannot save the peer lists to {}: {e}", path.display());
            }
        }
    }

    fn ban(&self, target: BanTarget, seconds: u64) {
        lock(&self.book).ban(target, seconds, unix_now());
        for c in self.snapshot() {
            if target.covers(c.addr.ip()) {
                c.close();
            }
        }
        wow_log::info!(LOG, "banned {target} for {seconds} s");
    }

    fn trim_connections(&self, incoming: bool, keep: usize) {
        let mut matching: Vec<Arc<Conn>> = self
            .snapshot()
            .into_iter()
            .filter(|c| c.incoming == incoming)
            .collect();
        // Newest go first, so long-lived connections survive.
        matching.sort_by_key(|c| std::cmp::Reverse(c.connected));
        let surplus = matching.len().saturating_sub(keep);
        for c in matching.into_iter().take(surplus) {
            c.close();
        }
    }

    fn sync_status(&self) -> SyncStatus {
        let ours = self.core.sync_data();
        let conns = self.snapshot();
        let incoming = conns.iter().filter(|c| c.incoming).count();
        let best = conns
            .iter()
            .map(|c| c.peer_sync().current_height)
            .max()
            .unwrap_or(0);
        let busy = !lock(&self.queue).is_empty()
            || conns
                .iter()
                .any(|c| matches!(c.state(), STATE_SYNCHRONIZING | STATE_STANDBY));
        // One block of slack: a peer that has just announced a block this
        // node is still verifying does not make it unsynchronised.
        let synchronized = self.ever_synced.load(Ordering::Relaxed)
            && !conns.is_empty()
            && !busy
            && best <= ours.current_height + 1;
        SyncStatus {
            height: ours.current_height,
            target_height: best.max(ours.current_height),
            synchronized,
            busy_syncing: busy,
            outgoing: conns.len() - incoming,
            incoming,
        }
    }

    // ---------------------------------------------------------- block queue

    fn wake_applier(&self) {
        let (flag, cv) = &self.apply_wake;
        *lock(flag) = true;
        cv.notify_one();
    }

    /// Throw the queue away: its spans no longer fit the chain.
    fn flush_queue(&self) {
        lock(&self.queue).clear();
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    // ---------------------------------------------------------------- relay

    /// Pass transactions on (`specs/08` §7; `levin_notify.cpp`'s `send_txs`).
    ///
    /// What this node originated always goes through a stem; what arrived
    /// through one goes on through one in a stem epoch, and is fluffed in a
    /// fluff epoch. A stem send is one message to the stem the epoch maps
    /// the sender to, after which each transaction waits under an embargo --
    /// if it has not been seen fluffed when the embargo ends, this node
    /// fluffs it. A fluff is queued to every other peer and flushed on each
    /// one's Poisson timer.
    fn relay_txs(&self, from: Option<u64>, txs: TxBatch, how: TxRelay) {
        let own = how == TxRelay::Local;
        // This node's own transaction already under an embargo has just gone
        // through a stem, sent by another thread that read the pool a moment
        // before this one: the RPC and the pool's re-relay both reach here.
        // Sending it again would show the stem peer what looks like a loop,
        // and a loop is fluffed.
        let txs: TxBatch = if own {
            let relay = lock(&self.relay);
            txs.into_iter()
                .filter(|(id, _)| !relay.embargo.contains_key(id))
                .collect()
        } else {
            txs
        };
        if txs.is_empty() {
            return;
        }
        let stem = match how {
            TxRelay::Local => true,
            TxRelay::Stem => !lock(&self.relay).fluffing,
            TxRelay::Fluff => false,
        };
        if stem {
            // As `dandelionpp_notify` tries it: the stem, and when that finds
            // no connection, the map mended from the connections there are now
            // and the stem again -- twice, before giving up and fluffing. With
            // the stems mended only on the next tick, a transaction submitted
            // just after a stem went, or just after the first peer arrived,
            // was fluffed straight from this node.
            for _ in 0..2 {
                if self.stem(from, &txs, own) {
                    return;
                }
                let candidates = self.stem_candidates();
                let mut rand = |n: usize| self.rand_below(n);
                lock(&self.relay).stems.update(candidates, &mut rand);
            }
            wow_log::debug!(
                LOG,
                "no Dandelion++ stem for {} transaction(s); fluffing",
                txs.len()
            );
        }
        self.fluff(from, txs);
    }

    /// Send `txs` through the stem the epoch's map gives `from`, together,
    /// and put them under an embargo. Returns whether they went -- or, when
    /// they are this node's `own`, whether each is under an embargo now.
    ///
    /// The relay lock is held from choosing the stem to recording the
    /// embargo, so two threads relaying the same transaction of this node's
    /// cannot both send it.
    fn stem(&self, from: Option<u64>, txs: &TxBatch, own: bool) -> bool {
        let mut relay = lock(&self.relay);
        let fresh: TxBatch = txs
            .iter()
            .filter(|(id, _)| !own || !relay.embargo.contains_key(id))
            .cloned()
            .collect();
        if fresh.is_empty() {
            return true;
        }
        let mut rand = |n: usize| self.rand_below(n);
        let conn = relay
            .stems
            .get_stem(from, &mut rand)
            .and_then(|id| lock(&self.conns).get(&id).cloned())
            .filter(|c| c.state() == STATE_NORMAL);
        let Some(conn) = conn else {
            return false;
        };
        let blobs = fresh.iter().map(|(_, blob)| blob.clone()).collect();
        let body = self.tx_message(blobs, false);
        if !conn.notify(command::NEW_TRANSACTIONS, &body) {
            return false;
        }
        let now = Instant::now();
        for (id, blob) in &fresh {
            let deadline = now + self.embargo();
            relay.embargo.insert(*id, (deadline, blob.clone()));
        }
        drop(relay);
        let ids: Vec<Hash256> = fresh.iter().map(|(id, _)| *id).collect();
        self.core.tx_relayed(&ids, TxRelay::Stem);
        true
    }

    /// Queue `txs` to every synchronised peer but `except` (`fluff_notify`).
    fn fluff(&self, except: Option<u64>, txs: TxBatch) {
        let targets: Vec<(u64, bool)> = self
            .snapshot()
            .iter()
            .filter(|c| Some(c.id) != except && c.state() == STATE_NORMAL)
            .map(|c| (c.id, c.incoming))
            .collect();
        let ids: Vec<Hash256> = txs.iter().map(|(id, _)| *id).collect();
        let mut relay = lock(&self.relay);
        for id in &ids {
            relay.embargo.remove(id);
        }
        if targets.is_empty() {
            // Sent to nobody, so not marked relayed: the pool offers them
            // again ([`Core::due_for_relay`]) until a synchronised peer can
            // take them. Marking them here left them in the pool for good.
            wow_log::debug!(
                LOG,
                "no synchronised peer to send {} transaction(s) to; they wait in the pool",
                ids.len()
            );
            return;
        }
        let now = Instant::now();
        for (t, incoming) in targets {
            // The timer starts with the first transaction a connection's
            // queue takes, and the rest wait for it.
            let queue = relay
                .queued
                .entry(t)
                .or_insert_with(|| (now + self.flush_delay(incoming), Vec::new()));
            queue.1.extend(txs.iter().cloned());
        }
        drop(relay);
        self.core.tx_relayed(&ids, TxRelay::Fluff);
    }

    /// A `NOTIFY_NEW_TRANSACTIONS` body for a relay, padded with
    /// `--pad-transactions` as `make_tx_message` pads it. Only relays are: an
    /// answer to a complement request goes out as it is, as the C++ sends it.
    fn tx_message(&self, txs: Vec<Vec<u8>>, fluff: bool) -> Vec<u8> {
        let message = NewTransactions {
            txs,
            dandelionpp_fluff: fluff,
        };
        if self.cfg.pad_transactions {
            message.to_padded_bytes()
        } else {
            message.to_bytes()
        }
    }

    /// The outgoing connections a stem may use (`get_out_connections`):
    /// synchronised ones.
    fn stem_candidates(&self) -> Vec<u64> {
        self.snapshot()
            .iter()
            .filter(|c| !c.incoming && c.state() == STATE_NORMAL)
            .map(|c| c.id)
            .collect()
    }

    fn relay_tick(&self) {
        let now = Instant::now();

        // A new epoch (`start_epoch`): new stems from the outgoing
        // connections, and a new draw of whether it fluffs. Between epochs a
        // stem that went away is replaced when a send finds it gone, and only
        // it ([`Shared::relay_txs`]); replacing both and starting the epoch
        // over whenever one stem dropped reshuffled every source's path.
        if now >= lock(&self.relay).epoch_ends {
            let candidates = self.stem_candidates();
            let mut rand = |n: usize| self.rand_below(n);
            let fluffing = rand(100) < DANDELION_FLUFF_PERCENT;
            let stems = StemMap::new(candidates, DANDELION_STEMS, &mut rand);
            let epoch = DANDELION_MIN_EPOCH
                + Duration::from_secs(self.rand_u64() % DANDELION_EPOCH_RANGE_SECS);
            let mut relay = lock(&self.relay);
            relay.fluffing = fluffing;
            relay.stems = stems;
            relay.epoch_ends = now + epoch;
            wow_log::debug!(
                LOG,
                "a new Dandelion++ epoch: {}",
                if fluffing { "fluff" } else { "stem" }
            );
        }

        // Embargoes that ran out without the transaction coming back fluffed.
        let expired: TxBatch = {
            let mut relay = lock(&self.relay);
            let ids: Vec<Hash256> = relay
                .embargo
                .iter()
                .filter(|(_, (deadline, _))| *deadline <= now)
                .map(|(id, _)| *id)
                .collect();
            ids.into_iter()
                .filter_map(|id| relay.embargo.remove(&id).map(|(_, blob)| (id, blob)))
                .collect()
        };
        self.relay_txs(None, expired, TxRelay::Fluff);

        // Flushes that are due.
        let due: Vec<(u64, TxBatch)> = {
            let mut relay = lock(&self.relay);
            let ids: Vec<u64> = relay
                .queued
                .iter()
                .filter(|(_, (at, _))| *at <= now)
                .map(|(id, _)| *id)
                .collect();
            ids.into_iter()
                .filter_map(|id| relay.queued.remove(&id).map(|(_, txs)| (id, txs)))
                .collect()
        };
        if !due.is_empty() {
            let conns = lock(&self.conns);
            for (id, mut txs) in due {
                if let Some(c) = conns.get(&id) {
                    flush_order(&mut txs);
                    let blobs = txs.into_iter().map(|(_, b)| b).collect();
                    c.notify(command::NEW_TRANSACTIONS, &self.tx_message(blobs, true));
                }
            }
        }

        // A transaction sent once can still have reached no one: a peer that
        // dropped it, a connection that closed before its flush. The pool says
        // what is due to go again, as `relay_txpool_transactions` asks it in
        // the C++, and they go together: those submitted here and never
        // stemmed through the stem, the rest as fluff.
        let mut local = TxBatch::new();
        let mut public = TxBatch::new();
        for (id, blob, how) in self.core.due_for_relay() {
            match how {
                TxRelay::Local => local.push((id, blob)),
                TxRelay::Stem | TxRelay::Fluff => public.push((id, blob)),
            }
        }
        self.relay_txs(None, local, TxRelay::Local);
        self.relay_txs(None, public, TxRelay::Fluff);
    }

    /// Announce a block to every synchronised peer but `except`: fluffy, with
    /// no transactions, to peers that reconstruct; whole to the rest
    /// (`specs/08` §6).
    fn relay_block(&self, entry: &BlockEntry, except: Option<u64>) {
        let height = self.core.sync_data().current_height;
        let fluffy = NewBlock {
            entry: BlockEntry {
                block: entry.block.clone(),
                txs: Vec::new(),
                block_weight: entry.block_weight,
            },
            current_blockchain_height: height,
        }
        .to_bytes();
        let full = NewBlock {
            entry: entry.clone(),
            current_blockchain_height: height,
        }
        .to_bytes();
        for c in self.snapshot() {
            if Some(c.id) == except || c.state() != STATE_NORMAL {
                continue;
            }
            if c.fluffy() {
                c.notify(command::NEW_FLUFFY_BLOCK, &fluffy);
            } else {
                c.notify(command::NEW_BLOCK, &full);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// threads
// ---------------------------------------------------------------------------

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic elsewhere while holding a lock poisons it; the data is still
    // usable, and a node that stopped serving every peer over one panic would
    // be worse off.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn accept_loop(shared: Arc<Shared>, listener: TcpListener) {
    if listener.set_nonblocking(true).is_err() {
        wow_log::error!(
            LOG,
            "cannot poll the peer listener; not accepting connections"
        );
        return;
    }
    while !shared.stopping() {
        match listener.accept() {
            Ok((stream, addr)) => {
                let s = shared.clone();
                let _ = std::thread::Builder::new()
                    .name("p2p-in".into())
                    .spawn(move || inbound(s, stream, addr));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                wow_log::debug!(LOG, "accept failed: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Read one message within `timeout`.
fn read_one(
    stream: &mut TcpStream,
    reader: &mut FrameReader,
    timeout: Duration,
) -> Result<(Header, Vec<u8>), String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + timeout;
    loop {
        match reader.poll(stream) {
            Ok(Some(m)) => return Ok(m),
            Ok(None) if Instant::now() >= deadline => return Err("timed out".into()),
            Ok(None) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn write_frame(stream: &mut TcpStream, header: Header, body: &[u8]) -> std::io::Result<()> {
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.write_all(&encode(&header, body))
}

fn inbound(shared: Arc<Shared>, mut stream: TcpStream, addr: SocketAddr) {
    let _ = stream.set_nonblocking(false);
    let now = unix_now();
    if lock(&shared.book).is_banned(addr.ip(), now) {
        return;
    }
    let (_, incoming) = shared.counts();
    if incoming >= shared.in_peers.load(Ordering::Relaxed) {
        return;
    }
    if !addr.ip().is_loopback() {
        // Incoming connections only, as `has_too_many_connections` counts:
        // this node dialling a host does not stop that host dialling back.
        let from_here = shared
            .snapshot()
            .iter()
            .filter(|c| c.incoming && c.addr.ip() == addr.ip())
            .count();
        if from_here >= shared.cfg.max_connections_per_ip {
            return;
        }
    }

    let mut reader = FrameReader::new(levin::INITIAL_MAX_PACKET_SIZE);
    let Ok((header, body)) = read_one(&mut stream, &mut reader, HANDSHAKE_TIMEOUT) else {
        return;
    };

    match (header.kind(), header.command) {
        // Another node checking that this one's advertised port answers.
        (Kind::Request, command::PING) => {
            let body = messages::ping_response(shared.peer_id);
            let _ = write_frame(
                &mut stream,
                Header::response(command::PING, body.len() as u64, 1),
                &body,
            );
        }
        (Kind::Request, command::HANDSHAKE) => {
            let req = match HandshakeRequest::parse(&body) {
                Ok(r) => r,
                Err(e) => {
                    wow_log::debug!(LOG, "{addr}: malformed handshake: {e}");
                    lock(&shared.book).record_failure(addr.ip(), now);
                    return;
                }
            };
            // `specs/08` §4.2, in its order.
            if req.node_data.network_id != messages::network_id(shared.cfg.network) {
                wow_log::debug!(LOG, "{addr}: a peer on another network");
                return;
            }
            if req.node_data.peer_id == shared.peer_id {
                return;
            }
            if shared
                .snapshot()
                .iter()
                .any(|c| c.peer_id == req.node_data.peer_id)
            {
                return;
            }

            let peers = shared.handshake_peers();
            let resp = messages::handshake_response(
                &shared.node_data(),
                &shared.core.sync_data(),
                &peers,
            );
            if write_frame(
                &mut stream,
                Header::response(command::HANDSHAKE, resp.len() as u64, 1),
                &resp,
            )
            .is_err()
            {
                return;
            }

            // `if(arg.node_data.my_port && zone.m_can_pingback)`: a node that
            // dials out through a proxy does not ping anyone back.
            let ping_back_it = req.node_data.my_port != 0
                && req.node_data.my_port <= u32::from(u16::MAX)
                && shared.can_pingback();
            if ping_back_it {
                let s = shared.clone();
                let node = req.node_data.clone();
                let seed = req.payload_data.pruning_seed;
                let _ = std::thread::Builder::new()
                    .name("p2p-pingback".into())
                    .spawn(move || ping_back(s, addr.ip(), node, seed));
            }

            reader.set_limit(levin::DEFAULT_MAX_PACKET_SIZE);
            // What the handshake handed over, no timed sync hands over again.
            let sent_addresses = peers
                .iter()
                .filter_map(|e| e.address.socket_addr())
                .collect();
            run_connection(
                shared,
                stream,
                addr,
                true,
                req.node_data,
                req.payload_data,
                reader,
                sent_addresses,
            );
        }
        _ => {}
    }
}

/// Confirm an incoming peer's advertised port answers as that peer, and only
/// then list it as white (`specs/08` §4.2).
fn ping_back(shared: Arc<Shared>, ip: IpAddr, node: BasicNodeData, pruning_seed: u32) {
    let target = SocketAddr::new(ip, node.my_port as u16);
    if !lock(&shared.book).is_listable(&target) {
        return;
    }
    let confirmed = (|| -> Result<bool, String> {
        let mut stream =
            TcpStream::connect_timeout(&target, PING_TIMEOUT).map_err(|e| e.to_string())?;
        let body = messages::empty_body();
        write_frame(
            &mut stream,
            Header::request(command::PING, body.len() as u64),
            &body,
        )
        .map_err(|e| e.to_string())?;
        let mut reader = FrameReader::new(levin::INITIAL_MAX_PACKET_SIZE);
        let (h, body) = read_one(&mut stream, &mut reader, HANDSHAKE_TIMEOUT)?;
        if h.command != command::PING || h.kind() != Kind::Response {
            return Ok(false);
        }
        Ok(PingResponse::parse(&body)
            .map(|p| p.confirms(node.peer_id))
            .unwrap_or(false))
    })();

    if let Ok(true) = confirmed {
        // Not `set_peer_just_seen`: an address already white keeps its
        // `last_seen`, as `append_with_peer_white` leaves it after a ping.
        lock(&shared.book).add_white(
            PeerRecord {
                addr: target,
                id: node.peer_id,
                last_seen: unix_now() as i64,
                pruning_seed,
                rpc_port: node.rpc_port,
            },
            false,
        );
        wow_log::debug!(LOG, "{target} answered a ping-back; white-listed");
    }
}

/// Dial and handshake, returning the connection ready to run.
///
/// With `--proxy`, the socket comes from the proxy instead. The target is
/// given to it as an address rather than a name: everything dialled here came
/// from a peer list or from an option this node resolved at start, so there is
/// nothing left to look up.
fn dial(
    shared: &Shared,
    addr: SocketAddr,
) -> Result<(TcpStream, FrameReader, HandshakeResponse), String> {
    let mut stream = match &shared.cfg.proxy {
        Some(proxy) => {
            let target = socks::Target::Ip(addr);
            socks::connect(proxy, target, socks::CONNECT_TIMEOUT)
                .map_err(|e| format!("through the proxy at {proxy}: {e}"))?
        }
        None => TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|e| e.to_string())?,
    };
    let _ = stream.set_nodelay(true);
    let body = messages::handshake_request(&shared.node_data(), &shared.core.sync_data());
    write_frame(
        &mut stream,
        Header::request(command::HANDSHAKE, body.len() as u64),
        &body,
    )
    .map_err(|e| e.to_string())?;

    let mut reader = FrameReader::new(levin::INITIAL_MAX_PACKET_SIZE);
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("the handshake timed out".into());
        }
        let (h, body) = read_one(&mut stream, &mut reader, left)?;
        if h.command != command::HANDSHAKE || h.kind() != Kind::Response {
            continue;
        }
        if h.return_code < 0 {
            return Err(format!("the handshake was refused ({})", h.return_code));
        }
        let r = HandshakeResponse::parse(&body).map_err(|e| e.to_string())?;
        if r.node_data.network_id != messages::network_id(shared.cfg.network) {
            return Err("that peer is on another network".into());
        }
        if r.node_data.peer_id == shared.peer_id {
            return Err("connected to ourselves".into());
        }
        reader.set_limit(levin::DEFAULT_MAX_PACKET_SIZE);
        return Ok((stream, reader, r));
    }
}

/// A sync held up by something that is not the sender's fault: a full disk, a
/// proof this build cannot check, a clock that disagrees.
///
/// Every peer's copy of the next blocks fails the same way, so trying again at
/// once only repeats the failure as fast as the blocks download -- several
/// times a second, each time with a warning and a dropped peer. This paces the
/// attempts and says the same thing once.
#[derive(Debug, Default)]
struct Stall {
    /// Failures since the chain last grew, for the back-off.
    streak: u32,
    /// The applier does not try again before this.
    retry_at: Option<Instant>,
    /// The failure last warned about, and when.
    warned: Option<(String, Instant)>,
    /// How often it has recurred since, logged at debug level only.
    quieted: u64,
}

/// How [`Stall::failed`] says to log a failure.
#[derive(Debug, PartialEq, Eq)]
enum StallReport {
    /// A warning, counting the recurrences not warned about since the last.
    Warn { quieted: u64 },
    /// The failure a recent warning was about: debug level.
    Quiet,
}

impl Stall {
    fn waiting(&self, now: Instant) -> bool {
        self.retry_at.is_some_and(|t| now < t)
    }

    /// Another failure: how long to wait before trying again, and how loudly
    /// to say so.
    fn failed(&mut self, reason: &str, now: Instant) -> (Duration, StallReport) {
        let wait = STALL_RETRY
            .saturating_mul(1 << self.streak.min(6))
            .min(STALL_RETRY_MAX);
        self.streak = self.streak.saturating_add(1);
        self.retry_at = Some(now + wait);

        let same = self.warned.as_ref().filter(|(r, _)| r == reason);
        if same.is_some_and(|(_, at)| now.duration_since(*at) < STALL_QUIET) {
            self.quieted += 1;
            return (wait, StallReport::Quiet);
        }
        let quieted = if same.is_some() { self.quieted } else { 0 };
        self.quieted = 0;
        self.warned = Some((reason.to_string(), now));
        (wait, StallReport::Warn { quieted })
    }

    /// The chain grew. Returns whether it had been stalled.
    fn cleared(&mut self) -> bool {
        self.retry_at = None;
        std::mem::take(&mut self.streak) > 0
    }
}

/// The one thread that adds synced blocks to the chain.
fn apply_loop(shared: Arc<Shared>) {
    let mut stall = Stall::default();
    while !shared.stopping() {
        {
            let (flag, cv) = &shared.apply_wake;
            let mut woken = lock(flag);
            if !*woken {
                woken = match cv.wait_timeout(woken, MAINTENANCE_TICK) {
                    Ok((guard, _)) => guard,
                    Err(e) => e.into_inner().0,
                };
            }
            *woken = false;
        }
        // After a failure that was not the sender's fault, wait out the
        // back-off rather than fail again as fast as blocks arrive.
        if stall.waiting(Instant::now()) {
            continue;
        }
        drain_queue(&shared, &mut stall);
    }
}

/// Add every span the chain can take now, in height order
/// (`try_add_next_blocks`).
///
/// What a failure costs depends on whose fault it is. A block that shows its
/// sender lied bans the sender and gives back everything it delivered; one
/// this node could not take drops the sender without a ban and pauses the sync
/// ([`Stall`]); and spans that no longer attach to the chain -- it moved under
/// the queue -- throw the queue away so every connection reads its peer's
/// chain afresh.
fn drain_queue(shared: &Shared, stall: &mut Stall) {
    while !shared.stopping() {
        let height = shared.core.sync_data().current_height;
        let span = lock(&shared.queue).take_next(height, |id| shared.core.have_block(id));
        let Some(span) = span else {
            return;
        };
        let (taken, stop) = shared.core.apply_blocks(&span.blocks);
        lock(&shared.queue).applied(&span);
        if taken > 0 && stall.cleared() {
            wow_log::info!(
                LOG,
                "sync resumed at height {}",
                shared.core.sync_data().current_height
            );
        }
        match stop {
            None
            | Some(BlockVerdict::Added | BlockVerdict::Alternative | BlockVerdict::AlreadyHave) => {
            }
            Some(BlockVerdict::Orphan) => {
                wow_log::debug!(
                    LOG,
                    "blocks from {} at height {} do not attach to the chain; restarting the sync",
                    span.origin,
                    span.start
                );
                shared.flush_queue();
                return;
            }
            Some(BlockVerdict::Rejected { reason, ban: true }) => {
                wow_log::warn!(
                    LOG,
                    "{} sent an invalid block in the span from height {}: {reason}; banning",
                    span.origin,
                    span.start
                );
                lock(&shared.queue).flush(span.conn, true);
                shared.ban(BanTarget::Host(span.origin.ip()), IP_BLOCKTIME);
            }
            Some(BlockVerdict::MissingTxs(_)) => {
                wow_log::warn!(
                    LOG,
                    "{} left transactions out of a block it sent; banning",
                    span.origin
                );
                lock(&shared.queue).flush(span.conn, true);
                shared.ban(BanTarget::Host(span.origin.ip()), IP_BLOCKTIME);
            }
            Some(BlockVerdict::Rejected { reason, .. }) => {
                // Not the peer's fault, and not something asking again at once
                // fixes: another peer's copy of these blocks fails the same way.
                let at = span.start + taken as u64;
                let (wait, report) = stall.failed(&reason, Instant::now());
                let wait = wait.as_secs();
                match report {
                    StallReport::Warn { quieted: 0 } => wow_log::warn!(
                        LOG,
                        "sync stalled at height {at}: {reason}; retrying in {wait} s"
                    ),
                    StallReport::Warn { quieted } => wow_log::warn!(
                        LOG,
                        "sync still stalled at height {at} after {quieted} more attempt(s): \
                         {reason}; retrying in {wait} s"
                    ),
                    StallReport::Quiet => wow_log::debug!(
                        LOG,
                        "sync stalled at height {at} again: {reason}; retrying in {wait} s"
                    ),
                }
                lock(&shared.queue).flush(span.conn, true);
                if let Some(c) = lock(&shared.conns).get(&span.conn) {
                    c.close();
                }
                return;
            }
        }
    }
}

fn maintenance(shared: Arc<Shared>) {
    let mut last_save = Instant::now();
    // Both due at once, as `once_a_time_seconds` is on its first call.
    let mut last_timed_sync: Option<Instant> = None;
    let mut last_gray_check: Option<Instant> = None;
    while !shared.stopping() {
        if last_timed_sync.is_none_or(|t| t.elapsed() >= TIMED_SYNC_INTERVAL) {
            last_timed_sync = Some(Instant::now());
            timed_sync_all(&shared);
        }
        make_connections(&shared);
        if last_gray_check.is_none_or(|t| t.elapsed() >= GRAY_HOUSEKEEPING_INTERVAL) {
            last_gray_check = Some(Instant::now());
            gray_housekeeping(&shared);
        }
        shared.relay_tick();
        if last_save.elapsed() >= SAVE_EVERY {
            shared.save_state();
            last_save = Instant::now();
        }
        std::thread::sleep(MAINTENANCE_TICK);
    }
}

/// Keep the outgoing connections at their target (`specs/08` §8.1).
fn make_connections(shared: &Arc<Shared>) {
    let (outgoing, _) = shared.counts();
    let dialing = lock(&shared.dialing).len();
    let target = shared.out_peers.load(Ordering::Relaxed);
    let exclusive = !shared.cfg.exclusive_nodes.is_empty();

    // Priority nodes are dialled even over the target; they are the operator's
    // choice, not the node's.
    let mut wanted: Vec<SocketAddr> = Vec::new();
    let taken: HashSet<SocketAddr> = shared
        .snapshot()
        .iter()
        .map(|c| c.addr)
        .chain(lock(&shared.dialing).iter().copied())
        .collect();
    let now = Instant::now();
    let fresh = |a: &SocketAddr| {
        lock(&shared.tried)
            .get(a)
            .is_none_or(|t| now.duration_since(*t) >= RETRY_AFTER)
    };

    if exclusive {
        wanted.extend(
            shared
                .cfg
                .exclusive_nodes
                .iter()
                .filter(|a| !taken.contains(a) && fresh(a)),
        );
        wanted.truncate(target.saturating_sub(outgoing + dialing));
    } else {
        wanted.extend(
            shared
                .cfg
                .priority_nodes
                .iter()
                .filter(|a| !taken.contains(a) && fresh(a)),
        );
        if outgoing + dialing + wanted.len() < target {
            if let Some(a) = pick_candidate(shared, &taken, outgoing, target) {
                wanted.push(a);
            }
        }
    }

    for addr in wanted {
        if lock(&shared.dialing).len() >= MAX_DIALING {
            break;
        }
        if lock(&shared.book).is_banned(addr.ip(), unix_now()) {
            continue;
        }
        lock(&shared.tried).insert(addr, now);
        lock(&shared.dialing).insert(addr);
        let s = shared.clone();
        let spawned = std::thread::Builder::new()
            .name("p2p-out".into())
            .spawn(move || {
                let result = dial(&s, addr);
                lock(&s.dialing).remove(&addr);
                match result {
                    Ok((stream, reader, hs)) => {
                        {
                            let now = unix_now();
                            let mut book = lock(&s.book);
                            book.merge_peerlist(&hs.peers, now);
                            book.add_white(
                                PeerRecord {
                                    addr,
                                    id: hs.node_data.peer_id,
                                    last_seen: now as i64,
                                    pruning_seed: hs.payload_data.pruning_seed,
                                    rpc_port: hs.node_data.rpc_port,
                                },
                                true,
                            );
                        }
                        run_connection(
                            s,
                            stream,
                            addr,
                            false,
                            hs.node_data,
                            hs.payload_data,
                            reader,
                            HashSet::new(),
                        );
                    }
                    Err(e) => {
                        // Not dropped from the lists: the C++ leaves a peer
                        // it could not reach where it was, and does not try
                        // the host from them again for an hour.
                        wow_log::debug!(LOG, "{addr}: {e}");
                        lock(&s.book).record_addr_failed(addr.ip(), unix_now());
                    }
                }
            });
        if spawned.is_err() {
            lock(&shared.dialing).remove(&addr);
        }
    }
}

/// The next address to dial (`connections_maker`): an anchor while there are
/// few connections; then the white list until 70% of the outgoing target is
/// connected and the gray list first after that, choosing as
/// [`AddressBook::pick`] does; then the operator's `--add-peer` addresses,
/// then the seed nodes.
fn pick_candidate(
    shared: &Arc<Shared>,
    taken: &HashSet<SocketAddr>,
    outgoing: usize,
    target: usize,
) -> Option<SocketAddr> {
    let now = Instant::now();
    let unix = unix_now();
    let tried = lock(&shared.tried).clone();
    let usable = |a: &SocketAddr| {
        !taken.contains(a)
            && tried
                .get(a)
                .is_none_or(|t| now.duration_since(*t) >= RETRY_AFTER)
    };
    // `is_peer_used` also knows a node by its id on the same host, whatever
    // the port.
    let peers: HashSet<(IpAddr, u64)> = shared
        .snapshot()
        .iter()
        .map(|c| (c.addr.ip(), c.peer_id))
        .collect();

    let mut book = lock(&shared.book);
    let bans = book.bans(unix);
    let unusable = |r: &PeerRecord| {
        !usable(&r.addr)
            || r.id == shared.peer_id
            || peers.contains(&(r.addr.ip(), r.id))
            || bans.iter().any(|(t, _)| t.covers(r.addr.ip()))
            || book.is_addr_recently_failed(r.addr.ip(), unix)
    };

    if outgoing < ANCHOR_CONNECTIONS {
        if let Some(r) = book.anchors().into_iter().find(|r| !unusable(r)) {
            return Some(r.addr);
        }
    }

    let white_first = outgoing < target * WHITELIST_CONNECTIONS_PERCENT / 100;
    let connected: Vec<SocketAddr> = taken.iter().copied().collect();
    for from_white in [white_first, !white_first] {
        let mut rand = |n: usize| shared.rand_below(n);
        if let Some(r) = book.pick(from_white, &connected, &mut rand, &unusable) {
            return Some(r.addr);
        }
    }
    drop(book);

    shared
        .cfg
        .add_peers
        .iter()
        .chain(shared.cfg.seed_nodes.iter())
        .copied()
        .find(|a| usable(a))
}

/// Check one gray-list address, and promote or forget it
/// (`gray_peerlist_housekeeping`).
///
/// A handshake, and a disconnect straight after. An address that answers is
/// white-listed, with what the gray list knew of it, and its peer list is
/// taken as any handshake's is; one that does not is dropped from the gray
/// list. Without this the gray list only grows staler, and every outgoing
/// connection dialled from it is a guess.
///
/// Not with exclusive nodes, and not while this node is still short of
/// connections to sync from (`needs_new_sync_connections`): those dials go to
/// connections it keeps.
fn gray_housekeeping(shared: &Arc<Shared>) {
    if !shared.cfg.exclusive_nodes.is_empty() || shared.needs_new_sync_connections() {
        return;
    }
    let candidate = {
        let book = lock(&shared.book);
        let mut rand = |n: usize| shared.rand_below(n);
        book.random_gray(&mut rand)
    };
    let Some(rec) = candidate else {
        return;
    };
    let addr = rec.addr;
    if !lock(&shared.dialing).insert(addr) {
        return;
    }
    let s = shared.clone();
    let spawned = std::thread::Builder::new()
        .name("p2p-gray".into())
        .spawn(move || {
            let result = dial(&s, addr);
            lock(&s.dialing).remove(&addr);
            let now = unix_now();
            let mut book = lock(&s.book);
            match result {
                Ok((stream, _, hs)) => {
                    let _ = stream.shutdown(Shutdown::Both);
                    book.merge_peerlist(&hs.peers, now);
                    // `set_peer_just_seen`, with the gray entry's id, pruning
                    // seed and RPC port.
                    book.add_white(
                        PeerRecord {
                            last_seen: now as i64,
                            ..rec
                        },
                        true,
                    );
                    wow_log::debug!(LOG, "{addr}: answered; white-listed");
                }
                Err(e) => {
                    book.record_addr_failed(addr.ip(), now);
                    book.remove_gray(&addr);
                    wow_log::debug!(LOG, "{addr}: {e}; dropped from the gray list");
                }
            }
        });
    if spawned.is_err() {
        lock(&shared.dialing).remove(&addr);
    }
}

/// Run a handshaken connection on the current thread until it ends.
///
/// `sent_addresses` is what the handshake gave the peer: nothing for an
/// outgoing connection, whose handshake request carries no peer list.
#[allow(
    clippy::too_many_arguments,
    reason = "what the handshake settled, which each side gathers differently"
)]
fn run_connection(
    shared: Arc<Shared>,
    mut stream: TcpStream,
    addr: SocketAddr,
    incoming: bool,
    node: BasicNodeData,
    sync: CoreSyncData,
    mut reader: FrameReader,
    sent_addresses: HashSet<SocketAddr>,
) {
    let (Ok(writer), Ok(socket)) = (stream.try_clone(), stream.try_clone()) else {
        return;
    };
    let (tx, rx) = sync_channel(OUTBOX_CAPACITY);
    let closed = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));
    let conn = Arc::new(Conn {
        id: shared.next_id.fetch_add(1, Ordering::Relaxed),
        addr,
        incoming,
        peer_id: node.peer_id,
        rpc_port: node.rpc_port,
        support_flags: AtomicU32::new(node.support_flags),
        connected: Instant::now(),
        sync: Mutex::new(sync),
        state: AtomicU8::new(STATE_HANDSHAKE),
        outbox: tx,
        socket,
        closed: closed.clone(),
        recv_bytes: AtomicU64::new(0),
        sent_bytes: sent.clone(),
        last_recv: Mutex::new(Instant::now()),
        timed_sync_sent: Mutex::new(None),
    });

    {
        let mut conns = lock(&shared.conns);
        // The same node twice is one connection too many.
        if shared.stopping() || conns.values().any(|c| c.peer_id == node.peer_id) {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        conns.insert(conn.id, conn.clone());
    }
    wow_log::info!(
        LOG,
        "{} peer {addr} (id {:016x}, height {})",
        if incoming { "incoming" } else { "outgoing" },
        node.peer_id,
        conn.peer_sync().current_height
    );

    let _ = std::thread::Builder::new()
        .name("p2p-write".into())
        .spawn(move || write_loop(writer, rx, closed, sent));

    let mut proto = Proto::new(sent_addresses);
    let _ = stream.set_read_timeout(Some(TICK));
    advance(&shared, &conn, &mut proto);

    let fault = loop {
        if shared.stopping() || conn.closed.load(Ordering::Relaxed) {
            break None;
        }
        match reader.poll(&mut stream) {
            Ok(Some((header, body))) => {
                conn.recv_bytes
                    .fetch_add((levin::HEADER_LEN + body.len()) as u64, Ordering::Relaxed);
                *lock(&conn.last_recv) = Instant::now();
                if let Err(f) = handle_message(&shared, &conn, &mut proto, header, &body) {
                    break Some(f);
                }
            }
            Ok(None) => {}
            Err(e) => break Some(Fault::drop(e.to_string())),
        }
        if let Err(f) = housekeeping(&shared, &conn, &mut proto) {
            break Some(f);
        }
    };

    {
        let mut conns = lock(&shared.conns);
        conns.remove(&conn.id);
        // Cut off from the network: whatever the pool missed meanwhile is
        // asked for again once back.
        if conns.is_empty() {
            shared.ask_complement.store(true, Ordering::Relaxed);
        }
    }
    lock(&shared.queue).flush(conn.id, false);
    conn.close();
    match fault {
        Some(Fault { reason, ban: true }) => {
            wow_log::warn!(LOG, "{addr}: {reason}; banning");
            shared.ban(BanTarget::Host(addr.ip()), IP_BLOCKTIME);
        }
        Some(Fault { reason, .. }) => {
            wow_log::debug!(LOG, "{addr}: disconnected: {reason}");
        }
        None => {}
    }
}

fn write_loop(
    mut stream: TcpStream,
    rx: Receiver<Vec<u8>>,
    closed: Arc<AtomicBool>,
    sent: Arc<AtomicU64>,
) {
    let _ = stream.set_write_timeout(Some(INVOKE_TIMEOUT));
    loop {
        if closed.load(Ordering::Relaxed) {
            break;
        }
        match rx.recv_timeout(TICK) {
            Ok(frame) => {
                if stream.write_all(&frame).is_err() {
                    break;
                }
                sent.fetch_add(frame.len() as u64, Ordering::Relaxed);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    closed.store(true, Ordering::SeqCst);
    let _ = stream.shutdown(Shutdown::Both);
}

// ---------------------------------------------------------------------------
// the protocol
// ---------------------------------------------------------------------------

fn malformed(what: &str, e: impl std::fmt::Display) -> Fault {
    Fault::drop(format!("malformed {what}: {e}"))
}

fn handle_message(
    shared: &Shared,
    conn: &Conn,
    proto: &mut Proto,
    header: Header,
    body: &[u8],
) -> Result<(), Fault> {
    let core = &shared.core;
    match (header.kind(), header.command) {
        (Kind::Request, command::TIMED_SYNC) => {
            let t = TimedSync::parse(body).map_err(|e| malformed("timed sync", e))?;
            *lock(&conn.sync) = t.payload_data;
            let peers = unsent(shared.handshake_peers(), &mut proto.sent_addresses);
            let reply = messages::timed_sync_response_with_peers(&core.sync_data(), &peers);
            conn.respond(command::TIMED_SYNC, 1, &reply);
        }
        (Kind::Response, command::TIMED_SYNC) => {
            *lock(&conn.timed_sync_sent) = None;
            if header.return_code >= 0 {
                let t = TimedSync::parse(body).map_err(|e| malformed("timed sync", e))?;
                let pruning_seed = t.payload_data.pruning_seed;
                *lock(&conn.sync) = t.payload_data;
                let now = unix_now();
                let mut book = lock(&shared.book);
                book.merge_peerlist(&t.peers, now);
                // An outgoing peer that answers is seen just now
                // (`set_peer_just_seen` in `do_peer_timed_sync`).
                if !conn.incoming {
                    book.add_white(
                        PeerRecord {
                            addr: conn.addr,
                            id: conn.peer_id,
                            last_seen: now as i64,
                            pruning_seed,
                            rpc_port: conn.rpc_port,
                        },
                        true,
                    );
                }
            }
        }
        (Kind::Request, command::PING) => {
            conn.respond(command::PING, 1, &messages::ping_response(shared.peer_id));
        }
        (Kind::Request, command::REQUEST_SUPPORT_FLAGS) => {
            conn.respond(
                command::REQUEST_SUPPORT_FLAGS,
                1,
                &messages::support_flags_response_with(SUPPORT_FLAG_FLUFFY_BLOCKS),
            );
        }
        (Kind::Response, command::REQUEST_SUPPORT_FLAGS) => {
            if let Ok(flags) = messages::support_flags_of(body) {
                conn.support_flags.store(flags, Ordering::Relaxed);
            }
        }
        (Kind::Request, command::HANDSHAKE) => {
            return Err(Fault::drop("a second handshake"));
        }
        (Kind::Request, cmd) => {
            // Not served: say so, so the peer's invoke does not hang.
            conn.respond(cmd, levin::ERROR_CONNECTION_HANDLER_NOT_DEFINED, &[]);
        }
        (Kind::Notification, command::REQUEST_CHAIN) => {
            let req = ChainRequest::parse(body).map_err(|e| malformed("chain request", e))?;
            let Some(r) = core.chain_reply(&req.block_ids) else {
                return Err(Fault::drop(
                    "asked for a chain from blocks this node does not have",
                ));
            };
            conn.notify(
                command::RESPONSE_CHAIN_ENTRY,
                &messages::chain_entry_response(
                    r.start_height,
                    r.total_height,
                    r.cumulative_difficulty,
                    &r.block_ids,
                    &r.block_weights,
                    &r.first_block,
                ),
            );
        }
        (Kind::Notification, command::REQUEST_GET_OBJECTS) => {
            let req = ObjectsRequest::parse(body).map_err(|e| malformed("block request", e))?;
            // The reference drops a peer that asks for more (`docs/spec-deltas.md` §22).
            if req.blocks.len() > messages::MAX_OBJECT_REQUEST_COUNT {
                return Err(Fault::drop("asked for more blocks than one request may"));
            }
            let (blocks, missed) = core.blocks(&req.blocks);
            conn.notify(
                command::RESPONSE_GET_OBJECTS,
                &messages::objects_response(&blocks, &missed, core.sync_data().current_height),
            );
        }
        (Kind::Notification, command::RESPONSE_CHAIN_ENTRY) => {
            on_chain_entry(shared, conn, proto, body)?;
        }
        (Kind::Notification, command::RESPONSE_GET_OBJECTS) => {
            on_objects(shared, conn, proto, body)?;
        }
        (Kind::Notification, command::NEW_BLOCK | command::NEW_FLUFFY_BLOCK) => {
            on_new_block(shared, conn, proto, body)?;
        }
        (Kind::Notification, command::REQUEST_FLUFFY_MISSING_TX) => {
            let m =
                FluffyMissingTxs::parse(body).map_err(|e| malformed("missing-tx request", e))?;
            let Some(entry) = core.block_with_txs(&m.block_hash, &m.missing_tx_indices) else {
                return Err(Fault::drop(
                    "asked for the transactions of a block this node does not have",
                ));
            };
            let reply = NewBlock {
                entry,
                current_blockchain_height: core.sync_data().current_height,
            };
            conn.notify(command::NEW_FLUFFY_BLOCK, &reply.to_bytes());
        }
        (Kind::Notification, command::NEW_TRANSACTIONS) => {
            on_new_transactions(shared, conn, body)?;
        }
        // Only from a peer in the normal state, as the C++ answers.
        (Kind::Notification, command::GET_TXPOOL_COMPLEMENT) if conn.state() == STATE_NORMAL => {
            let c = TxpoolComplement::parse(body).map_err(|e| malformed("pool complement", e))?;
            let known: HashSet<Hash256> = c.hashes.into_iter().collect();
            let txs = core.pool_txs_except(&known);
            if !txs.is_empty() {
                let body = NewTransactions {
                    txs,
                    dandelionpp_fluff: true,
                }
                .to_bytes();
                conn.notify(command::NEW_TRANSACTIONS, &body);
            }
        }
        _ => {}
    }
    Ok(())
}

/// The peers of `peers` this connection has not been given yet, now marked
/// given (`handle_timed_sync`).
///
/// A peer asks for a timed sync every minute. Handing it a fresh random
/// selection each time would give it the whole white list within the hour,
/// and show it, entry by entry, what joined the list and when.
fn unsent(peers: Vec<PeerlistEntry>, sent: &mut HashSet<SocketAddr>) -> Vec<PeerlistEntry> {
    peers
        .into_iter()
        .filter(|e| e.address.socket_addr().is_none_or(|a| sent.insert(a)))
        .collect()
}

fn housekeeping(shared: &Shared, conn: &Conn, proto: &mut Proto) -> Result<(), Fault> {
    let now = Instant::now();
    if now < proto.next_housekeeping {
        return Ok(());
    }
    proto.next_housekeeping = now + TICK;

    if let Some(p) = &proto.pending {
        if now.duration_since(p.sent()) > INVOKE_TIMEOUT {
            return Err(Fault::drop("did not answer a sync request"));
        }
    }
    if now.duration_since(*lock(&conn.last_recv)) > IDLE_TIMEOUT {
        return Err(Fault::drop("idle"));
    }
    advance(shared, conn, proto);
    Ok(())
}

/// A timed sync to every connection not still waiting on its last one
/// (`peer_sync_idle_maker`).
///
/// One clock for all of them, as the C++ runs it from its idle loop, so a
/// peer's first comes anywhere up to a minute after its handshake. On each
/// connection's own clock, a timed sync came exactly a minute after every
/// handshake, which only this node did.
fn timed_sync_all(shared: &Shared) {
    let body = messages::timed_sync_request(&shared.core.sync_data());
    for c in shared.snapshot() {
        let mut sent = lock(&c.timed_sync_sent);
        // One the peer never answered stops holding the next back after
        // `P2P_DEFAULT_INVOKE_TIMEOUT`, when the C++'s invoke would time out.
        if sent.is_some_and(|t| t.elapsed() < INVOKE_TIMEOUT) {
            continue;
        }
        *sent = Some(Instant::now());
        c.request(command::TIMED_SYNC, &body);
    }
}

/// Move this connection's part of the sync along (`request_missing_objects`).
///
/// In order: settle into the normal state once the peer is no longer ahead;
/// fetch the span the chain needs next if its owner is overdue; reserve and
/// fetch the next span of the peer's chain nobody else is fetching; and when
/// everything the peer offered is on the chain, ask it for more of its chain.
/// A connection that can do none of these waits in standby.
fn advance(shared: &Shared, conn: &Conn, proto: &mut Proto) {
    if proto.pending.is_some() || shared.stopping() {
        return;
    }
    let generation = shared.generation.load(Ordering::Relaxed);
    if proto.generation != generation {
        // The queue was thrown away, and with it the reason to trust what
        // this connection knew of its peer's chain.
        proto.generation = generation;
        proto.chain.clear();
    }
    if shared.cfg.no_sync {
        settle(shared, conn);
        return;
    }

    // Drop the front of the peer's chain this node already has.
    let known = proto
        .chain
        .iter()
        .take_while(|id| shared.core.have_block(id))
        .count();
    proto.chain.drain(..known);
    proto.chain_start += known as u64;

    let ours = shared.core.sync_data();
    if proto.chain.is_empty() {
        // Not ahead: no more work than ours, or a tip this node already holds.
        // The second is the C++ test (`process_payload_sync_data` settles on
        // `have_block(top_id)`). Without it a peer on the same chain stays
        // unsettled for as long as the two nodes' stored difficulties disagree,
        // as they do for a database synced before the hard-fork version fix,
        // and nothing is relayed to it.
        let peer = conn.peer_sync();
        if peer.cumulative_difficulty <= ours.cumulative_difficulty
            || shared.core.have_block(&peer.top_id)
        {
            settle(shared, conn);
        } else if Instant::now() >= proto.chain_again_at {
            request_chain(shared, conn, proto);
        } else {
            conn.set_state(STATE_STANDBY);
        }
        return;
    }

    let now = Instant::now();
    let overdue_after = if conn.state() == STATE_STANDBY {
        queue::NEXT_SPAN_THRESHOLD_STANDBY
    } else {
        queue::NEXT_SPAN_THRESHOLD
    };
    let near_tip = proto.chain_start < ours.current_height + queue::FORCE_DOWNLOAD_NEAR_BLOCKS;
    let batch = proto.batch;
    let reserved = {
        let mut q = lock(&shared.queue);
        let overdue = q
            .overdue_next(ours.current_height, overdue_after, now)
            .filter(|(start, ids, owner)| *owner != conn.id && offers(proto, *start, ids));
        if let Some((start, ids, _)) = overdue {
            q.touch(start, now);
            Some((start, ids))
        } else if near_tip || !q.is_full() {
            q.reserve(
                conn.id,
                conn.addr,
                proto.chain_start,
                &proto.chain,
                |start, free| batch.next(start, free),
                now,
            )
        } else {
            None
        }
    };

    match reserved {
        Some((start, ids)) => {
            // One request in flight per connection, which is what `pending`
            // being a single slot means and what the reference does.
            //
            // A second in flight would hide the round trip, and it is worth
            // knowing why that is not done here. Parallelism across *peers* is
            // the reference's answer and this node's: a dozen connections each
            // filling a span is already a dozen requests in the air, and the
            // applier is the thing they queue behind. A second request per
            // connection would also mean matching an answer to the request it
            // belongs to -- `RESPONSE_GET_OBJECTS` does not name one -- and
            // deciding what a span whose partner failed should do. That is a
            // protocol change, on the path that has to agree with C++ peers,
            // for a saving the peer count already buys.
            conn.notify(
                command::REQUEST_GET_OBJECTS,
                &messages::request_objects(&ids, false),
            );
            proto.pending = Some(Pending::Objects {
                sent: now,
                start,
                ids,
            });
            conn.set_state(STATE_SYNCHRONIZING);
        }
        // Everything this peer offered is in flight elsewhere, or the queue is
        // full: wait, and try again on the next tick.
        None => conn.set_state(STATE_STANDBY),
    }
}

/// Whether the peer's chain holds `ids` from height `start`.
fn offers(proto: &Proto, start: u64, ids: &[Hash256]) -> bool {
    let Some(offset) = start.checked_sub(proto.chain_start) else {
        return false;
    };
    let offset = offset as usize;
    offset
        .checked_add(ids.len())
        .and_then(|end| proto.chain.get(offset..end))
        == Some(ids)
}

/// The peer is not ahead: the connection is in the normal state, and a sync
/// it took part in has ended.
fn settle(shared: &Shared, conn: &Conn) {
    // A handshaken peer that is not ahead means this node is caught up with at
    // least one of the network's views.
    shared.ever_synced.store(true, Ordering::Relaxed);
    let was_syncing = matches!(conn.state(), STATE_SYNCHRONIZING | STATE_STANDBY);
    conn.set_state(STATE_NORMAL);
    // Catch the pool up with the network's (`specs/08` §6.3), once, from the
    // first connection to settle after the node is synchronised
    // (`on_connection_synchronized`). Asking every connection that finished a
    // sync fetched the same pool a dozen times over, and it offered the
    // peers this node's private transactions' hashes too: only public ones
    // are listed, since a hash is all it takes to tell a stem holds one.
    if shared.ask_complement.load(Ordering::Relaxed)
        && shared.sync_status().synchronized
        && shared.ask_complement.swap(false, Ordering::SeqCst)
    {
        let body = TxpoolComplement {
            hashes: shared.core.pool_hashes(),
        }
        .to_bytes();
        conn.notify(command::GET_TXPOOL_COMPLEMENT, &body);
    }
    if !was_syncing {
        return;
    }
    wow_log::info!(
        LOG,
        "synchronised with {} at height {}",
        conn.addr,
        shared.core.sync_data().current_height
    );
}

fn request_chain(shared: &Shared, conn: &Conn, proto: &mut Proto) {
    let mut history = shared.core.short_history();
    // Start from the last block this connection reserved, which may still be
    // waiting in the queue rather than on the chain (`m_last_known_hash`).
    if let Some(last) = lock(&shared.queue).last_known(conn.id) {
        if history.first() != Some(&last) {
            history.insert(0, last);
        }
    }
    conn.notify(
        command::REQUEST_CHAIN,
        &messages::request_chain(&history, false),
    );
    proto.pending = Some(Pending::Chain(Instant::now()));
    proto.chain.clear();
    conn.set_state(STATE_SYNCHRONIZING);
}

fn on_chain_entry(
    shared: &Shared,
    conn: &Conn,
    proto: &mut Proto,
    body: &[u8],
) -> Result<(), Fault> {
    if !matches!(proto.pending, Some(Pending::Chain(_))) {
        return Ok(());
    }
    proto.pending = None;
    let entry =
        ChainEntry::parse(body).map_err(|e| Fault::ban(format!("a malformed chain entry: {e}")))?;
    let n = entry.block_ids.len() as u64;
    if n == 0 {
        return Err(Fault::drop("an empty chain entry"));
    }
    if entry.block_ids.len() > messages::BLOCK_IDS_MAX_COUNT
        || entry.total_height < n
        || entry.start_height > entry.total_height - n
    {
        return Err(Fault::drop("a chain entry with inconsistent heights"));
    }
    // `specs/08` §5.3: the first id is the split point, which this node must
    // have -- on the chain, or waiting in the queue at that height.
    let first = entry.block_ids[0];
    let queued = lock(&shared.queue).height_of(&first) == Some(entry.start_height);
    if !queued && !shared.core.have_block(&first) {
        return Err(Fault::drop(
            "a chain entry that does not start at a block this node has",
        ));
    }
    let mut seen = HashSet::with_capacity(entry.block_ids.len());
    if !entry.block_ids.iter().all(|id| seen.insert(*id)) {
        return Err(Fault::drop("a chain entry that names a block twice"));
    }
    {
        let mut s = lock(&conn.sync);
        s.current_height = s.current_height.max(entry.total_height);
    }

    proto.generation = shared.generation.load(Ordering::Relaxed);
    proto.chain = entry.block_ids;
    proto.chain_start = entry.start_height;
    // A chain entry with nothing new in it is not asked for again straight
    // away, or a peer that claims more work than it can show would be asked
    // in a loop.
    if proto.chain.iter().all(|id| shared.core.have_block(id)) {
        proto.chain_again_at = Instant::now() + queue::NEXT_SPAN_THRESHOLD_STANDBY;
    }
    advance(shared, conn, proto);
    Ok(())
}

fn on_objects(shared: &Shared, conn: &Conn, proto: &mut Proto, body: &[u8]) -> Result<(), Fault> {
    let Some(Pending::Objects { sent, start, ids }) = proto.pending.take() else {
        return Err(Fault::drop("sent blocks that were not requested"));
    };
    let resp = ObjectsResponse::parse(body)
        .map_err(|e| Fault::ban(format!("a malformed block response: {e}")))?;

    // `specs/08` §5.5: every block must be one that was asked for. In order,
    // which is how both the reference and this node send them.
    if resp.blocks.len() > ids.len() {
        return Err(Fault::ban("sent more blocks than were requested"));
    }
    for (b, want) in resp.blocks.iter().zip(&ids) {
        let block = wow_types::Block::from_blob(&b.block).ok();
        if block.as_ref().and_then(|blk| blk.block_id()) != Some(*want) {
            return Err(Fault::ban("sent a block that was not the one requested"));
        }
        if block.is_some_and(|blk| blk.tx_hashes.len() != b.txs.len()) {
            return Err(Fault::drop(
                "sent a block without the transactions it names",
            ));
        }
    }
    if resp.blocks.is_empty() {
        return Err(Fault::drop("had none of the blocks its chain offered"));
    }
    {
        let mut s = lock(&conn.sync);
        s.current_height = s.current_height.max(resp.current_blockchain_height);
    }

    let n = resp.blocks.len();
    let size: usize = resp
        .blocks
        .iter()
        .map(|b| b.block.len() + b.txs.iter().map(Vec::len).sum::<usize>())
        .sum();
    let rate = size as f64 / sent.elapsed().as_secs_f64().max(1e-6);
    if n == ids.len() {
        proto.batch.grow();
    } else {
        proto.batch.shrink();
    }
    let filed = lock(&shared.queue).fill(start, &ids, resp.blocks, conn.id, conn.addr, rate, size);
    if filed {
        shared.wake_applier();
    }
    advance(shared, conn, proto);
    Ok(())
}

fn on_new_block(shared: &Shared, conn: &Conn, proto: &mut Proto, body: &[u8]) -> Result<(), Fault> {
    // The reference ignores announcements from a connection that is not in
    // the normal state; while syncing, the sync will bring the block anyway.
    if conn.state() != STATE_NORMAL {
        return Ok(());
    }
    let nb = NewBlock::parse(body).map_err(|e| malformed("block announcement", e))?;
    {
        let mut s = lock(&conn.sync);
        s.current_height = s.current_height.max(nb.current_blockchain_height);
    }
    match shared.core.new_block(&nb.entry) {
        BlockVerdict::Added => {
            wow_log::debug!(LOG, "block from {} added", conn.addr);
            shared.relay_block(&nb.entry, Some(conn.id));
        }
        BlockVerdict::Alternative | BlockVerdict::AlreadyHave => {}
        BlockVerdict::Orphan => {
            if !shared.cfg.no_sync && proto.pending.is_none() {
                request_chain(shared, conn, proto);
            }
        }
        BlockVerdict::MissingTxs(indices) => {
            let Some(id) = wow_types::Block::from_blob(&nb.entry.block)
                .ok()
                .and_then(|b| b.block_id())
            else {
                return Err(Fault::ban("announced a block that does not parse"));
            };
            let ask = FluffyMissingTxs {
                block_hash: id,
                current_blockchain_height: shared.core.sync_data().current_height,
                missing_tx_indices: indices,
            };
            conn.notify(command::REQUEST_FLUFFY_MISSING_TX, &ask.to_bytes());
        }
        BlockVerdict::Rejected { reason, ban: true } => return Err(Fault::ban(reason)),
        BlockVerdict::Rejected { reason, .. } => {
            wow_log::debug!(LOG, "block from {} refused: {reason}", conn.addr);
        }
    }
    Ok(())
}

fn on_new_transactions(shared: &Shared, conn: &Conn, body: &[u8]) -> Result<(), Fault> {
    if conn.state() != STATE_NORMAL {
        return Ok(());
    }
    let m = NewTransactions::parse(body).map_err(|e| malformed("transactions", e))?;
    let verdicts = shared.core.incoming_txs(&m.txs, m.dandelionpp_fluff);
    // Passed on as two batches, the stem and the fluff, as the C++ relays
    // them (`handle_notify_new_transactions`); one message per transaction
    // told a stem peer how many there had been, and in what order.
    let mut stem = TxBatch::new();
    let mut fluff = TxBatch::new();
    for (blob, verdict) in m.txs.into_iter().zip(verdicts) {
        match verdict {
            // As the pool says, not as the message says: a stem copy of a
            // transaction this node already holds in its stem is a loop, and
            // is fluffed -- where answering "known" left it to sit out the
            // embargo while the stem went quiet.
            TxVerdict::Accepted {
                id,
                how: Some(TxRelay::Local | TxRelay::Stem),
            } => stem.push((id, blob)),
            TxVerdict::Accepted {
                id,
                how: Some(TxRelay::Fluff),
            } => fluff.push((id, blob)),
            TxVerdict::Accepted { .. } => {}
            TxVerdict::Known { id } => {
                // Seen fluffed: any embargo on it has served its purpose.
                if m.dandelionpp_fluff {
                    lock(&shared.relay).embargo.remove(&id);
                }
            }
            TxVerdict::Rejected { reason, ban: true } => return Err(Fault::ban(reason)),
            TxVerdict::Rejected { .. } => {}
        }
    }
    shared.relay_txs(Some(conn.id), stem, TxRelay::Stem);
    shared.relay_txs(Some(conn.id), fluff, TxRelay::Fluff);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_timeouts_are_the_documented_ones() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_millis(5_000));
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_millis(5_000));
        assert_eq!(PING_TIMEOUT, Duration::from_millis(2_000));
        assert_eq!(INVOKE_TIMEOUT, Duration::from_secs(120));
        assert_eq!(TIMED_SYNC_INTERVAL, Duration::from_secs(60));
        assert_eq!(IDLE_TIMEOUT, Duration::from_secs(300));
    }

    #[test]
    fn the_dandelion_constants_are_the_documented_ones() {
        assert_eq!(DANDELION_STEMS, 2);
        assert_eq!(DANDELION_FLUFF_PERCENT, 20);
        assert_eq!(DANDELION_MIN_EPOCH, Duration::from_secs(600));
        assert_eq!(DANDELION_EMBARGO_AVERAGE, Duration::from_secs(39));
        assert_eq!(DANDELION_FLUSH_AVERAGE, Duration::from_secs(5));
        assert_eq!((FLUSH_QUARTERS_IN, FLUSH_QUARTERS_OUT), (20, 10));
    }

    /// splitmix64, as uniform draws in (0, 1]: a fixed sequence, so the
    /// statistics below are the same on every run.
    fn uniforms(mut state: u64) -> impl FnMut() -> f64 {
        move || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            ((z >> 11) + 1) as f64 / (1u64 << 53) as f64
        }
    }

    /// The timers are Poisson counts, as `std::poisson_distribution` gives
    /// them: the mean asked for, and a variance equal to it. An exponential
    /// delay, which this used, has the mean but a variance of its square --
    /// 1,521 s² for the embargo rather than 39.
    #[test]
    fn the_dandelion_timers_are_poisson() {
        for mean in [10u64, 20, 39] {
            let mut next = uniforms(mean);
            let n = 20_000;
            let draws: Vec<f64> = (0..n).map(|_| poisson(mean, &mut next) as f64).collect();
            let avg = draws.iter().sum::<f64>() / n as f64;
            let var = draws.iter().map(|d| (d - avg).powi(2)).sum::<f64>() / n as f64;
            let expected = mean as f64;
            assert!((avg - expected).abs() < 0.3, "mean {mean}: {avg}");
            assert!((var / expected - 1.0).abs() < 0.1, "mean {mean}: {var}");
        }
        assert_eq!(poisson(0, uniforms(1)), 0);
    }

    /// A batch goes out sorted and without repeats, whatever order it was
    /// queued in.
    #[test]
    fn a_flush_does_not_keep_the_arrival_order() {
        let mut txs: TxBatch = vec![
            ([3; 32], vec![3, 3]),
            ([1; 32], vec![1]),
            ([3; 32], vec![3, 3]),
            ([2; 32], vec![2]),
        ];
        flush_order(&mut txs);
        let blobs: Vec<Vec<u8>> = txs.into_iter().map(|(_, b)| b).collect();
        assert_eq!(blobs, vec![vec![1], vec![2], vec![3, 3]]);
    }

    /// Each source keeps its stem for the epoch; a new source takes the least
    /// used; a stem that goes away is replaced alone, and a source mapped to it
    /// moves on.
    #[test]
    fn the_stem_map_is_sticky_and_mends_only_what_broke() {
        let mut first = |_: usize| 0;
        let mut map = StemMap::new(vec![10, 11, 12, 13], DANDELION_STEMS, &mut first);
        let stems: Vec<Option<u64>> = map.out.clone();
        assert_eq!(stems.len(), 2);
        assert!(stems.iter().all(|s| s.is_some()));

        let local = map.get_stem(None, &mut first).unwrap();
        let peer = map.get_stem(Some(7), &mut first).unwrap();
        assert_ne!(local, peer, "the second source takes the other stem");
        for _ in 0..5 {
            assert_eq!(map.get_stem(None, &mut first), Some(local));
            assert_eq!(map.get_stem(Some(7), &mut first), Some(peer));
        }
        assert_eq!(map.usage, vec![1, 1]);

        // Nothing changed: nothing to do.
        assert!(!map.update((10..14).collect(), &mut first));

        // The local stem goes away. Its slot takes another connection, the
        // other slot keeps its own, and the local source moves.
        let live: Vec<u64> = (10..14).filter(|c| *c != local).collect();
        assert!(map.update(live, &mut first));
        assert!(map.out.contains(&Some(peer)));
        assert!(!map.out.contains(&Some(local)));
        assert_eq!(map.get_stem(Some(7), &mut first), Some(peer));
        let moved = map.get_stem(None, &mut first).unwrap();
        assert_ne!(moved, local);
        assert_eq!(map.usage.iter().sum::<usize>(), 2);

        // With no connections left, there is no stem, and no mapping kept.
        assert!(map.update(Vec::new(), &mut first));
        assert_eq!(map.get_stem(None, &mut first), None);
        assert!(!map.sources.contains_key(&None));
    }

    /// An epoch that starts with no connections fills its stems as they come.
    #[test]
    fn an_empty_stem_map_fills_up() {
        let mut first = |_: usize| 0;
        let mut map = StemMap::new(Vec::new(), DANDELION_STEMS, &mut first);
        assert_eq!(map.get_stem(None, &mut first), None);
        assert!(map.update(vec![5], &mut first));
        assert_eq!(map.get_stem(None, &mut first), Some(5));
        assert!(map.update(vec![5, 6, 7], &mut first));
        assert_eq!(map.out.len(), DANDELION_STEMS);
        assert_eq!(map.get_stem(Some(1), &mut first), map.out[1]);
    }

    /// Mainnet has its six hard-coded seeds; the test networks have none of
    /// their own (`specs/01` §12.2).
    #[test]
    fn only_mainnet_has_seed_nodes() {
        assert_eq!(seed_nodes(Network::Mainnet).len(), 6);
        assert!(seed_nodes(Network::Testnet).is_empty());
        assert!(seed_nodes(Network::Stagenet).is_empty());
    }

    /// A failure that keeps recurring is retried after a doubling wait, with a
    /// cap, and warned about once until it has been quiet for a while.
    #[test]
    fn a_stalled_sync_backs_off_and_warns_once() {
        let t0 = Instant::now();
        let mut stall = Stall::default();
        let full = "step 12 (Commit): storage: backend: mdb_put: MDB_MAP_FULL";

        let (wait, report) = stall.failed(full, t0);
        assert_eq!(
            (wait, report),
            (Duration::from_secs(1), StallReport::Warn { quieted: 0 })
        );
        assert!(stall.waiting(t0));
        assert!(!stall.waiting(t0 + wait));

        let waits: Vec<u64> = (0..8)
            .map(|i| {
                let (wait, report) = stall.failed(full, t0 + Duration::from_secs(i));
                assert_eq!(report, StallReport::Quiet);
                wait.as_secs()
            })
            .collect();
        assert_eq!(waits, [2, 4, 8, 16, 32, 60, 60, 60]);

        // Once the quiet period is over it is warned about again, with a count.
        let later = t0 + STALL_QUIET;
        assert_eq!(
            stall.failed(full, later).1,
            StallReport::Warn { quieted: 8 }
        );
        // A different failure is warned about at once, without that count.
        assert_eq!(
            stall.failed("clock", later).1,
            StallReport::Warn { quieted: 0 }
        );

        // Progress ends the stall and starts the back-off over.
        assert!(stall.cleared());
        assert!(!stall.waiting(later));
        assert!(!stall.cleared(), "only once");
        assert_eq!(stall.failed("clock", later).0, Duration::from_secs(1));
    }

    /// A peer is given each address once per connection: what the handshake
    /// gave, and what an earlier timed sync gave, the next timed sync leaves
    /// out.
    #[test]
    fn a_timed_sync_gives_only_peers_not_given_before() {
        let entry = |host: &str| PeerlistEntry {
            address: messages::NetworkAddress::from_socket_addr(host.parse().unwrap()),
            id: 1,
            last_seen: 0,
            pruning_seed: 0,
            rpc_port: 0,
        };
        let a = entry("8.8.8.8:34567");
        let b = entry("9.9.9.9:34567");
        let c = entry("1.1.1.1:34567");

        // The handshake gave `a`.
        let mut sent = HashSet::new();
        sent.insert("8.8.8.8:34567".parse::<SocketAddr>().unwrap());
        assert_eq!(
            unsent(vec![a.clone(), b.clone()], &mut sent),
            vec![b.clone()]
        );
        assert_eq!(
            unsent(vec![b.clone(), c.clone(), a.clone()], &mut sent),
            vec![c]
        );
        assert!(unsent(vec![a, b], &mut sent).is_empty());
        assert_eq!(sent.len(), 3);
    }

    #[test]
    fn the_defaults_match_the_reference() {
        let c = Config::new(Network::Mainnet);
        assert_eq!(c.out_peers, 12, "P2P_DEFAULT_CONNECTIONS_COUNT");
        assert_eq!(c.listen.unwrap().port(), 34_567);
        assert_eq!(Config::new(Network::Testnet).listen.unwrap().port(), 28_080);
        assert_eq!(c.max_connections_per_ip, 1);
    }
}
