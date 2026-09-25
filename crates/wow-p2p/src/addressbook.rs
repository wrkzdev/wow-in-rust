//! Who this node knows about, who it has verified, and who it has banned
//! (`specs/08` §8).
//!
//! # Three lists
//!
//! * **white** -- peers this node has itself reached: an outgoing handshake
//!   that succeeded, or an incoming peer whose advertised port answered a
//!   ping-back. Nothing a stranger *says* puts an address here.
//! * **gray** -- addresses other peers mentioned. Unverified, and the larger
//!   list by design: most of it is stale.
//! * **anchor** -- peers this node had outgoing connections to when it last
//!   stopped. It reconnects to those first, which is the eclipse-attack
//!   mitigation `specs/08` §8.1 describes: an attacker who floods the gray list
//!   between runs still does not choose this node's first connections.
//!
//! # Persisted in a file of its own
//!
//! `specs/08` §8.1 allows a node its own format for the peer state provided it
//! does not reuse `p2pstate.bin`, which a C++ node sharing the data directory
//! would try to read. This one is epee portable storage in
//! [`STATE_FILENAME`].
//!
//! # A stranger's `last_seen` decides nothing
//!
//! Each list is ordered as the C++ orders its `multi_index_container`: by
//! `last_seen`, and among equal ones by arrival. That order decides what is
//! trimmed and what is dialled first, so only this node's own clock sets
//! `last_seen`. A peer list's timestamps are zeroed on the way in
//! (`sanitize_peerlist`), and an address already listed keeps the one it had
//! (`append_with_peer_gray`: "incoming peer list are untrusted").

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use wow_serialize::epee::{self, Section, Value};

use crate::messages::{peer_list_value, NetworkAddress, PeerlistEntry};

/// `P2P_LOCAL_WHITE_PEERLIST_LIMIT`.
pub const WHITE_LIMIT: usize = 1_000;
/// `P2P_LOCAL_GRAY_PEERLIST_LIMIT`.
pub const GRAY_LIMIT: usize = 5_000;
/// `P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT`.
pub const ANCHOR_CONNECTIONS: usize = 2;
/// `P2P_IP_FAILS_BEFORE_BLOCK`.
pub const FAILS_BEFORE_BLOCK: u32 = 10;
/// `P2P_FAILED_ADDR_FORGET_SECONDS`.
pub const FAILED_ADDR_FORGET_SECONDS: u64 = 3_600;
/// `P2P_IP_BLOCKTIME`.
pub const IP_BLOCKTIME: u64 = 86_400;
/// How many of the most recently seen white peers an outgoing connection is
/// chosen among: the `limit` in `make_new_connection_from_peerlist`. The
/// gray list has none.
pub const WHITE_CANDIDATES: usize = 20;

/// `CRYPTONOTE_PRUNING_LOG_STRIPES`.
const PRUNING_LOG_STRIPES: u32 = 3;
/// `PRUNING_SEED_LOG_STRIPES_SHIFT`.
const PRUNING_SEED_LOG_STRIPES_SHIFT: u32 = 7;

/// The peer-state file, beside the database directory. Deliberately not
/// `p2pstate.bin`.
pub const STATE_FILENAME: &str = "p2pstate-rs.bin";

/// The state file's format version.
const STATE_VERSION: u64 = 1;

/// One address this node can dial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    pub addr: SocketAddr,
    pub id: u64,
    /// Unix seconds.
    pub last_seen: i64,
    pub pruning_seed: u32,
    pub rpc_port: u16,
}

impl PeerRecord {
    /// From a peer-list entry, for the address kinds this node can dial.
    pub fn from_entry(e: &PeerlistEntry) -> Option<PeerRecord> {
        Some(PeerRecord {
            addr: e.address.socket_addr()?,
            id: e.id,
            last_seen: e.last_seen,
            pruning_seed: e.pruning_seed,
            rpc_port: e.rpc_port,
        })
    }

    pub fn to_entry(&self) -> PeerlistEntry {
        PeerlistEntry {
            address: NetworkAddress::from_socket_addr(self.addr),
            id: self.id,
            last_seen: self.last_seen,
            pruning_seed: self.pruning_seed,
            rpc_port: self.rpc_port,
        }
    }

    /// `self` in place of `old`, as the C++ updates an entry already listed:
    /// a pruning seed or RPC port `self` lacks is kept from `old` ("guard
    /// against older nodes not passing pruning info around"), and so is
    /// `last_seen`, unless this node has just seen the peer itself.
    fn replacing(self, old: &PeerRecord, trust_last_seen: bool) -> PeerRecord {
        let mut new = self;
        if new.pruning_seed == 0 {
            new.pruning_seed = old.pruning_seed;
        }
        if new.rpc_port == 0 {
            new.rpc_port = old.rpc_port;
        }
        if !trust_last_seen {
            new.last_seen = old.last_seen;
        }
        new
    }
}

/// A list entry, and when it arrived.
#[derive(Clone, Debug)]
struct Listed {
    rec: PeerRecord,
    /// Arrival order. Entries with equal `last_seen` keep it in the C++'s
    /// time index, and every address a peer mentions has a `last_seen` of
    /// zero, so this is what trims the oldest of them first rather than,
    /// say, the one whose address sorts lowest -- which a peer could choose.
    seq: u64,
}

/// Whether two addresses are one host (`is_same_host`).
///
/// Never for loopback. The C++ lists no loopback address at all; this node
/// does only under `--allow-local-ip`, which is for several nodes on one
/// machine, and treating them as one host would leave room for one of them.
fn same_host(a: &SocketAddr, b: &SocketAddr) -> bool {
    a.ip() == b.ip() && !a.ip().is_loopback()
}

/// The host an address counts as when choosing whom to dial: an IPv4-mapped
/// IPv6 address is its IPv4 host, as `get_host_string` has it.
fn host_of(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// The IPv4 /24 an address is in, for the one-peer-per-subnet rule. `None`
/// for IPv6, which the rule does not cover, and for loopback, for the reason
/// [`same_host`] gives.
fn subnet_of(ip: IpAddr) -> Option<u32> {
    match ip.to_canonical() {
        IpAddr::V4(a) if !a.is_loopback() => Some(u32::from(a) & 0xffff_ff00),
        _ => None,
    }
}

/// Whether a pruning seed is one a node could send: none, or
/// `make_pruning_seed(stripe, CRYPTONOTE_PRUNING_LOG_STRIPES)` for a stripe
/// from 1 to 8 (`sanitize_peerlist`).
fn is_valid_pruning_seed(seed: u32) -> bool {
    let first = PRUNING_LOG_STRIPES << PRUNING_SEED_LOG_STRIPES_SHIFT;
    let last = first | ((1 << PRUNING_LOG_STRIPES) - 1);
    seed == 0 || (first..=last).contains(&seed)
}

/// `get_random_index_with_fixed_probability`: an index from `0` to
/// `max_index`, `x³ / (16³ · max_index²)` for a uniform `x` up to
/// `16 · max_index`. The front is heavily favoured: with twenty candidates
/// the first is picked more than a third of the time.
fn weighted_index(max_index: usize, rand_below: &mut dyn FnMut(usize) -> usize) -> usize {
    if max_index == 0 {
        return 0;
    }
    let x = rand_below(16 * max_index + 1);
    x * x * x / (max_index * max_index * 16 * 16 * 16)
}

/// A Fisher-Yates shuffle.
fn shuffle<T>(items: &mut [T], rand_below: &mut dyn FnMut(usize) -> usize) {
    for i in (1..items.len()).rev() {
        items.swap(i, rand_below(i + 1));
    }
}

/// An IPv4 network, as `--ban-list` and `set_bans` accept one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Subnet {
    base: Ipv4Addr,
    prefix: u8,
}

impl Subnet {
    /// `a.b.c.d/nn`. The host bits are cleared, so `10.1.2.3/8` is `10.0.0.0/8`.
    pub fn parse(s: &str) -> Option<Subnet> {
        let (ip, bits) = s.split_once('/')?;
        let ip: Ipv4Addr = ip.trim().parse().ok()?;
        let prefix: u8 = bits.trim().parse().ok()?;
        if prefix > 32 {
            return None;
        }
        Some(Subnet {
            base: Ipv4Addr::from(u32::from(ip) & Self::mask(prefix)),
            prefix,
        })
    }

    fn mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix))
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => u32::from(a) & Self::mask(self.prefix) == u32::from(self.base),
            IpAddr::V6(_) => false,
        }
    }
}

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.base, self.prefix)
    }
}

/// What a ban applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BanTarget {
    Host(IpAddr),
    Subnet(Subnet),
}

impl BanTarget {
    /// A host address, or an IPv4 subnet written `a.b.c.d/nn`.
    pub fn parse(s: &str) -> Option<BanTarget> {
        let s = s.trim();
        if s.contains('/') {
            Subnet::parse(s).map(BanTarget::Subnet)
        } else {
            s.parse().ok().map(BanTarget::Host)
        }
    }

    pub fn covers(&self, ip: IpAddr) -> bool {
        match self {
            BanTarget::Host(h) => *h == ip,
            BanTarget::Subnet(n) => n.contains(ip),
        }
    }
}

impl std::fmt::Display for BanTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BanTarget::Host(h) => write!(f, "{h}"),
            BanTarget::Subnet(n) => write!(f, "{n}"),
        }
    }
}

/// A `--ban-list` file: one address or subnet per line, `#` comments.
///
/// A line that is neither is an error naming it, rather than a ban silently
/// not applied.
pub fn parse_ban_list(text: &str) -> Result<Vec<BanTarget>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        out.push(
            BanTarget::parse(line)
                .ok_or_else(|| format!("line {}: `{line}` is not an address or subnet", n + 1))?,
        );
    }
    Ok(out)
}

/// Whether an address is on the public internet.
///
/// Peer lists are for addresses other nodes can reach, so a private, loopback
/// or link-local one is kept out unless the operator allows it -- a node on a
/// LAN would otherwise gossip `192.168.x.y` to the world.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_documentation()
                || a.is_unspecified()
                || a.is_multicast()
                || o[0] == 0
                // 100.64.0.0/10, carrier-grade NAT.
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(a) => {
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || a.is_unique_local()
                || a.is_unicast_link_local())
        }
    }
}

/// The peer lists and the ban table.
#[derive(Debug, Default)]
pub struct AddressBook {
    white: HashMap<SocketAddr, Listed>,
    gray: HashMap<SocketAddr, Listed>,
    anchors: HashMap<SocketAddr, PeerRecord>,
    /// Target and the unix second the ban ends; `u64::MAX` is indefinite.
    bans: HashMap<BanTarget, u64>,
    /// Failures per address: how many, and when the first of them was.
    fails: HashMap<IpAddr, (u32, u64)>,
    /// Hosts a connection to failed, and when the last one did
    /// (`m_conn_fails_cache`).
    failed_hosts: HashMap<IpAddr, u64>,
    /// The next [`Listed::seq`].
    next_seq: u64,
    allow_local: bool,
}

impl AddressBook {
    /// An empty book. With `allow_local`, private and loopback addresses may
    /// enter the peer lists (`--allow-local-ip`).
    pub fn new(allow_local: bool) -> AddressBook {
        AddressBook {
            allow_local,
            ..Default::default()
        }
    }

    pub fn set_allow_local(&mut self, allow: bool) {
        self.allow_local = allow;
    }

    /// Whether an address may be listed at all.
    pub fn is_listable(&self, addr: &SocketAddr) -> bool {
        addr.port() != 0 && (self.allow_local || is_public(addr.ip()))
    }

    fn listed(&mut self, rec: PeerRecord) -> Listed {
        self.next_seq += 1;
        Listed {
            rec,
            seq: self.next_seq,
        }
    }

    /// An address a peer mentioned (`append_with_peer_gray`). Ignored if it
    /// is already white.
    ///
    /// Already gray, it is updated but keeps its `last_seen`. A peer that
    /// could raise that could keep its own entries away from the trimming,
    /// which starts with the least recently seen.
    pub fn add_gray(&mut self, rec: PeerRecord) {
        if !self.is_listable(&rec.addr) || self.white.contains_key(&rec.addr) {
            return;
        }
        if let Some(existing) = self.gray.get_mut(&rec.addr) {
            existing.rec = rec.replacing(&existing.rec, false);
            return;
        }
        let listed = self.listed(rec);
        self.gray.insert(listed.rec.addr, listed);
        trim(&mut self.gray, GRAY_LIMIT, |_| {});
    }

    /// An address this node verified itself (`append_with_peer_white`).
    ///
    /// New to the white list, it replaces any entry for another port of the
    /// same host (`evict_host_from_peerlist`): one host is one peer, however
    /// many ports it answers on. Already there, it is updated, and takes
    /// `rec`'s `last_seen` only with `trust_last_seen` -- when this node has
    /// just handshaken with or heard from the peer (`set_peer_just_seen`).
    /// A ping-back or an `--add-peer` entry leaves it as it was.
    pub fn add_white(&mut self, rec: PeerRecord, trust_last_seen: bool) {
        if !self.is_listable(&rec.addr) {
            return;
        }
        self.gray.remove(&rec.addr);
        if let Some(existing) = self.white.get_mut(&rec.addr) {
            existing.rec = rec.replacing(&existing.rec, trust_last_seen);
            return;
        }
        let addr = rec.addr;
        self.white.retain(|a, _| !same_host(a, &addr));
        let listed = self.listed(rec);
        self.white.insert(addr, listed);
        let mut evicted = Vec::new();
        trim(&mut self.white, WHITE_LIMIT, |r| evicted.push(r));
        // A peer pushed out of the white list is still a peer; it goes back
        // to being merely known of.
        for r in evicted {
            self.add_gray(r);
        }
    }

    /// A peer list another node sent (`handle_remote_peerlist`).
    ///
    /// Sanitised first, as `sanitize_peerlist` does: an entry that is not a
    /// public address, whose port is its own RPC port, or whose pruning seed
    /// no node could have is dropped, and every `last_seen` is zeroed. Then
    /// merged into the gray list, less hosts this node failed to reach within
    /// the hour or has banned.
    pub fn merge_peerlist(&mut self, peers: &[PeerlistEntry], now: u64) {
        for e in peers {
            let Some(mut rec) = PeerRecord::from_entry(e) else {
                continue;
            };
            let ip = rec.addr.ip();
            if !is_public(ip)
                || (ip.is_ipv4() && rec.addr.port() == rec.rpc_port)
                || !is_valid_pruning_seed(rec.pruning_seed)
                || self.is_addr_recently_failed(ip, now)
                || self.is_banned(ip, now)
            {
                continue;
            }
            rec.last_seen = 0;
            self.add_gray(rec);
        }
    }

    /// Forget a gray address that did not answer the housekeeping check
    /// (`remove_from_peer_gray`).
    pub fn remove_gray(&mut self, addr: &SocketAddr) {
        self.gray.remove(addr);
    }

    /// Note that a connection to `ip` failed (`record_addr_failed`).
    pub fn record_addr_failed(&mut self, ip: IpAddr, now: u64) {
        // What has been forgotten goes, so the table holds an hour at most.
        self.failed_hosts
            .retain(|_, at| now.saturating_sub(*at) <= FAILED_ADDR_FORGET_SECONDS);
        self.failed_hosts.insert(ip, now);
    }

    /// Whether a connection to `ip` failed within the last
    /// [`FAILED_ADDR_FORGET_SECONDS`] (`is_addr_recently_failed`). Such a host
    /// is not dialled from the lists, nor taken from a peer list, until then.
    pub fn is_addr_recently_failed(&self, ip: IpAddr, now: u64) -> bool {
        self.failed_hosts
            .get(&ip)
            .is_some_and(|at| now.saturating_sub(*at) <= FAILED_ADDR_FORGET_SECONDS)
    }

    pub fn add_anchor(&mut self, rec: PeerRecord) {
        if self.is_listable(&rec.addr) {
            self.anchors.insert(rec.addr, rec);
        }
    }

    pub fn remove_anchor(&mut self, addr: &SocketAddr) {
        self.anchors.remove(addr);
    }

    pub fn clear_anchors(&mut self) {
        self.anchors.clear();
    }

    pub fn anchors(&self) -> Vec<PeerRecord> {
        sorted(self.anchors.values().cloned().collect())
    }

    /// The white list, most recently seen first.
    pub fn white(&self) -> Vec<PeerRecord> {
        sorted(self.white.values().map(|l| l.rec.clone()).collect())
    }

    /// The gray list, most recently seen first.
    pub fn gray(&self) -> Vec<PeerRecord> {
        sorted(self.gray.values().map(|l| l.rec.clone()).collect())
    }

    pub fn is_white(&self, addr: &SocketAddr) -> bool {
        self.white.contains_key(addr)
    }

    /// `(white, gray)` sizes.
    pub fn counts(&self) -> (usize, usize) {
        (self.white.len(), self.gray.len())
    }

    /// The next address to dial from one list, chosen as
    /// `make_new_connection_from_peerlist` chooses it (`p2p/net_node.inl`).
    ///
    /// * One port per host: of a host's entries only the most recently seen
    ///   is a candidate, so a host cannot weigh the choice by advertising many
    ///   ports.
    /// * One peer per /24: the candidates are gone through in random order,
    ///   taking one from each IPv4 /24 that none of `connected` is in, and put
    ///   back in `last_seen` order. Only when that leaves none that can be
    ///   used is the rule dropped.
    /// * From the white list, one of the [`WHITE_CANDIDATES`] most recently
    ///   seen, weighted heavily towards the most recent; from the gray list,
    ///   any, uniformly.
    ///
    /// `unusable` rejects a candidate that is connected, banned or failed
    /// recently. The C++ rejects those after picking, and picks again, three
    /// times at most; leaving them out before the pick makes the same choice
    /// without the limit.
    ///
    /// `rand_below(n)` returns a uniformly random value in `0..n`.
    pub fn pick(
        &self,
        from_white: bool,
        connected: &[SocketAddr],
        rand_below: &mut dyn FnMut(usize) -> usize,
        unusable: &dyn Fn(&PeerRecord) -> bool,
    ) -> Option<PeerRecord> {
        let list = if from_white { &self.white } else { &self.gray };
        // Most recently seen first and, of equal `last_seen`, the latest to
        // arrive, as the C++ walks its time index from the end.
        let mut by_time: Vec<&Listed> = list.values().collect();
        by_time.sort_by_key(|a| std::cmp::Reverse((a.rec.last_seen, a.seq)));

        let mut hosts = HashSet::new();
        let peers: Vec<&PeerRecord> = by_time
            .into_iter()
            .map(|l| &l.rec)
            .filter(|r| r.addr.ip().is_loopback() || hosts.insert(host_of(r.addr.ip())))
            .collect();

        let mut subnets: HashSet<u32> =
            connected.iter().filter_map(|a| subnet_of(a.ip())).collect();
        let mut shuffled = peers.clone();
        shuffle(&mut shuffled, rand_below);
        let mut one_per_subnet: Vec<&PeerRecord> = shuffled
            .into_iter()
            .filter(|r| subnet_of(r.addr.ip()).is_none_or(|s| subnets.insert(s)))
            .collect();
        one_per_subnet.sort_by_key(|a| std::cmp::Reverse(a.last_seen));

        let limit = if from_white {
            WHITE_CANDIDATES
        } else {
            usize::MAX
        };
        let mut filtered: Vec<&PeerRecord> = Vec::new();
        for candidates in [one_per_subnet, peers] {
            filtered = candidates
                .into_iter()
                .filter(|r| !unusable(r))
                .take(limit)
                .collect();
            if !filtered.is_empty() {
                break;
            }
        }
        if filtered.is_empty() {
            return None;
        }
        let i = if from_white {
            weighted_index(filtered.len() - 1, rand_below)
        } else {
            rand_below(filtered.len())
        };
        filtered.get(i).copied().cloned()
    }

    /// A gray address chosen uniformly, for the housekeeping that checks one
    /// a minute (`get_random_gray_peer`).
    pub fn random_gray(&self, rand_below: &mut dyn FnMut(usize) -> usize) -> Option<PeerRecord> {
        if self.gray.is_empty() {
            return None;
        }
        let i = rand_below(self.gray.len());
        self.gray.values().nth(i).map(|l| l.rec.clone())
    }

    /// Up to `n` white peers for a handshake or timed-sync response, picked
    /// as `get_peerlist_head(..., anonymize = true, depth = n)` picks them
    /// (`p2p/net_peerlist.h`).
    ///
    /// At random from the whole white list, and with `last_seen` zeroed.
    /// This node sets a peer's `last_seen` when it connects to it or the peer
    /// answers a ping-back, so the real timestamps -- or a list that took the
    /// `n` most recently seen -- would tell anyone who asks which peers this
    /// node is connected to right now, its Dandelion++ stems among them. The
    /// C++ comment cites Cao et al., "Exploring the Monero Peer-to-Peer
    /// Network", for the attack.
    pub fn handshake_peers(
        &self,
        n: usize,
        rand_below: &mut dyn FnMut(usize) -> usize,
    ) -> Vec<PeerlistEntry> {
        let mut all: Vec<&PeerRecord> = self.white.values().map(|l| &l.rec).collect();
        // A partial Fisher-Yates: only the first `n` places need shuffling,
        // which picks the same way as the C++'s whole shuffle and truncate.
        let take = n.min(all.len());
        for i in 0..take {
            let j = i + rand_below(all.len() - i);
            all.swap(i, j);
        }
        all.into_iter()
            .take(take)
            .map(|r| PeerlistEntry {
                last_seen: 0,
                ..r.to_entry()
            })
            .collect()
    }

    // ---------------------------------------------------------------- bans

    /// Ban for `seconds` from `now`; `u64::MAX` bans indefinitely.
    pub fn ban(&mut self, target: BanTarget, seconds: u64, now: u64) {
        self.bans.insert(target, now.saturating_add(seconds));
    }

    pub fn unban(&mut self, target: &BanTarget) -> bool {
        if let BanTarget::Host(ip) = target {
            self.fails.remove(ip);
        }
        self.bans.remove(target).is_some()
    }

    /// Whether `ip` is covered by a ban in force. Expired bans are dropped as
    /// a side effect.
    pub fn is_banned(&mut self, ip: IpAddr, now: u64) -> bool {
        self.bans.retain(|_, until| *until > now);
        self.bans.keys().any(|t| t.covers(ip))
    }

    /// The bans in force, with the seconds each has left.
    pub fn bans(&mut self, now: u64) -> Vec<(BanTarget, u64)> {
        self.bans.retain(|_, until| *until > now);
        let mut out: Vec<(BanTarget, u64)> = self
            .bans
            .iter()
            .map(|(t, until)| (*t, until.saturating_sub(now)))
            .collect();
        out.sort_by_key(|(t, _)| t.to_string());
        out
    }

    /// Count a failure against `ip`. The tenth within
    /// [`FAILED_ADDR_FORGET_SECONDS`] bans it for [`IP_BLOCKTIME`], and this
    /// returns true when that happens.
    pub fn record_failure(&mut self, ip: IpAddr, now: u64) -> bool {
        // Counts whose hour has passed go, as `record_addr_failed`'s do. An
        // entry below the ban threshold was otherwise only ever reset, never
        // removed -- the C++'s `host_count` leak -- so a stranger cycling
        // through addresses (one IPv6 /64 is plenty) grew the table without
        // end, one malformed handshake at a time.
        self.fails
            .retain(|_, (_, first)| now.saturating_sub(*first) <= FAILED_ADDR_FORGET_SECONDS);
        let entry = self.fails.entry(ip).or_insert((0, now));
        if now.saturating_sub(entry.1) > FAILED_ADDR_FORGET_SECONDS {
            *entry = (0, now);
        }
        entry.0 += 1;
        if entry.0 >= FAILS_BEFORE_BLOCK {
            self.fails.remove(&ip);
            self.ban(BanTarget::Host(ip), IP_BLOCKTIME, now);
            return true;
        }
        false
    }

    // --------------------------------------------------------- persistence

    pub fn to_bytes(&self) -> Vec<u8> {
        let entries = |records: Vec<PeerRecord>| {
            peer_list_value(&records.iter().map(PeerRecord::to_entry).collect::<Vec<_>>())
        };
        let mut s = Section::new();
        s.insert("version".into(), Value::U64(STATE_VERSION));
        s.insert("white".into(), entries(self.white()));
        s.insert("gray".into(), entries(self.gray()));
        s.insert("anchor".into(), entries(self.anchors()));
        let bans = self
            .bans
            .iter()
            .map(|(t, until)| {
                let mut b = Section::new();
                b.insert("target".into(), Value::String(t.to_string().into_bytes()));
                b.insert("until".into(), Value::U64(*until));
                b
            })
            .collect();
        s.insert("bans".into(), crate::messages::section_array(bans));
        epee::to_bytes(&s).unwrap_or_default()
    }

    /// Read a saved book. Entries that do not parse are skipped: losing one
    /// remembered peer is better than refusing to start.
    pub fn from_bytes(bytes: &[u8], allow_local: bool) -> Result<AddressBook, String> {
        let s = epee::from_bytes(bytes).map_err(|e| format!("not a peer-state file: {e}"))?;
        let version = s.get("version").and_then(Value::as_u64).unwrap_or(0);
        if version != STATE_VERSION {
            return Err(format!(
                "peer-state version {version}, expected {STATE_VERSION}"
            ));
        }

        let records = |name: &str| -> Vec<PeerRecord> {
            s.get(name)
                .and_then(Value::as_array)
                .map(|a| {
                    a.items
                        .iter()
                        .filter_map(Value::as_object)
                        .filter_map(|e| PeerlistEntry::from_section(e).ok())
                        .filter_map(|e| PeerRecord::from_entry(&e))
                        .collect()
                })
                .unwrap_or_default()
        };

        // The lists are saved most recently seen first. Read back oldest
        // first, so they arrive in the order they are kept in, and of two
        // entries for one host the white list keeps the more recent.
        let mut book = AddressBook::new(allow_local);
        for r in records("white").into_iter().rev() {
            book.add_white(r, true);
        }
        for r in records("gray").into_iter().rev() {
            book.add_gray(r);
        }
        for r in records("anchor") {
            book.add_anchor(r);
        }
        if let Some(a) = s.get("bans").and_then(Value::as_array) {
            for b in a.items.iter().filter_map(Value::as_object) {
                let target = b
                    .get("target")
                    .and_then(Value::as_bytes)
                    .and_then(|t| std::str::from_utf8(t).ok())
                    .and_then(BanTarget::parse);
                let until = b.get("until").and_then(Value::as_u64);
                if let (Some(t), Some(u)) = (target, until) {
                    book.bans.insert(t, u);
                }
            }
        }
        Ok(book)
    }

    /// Write to `path`, through a temporary file so a crash mid-write leaves
    /// the previous state rather than half of this one.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.to_bytes())?;
        std::fs::rename(&tmp, path)
    }

    /// Read from `path`. A missing file is an empty book.
    pub fn load(path: &Path, allow_local: bool) -> Result<AddressBook, String> {
        match std::fs::read(path) {
            Ok(bytes) => AddressBook::from_bytes(&bytes, allow_local),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AddressBook::new(allow_local)),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }
}

fn sorted(mut v: Vec<PeerRecord>) -> Vec<PeerRecord> {
    v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.addr.cmp(&b.addr)));
    v
}

/// Drop entries from the front of the C++'s time order -- least recently
/// seen, and of those the first to arrive -- until `m` fits, handing each to
/// `evicted` (`trim_gray_peerlist`, `trim_white_peerlist`).
fn trim(m: &mut HashMap<SocketAddr, Listed>, limit: usize, mut evicted: impl FnMut(PeerRecord)) {
    if m.len() <= limit {
        return;
    }
    let mut by_age: Vec<(i64, u64, SocketAddr)> = m
        .values()
        .map(|l| (l.rec.last_seen, l.seq, l.rec.addr))
        .collect();
    by_age.sort();
    for (_, _, addr) in by_age.into_iter().take(m.len() - limit) {
        if let Some(l) = m.remove(&addr) {
            evicted(l.rec);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(addr: &str, last_seen: i64) -> PeerRecord {
        PeerRecord {
            addr: addr.parse().unwrap(),
            id: last_seen as u64,
            last_seen,
            pruning_seed: 0,
            rpc_port: 0,
        }
    }

    fn first(_: usize) -> usize {
        0
    }

    fn entry(addr: &str, last_seen: i64, pruning_seed: u32, rpc_port: u16) -> PeerlistEntry {
        PeerlistEntry {
            address: NetworkAddress::from_socket_addr(addr.parse().unwrap()),
            id: 1,
            last_seen,
            pruning_seed,
            rpc_port,
        }
    }

    fn never(_: &PeerRecord) -> bool {
        false
    }

    #[test]
    fn a_verified_peer_moves_from_gray_to_white() {
        let mut b = AddressBook::new(false);
        b.add_gray(rec("8.8.8.8:34567", 1));
        assert_eq!(b.counts(), (0, 1));

        b.add_white(rec("8.8.8.8:34567", 2), true);
        assert_eq!(b.counts(), (1, 0), "promotion removes it from gray");

        // Mentioned again by a peer, it stays white.
        b.add_gray(rec("8.8.8.8:34567", 3));
        assert_eq!(b.counts(), (1, 0));
    }

    /// A private or loopback address stays out of the lists unless allowed,
    /// so a LAN node does not gossip its neighbours to the internet.
    #[test]
    fn local_addresses_are_kept_out_unless_allowed() {
        let mut b = AddressBook::new(false);
        for a in [
            "127.0.0.1:34567",
            "192.168.1.5:34567",
            "10.0.0.1:34567",
            "[::1]:34567",
            "8.8.8.8:0",
        ] {
            b.add_gray(rec(a, 1));
            b.add_white(rec(a, 1), true);
        }
        assert_eq!(b.counts(), (0, 0));

        let mut b = AddressBook::new(true);
        b.add_white(rec("127.0.0.1:34567", 1), true);
        assert_eq!(b.counts(), (1, 0));
    }

    /// Past the white limit the least recently seen peer drops back to gray
    /// rather than vanishing.
    #[test]
    fn the_white_list_is_capped_by_age() {
        let mut b = AddressBook::new(true);
        for i in 0..WHITE_LIMIT as i64 + 1 {
            let addr = format!("10.1.{}.{}:1", i / 256, i % 256);
            b.add_white(rec(&addr, i + 1), true);
        }
        assert_eq!(b.counts(), (WHITE_LIMIT, 1));
        assert_eq!(b.gray()[0].last_seen, 1, "the oldest was evicted");
    }

    /// Only this node's own clock moves `last_seen`. A peer mentioning an
    /// address again cannot, nor can a ping-back; a handshake can. What an
    /// update leaves out -- a pruning seed, an RPC port -- is kept.
    #[test]
    fn only_this_node_moves_last_seen() {
        let mut b = AddressBook::new(false);
        let mut first_mention = rec("8.8.8.8:34567", 0);
        first_mention.pruning_seed = 385;
        b.add_gray(first_mention);
        let mut again = rec("8.8.8.8:34567", i64::MAX);
        again.rpc_port = 34_568;
        b.add_gray(again);
        let gray = b.gray();
        assert_eq!(gray[0].last_seen, 0);
        assert_eq!((gray[0].pruning_seed, gray[0].rpc_port), (385, 34_568));

        b.add_white(rec("9.9.9.9:34567", 100), true);
        b.add_white(rec("9.9.9.9:34567", 200), false);
        assert_eq!(b.white()[0].last_seen, 100, "a ping-back leaves it");
        b.add_white(rec("9.9.9.9:34567", 300), true);
        assert_eq!(b.white()[0].last_seen, 300, "a handshake moves it");
    }

    /// The gray list is trimmed first come, first gone. Everything a peer
    /// mentions has a `last_seen` of zero, so an address that happens to sort
    /// high must not be what keeps an entry in.
    #[test]
    fn the_gray_list_trims_the_first_to_arrive() {
        let mut b = AddressBook::new(false);
        let high: SocketAddr = "223.255.255.1:34567".parse().unwrap();
        b.add_gray(rec(&high.to_string(), 0));
        for i in 0..GRAY_LIMIT - 1 {
            b.add_gray(rec(&format!("8.{}.{}.1:34567", i / 256, i % 256), 0));
        }
        assert_eq!(b.counts(), (0, GRAY_LIMIT));

        b.add_gray(rec("9.0.0.1:34567", 0));
        assert_eq!(b.counts(), (0, GRAY_LIMIT));
        let gray = b.gray();
        assert!(
            !gray.iter().any(|r| r.addr == high),
            "the first to arrive went"
        );
        assert!(gray.iter().any(|r| r.addr.to_string() == "8.0.0.1:34567"));
    }

    /// A peer list is sanitised as the C++ sanitises one: public addresses
    /// only, whatever `--allow-local-ip` says; not a port that is the entry's
    /// own RPC port, nor a pruning seed no node could have; `last_seen`
    /// zeroed; and nothing from a host that failed within the hour or is
    /// banned.
    #[test]
    fn a_peer_list_is_sanitised_on_the_way_in() {
        let mut b = AddressBook::new(true);
        let now = 10_000;
        b.record_addr_failed("7.7.7.7".parse().unwrap(), now - 60);
        b.ban(BanTarget::parse("6.6.6.0/24").unwrap(), 3_600, now);
        b.merge_peerlist(
            &[
                entry("8.8.8.8:34567", 1_700_000_000, 0, 34_568),
                entry("9.9.9.9:34567", 0, 385, 0),
                entry("192.168.1.5:34567", 0, 0, 0),
                entry("127.0.0.1:34567", 0, 0, 0),
                entry("1.1.1.1:34568", 0, 0, 34_568),
                entry("2.2.2.2:34567", 0, 7, 0),
                entry("7.7.7.7:34567", 0, 0, 0),
                entry("6.6.6.6:34567", 0, 0, 0),
            ],
            now,
        );
        let gray = b.gray();
        assert_eq!(
            gray.iter().map(|r| r.addr.to_string()).collect::<Vec<_>>(),
            ["8.8.8.8:34567", "9.9.9.9:34567"]
        );
        assert!(
            gray.iter().all(|r| r.last_seen == 0),
            "a stranger's timestamps are not kept"
        );

        // An hour on, the host that failed is taken again.
        b.merge_peerlist(
            &[entry("7.7.7.7:34567", 0, 0, 0)],
            now + FAILED_ADDR_FORGET_SECONDS,
        );
        assert_eq!(b.counts(), (0, 3));
    }

    /// One host is one white peer: a new port replaces the old. Loopback is
    /// the exception, for several nodes on one machine.
    #[test]
    fn a_host_has_one_white_entry() {
        let mut b = AddressBook::new(true);
        b.add_white(rec("8.8.8.8:34567", 1), true);
        b.add_white(rec("8.8.8.8:28080", 2), true);
        assert_eq!(b.white().len(), 1);
        assert_eq!(b.white()[0].addr.port(), 28_080);

        b.add_white(rec("127.0.0.1:34567", 3), true);
        b.add_white(rec("127.0.0.1:34568", 4), true);
        assert_eq!(b.counts(), (3, 0));
    }

    /// A host that could not be reached is left alone for an hour.
    #[test]
    fn a_failed_host_is_skipped_for_an_hour() {
        let mut b = AddressBook::new(false);
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!b.is_addr_recently_failed(ip, 100));
        b.record_addr_failed(ip, 100);
        let an_hour_on = 100 + FAILED_ADDR_FORGET_SECONDS;
        assert!(b.is_addr_recently_failed(ip, an_hour_on));
        assert!(!b.is_addr_recently_failed(ip, an_hour_on + 1));
        assert!(!b.is_addr_recently_failed("8.8.4.4".parse().unwrap(), 100));
    }

    /// A host on several ports is one candidate, the port most recently seen.
    /// If that one cannot be used, the host is not dialled on another.
    #[test]
    fn a_host_is_one_candidate_however_many_ports() {
        let mut b = AddressBook::new(false);
        b.add_gray(rec("8.8.8.8:34567", 0));
        b.add_gray(rec("8.8.8.8:28080", 0));
        let picked = b.pick(false, &[], &mut first, &never).unwrap();
        assert_eq!(
            picked.addr.port(),
            28_080,
            "of equal last_seen, the later arrival"
        );
        let not_that = |r: &PeerRecord| r.addr.port() == 28_080;
        assert_eq!(b.pick(false, &[], &mut first, &not_that), None);
        assert!(AddressBook::new(false).random_gray(&mut first).is_none());
    }

    /// Not a second peer in a /24 this node is connected to while another
    /// subnet offers one, however much more recently seen. With nothing
    /// usable elsewhere, the rule gives way.
    #[test]
    fn a_connected_subnet_is_passed_over() {
        let mut b = AddressBook::new(false);
        b.add_white(rec("1.2.3.4:34567", 100), true);
        b.add_white(rec("5.6.7.8:34567", 1), true);
        let connected: [SocketAddr; 1] = ["1.2.3.200:34567".parse().unwrap()];

        let picked = b.pick(true, &connected, &mut first, &never).unwrap();
        assert_eq!(picked.addr.to_string(), "5.6.7.8:34567");

        let failed = |r: &PeerRecord| r.last_seen == 1;
        let picked = b.pick(true, &connected, &mut first, &failed).unwrap();
        assert_eq!(picked.addr.to_string(), "1.2.3.4:34567");
    }

    /// From the white list, one of the twenty most recently seen, the most
    /// recent favoured; from the gray list, any of them.
    #[test]
    fn white_candidates_are_the_most_recently_seen() {
        let mut b = AddressBook::new(false);
        for i in 1..=30 {
            b.add_white(rec(&format!("8.8.{i}.1:34567"), i), true);
            b.add_gray(rec(&format!("9.9.{i}.1:34567"), i));
        }
        let mut last = |n: usize| n - 1;
        let white = b.pick(true, &[], &mut last, &never).unwrap();
        assert_eq!(white.last_seen, 11, "the twentieth most recent at most");
        let gray = b.pick(false, &[], &mut last, &never).unwrap();
        assert_eq!(gray.last_seen, 1, "the least recent of all thirty");
        let white = b.pick(true, &[], &mut first, &never).unwrap();
        assert_eq!(white.last_seen, 30);
    }

    /// `get_random_index_with_fixed_probability`, at its ends and between.
    #[test]
    fn the_weighted_index_favours_the_front() {
        assert_eq!(weighted_index(0, &mut first), 0);
        assert_eq!(weighted_index(19, &mut first), 0);
        assert_eq!(weighted_index(19, &mut |n: usize| n - 1), 19);
        // 160³ / (16³ · 19²) = 4 096 000 / 1 478 656.
        assert_eq!(weighted_index(19, &mut |_: usize| 160), 2);
        // Of the 305 values x takes, 0 to 113 give the first candidate.
        let front = (0..305)
            .filter(|&x| weighted_index(19, &mut |_: usize| x) == 0)
            .count();
        assert_eq!(front, 114);
    }

    /// A handshake offers white peers only, at most the number asked for.
    #[test]
    fn handshake_peers_come_from_the_white_list() {
        let mut b = AddressBook::new(false);
        for i in 0..10 {
            b.add_white(rec(&format!("8.8.8.{i}:34567"), i), true);
        }
        b.add_gray(rec("9.9.9.9:34567", 100));

        let offered = b.handshake_peers(4, &mut first);
        assert_eq!(offered.len(), 4);
        assert!(offered
            .iter()
            .all(|e| e.address.socket_addr().unwrap().ip().to_string() != "9.9.9.9"));
        assert_eq!(b.handshake_peers(250, &mut first).len(), 10);
    }

    /// A shared peer carries no `last_seen`: the real one says when this node
    /// last connected to that peer, which is who it is connected to now.
    #[test]
    fn shared_peers_do_not_say_when_they_were_seen() {
        let mut b = AddressBook::new(false);
        for i in 1..=5 {
            let seen = 1_700_000_000 + i;
            b.add_white(rec(&format!("8.8.8.{i}:34567"), seen), true);
        }
        let offered = b.handshake_peers(250, &mut first);
        assert_eq!(offered.len(), 5);
        assert!(offered.iter().all(|e| e.last_seen == 0));
        assert!(
            offered.iter().all(|e| e.id != 0),
            "only the timestamp is hidden"
        );

        // The book itself keeps them, for its own choices and the state file.
        assert!(b.white().iter().all(|r| r.last_seen >= 1_700_000_001));
    }

    #[test]
    fn bans_cover_hosts_and_subnets_and_expire() {
        let mut b = AddressBook::new(false);
        let host: IpAddr = "1.2.3.4".parse().unwrap();
        b.ban(BanTarget::Host(host), 100, 1_000);
        assert!(b.is_banned(host, 1_050));
        assert!(!b.is_banned(host, 1_100), "expired at the deadline");

        b.ban(BanTarget::parse("10.20.0.0/16").unwrap(), u64::MAX, 0);
        assert!(b.is_banned("10.20.99.1".parse().unwrap(), 5));
        assert!(!b.is_banned("10.21.0.1".parse().unwrap(), 5));
        assert_eq!(b.bans(5).len(), 1);

        assert!(b.unban(&BanTarget::parse("10.20.0.0/16").unwrap()));
        assert!(!b.is_banned("10.20.99.1".parse().unwrap(), 5));
    }

    /// The tenth failure within the hour bans the address for a day
    /// (`specs/08` §8.2); failures older than the hour are forgotten.
    #[test]
    fn ten_failures_in_an_hour_ban_for_a_day() {
        let mut b = AddressBook::new(false);
        let ip: IpAddr = "5.6.7.8".parse().unwrap();
        for i in 0..FAILS_BEFORE_BLOCK - 1 {
            assert!(!b.record_failure(ip, 100 + u64::from(i)));
        }
        assert!(b.record_failure(ip, 200), "the tenth bans");
        assert!(b.is_banned(ip, 200 + IP_BLOCKTIME - 1));

        let other: IpAddr = "5.6.7.9".parse().unwrap();
        for _ in 0..FAILS_BEFORE_BLOCK - 1 {
            b.record_failure(other, 0);
        }
        assert!(
            !b.record_failure(other, FAILED_ADDR_FORGET_SECONDS + 1),
            "the earlier nine were forgotten"
        );
    }

    /// A failure count is dropped once its hour is over, not only reset when
    /// the same address fails again: otherwise every address that ever sent
    /// one bad handshake stayed in the table for good.
    #[test]
    fn stale_failure_counts_are_removed() {
        let mut b = AddressBook::new(false);
        for i in 0..100u8 {
            b.record_failure(IpAddr::from([7, 7, 7, i]), 0);
        }
        assert_eq!(b.fails.len(), 100);
        b.record_failure("8.8.8.8".parse().unwrap(), FAILED_ADDR_FORGET_SECONDS + 1);
        assert_eq!(b.fails.len(), 1, "only the fresh count is left");
    }

    #[test]
    fn a_ban_list_file_parses_or_names_the_bad_line() {
        let text = "# bad actors\n1.2.3.4\n\n  10.0.0.0/8  # a whole network\n2001:db8::1\n";
        let list = parse_ban_list(text).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[1].to_string(), "10.0.0.0/8");

        let e = parse_ban_list("1.2.3.4\nnot-an-address\n").unwrap_err();
        assert!(e.contains("line 2"), "{e}");
        assert!(Subnet::parse("1.2.3.4/33").is_none());
    }

    /// Peers, anchors and bans survive a save and a load.
    #[test]
    fn the_book_survives_a_restart() {
        let mut b = AddressBook::new(false);
        b.add_white(rec("8.8.8.8:34567", 10), true);
        b.add_white(rec("8.8.4.4:34567", 12), true);
        b.add_gray(rec("9.9.9.9:34567", 5));
        b.add_gray(rec("9.9.9.10:34567", 0));
        b.add_gray(rec("9.9.9.11:34567", 0));
        b.add_anchor(rec("1.1.1.1:34567", 7));
        b.ban(BanTarget::parse("4.4.4.4").unwrap(), u64::MAX, 0);

        let mut back = AddressBook::from_bytes(&b.to_bytes(), false).unwrap();
        assert_eq!(back.white(), b.white());
        assert_eq!(back.gray(), b.gray());
        assert_eq!(back.anchors(), b.anchors());
        assert!(back.is_banned("4.4.4.4".parse().unwrap(), 1));

        assert!(AddressBook::from_bytes(b"not epee", false).is_err());
    }
}
