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

use std::collections::HashMap;
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
    white: HashMap<SocketAddr, PeerRecord>,
    gray: HashMap<SocketAddr, PeerRecord>,
    anchors: HashMap<SocketAddr, PeerRecord>,
    /// Target and the unix second the ban ends; `u64::MAX` is indefinite.
    bans: HashMap<BanTarget, u64>,
    /// Failures per address: how many, and when the first of them was.
    fails: HashMap<IpAddr, (u32, u64)>,
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

    /// An address a peer mentioned. Ignored if it is already white.
    pub fn add_gray(&mut self, rec: PeerRecord) {
        if !self.is_listable(&rec.addr) || self.white.contains_key(&rec.addr) {
            return;
        }
        match self.gray.get_mut(&rec.addr) {
            Some(existing) => {
                if rec.last_seen > existing.last_seen {
                    *existing = rec;
                }
            }
            None => {
                self.gray.insert(rec.addr, rec);
            }
        }
        trim(&mut self.gray, GRAY_LIMIT, |_| {});
    }

    /// An address this node verified itself.
    pub fn add_white(&mut self, rec: PeerRecord) {
        if !self.is_listable(&rec.addr) {
            return;
        }
        self.gray.remove(&rec.addr);
        self.white.insert(rec.addr, rec);
        let mut evicted = Vec::new();
        trim(&mut self.white, WHITE_LIMIT, |r| evicted.push(r));
        // A peer pushed out of the white list is still a peer; it goes back
        // to being merely known of.
        for r in evicted {
            self.add_gray(r);
        }
    }

    /// Forget an address that could not be reached.
    ///
    /// A white one is demoted to gray rather than dropped -- it answered once,
    /// and a node that is down for an hour should not vanish from every list
    /// it was on.
    pub fn failed_to_reach(&mut self, addr: &SocketAddr) {
        self.gray.remove(addr);
        if let Some(r) = self.white.remove(addr) {
            self.gray.insert(r.addr, r);
        }
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
        sorted(&self.anchors)
    }

    /// The white list, most recently seen first.
    pub fn white(&self) -> Vec<PeerRecord> {
        sorted(&self.white)
    }

    /// The gray list, most recently seen first.
    pub fn gray(&self) -> Vec<PeerRecord> {
        sorted(&self.gray)
    }

    pub fn is_white(&self, addr: &SocketAddr) -> bool {
        self.white.contains_key(addr)
    }

    /// `(white, gray)` sizes.
    pub fn counts(&self) -> (usize, usize) {
        (self.white.len(), self.gray.len())
    }

    /// A random address from one list, skipping those `skip` rejects.
    ///
    /// `rand_below(n)` returns a uniformly random value in `0..n`.
    pub fn pick(
        &self,
        from_white: bool,
        rand_below: &mut dyn FnMut(usize) -> usize,
        skip: &dyn Fn(&SocketAddr) -> bool,
    ) -> Option<PeerRecord> {
        let list = if from_white { &self.white } else { &self.gray };
        let candidates: Vec<&PeerRecord> = list.values().filter(|r| !skip(&r.addr)).collect();
        if candidates.is_empty() {
            return None;
        }
        Some(candidates[rand_below(candidates.len())].clone())
    }

    /// Up to `n` white peers, chosen at random, for a handshake or timed-sync
    /// response.
    pub fn handshake_peers(
        &self,
        n: usize,
        rand_below: &mut dyn FnMut(usize) -> usize,
    ) -> Vec<PeerlistEntry> {
        let mut all: Vec<&PeerRecord> = self.white.values().collect();
        // A partial Fisher-Yates: only the first `n` places need shuffling.
        let take = n.min(all.len());
        for i in 0..take {
            let j = i + rand_below(all.len() - i);
            all.swap(i, j);
        }
        all.into_iter()
            .take(take)
            .map(PeerRecord::to_entry)
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
        let entries = |m: &HashMap<SocketAddr, PeerRecord>| {
            peer_list_value(
                &sorted(m)
                    .iter()
                    .map(PeerRecord::to_entry)
                    .collect::<Vec<_>>(),
            )
        };
        let mut s = Section::new();
        s.insert("version".into(), Value::U64(STATE_VERSION));
        s.insert("white".into(), entries(&self.white));
        s.insert("gray".into(), entries(&self.gray));
        s.insert("anchor".into(), entries(&self.anchors));
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

        let mut book = AddressBook::new(allow_local);
        for r in records("white") {
            book.add_white(r);
        }
        for r in records("gray") {
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

fn sorted(m: &HashMap<SocketAddr, PeerRecord>) -> Vec<PeerRecord> {
    let mut v: Vec<PeerRecord> = m.values().cloned().collect();
    v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.addr.cmp(&b.addr)));
    v
}

/// Drop the least recently seen entries until `m` fits, handing each to
/// `evicted`.
fn trim(
    m: &mut HashMap<SocketAddr, PeerRecord>,
    limit: usize,
    mut evicted: impl FnMut(PeerRecord),
) {
    if m.len() <= limit {
        return;
    }
    let mut by_age: Vec<(i64, SocketAddr)> = m.values().map(|r| (r.last_seen, r.addr)).collect();
    by_age.sort();
    for (_, addr) in by_age.into_iter().take(m.len() - limit) {
        if let Some(r) = m.remove(&addr) {
            evicted(r);
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

    #[test]
    fn a_verified_peer_moves_from_gray_to_white() {
        let mut b = AddressBook::new(false);
        b.add_gray(rec("8.8.8.8:34567", 1));
        assert_eq!(b.counts(), (0, 1));

        b.add_white(rec("8.8.8.8:34567", 2));
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
            b.add_white(rec(a, 1));
        }
        assert_eq!(b.counts(), (0, 0));

        let mut b = AddressBook::new(true);
        b.add_white(rec("127.0.0.1:34567", 1));
        assert_eq!(b.counts(), (1, 0));
    }

    /// Past the white limit the least recently seen peer drops back to gray
    /// rather than vanishing.
    #[test]
    fn the_white_list_is_capped_by_age() {
        let mut b = AddressBook::new(true);
        for i in 0..WHITE_LIMIT as i64 + 1 {
            b.add_white(rec(&format!("10.1.{}.{}:1", i / 256, i % 256), i + 1));
        }
        assert_eq!(b.counts(), (WHITE_LIMIT, 1));
        assert_eq!(b.gray()[0].last_seen, 1, "the oldest was evicted");
    }

    #[test]
    fn failing_to_reach_a_white_peer_demotes_it() {
        let mut b = AddressBook::new(false);
        b.add_white(rec("8.8.8.8:1", 1));
        b.failed_to_reach(&"8.8.8.8:1".parse().unwrap());
        assert_eq!(b.counts(), (0, 1));
        b.failed_to_reach(&"8.8.8.8:1".parse().unwrap());
        assert_eq!(b.counts(), (0, 0), "a gray one is forgotten");
    }

    /// A handshake offers white peers only, at most the number asked for.
    #[test]
    fn handshake_peers_come_from_the_white_list() {
        let mut b = AddressBook::new(false);
        for i in 0..10 {
            b.add_white(rec(&format!("8.8.8.{i}:34567"), i));
        }
        b.add_gray(rec("9.9.9.9:34567", 100));

        let offered = b.handshake_peers(4, &mut first);
        assert_eq!(offered.len(), 4);
        assert!(offered
            .iter()
            .all(|e| e.address.socket_addr().unwrap().ip().to_string() != "9.9.9.9"));
        assert_eq!(b.handshake_peers(250, &mut first).len(), 10);
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
        b.add_white(rec("8.8.8.8:34567", 10));
        b.add_gray(rec("9.9.9.9:34567", 5));
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
