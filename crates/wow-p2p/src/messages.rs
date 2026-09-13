//! The structures peers exchange (`specs/08` §3).
//!
//! Every one of these is epee portable storage, and the entry names below are
//! the exact ones on the wire — a C++ node looks them up by name, so a rename
//! is a break.
//!
//! # Everything here parses bytes a stranger chose
//!
//! A peer is unauthenticated. `specs/15` §4.4 governs: **never panic**. Every
//! function below returns a `Result`, no slice is indexed without a length
//! check, and no length a peer sends is used to size an allocation without
//! being bounded first.

use wow_serialize::epee::{self, Array, Section, Value};

/// `NETWORK_ID` (`specs/01` §2.1). Sixteen bytes, sent verbatim, and the fork
/// guard: a peer with a different value is on another chain.
pub const NETWORK_ID_MAINNET: [u8; 16] = [
    0x11, 0x33, 0xFF, 0x77, 0x61, 0x04, 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x10,
];
pub const NETWORK_ID_TESTNET: [u8; 16] = [
    0x12, 0x30, 0xF1, 0x71, 0x61, 0x04, 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x11,
];
pub const NETWORK_ID_STAGENET: [u8; 16] = [
    0x12, 0x30, 0xF1, 0x71, 0x61, 0x04, 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x12,
];

/// The network id for a network. `Fakechain` uses mainnet's config block.
pub fn network_id(network: wow_types::Network) -> [u8; 16] {
    match network.config() {
        wow_types::Network::Testnet => NETWORK_ID_TESTNET,
        wow_types::Network::Stagenet => NETWORK_ID_STAGENET,
        _ => NETWORK_ID_MAINNET,
    }
}

/// The default P2P port for a network (`specs/01` §2).
pub fn default_port(network: wow_types::Network) -> u16 {
    match network.config() {
        wow_types::Network::Testnet => 28080,
        wow_types::Network::Stagenet => 38080,
        _ => 34567,
    }
}

/// `P2P_MAX_PEERS_IN_HANDSHAKE`.
pub const MAX_PEERS_IN_HANDSHAKE: usize = 250;
/// `BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT`.
pub const BLOCK_IDS_DEFAULT_COUNT: usize = 10_000;
/// `BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT` — more than this in one response is a
/// protocol violation.
pub const BLOCK_IDS_MAX_COUNT: usize = 25_000;
/// `BLOCKS_SYNCHRONIZING_MAX_COUNT` — the most blocks a *span* may cover.
pub const BLOCKS_MAX_COUNT: usize = 2_048;
/// `CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT` — the most blocks one
/// `NOTIFY_REQUEST_GET_OBJECTS` may ask for.
///
/// This is **not** [`BLOCKS_MAX_COUNT`], and confusing the two costs the
/// connection: `handle_request_get_objects` drops any peer that asks for more
/// than a hundred, with no reply and no Levin error — the sync simply reads
/// end-of-file. `specs/08` §5.4 does not mention this limit; see
/// `docs/spec-deltas.md` §22.
pub const MAX_OBJECT_REQUEST_COUNT: usize = 100;
/// `BLOCKS_SYNCHRONIZING_DEFAULT_COUNT`.
pub const BLOCKS_DEFAULT_COUNT: usize = 20;
/// `SEEDHASH_EPOCH_BLOCKS` — batches are aligned to this so one request shares
/// a RandomWOW seed (`specs/03` §3.4).
pub const SEEDHASH_EPOCH_BLOCKS: u64 = 2_048;

/// Why a message body could not be read.
///
/// Separate from [`crate::levin::LevinError`], which is about framing. A
/// well-framed message with a nonsensical body is a different fault from a
/// stream that is not Levin at all, and a caller acts on them differently: the
/// first is one bad peer, the second is a port that is not what it claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageError {
    /// A required entry was absent, the wrong type, or the wrong length.
    Malformed(&'static str),
    /// The body is not valid epee portable storage.
    Epee(wow_serialize::Error),
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageError::Malformed(w) => write!(f, "malformed message: {w}"),
            MessageError::Epee(e) => write!(f, "malformed epee: {e}"),
        }
    }
}

impl std::error::Error for MessageError {}

impl From<wow_serialize::Error> for MessageError {
    fn from(e: wow_serialize::Error) -> Self {
        MessageError::Epee(e)
    }
}

type Result<T> = std::result::Result<T, MessageError>;

fn missing(what: &'static str) -> MessageError {
    MessageError::Malformed(what)
}

/// `basic_node_data` (`specs/08` §3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicNodeData {
    pub network_id: [u8; 16],
    pub peer_id: u64,
    /// Zero means "do not add me to peer lists" — which is what a node behind
    /// a firewall, or one that does not want inbound connections, says.
    pub my_port: u32,
    pub rpc_port: u16,
    pub rpc_credits_per_hash: u32,
    pub support_flags: u32,
}

impl BasicNodeData {
    pub fn to_section(&self) -> Section {
        let mut s = Section::new();
        s.insert("network_id".into(), Value::String(self.network_id.to_vec()));
        s.insert("peer_id".into(), Value::U64(self.peer_id));
        s.insert("my_port".into(), Value::U32(self.my_port));
        s.insert("rpc_port".into(), Value::U16(self.rpc_port));
        s.insert(
            "rpc_credits_per_hash".into(),
            Value::U32(self.rpc_credits_per_hash),
        );
        s.insert("support_flags".into(), Value::U32(self.support_flags));
        s
    }

    pub fn from_section(s: &Section) -> Result<BasicNodeData> {
        let id = s
            .get("network_id")
            .and_then(Value::as_bytes)
            .ok_or(missing("network_id"))?;
        Ok(BasicNodeData {
            network_id: id.try_into().map_err(|_| missing("network_id length"))?,
            peer_id: s.get("peer_id").and_then(Value::as_u64).unwrap_or(0),
            my_port: s.get("my_port").and_then(Value::as_u64).unwrap_or(0) as u32,
            rpc_port: s.get("rpc_port").and_then(Value::as_u64).unwrap_or(0) as u16,
            rpc_credits_per_hash: s
                .get("rpc_credits_per_hash")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32,
            support_flags: s.get("support_flags").and_then(Value::as_u64).unwrap_or(0) as u32,
        })
    }
}

/// `CORE_SYNC_DATA` (`specs/08` §3.4) — what a peer says about its chain.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CoreSyncData {
    pub current_height: u64,
    /// The cumulative difficulty, as a `u128` assembled from the low and high
    /// halves the wire carries separately.
    pub cumulative_difficulty: u128,
    pub top_id: [u8; 32],
    pub top_version: u8,
    pub pruning_seed: u32,
}

impl CoreSyncData {
    pub fn to_section(&self) -> Section {
        let mut s = Section::new();
        s.insert("current_height".into(), Value::U64(self.current_height));
        s.insert(
            "cumulative_difficulty".into(),
            Value::U64(self.cumulative_difficulty as u64),
        );
        // Always written, even when zero, which is what the reference does.
        s.insert(
            "cumulative_difficulty_top64".into(),
            Value::U64((self.cumulative_difficulty >> 64) as u64),
        );
        s.insert("top_id".into(), Value::String(self.top_id.to_vec()));
        s.insert("top_version".into(), Value::U8(self.top_version));
        s.insert("pruning_seed".into(), Value::U32(self.pruning_seed));
        s
    }

    pub fn from_section(s: &Section) -> Result<CoreSyncData> {
        let top = s
            .get("top_id")
            .and_then(Value::as_bytes)
            .ok_or(missing("top_id"))?;
        let low = s
            .get("cumulative_difficulty")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u128;
        let high = s
            .get("cumulative_difficulty_top64")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u128;

        Ok(CoreSyncData {
            current_height: s.get("current_height").and_then(Value::as_u64).unwrap_or(0),
            cumulative_difficulty: (high << 64) | low,
            top_id: top.try_into().map_err(|_| missing("top_id length"))?,
            top_version: s.get("top_version").and_then(Value::as_u64).unwrap_or(0) as u8,
            pruning_seed: s.get("pruning_seed").and_then(Value::as_u64).unwrap_or(0) as u32,
        })
    }
}

/// One peer, as a peer list carries it (`specs/08` §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerlistEntry {
    pub address: NetworkAddress,
    pub id: u64,
    pub last_seen: i64,
    pub pruning_seed: u32,
    pub rpc_port: u16,
}

/// `network_address` (`specs/08` §3.1).
///
/// Types 3 and 4 are Tor and i2p. They are parsed structurally even though this
/// node cannot connect to them, because the reference treats an unknown type as
/// an error and dropping a whole peer list over one onion address would be
/// worse than ignoring the entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkAddress {
    V4 {
        ip: u32,
        port: u16,
    },
    V6 {
        addr: [u8; 16],
        port: u16,
    },
    /// Tor or i2p: a host string and a port.
    Hidden {
        kind: u8,
        host: String,
        port: u16,
    },
}

impl NetworkAddress {
    /// The socket address to dial, for the kinds this node can reach.
    pub fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            // `m_ip` holds the four octets in wire order, so the low byte is
            // `a` in `a.b.c.d`.
            NetworkAddress::V4 { ip, port } => Some(std::net::SocketAddr::from((
                std::net::Ipv4Addr::from(ip.to_be()),
                *port,
            ))),
            NetworkAddress::V6 { addr, port } => Some(std::net::SocketAddr::from((
                std::net::Ipv6Addr::from(*addr),
                *port,
            ))),
            NetworkAddress::Hidden { .. } => None,
        }
    }

    pub fn to_section(&self) -> Section {
        let mut outer = Section::new();
        let mut inner = Section::new();
        let kind = match self {
            NetworkAddress::V4 { ip, port } => {
                inner.insert("m_ip".into(), Value::U32(*ip));
                inner.insert("m_port".into(), Value::U16(*port));
                1u8
            }
            NetworkAddress::V6 { addr, port } => {
                inner.insert("addr".into(), Value::String(addr.to_vec()));
                inner.insert("m_port".into(), Value::U16(*port));
                2u8
            }
            NetworkAddress::Hidden { kind, host, port } => {
                inner.insert("host".into(), Value::String(host.as_bytes().to_vec()));
                inner.insert("port".into(), Value::U16(*port));
                *kind
            }
        };
        outer.insert("type".into(), Value::U8(kind));
        outer.insert("addr".into(), Value::Object(inner));
        outer
    }

    pub fn from_section(s: &Section) -> Result<NetworkAddress> {
        let kind = s
            .get("type")
            .and_then(Value::as_u64)
            .ok_or(missing("type"))? as u8;
        let addr = s
            .get("addr")
            .and_then(Value::as_object)
            .ok_or(missing("addr"))?;

        match kind {
            1 => Ok(NetworkAddress::V4 {
                ip: addr
                    .get("m_ip")
                    .and_then(Value::as_u64)
                    .ok_or(missing("m_ip"))? as u32,
                port: addr.get("m_port").and_then(Value::as_u64).unwrap_or(0) as u16,
            }),
            2 => {
                let bytes = addr
                    .get("addr")
                    .and_then(Value::as_bytes)
                    .ok_or(missing("ipv6 addr"))?;
                Ok(NetworkAddress::V6 {
                    addr: bytes.try_into().map_err(|_| missing("ipv6 length"))?,
                    port: addr.get("m_port").and_then(Value::as_u64).unwrap_or(0) as u16,
                })
            }
            3 | 4 => Ok(NetworkAddress::Hidden {
                kind,
                host: addr
                    .get("host")
                    .and_then(Value::as_bytes)
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default(),
                port: addr.get("port").and_then(Value::as_u64).unwrap_or(0) as u16,
            }),
            _ => Err(missing("unknown network address type")),
        }
    }
}

impl PeerlistEntry {
    pub fn from_section(s: &Section) -> Result<PeerlistEntry> {
        let addr = s
            .get("adr")
            .and_then(Value::as_object)
            .ok_or(missing("adr"))?;
        Ok(PeerlistEntry {
            address: NetworkAddress::from_section(addr)?,
            id: s.get("id").and_then(Value::as_u64).unwrap_or(0),
            last_seen: s.get("last_seen").and_then(Value::as_u64).unwrap_or(0) as i64,
            pruning_seed: s.get("pruning_seed").and_then(Value::as_u64).unwrap_or(0) as u32,
            rpc_port: s.get("rpc_port").and_then(Value::as_u64).unwrap_or(0) as u16,
        })
    }
}

/// A handshake request.
pub fn handshake_request(node: &BasicNodeData, sync: &CoreSyncData) -> Vec<u8> {
    let mut s = Section::new();
    s.insert("node_data".into(), Value::Object(node.to_section()));
    s.insert("payload_data".into(), Value::Object(sync.to_section()));
    epee::to_bytes(&s).unwrap_or_default()
}

/// A handshake response, as the other side sends it.
#[derive(Clone, Debug)]
pub struct HandshakeResponse {
    pub node_data: BasicNodeData,
    pub payload_data: CoreSyncData,
    pub peers: Vec<PeerlistEntry>,
}

impl HandshakeResponse {
    pub fn parse(body: &[u8]) -> Result<HandshakeResponse> {
        let s = epee::from_bytes(body)?;
        let node = s
            .get("node_data")
            .and_then(Value::as_object)
            .ok_or(missing("node_data"))?;
        let payload = s
            .get("payload_data")
            .and_then(Value::as_object)
            .ok_or(missing("payload_data"))?;

        // A peer list longer than the documented maximum is a protocol
        // violation, not something to truncate quietly.
        let peers = match s.get("local_peerlist_new").and_then(Value::as_array) {
            None => Vec::new(),
            Some(a) => {
                if a.items.len() > MAX_PEERS_IN_HANDSHAKE {
                    return Err(missing("too many peers in handshake"));
                }
                a.items
                    .iter()
                    .filter_map(Value::as_object)
                    // An entry this node cannot parse is skipped rather than
                    // failing the handshake: one onion address should not cost
                    // a peer.
                    .filter_map(|e| PeerlistEntry::from_section(e).ok())
                    .collect()
            }
        };

        Ok(HandshakeResponse {
            node_data: BasicNodeData::from_section(node)?,
            payload_data: CoreSyncData::from_section(payload)?,
            peers,
        })
    }
}

/// `NOTIFY_REQUEST_CHAIN` (`specs/08` §5.2).
pub fn request_chain(block_ids: &[[u8; 32]], prune: bool) -> Vec<u8> {
    let mut s = Section::new();
    // `CONTAINER_POD_AS_BLOB`: one string of concatenated hashes.
    s.insert(
        "block_ids".into(),
        Value::String(block_ids.iter().flatten().copied().collect()),
    );
    s.insert("prune".into(), Value::Bool(prune));
    epee::to_bytes(&s).unwrap_or_default()
}

/// `NOTIFY_RESPONSE_CHAIN_ENTRY` (`specs/08` §5.3).
#[derive(Clone, Debug, Default)]
pub struct ChainEntry {
    pub start_height: u64,
    pub total_height: u64,
    pub cumulative_difficulty: u128,
    pub block_ids: Vec<[u8; 32]>,
}

impl ChainEntry {
    pub fn parse(body: &[u8]) -> Result<ChainEntry> {
        let s = epee::from_bytes(body)?;
        let ids = s
            .get("m_block_ids")
            .and_then(Value::as_bytes)
            .unwrap_or(&[]);
        if ids.len() % 32 != 0 {
            return Err(missing("m_block_ids is not a whole number of hashes"));
        }
        let count = ids.len() / 32;
        if count > BLOCK_IDS_MAX_COUNT {
            return Err(missing("too many block ids"));
        }

        let low = s
            .get("cumulative_difficulty")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u128;
        let high = s
            .get("cumulative_difficulty_top64")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u128;

        Ok(ChainEntry {
            start_height: s.get("start_height").and_then(Value::as_u64).unwrap_or(0),
            total_height: s.get("total_height").and_then(Value::as_u64).unwrap_or(0),
            cumulative_difficulty: (high << 64) | low,
            block_ids: ids
                .chunks_exact(32)
                .map(|c| c.try_into().expect("32 bytes"))
                .collect(),
        })
    }
}

/// `NOTIFY_REQUEST_GET_OBJECTS` (`specs/08` §5.4).
pub fn request_objects(blocks: &[[u8; 32]], prune: bool) -> Vec<u8> {
    let mut s = Section::new();
    s.insert(
        "blocks".into(),
        Value::String(blocks.iter().flatten().copied().collect()),
    );
    s.insert("prune".into(), Value::Bool(prune));
    epee::to_bytes(&s).unwrap_or_default()
}

/// One block and its transactions (`specs/08` §3.5).
#[derive(Clone, Debug, Default)]
pub struct BlockEntry {
    pub block: Vec<u8>,
    pub txs: Vec<Vec<u8>>,
    pub block_weight: u64,
}

impl BlockEntry {
    /// `pruned` changes the **type** of `txs`, so it is read first.
    pub fn from_section(s: &Section) -> Result<BlockEntry> {
        let pruned = s.get("pruned").and_then(Value::as_bool).unwrap_or(false);
        let block = s
            .get("block")
            .and_then(Value::as_bytes)
            .ok_or(missing("block"))?
            .to_vec();

        let txs = match s.get("txs") {
            None => Vec::new(),
            Some(Value::Array(a)) => a
                .items
                .iter()
                .map(|t| {
                    if pruned {
                        t.as_object()
                            .and_then(|o| o.get("blob"))
                            .and_then(Value::as_bytes)
                            .map(<[u8]>::to_vec)
                            .ok_or(missing("pruned tx blob"))
                    } else {
                        t.as_bytes().map(<[u8]>::to_vec).ok_or(missing("tx blob"))
                    }
                })
                .collect::<Result<Vec<_>>>()?,
            Some(_) => return Err(missing("txs is not an array")),
        };

        Ok(BlockEntry {
            block,
            txs,
            block_weight: s.get("block_weight").and_then(Value::as_u64).unwrap_or(0),
        })
    }
}

/// `NOTIFY_RESPONSE_GET_OBJECTS` (`specs/08` §5.5).
#[derive(Clone, Debug, Default)]
pub struct ObjectsResponse {
    pub blocks: Vec<BlockEntry>,
    pub missed_ids: Vec<[u8; 32]>,
    pub current_blockchain_height: u64,
}

impl ObjectsResponse {
    pub fn parse(body: &[u8]) -> Result<ObjectsResponse> {
        let s = epee::from_bytes(body)?;
        let blocks = match s.get("blocks").and_then(Value::as_array) {
            None => Vec::new(),
            Some(a) => {
                if a.items.len() > BLOCKS_MAX_COUNT {
                    return Err(missing("too many blocks in one response"));
                }
                a.items
                    .iter()
                    .filter_map(Value::as_object)
                    .map(BlockEntry::from_section)
                    .collect::<Result<Vec<_>>>()?
            }
        };

        let missed = s.get("missed_ids").and_then(Value::as_bytes).unwrap_or(&[]);
        if missed.len() % 32 != 0 {
            return Err(missing("missed_ids is not a whole number of hashes"));
        }

        Ok(ObjectsResponse {
            blocks,
            missed_ids: missed
                .chunks_exact(32)
                .map(|c| c.try_into().expect("32 bytes"))
                .collect(),
            current_blockchain_height: s
                .get("current_blockchain_height")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        })
    }
}

/// A `COMMAND_TIMED_SYNC` request body.
pub fn timed_sync_request(sync: &CoreSyncData) -> Vec<u8> {
    let mut s = Section::new();
    s.insert("payload_data".into(), Value::Object(sync.to_section()));
    epee::to_bytes(&s).unwrap_or_default()
}

/// An empty `COMMAND_REQUEST_SUPPORT_FLAGS` body.
pub fn empty_body() -> Vec<u8> {
    epee::to_bytes(&Section::new()).unwrap_or_default()
}

/// This node's support flags.
///
/// `specs/01` §11.1: `P2P_SUPPORT_FLAG_FLUFFY_BLOCKS` is `0x01` and is the only
/// flag defined. This node advertises **nothing**: it does not accept inbound
/// connections and does not reconstruct fluffy blocks, and claiming a flag it
/// cannot honour would have peers send it blocks it must then throw away.
pub const SUPPORT_FLAGS: u32 = 0;

/// A `COMMAND_REQUEST_SUPPORT_FLAGS` response.
///
/// The reference invokes this within five seconds of the handshake
/// (`P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT`) and **closes the connection** when
/// the timer expires unanswered. A node that only ever spoke when spoken to
/// would look healthy for five seconds and then be hung up on, mid-sync, with
/// no explanation on either side.
pub fn support_flags_response() -> Vec<u8> {
    let mut s = Section::new();
    s.insert("support_flags".into(), Value::U32(SUPPORT_FLAGS));
    epee::to_bytes(&s).unwrap_or_default()
}

/// A `COMMAND_PING` response (`specs/08` §4.2).
///
/// The peer matches `peer_id` against the handshake's before it will white-list
/// this node, so the id has to be the same one.
pub fn ping_response(peer_id: u64) -> Vec<u8> {
    let mut s = Section::new();
    s.insert("status".into(), Value::String(PING_OK.as_bytes().to_vec()));
    s.insert("peer_id".into(), Value::U64(peer_id));
    epee::to_bytes(&s).unwrap_or_default()
}

/// The status a successful `COMMAND_PING` returns.
pub const PING_OK: &str = "OK";

/// A `COMMAND_TIMED_SYNC` response (`specs/08` §4.4).
///
/// The peer list is empty: this node has no peers of its own to offer that the
/// other side did not already give it.
pub fn timed_sync_response(sync: &CoreSyncData) -> Vec<u8> {
    let mut s = Section::new();
    s.insert("payload_data".into(), Value::Object(sync.to_section()));
    s.insert("local_peerlist_new".into(), section_array(Vec::new()));
    epee::to_bytes(&s).unwrap_or_default()
}

/// Build an array value from sections, for the few places this node sends one.
pub fn section_array(items: Vec<Section>) -> Value {
    Value::Array(Array {
        elem_type: epee::ty::OBJECT,
        items: items.into_iter().map(Value::Object).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three replies the reference asks for by *request*, not notification.
    ///
    /// Getting `support_flags` wrong is the expensive one: the reference gives
    /// it five seconds and then closes the socket, so the symptom is an
    /// unexplained end-of-file several seconds into an otherwise healthy sync.
    #[test]
    fn the_inbound_replies_carry_the_fields_the_reference_reads() {
        let s = epee::from_bytes(&support_flags_response()).expect("parses");
        assert_eq!(
            s.get("support_flags").and_then(Value::as_u64),
            Some(0),
            "this node advertises no flags: it serves no inbound work"
        );

        let s = epee::from_bytes(&ping_response(0x0123_4567_89ab_cdef)).expect("parses");
        assert_eq!(
            s.get("status").and_then(Value::as_bytes),
            Some(b"OK".as_slice()),
            "the peer matches this literally before it will white-list us"
        );
        assert_eq!(
            s.get("peer_id").and_then(Value::as_u64),
            Some(0x0123_4567_89ab_cdef)
        );

        let ours = CoreSyncData {
            current_height: 1_234,
            cumulative_difficulty: 5_678,
            top_id: [7u8; 32],
            top_version: 20,
            pruning_seed: 0,
        };
        let s = epee::from_bytes(&timed_sync_response(&ours)).expect("parses");
        let payload = s
            .get("payload_data")
            .and_then(Value::as_object)
            .expect("payload_data");
        let back = CoreSyncData::from_section(payload).expect("round trips");
        assert_eq!(back.current_height, 1_234);
        assert_eq!(back.cumulative_difficulty, 5_678);
        assert_eq!(back.top_id, [7u8; 32]);
        assert!(
            s.contains_key("local_peerlist_new"),
            "the field is present even when empty; the reference reads it"
        );
    }

    /// One request may name a hundred blocks, and that is a different constant
    /// from the span maximum. Asking for 101 gets the socket closed with no
    /// reply at all, so this number is load-bearing.
    #[test]
    fn a_block_request_is_capped_well_below_the_span_maximum() {
        assert_eq!(MAX_OBJECT_REQUEST_COUNT, 100);
        assert_eq!(BLOCKS_MAX_COUNT, 2_048);
    }

    /// The network ids are the ones `specs/01` §2.1 gives, and they differ.
    /// This is the fork guard: a wrong value connects a node to another chain.
    #[test]
    fn the_network_ids_are_the_documented_ones() {
        assert_eq!(
            NETWORK_ID_MAINNET,
            [
                0x11, 0x33, 0xFF, 0x77, 0x61, 0x04, 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1,
                0xA1, 0x10
            ]
        );
        assert_ne!(NETWORK_ID_MAINNET, NETWORK_ID_TESTNET);
        assert_ne!(NETWORK_ID_TESTNET, NETWORK_ID_STAGENET);
        // Testnet and stagenet differ only in the last byte, which is exactly
        // the kind of thing to assert rather than assume.
        assert_eq!(
            NETWORK_ID_TESTNET[..15],
            NETWORK_ID_STAGENET[..15],
            "they share everything but the last byte"
        );
        assert_ne!(NETWORK_ID_TESTNET[15], NETWORK_ID_STAGENET[15]);

        assert_eq!(network_id(wow_types::Network::Mainnet), NETWORK_ID_MAINNET);
        assert_eq!(
            network_id(wow_types::Network::Fakechain),
            NETWORK_ID_MAINNET,
            "fakechain uses the mainnet config block"
        );
    }

    #[test]
    fn the_ports_are_the_documented_ones() {
        assert_eq!(default_port(wow_types::Network::Mainnet), 34_567);
        assert_eq!(default_port(wow_types::Network::Testnet), 28_080);
        assert_eq!(default_port(wow_types::Network::Stagenet), 38_080);
    }

    #[test]
    fn node_data_round_trips() {
        let node = BasicNodeData {
            network_id: NETWORK_ID_MAINNET,
            peer_id: 0x0123_4567_89ab_cdef,
            my_port: 34_567,
            rpc_port: 34_568,
            rpc_credits_per_hash: 0,
            support_flags: 1,
        };
        let back = BasicNodeData::from_section(&node.to_section()).expect("parses");
        assert_eq!(back, node);
    }

    /// The cumulative difficulty spans two `u64` fields, and the high one is
    /// always written. A reader that ignores it sees a chain that looks far
    /// behind once the difficulty passes 2^64.
    #[test]
    fn the_cumulative_difficulty_spans_two_words() {
        let sync = CoreSyncData {
            current_height: 500_000,
            cumulative_difficulty: (3u128 << 64) | 7,
            top_id: [9u8; 32],
            top_version: 20,
            pruning_seed: 0,
        };
        let s = sync.to_section();
        assert_eq!(
            s.get("cumulative_difficulty").and_then(Value::as_u64),
            Some(7)
        );
        assert_eq!(
            s.get("cumulative_difficulty_top64").and_then(Value::as_u64),
            Some(3)
        );
        assert_eq!(CoreSyncData::from_section(&s).expect("parses"), sync);

        // And the top word is written even when zero.
        let small = CoreSyncData {
            cumulative_difficulty: 5,
            ..Default::default()
        };
        assert!(small
            .to_section()
            .contains_key("cumulative_difficulty_top64"));
    }

    /// `m_ip` holds the octets in wire order, so `1.2.3.4` is not `4.3.2.1`.
    #[test]
    fn an_ipv4_address_keeps_its_octet_order() {
        // 1.2.3.4 as the four wire bytes read little-endian into a u32.
        let ip = u32::from_le_bytes([1, 2, 3, 4]);
        let a = NetworkAddress::V4 { ip, port: 34_567 };
        let addr = a.socket_addr().expect("an address");
        assert_eq!(addr.to_string(), "1.2.3.4:34567");

        let back = NetworkAddress::from_section(&a.to_section()).expect("parses");
        assert_eq!(back, a);
    }

    #[test]
    fn address_types_round_trip() {
        for a in [
            NetworkAddress::V4 { ip: 7, port: 1 },
            NetworkAddress::V6 {
                addr: [1u8; 16],
                port: 2,
            },
            NetworkAddress::Hidden {
                kind: 4,
                host: "example.onion".into(),
                port: 3,
            },
        ] {
            assert_eq!(
                NetworkAddress::from_section(&a.to_section()).expect("parses"),
                a
            );
        }
    }

    /// An unknown address type is an error, as the reference makes it.
    #[test]
    fn an_unknown_address_type_is_an_error() {
        let mut s = Section::new();
        s.insert("type".into(), Value::U8(9));
        s.insert("addr".into(), Value::Object(Section::new()));
        assert!(NetworkAddress::from_section(&s).is_err());
    }

    /// A peer list longer than the documented maximum is refused rather than
    /// truncated.
    #[test]
    fn an_oversized_peer_list_is_refused() {
        let node = BasicNodeData {
            network_id: NETWORK_ID_MAINNET,
            peer_id: 1,
            my_port: 0,
            rpc_port: 0,
            rpc_credits_per_hash: 0,
            support_flags: 0,
        };
        let sync = CoreSyncData::default();

        let mut peer = Section::new();
        peer.insert(
            "adr".into(),
            Value::Object(NetworkAddress::V4 { ip: 1, port: 1 }.to_section()),
        );
        peer.insert("id".into(), Value::U64(2));

        let mut s = Section::new();
        s.insert("node_data".into(), Value::Object(node.to_section()));
        s.insert("payload_data".into(), Value::Object(sync.to_section()));
        s.insert(
            "local_peerlist_new".into(),
            section_array(vec![peer; MAX_PEERS_IN_HANDSHAKE + 1]),
        );

        let body = epee::to_bytes(&s).expect("serialize");
        assert!(HandshakeResponse::parse(&body).is_err());
    }

    /// A chain entry with a partial hash, or too many, is refused.
    #[test]
    fn a_malformed_chain_entry_is_refused() {
        let mut s = Section::new();
        s.insert("m_block_ids".into(), Value::String(vec![0u8; 33]));
        let body = epee::to_bytes(&s).expect("serialize");
        assert!(
            ChainEntry::parse(&body).is_err(),
            "33 is not a multiple of 32"
        );

        let mut s = Section::new();
        s.insert(
            "m_block_ids".into(),
            Value::String(vec![0u8; 32 * (BLOCK_IDS_MAX_COUNT + 1)]),
        );
        let body = epee::to_bytes(&s).expect("serialize");
        assert!(ChainEntry::parse(&body).is_err(), "past the maximum");
    }

    /// `pruned` changes the type of `txs`, so it has to be read first.
    #[test]
    fn the_pruned_flag_changes_the_tx_shape() {
        // Unpruned: raw blobs.
        let mut s = Section::new();
        s.insert("block".into(), Value::String(vec![1, 2, 3]));
        s.insert(
            "txs".into(),
            Value::Array(Array {
                elem_type: epee::ty::STRING,
                items: vec![Value::String(vec![4, 5])],
            }),
        );
        let e = BlockEntry::from_section(&s).expect("parses");
        assert_eq!(e.txs, vec![vec![4, 5]]);

        // Pruned: sections with a `blob`.
        let mut inner = Section::new();
        inner.insert("blob".into(), Value::String(vec![6, 7]));
        let mut s = Section::new();
        s.insert("pruned".into(), Value::Bool(true));
        s.insert("block".into(), Value::String(vec![1]));
        s.insert("txs".into(), section_array(vec![inner]));
        let e = BlockEntry::from_section(&s).expect("parses");
        assert_eq!(e.txs, vec![vec![6, 7]]);
    }

    /// The chain request is a packed blob, not an array. Getting that backwards
    /// makes a peer answer from genesis every time.
    #[test]
    fn the_chain_request_packs_its_hashes() {
        let ids = [[1u8; 32], [2u8; 32]];
        let body = request_chain(&ids, false);
        let s = epee::from_bytes(&body).expect("parses");
        let packed = s
            .get("block_ids")
            .and_then(Value::as_bytes)
            .expect("a string");
        assert_eq!(packed.len(), 64);
        assert_eq!(&packed[..32], &[1u8; 32]);
        assert_eq!(&packed[32..], &[2u8; 32]);
    }

    /// The batch limits are the documented ones.
    #[test]
    fn the_limits_are_the_documented_ones() {
        assert_eq!(MAX_PEERS_IN_HANDSHAKE, 250);
        assert_eq!(BLOCK_IDS_DEFAULT_COUNT, 10_000);
        assert_eq!(BLOCK_IDS_MAX_COUNT, 25_000);
        assert_eq!(BLOCKS_MAX_COUNT, 2_048);
        assert_eq!(BLOCKS_DEFAULT_COUNT, 20);
        assert_eq!(SEEDHASH_EPOCH_BLOCKS, 2_048);
    }
}
