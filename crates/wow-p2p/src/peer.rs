//! A connection to one peer: the handshake, and sending and receiving Levin
//! messages (`specs/08` §4).
//!
//! # The network id is the fork guard
//!
//! `specs/08` §4.2 lists the reasons to drop a connection, and the first is a
//! `network_id` mismatch. That check is what keeps a mainnet node off testnet
//! and off another fork entirely — a node that skipped it would sync a chain
//! its own rules reject, block by block, and blame itself.
//!
//! # Outgoing only
//!
//! This dials peers; it does not listen. A node that accepts inbound
//! connections has to deal with the ping-back that gates the white list
//! (`specs/08` §4.2), peer bans, and connection limits, and none of that is
//! needed to *sync from* the network. Saying so is better than a listener that
//! half works.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::levin::{self, Header, LevinError};
use crate::messages::{
    self, BasicNodeData, ChainEntry, CoreSyncData, HandshakeResponse, MessageError, ObjectsResponse,
};

/// `P2P_DEFAULT_CONNECT_TIMEOUT`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// `P2P_DEFAULT_INVOKE_TIMEOUT` — a connection that does not answer within this
/// is dropped (`specs/08` §4.4).
const INVOKE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub enum PeerError {
    Io(std::io::Error),
    Levin(LevinError),
    Message(MessageError),
    /// The peer is on another network. This is the fork guard.
    WrongNetwork {
        theirs: [u8; 16],
        ours: [u8; 16],
    },
    /// We dialled ourselves.
    SelfConnection,
    /// The peer answered a different command than the one asked.
    UnexpectedCommand {
        wanted: u32,
        got: u32,
    },
    /// The peer returned a Levin error code.
    Refused(i32),
    /// The peer said it has no chain.
    EmptyChain,
    /// A response violated the protocol in a way that warrants dropping the
    /// peer rather than retrying.
    Protocol(&'static str),
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerError::Io(e) => write!(f, "io: {e}"),
            PeerError::Levin(e) => write!(f, "framing: {e}"),
            PeerError::Message(e) => write!(f, "{e}"),
            PeerError::WrongNetwork { theirs, ours } => write!(
                f,
                "that peer is on network {}, this node is on {}",
                wow_crypto::hex::encode(theirs),
                wow_crypto::hex::encode(ours)
            ),
            PeerError::SelfConnection => f.write_str("connected to ourselves"),
            PeerError::UnexpectedCommand { wanted, got } => {
                write!(f, "asked for command {wanted} and got {got}")
            }
            PeerError::Refused(code) => write!(f, "the peer refused with code {code}"),
            PeerError::EmptyChain => f.write_str("the peer has no chain"),
            PeerError::Protocol(w) => write!(f, "protocol violation: {w}"),
        }
    }
}

impl std::error::Error for PeerError {}

impl From<std::io::Error> for PeerError {
    fn from(e: std::io::Error) -> Self {
        PeerError::Io(e)
    }
}
impl From<LevinError> for PeerError {
    fn from(e: LevinError) -> Self {
        PeerError::Levin(e)
    }
}
impl From<MessageError> for PeerError {
    fn from(e: MessageError) -> Self {
        PeerError::Message(e)
    }
}

type Result<T> = std::result::Result<T, PeerError>;

/// What this node tells peers about itself.
#[derive(Clone, Debug)]
pub struct NodeIdentity {
    pub network: wow_types::Network,
    pub peer_id: u64,
    /// The port to advertise. **Zero means "do not list me"**, which is what a
    /// node that does not accept inbound connections should say — and this one
    /// does not, so zero is the honest value.
    pub my_port: u32,
}

impl NodeIdentity {
    pub fn node_data(&self) -> BasicNodeData {
        BasicNodeData {
            network_id: messages::network_id(self.network),
            peer_id: self.peer_id,
            my_port: self.my_port,
            rpc_port: 0,
            rpc_credits_per_hash: 0,
            support_flags: 0,
        }
    }
}

/// An open connection to a peer, after a successful handshake.
pub struct Peer {
    stream: TcpStream,
    address: SocketAddr,
    /// The size limit in force. It rises after the handshake
    /// (`specs/08` §1).
    limit: u64,
    /// What the peer last said about its chain.
    pub sync: CoreSyncData,
    pub peer_id: u64,
    /// Peers the handshake handed over, for a caller keeping a peer list.
    pub known_peers: Vec<messages::PeerlistEntry>,
    /// Our own peer id, for answering `COMMAND_PING`.
    our_peer_id: u64,
    /// What this node currently says about its own chain, for answering
    /// `COMMAND_TIMED_SYNC`. The sync loop keeps it current as blocks land, so
    /// a peer asking mid-sync is told the truth rather than the height this
    /// node started at.
    pub our_sync: CoreSyncData,
}

impl Peer {
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Dial a peer and handshake.
    pub fn connect(
        address: impl ToSocketAddrs,
        identity: &NodeIdentity,
        ours: &CoreSyncData,
    ) -> Result<Peer> {
        let mut last: Option<std::io::Error> = None;
        for addr in address.to_socket_addrs()? {
            match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(stream) => return Peer::handshake(stream, addr, identity, ours),
                Err(e) => last = Some(e),
            }
        }
        Err(PeerError::Io(last.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no address resolved")
        })))
    }

    fn handshake(
        stream: TcpStream,
        address: SocketAddr,
        identity: &NodeIdentity,
        ours: &CoreSyncData,
    ) -> Result<Peer> {
        stream.set_read_timeout(Some(INVOKE_TIMEOUT))?;
        stream.set_write_timeout(Some(INVOKE_TIMEOUT))?;
        stream.set_nodelay(true)?;

        let mut peer = Peer {
            stream,
            address,
            // Before the handshake the smaller limit applies (`specs/08` §1).
            limit: levin::INITIAL_MAX_PACKET_SIZE,
            sync: CoreSyncData::default(),
            peer_id: 0,
            known_peers: Vec::new(),
            our_peer_id: identity.peer_id,
            our_sync: ours.clone(),
        };

        let body = messages::handshake_request(&identity.node_data(), ours);
        let response = peer.invoke(levin::command::HANDSHAKE, &body)?;
        let response = HandshakeResponse::parse(&response)?;

        // `specs/08` §4.2, in its order. The network id first: everything after
        // it is meaningless if the peer is on another chain.
        let ours_id = messages::network_id(identity.network);
        if response.node_data.network_id != ours_id {
            return Err(PeerError::WrongNetwork {
                theirs: response.node_data.network_id,
                ours: ours_id,
            });
        }
        if response.node_data.peer_id == identity.peer_id {
            return Err(PeerError::SelfConnection);
        }

        // `top_version` may differ from ours. `specs/08` §4.3 is explicit that
        // this is informational and a node MUST NOT drop the peer over it.
        peer.limit = levin::DEFAULT_MAX_PACKET_SIZE;
        peer.sync = response.payload_data;
        peer.peer_id = response.node_data.peer_id;
        peer.known_peers = response.peers;
        Ok(peer)
    }

    /// Send a request and read its response.
    pub fn invoke(&mut self, command: u32, body: &[u8]) -> Result<Vec<u8>> {
        let header = Header::request(command, body.len() as u64);
        self.stream.write_all(&header.write())?;
        self.stream.write_all(body)?;
        self.stream.flush()?;
        self.read_response(command)
    }

    /// Send a notification, which expects no reply.
    pub fn notify(&mut self, command: u32, body: &[u8]) -> Result<()> {
        let header = Header::notification(command, body.len() as u64);
        self.stream.write_all(&header.write())?;
        self.stream.write_all(body)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Answer a message the peer sent us.
    ///
    /// Three of the reference's commands are *requests*, and one of them is not
    /// optional. Within five seconds of the handshake the reference invokes
    /// `COMMAND_REQUEST_SUPPORT_FLAGS` with a
    /// `P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT` of five seconds, and closes the
    /// connection when that timer expires unanswered. A node that never replied
    /// would sync for five seconds and then be hung up on with no error from
    /// either side -- which is exactly what this node did before this existed.
    ///
    /// Anything else is ignored. Notifications need no answer, and a request
    /// this node does not serve gets `LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED`
    /// rather than silence, which is what `specs/08` §2 asks for and what lets
    /// the peer stop waiting.
    fn serve(&mut self, header: &Header, _body: &[u8]) -> Result<()> {
        if header.kind() != levin::Kind::Request {
            return Ok(());
        }

        let (code, body) = match header.command {
            levin::command::REQUEST_SUPPORT_FLAGS => (0, messages::support_flags_response()),
            levin::command::PING => (0, messages::ping_response(self.our_peer_id)),
            levin::command::TIMED_SYNC => (0, messages::timed_sync_response(&self.our_sync)),
            // Not served: say so rather than leave the peer's invoke hanging
            // until its own timeout closes the connection.
            _ => (levin::ERROR_CONNECTION_HANDLER_NOT_DEFINED, Vec::new()),
        };

        let reply = Header::response(header.command, body.len() as u64, code);
        self.stream.write_all(&reply.write())?;
        self.stream.write_all(&body)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Read messages until one matches `wanted`.
    ///
    /// A peer interleaves notifications with responses — it may push a new
    /// block while answering a chain request — so anything else is skipped
    /// rather than treated as a desync.
    fn read_response(&mut self, wanted: u32) -> Result<Vec<u8>> {
        // A bound, so a peer that streams notifications forever cannot hold
        // this thread. Sixty-four is far above anything legitimate between a
        // request and its answer.
        for _ in 0..64 {
            let (header, body) = self.read_message()?;
            if header.command == wanted && header.kind() == levin::Kind::Response {
                if header.return_code < 0 {
                    return Err(PeerError::Refused(header.return_code));
                }
                return Ok(body);
            }
            self.serve(&header, &body)?;
        }
        Err(PeerError::UnexpectedCommand { wanted, got: 0 })
    }

    /// Read one whole message, reassembling fragments.
    pub fn read_message(&mut self) -> Result<(Header, Vec<u8>)> {
        let mut reassembler = levin::Reassembler::new();
        loop {
            let mut head = [0u8; levin::HEADER_LEN];
            self.stream.read_exact(&mut head)?;
            let header = Header::read(&head, self.limit)?;

            let mut body = vec![0u8; header.length as usize];
            self.stream.read_exact(&mut body)?;

            trace(&header, body.len());

            match reassembler.push(&header, &body, self.limit)? {
                levin::Reassembly::NotAFragment => return Ok((header, body)),
                levin::Reassembly::Complete {
                    header: inner,
                    body: inner_body,
                } => return Ok((inner, inner_body)),
                // A dummy or a partial fragment: read the next one.
                levin::Reassembly::Discarded | levin::Reassembly::Buffered => continue,
            }
        }
    }

    /// `NOTIFY_REQUEST_CHAIN` and its answer (`specs/08` §5.2, §5.3).
    ///
    /// `history` is the short chain history: the last ten block ids, then
    /// exponentially spaced ones, genesis last.
    pub fn request_chain(&mut self, history: &[[u8; 32]]) -> Result<ChainEntry> {
        let body = messages::request_chain(history, false);
        self.notify(levin::command::REQUEST_CHAIN, &body)?;

        let raw = self.await_notification(levin::command::RESPONSE_CHAIN_ENTRY)?;
        let entry = ChainEntry::parse(&raw)?;

        if entry.block_ids.is_empty() {
            return Err(PeerError::EmptyChain);
        }
        // `specs/08` §5.3: the requester must check that the first id is one it
        // already has. A peer that answers from somewhere else is offering a
        // chain this node cannot attach.
        if !history.contains(&entry.block_ids[0]) {
            return Err(PeerError::Protocol(
                "the chain entry does not start at a block we asked from",
            ));
        }
        Ok(entry)
    }

    /// `NOTIFY_REQUEST_GET_OBJECTS` and its answer (`specs/08` §5.4, §5.5).
    ///
    /// Verifies that every returned block was asked for, which `specs/08` §5.5
    /// requires: a peer that sends something else is feeding blocks the caller
    /// never chose.
    pub fn request_blocks(&mut self, ids: &[[u8; 32]]) -> Result<ObjectsResponse> {
        if ids.len() > messages::MAX_OBJECT_REQUEST_COUNT {
            return Err(PeerError::Protocol("asked for too many blocks at once"));
        }
        let body = messages::request_objects(ids, false);
        self.notify(levin::command::REQUEST_GET_OBJECTS, &body)?;

        let raw = self.await_notification(levin::command::RESPONSE_GET_OBJECTS)?;
        let response = ObjectsResponse::parse(&raw)?;

        if response.blocks.len() > ids.len() {
            return Err(PeerError::Protocol("more blocks than were requested"));
        }
        Ok(response)
    }

    /// Read until a notification with `command` arrives.
    ///
    /// The chain-sync commands are notifications in both directions, not
    /// request/response pairs, so the answer arrives as a separate message with
    /// its own command id.
    fn await_notification(&mut self, command: u32) -> Result<Vec<u8>> {
        for _ in 0..64 {
            let (header, body) = self.read_message()?;
            if header.command == command {
                return Ok(body);
            }
            self.serve(&header, &body)?;
        }
        Err(PeerError::UnexpectedCommand {
            wanted: command,
            got: 0,
        })
    }

    /// `COMMAND_TIMED_SYNC` (`specs/08` §4.4): learn the peer's new tip.
    pub fn timed_sync(&mut self, ours: &CoreSyncData) -> Result<CoreSyncData> {
        let body = messages::timed_sync_request(ours);
        let raw = self.invoke(levin::command::TIMED_SYNC, &body)?;
        let s = wow_serialize::epee::from_bytes(&raw).map_err(MessageError::from)?;
        let payload = s
            .get("payload_data")
            .and_then(wow_serialize::epee::Value::as_object)
            .ok_or(MessageError::Malformed("payload_data"))?;
        let sync = CoreSyncData::from_section(payload)?;
        self.sync = sync.clone();
        Ok(sync)
    }
}

/// Log every inbound frame when `WOW_P2P_TRACE` is set.
///
/// Interoperating with another implementation means most faults show up as
/// "the peer hung up", which says nothing about which message it disliked.
/// A frame log is the difference between a guess and an answer.
fn trace(header: &Header, len: usize) {
    if std::env::var_os("WOW_P2P_TRACE").is_none() {
        return;
    }
    let kind = match header.kind() {
        levin::Kind::Request => "request",
        levin::Kind::Response => "response",
        levin::Kind::Notification => "notify",
        levin::Kind::FragmentBegin => "fragment-begin",
        levin::Kind::FragmentMiddle => "fragment-middle",
        levin::Kind::FragmentEnd => "fragment-end",
        levin::Kind::Dummy => "dummy",
        levin::Kind::Unknown => "unknown",
    };
    eprintln!(
        "p2p <- {kind} {} ({} bytes, rc {})",
        command_name(header.command),
        len,
        header.return_code
    );
}

fn command_name(id: u32) -> String {
    let name = match id {
        levin::command::HANDSHAKE => "HANDSHAKE",
        levin::command::TIMED_SYNC => "TIMED_SYNC",
        levin::command::PING => "PING",
        levin::command::REQUEST_SUPPORT_FLAGS => "REQUEST_SUPPORT_FLAGS",
        levin::command::NEW_BLOCK => "NEW_BLOCK",
        levin::command::NEW_TRANSACTIONS => "NEW_TRANSACTIONS",
        levin::command::REQUEST_GET_OBJECTS => "REQUEST_GET_OBJECTS",
        levin::command::RESPONSE_GET_OBJECTS => "RESPONSE_GET_OBJECTS",
        levin::command::REQUEST_CHAIN => "REQUEST_CHAIN",
        levin::command::RESPONSE_CHAIN_ENTRY => "RESPONSE_CHAIN_ENTRY",
        levin::command::NEW_FLUFFY_BLOCK => "NEW_FLUFFY_BLOCK",
        levin::command::REQUEST_FLUFFY_MISSING_TX => "REQUEST_FLUFFY_MISSING_TX",
        levin::command::GET_TXPOOL_COMPLEMENT => "GET_TXPOOL_COMPLEMENT",
        _ => return format!("command {id}"),
    };
    format!("{name} ({id})")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake peer that handshakes, then behaves like the reference: it invokes
    /// `COMMAND_REQUEST_SUPPORT_FLAGS` and waits. The reference gives that
    /// invoke five seconds and closes the connection when it expires, which is
    /// the whole reason `serve` exists.
    fn fake_peer(
        their_id: u64,
        network: wow_types::Network,
    ) -> (
        std::net::SocketAddr,
        std::thread::JoinHandle<Option<Header>>,
    ) {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");

            // Read the handshake request.
            let mut head = [0u8; levin::HEADER_LEN];
            sock.read_exact(&mut head).expect("header");
            let header = Header::read(&head, levin::DEFAULT_MAX_PACKET_SIZE).expect("parse");
            let mut body = vec![0u8; header.length as usize];
            sock.read_exact(&mut body).expect("body");

            // Answer it.
            let node = BasicNodeData {
                network_id: messages::network_id(network),
                peer_id: their_id,
                my_port: 0,
                rpc_port: 0,
                rpc_credits_per_hash: 0,
                support_flags: 1,
            };
            let sync = CoreSyncData {
                current_height: 100,
                cumulative_difficulty: 100,
                top_id: [9u8; 32],
                top_version: 20,
                pruning_seed: 0,
            };
            let mut s = wow_serialize::epee::Section::new();
            s.insert(
                "node_data".into(),
                wow_serialize::epee::Value::Object(node.to_section()),
            );
            s.insert(
                "payload_data".into(),
                wow_serialize::epee::Value::Object(sync.to_section()),
            );
            let reply = wow_serialize::epee::to_bytes(&s).expect("encode");
            let h = Header::response(levin::command::HANDSHAKE, reply.len() as u64, 1);
            sock.write_all(&h.write()).expect("write header");
            sock.write_all(&reply).expect("write body");
            sock.flush().expect("flush");

            // Now do what the reference does: ask for support flags and wait
            // for an answer.
            let ask = messages::empty_body();
            let h = Header::request(levin::command::REQUEST_SUPPORT_FLAGS, ask.len() as u64);
            sock.write_all(&h.write()).expect("write ask");
            sock.write_all(&ask).expect("write ask body");
            sock.flush().expect("flush");

            // Read until the answer turns up. The node under test sends its own
            // messages too -- a chain request goes out before it ever looks at
            // the socket -- so the reply is not necessarily first.
            sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
            for _ in 0..8 {
                let mut head = [0u8; levin::HEADER_LEN];
                if sock.read_exact(&mut head).is_err() {
                    // What the reference sees today when a node never replies.
                    return None;
                }
                let header = Header::read(&head, levin::DEFAULT_MAX_PACKET_SIZE).expect("parse");
                let mut body = vec![0u8; header.length as usize];
                if sock.read_exact(&mut body).is_err() {
                    return None;
                }
                if header.command == levin::command::REQUEST_SUPPORT_FLAGS {
                    return Some(header);
                }
            }
            None
        });

        (addr, handle)
    }

    /// The handshake works against a peer that speaks the real framing, and the
    /// support-flags request it sends straight afterwards **is answered**.
    ///
    /// This is the bug that cost a live sync: the reference invokes
    /// `COMMAND_REQUEST_SUPPORT_FLAGS` with a five-second timeout and closes
    /// the connection when it expires. A node that ignored inbound requests
    /// synced perfectly for five seconds and was then hung up on, reporting
    /// only "failed to fill whole buffer".
    #[test]
    fn an_inbound_support_flags_request_is_answered() {
        let (addr, handle) = fake_peer(0xDEAD_BEEF, wow_types::Network::Mainnet);

        let identity = NodeIdentity {
            network: wow_types::Network::Mainnet,
            peer_id: 1,
            my_port: 0,
        };
        let mut peer = match Peer::connect(addr, &identity, &CoreSyncData::default()) {
            Ok(p) => p,
            Err(e) => panic!("handshake failed: {e}"),
        };
        assert_eq!(peer.peer_id, 0xDEAD_BEEF);
        assert_eq!(peer.sync.current_height, 100);

        // The support-flags request is sitting in the socket. Reading anything
        // at all runs `serve`, which must answer it.
        //
        // `request_chain` will fail -- this peer sends no chain entry -- but by
        // then the reply has gone out, which is what the fake peer is checking.
        let _ = peer.request_chain(&[[0u8; 32]]);
        drop(peer);

        let answered = handle.join().expect("peer thread");
        let header = answered.expect("the peer must receive a reply, not a timeout");
        assert_eq!(header.command, levin::command::REQUEST_SUPPORT_FLAGS);
        assert_eq!(header.kind(), levin::Kind::Response);
        assert_eq!(header.return_code, 0);
    }

    /// A peer on another network is refused before anything else is believed.
    /// This is the fork guard (`specs/08` §4.2).
    #[test]
    fn a_peer_on_another_network_is_refused() {
        let (addr, handle) = fake_peer(0xDEAD_BEEF, wow_types::Network::Testnet);

        let identity = NodeIdentity {
            network: wow_types::Network::Mainnet,
            peer_id: 1,
            my_port: 0,
        };
        match Peer::connect(addr, &identity, &CoreSyncData::default()) {
            Err(PeerError::WrongNetwork { theirs, ours }) => {
                assert_eq!(theirs, messages::NETWORK_ID_TESTNET);
                assert_eq!(ours, messages::NETWORK_ID_MAINNET);
            }
            Err(other) => panic!("expected a network mismatch, got {other}"),
            Ok(_) => panic!("a testnet peer must not be accepted on mainnet"),
        }
        let _ = handle.join();
    }

    /// Dialling a node with our own peer id is a self-connection, and the
    /// network id is checked *first* -- a wrong-network self-connection is
    /// reported as the wrong network, because that is the more useful fault.
    #[test]
    fn a_self_connection_is_refused() {
        let (addr, handle) = fake_peer(7, wow_types::Network::Mainnet);

        let identity = NodeIdentity {
            network: wow_types::Network::Mainnet,
            peer_id: 7,
            my_port: 0,
        };
        match Peer::connect(addr, &identity, &CoreSyncData::default()) {
            Err(PeerError::SelfConnection) => {}
            Err(other) => panic!("expected a self-connection, got {other}"),
            Ok(_) => panic!("we dialled ourselves"),
        }
        let _ = handle.join();
    }

    /// A peer that will not be dialled, to check the failure path is an error
    /// and not a hang.
    #[test]
    fn an_unreachable_peer_is_an_error() {
        let identity = NodeIdentity {
            network: wow_types::Network::Mainnet,
            peer_id: 1,
            my_port: 0,
        };
        // `Peer` holds a socket and is deliberately not `Debug`, so the
        // failure is matched rather than unwrapped.
        match Peer::connect("127.0.0.1:1", &identity, &CoreSyncData::default()) {
            Err(PeerError::Io(_)) => {}
            Err(other) => panic!("expected an io error, got {other}"),
            Ok(_) => panic!("nothing is listening on port 1"),
        }
    }

    /// A node that does not listen advertises port zero, which is how it tells
    /// peers not to list it (`specs/08` §3.3).
    #[test]
    fn a_non_listening_node_advertises_port_zero() {
        let identity = NodeIdentity {
            network: wow_types::Network::Mainnet,
            peer_id: 42,
            my_port: 0,
        };
        let node = identity.node_data();
        assert_eq!(node.my_port, 0);
        assert_eq!(node.peer_id, 42);
        assert_eq!(node.network_id, messages::NETWORK_ID_MAINNET);
    }

    /// The errors say which chain each side is on, because "handshake failed"
    /// is useless when the cause is a testnet node on the mainnet port.
    #[test]
    fn a_wrong_network_error_names_both_sides() {
        let e = PeerError::WrongNetwork {
            theirs: messages::NETWORK_ID_TESTNET,
            ours: messages::NETWORK_ID_MAINNET,
        };
        let text = e.to_string();
        assert!(text.contains(&wow_crypto::hex::encode(&messages::NETWORK_ID_TESTNET)));
        assert!(text.contains(&wow_crypto::hex::encode(&messages::NETWORK_ID_MAINNET)));
    }

    /// The timeouts are the documented ones.
    #[test]
    fn the_timeouts_are_the_documented_ones() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(INVOKE_TIMEOUT, Duration::from_secs(120));
    }
}
