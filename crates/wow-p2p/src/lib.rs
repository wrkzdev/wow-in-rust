//! Levin codec, peerlist, connection manager, sync, Dandelion++ relay
//! (`specs/08-p2p.md`).
//!
//! [`levin`] is the wire framing — the 33-byte header, the command set, the
//! size limits and fragment reassembly. [`messages`] is what peers exchange
//! (`specs/08` §3), [`peer`] is one connection and its handshake (§4), and
//! [`sync`] pulls a chain from one of them (§5).
//!
//! # What is here and what is not
//!
//! Enough to **sync from** the network: dial a peer, handshake, find where the
//! chains diverge, pull the blocks after it. Not here, and each absent rather
//! than half-built:
//!
//! * **listening.** Accepting inbound connections needs the ping-back that
//!   gates the white list (§4.2), peer bans and connection limits.
//! * **the peer list.** Peers from a handshake are handed to the caller and
//!   nothing is persisted, so every run starts from its seed nodes.
//! * **block propagation** (§6) and **Dandelion++ relay** (§7). This node
//!   receives; it does not announce.
//!
//! Everything in this crate parses bytes an unauthenticated peer chose, so
//! `specs/15` §4.4's invariant governs: **never panic**. A parse failure is a
//! `Result`; a panic here is a remote crash.

#![forbid(unsafe_code)]

pub mod levin;
pub mod messages;
pub mod peer;
pub mod sync;

pub use levin::{command, flags, Header, Kind, LevinError, Reassembler, Reassembly};
pub use messages::{BasicNodeData, CoreSyncData, MessageError, NetworkAddress, PeerlistEntry};
pub use peer::{NodeIdentity, Peer, PeerError};
pub use sync::{sync_from, ChainTip, Progress, SyncError};
