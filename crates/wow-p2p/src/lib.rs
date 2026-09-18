//! Levin codec, peer lists, connection manager, sync, Dandelion++ relay
//! (`specs/08-p2p.md`).
//!
//! [`levin`] is the wire framing — the 33-byte header, the command set, the
//! size limits and fragment reassembly — and [`frame`] reads it off a socket
//! that times out. [`messages`] is what peers exchange (`specs/08` §3).
//!
//! Two ways to use a peer:
//!
//! * [`peer`] and [`sync`]: one outgoing connection, driven synchronously --
//!   dial, handshake, pull a chain. What `wownerod --sync-from` uses.
//! * [`node`]: a whole node. It listens and dials, keeps [`addressbook`]'s
//!   white, gray and anchor lists and its bans, syncs from whichever peer is
//!   ahead, serves chain data to peers that are behind, and relays blocks and
//!   transactions -- deciding nothing about validity itself, which it asks a
//!   [`node::Core`] about.
//!
//! [`queue`] spreads a node's sync across several peers (§5.6).
//!
//! [`socks`] is the SOCKS5 client a proxied connection dials through (§7.4).
//!
//! Not here: pruning (§9), and the i2p/Tor zones and their noise channels
//! (§7.4).
//!
//! Everything in this crate parses bytes an unauthenticated peer chose, so
//! `specs/15` §4.4's invariant governs: **never panic**. A parse failure is a
//! `Result`; a panic here is a remote crash.

#![forbid(unsafe_code)]

pub mod addressbook;
pub mod frame;
pub mod levin;
pub mod messages;
pub mod net;
pub mod node;
pub mod peer;
pub mod queue;
pub mod socks;
pub mod sync;

pub use levin::{command, flags, Header, Kind, LevinError, Reassembler, Reassembly};
pub use messages::{BasicNodeData, CoreSyncData, MessageError, NetworkAddress, PeerlistEntry};
pub use peer::{NodeIdentity, Peer, PeerError};
pub use sync::{sync_from, ChainTip, Progress, SyncError};
