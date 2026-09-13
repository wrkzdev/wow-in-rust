//! ZeroMQ's wire protocol, ZMTP 3.1, for the daemon's ZMQ RPC and its
//! publisher (`specs/09` §3.2; `src/rpc/zmq_server.cpp` in the C++).
//!
//! # Not libzmq
//!
//! The C++ links libzmq. This crate speaks the protocol itself -- RFC 23's
//! framing and RFC 37's NULL-security handshake -- so the node carries no C
//! library and no cross-build for one. It implements what the daemon needs and
//! nothing else:
//!
//! * [`RepServer`]: a REP socket answering REQ and DEALER peers, as
//!   `--zmq-rpc-bind-port` serves;
//! * [`Publisher`]: a PUB socket with prefix subscriptions, as `--zmq-pub`
//!   serves;
//! * [`ReqSocket`] and [`SubSocket`]: the other ends, for tests and tools.
//!
//! No CURVE or PLAIN security (the C++ daemon uses neither), no IPC or in-proc
//! transports, and one TCP connection per client socket.
//!
//! # This faces the network
//!
//! A frame's size is checked against [`MAX_MESSAGE_SIZE`] before its body is
//! allocated, and nothing here panics on what a peer sends.

#![forbid(unsafe_code)]

pub mod client;
pub mod server;
pub mod zmtp;

pub use client::{ReqSocket, SubSocket};
pub use server::{Handler, Publisher, RepServer};
pub use zmtp::{SocketType, ZmtpError, MAX_MESSAGE_SIZE};
