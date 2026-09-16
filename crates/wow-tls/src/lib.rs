//! TLS for the node and the wallets, on one [`provider`].
//!
//! `wownerod` serves its RPC over TLS with it (`bin/wownerod/src/rpc/tls.rs`),
//! and `wow-daemon-client` reaches an `https://` node with it, so a wallet's
//! TLS is as pure Rust as the node's: no ring, aws-lc-rs or OpenSSL.

pub mod provider;
