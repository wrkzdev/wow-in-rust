//! Wownero wire formats.
//!
//! Wownero uses **three** distinct encodings and mixing them up is the most
//! common source of interop failure (`specs/04-serialization.md`):
//!
//! | Encoding | Where | Consensus? |
//! |---|---|---|
//! | [`binary`] archive | block/tx blobs, everything hashed, the blockchain DB | **yes**, byte-exact |
//! | [`epee`] portable storage | Levin P2P payloads, `*.bin` RPC, `p2pstate.bin` | wire-exact |
//! | JSON | JSON-RPC and plain-HTTP RPC | field-name exact |
//!
//! JSON lives with the RPC types rather than here, because its field names come
//! from the same `KV_SERIALIZE` macros as the portable-storage entry names.
//!
//! The two varint encodings are deliberately in separate modules that do not
//! re-export each other: [`varint`] is the consensus base-128 one, and
//! [`epee::varint`] is the `(value << 2) | width` one.

#![forbid(unsafe_code)]

pub mod binary;
pub mod epee;
pub mod error;
pub mod varint;

pub use binary::{BinDeserialize, BinSerialize, Reader, Writer};
pub use error::{Error, Result};
