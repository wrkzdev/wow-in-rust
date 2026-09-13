//! Wownero block, transaction, RingCT and address types.
//!
//! `specs/05-blocks-and-transactions.md`, with the wire encoding from
//! `specs/04-serialization.md` §1.
//!
//! # The shape of this crate
//!
//! Every structure here carries its **binary-archive** encoding, because the
//! encoding is the type: the format is positional with no field names and no
//! framing, so declaration order is part of the wire format
//! (`specs/04` §1.2).
//!
//! Two properties are load-bearing and easy to lose:
//!
//! * **Context-dependent lengths.** `rctSigPrunable` cannot be parsed without
//!   `(type, inputs, outputs, mixin)`, none of which appear on the wire — they
//!   come from the already-parsed prefix (`specs/04` §1.4). That is why
//!   [`wow_serialize::BinDeserialize`] takes a context rather than following
//!   serde's model.
//! * **Hashes come from blob offsets, not re-serialization.** A v2 transaction
//!   hash is a hash of three hashes over slices of the original blob
//!   (`specs/05` §3.2), so [`tx::Transaction`] records `prefix_size` and
//!   `unprunable_size` while parsing.
//!
//! # Round-trip
//!
//! `serialize(parse(blob)) == blob` is the M1 gate (`specs/15` §2.2): it
//! catches non-canonical varints, missed conditional fields and wrong
//! array-length derivations in one assertion.

#![forbid(unsafe_code)]

pub mod address;
pub mod block;
pub mod difficulty;
pub mod hashes;
pub mod limits;
pub mod rct;
pub mod tx;
pub mod tx_extra;
pub mod weight;

pub use address::{Address, AddressError, AddressKind, Network};
pub use block::{Block, BlockHeader};
pub use difficulty::{check_hash, Difficulty};
pub use hashes::{transaction_hash, transaction_hash_from_blob, tx_prefix_hash};
pub use rct::{RctSignatures, RctType};
pub use tx::{Transaction, TransactionPrefix, TxIn, TxOut, TxOutTarget};
pub use weight::get_transaction_weight;

// Re-exported so downstream crates need only one dependency for the common
// types.
pub use wow_crypto::types::{
    AccountPublicAddress, Hash256, Hash8, KeyImage, PublicKey, SecretKey, Signature,
    SubaddressIndex, ViewTag,
};
pub use wow_serialize::error::{Error, Result};
