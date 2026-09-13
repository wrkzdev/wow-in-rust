//! `BlockchainDb` trait plus the LMDB implementation, byte-compatible with wownerod's `data.mdb` (`specs/10-storage-lmdb.md`).
//!
//! Scheduled for milestone **M2** (`specs/00-overview.md` §6) and in progress.
//!
//! `specs/15` §3.3 sets the order of work: "Comparator unit tests **first**",
//! because a wrong comparator silently breaks every `MDB_GET_BOTH` lookup
//! rather than failing loudly. [`comparator`] is that, and it is complete. The
//! record layouts (`specs/10` §4) are next, and are done: [`records`] encodes
//! and decodes every value type byte-exactly, field by field with length
//! checks. The `BlockchainDb` trait (§9) and the LMDB environment itself
//! follow.

//! # `unsafe`
//!
//! `specs/10` §1.1 is blunt about why this crate cannot be `forbid(unsafe_code)`
//! the way the rest of the workspace is: LMDB hands out pointers into an
//! mmap'd region, and a corrupt or externally-modified `data.mdb` is undefined
//! behaviour rather than an error return. `heed` marks the affected entry
//! points `unsafe` and this crate keeps them that way.
//!
//! The rule is `deny`, not `forbid`, with a per-site exception carrying a
//! `SAFETY` note — and the exceptions are confined to environment setup. No
//! record decoder uses `unsafe`: every one of them checks the slice length and
//! returns an error (`specs/10` §4).
#![deny(unsafe_code)]

pub mod comparator;
pub mod db;
pub mod env;
pub mod lmdb;
pub mod raw;
pub mod records;
pub mod semantics;
pub mod tables;

pub use comparator::{
    assert_little_endian, compare_hash32, compare_string, compare_uint64, ZEROKEY,
};
pub use db::{AltBlockData, BlockchainDb, DbError, OutputData, TxData};
pub use env::{check_version, db_dir, OpenMode, SyncMode, VersionVerdict, VERSION};
pub use records::{
    AltBlock, BlockHeight, BlockInfo, OutKey, OutTx, RecordError, RelayMethod, TxIndex, TxPoolMeta,
};
pub use tables::{Cmp, Table, TABLES};
