//! Wallet core: keys, files, and scanning (`specs/12-wallet-core.md`).
//!
//! Milestone **M4** (`specs/00-overview.md` §6).
//!
//! | Module | Covers |
//! |---|---|
//! | [`chacha`] | ChaCha8/20 and the three key derivations built on them |
//! | [`account`] | `account_base`, and the `key_data` blob |
//! | [`keys_file`] | the `<name>.keys` file, read and written compatibly |
//! | [`subaddress`] | the spend-key → `(major, minor)` table |
//! | [`scan`] | deciding whether a transaction paid this wallet |
//! | [`history`] | what this wallet sent, and its transfer history |
//! | [`rings`] | the rings this wallet has spent with, to spend with again |
//! | [`store`] | where an open wallet's files live: on disk, or in memory a program keeps |
//! | [`send`] | a destination to a relayed transaction, prepared and then committed |
//!
//! # What is here and what is not
//!
//! Everything needed to **open a wallet and recognise money arriving**: the
//! keys file the C++ wallet writes, address and subaddress derivation, output
//! scanning with view tags, RingCT amount decoding, and key images.
//!
//! And spending: input selection and the fee ([`spend`]), decoys ([`decoys`]),
//! building and signing ([`transfer`]), and the path from a destination to a
//! relayed transaction that every wallet front end shares ([`send`]).
//!
//! The cache file (`specs/12` §2.2) is deliberately **not** the C++ format —
//! that is a Boost portable binary archive, and §2.2 says so and says to detect
//! one and rescan from the chain instead. The keys file is the one that must be
//! shared, and it is.

pub mod account;
pub mod chacha;
pub mod clock;
pub mod decoys;
pub mod entropy;
pub mod files;
pub mod history;
pub mod keys_file;
pub mod lock;
pub mod priority;
pub mod refresh;
pub mod rings;
pub mod scan;
pub mod send;
pub mod spend;
pub mod store;
pub mod subaddress;
pub mod transfer;

pub use account::{AccountBase, AccountError, AccountKeys};
pub use decoys::{select_ring, GammaPicker, RandomSource, Ring};
pub use files::PoolCheck;
pub use history::{EntryKind, HistoryEntry, PooledTx, SentDestination, SentState, SentTx};
pub use keys_file::{AskPassword, KeysFile, KeysFileError};
pub use refresh::{BlockSource, RefreshError, RefreshEvent, RefreshSummary, Transfer, WalletState};
pub use scan::{scan_transaction, Received, ScanError, ScanKeys};
pub use spend::{plan, plan_sweep, SpendError, SpendOptions, SpendPlan};
pub use subaddress::SubaddressTable;
