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
//!
//! # What is here and what is not
//!
//! Everything needed to **open a wallet and recognise money arriving**: the
//! keys file the C++ wallet writes, address and subaddress derivation, output
//! scanning with view tags, RingCT amount decoding, and key images.
//!
//! **Spending is not here.** Building a transaction needs CLSAG signing and
//! Bulletproofs+ proving, the two remaining "algorithm gaps" of
//! `specs/README.md`, and neither is implemented in `wow-crypto` yet. Input
//! selection, decoy selection and fee calculation (`specs/12` §4) wait on them,
//! because there is no point selecting inputs for a transaction that cannot be
//! signed.
//!
//! The cache file (`specs/12` §2.2) is deliberately **not** the C++ format —
//! that is a Boost portable binary archive, and §2.2 says so and says to detect
//! one and rescan from the chain instead. The keys file is the one that must be
//! shared, and it is.

pub mod account;
pub mod chacha;
pub mod decoys;
pub mod entropy;
pub mod files;
pub mod keys_file;
pub mod refresh;
pub mod scan;
pub mod spend;
pub mod subaddress;
pub mod transfer;

pub use account::{AccountBase, AccountError, AccountKeys};
pub use decoys::{select_ring, GammaPicker, RandomSource, Ring};
pub use keys_file::{AskPassword, KeysFile, KeysFileError};
pub use refresh::{BlockSource, RefreshError, Transfer, WalletState};
pub use scan::{scan_transaction, Received, ScanError, ScanKeys};
pub use spend::{plan, plan_sweep, SpendError, SpendOptions, SpendPlan};
pub use subaddress::SubaddressTable;
