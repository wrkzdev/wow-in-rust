//! The `Blockchain` state machine, transaction pool and miner
//! (`specs/06-consensus-rules.md`, `specs/00-overview.md` §5).
//!
//! Milestone **M2/M3**, in progress. [`chain::Blockchain`] runs the twelve
//! ordered validation steps of `specs/06` §2 over a [`wow_storage`] store, and
//! [`pow`] is the seam where proof-of-work verification plugs in.
//!
//! The ordering is the point. `specs/06` §2 opens with "**Order matters because
//! some checks feed later ones**", and [`chain::Step`] names each one so a
//! rejection reports how far a block got rather than only that it failed.

#![forbid(unsafe_code)]

pub mod chain;
pub mod error;
pub mod pow;

pub use chain::{Blockchain, ChainState, Rejection, Step};
pub use error::{Added, BlockError};
pub use pow::{PowError, PowVerifier, RandomWowOnly, TrustingVerifier};
