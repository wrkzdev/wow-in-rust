//! The transaction-verification seam (`specs/06` §5.11).
//!
//! `specs/06` §2 step 9 runs `check_tx_inputs` over every transaction a block
//! names, and §5.11 says what that means: each ring signature, the range
//! proof, and the commitment sum `sum(pseudoOuts) == sum(outPk) + fee*H` --
//! plus, from §5.4, that every ring member is unlocked and old enough.
//!
//! It is a trait for the same reasons [`crate::pow`] is, and one more:
//!
//! * The checks need a ring resolved out of the store, so they are not pure
//!   functions over the block the way the rest of `specs/06` is.
//! * They cost more than everything else in the block path put together. Who
//!   does that work, and on how many cores, belongs to the caller: `wownerod`
//!   verifies a whole sync batch side by side *before* it takes the chain
//!   lock, exactly as it already does for proofs of work.
//! * Not every caller has a chain to resolve rings against. The tests that
//!   drive [`crate::Blockchain`] over a store double are not about ring
//!   signatures.
//!
//! A `Blockchain` with no verifier set does none of this, which is what every
//! caller but `wownerod` wants. Setting one is
//! [`crate::Blockchain::verify_transactions_with`].
//!
//! # Why the height goes in
//!
//! `chain_height` is the height the chain stands at **before** the block is
//! added, which is what the C++ `check_tx_inputs` sees (`m_db->height()` is
//! called while the block is still being validated). It decides two things:
//! whether a ring member's unlock time has passed, and whether it is at least
//! `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` blocks old.
//!
//! Both are **monotone in the height**: an output unlocked at height *h* is
//! unlocked at every height above it, and one old enough at *h* is old enough
//! later. So a result computed at a lower height and reused at a higher one
//! can only be too strict, never too permissive -- which is what makes it safe
//! for a caller to verify a whole batch ahead of applying it.

use wow_crypto::types::Hash256;
use wow_types::tx::Transaction;

/// Why a transaction did not verify.
///
/// Two cases, and they mean opposite things about whoever sent the block:
/// [`TxCheckError::Invalid`] is the sender's fault, and
/// [`TxCheckError::Unsupported`] is **ours**. The block is refused either way
/// -- a node that waved through what it could not check would be trusting the
/// sender for exactly the thing it exists not to trust them for -- but the
/// peer is not banned for a rule this node has not written yet.
///
/// The same distinction [`crate::pow::PowError::CryptoNightNotImplemented`]
/// makes, for the same reason: a missing rule once cost this node every peer
/// it had at a hard-fork block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxCheckError {
    /// A ring signature, the range proof, the commitment sum or a ring member
    /// did not check out.
    Invalid(String),
    /// This node has no verifier for a transaction of this shape.
    Unsupported(String),
}

impl std::fmt::Display for TxCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxCheckError::Invalid(w) => f.write_str(w),
            TxCheckError::Unsupported(w) => f.write_str(w),
        }
    }
}

impl std::error::Error for TxCheckError {}

/// Verifies a block's transactions against the chain (`specs/06` §5.11).
pub trait TxVerifier: Send + Sync {
    /// Check one transaction of a block, with the chain standing at
    /// `chain_height`.
    ///
    /// `hash` is the transaction's id, so an implementation can recognise work
    /// it has already done; `now` is the wall clock, for time-based unlocks.
    ///
    /// The error carries a sentence rather than a code, because the only thing
    /// upstream branches on is [`TxCheckError`]'s two cases; the sentence is
    /// for telling an operator *which* of §5.11 failed.
    fn verify(
        &self,
        hash: &Hash256,
        tx: &Transaction,
        hf_version: u8,
        chain_height: u64,
        now: u64,
    ) -> Result<(), TxCheckError>;
}

/// A verifier that refuses everything, for tests that want to prove the seam
/// is reached.
///
/// The mirror of [`crate::pow::TrustingVerifier`], and the useful direction:
/// a test can show a block is rejected *because* its transactions were
/// checked, which a permissive double cannot.
#[derive(Debug, Default, Clone, Copy)]
pub struct RefusingTxVerifier;

impl TxVerifier for RefusingTxVerifier {
    fn verify(
        &self,
        _hash: &Hash256,
        _tx: &Transaction,
        _hf_version: u8,
        _chain_height: u64,
        _now: u64,
    ) -> Result<(), TxCheckError> {
        Err(TxCheckError::Invalid(
            "this verifier refuses every transaction".to_string(),
        ))
    }
}
