//! The proof-of-work seam.
//!
//! `specs/03-pow.md`. Wownero uses **RandomWOW** from HF 13 (height 114,969)
//! and CryptoNight variants before it.
//!
//! This is a trait rather than a direct call for two reasons, and only one of
//! them is the usual one:
//!
//! * **CryptoNight is not implemented yet.** `specs/03` §2 allows deferring it,
//!   and [`RandomWowOnly`] makes the gap explicit — a pre-HF-13 block returns
//!   [`PowError::CryptoNightNotImplemented`] rather than being waved through.
//!   A node that silently skipped those proofs would sync a chain nobody else
//!   agrees with.
//! * A verifying node can skip the proof below a **precomputed hash file**
//!   (`specs/01` §14.1) or below the last checkpoint, and that decision belongs
//!   to the caller, not to the hasher.

use wow_crypto::types::Hash256;

/// Why a proof of work could not be computed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PowError {
    /// Pre-HF-13 blocks need CryptoNight v0/v1/v2/v4, which this node does not
    /// have yet (`specs/02` §7, `specs/03` §2).
    CryptoNightNotImplemented { height: u64, variant: &'static str },
    /// The RandomWOW library refused.
    RandomWow(String),
    /// The block has no hashing blob — it did not parse far enough.
    NoHashingBlob,
}

impl std::fmt::Display for PowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PowError::CryptoNightNotImplemented { height, variant } => write!(
                f,
                "height {height} needs CryptoNight {variant}, which is not \
                 implemented; see specs/02 §7. Sync from a checkpoint above \
                 HF 13 (114,969) or wait for it."
            ),
            PowError::RandomWow(e) => write!(f, "randomwow: {e}"),
            PowError::NoHashingBlob => write!(f, "block has no hashing blob"),
        }
    }
}

impl std::error::Error for PowError {}

/// Computes a block's proof-of-work hash.
pub trait PowVerifier: Send + Sync {
    /// The PoW hash for a block at `height`.
    ///
    /// `seed_hash` is the RandomWOW seed for this height (`specs/03` §3), which
    /// the caller resolves because it needs the chain to do so.
    fn pow_hash(
        &self,
        height: u64,
        major_version: u8,
        hashing_blob: &[u8],
        seed_hash: &Hash256,
    ) -> Result<Hash256, PowError>;

    /// May the proof be skipped at this height?
    ///
    /// `specs/06` §2 step 6: "unless a precomputed hash covers this height".
    /// The default is never.
    fn may_skip(&self, _height: u64) -> bool {
        false
    }
}

/// Which CryptoNight variant a pre-HF-13 height needs (`specs/03` §2).
pub const fn cryptonight_variant(major_version: u8) -> &'static str {
    match major_version {
        0..=6 => "v0",
        7 => "v1",
        8..=9 => "v2",
        _ => "v4/r",
    }
}

/// A verifier that handles RandomWOW and refuses everything older.
///
/// The refusal is the point: `specs/03` §2 permits deferring CryptoNight, but
/// not pretending a block passed.
pub struct RandomWowOnly<F>(pub F)
where
    F: Fn(&[u8], &Hash256) -> Result<Hash256, String> + Send + Sync;

impl<F> PowVerifier for RandomWowOnly<F>
where
    F: Fn(&[u8], &Hash256) -> Result<Hash256, String> + Send + Sync,
{
    fn pow_hash(
        &self,
        height: u64,
        major_version: u8,
        hashing_blob: &[u8],
        seed_hash: &Hash256,
    ) -> Result<Hash256, PowError> {
        // `RX_BLOCK_VERSION` is 13 (`specs/03` §3).
        if major_version < 13 {
            return Err(PowError::CryptoNightNotImplemented {
                height,
                variant: cryptonight_variant(major_version),
            });
        }
        (self.0)(hashing_blob, seed_hash).map_err(PowError::RandomWow)
    }
}

/// A verifier that accepts everything, for tests that are not about PoW.
///
/// Never use this on a real chain: it is the difference between verifying and
/// trusting.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrustingVerifier;

impl PowVerifier for TrustingVerifier {
    fn pow_hash(
        &self,
        _height: u64,
        _major_version: u8,
        _hashing_blob: &[u8],
        _seed_hash: &Hash256,
    ) -> Result<Hash256, PowError> {
        // The all-zero hash beats every difficulty, which is what "accept" means
        // to `check_hash`.
        Ok([0u8; 32])
    }

    fn may_skip(&self, _height: u64) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The variants, by the hard-fork ranges in `specs/03` §2.
    #[test]
    fn the_cryptonight_variants_map_to_versions() {
        assert_eq!(cryptonight_variant(1), "v0");
        assert_eq!(cryptonight_variant(6), "v0");
        assert_eq!(cryptonight_variant(7), "v1");
        assert_eq!(cryptonight_variant(8), "v2");
        assert_eq!(cryptonight_variant(9), "v2");
        assert_eq!(cryptonight_variant(10), "v4/r");
        assert_eq!(cryptonight_variant(12), "v4/r");
    }

    /// A pre-HF-13 block is **refused**, not accepted. `specs/03` §2 allows
    /// deferring CryptoNight; it does not allow skipping the check.
    #[test]
    fn pre_hf13_blocks_are_refused_rather_than_waved_through() {
        let v = RandomWowOnly(|_: &[u8], _: &Hash256| Ok([0u8; 32]));

        for version in 7u8..13 {
            let e = v.pow_hash(1000, version, b"blob", &[0; 32]).unwrap_err();
            assert!(
                matches!(e, PowError::CryptoNightNotImplemented { .. }),
                "version {version} must be refused, got {e:?}"
            );
            // And the message says what is missing and how to work around it.
            let s = e.to_string();
            assert!(s.contains("CryptoNight"));
            assert!(s.contains("114,969"), "points at the HF 13 height");
        }

        // From 13 it delegates.
        assert_eq!(v.pow_hash(1000, 13, b"blob", &[0; 32]), Ok([0u8; 32]));
        assert_eq!(v.pow_hash(1000, 20, b"blob", &[0; 32]), Ok([0u8; 32]));
    }

    #[test]
    fn a_randomwow_failure_is_reported_not_swallowed() {
        let v = RandomWowOnly(|_: &[u8], _: &Hash256| Err("dataset missing".to_string()));
        let e = v.pow_hash(200_000, 20, b"blob", &[0; 32]).unwrap_err();
        assert_eq!(e, PowError::RandomWow("dataset missing".into()));
        assert!(e.to_string().contains("dataset missing"));
    }

    /// The trusting verifier returns a hash that beats any difficulty, which is
    /// what makes it usable in tests and unusable in production.
    #[test]
    fn the_trusting_verifier_beats_every_difficulty() {
        let h = TrustingVerifier
            .pow_hash(0, 20, b"", &[0; 32])
            .expect("never fails");
        assert_eq!(h, [0u8; 32]);
        assert!(wow_types::check_hash(&h, u128::from(u64::MAX)));
        assert!(TrustingVerifier.may_skip(0));
    }

    #[test]
    fn the_default_verifier_never_skips() {
        let v = RandomWowOnly(|_: &[u8], _: &Hash256| Ok([0u8; 32]));
        for h in [0u64, 1, 114_969, 514_000, u64::MAX] {
            assert!(!v.may_skip(h), "height {h}");
        }
    }
}
