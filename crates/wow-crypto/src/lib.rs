//! Wownero cryptographic primitives.
//!
//! `specs/02-crypto.md`. Everything in that document is consensus-critical: a
//! one-bit difference in any primitive produces a node that cannot validate the
//! chain.
//!
//! # What is here
//!
//! | Module | Covers |
//! |---|---|
//! | [`keccak`] | Keccak-f[1600] and Keccak-256 with the **original** padding |
//! | [`hash`] | `cn_fast_hash`, `tree_hash` (the tx Merkle root) |
//! | [`field`] | GF(2^255-19), for `ge_fromfe_frombytes_vartime` only |
//! | [`ops`] | ed25519 group/scalar ops, `hash_to_ec`, key images |
//! | [`keys`] | key derivation, view tags, subaddresses, payment-id encryption |
//! | [`signature`] | the CryptoNote Schnorr signature and v1 ring signatures |
//! | [`base58`] | CryptoNote base58 and address encoding |
//! | [`mnemonic`] | 25-word seeds in 13 languages |
//! | [`random`] | `random_scalar`, and the reference's deterministic test PRNG |
//! | [`cn`] | CryptoNight v0 and its four final hashes |
//!
//! # Not here yet
//!
//! CLSAG and Bulletproofs+ are two of the three "algorithm gaps" named in
//! `specs/README.md` (the third, CryptoNight, is now in [`cn`]): for those the
//! C++ is the specification and the spec documents only the wire format, the
//! domain separators and the conventions.
//!
//! CryptoNight variants 1, 2 and 4 are also absent — see [`cn`] for why that
//! matters only to a node verifying from genesis.
//!
//! # Conventions that differ from a standard ed25519 library
//!
//! * **Point decoding is permissive.** Small-order and non-canonical `y`
//!   encodings are accepted, because `ge_frombytes_vartime` accepts them. Do
//!   not add torsion or canonicality checks that the C does not have.
//! * **Keccak, not SHA-3.** `cn_fast_hash(b"")` is
//!   `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.
//! * **`hash_to_ec` is not a standard hash-to-curve.** It is the CryptoNote
//!   map, ported literally.
//!
//! # Validation
//!
//! `tests/reference_vectors.rs` runs all 5,545 vectors from the reference
//! tree's `tests/crypto/tests.txt`, vendored at `tests/corpus/crypto/`. That is
//! the M1 gate for this crate (`specs/15-testing-and-conformance.md` §2.1).

#![forbid(unsafe_code)]

pub mod base58;
pub mod bulletproofs_plus;
pub mod clsag;
pub mod cn;
pub mod field;
pub mod hash;
pub mod hex;
pub mod keccak;
pub mod keys;
pub mod md5;
pub mod mnemonic;
pub mod ops;
pub mod random;
pub mod rct;
pub mod signature;
pub mod types;

/// Wiping a secret when it goes out of scope.
///
/// Re-exported so that every crate holding a password, a seed or a derived key
/// wipes it the same way, and none of them has to name the dependency itself.
/// `src/crypto/crypto.h`'s `secret_key` is a `tools::scrubbed` and
/// `contrib/epee/include/wipeable_string.h` is the same idea for text: memory
/// a secret passed through is overwritten rather than left for whatever reads
/// the page next -- a core dump, a swap file, or the next allocation.
///
/// It is not a guarantee. A `String` that grows reallocates and leaves the old
/// bytes behind, and nothing here locks pages against swap (`mlock`, which the
/// C++ does do). It closes the common case.
pub use zeroize::{Zeroize, Zeroizing};

pub use hash::{cn_fast_hash, tree_hash, NULL_HASH};
pub use keys::{
    derivation_to_scalar, derive_public_key, derive_secret_key, derive_subaddress_public_key,
    derive_view_tag, generate_key_derivation, get_subaddress, view_key_from_spend_key,
};
pub use ops::{
    check_key, generate_key_image, hash_to_ec, hash_to_point, hash_to_scalar, sc_check,
    sc_reduce32, secret_key_to_public_key,
};
pub use signature::{
    check_ring_signature, check_signature, generate_ring_signature, generate_signature,
};
pub use types::{
    AccountPublicAddress, EcPoint, EcScalar, Hash256, Hash8, KeyDerivation, KeyImage, PublicKey,
    SecretKey, Signature, SubaddressIndex, ViewTag,
};
