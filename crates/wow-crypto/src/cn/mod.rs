//! CryptoNight and its four final hashes.
//!
//! `specs/02-crypto.md` §7: "a Rust wallet **must implement CryptoNight v0**
//! even though the chain no longer uses it, purely to open existing wallet
//! files".
//!
//! [`cn_slow_hash`] is the whole function; [`aes`] holds the round function it
//! mixes with. It ends by running one of four hashes over its Keccak state,
//! chosen by `state[0] & 3`:
//!
//! | `state[0] & 3` | hash |
//! |---|---|
//! | 0 | [`blake256`] |
//! | 1 | [`groestl256`] |
//! | 2 | [`jh256`] |
//! | 3 | [`skein256`] |
//!
//! All five are validated against the reference tree's own vectors in
//! `tests/corpus/cryptonight/`: 321 each for the final hashes, and the four in
//! `tests-slow.txt` for CryptoNight itself.
//!
//! Variants 0 and 1 are implemented. Variant 1 is what mainnet used for proof
//! of work at major versions 7 and 8 (`specs/03` §2), which is the first
//! stretch of the chain and what a regtest chain from genesis mines with.
//! Variants 2 and 4 cover versions 9-12 and are still missing; their vectors
//! are vendored at `tests-slow-2.txt` and `-4` and are not yet exercised.

pub mod aes;
pub mod blake256;
pub mod groestl256;
pub mod jh256;
pub mod skein256;
pub mod slow_hash;

pub use blake256::blake256;
pub use groestl256::groestl256;
pub use jh256::jh256;
pub use skein256::skein256;
pub use slow_hash::{cn_slow_hash, cn_slow_hash_v1, CnError, Variant};
