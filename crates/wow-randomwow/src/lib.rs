//! RandomWOW — Wownero's proof of work.
//!
//! `specs/03-pow.md`. RandomWOW is RandomX compiled with a Wownero-specific
//! `configuration.h`: the algorithm structure is unmodified, only the
//! parameters differ. The three that matter most are a **1 MiB** scratchpad
//! (RandomX: 2 MiB), **1024** program iterations (2048), **16** programs (8),
//! and the Argon2d salt `"RandomWOW\x01"` (`"RandomX\x03"`).
//!
//! > **Using upstream RandomX defaults produces valid-looking hashes that fail
//! > every difficulty check on the real chain.**
//!
//! That failure mode is silent and confusing, so it is guarded three times:
//! `build.rs` refuses to build against the wrong `configuration.h`,
//! [`config::verify_linked_configuration`] re-checks the **linked** library at
//! runtime, and the tests in [`config`] assert the salt and the frequency sum
//! that `specs/15` §2.4 names. `tests/hashing.rs` closes the loop by checking
//! that the canonical RandomX test vector does *not* come out to upstream
//! RandomX's published answer.
//!
//! # What is here
//!
//! * [`config`] — the linked library's parameters, read back through FFI.
//! * [`seed`] — seed-hash epochs (`rx_seedheight`), pure arithmetic.
//! * [`vm`] — safe `Cache` / `Dataset` / `Vm` wrappers and a two-slot
//!   [`vm::SeedCache`].
//! * [`ffi`] — the raw bindings.
//!
//! # What is not
//!
//! CryptoNight v0/v1/v2/v4, which `pow_hash` needs for blocks below HF 13
//! (`specs/03` §2). A node syncing from a checkpointed snapshot never evaluates
//! them; a node verifying from genesis does, and a wallet needs v0 to decrypt
//! existing key files (`specs/02` §7). That is M2/M4 work.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod config;
pub mod ffi;
pub mod seed;
pub mod vm;

pub use config::{verify_linked_configuration, Configuration};
pub use seed::{rx_seedheight, rx_seedheights, SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG};
pub use vm::{Cache, Dataset, RandomWowError, SeedCache, Vm};

/// A 32-byte hash.
pub type Hash256 = [u8; 32];

/// `RX_BLOCK_VERSION` — the hard-fork version at which RandomWOW takes over
/// from CryptoNight (`specs/01` §3.4).
pub const RX_BLOCK_VERSION: u8 = 13;

/// The height whose proof-of-work hash is hard-coded (`specs/03` §5).
pub const POW_OVERRIDE_HEIGHT: u64 = 202_612;

/// The hard-coded hash `get_block_longhash` returns at height 202,612,
/// regardless of the block's contents.
///
/// A Monero artifact — their block 202,612 held 514 transactions and tripped a
/// bug in the original `tree_hash_cnt`. Wownero inherited the workaround
/// verbatim, **and it fires on Wownero's own height 202,612**, where the block
/// is a RandomWOW block at HF 15 (`specs/06` §9.2).
///
/// Do not "fix" this by removing it: a node that computes the real hash there
/// disagrees with the reference about whether the block is valid whenever PoW
/// is actually checked.
pub const POW_OVERRIDE_HASH: Hash256 = [
    0x84, 0xf6, 0x47, 0x66, 0x47, 0x5d, 0x51, 0x83, 0x7a, 0xc9, 0xef, 0xbe, 0xf1, 0x92, 0x64, 0x86,
    0xe5, 0x85, 0x63, 0xc9, 0x5a, 0x19, 0xfe, 0xf4, 0xae, 0xc3, 0x25, 0x4f, 0x03, 0x00, 0x00, 0x00,
];

/// Which proof-of-work algorithm a block uses (`specs/03` §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowAlgorithm {
    /// The hard-coded hash at height 202,612. Checked **first**, before any
    /// version dispatch — `specs/03` §7.
    Override,
    /// `cn_slow_hash(blob, variant, height)`. Variant 4 takes `height` as an
    /// input, which is why it is carried here.
    CryptoNight { variant: u8 },
    /// RandomWOW, keyed by the block id at `rx_seedheight(height)`.
    RandomWow,
}

/// Select the algorithm for a block, reproducing `get_block_longhash`'s
/// dispatch order.
///
/// ```
/// use wow_randomwow::{select_algorithm, PowAlgorithm};
/// // The override wins over everything, including the version dispatch.
/// assert_eq!(select_algorithm(202_612, 15), PowAlgorithm::Override);
/// assert_eq!(select_algorithm(1, 7), PowAlgorithm::CryptoNight { variant: 1 });
/// assert_eq!(select_algorithm(60_000, 9), PowAlgorithm::CryptoNight { variant: 2 });
/// assert_eq!(select_algorithm(90_000, 11), PowAlgorithm::CryptoNight { variant: 4 });
/// assert_eq!(select_algorithm(200_000, 13), PowAlgorithm::RandomWow);
/// ```
pub fn select_algorithm(height: u64, major_version: u8) -> PowAlgorithm {
    // MUST come first (`specs/03` §2, §7).
    if height == POW_OVERRIDE_HEIGHT {
        return PowAlgorithm::Override;
    }
    if major_version >= RX_BLOCK_VERSION {
        PowAlgorithm::RandomWow
    } else if major_version >= 11 {
        PowAlgorithm::CryptoNight { variant: 4 }
    } else if major_version >= 9 {
        PowAlgorithm::CryptoNight { variant: 2 }
    } else {
        PowAlgorithm::CryptoNight { variant: 1 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `specs/03` §7: "`pow_hash` checks `height == 202612` **first**, before
    /// any version dispatch."
    #[test]
    fn the_override_precedes_version_dispatch() {
        // Whatever the major version, height 202,612 takes the override.
        for v in [7u8, 9, 11, 13, 15, 20, 255] {
            assert_eq!(
                select_algorithm(POW_OVERRIDE_HEIGHT, v),
                PowAlgorithm::Override,
                "major_version {v}"
            );
        }
        // The neighbouring heights do not.
        assert_eq!(select_algorithm(202_611, 15), PowAlgorithm::RandomWow);
        assert_eq!(select_algorithm(202_613, 15), PowAlgorithm::RandomWow);
    }

    /// The version-to-algorithm table from `specs/03` §2.
    #[test]
    fn algorithm_by_major_version() {
        for v in [7u8, 8] {
            assert_eq!(
                select_algorithm(1000, v),
                PowAlgorithm::CryptoNight { variant: 1 }
            );
        }
        for v in [9u8, 10] {
            assert_eq!(
                select_algorithm(1000, v),
                PowAlgorithm::CryptoNight { variant: 2 }
            );
        }
        for v in [11u8, 12] {
            assert_eq!(
                select_algorithm(1000, v),
                PowAlgorithm::CryptoNight { variant: 4 }
            );
        }
        for v in [13u8, 14, 15, 18, 20] {
            assert_eq!(select_algorithm(1000, v), PowAlgorithm::RandomWow);
        }
    }

    /// The mainnet height at which the algorithm actually changes, per the
    /// hard-fork table: HF 13 activates at 114,969.
    #[test]
    fn the_randomwow_switch_is_at_114969() {
        assert_eq!(
            select_algorithm(114_968, 12),
            PowAlgorithm::CryptoNight { variant: 4 }
        );
        assert_eq!(select_algorithm(114_969, 13), PowAlgorithm::RandomWow);
    }

    /// The override hash, as a little-endian u256, passes `check_hash` only for
    /// difficulty <= 1,297,898,660 (`specs/03` §5 item 2) — which is well below
    /// the real difficulty in that range, and is why a from-genesis run with
    /// `--fast-block-sync 0` can reject the block.
    #[test]
    fn the_override_hash_has_a_low_difficulty_ceiling() {
        // Reconstruct the constant from its documented hex to catch a typo.
        let hex = "84f64766475d51837ac9efbef1926486e58563c95a19fef4aec3254f03000000";
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        assert_eq!(&POW_OVERRIDE_HASH[..], &bytes[..]);

        // The top bytes are zero, so the value is small -- that is what gives
        // it a difficulty ceiling at all.
        assert_eq!(&POW_OVERRIDE_HASH[29..], &[0, 0, 0]);
    }
}
