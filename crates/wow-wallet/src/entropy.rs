//! Operating-system entropy.
//!
//! Everything secret in a transaction comes from the seed here: the transaction
//! key, the output masks, the Bulletproof+ blinding, the CLSAG nonces and the
//! decoy choices. A predictable seed does not produce an invalid transaction.
//! It produces a perfectly valid one that reveals which input was really spent,
//! and lets anyone recompute the spend key from two signatures.
//!
//! This needs a platform call, so it is the only `unsafe` in the wallet. Each
//! block says what it relies on.

use wow_crypto::keccak::HASH_STATE_BYTES;
use wow_crypto::random::Rng;

/// Fill `out` with bytes from the operating system's CSPRNG.
///
/// Returns `false` if the platform call failed, which the caller must treat as
/// fatal — there is no reasonable fallback, and inventing one from the clock
/// would be worse than stopping.
#[cfg(unix)]
fn os_random(out: &mut [u8]) -> bool {
    use std::io::Read;
    match std::fs::File::open("/dev/urandom") {
        Ok(mut f) => f.read_exact(out).is_ok(),
        Err(_) => false,
    }
}

#[cfg(windows)]
fn os_random(out: &mut [u8]) -> bool {
    // `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` needs no
    // algorithm handle, which is why it is preferred here over opening one.
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }

    // SAFETY: `out` is a valid, writable slice of exactly `cb_buffer` bytes,
    // and the null algorithm handle is what
    // `BCRYPT_USE_SYSTEM_PREFERRED_RNG` requires. The call writes only into
    // that buffer and returns a status rather than allocating anything.
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            out.as_mut_ptr(),
            out.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    status == 0
}

/// A random number generator seeded from the operating system.
///
/// The state is the reference's 200-byte Keccak state (`src/crypto/random.c`),
/// seeded here rather than from a fixed constant.
pub fn seeded_rng() -> Result<Rng, String> {
    let mut state = [0u8; HASH_STATE_BYTES];
    if !os_random(&mut state) {
        return Err(
            "could not read entropy from the operating system; refusing to continue, because \
             every secret in a transaction comes from it"
                .into(),
        );
    }
    Ok(Rng::from_state(state))
}
