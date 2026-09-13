//! Random scalar generation, plus the reference tree's deterministic PRNG.
//!
//! `src/crypto/random.c` keeps a 200-byte Keccak state and, on each request,
//! permutes it and returns the first `n` bytes of the rate. That is all the
//! entropy machinery there is — the state is seeded once at startup.
//!
//! `tests/crypto/random.c` overrides the seeding with
//! `memset(&state, 42, sizeof(union hash_state))`, which is what makes
//! `tests/crypto/tests.txt` reproducible. [`Rng::deterministic_test_seed`]
//! reproduces that exactly, so the 1,013 vectors that consume randomness
//! (`random_scalar`, `generate_keys`, `generate_signature`,
//! `generate_ring_signature`) are checked rather than skipped
//! (`specs/15-testing-and-conformance.md` §2.1).

use crate::keccak::{keccakf, HASH_DATA_AREA, HASH_STATE_BYTES};
use crate::ops::{sc_is_nonzero, sc_reduce32};
use crate::types::SecretKey;

/// `15 * l`, the largest multiple of `l` that fits in 32 bytes.
///
/// `random32_unbiased` in `src/crypto/crypto.cpp` rejection-samples below this
/// so the reduction is unbiased.
const LIMIT: [u8; 32] = [
    0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29, 0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0,
];

/// `less32(k0, k1)`: compare 32-byte little-endian integers.
fn less32(k0: &[u8; 32], k1: &[u8; 32]) -> bool {
    for n in (0..32).rev() {
        if k0[n] < k1[n] {
            return true;
        }
        if k0[n] > k1[n] {
            return false;
        }
    }
    false
}

/// A source of random bytes with the reference's state machine.
///
/// The production path seeds from the OS; [`Rng::deterministic_test_seed`]
/// seeds the way `tests/crypto/random.c` does.
pub struct Rng {
    state: [u8; HASH_STATE_BYTES],
}

impl Rng {
    /// `setup_random()` from `tests/crypto/random.c`: fill the whole 200-byte
    /// Keccak state with `0x2a`.
    pub fn deterministic_test_seed() -> Rng {
        Rng {
            state: [42u8; HASH_STATE_BYTES],
        }
    }

    /// Seed from an explicit 200-byte state.
    pub fn from_state(state: [u8; HASH_STATE_BYTES]) -> Rng {
        Rng { state }
    }

    /// `generate_random_bytes_not_thread_safe(n, result)`.
    ///
    /// Permute, then copy out of the front of the state; for `n` over the rate,
    /// permute again per 136-byte chunk.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut off = 0;
        loop {
            self.permute();
            let n = out.len() - off;
            if n <= HASH_DATA_AREA {
                out[off..].copy_from_slice(&self.state[..n]);
                return;
            }
            out[off..off + HASH_DATA_AREA].copy_from_slice(&self.state[..HASH_DATA_AREA]);
            off += HASH_DATA_AREA;
        }
    }

    fn permute(&mut self) {
        let mut w = [0u64; 25];
        for (i, word) in self.state.chunks_exact(8).enumerate() {
            w[i] = u64::from_le_bytes(word.try_into().unwrap());
        }
        keccakf(&mut w);
        for (i, word) in self.state.chunks_exact_mut(8).enumerate() {
            word.copy_from_slice(&w[i].to_le_bytes());
        }
    }

    /// `random32_unbiased(bytes)`.
    ///
    /// Rejection-samples 32 bytes below `15 * l`, reduces, and rejects zero.
    /// Note this is **not** simply `sc_reduce32(32 random bytes)`: the
    /// rejection loop consumes a variable number of draws, so reproducing it is
    /// required for the reference vectors to line up.
    pub fn random32_unbiased(&mut self) -> [u8; 32] {
        loop {
            let mut b = [0u8; 32];
            self.fill(&mut b);
            if !less32(&b, &LIMIT) {
                continue;
            }
            let r = sc_reduce32(&b);
            if sc_is_nonzero(&r) {
                return r;
            }
        }
    }

    /// `crypto::random_scalar(res)`.
    #[inline]
    pub fn random_scalar(&mut self) -> [u8; 32] {
        self.random32_unbiased()
    }

    /// `generate_keys(pub, sec)` with `recover = false`.
    ///
    /// Note the redundant `sc_reduce32` the C applies to an already-reduced
    /// scalar ("reduce in case second round of keys"); it is a no-op here but
    /// reproduced for clarity.
    pub fn generate_keys(&mut self) -> (crate::types::PublicKey, SecretKey) {
        let rng = self.random_scalar();
        let sec = SecretKey(sc_reduce32(&rng));
        let pub_key = crate::ops::secret_key_to_public_key(&sec)
            .expect("a reduced scalar is always canonical");
        (pub_key, sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The deterministic seed must produce a stable stream; if this changes,
    /// every `random_scalar` vector in `tests.txt` will fail and the cause will
    /// be here rather than in the curve code.
    #[test]
    fn deterministic_stream_is_stable() {
        let mut a = Rng::deterministic_test_seed();
        let mut b = Rng::deterministic_test_seed();
        for _ in 0..8 {
            assert_eq!(a.random_scalar(), b.random_scalar());
        }
    }

    #[test]
    fn scalars_are_canonical_and_nonzero() {
        let mut r = Rng::deterministic_test_seed();
        for _ in 0..256 {
            let s = r.random_scalar();
            assert!(crate::ops::sc_check(&s));
            assert!(sc_is_nonzero(&s));
        }
    }

    #[test]
    fn fill_spans_multiple_rate_blocks() {
        let mut r = Rng::deterministic_test_seed();
        let mut big = [0u8; HASH_DATA_AREA * 3 + 7];
        r.fill(&mut big);
        // A second identical stream, drawn in one go, matches the first.
        let mut r2 = Rng::deterministic_test_seed();
        let mut big2 = [0u8; HASH_DATA_AREA * 3 + 7];
        r2.fill(&mut big2);
        assert_eq!(big, big2);
        assert_ne!(&big[..32], &big[HASH_DATA_AREA..HASH_DATA_AREA + 32]);
    }

    #[test]
    fn less32_orders_little_endian() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1;
        assert!(less32(&a, &b));
        assert!(!less32(&b, &a));
        assert!(!less32(&a, &a));
        a[0] = 0xff;
        assert!(less32(&a, &b), "the high byte dominates");
    }

    #[test]
    fn generated_keys_are_a_matching_pair() {
        let mut r = Rng::deterministic_test_seed();
        for _ in 0..32 {
            let (p, s) = r.generate_keys();
            assert_eq!(crate::ops::secret_key_to_public_key(&s).unwrap(), p);
        }
    }
}
