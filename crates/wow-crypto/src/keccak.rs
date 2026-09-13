//! Keccak-f[1600] and Keccak-256 with the **original** padding.
//!
//! `specs/02-crypto.md` §1.1: `cn_fast_hash` is Keccak with the `0x01` domain
//! byte, not SHA3-256 with `0x06`. Reference: `src/crypto/keccak.c`.
//!
//! The permutation is exposed separately because `src/crypto/random.c` builds
//! its PRNG directly on the 200-byte state (`hash_permutation`), and the
//! reference test vectors depend on reproducing that PRNG exactly
//! (`specs/15-testing-and-conformance.md` §2.1).

/// Rate of Keccak-256 in bytes. `HASH_DATA_AREA` in `src/crypto/hash-ops.h`.
pub const HASH_DATA_AREA: usize = 136;
/// Size of the Keccak state in bytes. `union hash_state` is 200 bytes.
pub const HASH_STATE_BYTES: usize = 200;

const ROUNDS: usize = 24;

const RC: [u64; ROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation, in place. `keccakf(st, 24)` in the C.
///
/// This is `hash_permutation` from `src/crypto/hash-ops.h`.
pub fn keccakf(st: &mut [u64; 25]) {
    let mut bc = [0u64; 5];

    for &rc in RC.iter() {
        // Theta
        for i in 0..5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in (0..25).step_by(5) {
                st[j + i] ^= t;
            }
        }

        // Rho and Pi
        let mut t = st[1];
        for i in 0..24 {
            let j = PILN[i];
            let tmp = st[j];
            st[j] = t.rotate_left(ROTC[i]);
            t = tmp;
        }

        // Chi
        for j in (0..25).step_by(5) {
            bc[..5].copy_from_slice(&st[j..j + 5]);
            for i in 0..5 {
                st[j + i] = bc[i] ^ ((!bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
            }
        }

        // Iota
        st[0] ^= rc;
    }
}

/// Keccak-256 with the original (`0x01`) padding byte.
///
/// Equivalent to `keccak(in, inlen, md, 32)` in `src/crypto/keccak.c`, which is
/// what `cn_fast_hash` calls.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let st = sponge(data);
    let mut out = [0u8; 32];
    for (i, chunk) in out.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        *chunk = st[i].to_le_bytes();
    }
    out
}

/// The same sponge, but returning the whole 200-byte state rather than the
/// first 32 bytes.
///
/// `keccak1600` in `src/crypto/keccak.c`. `cn_slow_hash` starts from this: it
/// reads AES keys out of the first 64 bytes and the scratchpad seed out of the
/// next 128, so truncating to a digest would throw away most of what it needs.
pub fn keccak1600(data: &[u8]) -> [u8; HASH_STATE_BYTES] {
    let st = sponge(data);
    let mut out = [0u8; HASH_STATE_BYTES];
    for (i, chunk) in out.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        *chunk = st[i].to_le_bytes();
    }
    out
}

/// Absorb `data` at the 136-byte rate with the original padding, and return the
/// final state. The rate does not depend on the output length here: the C picks
/// `200 - 2 * mdlen` only for short digests, and `HASH_DATA_AREA` for both of
/// the lengths used above.
fn sponge(data: &[u8]) -> [u64; 25] {
    let mut st = [0u64; 25];
    let (blocks, rem) = data.as_chunks::<HASH_DATA_AREA>();
    for block in blocks {
        absorb(&mut st, block);
        keccakf(&mut st);
    }

    // Final, padded block. `0x01` domain byte, `0x80` at the end of the rate.
    let mut last = [0u8; HASH_DATA_AREA];
    last[..rem.len()].copy_from_slice(rem);
    last[rem.len()] = 0x01;
    last[HASH_DATA_AREA - 1] |= 0x80;
    absorb(&mut st, &last);
    keccakf(&mut st);
    st
}

#[inline]
fn absorb(st: &mut [u64; 25], block: &[u8]) {
    debug_assert_eq!(block.len(), HASH_DATA_AREA);
    for (i, word) in block.as_chunks::<8>().0.iter().enumerate() {
        st[i] ^= u64::from_le_bytes(*word);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_02_1_1_vectors() {
        // specs/02-crypto.md §1.1 and specs/15 §2.1.
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex::encode(keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn not_sha3() {
        // The SHA3-256 answer for "" -- if we ever produce this, the padding
        // byte regressed from 0x01 to 0x06.
        assert_ne!(
            hex::encode(keccak256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn rate_boundary() {
        // Exercises the absorb loop across the 136-byte rate boundary: a full
        // block plus one byte must take a second permutation.
        let a = keccak256(&[0x61u8; HASH_DATA_AREA - 1]);
        let b = keccak256(&[0x61u8; HASH_DATA_AREA]);
        let c = keccak256(&[0x61u8; HASH_DATA_AREA + 1]);
        assert_ne!(a, b);
        assert_ne!(b, c);
    }
}
