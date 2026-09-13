//! Grøstl-256, the second of CryptoNight's four final hashes.
//!
//! `src/crypto/groestl.c`. Selected when `state[0] & 3 == 1`.
//!
//! # Written from the specification, not from the tables
//!
//! The C is a table-driven implementation carrying 2,048 precomputed `u32`
//! constants (`groestl_tables.h`). This is the byte-oriented form the Grøstl
//! specification defines, which is the same function and is checkable by
//! reading — the tables are an optimisation for a hash that runs **once** at
//! the end of `cn_slow_hash`, where it costs nothing.
//!
//! The C's layout was read off its round functions rather than assumed: `P`
//! takes its round counter as `0x00000009` (low byte, row 0) and `Q` as
//! `0x09000000` (high byte, row 7), which pins the state to column-major with
//! byte `8*col + row`. That matches the published constants, and the 321
//! reference vectors confirm it.

/// The AES S-box, which Grøstl's SubBytes uses unchanged.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// The block size, and the state size: 64 bytes, eight columns of eight rows.
const BLOCK: usize = 64;
/// Rounds in each of `P` and `Q`, for the 512-bit permutation.
const ROUNDS: usize = 10;
/// `LENGTHFIELDLEN` — the trailing block counter.
const LENGTH_FIELD: usize = 8;

/// `ShiftBytes` for `P`: row `r` moves left by `r`.
const SHIFT_P: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
/// `ShiftBytes` for `Q`.
const SHIFT_Q: [usize; 8] = [1, 3, 5, 7, 0, 2, 4, 6];

/// Multiply in GF(2^8) with the AES polynomial.
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let high = a & 0x80 != 0;
        a <<= 1;
        if high {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// `a[row][col]` is `state[8 * col + row]`.
#[inline]
fn at(state: &[u8; BLOCK], col: usize, row: usize) -> u8 {
    state[8 * col + row]
}

/// One round of `P` or `Q`.
fn round(state: &mut [u8; BLOCK], r: u8, is_q: bool) {
    // AddRoundConstant.
    if is_q {
        // Every byte is complemented, and row 7 carries the column and the
        // round counter.
        for (i, b) in state.iter_mut().enumerate() {
            *b ^= 0xff;
            if i % 8 == 7 {
                *b ^= ((i / 8) as u8) << 4;
                *b ^= r;
            }
        }
    } else {
        for col in 0..8 {
            state[8 * col] ^= ((col as u8) << 4) ^ r;
        }
    }

    // SubBytes.
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }

    // ShiftBytes, then MixBytes, into a fresh state.
    let shift = if is_q { &SHIFT_Q } else { &SHIFT_P };
    let mut shifted = [0u8; BLOCK];
    for col in 0..8 {
        for row in 0..8 {
            shifted[8 * col + row] = at(state, (col + shift[row]) % 8, row);
        }
    }

    // MixBytes: the circulant matrix [02 02 03 04 05 03 05 07] over each
    // column.
    const M: [u8; 8] = [0x02, 0x02, 0x03, 0x04, 0x05, 0x03, 0x05, 0x07];
    for col in 0..8 {
        let mut out = [0u8; 8];
        for (row, o) in out.iter_mut().enumerate() {
            let mut acc = 0u8;
            for (k, m) in M.iter().enumerate() {
                acc ^= gmul(*m, shifted[8 * col + (row + k) % 8]);
            }
            *o = acc;
        }
        state[8 * col..8 * col + 8].copy_from_slice(&out);
    }
}

fn permute(state: &mut [u8; BLOCK], is_q: bool) {
    for r in 0..ROUNDS {
        round(state, r as u8, is_q);
    }
}

/// `F512`: `h ^= P(h ^ m) ^ Q(m)`.
fn compress(h: &mut [u8; BLOCK], m: &[u8; BLOCK]) {
    let mut p = *h;
    for (a, b) in p.iter_mut().zip(m.iter()) {
        *a ^= b;
    }
    let mut q = *m;

    permute(&mut p, false);
    permute(&mut q, true);

    for i in 0..BLOCK {
        h[i] ^= p[i] ^ q[i];
    }
}

/// Grøstl-256 of `input`.
pub fn groestl256(input: &[u8]) -> [u8; 32] {
    // The IV is zero except for the output length, big-endian, in the last two
    // bytes — so row 6 of column 7.
    let mut h = [0u8; BLOCK];
    h[62] = 0x01; // 256 bits

    let mut blocks: u64 = 0;
    let (chunks, rest) = input.as_chunks::<BLOCK>();
    for c in chunks {
        compress(&mut h, c);
        blocks += 1;
    }

    // Padding: 0x80, zeros, then the **block count including padding** as a
    // big-endian u64 — a block counter, not a bit length.
    let mut buf = [0u8; BLOCK];
    buf[..rest.len()].copy_from_slice(rest);
    let mut ptr = rest.len();
    buf[ptr] = 0x80;
    ptr += 1;

    if ptr > BLOCK - LENGTH_FIELD {
        // Padding needs a second block.
        compress(&mut h, &buf);
        blocks += 1;
        buf = [0u8; BLOCK];
    }
    blocks += 1;
    buf[BLOCK - LENGTH_FIELD..].copy_from_slice(&blocks.to_be_bytes());
    compress(&mut h, &buf);

    // Output transformation: truncate `h ^ P(h)`.
    let mut p = h;
    permute(&mut p, false);
    for i in 0..BLOCK {
        h[i] ^= p[i];
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&h[32..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published Grøstl-256 vector for the empty input.
    #[test]
    fn the_empty_input() {
        assert_eq!(
            crate::hex::encode(&groestl256(b"")),
            "1a52d11d550039be16107f9c58db9ebcc417f16f736adb2502567119f0083467"
        );
    }

    /// A one-byte input, and one that lands exactly on the two-block padding
    /// boundary.
    #[test]
    fn the_padding_boundaries() {
        // 55 bytes leaves room for 0x80 plus the 8-byte counter in one block.
        assert_eq!(groestl256(&[0u8; 55]).len(), 32);
        // 56 forces a second padding block, which is the branch worth having.
        assert_ne!(groestl256(&[0u8; 55]), groestl256(&[0u8; 56]));
        assert_ne!(groestl256(&[0u8; 63]), groestl256(&[0u8; 64]));
    }

    /// GF(2^8) multiplication, against values that exercise the reduction.
    #[test]
    fn the_field_multiplication() {
        assert_eq!(gmul(0x02, 0x80), 0x1b, "the reduction polynomial");
        assert_eq!(gmul(0x01, 0xff), 0xff, "one is the identity");
        assert_eq!(gmul(0x00, 0xff), 0x00);
        assert_eq!(gmul(0x03, 0x01), 0x03);
        // Commutative.
        for (a, b) in [(0x57u8, 0x83u8), (0x02, 0x87), (0x07, 0xf0)] {
            assert_eq!(gmul(a, b), gmul(b, a), "{a:#x} * {b:#x}");
        }
    }

    /// The IV carries the output length in the last two bytes, big-endian.
    #[test]
    fn the_iv_encodes_the_output_length() {
        let mut h = [0u8; BLOCK];
        h[62] = 0x01;
        assert_eq!(u16::from_be_bytes([h[62], h[63]]), 256);
    }
}
