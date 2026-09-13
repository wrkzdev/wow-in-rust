//! BLAKE-256, one of CryptoNight's four final hashes.
//!
//! `src/crypto/blake256.c`. This is BLAKE-256 the SHA-3 finalist, **not**
//! BLAKE2 — different constants, different round count, and a different padding
//! rule.
//!
//! Selected when `state[0] & 3 == 0` at the end of `cn_slow_hash`
//! (`specs/02` §7).

const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The 16 round constants — the first digits of pi.
const C: [u32; 16] = [
    0x243f_6a88,
    0x85a3_08d3,
    0x1319_8a2e,
    0x0370_7344,
    0xa409_3822,
    0x299f_31d0,
    0x082e_fa98,
    0xec4e_6c89,
    0x4528_21e6,
    0x38d0_1377,
    0xbe54_66cf,
    0x34e9_0c6c,
    0xc0ac_29b7,
    0xc97c_50dd,
    0x3f84_d5b5,
    0xb547_0917,
];

/// The message permutation, ten rows used cyclically over fourteen rounds.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

struct State {
    h: [u32; 8],
    t: [u32; 2],
    buf: [u8; 64],
    buflen: usize,
    /// Set when the block being compressed carries no length counter — the
    /// case where padding filled a whole block.
    nullt: bool,
}

impl State {
    fn new() -> State {
        State {
            h: IV,
            t: [0, 0],
            buf: [0; 64],
            buflen: 0,
            nullt: false,
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().expect("16 words"));
        }

        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&C[..8]);

        // The length counter is mixed in unless this block is pure padding.
        if !self.nullt {
            v[12] ^= self.t[0];
            v[13] ^= self.t[0];
            v[14] ^= self.t[1];
            v[15] ^= self.t[1];
        }

        for round in 0..14 {
            let s = &SIGMA[round % 10];
            g(&mut v, 0, 4, 8, 12, &m, s, 0);
            g(&mut v, 1, 5, 9, 13, &m, s, 2);
            g(&mut v, 2, 6, 10, 14, &m, s, 4);
            g(&mut v, 3, 7, 11, 15, &m, s, 6);
            g(&mut v, 0, 5, 10, 15, &m, s, 8);
            g(&mut v, 1, 6, 11, 12, &m, s, 10);
            g(&mut v, 2, 7, 8, 13, &m, s, 12);
            g(&mut v, 3, 4, 9, 14, &m, s, 14);
        }

        // Each half of `v` folds into `h`, so index 8..16 wraps around.
        for (i, w) in v.iter().enumerate() {
            self.h[i % 8] ^= w;
        }
    }

    /// `blake256_update`, with `datalen` in **bits** as the C takes it.
    fn update(&mut self, data: &[u8], mut datalen: usize) {
        let mut offset = 0usize;
        let left = self.buflen >> 3;
        let fill = 64 - left;

        if left > 0 && (datalen >> 3) >= fill {
            self.buf[left..left + fill].copy_from_slice(&data[..fill]);
            self.t[0] = self.t[0].wrapping_add(512);
            if self.t[0] == 0 {
                self.t[1] = self.t[1].wrapping_add(1);
            }
            let block = self.buf;
            self.compress(&block);
            offset += fill;
            datalen -= fill << 3;
            self.buflen = 0;
        }

        while datalen >= 512 {
            self.t[0] = self.t[0].wrapping_add(512);
            if self.t[0] == 0 {
                self.t[1] = self.t[1].wrapping_add(1);
            }
            let block: [u8; 64] = data[offset..offset + 64].try_into().expect("512 bits");
            self.compress(&block);
            offset += 64;
            datalen -= 512;
        }

        if datalen > 0 {
            let left = self.buflen >> 3;
            let n = (datalen >> 3) + usize::from(!datalen.is_multiple_of(8));
            self.buf[left..left + n].copy_from_slice(&data[offset..offset + n]);
            self.buflen += datalen;
        } else {
            self.buflen = 0;
        }
    }
}

#[allow(clippy::too_many_arguments, reason = "the BLAKE G function takes them")]
fn g(
    v: &mut [u32; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    m: &[u32; 16],
    s: &[usize; 16],
    i: usize,
) {
    v[a] = v[a].wrapping_add(m[s[i]] ^ C[s[i + 1]]).wrapping_add(v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(m[s[i + 1]] ^ C[s[i]]).wrapping_add(v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

const PADDING: [u8; 65] = {
    let mut p = [0u8; 65];
    p[0] = 0x80;
    p
};

/// BLAKE-256 of `input`.
pub fn blake256(input: &[u8]) -> [u8; 32] {
    let mut s = State::new();
    s.update(input, input.len() * 8);

    // `blake256_final`, with the standard `pa = 0x81`, `pb = 0x01`.
    let lo = s.t[0].wrapping_add(s.buflen as u32);
    let hi = if lo < s.buflen as u32 {
        s.t[1].wrapping_add(1)
    } else {
        s.t[1]
    };
    let mut msglen = [0u8; 8];
    msglen[..4].copy_from_slice(&hi.to_be_bytes());
    msglen[4..].copy_from_slice(&lo.to_be_bytes());

    if s.buflen == 440 {
        s.t[0] = s.t[0].wrapping_sub(8);
        s.update(&[0x81], 8);
    } else {
        if s.buflen < 440 {
            if s.buflen == 0 {
                s.nullt = true;
            }
            s.t[0] = s.t[0].wrapping_sub((440 - s.buflen) as u32);
            let n = (440 - s.buflen) / 8;
            s.update(&PADDING[..n], 440 - s.buflen);
        } else {
            s.t[0] = s.t[0].wrapping_sub((512 - s.buflen) as u32);
            let n = (512 - s.buflen) / 8;
            s.update(&PADDING[..n], 512 - s.buflen);
            s.t[0] = s.t[0].wrapping_sub(440);
            s.update(&PADDING[1..1 + 55], 440);
            s.nullt = true;
        }
        s.update(&[0x01], 8);
        s.t[0] = s.t[0].wrapping_sub(8);
    }
    s.t[0] = s.t[0].wrapping_sub(64);
    s.update(&msglen, 64);

    let mut out = [0u8; 32];
    for (i, w) in s.h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published BLAKE-256 vectors: one zero byte, and 72 zero bytes.
    #[test]
    fn the_published_vectors() {
        assert_eq!(
            crate::hex::encode(&blake256(&[0u8])),
            "0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87"
        );
        assert_eq!(
            crate::hex::encode(&blake256(&[0u8; 72])),
            "d419bad32d504fb7d44d460c42c5593fe544fa4c135dec31e21bd9abdcc22d41"
        );
    }

    /// The empty input, which exercises the `buflen == 0` path that sets
    /// `nullt`.
    #[test]
    fn the_empty_input() {
        assert_eq!(
            crate::hex::encode(&blake256(b"")),
            "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a"
        );
    }
}
