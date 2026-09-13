//! BLAKE2b (RFC 7693), Argon2's variable-length `H'`, and RandomX's
//! `Blake2Generator` (`blake2/blake2b.c`, `blake2_generator.cpp`).

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
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
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const BLOCK: usize = 128;

/// An unkeyed BLAKE2b state.
pub(crate) struct Blake2b {
    h: [u64; 8],
    counter: u128,
    buf: [u8; BLOCK],
    len: usize,
    out_len: usize,
}

impl Blake2b {
    /// `out_len` is 1 to 64 bytes; it is part of the parameter block.
    pub(crate) fn new(out_len: usize) -> Blake2b {
        assert!((1..=64).contains(&out_len), "BLAKE2b output is 1-64 bytes");
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ out_len as u64;
        Blake2b {
            h,
            counter: 0,
            buf: [0; BLOCK],
            len: 0,
            out_len,
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            // The last block is compressed only by `finalize`, so a full buffer
            // waits until more input shows it is not the last.
            if self.len == BLOCK {
                self.counter += BLOCK as u128;
                compress(&mut self.h, &self.buf, self.counter, false);
                self.len = 0;
            }
            let n = (BLOCK - self.len).min(data.len());
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
        }
    }

    pub(crate) fn finalize(mut self, out: &mut [u8]) {
        self.counter += self.len as u128;
        self.buf[self.len..].fill(0);
        compress(&mut self.h, &self.buf, self.counter, true);
        let mut full = [0u8; 64];
        for (chunk, word) in full.as_chunks_mut::<8>().0.iter_mut().zip(self.h) {
            *chunk = word.to_le_bytes();
        }
        out[..self.out_len].copy_from_slice(&full[..self.out_len]);
    }
}

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress(h: &mut [u64; 8], block: &[u8; BLOCK], counter: u128, last: bool) {
    let mut m = [0u64; 16];
    for (word, chunk) in m.iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= counter as u64;
    v[13] ^= (counter >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b of `input`, `out.len()` bytes long.
pub(crate) fn blake2b(out: &mut [u8], input: &[u8]) {
    let mut s = Blake2b::new(out.len());
    s.update(input);
    s.finalize(out);
}

/// Argon2's `H'`: BLAKE2b stretched to any length (`blake2b_long`).
pub(crate) fn blake2b_long(out: &mut [u8], input: &[u8]) {
    let out_len = out.len();
    let len_bytes = (out_len as u32).to_le_bytes();
    if out_len <= 64 {
        let mut s = Blake2b::new(out_len);
        s.update(&len_bytes);
        s.update(input);
        s.finalize(out);
        return;
    }
    let mut s = Blake2b::new(64);
    s.update(&len_bytes);
    s.update(input);
    let mut buf = [0u8; 64];
    s.finalize(&mut buf);
    out[..32].copy_from_slice(&buf[..32]);
    let mut pos = 32;
    let mut remaining = out_len - 32;
    while remaining > 64 {
        let prev = buf;
        blake2b(&mut buf, &prev);
        out[pos..pos + 32].copy_from_slice(&buf[..32]);
        pos += 32;
        remaining -= 32;
    }
    let prev = buf;
    blake2b(&mut out[pos..pos + remaining], &prev);
}

/// RandomX's byte and integer source for SuperscalarHash generation: a
/// 64-byte buffer, rehashed with BLAKE2b whenever it runs out.
pub(crate) struct Blake2Generator {
    data: [u8; 64],
    index: usize,
}

impl Blake2Generator {
    pub(crate) fn new(seed: &[u8], nonce: u32) -> Blake2Generator {
        let mut data = [0u8; 64];
        let n = seed.len().min(60);
        data[..n].copy_from_slice(&seed[..n]);
        data[60..].copy_from_slice(&nonce.to_le_bytes());
        Blake2Generator { data, index: 64 }
    }

    fn check(&mut self, needed: usize) {
        if self.index + needed > self.data.len() {
            let prev = self.data;
            blake2b(&mut self.data, &prev);
            self.index = 0;
        }
    }

    pub(crate) fn get_byte(&mut self) -> u8 {
        self.check(1);
        let b = self.data[self.index];
        self.index += 1;
        b
    }

    pub(crate) fn get_u32(&mut self) -> u32 {
        self.check(4);
        let v = u32::from_le_bytes(
            self.data[self.index..self.index + 4]
                .try_into()
                .expect("4 bytes"),
        );
        self.index += 4;
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// RFC 7693 Appendix A, and the empty message.
    #[test]
    fn blake2b_matches_the_rfc() {
        let mut out = [0u8; 64];
        blake2b(&mut out, b"abc");
        assert_eq!(
            hex(&out),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        blake2b(&mut out, b"");
        assert_eq!(
            hex(&out),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    /// Input across block boundaries, fed at once or a byte at a time.
    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in [0, 1, 127, 128, 129, 256, 257, 1000] {
            let mut one = [0u8; 32];
            blake2b(&mut one, &data[..len]);
            let mut s = Blake2b::new(32);
            for b in &data[..len] {
                s.update(std::slice::from_ref(b));
            }
            let mut many = [0u8; 32];
            s.finalize(&mut many);
            assert_eq!(one, many, "length {len}");
        }
    }

    /// RandomX derives its AES constants from BLAKE2b: `state0..3 =
    /// Blake2b-512("RandomX AesHash1R state")`. The first state, as
    /// `_mm_set_epi32(0xd7983aad, 0xcc82db47, 0x9fa856de, 0x92b52c0d)` lays
    /// it out in memory.
    #[test]
    fn the_aes_constants_come_from_blake2b() {
        let mut out = [0u8; 64];
        blake2b(&mut out, b"RandomX AesHash1R state");
        assert_eq!(hex(&out[..16]), "0d2cb592de56a89f47db82ccad3a98d7");
    }

    #[test]
    fn long_hashes_have_the_asked_length_and_prefix_structure() {
        let mut a = [0u8; 1024];
        blake2b_long(&mut a, b"seed");
        let mut b = [0u8; 1024];
        blake2b_long(&mut b, b"seed");
        assert_eq!(a, b);
        let mut short = [0u8; 40];
        blake2b_long(&mut short, b"seed");
        assert_ne!(&a[..40], &short[..], "the length is hashed in");
    }
}
