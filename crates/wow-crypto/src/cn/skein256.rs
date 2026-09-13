//! Skein-512-256, the last of CryptoNight's four final hashes.
//!
//! `src/crypto/skein.c`. Selected when `state[0] & 3 == 3`.
//!
//! The name in the C is `hash_extra_skein`, which calls `skein_hash` with a
//! 256-bit output length — but the *state* is 512 bits. This is Skein-512-256
//! (v1.3), not Skein-256-256: a 512-bit Threefish under UBI chaining, truncated
//! on output. Getting that wrong produces a hash that is self-consistent and
//! wrong, so the reference vectors are the only real check.
//!
//! Three things here are easy to state and easy to get backwards, so they are
//! called out where they happen:
//!
//! * the initial chaining value is **computed** from a config block rather than
//!   copied from a table (the C carries precomputed IVs for the common sizes;
//!   [`tests::the_config_block_reproduces_the_published_iv`] checks the two
//!   agree),
//! * `update` always holds the final block back, so `final` never sees an
//!   already-processed buffer, and
//! * the output is Threefish in **counter mode**, not the chaining value.

/// The block size, and the state size.
const BLOCK: usize = 64;

/// `SKEIN_KS_PARITY` — the constant folded into the ninth key word.
const KS_PARITY: u64 = 0x1BD1_1BDA_A9FC_1A22;

/// `SKEIN_SCHEMA_VER`: version 1 in the high word, `"SHA3"` little-endian in
/// the low.
const SCHEMA_VER: u64 = 0x0000_0001_3341_4853;

/// `SKEIN_CFG_STR_LEN` — the config block's byte count, four words of it.
const CFG_STR_LEN: u64 = 32;

// Tweak flags. The C writes these as bit positions counted from 64 into the
// second tweak word; these are the resulting bits.
const T1_FLAG_FIRST: u64 = 1 << 62;
const T1_FLAG_FINAL: u64 = 1 << 63;
const T1_BLK_TYPE_CFG: u64 = 4 << 56;
const T1_BLK_TYPE_MSG: u64 = 48 << 56;
const T1_BLK_TYPE_OUT: u64 = 63 << 56;

/// Threefish-512 rotation constants, eight rounds by four mixes.
const ROT: [[u32; 4]; 8] = [
    [46, 36, 19, 37],
    [33, 27, 14, 42],
    [17, 49, 36, 39],
    [44, 9, 54, 56],
    [39, 30, 34, 24],
    [13, 50, 10, 17],
    [25, 29, 39, 43],
    [8, 35, 56, 22],
];

/// The word permutation, folded into the operand order the way the reference's
/// unrolled macros do. Cycles with period four.
const PERM: [[usize; 8]; 4] = [
    [0, 1, 2, 3, 4, 5, 6, 7],
    [2, 1, 4, 7, 6, 5, 0, 3],
    [4, 1, 6, 3, 0, 5, 2, 7],
    [6, 1, 0, 7, 2, 5, 4, 3],
];

struct Ctx {
    /// The chaining value, and the Threefish key.
    x: [u64; 8],
    /// The tweak: byte counter, then flags and block type.
    t: [u64; 2],
    buf: [u8; BLOCK],
    bcnt: usize,
}

impl Ctx {
    /// `Skein_512_Init`, by way of the config block.
    fn new(hash_bit_len: u64) -> Ctx {
        let mut ctx = Ctx {
            x: [0; 8],
            t: [0, T1_FLAG_FIRST | T1_BLK_TYPE_CFG | T1_FLAG_FINAL],
            buf: [0; BLOCK],
            bcnt: 0,
        };

        // The config block: schema, output length, and a tree-info word that is
        // zero for sequential hashing. The rest is zero padding.
        let mut cfg = [0u8; BLOCK];
        cfg[0..8].copy_from_slice(&SCHEMA_VER.to_le_bytes());
        cfg[8..16].copy_from_slice(&hash_bit_len.to_le_bytes());
        ctx.process_block(&cfg, CFG_STR_LEN);

        // Switch to message mode for the data that follows.
        ctx.t = [0, T1_FLAG_FIRST | T1_BLK_TYPE_MSG];
        ctx.bcnt = 0;
        ctx
    }

    /// `Skein_512_Process_Block`: Threefish-512 keyed by the chaining value,
    /// with the block as plaintext and a feed-forward xor at the end.
    fn process_block(&mut self, block: &[u8; BLOCK], byte_cnt_add: u64) {
        // The key schedule: the eight chaining words plus their parity.
        let mut ks = [0u64; 9];
        let mut parity = KS_PARITY;
        for (k, x) in ks.iter_mut().zip(self.x.iter()) {
            *k = *x;
            parity ^= *x;
        }
        ks[8] = parity;

        self.t[0] = self.t[0].wrapping_add(byte_cnt_add);
        let ts = [self.t[0], self.t[1], self.t[0] ^ self.t[1]];

        let mut w = [0u64; 8];
        for (i, word) in w.iter_mut().enumerate() {
            *word = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        }

        // Subkey 0.
        let mut x = [0u64; 8];
        for ((xi, wi), ki) in x.iter_mut().zip(w.iter()).zip(ks.iter()) {
            *xi = wi.wrapping_add(*ki);
        }
        x[5] = x[5].wrapping_add(ts[0]);
        x[6] = x[6].wrapping_add(ts[1]);

        // Eighteen groups of four rounds, each followed by a subkey injection.
        for group in 0..18usize {
            for j in 0..4usize {
                let d = group * 4 + j;
                let p = &PERM[d % 4];
                let rot = &ROT[d % 8];
                for k in 0..4 {
                    let (a, b) = (p[2 * k], p[2 * k + 1]);
                    x[a] = x[a].wrapping_add(x[b]);
                    x[b] = x[b].rotate_left(rot[k]);
                    x[b] ^= x[a];
                }
            }

            let s = group + 1;
            for (i, xi) in x.iter_mut().enumerate() {
                *xi = xi.wrapping_add(ks[(s + i) % 9]);
            }
            x[5] = x[5].wrapping_add(ts[s % 3]);
            x[6] = x[6].wrapping_add(ts[(s + 1) % 3]);
            x[7] = x[7].wrapping_add(s as u64);
        }

        for ((cv, xi), wi) in self.x.iter_mut().zip(x.iter()).zip(w.iter()) {
            *cv = xi ^ wi;
        }

        // Only the first block of a UBI pass carries the first flag.
        self.t[1] &= !T1_FLAG_FIRST;
    }

    /// `Skein_512_Update`. Note the strict `>`: a message that lands exactly on
    /// a block boundary leaves a full buffer behind rather than processing it,
    /// because the final block must be tagged as final.
    fn update(&mut self, mut msg: &[u8]) {
        if msg.len() + self.bcnt > BLOCK {
            if self.bcnt > 0 {
                let n = BLOCK - self.bcnt;
                self.buf[self.bcnt..].copy_from_slice(&msg[..n]);
                msg = &msg[n..];
                let block = self.buf;
                self.process_block(&block, BLOCK as u64);
                self.bcnt = 0;
            }
            if msg.len() > BLOCK {
                let n = (msg.len() - 1) / BLOCK;
                for block in msg[..n * BLOCK].as_chunks::<BLOCK>().0 {
                    self.process_block(block, BLOCK as u64);
                }
                msg = &msg[n * BLOCK..];
            }
        }
        if !msg.is_empty() {
            self.buf[self.bcnt..self.bcnt + msg.len()].copy_from_slice(msg);
            self.bcnt += msg.len();
        }
    }

    /// `Skein_512_Final`: close the message pass, then generate the digest by
    /// running Threefish in counter mode under the resulting chaining value.
    fn finish(&mut self, out: &mut [u8]) {
        self.t[1] |= T1_FLAG_FINAL;
        self.buf[self.bcnt..].fill(0);
        let block = self.buf;
        let bcnt = self.bcnt as u64;
        self.process_block(&block, bcnt);

        let key = self.x;
        for (i, part) in out.chunks_mut(BLOCK).enumerate() {
            let mut ctr = [0u8; BLOCK];
            ctr[..8].copy_from_slice(&(i as u64).to_le_bytes());
            self.x = key;
            self.t = [0, T1_FLAG_FIRST | T1_BLK_TYPE_OUT | T1_FLAG_FINAL];
            // The counter block counts as eight bytes, not sixty-four.
            self.process_block(&ctr, 8);

            let mut bytes = [0u8; BLOCK];
            for (j, word) in self.x.iter().enumerate() {
                bytes[j * 8..j * 8 + 8].copy_from_slice(&word.to_le_bytes());
            }
            part.copy_from_slice(&bytes[..part.len()]);
        }
    }
}

/// Skein-512-256 of `input`.
pub fn skein256(input: &[u8]) -> [u8; 32] {
    let mut ctx = Ctx::new(256);
    ctx.update(input);
    let mut out = [0u8; 32];
    ctx.finish(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published Skein-512-256 vector for the empty input.
    #[test]
    fn the_empty_input() {
        assert_eq!(
            crate::hex::encode(&skein256(b"")),
            "39ccc4554a8b31853b9de7a1fe638a24cce6b35a55f2431009e18780335d2621"
        );
    }

    /// The config block must reproduce the IV the C keeps precomputed for this
    /// output length. If it does not, every later block is keyed wrongly.
    #[test]
    fn the_config_block_reproduces_the_published_iv() {
        const IV_256: [u64; 8] = [
            0xCCD0_44A1_2FDB_3E13,
            0xE835_9030_1A79_A9EB,
            0x55AE_A061_4F81_6E6F,
            0x2A27_67A4_AE9B_94DB,
            0xEC06_025E_74DD_7683,
            0xE7A4_36CD_C474_6251,
            0xC36F_BAF9_393A_D185,
            0x3EED_BA18_33ED_FC13,
        ];
        assert_eq!(Ctx::new(256).x, IV_256);
    }

    /// A message ending exactly on a block boundary must leave that block
    /// buffered, so it is processed as the final block and not as a message
    /// block. Both branches of `update` are exercised here.
    #[test]
    fn the_final_block_is_always_held_back() {
        let mut ctx = Ctx::new(256);
        ctx.update(&[0u8; 64]);
        assert_eq!(ctx.bcnt, 64, "a full block stays buffered");
        assert_eq!(ctx.t[0], 0, "and so is not yet counted");

        let mut ctx = Ctx::new(256);
        ctx.update(&[0u8; 65]);
        assert_eq!(ctx.bcnt, 1);
        assert_eq!(ctx.t[0], 64);

        // Byte-at-a-time must agree with one call.
        let msg: Vec<u8> = (0u8..200).collect();
        let mut ctx = Ctx::new(256);
        for b in &msg {
            ctx.update(std::slice::from_ref(b));
        }
        let mut a = [0u8; 32];
        ctx.finish(&mut a);
        assert_eq!(a, skein256(&msg));
    }

    /// The tweak flags land where the reference puts them.
    #[test]
    fn the_tweak_layout() {
        assert_eq!(T1_FLAG_FIRST, 0x4000_0000_0000_0000);
        assert_eq!(T1_FLAG_FINAL, 0x8000_0000_0000_0000);
        assert_eq!(T1_BLK_TYPE_CFG, 0x0400_0000_0000_0000);
        assert_eq!(T1_BLK_TYPE_MSG, 0x3000_0000_0000_0000);
        assert_eq!(T1_BLK_TYPE_OUT, 0x3F00_0000_0000_0000);
    }
}
