//! The AES pieces of CryptoNight.
//!
//! `src/crypto/aesb.c` and the `aes_expand_key` / `aes_pseudo_round` helpers in
//! `src/crypto/slow-hash.c`.
//!
//! CryptoNight does not use AES as a cipher. It uses the AES *round function*
//! as a mixing step, so two things differ from textbook AES:
//!
//! * there is **no initial AddRoundKey** — [`pseudo_round`] applies ten rounds
//!   with round keys 0..10 and nothing before them, and
//! * the last round still does **MixColumns**, unlike real AES where it is
//!   dropped.
//!
//! Both are exactly what `_mm_aesenc_si128` does when called ten times in a
//! row, which is the form the hardware path uses and therefore the definition
//! the portable path has to match. [`round`] is one `aesenc`.

/// The AES S-box.
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

/// The round constants the key schedule needs. A 256-bit key reaches word 56,
/// so only seven are ever read.
const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

/// The block size, which is also the round-key size.
pub const BLOCK: usize = 16;
/// The key size CryptoNight uses: 256 bits.
pub const KEY: usize = 32;
/// The full AES-256 expansion: fifteen round keys.
pub const EXPANDED: usize = 240;
/// Round keys [`pseudo_round`] actually applies.
const PSEUDO_ROUNDS: usize = 10;

/// Multiply by x in GF(2^8), the AES field.
#[inline]
fn xtime(a: u8) -> u8 {
    (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 }
}

/// The AES-256 key schedule.
///
/// Standard: RotWord + SubWord + Rcon every eighth word, and a bare SubWord
/// four words after each of those — the extra step that only 256-bit keys have.
pub fn expand_key(key: &[u8; KEY]) -> [u8; EXPANDED] {
    let mut exp = [0u8; EXPANDED];
    exp[..KEY].copy_from_slice(key);

    for i in (KEY / 4)..(EXPANDED / 4) {
        let mut t = [0u8; 4];
        t.copy_from_slice(&exp[(i - 1) * 4..i * 4]);

        if i % 8 == 0 {
            t.rotate_left(1);
            for b in t.iter_mut() {
                *b = SBOX[*b as usize];
            }
            t[0] ^= RCON[i / 8 - 1];
        } else if i % 8 == 4 {
            for b in t.iter_mut() {
                *b = SBOX[*b as usize];
            }
        }

        for j in 0..4 {
            exp[i * 4 + j] = exp[(i - 8) * 4 + j] ^ t[j];
        }
    }
    exp
}

/// One AES round: SubBytes, ShiftRows, MixColumns, AddRoundKey. This is
/// `aesb_single_round`, and one `_mm_aesenc_si128`.
///
/// The block is column-major, so byte `4 * col + row`.
pub fn round(block: &mut [u8; BLOCK], key: &[u8; BLOCK]) {
    // SubBytes and ShiftRows together: row `r` reads `r` columns to the right.
    let mut s = [0u8; BLOCK];
    for col in 0..4 {
        for row in 0..4 {
            s[4 * col + row] = SBOX[block[4 * ((col + row) % 4) + row] as usize];
        }
    }

    // MixColumns, folding AddRoundKey into the same pass.
    for col in 0..4 {
        let (a0, a1, a2, a3) = (s[4 * col], s[4 * col + 1], s[4 * col + 2], s[4 * col + 3]);
        block[4 * col] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3 ^ key[4 * col];
        block[4 * col + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3 ^ key[4 * col + 1];
        block[4 * col + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3 ^ key[4 * col + 2];
        block[4 * col + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3) ^ key[4 * col + 3];
    }
}

/// Ten AES rounds with consecutive round keys and no whitening —
/// `aesb_pseudo_round`.
pub fn pseudo_round(block: &mut [u8; BLOCK], keys: &[u8; EXPANDED]) {
    for r in 0..PSEUDO_ROUNDS {
        let key: &[u8; BLOCK] = keys[r * BLOCK..(r + 1) * BLOCK]
            .try_into()
            .expect("16 bytes");
        round(block, key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    /// FIPS-197 A.3: the AES-256 key schedule for the sample key.
    #[test]
    fn the_key_schedule_matches_fips_197() {
        let key: [u8; KEY] =
            hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
                .expect("hex")
                .try_into()
                .expect("32 bytes");
        let exp = expand_key(&key);

        // w[8], the first word past the key itself.
        assert_eq!(&exp[32..36], &hex::decode("9ba35411").expect("hex")[..]);
        // w[59], the last word of the expansion.
        assert_eq!(&exp[236..240], &hex::decode("706c631e").expect("hex")[..]);
    }

    /// One call is `aesenc`, checked against FIPS-197 C.1: the whole of round
    /// one of the AES-128 example, which is SubBytes, ShiftRows, MixColumns and
    /// AddRoundKey in exactly that order.
    #[test]
    fn one_round_is_aesenc() {
        let mut b: [u8; BLOCK] = hex::decode("00112233445566778899aabbccddeeff")
            .expect("hex")
            .try_into()
            .expect("16 bytes");
        // Whiten by hand — real AES does this before round one, CryptoNight
        // never does it at all.
        let k0: [u8; BLOCK] = hex::decode("000102030405060708090a0b0c0d0e0f")
            .expect("hex")
            .try_into()
            .expect("16 bytes");
        for (x, k) in b.iter_mut().zip(k0.iter()) {
            *x ^= k;
        }
        // FIPS-197 C.1, round[1].start.
        assert_eq!(hex::encode(&b), "00102030405060708090a0b0c0d0e0f0");

        let k1: [u8; BLOCK] = hex::decode("d6aa74fdd2af72fadaa678f1d6ab76fe")
            .expect("hex")
            .try_into()
            .expect("16 bytes");
        round(&mut b, &k1);
        // FIPS-197 C.1, round[2].start.
        assert_eq!(hex::encode(&b), "89d810e8855ace682d1843d8cb128fe4");
    }

    /// A zero key leaves the round function alone, and it is not the identity.
    #[test]
    fn the_round_mixes() {
        let mut b = [0u8; BLOCK];
        round(&mut b, &[0u8; BLOCK]);
        // SBOX[0] = 0x63; MixColumns of an all-0x63 column is 0x63 again.
        assert_eq!(b, [0x63u8; BLOCK]);

        let mut b = [0u8; BLOCK];
        b[0] = 1;
        round(&mut b, &[0u8; BLOCK]);
        assert_ne!(b, [0x63u8; BLOCK]);
    }

    /// `xtime` reduces by the AES polynomial.
    #[test]
    fn the_field_doubling() {
        assert_eq!(xtime(0x80), 0x1b);
        assert_eq!(xtime(0x01), 0x02);
        assert_eq!(xtime(0x57), 0xae);
    }
}
