//! RandomX's AES functions: `AesGenerator1R`, `AesGenerator4R` and
//! `AesHash1R` (`aes_hash.cpp`; RandomX spec §3.2-3.4).
//!
//! Each works on four 128-bit lanes and uses single AES rounds -- x86's
//! `AESENC` (SubBytes, ShiftRows, MixColumns, AddRoundKey) and `AESDEC` (their
//! inverses, then AddRoundKey) -- as mixing steps, not as a cipher. The
//! portable rounds use the usual T-tables, computed here at compile time; on
//! x86-64 with AES-NI the hardware rounds are used instead, and a test holds
//! the two to the same answer.

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

const fn xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

/// A little-endian 32-bit word from four bytes.
const fn word(b0: u8, b1: u8, b2: u8, b3: u8) -> u32 {
    b0 as u32 | (b1 as u32) << 8 | (b2 as u32) << 16 | (b3 as u32) << 24
}

/// `lutEnc0..3`: SubBytes and MixColumns for the byte in each row.
static ENC: [[u32; 256]; 4] = {
    let mut t = [[0u32; 256]; 4];
    let mut i = 0;
    while i < 256 {
        let s = SBOX[i];
        let s2 = xtime(s);
        let s3 = s2 ^ s;
        t[0][i] = word(s2, s, s, s3);
        t[1][i] = word(s3, s2, s, s);
        t[2][i] = word(s, s3, s2, s);
        t[3][i] = word(s, s, s3, s2);
        i += 1;
    }
    t
};

/// `lutDec0..3`: InvSubBytes and InvMixColumns for the byte in each row.
static DEC: [[u32; 256]; 4] = {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    let mut t = [[0u32; 256]; 4];
    let mut i = 0;
    while i < 256 {
        let y = inv[i];
        let (y9, y11, y13, y14) = (gmul(y, 9), gmul(y, 11), gmul(y, 13), gmul(y, 14));
        t[0][i] = word(y14, y9, y13, y11);
        t[1][i] = word(y11, y14, y9, y13);
        t[2][i] = word(y13, y11, y14, y9);
        t[3][i] = word(y9, y13, y11, y14);
        i += 1;
    }
    t
};

/// A 128-bit lane as its four little-endian words, byte 0 first.
type Lane = [u32; 4];

/// `soft_aesenc`: one `AESENC` round.
#[inline(always)]
fn enc(s: Lane, key: Lane) -> Lane {
    let (s0, s1, s2, s3) = (s[3], s[2], s[1], s[0]);
    let b = |x: u32, shift: u32| ((x >> shift) & 0xff) as usize;
    [
        ENC[0][b(s3, 0)] ^ ENC[1][b(s2, 8)] ^ ENC[2][b(s1, 16)] ^ ENC[3][b(s0, 24)] ^ key[0],
        ENC[0][b(s2, 0)] ^ ENC[1][b(s1, 8)] ^ ENC[2][b(s0, 16)] ^ ENC[3][b(s3, 24)] ^ key[1],
        ENC[0][b(s1, 0)] ^ ENC[1][b(s0, 8)] ^ ENC[2][b(s3, 16)] ^ ENC[3][b(s2, 24)] ^ key[2],
        ENC[0][b(s0, 0)] ^ ENC[1][b(s3, 8)] ^ ENC[2][b(s2, 16)] ^ ENC[3][b(s1, 24)] ^ key[3],
    ]
}

/// `soft_aesdec`: one `AESDEC` round.
#[inline(always)]
fn dec(s: Lane, key: Lane) -> Lane {
    let (s0, s1, s2, s3) = (s[3], s[2], s[1], s[0]);
    let b = |x: u32, shift: u32| ((x >> shift) & 0xff) as usize;
    [
        DEC[0][b(s3, 0)] ^ DEC[1][b(s0, 8)] ^ DEC[2][b(s1, 16)] ^ DEC[3][b(s2, 24)] ^ key[0],
        DEC[0][b(s2, 0)] ^ DEC[1][b(s3, 8)] ^ DEC[2][b(s0, 16)] ^ DEC[3][b(s1, 24)] ^ key[1],
        DEC[0][b(s1, 0)] ^ DEC[1][b(s2, 8)] ^ DEC[2][b(s3, 16)] ^ DEC[3][b(s0, 24)] ^ key[2],
        DEC[0][b(s0, 0)] ^ DEC[1][b(s1, 8)] ^ DEC[2][b(s2, 16)] ^ DEC[3][b(s3, 24)] ^ key[3],
    ]
}

fn lane(bytes: &[u8]) -> Lane {
    let w = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().expect("4 bytes"));
    [w(0), w(4), w(8), w(12)]
}

fn put_lane(out: &mut [u8], l: &Lane) {
    for (chunk, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(l) {
        *chunk = w.to_le_bytes();
    }
}

fn lanes(bytes: &[u8; 64]) -> [Lane; 4] {
    [
        lane(&bytes[0..16]),
        lane(&bytes[16..32]),
        lane(&bytes[32..48]),
        lane(&bytes[48..64]),
    ]
}

fn put_lanes(out: &mut [u8], s: &[Lane; 4]) {
    for (chunk, l) in out.as_chunks_mut::<16>().0.iter_mut().zip(s) {
        put_lane(chunk, l);
    }
}

// The constants as `_mm_set_epi32` lists them run from the high word down;
// these are the same words in memory order.

/// `AES_HASH_1R_STATE0..3` = BLAKE2b-512("RandomX AesHash1R state").
const HASH_STATE: [Lane; 4] = [
    [0x92b52c0d, 0x9fa856de, 0xcc82db47, 0xd7983aad],
    [0x338d996e, 0x15c7b798, 0xf59e125a, 0xace78057],
    [0x6a770017, 0xae62c7d0, 0x5079506b, 0xe8a07ce4],
    [0x630a240c, 0x07ad828d, 0x79a10005, 0x7e994948],
];

/// `AES_HASH_1R_XKEY0..1` = BLAKE2b-256("RandomX AesHash1R xkeys").
const HASH_XKEYS: [Lane; 2] = [
    [0xf6fa8389, 0x8b24949f, 0x90dc56bf, 0x06890201],
    [0x61b263d1, 0x51f4e03c, 0xee1043c6, 0xed18f99b],
];

/// `AES_GEN_1R_KEY0..3` = BLAKE2b-512("RandomX AesGenerator1R keys").
const GEN1R_KEYS: [Lane; 4] = [
    [0x6daca553, 0x62716609, 0xdbb5552b, 0xb4f44917],
    [0x6d7caf07, 0x846a710d, 0x1725d378, 0x0da1dc4e],
    [0x3f1262f1, 0x9f947ec6, 0xf4c0794f, 0x3e20e345],
    [0x6aef8135, 0xb1ba317c, 0x16314c88, 0x49169154],
];

/// RandomWOW's `AES_GEN_4R_KEY0..3`, on all four lanes.
///
/// The fork's commit replaced upstream's values and dropped keys 4-7 from the
/// rounds, leaving the comment that derives them from BLAKE2b unchanged; what
/// these are derived from, if anything, it does not say.
pub(crate) const GEN4R_KEYS_WOWNERO: [Lane; 8] = {
    let k = [
        [0xf890465d, 0x7ffbe4a6, 0x141f82b7, 0xcf359e95],
        [0x6a55c450, 0xfee8278a, 0xbd5c5ac3, 0x6741ffdc],
        [0x114c47a4, 0xd524fde4, 0xa7279ad2, 0x3d324aac],
        [0x810c3a2a, 0x99a9aeff, 0x42d3dbd9, 0x76f6db08],
    ];
    [k[0], k[1], k[2], k[3], k[0], k[1], k[2], k[3]]
};

/// Upstream's `AES_GEN_4R_KEY0..3` = BLAKE2b-512("RandomX AesGenerator4R keys
/// 0-3") for lanes 0 and 1, and `KEY4..7` = BLAKE2b-512("RandomX
/// AesGenerator4R keys 4-7") for lanes 2 and 3.
pub(crate) const GEN4R_KEYS_RANDOMX: [Lane; 8] = [
    [0x6421aadd, 0xd1833ddb, 0x2f546d2b, 0x99e5d23f],
    [0xb20e3450, 0xb6913f55, 0x06f79d53, 0xa5dfcde5],
    [0x5c3ed904, 0x515e7baf, 0x0aa4679f, 0x171c02bf],
    [0x85623763, 0xe78f5d08, 0xcd673785, 0xd8ded291],
    [0xb5826f73, 0xe3d6a7a6, 0x3d518b6d, 0x229effb4],
    [0xc7566bf3, 0x9c10b3d9, 0xe9024d4e, 0xb272b7d2],
    [0xf273c9e7, 0xf765a38b, 0x2ba9660a, 0xf63befa7],
    [0x7a7cd609, 0x915839de, 0x0c06d1fd, 0xc0b0762d],
];

/// Whether this CPU has the AES instructions the hardware rounds use.
pub(crate) fn hardware_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// `fillAes1Rx4`: fill `out` (a multiple of 64 bytes) from `state`, one round
/// per 16 bytes, and leave the advanced state in `state`.
pub(crate) fn fill_aes_1r_x4(state: &mut [u8; 64], out: &mut [u8], hard: bool) {
    debug_assert!(out.len().is_multiple_of(64));
    #[cfg(target_arch = "x86_64")]
    if hard && hardware_available() {
        // SAFETY: the CPU was just checked for AES-NI.
        unsafe { hw::fill_1r(state, out) };
        return;
    }
    let _ = hard;
    let mut s = lanes(state);
    for block in out.as_chunks_mut::<64>().0 {
        s[0] = dec(s[0], GEN1R_KEYS[0]);
        s[1] = enc(s[1], GEN1R_KEYS[1]);
        s[2] = dec(s[2], GEN1R_KEYS[2]);
        s[3] = enc(s[3], GEN1R_KEYS[3]);
        put_lanes(block, &s);
    }
    put_lanes(state, &s);
}

/// `fillAes4Rx4`: fill `out` from `state` with four rounds per 16 bytes. The
/// state is not written back. `keys` holds four keys for lanes 0 and 1, then
/// four for lanes 2 and 3.
pub(crate) fn fill_aes_4r_x4(state: &[u8; 64], out: &mut [u8], keys: &[Lane; 8], hard: bool) {
    debug_assert!(out.len().is_multiple_of(64));
    #[cfg(target_arch = "x86_64")]
    if hard && hardware_available() {
        // SAFETY: the CPU was just checked for AES-NI.
        unsafe { hw::fill_4r(state, out, keys) };
        return;
    }
    let _ = hard;
    let (keys01, keys23) = keys.split_at(4);
    let mut s = lanes(state);
    for block in out.as_chunks_mut::<64>().0 {
        for (key, key23) in keys01.iter().zip(keys23) {
            s[0] = dec(s[0], *key);
            s[1] = enc(s[1], *key);
            s[2] = dec(s[2], *key23);
            s[3] = enc(s[3], *key23);
        }
        put_lanes(block, &s);
    }
}

/// `hashAes1Rx4`: a 64-byte hash of `input` (a multiple of 64 bytes).
pub(crate) fn hash_aes_1r_x4(input: &[u8], hard: bool) -> [u8; 64] {
    debug_assert!(input.len().is_multiple_of(64));
    #[cfg(target_arch = "x86_64")]
    if hard && hardware_available() {
        // SAFETY: the CPU was just checked for AES-NI.
        return unsafe { hw::hash_1r(input) };
    }
    let _ = hard;
    let mut s = HASH_STATE;
    for block in input.as_chunks::<64>().0 {
        s[0] = enc(s[0], lane(&block[0..16]));
        s[1] = dec(s[1], lane(&block[16..32]));
        s[2] = enc(s[2], lane(&block[32..48]));
        s[3] = dec(s[3], lane(&block[48..64]));
    }
    for key in &HASH_XKEYS {
        s[0] = enc(s[0], *key);
        s[1] = dec(s[1], *key);
        s[2] = enc(s[2], *key);
        s[3] = dec(s[3], *key);
    }
    let mut out = [0u8; 64];
    put_lanes(&mut out, &s);
    out
}

#[cfg(target_arch = "x86_64")]
mod hw {
    use core::arch::x86_64::{
        __m128i, _mm_aesdec_si128, _mm_aesenc_si128, _mm_loadu_si128, _mm_storeu_si128,
    };

    use super::{put_lane, Lane, GEN1R_KEYS, HASH_STATE, HASH_XKEYS};

    fn bytes(l: &Lane) -> [u8; 16] {
        let mut b = [0u8; 16];
        put_lane(&mut b, l);
        b
    }

    #[target_feature(enable = "aes")]
    unsafe fn load(b: &[u8]) -> __m128i {
        debug_assert!(b.len() >= 16);
        // SAFETY: at least 16 readable bytes; `loadu` needs no alignment.
        unsafe { _mm_loadu_si128(b.as_ptr().cast()) }
    }

    #[target_feature(enable = "aes")]
    unsafe fn store(b: &mut [u8], v: __m128i) {
        debug_assert!(b.len() >= 16);
        // SAFETY: at least 16 writable bytes; `storeu` needs no alignment.
        unsafe { _mm_storeu_si128(b.as_mut_ptr().cast(), v) }
    }

    /// # Safety
    /// The CPU must support AES-NI.
    #[target_feature(enable = "aes")]
    pub(super) unsafe fn fill_1r(state: &mut [u8; 64], out: &mut [u8]) {
        // SAFETY: the caller checked for AES-NI; every load and store is on a
        // 16-byte window of a 64-byte chunk.
        unsafe {
            let k: Vec<__m128i> = GEN1R_KEYS.iter().map(|l| load(&bytes(l))).collect();
            let mut s = [
                load(&state[0..]),
                load(&state[16..]),
                load(&state[32..]),
                load(&state[48..]),
            ];
            for block in out.as_chunks_mut::<64>().0 {
                s[0] = _mm_aesdec_si128(s[0], k[0]);
                s[1] = _mm_aesenc_si128(s[1], k[1]);
                s[2] = _mm_aesdec_si128(s[2], k[2]);
                s[3] = _mm_aesenc_si128(s[3], k[3]);
                for (i, v) in s.iter().enumerate() {
                    store(&mut block[16 * i..], *v);
                }
            }
            for (i, v) in s.iter().enumerate() {
                store(&mut state[16 * i..], *v);
            }
        }
    }

    /// # Safety
    /// The CPU must support AES-NI.
    #[target_feature(enable = "aes")]
    pub(super) unsafe fn fill_4r(state: &[u8; 64], out: &mut [u8], keys: &[Lane; 8]) {
        // SAFETY: as `fill_1r`.
        unsafe {
            let k: Vec<__m128i> = keys.iter().map(|l| load(&bytes(l))).collect();
            let (k, k23) = k.split_at(4);
            let mut s = [
                load(&state[0..]),
                load(&state[16..]),
                load(&state[32..]),
                load(&state[48..]),
            ];
            for block in out.as_chunks_mut::<64>().0 {
                for (key, key23) in k.iter().zip(k23) {
                    s[0] = _mm_aesdec_si128(s[0], *key);
                    s[1] = _mm_aesenc_si128(s[1], *key);
                    s[2] = _mm_aesdec_si128(s[2], *key23);
                    s[3] = _mm_aesenc_si128(s[3], *key23);
                }
                for (i, v) in s.iter().enumerate() {
                    store(&mut block[16 * i..], *v);
                }
            }
        }
    }

    /// # Safety
    /// The CPU must support AES-NI.
    #[target_feature(enable = "aes")]
    pub(super) unsafe fn hash_1r(input: &[u8]) -> [u8; 64] {
        // SAFETY: as `fill_1r`.
        unsafe {
            let mut s = [
                load(&bytes(&HASH_STATE[0])),
                load(&bytes(&HASH_STATE[1])),
                load(&bytes(&HASH_STATE[2])),
                load(&bytes(&HASH_STATE[3])),
            ];
            for block in input.as_chunks::<64>().0 {
                s[0] = _mm_aesenc_si128(s[0], load(&block[0..]));
                s[1] = _mm_aesdec_si128(s[1], load(&block[16..]));
                s[2] = _mm_aesenc_si128(s[2], load(&block[32..]));
                s[3] = _mm_aesdec_si128(s[3], load(&block[48..]));
            }
            for key in &HASH_XKEYS {
                let key = load(&bytes(key));
                s[0] = _mm_aesenc_si128(s[0], key);
                s[1] = _mm_aesdec_si128(s[1], key);
                s[2] = _mm_aesenc_si128(s[2], key);
                s[3] = _mm_aesdec_si128(s[3], key);
            }
            let mut out = [0u8; 64];
            for (i, v) in s.iter().enumerate() {
                store(&mut out[16 * i..], *v);
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Upstream's `AesGenerator4R` keys are the BLAKE2b-512 hashes their
    /// comment names, which is what makes a typo in them detectable.
    #[test]
    fn upstream_4r_keys_come_from_blake2b() {
        for (label, keys) in [
            (
                &b"RandomX AesGenerator4R keys 0-3"[..],
                &GEN4R_KEYS_RANDOMX[..4],
            ),
            (b"RandomX AesGenerator4R keys 4-7", &GEN4R_KEYS_RANDOMX[4..]),
        ] {
            let mut out = [0u8; 64];
            crate::blake2b::blake2b(&mut out, label);
            let mut want = [0u8; 64];
            put_lanes(&mut want, &[keys[0], keys[1], keys[2], keys[3]]);
            assert_eq!(out, want, "{}", String::from_utf8_lossy(label));
        }
        assert_eq!(GEN4R_KEYS_WOWNERO[..4], GEN4R_KEYS_WOWNERO[4..]);
    }

    /// The first entries of the C++'s tables, which the formulas must give.
    #[test]
    fn the_tables_match_the_reference() {
        assert_eq!(ENC[0][0], 0xa56363c6);
        assert_eq!(ENC[1][0], 0x6363c6a5);
        assert_eq!(ENC[3][0], 0xc6a56363);
        assert_eq!(DEC[0][0], 0x50a7f451);
        assert_eq!(DEC[1][0], 0xa7f45150);
    }

    /// `tests.cpp`, "AesGenerator1R".
    #[test]
    fn aes_generator_1r_matches_the_reference_vector() {
        for hard in [false, true] {
            let mut state = [0u8; 64];
            state[..32].copy_from_slice(&unhex(
                "6c19536eb2de31b6c0065f7f116e86f960d8af0c57210a6584c3237b9d064dc7",
            ));
            let mut out = [0u8; 64];
            fill_aes_1r_x4(&mut state, &mut out, hard);
            assert_eq!(
                hex(&out[..32]),
                "fa89397dd6ca422513aeadba3f124b5540324c4ad4b6db434394307a17c833ab",
                "hard {hard}"
            );
        }
    }

    /// The portable rounds agree with AES-NI wherever the CPU has it.
    #[test]
    fn portable_and_hardware_rounds_agree() {
        if !hardware_available() {
            return;
        }
        let mut seed = [0u8; 64];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i * 37 + 11) as u8;
        }
        let (mut s1, mut s2) = (seed, seed);
        let (mut a, mut b) = (vec![0u8; 4096], vec![0u8; 4096]);
        fill_aes_1r_x4(&mut s1, &mut a, false);
        fill_aes_1r_x4(&mut s2, &mut b, true);
        assert_eq!(a, b);
        assert_eq!(s1, s2);
        for keys in [&GEN4R_KEYS_WOWNERO, &GEN4R_KEYS_RANDOMX] {
            fill_aes_4r_x4(&seed, &mut a, keys, false);
            fill_aes_4r_x4(&seed, &mut b, keys, true);
            assert_eq!(a, b);
        }
        assert_eq!(hash_aes_1r_x4(&a, false), hash_aes_1r_x4(&a, true));
    }
}
