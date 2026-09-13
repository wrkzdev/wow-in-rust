//! CryptoNote base58 — **not** Bitcoin base58.
//!
//! `specs/02-crypto.md` §5, from `src/common/base58.cpp`.
//!
//! Data is processed in **8-byte blocks**, each encoded as exactly **11**
//! characters; a trailing partial block of `n` bytes takes
//! `ENCODED_BLOCK_SIZES[n]` characters. Each block is a **big-endian** integer.
//! The fixed block size is what makes this streamable and is why the encoding
//! has no leading-zero special case.

use crate::hash::cn_fast_hash;
use wow_serialize::varint::{read_varint, write_varint};

/// The alphabet. Note `l`, `I`, `0` and `O` are absent.
pub const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const ALPHABET_SIZE: u64 = 58;

/// `encoded_block_sizes[n]` — characters produced by an `n`-byte block.
pub const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

const FULL_BLOCK_SIZE: usize = 8;
const FULL_ENCODED_BLOCK_SIZE: usize = 11;

/// The 4-byte address checksum length.
pub const ADDR_CHECKSUM_SIZE: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base58Error {
    /// A character outside the alphabet.
    InvalidSymbol,
    /// A length that no combination of full and partial blocks can produce.
    InvalidLength,
    /// A block whose value does not fit the bytes it decodes to.
    Overflow,
    /// `decode_addr`: the trailing checksum did not match.
    ChecksumMismatch,
    /// `decode_addr`: the leading varint tag was malformed.
    BadTag,
    /// `decode_addr`: the blob was shorter than the checksum.
    TooShort,
}

impl core::fmt::Display for Base58Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Base58Error::InvalidSymbol => "invalid base58 symbol",
            Base58Error::InvalidLength => "invalid base58 length",
            Base58Error::Overflow => "base58 block overflows its byte width",
            Base58Error::ChecksumMismatch => "address checksum mismatch",
            Base58Error::BadTag => "malformed address tag",
            Base58Error::TooShort => "address too short",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Base58Error {}

/// `decoded_block_sizes(encoded_len)`: the inverse of [`ENCODED_BLOCK_SIZES`],
/// or `None` for a length no block can produce (1, 4 and 8).
fn decoded_block_size(encoded: usize) -> Option<usize> {
    ENCODED_BLOCK_SIZES.iter().position(|&n| n == encoded)
}

fn uint_8be_to_64(data: &[u8]) -> u64 {
    debug_assert!((1..=8).contains(&data.len()));
    let mut buf = [0u8; 8];
    buf[8 - data.len()..].copy_from_slice(data);
    u64::from_be_bytes(buf)
}

fn uint_64_to_8be(num: u64, size: usize, out: &mut [u8]) {
    debug_assert!((1..=8).contains(&size));
    let be = num.to_be_bytes();
    out[..size].copy_from_slice(&be[8 - size..]);
}

fn encode_block(block: &[u8], out: &mut [u8]) {
    let mut num = uint_8be_to_64(block);
    let n = ENCODED_BLOCK_SIZES[block.len()];
    // Pre-filled with alphabet[0], so leading "1"s come for free.
    out[..n].fill(ALPHABET[0]);
    let mut i = n;
    while num > 0 {
        i -= 1;
        out[i] = ALPHABET[(num % ALPHABET_SIZE) as usize];
        num /= ALPHABET_SIZE;
    }
}

fn decode_block(block: &[u8], out: &mut [u8]) -> Result<(), Base58Error> {
    let res_size = decoded_block_size(block.len()).ok_or(Base58Error::InvalidLength)?;
    if res_size == 0 {
        return Err(Base58Error::InvalidLength);
    }

    let mut res_num: u64 = 0;
    let mut order: u64 = 1;
    for &ch in block.iter().rev() {
        let digit = ALPHABET
            .iter()
            .position(|&a| a == ch)
            .ok_or(Base58Error::InvalidSymbol)? as u64;
        // The C uses mul128 and checks both the high word and the addition
        // carry; `checked_*` is the same test.
        let product = order.checked_mul(digit).ok_or(Base58Error::Overflow)?;
        res_num = res_num.checked_add(product).ok_or(Base58Error::Overflow)?;
        order = order.wrapping_mul(ALPHABET_SIZE); // 58^10 < 2^64, never overflows in use
    }

    if res_size < FULL_BLOCK_SIZE && (1u64 << (8 * res_size)) <= res_num {
        return Err(Base58Error::Overflow);
    }
    uint_64_to_8be(res_num, res_size, out);
    Ok(())
}

/// `tools::base58::encode(data)`.
pub fn encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let full_blocks = data.len() / FULL_BLOCK_SIZE;
    let last = data.len() % FULL_BLOCK_SIZE;
    let size = full_blocks * FULL_ENCODED_BLOCK_SIZE + ENCODED_BLOCK_SIZES[last];

    let mut out = vec![ALPHABET[0]; size];
    for i in 0..full_blocks {
        let (src, dst) = (
            &data[i * FULL_BLOCK_SIZE..(i + 1) * FULL_BLOCK_SIZE],
            &mut out[i * FULL_ENCODED_BLOCK_SIZE..],
        );
        encode_block(src, dst);
    }
    if last > 0 {
        let src = &data[full_blocks * FULL_BLOCK_SIZE..];
        let dst = &mut out[full_blocks * FULL_ENCODED_BLOCK_SIZE..];
        encode_block(src, dst);
    }
    // Every byte written came from ALPHABET, which is ASCII.
    String::from_utf8(out).expect("base58 alphabet is ASCII")
}

/// `tools::base58::decode(enc, data)`.
pub fn decode(enc: &str) -> Result<Vec<u8>, Base58Error> {
    if enc.is_empty() {
        return Ok(Vec::new());
    }
    let enc = enc.as_bytes();
    let full_blocks = enc.len() / FULL_ENCODED_BLOCK_SIZE;
    let last_enc = enc.len() % FULL_ENCODED_BLOCK_SIZE;
    let last_dec = decoded_block_size(last_enc).ok_or(Base58Error::InvalidLength)?;
    let size = full_blocks * FULL_BLOCK_SIZE + last_dec;

    let mut out = vec![0u8; size];
    for i in 0..full_blocks {
        let src = &enc[i * FULL_ENCODED_BLOCK_SIZE..(i + 1) * FULL_ENCODED_BLOCK_SIZE];
        decode_block(src, &mut out[i * FULL_BLOCK_SIZE..])?;
    }
    if last_enc > 0 {
        let src = &enc[full_blocks * FULL_ENCODED_BLOCK_SIZE..];
        decode_block(src, &mut out[full_blocks * FULL_BLOCK_SIZE..])?;
    }
    Ok(out)
}

/// `encode_addr(tag, data)`.
///
/// ```text
/// body     = varint(prefix) || data
/// checksum = cn_fast_hash(body)[0..4]
/// address  = base58_encode(body || checksum)
/// ```
pub fn encode_addr(tag: u64, data: &[u8]) -> String {
    let mut buf = Vec::with_capacity(10 + data.len() + ADDR_CHECKSUM_SIZE);
    write_varint(&mut buf, tag);
    buf.extend_from_slice(data);
    let checksum = cn_fast_hash(&buf);
    buf.extend_from_slice(&checksum[..ADDR_CHECKSUM_SIZE]);
    encode(&buf)
}

/// `decode_addr(addr, tag, data)`. Returns `(tag, data)`.
pub fn decode_addr(addr: &str) -> Result<(u64, Vec<u8>), Base58Error> {
    let blob = decode(addr)?;
    if blob.len() <= ADDR_CHECKSUM_SIZE {
        return Err(Base58Error::TooShort);
    }
    let (body, checksum) = blob.split_at(blob.len() - ADDR_CHECKSUM_SIZE);
    let expected = cn_fast_hash(body);
    if checksum != &expected[..ADDR_CHECKSUM_SIZE] {
        return Err(Base58Error::ChecksumMismatch);
    }
    let (tag, n) = read_varint(body).map_err(|_| Base58Error::BadTag)?;
    Ok((tag, body[n..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_is_the_cryptonote_one() {
        assert_eq!(ALPHABET.len(), 58);
        // Bitcoin's alphabet is the same set; the *block* scheme is what differs.
        // Guard the visually confusable exclusions.
        for bad in *b"0OIl" {
            assert!(
                !ALPHABET.contains(&bad),
                "{} should be excluded",
                bad as char
            );
        }
    }

    #[test]
    fn block_size_table() {
        assert_eq!(ENCODED_BLOCK_SIZES, [0, 2, 3, 5, 6, 7, 9, 10, 11]);
        // 1, 4 and 8 encoded characters are impossible.
        assert_eq!(decoded_block_size(1), None);
        assert_eq!(decoded_block_size(4), None);
        assert_eq!(decoded_block_size(8), None);
        assert_eq!(decoded_block_size(11), Some(8));
        assert_eq!(decoded_block_size(0), Some(0));
    }

    #[test]
    fn roundtrips_all_short_lengths() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            let enc = encode(&data);
            assert_eq!(decode(&enc).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn all_ones_and_all_max_bytes() {
        for pat in [0x00u8, 0xff] {
            for len in [1usize, 7, 8, 9, 16, 64, 69] {
                let data = vec![pat; len];
                assert_eq!(decode(&encode(&data)).unwrap(), data);
            }
        }
    }

    /// `specs/02` §5: a full 8-byte block is exactly 11 characters, and a
    /// partial block follows the table. This is the property that makes
    /// CryptoNote base58 differ from Bitcoin's.
    #[test]
    fn encoded_lengths_follow_the_block_table() {
        assert_eq!(encode(&[0u8; 8]).len(), 11);
        assert_eq!(encode(&[0u8; 16]).len(), 22);
        assert_eq!(encode(&[0u8; 9]).len(), 11 + 2);
        assert_eq!(encode(&[0u8; 12]).len(), 11 + 6);
        // A mainnet standard address: varint(4146) is 2 bytes, + 64 + 4 = 70.
        assert_eq!(encode(&[0u8; 70]).len(), 8 * 11 + ENCODED_BLOCK_SIZES[6]);
        assert_eq!(encode(&[0u8; 70]).len(), 97);
        // An integrated address: 2 + 72 + 4 = 78 bytes -> 108 characters.
        assert_eq!(encode(&[0u8; 78]).len(), 108);
    }

    #[test]
    fn rejects_impossible_lengths() {
        assert_eq!(decode("1"), Err(Base58Error::InvalidLength));
        assert_eq!(decode("1111"), Err(Base58Error::InvalidLength));
        assert_eq!(decode("11111111"), Err(Base58Error::InvalidLength));
        // 11 + 1 is also impossible.
        assert_eq!(decode("111111111112"), Err(Base58Error::InvalidLength));
    }

    #[test]
    fn rejects_invalid_symbols() {
        assert_eq!(decode("11"), Ok(vec![0]));
        assert_eq!(decode("0l"), Err(Base58Error::InvalidSymbol));
        assert_eq!(decode("1O"), Err(Base58Error::InvalidSymbol));
        assert_eq!(decode("1 "), Err(Base58Error::InvalidSymbol));
    }

    /// A block may encode a number too large for the bytes it decodes to; the C
    /// checks for this and so must we, or two strings would decode to one blob.
    #[test]
    fn rejects_block_overflow() {
        // "zz" would decode to 57*58 + 57 = 3363 > 255, which does not fit 1 byte.
        assert_eq!(decode("zz"), Err(Base58Error::Overflow));
        // The largest valid 2-character block is 255 = 4*58 + 23 -> "5Q".
        assert_eq!(decode("5Q").unwrap(), vec![255]);
    }

    #[test]
    fn address_roundtrip_for_all_wownero_prefixes() {
        let data = [0x42u8; 64];
        // specs/01 §2: mainnet 4146 / 6810 / 12208, testnet 53 / 54 / 63,
        // stagenet 24 / 25 / 36.
        for tag in [4146u64, 6810, 12208, 53, 54, 63, 24, 25, 36] {
            let addr = encode_addr(tag, &data);
            let (got_tag, got_data) = decode_addr(&addr).unwrap();
            assert_eq!(got_tag, tag);
            assert_eq!(got_data, data);
        }
    }

    #[test]
    fn mainnet_address_lengths() {
        // 97 characters for a standard/sub address, 108 for an integrated one.
        assert_eq!(encode_addr(4146, &[0u8; 64]).len(), 97);
        assert_eq!(encode_addr(12208, &[0u8; 64]).len(), 97);
        assert_eq!(encode_addr(6810, &[0u8; 72]).len(), 108);
    }

    #[test]
    fn checksum_is_enforced() {
        let addr = encode_addr(4146, &[7u8; 64]);
        assert!(decode_addr(&addr).is_ok());
        // Flip one character in the checksum region (the tail).
        let mut chars: Vec<char> = addr.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '1' { '2' } else { '1' };
        let tampered: String = chars.into_iter().collect();
        assert!(matches!(
            decode_addr(&tampered),
            Err(Base58Error::ChecksumMismatch) | Err(Base58Error::Overflow)
        ));
    }

    #[test]
    fn decode_addr_rejects_short_input() {
        assert_eq!(decode_addr(""), Err(Base58Error::TooShort));
        assert_eq!(decode_addr("11"), Err(Base58Error::TooShort));
    }

    /// `specs/15` §4.4: base58 is a fuzz target; it must never panic.
    #[test]
    fn never_panics() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        for len in 0..120usize {
            let s: String = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                    // Draw from the full printable ASCII range, not just the
                    // alphabet, so invalid symbols are exercised too.
                    char::from(33u8 + ((x >> 33) % 94) as u8)
                })
                .collect();
            let _ = decode(&s);
            let _ = decode_addr(&s);
        }
        // Valid-alphabet strings of every length up to 40.
        for len in 0..40usize {
            let s: String = (0..len).map(|i| char::from(ALPHABET[i % 58])).collect();
            let _ = decode(&s);
            let _ = decode_addr(&s);
        }
    }
}
