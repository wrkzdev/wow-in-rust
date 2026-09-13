//! CRC-32 (the ISO-HDLC / zlib polynomial), matching `boost::crc_32_type`.
//!
//! Used only for the mnemonic checksum word (`specs/02-crypto.md` §6). Written
//! out rather than pulled in as a dependency: it is twelve lines and the
//! checksum decides whether a seed opens a wallet.

/// Reflected polynomial `0xEDB88320`, init `0xFFFFFFFF`, final XOR `0xFFFFFFFF`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The standard CRC-32 check values. `boost::crc_32_type` computes exactly
    /// these, so if the polynomial or the reflection were wrong, every seed
    /// checksum would be wrong too.
    #[test]
    fn known_vectors() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"abc"), 0x3524_41C2);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn is_order_sensitive() {
        assert_ne!(crc32(b"ab"), crc32(b"ba"));
    }
}
