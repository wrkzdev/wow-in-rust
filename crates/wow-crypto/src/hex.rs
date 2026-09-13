//! Minimal hex, so `Display` on the key types needs no dependency.
//!
//! `pod_to_hex` in the C prints bytes in **storage order**, lowercase. That
//! ordering is load-bearing at one consensus site: the HF 16–17 dynamic
//! coinbase unlock reads `pod_to_hex(block_id).substr(0, 3)` and parses those
//! 1.5 bytes of *text* as hex (`specs/06-consensus-rules.md` §5.1.1, §9.9). A
//! byte-swapped reading there is a chain split, so the convention is pinned by
//! a test here rather than left implicit.

const HEX: &[u8; 16] = b"0123456789abcdef";

/// `pod_to_hex`: lowercase hex in storage order.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// `hex_to_pod`. Rejects odd lengths and non-hex characters; accepts either
/// case, as `epee::string_tools::parse_hexstr_to_binbuff` does.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.as_chunks::<2>().0 {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

/// Decode into a fixed-size array.
pub fn decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = decode(s)?;
    v.try_into().ok()
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for len in 0..40usize {
            let v: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(29)).collect();
            assert_eq!(decode(&encode(&v)).unwrap(), v);
        }
    }

    /// Storage order, not reversed. The coinbase-unlock rule of
    /// `specs/06` §5.1.1 reads the first three characters of this string.
    #[test]
    fn prints_in_storage_order() {
        assert_eq!(encode(&[0x12, 0x34, 0xab]), "1234ab");
        let id = [0xdf, 0xd0, 0x56, 0xb2];
        assert_eq!(&encode(&id)[..3], "dfd");
        // ...which parses as 0xdfd = 3581, not as 0x0dd or a byte-swapped value.
        assert_eq!(u64::from_str_radix(&encode(&id)[..3], 16).unwrap(), 3581);
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(decode("abc").is_none(), "odd length");
        assert!(decode("zz").is_none(), "not hex");
        assert!(decode("0x12").is_none());
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode("AbCd").unwrap(), vec![0xab, 0xcd]);
        assert!(decode_array::<2>("abcd").is_some());
        assert!(decode_array::<3>("abcd").is_none());
    }
}
