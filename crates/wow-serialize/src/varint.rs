//! The **consensus** varint: CryptoNote/protobuf-style base-128.
//!
//! `specs/04-serialization.md` §1.1. This is *not* the epee varint of §2.1 —
//! confusing the two is the most common interop failure, so the two live in
//! separate modules and neither re-exports the other.
//!
//! Strictness on read is consensus-critical: block and tx blobs are hashed, so
//! an over-long encoding of a small value would let semantically identical data
//! produce two different hashes. `tools::read_varint` in `src/common/varint.h`
//! rejects both over-long encodings and overflow, and is reproduced here
//! including its **bit-width dependence** and its **tolerance of a truncated
//! encoding** — see [`read_varint_bits`].

use crate::error::{Error, Result};

/// Maximum bytes a `u64` varint can occupy: `ceil(64 / 7)`.
pub const MAX_VARINT_LEN_U64: usize = 10;

/// The number of bytes `v` encodes to. `tools::get_varint_byte_size`.
pub const fn varint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Write `v` as a base-128 varint, appending to `out`. `tools::write_varint`.
pub fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Write `v` into a fixed buffer, returning the number of bytes written.
///
/// Used where the C builds a small stack buffer, e.g. `derivation_to_scalar`
/// and `derive_view_tag` (`specs/02-crypto.md` §3.4, §3.7).
pub fn write_varint_to(buf: &mut [u8; MAX_VARINT_LEN_U64], mut v: u64) -> usize {
    let mut n = 0;
    while v >= 0x80 {
        buf[n] = (v as u8 & 0x7f) | 0x80;
        v >>= 7;
        n += 1;
    }
    buf[n] = v as u8;
    n + 1
}

/// `tools::read_varint<bits>` — reproduced **exactly**, quirks included.
///
/// `bits` is the bit width of the destination type, because the C templates on
/// `std::numeric_limits<T>::digits`. It is load-bearing: `major_version` is a
/// `uint8_t`, so its varint overflows at a different point than a `u64` field's
/// does. Passing the wrong width would accept blobs the reference rejects.
///
/// Rejects:
/// - **overflow** for the destination width (`EVARINT_OVERFLOW`),
/// - a **non-canonical** encoding — a zero byte at any position after the
///   first, which is how the C spells "over-long" (`EVARINT_REPRESENT`). This
///   catches `0x80 0x00` for zero.
///
/// Does **not** reject a truncated encoding. The C returns the number of bytes
/// consumed, which the archive tests with `0 <= read`, so running out of input
/// mid-varint is *success* with the partially accumulated value — and reading a
/// varint from an empty buffer yields `0`. `is_truncated` in the result says
/// whether that path was taken, so callers that need strictness (epee lengths,
/// fuzz invariants) can use [`read_varint`] instead.
///
/// This tolerance is only reachable when a varint is the final field of a blob,
/// in which case it decodes an alternative, non-canonical encoding of an
/// otherwise well-formed structure. Reproducing it keeps a peer that sends such
/// a blob from being treated differently than the reference node treats it.
pub fn read_varint_bits(input: &[u8], bits: u32) -> Result<VarintRead> {
    debug_assert!(bits > 0 && bits <= 64);
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut read: usize = 0;

    loop {
        let Some(&byte) = input.get(read) else {
            // `if (first == last) return read;` -- not an error in the C.
            return Ok(VarintRead {
                value,
                len: read,
                truncated: true,
            });
        };
        read += 1;

        // `if (shift + 7 >= bits && byte >= 1 << (bits - shift))`
        if shift + 7 >= bits {
            if shift >= bits {
                return Err(Error::VarintOverflow);
            }
            if u32::from(byte) >= 1u32 << (bits - shift) {
                return Err(Error::VarintOverflow);
            }
        }
        // `if (byte == 0 && shift != 0)`
        if byte == 0 && shift != 0 {
            return Err(Error::VarintNonCanonical);
        }

        value |= u64::from(byte & 0x7f) << shift;

        if byte & 0x80 == 0 {
            return Ok(VarintRead {
                value,
                len: read,
                truncated: false,
            });
        }
        shift += 7;
    }
}

/// The outcome of [`read_varint_bits`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VarintRead {
    /// The decoded value. Partial if `truncated`.
    pub value: u64,
    /// Bytes consumed.
    pub len: usize,
    /// True if the input ended mid-varint. The C calls this success.
    pub truncated: bool,
}

/// Read a `u64` varint, treating truncation as an error.
///
/// Use this everywhere except inside the binary archive, which must reproduce
/// the reference's EOF tolerance (see [`read_varint_bits`]).
pub fn read_varint(input: &[u8]) -> Result<(u64, usize)> {
    let r = read_varint_bits(input, 64)?;
    if r.truncated {
        return Err(Error::UnexpectedEof);
    }
    Ok((r.value, r.len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: u64) {
        let mut out = Vec::new();
        write_varint(&mut out, v);
        assert_eq!(out.len(), varint_len(v), "varint_len disagrees for {v}");
        let (got, n) = read_varint(&out).unwrap();
        assert_eq!(got, v);
        assert_eq!(n, out.len());

        let mut buf = [0u8; MAX_VARINT_LEN_U64];
        let n2 = write_varint_to(&mut buf, v);
        assert_eq!(&buf[..n2], &out[..]);
    }

    #[test]
    fn roundtrips() {
        for v in [
            0u64,
            1,
            0x7f,
            0x80,
            0x3fff,
            0x4000,
            255,
            256,
            300_000,
            u64::MAX,
        ] {
            roundtrip(v);
        }
        for shift in 0..64 {
            roundtrip(1u64 << shift);
            roundtrip((1u64 << shift).wrapping_sub(1));
        }
    }

    #[test]
    fn known_encodings() {
        let enc = |v: u64| {
            let mut o = Vec::new();
            write_varint(&mut o, v);
            o
        };
        assert_eq!(enc(0), vec![0x00]);
        assert_eq!(enc(127), vec![0x7f]);
        assert_eq!(enc(128), vec![0x80, 0x01]);
        assert_eq!(enc(16384), vec![0x80, 0x80, 0x01]);
        assert_eq!(
            enc(u64::MAX),
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
    }

    /// `0x80 0x00` and `0x00` both denote zero, but only the short form is
    /// legal — otherwise one block would have two valid blobs, and therefore
    /// one hash for two encodings.
    #[test]
    fn rejects_non_canonical_encodings() {
        for enc in [
            &[0x80u8, 0x00][..],
            &[0x81, 0x80, 0x00][..],
            &[0xff, 0x00][..],
        ] {
            assert!(
                matches!(read_varint(enc), Err(Error::VarintNonCanonical)),
                "{enc:?} should be non-canonical"
            );
        }
        assert_eq!(read_varint(&[0x00]).unwrap(), (0, 1));
        assert_eq!(read_varint(&[0x81, 0x01]).unwrap(), (129, 2));
    }

    #[test]
    fn rejects_overflow_at_the_destination_width() {
        // u64: the 10th byte may only be 0x01.
        let v = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert!(matches!(read_varint(&v), Err(Error::VarintOverflow)));
        let ok = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(read_varint(&ok).unwrap(), (u64::MAX, 10));
    }

    /// The width really is load-bearing: `major_version` is a `uint8_t`, so the
    /// same bytes that are a fine `u64` varint are an overflow for it.
    #[test]
    fn width_changes_the_overflow_point() {
        let bytes = [0x80u8, 0x02]; // = 256
        assert_eq!(read_varint_bits(&bytes, 64).unwrap().value, 256);
        assert!(matches!(
            read_varint_bits(&bytes, 8),
            Err(Error::VarintOverflow)
        ));
        // 255 is the largest u8, encoded in two bytes.
        let m = [0xffu8, 0x01];
        assert_eq!(read_varint_bits(&m, 8).unwrap().value, 255);
    }

    /// `specs/06` §9 territory: the reference treats a truncated varint as a
    /// successful read of the partial value. Reproduce it rather than "fixing"
    /// it, or a blob the reference node parses would be rejected here.
    #[test]
    fn truncation_is_success_in_the_reference() {
        let r = read_varint_bits(&[], 64).unwrap();
        assert_eq!((r.value, r.len, r.truncated), (0, 0, true));

        let r = read_varint_bits(&[0x80], 64).unwrap();
        assert_eq!((r.value, r.len, r.truncated), (0, 1, true));

        let r = read_varint_bits(&[0xff, 0x81], 64).unwrap();
        assert_eq!((r.value, r.len, r.truncated), (0xff, 2, true));

        // ...but the strict wrapper still errors, for callers that need it.
        assert!(matches!(read_varint(&[0x80]), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // specs/15 §4.4: a parse failure must be a Result, never a panic.
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                for bits in [8u32, 16, 32, 64] {
                    let _ = read_varint_bits(&[a as u8, b as u8], bits);
                    let _ = read_varint_bits(&[a as u8, b as u8, 0xff, 0x7f], bits);
                }
            }
        }
        let all_cont = [0x80u8; 16];
        for bits in [8u32, 16, 32, 64] {
            let _ = read_varint_bits(&all_cont, bits);
        }
    }
}
