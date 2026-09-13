//! The **epee** varint: `(value << 2) | width_code`, little-endian.
//!
//! `specs/04-serialization.md` §2.1. Completely different from the consensus
//! varint in [`crate::varint`]; the two are never interchangeable.
//!
//! | Low 2 bits | Total size | Value range |
//! |---|---|---|
//! | `00` | 1 byte  | 0 – 63 |
//! | `01` | 2 bytes | 64 – 16,383 |
//! | `10` | 4 bytes | 16,384 – 1,073,741,823 |
//! | `11` | 8 bytes | 1,073,741,824 – 4,611,686,018,427,387,903 |

use crate::error::{Error, Result};

/// The largest value an epee varint can carry: `2^62 - 1`.
pub const EPEE_VARINT_MAX: u64 = (1u64 << 62) - 1;

const MARK_BYTE: u8 = 0;
const MARK_WORD: u8 = 1;
const MARK_DWORD: u8 = 2;
const MARK_INT64: u8 = 3;

/// Write `v` as an epee varint. Values above [`EPEE_VARINT_MAX`] are an error
/// rather than a silent truncation.
pub fn write_epee_varint(out: &mut Vec<u8>, v: u64) -> Result<()> {
    if v <= 63 {
        out.push(((v as u8) << 2) | MARK_BYTE);
    } else if v <= 16_383 {
        out.extend_from_slice(&(((v as u16) << 2) | MARK_WORD as u16).to_le_bytes());
    } else if v <= 1_073_741_823 {
        out.extend_from_slice(&(((v as u32) << 2) | MARK_DWORD as u32).to_le_bytes());
    } else if v <= EPEE_VARINT_MAX {
        out.extend_from_slice(&((v << 2) | MARK_INT64 as u64).to_le_bytes());
    } else {
        return Err(Error::LimitExceeded("epee varint > 2^62 - 1"));
    }
    Ok(())
}

/// The number of bytes `v` encodes to.
pub fn epee_varint_len(v: u64) -> usize {
    if v <= 63 {
        1
    } else if v <= 16_383 {
        2
    } else if v <= 1_073_741_823 {
        4
    } else {
        8
    }
}

/// Read an epee varint from the front of `input`, returning the value and the
/// number of bytes consumed.
pub fn read_epee_varint(input: &[u8]) -> Result<(u64, usize)> {
    let first = *input.first().ok_or(Error::UnexpectedEof)?;
    let (len, raw) = match first & 0x03 {
        MARK_BYTE => (1usize, u64::from(first)),
        MARK_WORD => {
            let b = input.get(..2).ok_or(Error::UnexpectedEof)?;
            (2, u64::from(u16::from_le_bytes(b.try_into().unwrap())))
        }
        MARK_DWORD => {
            let b = input.get(..4).ok_or(Error::UnexpectedEof)?;
            (4, u64::from(u32::from_le_bytes(b.try_into().unwrap())))
        }
        _ => {
            let b = input.get(..8).ok_or(Error::UnexpectedEof)?;
            (8, u64::from_le_bytes(b.try_into().unwrap()))
        }
    };
    Ok((raw >> 2, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: u64) -> Vec<u8> {
        let mut o = Vec::new();
        write_epee_varint(&mut o, v).unwrap();
        o
    }

    /// The worked examples from `docs/PORTABLE_STORAGE.md`, reproduced in
    /// `specs/04-serialization.md` §2.1.
    #[test]
    fn documented_examples() {
        assert_eq!(enc(0), vec![0x00]);
        assert_eq!(enc(7), vec![0x1c]);
        assert_eq!(enc(101), vec![0x95, 0x01]);
        assert_eq!(enc(17_000), vec![0xa2, 0x09, 0x01, 0x00]);
        assert_eq!(
            enc(7_942_319_744),
            vec![0x03, 0xba, 0x98, 0x65, 0x07, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn width_boundaries() {
        assert_eq!(enc(63).len(), 1);
        assert_eq!(enc(64).len(), 2);
        assert_eq!(enc(16_383).len(), 2);
        assert_eq!(enc(16_384).len(), 4);
        assert_eq!(enc(1_073_741_823).len(), 4);
        assert_eq!(enc(1_073_741_824).len(), 8);
        assert_eq!(enc(EPEE_VARINT_MAX).len(), 8);
    }

    #[test]
    fn roundtrips() {
        let mut vals: Vec<u64> = vec![0, 1, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824];
        vals.push(EPEE_VARINT_MAX);
        for shift in 0..62 {
            vals.push(1u64 << shift);
        }
        for v in vals {
            let b = enc(v);
            assert_eq!(b.len(), epee_varint_len(v));
            assert_eq!(read_epee_varint(&b).unwrap(), (v, b.len()));
        }
    }

    #[test]
    fn rejects_out_of_range() {
        let mut o = Vec::new();
        assert!(write_epee_varint(&mut o, EPEE_VARINT_MAX + 1).is_err());
        assert!(write_epee_varint(&mut o, u64::MAX).is_err());
    }

    #[test]
    fn rejects_truncation_without_panicking() {
        assert!(matches!(read_epee_varint(&[]), Err(Error::UnexpectedEof)));
        assert!(matches!(
            read_epee_varint(&[0x01]),
            Err(Error::UnexpectedEof)
        ));
        assert!(matches!(
            read_epee_varint(&[0x02, 0, 0]),
            Err(Error::UnexpectedEof)
        ));
        assert!(matches!(
            read_epee_varint(&[0x03, 0, 0, 0, 0, 0, 0]),
            Err(Error::UnexpectedEof)
        ));
    }

    /// The epee varint and the consensus varint must never be confused: they
    /// disagree for every value above zero.
    #[test]
    fn is_not_the_consensus_varint() {
        for v in [1u64, 7, 63, 64, 127, 128, 300] {
            let mut consensus = Vec::new();
            crate::varint::write_varint(&mut consensus, v);
            assert_ne!(enc(v), consensus, "encodings coincide for {v}");
        }
    }
}
