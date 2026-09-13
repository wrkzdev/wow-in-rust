//! The binary archive — the consensus serialization.
//!
//! `specs/04-serialization.md` §1. This is the encoding for block and
//! transaction blobs, for everything that gets hashed, and for the blockchain
//! database.
//!
//! The format is entirely positional: no field names, no field tags, no length
//! framing around structs. Declaration order *is* the format. That plus the
//! context-dependent array lengths of `rctSigPrunable` is why `specs/04` §1.5
//! says not to force this into `serde`; the traits below take an explicit
//! context instead.

use crate::error::{Error, Result};
use crate::varint::{read_varint_bits, write_varint, MAX_VARINT_LEN_U64};

/// A cursor over a blob being parsed.
///
/// Tracks the read position so callers can record the byte offsets that
/// transaction hashing needs — `prefix_size` and `unprunable_size`
/// (`specs/05-blocks-and-transactions.md` §2.2, §3.2). Those offsets MUST come
/// from parsing; re-serializing to find them is both slower and wrong for a
/// non-canonically encoded blob.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Bytes consumed so far. This is the archive's `getpos()`.
    #[inline]
    pub fn pos(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The whole underlying blob, for slicing out hashed regions.
    #[inline]
    pub fn blob(&self) -> &'a [u8] {
        self.buf
    }

    /// Read exactly `n` bytes. Short input is an error, matching
    /// `serialize_blob`'s `good_ &= (len == actual)`.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::UnexpectedEof)?;
        if end > self.buf.len() {
            return Err(Error::UnexpectedEof);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("take returned N bytes"))
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// A raw little-endian integer. `FIELD(x)` on a POD (`specs/04` §1.2).
    pub fn read_u16_le(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    pub fn read_u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    pub fn read_u64_le(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    /// A `VARINT_FIELD` on a destination of `bits` width.
    ///
    /// Reproduces the archive's EOF tolerance: `serialize_uvarint` tests
    /// `0 <= read_varint(...)`, so a truncated varint is a successful read of
    /// the partial value and the cursor lands at the end of the blob. See
    /// [`crate::varint::read_varint_bits`].
    pub fn read_varint_bits(&mut self, bits: u32) -> Result<u64> {
        let r = read_varint_bits(&self.buf[self.pos..], bits)?;
        self.pos += r.len;
        Ok(r.value)
    }

    pub fn read_varint(&mut self) -> Result<u64> {
        self.read_varint_bits(64)
    }

    pub fn read_varint_u8(&mut self) -> Result<u8> {
        Ok(self.read_varint_bits(8)? as u8)
    }

    pub fn read_varint_u32(&mut self) -> Result<u32> {
        Ok(self.read_varint_bits(32)? as u32)
    }

    /// A length prefix for a container, bounded so a hostile blob cannot make
    /// us pre-allocate. `limit` is the structural cap from `specs/04` §1.6.
    pub fn read_len(&mut self, limit: usize, what: &'static str) -> Result<usize> {
        let n = self.read_varint()?;
        let n = usize::try_from(n).map_err(|_| Error::LimitExceeded(what))?;
        if n > limit {
            return Err(Error::LimitExceeded(what));
        }
        // A container of `n` elements needs at least `n` bytes on the wire, so
        // anything larger than the remaining input is a lie. This is the guard
        // that keeps `Vec::with_capacity` safe.
        if n > self.remaining() {
            return Err(Error::UnexpectedEof);
        }
        Ok(n)
    }

    /// `FIELD(x)` for a `std::string` / `blobdata`: `varint(len)` then bytes.
    pub fn read_bytes_prefixed(&mut self, limit: usize, what: &'static str) -> Result<&'a [u8]> {
        let n = self.read_len(limit, what)?;
        self.take(n)
    }
}

/// A growable output blob.
#[derive(Clone, Debug, Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { out: Vec::new() }
    }

    pub fn with_capacity(n: usize) -> Self {
        Writer {
            out: Vec::with_capacity(n),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.out.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.out
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.out
    }

    #[inline]
    pub fn write_bytes(&mut self, b: &[u8]) {
        self.out.extend_from_slice(b);
    }

    #[inline]
    pub fn write_u8(&mut self, v: u8) {
        self.out.push(v);
    }

    #[inline]
    pub fn write_u16_le(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn write_u32_le(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn write_u64_le(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn write_varint(&mut self, v: u64) {
        write_varint(&mut self.out, v);
    }

    /// `FIELD(x)` for a `std::string` / `blobdata`.
    pub fn write_bytes_prefixed(&mut self, b: &[u8]) {
        self.write_varint(b.len() as u64);
        self.write_bytes(b);
    }
}

/// Serialize into the binary archive.
pub trait BinSerialize {
    fn write(&self, w: &mut Writer);

    /// Convenience: serialize to a fresh `Vec`.
    fn to_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.into_vec()
    }
}

/// Deserialize from the binary archive.
///
/// `Ctx` carries the "length from context" information that `specs/04` §1.4
/// describes: `rctSigPrunable` cannot be parsed without `(type, inputs,
/// outputs, mixin)`, all of which come from the already-parsed prefix. For
/// types that need no context, `Ctx = ()`.
pub trait BinDeserialize: Sized {
    type Ctx;

    fn read(r: &mut Reader<'_>, ctx: Self::Ctx) -> Result<Self>;
}

/// Helper for the common `Ctx = ()` case.
pub fn from_blob<T: BinDeserialize<Ctx = ()>>(blob: &[u8]) -> Result<T> {
    let mut r = Reader::new(blob);
    T::read(&mut r, ())
}

/// The size a varint would occupy, without writing it.
pub const fn varint_size(v: u64) -> usize {
    crate::varint::varint_len(v)
}

/// Scratch buffer size for `write_varint_to`.
pub const VARINT_SCRATCH: usize = MAX_VARINT_LEN_U64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_tracks_position() {
        let blob = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut r = Reader::new(&blob);
        assert_eq!(r.pos(), 0);
        assert_eq!(r.read_u8().unwrap(), 1);
        assert_eq!(r.pos(), 1);
        assert_eq!(r.read_u32_le().unwrap(), u32::from_le_bytes([2, 3, 4, 5]));
        assert_eq!(r.pos(), 5);
        assert_eq!(r.remaining(), 4);
        assert_eq!(r.take(4).unwrap(), &[6, 7, 8, 9]);
        assert!(r.is_empty());
        assert!(matches!(r.read_u8(), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn take_rejects_overlong_requests_without_overflow() {
        let blob = [0u8; 4];
        let mut r = Reader::new(&blob);
        assert!(matches!(r.take(5), Err(Error::UnexpectedEof)));
        assert!(matches!(r.take(usize::MAX), Err(Error::UnexpectedEof)));
        // The cursor must not have moved on failure.
        assert_eq!(r.pos(), 0);
    }

    /// A length prefix must not be trusted to pre-allocate: `specs/04` §2.7 for
    /// epee, and the same reasoning for the consensus archive.
    #[test]
    fn read_len_is_bounded_by_the_remaining_input() {
        // varint 0xffffff... claiming ~2^35 elements, with 3 bytes left.
        let blob = [0xff, 0xff, 0xff, 0x7f, 0x01, 0x02, 0x03];
        let mut r = Reader::new(&blob);
        assert!(matches!(
            r.read_len(usize::MAX, "test"),
            Err(Error::UnexpectedEof)
        ));
    }

    #[test]
    fn read_len_enforces_the_structural_limit() {
        let blob = [0x05, 1, 2, 3, 4, 5];
        let mut r = Reader::new(&blob);
        assert!(matches!(
            r.read_len(4, "too many"),
            Err(Error::LimitExceeded("too many"))
        ));
    }

    #[test]
    fn writer_roundtrips_through_reader() {
        let mut w = Writer::new();
        w.write_u8(0xff);
        w.write_u16_le(0x1234);
        w.write_u32_le(0xdead_beef);
        w.write_u64_le(0x0123_4567_89ab_cdef);
        w.write_varint(300_000);
        w.write_bytes_prefixed(b"hello");
        let blob = w.into_vec();

        let mut r = Reader::new(&blob);
        assert_eq!(r.read_u8().unwrap(), 0xff);
        assert_eq!(r.read_u16_le().unwrap(), 0x1234);
        assert_eq!(r.read_u32_le().unwrap(), 0xdead_beef);
        assert_eq!(r.read_u64_le().unwrap(), 0x0123_4567_89ab_cdef);
        assert_eq!(r.read_varint().unwrap(), 300_000);
        assert_eq!(r.read_bytes_prefixed(16, "s").unwrap(), b"hello");
        assert!(r.is_empty());
    }

    /// The archive is EOF-tolerant for varints specifically, and only for
    /// varints: a short fixed-size read is still an error.
    #[test]
    fn varint_eof_tolerance_is_limited_to_varints() {
        let mut r = Reader::new(&[]);
        assert_eq!(r.read_varint().unwrap(), 0);
        let mut r = Reader::new(&[]);
        assert!(matches!(r.read_u8(), Err(Error::UnexpectedEof)));
        let mut r = Reader::new(&[1, 2, 3]);
        assert!(matches!(r.read_u32_le(), Err(Error::UnexpectedEof)));
    }
}
