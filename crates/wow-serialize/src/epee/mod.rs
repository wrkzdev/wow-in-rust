//! Epee portable storage — the P2P and `.bin` RPC encoding.
//!
//! `specs/04-serialization.md` §2. A self-describing name/value tree used for
//! every Levin payload, the binary RPC endpoints, and `p2pstate.bin`.
//!
//! This is the **highest-risk parser in the project** — it faces the network
//! directly, before any authentication (`specs/15` §4.4). Accordingly:
//!
//! * every length is validated against the remaining input before allocating,
//! * nesting is capped at [`RECURSION_LIMIT`],
//! * nothing panics: every failure is an [`Error`].

pub mod varint;

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use varint::{epee_varint_len, read_epee_varint, write_epee_varint};

/// `PORTABLE_STORAGE_SIGNATUREA` — `u32` LE `0x01011101`.
pub const SIGNATURE_A: u32 = 0x0101_1101;
/// `PORTABLE_STORAGE_SIGNATUREB` — `u32` LE `0x01020101`.
pub const SIGNATURE_B: u32 = 0x0102_0101;
/// `PORTABLE_STORAGE_FORMAT_VER`.
pub const FORMAT_VERSION: u8 = 1;

/// The 9-byte header every portable-storage blob begins with
/// (`specs/04` §2.2).
pub const HEADER: [u8; 9] = [0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01];

/// `EPEE_PORTABLE_STORAGE_RECURSION_LIMIT_INTERNAL`.
pub const RECURSION_LIMIT: usize = 100;

/// `MAX_STRING_LEN_POSSIBLE`.
pub const MAX_STRING_LEN: usize = 2_000_000_000;

/// Entry type bytes (`specs/04` §2.5).
pub mod ty {
    pub const INT64: u8 = 1;
    pub const INT32: u8 = 2;
    pub const INT16: u8 = 3;
    pub const INT8: u8 = 4;
    pub const UINT64: u8 = 5;
    pub const UINT32: u8 = 6;
    pub const UINT16: u8 = 7;
    pub const UINT8: u8 = 8;
    pub const DOUBLE: u8 = 9;
    pub const STRING: u8 = 10;
    pub const BOOL: u8 = 11;
    pub const OBJECT: u8 = 12;
    pub const ARRAY: u8 = 13;
    /// `SERIALIZE_FLAG_ARRAY`.
    pub const ARRAY_FLAG: u8 = 0x80;
}

/// A section: an ordered map of entry name to value.
///
/// Ordering is `BTreeMap` (lexicographic by name) rather than insertion order.
/// That is deliberate and safe: the reference reader looks entries up by name
/// and skips unknown ones (`specs/04` §2.7), so entry order carries no meaning.
/// A stable order also makes a re-encoded message byte-reproducible, which the
/// round-trip tests rely on.
pub type Section = BTreeMap<String, Value>;

/// A portable-storage value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    I64(i64),
    I32(i32),
    I16(i16),
    I8(i8),
    U64(u64),
    U32(u32),
    U16(u16),
    U8(u8),
    Double(f64),
    /// A STRING. **Hashes, keys and arbitrary binary blobs are all carried as
    /// STRING** (`specs/04` §2.5), so this is bytes, not UTF-8.
    String(Vec<u8>),
    Bool(bool),
    Object(Section),
    /// An array: `type | 0x80`, then `varint(count)`, then the values with no
    /// per-element type byte.
    Array(Array),
}

/// A homogeneous array. The element type is stored once, so an empty array
/// still needs to remember what it is empty *of*.
#[derive(Clone, Debug, PartialEq)]
pub struct Array {
    pub elem_type: u8,
    pub items: Vec<Value>,
}

impl Value {
    /// The type byte this value serializes as.
    pub fn type_byte(&self) -> u8 {
        match self {
            Value::I64(_) => ty::INT64,
            Value::I32(_) => ty::INT32,
            Value::I16(_) => ty::INT16,
            Value::I8(_) => ty::INT8,
            Value::U64(_) => ty::UINT64,
            Value::U32(_) => ty::UINT32,
            Value::U16(_) => ty::UINT16,
            Value::U8(_) => ty::UINT8,
            Value::Double(_) => ty::DOUBLE,
            Value::String(_) => ty::STRING,
            Value::Bool(_) => ty::BOOL,
            Value::Object(_) => ty::OBJECT,
            Value::Array(a) => a.elem_type,
        }
    }

    /// A STRING's bytes, if this is one.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::String(b) => Some(b),
            _ => None,
        }
    }

    /// Widen any unsigned integer value to `u64`.
    ///
    /// Useful because `KV_SERIALIZE` picks the narrowest type that fits, so a
    /// peer may legitimately send `UINT8` where the struct declares `uint64_t`.
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Value::U64(v) => Some(v),
            Value::U32(v) => Some(u64::from(v)),
            Value::U16(v) => Some(u64::from(v)),
            Value::U8(v) => Some(u64::from(v)),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match *self {
            Value::Bool(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Section> {
        match self {
            Value::Object(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Array> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Split a `KV_SERIALIZE_CONTAINER_POD_AS_BLOB` STRING into fixed-size
    /// elements.
    ///
    /// `specs/04` §2.6: a container of PODs travels as **one** STRING holding
    /// the concatenated elements, so `NOTIFY_REQUEST_CHAIN.block_ids` arrives
    /// as `32 * n` bytes, not as an array of 32-byte strings. The length MUST
    /// be a multiple of the element size.
    pub fn as_pod_container(&self, elem: usize) -> Result<Vec<&[u8]>> {
        debug_assert!(elem > 0);
        let b = self.as_bytes().ok_or(Error::TypeMismatch {
            field: "<pod container>",
            expected: "string",
        })?;
        if b.len() % elem != 0 {
            return Err(Error::BadPodBlobLength { len: b.len(), elem });
        }
        Ok(b.chunks_exact(elem).collect())
    }
}

/// Build a `CONTAINER_POD_AS_BLOB` STRING from fixed-size elements.
pub fn pod_container<'a, I: IntoIterator<Item = &'a [u8]>>(items: I) -> Value {
    let mut out = Vec::new();
    for i in items {
        out.extend_from_slice(i);
    }
    Value::String(out)
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

struct EpeeReader<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> EpeeReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::UnexpectedEof)?;
        if end > self.buf.len() {
            return Err(Error::UnexpectedEof);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn varint(&mut self) -> Result<u64> {
        let (v, n) = read_epee_varint(&self.buf[self.pos..])?;
        self.pos += n;
        Ok(v)
    }

    /// A count that will drive an allocation. Bounded by the bytes actually
    /// left, since every element occupies at least one byte on the wire.
    fn count(&mut self) -> Result<usize> {
        let n = self.varint()?;
        let n = usize::try_from(n).map_err(|_| Error::LimitExceeded("epee count"))?;
        if n > self.buf.len() - self.pos {
            return Err(Error::UnexpectedEof);
        }
        Ok(n)
    }

    fn section(&mut self) -> Result<Section> {
        self.depth += 1;
        if self.depth > RECURSION_LIMIT {
            return Err(Error::RecursionLimit);
        }
        let count = self.count()?;
        let mut out = Section::new();
        for _ in 0..count {
            let name_len = self.u8()? as usize;
            let name = self.take(name_len)?;
            let name = String::from_utf8_lossy(name).into_owned();
            let value = self.entry_value()?;
            // A duplicate name keeps the last occurrence, as a map assignment
            // in the reference reader would.
            out.insert(name, value);
        }
        self.depth -= 1;
        Ok(out)
    }

    fn entry_value(&mut self) -> Result<Value> {
        let tag = self.u8()?;
        if tag & ty::ARRAY_FLAG != 0 {
            let elem_type = tag & !ty::ARRAY_FLAG;
            let count = self.count()?;
            let mut items = Vec::with_capacity(count.min(4096));
            for _ in 0..count {
                items.push(self.scalar(elem_type)?);
            }
            Ok(Value::Array(Array { elem_type, items }))
        } else {
            self.scalar(tag)
        }
    }

    fn scalar(&mut self, tag: u8) -> Result<Value> {
        Ok(match tag {
            ty::INT64 => Value::I64(i64::from_le_bytes(self.take(8)?.try_into().unwrap())),
            ty::INT32 => Value::I32(i32::from_le_bytes(self.take(4)?.try_into().unwrap())),
            ty::INT16 => Value::I16(i16::from_le_bytes(self.take(2)?.try_into().unwrap())),
            ty::INT8 => Value::I8(self.take(1)?[0] as i8),
            ty::UINT64 => Value::U64(u64::from_le_bytes(self.take(8)?.try_into().unwrap())),
            ty::UINT32 => Value::U32(u32::from_le_bytes(self.take(4)?.try_into().unwrap())),
            ty::UINT16 => Value::U16(u16::from_le_bytes(self.take(2)?.try_into().unwrap())),
            ty::UINT8 => Value::U8(self.take(1)?[0]),
            ty::DOUBLE => Value::Double(f64::from_le_bytes(self.take(8)?.try_into().unwrap())),
            ty::BOOL => Value::Bool(self.take(1)?[0] != 0),
            ty::STRING => {
                let n = self.varint()?;
                let n = usize::try_from(n).map_err(|_| Error::LimitExceeded("epee string"))?;
                if n > MAX_STRING_LEN {
                    return Err(Error::LimitExceeded("epee string > MAX_STRING_LEN"));
                }
                Value::String(self.take(n)?.to_vec())
            }
            ty::OBJECT => Value::Object(self.section()?),
            // `specs/04` §2.5: ARRAY (13) as a standalone type is not used by
            // Monero/Wownero. Reject rather than guess at a layout.
            ty::ARRAY => return Err(Error::UnknownEpeeType(ty::ARRAY)),
            other => return Err(Error::UnknownEpeeType(other)),
        })
    }
}

/// Parse a portable-storage blob, header included.
pub fn from_bytes(blob: &[u8]) -> Result<Section> {
    let head = blob.get(..9).ok_or(Error::UnexpectedEof)?;
    if head != HEADER {
        return Err(Error::BadEpeeSignature);
    }
    let mut r = EpeeReader {
        buf: blob,
        pos: 9,
        depth: 0,
    };
    r.section()
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Serialize a section into a portable-storage blob, header included.
pub fn to_bytes(section: &Section) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&HEADER);
    write_section(&mut out, section)?;
    Ok(out)
}

fn write_section(out: &mut Vec<u8>, s: &Section) -> Result<()> {
    write_epee_varint(out, s.len() as u64)?;
    for (name, value) in s {
        let nb = name.as_bytes();
        if nb.len() > 255 {
            return Err(Error::NameTooLong);
        }
        out.push(nb.len() as u8);
        out.extend_from_slice(nb);
        write_entry_value(out, value)?;
    }
    Ok(())
}

fn write_entry_value(out: &mut Vec<u8>, v: &Value) -> Result<()> {
    match v {
        Value::Array(a) => {
            out.push(a.elem_type | ty::ARRAY_FLAG);
            write_epee_varint(out, a.items.len() as u64)?;
            for item in &a.items {
                if item.type_byte() != a.elem_type {
                    return Err(Error::InvalidValue("heterogeneous epee array"));
                }
                write_scalar(out, item)?;
            }
            Ok(())
        }
        other => {
            out.push(other.type_byte());
            write_scalar(out, other)
        }
    }
}

fn write_scalar(out: &mut Vec<u8>, v: &Value) -> Result<()> {
    match v {
        Value::I64(x) => out.extend_from_slice(&x.to_le_bytes()),
        Value::I32(x) => out.extend_from_slice(&x.to_le_bytes()),
        Value::I16(x) => out.extend_from_slice(&x.to_le_bytes()),
        Value::I8(x) => out.push(*x as u8),
        Value::U64(x) => out.extend_from_slice(&x.to_le_bytes()),
        Value::U32(x) => out.extend_from_slice(&x.to_le_bytes()),
        Value::U16(x) => out.extend_from_slice(&x.to_le_bytes()),
        Value::U8(x) => out.push(*x),
        Value::Double(x) => out.extend_from_slice(&x.to_le_bytes()),
        Value::Bool(x) => out.push(u8::from(*x)),
        Value::String(b) => {
            if b.len() > MAX_STRING_LEN {
                return Err(Error::LimitExceeded("epee string > MAX_STRING_LEN"));
            }
            write_epee_varint(out, b.len() as u64)?;
            out.extend_from_slice(b);
        }
        Value::Object(s) => write_section(out, s)?,
        Value::Array(_) => {
            // `specs/04` §2.5: nested arrays are impossible directly; the C
            // wraps an inner array in an object.
            return Err(Error::InvalidValue("directly nested epee array"));
        }
    }
    Ok(())
}

/// The encoded size of a section, without encoding it. Useful for Levin's
/// length field.
pub fn encoded_len(s: &Section) -> Result<usize> {
    let mut n = epee_varint_len(s.len() as u64);
    for (name, value) in s {
        if name.len() > 255 {
            return Err(Error::NameTooLong);
        }
        n += 1 + name.len() + value_len(value)?;
    }
    Ok(n)
}

fn value_len(v: &Value) -> Result<usize> {
    Ok(match v {
        Value::Array(a) => {
            let mut n = 1 + epee_varint_len(a.items.len() as u64);
            for i in &a.items {
                n += scalar_len(i)?;
            }
            n
        }
        other => 1 + scalar_len(other)?,
    })
}

fn scalar_len(v: &Value) -> Result<usize> {
    Ok(match v {
        Value::I64(_) | Value::U64(_) | Value::Double(_) => 8,
        Value::I32(_) | Value::U32(_) => 4,
        Value::I16(_) | Value::U16(_) => 2,
        Value::I8(_) | Value::U8(_) | Value::Bool(_) => 1,
        Value::String(b) => epee_varint_len(b.len() as u64) + b.len(),
        Value::Object(s) => encoded_len(s)?,
        Value::Array(_) => return Err(Error::InvalidValue("directly nested epee array")),
    })
}

// ---------------------------------------------------------------------------
// Field access with `KV_SERIALIZE` semantics
// ---------------------------------------------------------------------------

/// Helpers implementing the `KV_SERIALIZE*` read semantics of `specs/04` §2.6.
pub trait SectionExt {
    /// A required field. Absent is an error.
    fn req(&self, name: &'static str) -> Result<&Value>;
    /// `KV_SERIALIZE_OPT(x, default)`: absent means the default.
    fn opt_u64(&self, name: &'static str, default: u64) -> Result<u64>;
    fn opt_bool(&self, name: &'static str, default: bool) -> Result<bool>;
    /// `KV_SERIALIZE_VAL_POD_AS_BLOB`: a STRING of exactly `N` bytes.
    fn pod<const N: usize>(&self, name: &'static str) -> Result<[u8; N]>;
    /// A required unsigned integer, accepting any narrower unsigned type.
    fn u64(&self, name: &'static str) -> Result<u64>;
}

impl SectionExt for Section {
    fn req(&self, name: &'static str) -> Result<&Value> {
        self.get(name).ok_or(Error::MissingField(name))
    }

    fn opt_u64(&self, name: &'static str, default: u64) -> Result<u64> {
        match self.get(name) {
            None => Ok(default),
            Some(v) => v.as_u64().ok_or(Error::TypeMismatch {
                field: name,
                expected: "unsigned integer",
            }),
        }
    }

    fn opt_bool(&self, name: &'static str, default: bool) -> Result<bool> {
        match self.get(name) {
            None => Ok(default),
            Some(v) => v.as_bool().ok_or(Error::TypeMismatch {
                field: name,
                expected: "bool",
            }),
        }
    }

    fn pod<const N: usize>(&self, name: &'static str) -> Result<[u8; N]> {
        let b = self.req(name)?.as_bytes().ok_or(Error::TypeMismatch {
            field: name,
            expected: "string",
        })?;
        b.try_into().map_err(|_| Error::BadPodBlobLength {
            len: b.len(),
            elem: N,
        })
    }

    fn u64(&self, name: &'static str) -> Result<u64> {
        self.req(name)?.as_u64().ok_or(Error::TypeMismatch {
            field: name,
            expected: "unsigned integer",
        })
    }
}

#[cfg(test)]
mod tests;
