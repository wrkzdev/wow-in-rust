//! Serialization errors.
//!
//! Every parse failure in this crate is a `Result` error, never a panic:
//! `specs/15-testing-and-conformance.md` §4.4 — "a panic in a P2P message
//! parser is a remote crash".

use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input ended before the field was complete.
    UnexpectedEof,
    /// A varint whose value does not fit its destination type.
    VarintOverflow,
    /// A varint encoded in more bytes than necessary (`specs/04` §1.1).
    VarintNonCanonical,
    /// A varint longer than `ceil(bits / 7)` bytes.
    VarintTooLong,
    /// A variant tag that is not in the table of `specs/04` §1.3.
    UnknownVariantTag(u8),
    /// A structural limit from `specs/04` §1.6 was exceeded.
    LimitExceeded(&'static str),
    /// A field's value is not one this format admits.
    InvalidValue(&'static str),
    /// Epee: the 9-byte header did not match `specs/04` §2.2.
    BadEpeeSignature,
    /// Epee: an unknown type byte.
    UnknownEpeeType(u8),
    /// Epee: nesting deeper than the configured limit.
    RecursionLimit,
    /// Epee: a required (non-`OPT`) entry was absent.
    MissingField(&'static str),
    /// Epee: an entry had a type the reader did not expect.
    TypeMismatch {
        field: &'static str,
        expected: &'static str,
    },
    /// A `CONTAINER_POD_AS_BLOB` string whose length is not a multiple of the
    /// element size (`specs/04` §2.6).
    BadPodBlobLength { len: usize, elem: usize },
    /// A name longer than the one-byte length field allows.
    NameTooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEof => write!(f, "unexpected end of input"),
            Error::VarintOverflow => write!(f, "varint overflows its destination type"),
            Error::VarintNonCanonical => write!(f, "non-canonical varint encoding"),
            Error::VarintTooLong => write!(f, "varint longer than the destination type allows"),
            Error::UnknownVariantTag(t) => write!(f, "unknown variant tag {t:#04x}"),
            Error::LimitExceeded(w) => write!(f, "limit exceeded: {w}"),
            Error::InvalidValue(w) => write!(f, "invalid value: {w}"),
            Error::BadEpeeSignature => write!(f, "bad portable-storage signature"),
            Error::UnknownEpeeType(t) => write!(f, "unknown portable-storage type {t:#04x}"),
            Error::RecursionLimit => write!(f, "portable-storage nesting too deep"),
            Error::MissingField(n) => write!(f, "missing required entry {n:?}"),
            Error::TypeMismatch { field, expected } => {
                write!(f, "entry {field:?} is not a {expected}")
            }
            Error::BadPodBlobLength { len, elem } => {
                write!(f, "blob of {len} bytes is not a multiple of {elem}")
            }
            Error::NameTooLong => write!(f, "entry name longer than 255 bytes"),
        }
    }
}

impl std::error::Error for Error {}
