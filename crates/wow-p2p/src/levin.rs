//! Levin framing — the 33-byte header every P2P message carries.
//!
//! `specs/08-p2p.md` §1, `contrib/epee/include/net/levin_base.h`.
//!
//! # This code faces the network
//!
//! `specs/15` §4.4 sets one invariant above the rest: **never panic.** A parse
//! failure is a `Result`, always. A panic in a P2P message parser is a remote
//! crash, and this is the first thing an unauthenticated peer reaches.
//!
//! Two consequences visible throughout:
//!
//! * nothing is indexed without a length check, and no arithmetic on a
//!   peer-supplied length can overflow;
//! * the declared body length is checked against a limit **before** any
//!   allocation. `specs/08` §1 is emphatic that there are *two* limits and that
//!   the smaller one applies before the handshake — "the pre-handshake limit is
//!   what stops an unauthenticated peer from making you allocate 100 MB".

use std::fmt;

/// `LEVIN_SIGNATURE`, as the eight bytes appear on the wire.
///
/// `specs/08` §1: "Copy the byte sequence, do not re-derive it." It is the
/// little-endian encoding of `0x01011101` then `0x01010101`, which is *not*
/// what a casual reading of the constant suggests.
pub const SIGNATURE: [u8; 8] = [0x01, 0x21, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01];

/// `sizeof(bucket_head2)` — packed, so exactly 33 bytes.
pub const HEADER_LEN: usize = 33;

/// `LEVIN_PROTOCOL_VER_1`.
pub const PROTOCOL_VERSION: u32 = 1;

/// `LEVIN_INITIAL_MAX_PACKET_SIZE` — 256 KiB, **before** the handshake
/// completes.
pub const INITIAL_MAX_PACKET_SIZE: u64 = 256 * 1024;

/// `LEVIN_DEFAULT_MAX_PACKET_SIZE` — 100 MB, after the handshake.
pub const DEFAULT_MAX_PACKET_SIZE: u64 = 100_000_000;

/// `P2P_DEFAULT_PACKET_MAX_SIZE` — the value advertised in `network_config`.
///
/// A **separate** number from the two limits above, and not the one to enforce
/// framing with (`specs/08` §1).
pub const ADVERTISED_PACKET_MAX_SIZE: u64 = 50_000_000;

/// Levin header flags (`specs/08` §1).
pub mod flags {
    /// `LEVIN_PACKET_REQUEST`.
    pub const REQUEST: u32 = 0x1;
    /// `LEVIN_PACKET_RESPONSE`.
    pub const RESPONSE: u32 = 0x2;
    /// `LEVIN_PACKET_BEGIN` — first fragment.
    pub const BEGIN: u32 = 0x4;
    /// `LEVIN_PACKET_END` — last fragment.
    pub const END: u32 = 0x8;
}

/// What a header's flags and `expect_response` say it is (`specs/08` §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `Q`, no response expected.
    Notification,
    /// `Q`, response expected.
    Request,
    /// `S`.
    Response,
    /// `B` alone — the first piece of a fragmented message.
    FragmentBegin,
    /// No flags — a middle piece.
    FragmentMiddle,
    /// `E` alone — the last piece.
    FragmentEnd,
    /// `B | E` — a dummy, which **must be accepted and discarded**.
    Dummy,
    /// A flag combination the table does not name.
    Unknown,
}

/// The Levin command ids (`specs/08` §2).
pub mod command {
    pub const HANDSHAKE: u32 = 1001;
    pub const TIMED_SYNC: u32 = 1002;
    pub const PING: u32 = 1003;
    pub const REQUEST_SUPPORT_FLAGS: u32 = 1007;

    pub const NEW_BLOCK: u32 = 2001;
    pub const NEW_TRANSACTIONS: u32 = 2002;
    pub const REQUEST_GET_OBJECTS: u32 = 2003;
    pub const RESPONSE_GET_OBJECTS: u32 = 2004;
    pub const REQUEST_CHAIN: u32 = 2006;
    pub const RESPONSE_CHAIN_ENTRY: u32 = 2007;
    pub const NEW_FLUFFY_BLOCK: u32 = 2008;
    pub const REQUEST_FLUFFY_MISSING_TX: u32 = 2009;
    pub const GET_TXPOOL_COMPLEMENT: u32 = 2010;

    /// Commands the reference node does not implement (`specs/08` §2).
    ///
    /// 1004–1006 are `STAT_INFO`, `NETWORK_STATE` and `PEER_ID`; 2005 is
    /// likewise historical. A Rust node **must not send** them and should
    /// answer `LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED` if asked.
    pub const HISTORICAL: &[u32] = &[1004, 1005, 1006, 2005];

    /// Is this a command the reference node would answer?
    pub fn is_supported(id: u32) -> bool {
        matches!(
            id,
            HANDSHAKE
                | TIMED_SYNC
                | PING
                | REQUEST_SUPPORT_FLAGS
                | NEW_BLOCK
                | NEW_TRANSACTIONS
                | REQUEST_GET_OBJECTS
                | RESPONSE_GET_OBJECTS
                | REQUEST_CHAIN
                | RESPONSE_CHAIN_ENTRY
                | NEW_FLUFFY_BLOCK
                | REQUEST_FLUFFY_MISSING_TX
                | GET_TXPOOL_COMPLEMENT
        )
    }

    /// Every supported command, for tests and for a capability listing.
    pub const ALL: &[u32] = &[
        HANDSHAKE,
        TIMED_SYNC,
        PING,
        REQUEST_SUPPORT_FLAGS,
        NEW_BLOCK,
        NEW_TRANSACTIONS,
        REQUEST_GET_OBJECTS,
        RESPONSE_GET_OBJECTS,
        REQUEST_CHAIN,
        RESPONSE_CHAIN_ENTRY,
        NEW_FLUFFY_BLOCK,
        REQUEST_FLUFFY_MISSING_TX,
        GET_TXPOOL_COMPLEMENT,
    ];
}

/// `LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED`.
pub const ERROR_CONNECTION_HANDLER_NOT_DEFINED: i32 = -7;

/// Why a header would not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LevinError {
    /// Fewer than [`HEADER_LEN`] bytes.
    ShortHeader { found: usize },
    /// The first eight bytes were not [`SIGNATURE`].
    ///
    /// This is the first thing checked, and it is what tells a Levin stream
    /// from anything else pointed at the port.
    BadSignature { found: [u8; 8] },
    /// `length` exceeds the limit in force.
    ///
    /// Carries which limit applied, because the pre- and post-handshake cases
    /// are different bugs.
    TooLarge { length: u64, limit: u64 },
    /// `m_protocol_version` was not [`PROTOCOL_VERSION`].
    BadVersion { found: u32 },
    /// A fragment stream that does not start with `BEGIN`.
    FragmentWithoutBegin,
    /// Reassembled fragments did not contain a complete nested header.
    FragmentTooShort { found: usize },
    /// The reassembly buffer would exceed the limit.
    FragmentTooLarge { length: usize, limit: u64 },
}

impl fmt::Display for LevinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LevinError::ShortHeader { found } => {
                write!(f, "levin header is {found} bytes, need {HEADER_LEN}")
            }
            LevinError::BadSignature { found } => {
                write!(f, "not a levin stream: signature {found:02x?}")
            }
            LevinError::TooLarge { length, limit } => {
                write!(f, "body of {length} bytes exceeds the {limit}-byte limit")
            }
            LevinError::BadVersion { found } => {
                write!(
                    f,
                    "levin protocol version {found}, expected {PROTOCOL_VERSION}"
                )
            }
            LevinError::FragmentWithoutBegin => {
                write!(f, "fragment continued without a BEGIN")
            }
            LevinError::FragmentTooShort { found } => {
                write!(f, "reassembled {found} bytes, too few for a nested header")
            }
            LevinError::FragmentTooLarge { length, limit } => {
                write!(
                    f,
                    "reassembly reached {length} bytes, over the {limit}-byte limit"
                )
            }
        }
    }
}

impl std::error::Error for LevinError {}

/// `epee::levin::bucket_head2` — the 33-byte header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Body length. The header is **not** included.
    pub length: u64,
    /// `m_have_to_return_data`: 0 no, non-zero yes.
    pub expect_response: bool,
    pub command: u32,
    /// 0 in requests.
    pub return_code: i32,
    pub flags: u32,
    pub version: u32,
}

impl Header {
    /// Parse a header, enforcing the signature, the version, and `limit` on the
    /// declared body length.
    ///
    /// `limit` is [`INITIAL_MAX_PACKET_SIZE`] until the handshake completes and
    /// [`DEFAULT_MAX_PACKET_SIZE`] after (`specs/08` §1). The check happens
    /// here, before the caller allocates anything.
    pub fn read(buf: &[u8], limit: u64) -> Result<Header, LevinError> {
        if buf.len() < HEADER_LEN {
            return Err(LevinError::ShortHeader { found: buf.len() });
        }
        let sig: [u8; 8] = buf[0..8].try_into().expect("checked above");
        if sig != SIGNATURE {
            return Err(LevinError::BadSignature { found: sig });
        }

        let length = u64::from_le_bytes(buf[8..16].try_into().expect("checked above"));
        if length > limit {
            return Err(LevinError::TooLarge { length, limit });
        }

        let version = u32::from_le_bytes(buf[29..33].try_into().expect("checked above"));
        if version != PROTOCOL_VERSION {
            return Err(LevinError::BadVersion { found: version });
        }

        Ok(Header {
            length,
            expect_response: buf[16] != 0,
            command: u32::from_le_bytes(buf[17..21].try_into().expect("checked above")),
            return_code: i32::from_le_bytes(buf[21..25].try_into().expect("checked above")),
            flags: u32::from_le_bytes(buf[25..29].try_into().expect("checked above")),
            version,
        })
    }

    /// Serialise to the wire form.
    pub fn write(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..8].copy_from_slice(&SIGNATURE);
        out[8..16].copy_from_slice(&self.length.to_le_bytes());
        out[16] = u8::from(self.expect_response);
        out[17..21].copy_from_slice(&self.command.to_le_bytes());
        out[21..25].copy_from_slice(&self.return_code.to_le_bytes());
        out[25..29].copy_from_slice(&self.flags.to_le_bytes());
        out[29..33].copy_from_slice(&self.version.to_le_bytes());
        out
    }

    /// Classify by the table in `specs/08` §1.
    ///
    /// The order matters: `BEGIN | END` is a dummy, and must be tested before
    /// either flag alone.
    pub fn kind(&self) -> Kind {
        let q = self.flags & flags::REQUEST != 0;
        let s = self.flags & flags::RESPONSE != 0;
        let b = self.flags & flags::BEGIN != 0;
        let e = self.flags & flags::END != 0;

        match (q, s, b, e) {
            (false, false, true, true) => Kind::Dummy,
            (true, false, false, false) => {
                if self.expect_response {
                    Kind::Request
                } else {
                    Kind::Notification
                }
            }
            (false, true, false, false) => Kind::Response,
            (false, false, true, false) => Kind::FragmentBegin,
            (false, false, false, false) => Kind::FragmentMiddle,
            (false, false, false, true) => Kind::FragmentEnd,
            _ => Kind::Unknown,
        }
    }

    /// A notification header for `command` with a `length`-byte body.
    pub fn notification(command: u32, length: u64) -> Header {
        Header {
            length,
            expect_response: false,
            command,
            return_code: 0,
            flags: flags::REQUEST,
            version: PROTOCOL_VERSION,
        }
    }

    /// A request header, which expects a response.
    pub fn request(command: u32, length: u64) -> Header {
        Header {
            expect_response: true,
            ..Header::notification(command, length)
        }
    }

    /// A response header carrying `return_code`.
    pub fn response(command: u32, length: u64, return_code: i32) -> Header {
        Header {
            length,
            expect_response: false,
            command,
            return_code,
            flags: flags::RESPONSE,
            version: PROTOCOL_VERSION,
        }
    }
}

/// Reassembles a fragmented message (`specs/08` §1).
///
/// "Reassembled fragments contain a **complete nested Levin header** for the
/// real message" — so the output of a successful reassembly is itself a header
/// plus a body, not a bare body.
///
/// A dummy message (`BEGIN | END`) is *not* a fragment stream: it is accepted
/// and discarded, and must never start a reassembly.
#[derive(Debug, Default)]
pub struct Reassembler {
    buf: Vec<u8>,
    in_progress: bool,
}

/// What [`Reassembler::push`] decided about a frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Reassembly {
    /// Not a fragment — handle it normally.
    NotAFragment,
    /// A dummy; discarded.
    Discarded,
    /// Buffered, more to come.
    Buffered,
    /// Complete: the nested header and its body.
    Complete { header: Header, body: Vec<u8> },
}

impl Reassembler {
    pub fn new() -> Reassembler {
        Reassembler::default()
    }

    /// Is a reassembly underway?
    pub fn is_in_progress(&self) -> bool {
        self.in_progress
    }

    /// How many bytes are buffered.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Abandon any partial reassembly, e.g. on a protocol error.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.in_progress = false;
    }

    /// Feed one frame.
    ///
    /// `limit` bounds the *reassembled* size, not just each fragment — without
    /// that, a peer could send unlimited small fragments and grow the buffer
    /// without ever tripping the per-frame check.
    pub fn push(
        &mut self,
        header: &Header,
        body: &[u8],
        limit: u64,
    ) -> Result<Reassembly, LevinError> {
        match header.kind() {
            Kind::Dummy => Ok(Reassembly::Discarded),
            Kind::FragmentBegin => {
                // A new BEGIN replaces whatever was in flight, which is what
                // the C++ does rather than erroring.
                self.buf.clear();
                self.in_progress = true;
                self.extend(body, limit)?;
                Ok(Reassembly::Buffered)
            }
            Kind::FragmentMiddle | Kind::FragmentEnd if !self.in_progress => {
                Err(LevinError::FragmentWithoutBegin)
            }
            Kind::FragmentMiddle => {
                self.extend(body, limit)?;
                Ok(Reassembly::Buffered)
            }
            Kind::FragmentEnd => {
                self.extend(body, limit)?;
                let whole = std::mem::take(&mut self.buf);
                self.in_progress = false;

                let nested = Header::read(&whole, limit).map_err(|e| match e {
                    LevinError::ShortHeader { found } => LevinError::FragmentTooShort { found },
                    other => other,
                })?;
                Ok(Reassembly::Complete {
                    header: nested,
                    body: whole[HEADER_LEN..].to_vec(),
                })
            }
            _ => Ok(Reassembly::NotAFragment),
        }
    }

    fn extend(&mut self, body: &[u8], limit: u64) -> Result<(), LevinError> {
        let next = self.buf.len().saturating_add(body.len());
        if next as u64 > limit {
            self.reset();
            return Err(LevinError::FragmentTooLarge {
                length: next,
                limit,
            });
        }
        self.buf.extend_from_slice(body);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            length: 42,
            expect_response: true,
            command: command::HANDSHAKE,
            return_code: 0,
            flags: flags::REQUEST,
            version: PROTOCOL_VERSION,
        }
    }

    /// `specs/08` §1: the signature bytes are literal. Deriving them from the
    /// "two u32s" description is exactly the mistake the spec warns about.
    #[test]
    fn the_signature_is_the_documented_byte_sequence() {
        assert_eq!(SIGNATURE, [0x01, 0x21, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
        assert_eq!(HEADER_LEN, 33);

        // It *is* the LE encoding of those two u32s, which is worth pinning so
        // the literal and the description cannot drift apart.
        let lo = u32::from_le_bytes(SIGNATURE[0..4].try_into().unwrap());
        let hi = u32::from_le_bytes(SIGNATURE[4..8].try_into().unwrap());
        assert_eq!(lo, 0x0101_2101);
        assert_eq!(hi, 0x0101_0101);
    }

    #[test]
    fn a_header_round_trips() {
        let h = sample();
        let bytes = h.write();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(Header::read(&bytes, DEFAULT_MAX_PACKET_SIZE), Ok(h));
    }

    /// Every field sits at the offset `specs/08` §1 gives it. A shifted field
    /// would still parse and mean something else.
    #[test]
    fn fields_sit_at_their_documented_offsets() {
        let h = Header {
            length: 0x1122_3344_5566_7788,
            expect_response: true,
            command: 0x2001,
            return_code: -7,
            flags: 0xF,
            version: 1,
        };
        let b = h.write();
        assert_eq!(&b[0..8], &SIGNATURE);
        assert_eq!(&b[8..16], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(b[16], 1);
        assert_eq!(&b[17..21], &0x2001u32.to_le_bytes());
        assert_eq!(&b[21..25], &(-7i32).to_le_bytes());
        assert_eq!(&b[25..29], &0xFu32.to_le_bytes());
        assert_eq!(&b[29..33], &1u32.to_le_bytes());
    }

    /// The length field excludes the header — an inclusive reading would
    /// under-read every body by 33 bytes.
    #[test]
    fn the_length_excludes_the_header() {
        let h = Header::notification(command::NEW_BLOCK, 100);
        let b = h.write();
        assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), 100);
        assert_ne!(u64::from_le_bytes(b[8..16].try_into().unwrap()), 133);
    }

    // ---- the things a hostile peer sends ----

    #[test]
    fn a_short_header_is_an_error_not_a_panic() {
        for n in 0..HEADER_LEN {
            let buf = vec![0u8; n];
            assert_eq!(
                Header::read(&buf, DEFAULT_MAX_PACKET_SIZE),
                Err(LevinError::ShortHeader { found: n })
            );
        }
    }

    #[test]
    fn a_wrong_signature_is_rejected_first() {
        let mut b = sample().write();
        b[0] = 0x02;
        match Header::read(&b, DEFAULT_MAX_PACKET_SIZE) {
            Err(LevinError::BadSignature { found }) => assert_eq!(found[0], 0x02),
            other => panic!("expected BadSignature, got {other:?}"),
        }

        // Even a header that is also over-long reports the signature, because
        // the signature is what says this is a Levin stream at all.
        let mut b = Header::notification(1, u64::MAX).write();
        b[7] = 0xff;
        assert!(matches!(
            Header::read(&b, 1),
            Err(LevinError::BadSignature { .. })
        ));
    }

    /// `specs/08` §1: **two** limits, and the smaller applies before the
    /// handshake. This is what stops an unauthenticated peer from making the
    /// node allocate 100 MB.
    #[test]
    fn the_pre_handshake_limit_is_the_smaller_one() {
        assert_eq!(INITIAL_MAX_PACKET_SIZE, 256 * 1024);
        assert_eq!(DEFAULT_MAX_PACKET_SIZE, 100_000_000);
        const _: () = assert!(INITIAL_MAX_PACKET_SIZE < DEFAULT_MAX_PACKET_SIZE);

        let big = Header::notification(command::NEW_BLOCK, 1_000_000).write();
        // Accepted after the handshake...
        assert!(Header::read(&big, DEFAULT_MAX_PACKET_SIZE).is_ok());
        // ...and refused before it.
        assert_eq!(
            Header::read(&big, INITIAL_MAX_PACKET_SIZE),
            Err(LevinError::TooLarge {
                length: 1_000_000,
                limit: INITIAL_MAX_PACKET_SIZE
            })
        );
    }

    /// The limit is inclusive: exactly the limit is allowed, one more is not.
    #[test]
    fn the_size_limit_is_inclusive() {
        let at = Header::notification(1, INITIAL_MAX_PACKET_SIZE).write();
        assert!(Header::read(&at, INITIAL_MAX_PACKET_SIZE).is_ok());

        let over = Header::notification(1, INITIAL_MAX_PACKET_SIZE + 1).write();
        assert!(Header::read(&over, INITIAL_MAX_PACKET_SIZE).is_err());
    }

    /// `u64::MAX` as a length must not overflow anything on the way to being
    /// rejected.
    #[test]
    fn an_absurd_length_is_rejected_without_overflow() {
        let b = Header::notification(1, u64::MAX).write();
        assert_eq!(
            Header::read(&b, DEFAULT_MAX_PACKET_SIZE),
            Err(LevinError::TooLarge {
                length: u64::MAX,
                limit: DEFAULT_MAX_PACKET_SIZE
            })
        );
    }

    #[test]
    fn a_wrong_protocol_version_is_rejected() {
        let mut h = sample();
        h.version = 2;
        assert_eq!(
            Header::read(&h.write(), DEFAULT_MAX_PACKET_SIZE),
            Err(LevinError::BadVersion { found: 2 })
        );
    }

    /// Any 33 bytes at all must produce a `Result`, never a panic. The
    /// signature check makes most inputs fail fast, so the sweep also covers
    /// well-signed garbage.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..2_000 {
            let mut buf = [0u8; HEADER_LEN];
            for c in buf.chunks_mut(8) {
                let v = next().to_le_bytes();
                let n = c.len();
                c.copy_from_slice(&v[..n]);
            }
            let _ = Header::read(&buf, DEFAULT_MAX_PACKET_SIZE);

            // And again with a valid signature, so the rest of the parse runs.
            buf[0..8].copy_from_slice(&SIGNATURE);
            if let Ok(h) = Header::read(&buf, DEFAULT_MAX_PACKET_SIZE) {
                let _ = h.kind();
                assert_eq!(h.write()[0..8], SIGNATURE);
            }
        }
    }

    // ---- message kinds ----

    /// The table in `specs/08` §1, restated so the two can be diffed.
    #[test]
    fn the_kind_table_matches_the_spec() {
        let k = |flags, expect_response| {
            Header {
                length: 0,
                expect_response,
                command: 1,
                return_code: 0,
                flags,
                version: PROTOCOL_VERSION,
            }
            .kind()
        };

        assert_eq!(k(flags::REQUEST, false), Kind::Notification);
        assert_eq!(k(flags::REQUEST, true), Kind::Request);
        assert_eq!(k(flags::RESPONSE, false), Kind::Response);
        assert_eq!(k(flags::BEGIN, false), Kind::FragmentBegin);
        assert_eq!(k(0, false), Kind::FragmentMiddle);
        assert_eq!(k(flags::END, false), Kind::FragmentEnd);
        assert_eq!(k(flags::BEGIN | flags::END, false), Kind::Dummy);
    }

    /// A notification and a request differ **only** by `expect_response`; the
    /// flags are identical. Reading the kind from the flags alone would merge
    /// them.
    #[test]
    fn a_request_differs_from_a_notification_only_by_expect_response() {
        let n = Header::notification(command::NEW_BLOCK, 0);
        let r = Header::request(command::HANDSHAKE, 0);
        assert_eq!(n.flags, r.flags);
        assert_ne!(n.kind(), r.kind());
        assert_eq!(n.kind(), Kind::Notification);
        assert_eq!(r.kind(), Kind::Request);
    }

    /// `BEGIN | END` is a dummy, not "a fragment that is both ends". Testing
    /// the flags in the wrong order would start a reassembly on every dummy.
    #[test]
    fn begin_and_end_together_is_a_dummy() {
        let h = Header {
            flags: flags::BEGIN | flags::END,
            ..Header::notification(0, 0)
        };
        assert_eq!(h.kind(), Kind::Dummy);
        assert_ne!(h.kind(), Kind::FragmentBegin);
        assert_ne!(h.kind(), Kind::FragmentEnd);
    }

    #[test]
    fn an_unnamed_flag_combination_is_unknown() {
        for flags in [
            flags::REQUEST | flags::RESPONSE,
            flags::REQUEST | flags::BEGIN,
            flags::RESPONSE | flags::END,
            flags::RESPONSE | flags::BEGIN | flags::END,
        ] {
            let h = Header {
                flags,
                ..Header::notification(0, 0)
            };
            assert_eq!(h.kind(), Kind::Unknown, "flags {flags:#x}");
        }
    }

    /// Bits above the four defined ones are **ignored**, not rejected: the C++
    /// masks each flag it cares about and never inspects the rest. So a header
    /// with only undefined bits set has all four clear, which the table in
    /// `specs/08` §1 calls a middle fragment.
    ///
    /// Worth pinning because "unknown bit set" reads like it should be an
    /// error, and making it one would drop frames the reference node accepts.
    #[test]
    fn undefined_flag_bits_are_ignored() {
        let only_undefined = Header {
            flags: 0x10,
            ..Header::notification(0, 0)
        };
        assert_eq!(only_undefined.kind(), Kind::FragmentMiddle);

        // And they do not disturb a defined combination.
        for (base, want) in [
            (flags::REQUEST, Kind::Notification),
            (flags::RESPONSE, Kind::Response),
            (flags::BEGIN, Kind::FragmentBegin),
            (flags::END, Kind::FragmentEnd),
            (flags::BEGIN | flags::END, Kind::Dummy),
        ] {
            let h = Header {
                flags: base | 0xFFFF_FFF0,
                ..Header::notification(0, 0)
            };
            assert_eq!(h.kind(), want, "base {base:#x} with undefined bits set");
        }
    }

    // ---- commands ----

    #[test]
    fn the_command_ids_match_the_spec() {
        assert_eq!(command::HANDSHAKE, 1001);
        assert_eq!(command::TIMED_SYNC, 1002);
        assert_eq!(command::PING, 1003);
        assert_eq!(command::REQUEST_SUPPORT_FLAGS, 1007);
        assert_eq!(command::NEW_BLOCK, 2001);
        assert_eq!(command::NEW_TRANSACTIONS, 2002);
        assert_eq!(command::REQUEST_GET_OBJECTS, 2003);
        assert_eq!(command::RESPONSE_GET_OBJECTS, 2004);
        assert_eq!(command::REQUEST_CHAIN, 2006);
        assert_eq!(command::RESPONSE_CHAIN_ENTRY, 2007);
        assert_eq!(command::NEW_FLUFFY_BLOCK, 2008);
        assert_eq!(command::REQUEST_FLUFFY_MISSING_TX, 2009);
        assert_eq!(command::GET_TXPOOL_COMPLEMENT, 2010);
        assert_eq!(command::ALL.len(), 13);
    }

    /// `specs/08` §2: 1004–1006 and 2005 are historical. A Rust node must not
    /// send them, and 2005 sits in the middle of the notification range where
    /// it would be easy to include by accident.
    #[test]
    fn the_historical_commands_are_not_supported() {
        assert_eq!(command::HISTORICAL, &[1004, 1005, 1006, 2005]);
        for id in command::HISTORICAL {
            assert!(!command::is_supported(*id), "{id} must not be supported");
            assert!(!command::ALL.contains(id));
        }
        for id in command::ALL {
            assert!(command::is_supported(*id), "{id} must be supported");
        }
        assert!(!command::is_supported(9999));
        assert_eq!(ERROR_CONNECTION_HANDLER_NOT_DEFINED, -7);
    }

    // ---- fragments ----

    fn frag(flags: u32) -> Header {
        Header {
            flags,
            ..Header::notification(0, 0)
        }
    }

    /// A reassembled message contains a **complete nested header**, so the
    /// result is a header plus a body rather than a bare payload.
    #[test]
    fn fragments_reassemble_into_a_nested_message() {
        let inner = Header::notification(command::NEW_BLOCK, 5);
        let mut whole = inner.write().to_vec();
        whole.extend_from_slice(b"hello");

        let mut r = Reassembler::new();
        assert!(!r.is_in_progress());

        // Split across three frames at awkward boundaries.
        let (a, rest) = whole.split_at(10);
        let (b, c) = rest.split_at(20);

        assert_eq!(
            r.push(&frag(flags::BEGIN), a, DEFAULT_MAX_PACKET_SIZE),
            Ok(Reassembly::Buffered)
        );
        assert!(r.is_in_progress());
        assert_eq!(
            r.push(&frag(0), b, DEFAULT_MAX_PACKET_SIZE),
            Ok(Reassembly::Buffered)
        );
        let done = r
            .push(&frag(flags::END), c, DEFAULT_MAX_PACKET_SIZE)
            .unwrap();

        match done {
            Reassembly::Complete { header, body } => {
                assert_eq!(header, inner);
                assert_eq!(body, b"hello");
            }
            other => panic!("expected Complete, got {other:?}"),
        }
        assert!(
            !r.is_in_progress(),
            "state must be cleared after completion"
        );
        assert_eq!(r.buffered(), 0);
    }

    /// A dummy must be accepted and discarded, and must not disturb a
    /// reassembly in progress.
    #[test]
    fn a_dummy_is_discarded_and_does_not_start_a_reassembly() {
        let mut r = Reassembler::new();
        assert_eq!(
            r.push(
                &frag(flags::BEGIN | flags::END),
                b"junk",
                DEFAULT_MAX_PACKET_SIZE
            ),
            Ok(Reassembly::Discarded)
        );
        assert!(!r.is_in_progress());
        assert_eq!(r.buffered(), 0);
    }

    /// A middle or end fragment with no begin is a protocol error, not a panic
    /// and not a silent accept.
    #[test]
    fn a_fragment_without_a_begin_is_rejected() {
        let mut r = Reassembler::new();
        assert_eq!(
            r.push(&frag(0), b"x", DEFAULT_MAX_PACKET_SIZE),
            Err(LevinError::FragmentWithoutBegin)
        );
        assert_eq!(
            r.push(&frag(flags::END), b"x", DEFAULT_MAX_PACKET_SIZE),
            Err(LevinError::FragmentWithoutBegin)
        );
    }

    /// The limit bounds the **reassembled** total. Without that, a peer could
    /// send unlimited small fragments, each individually under the per-frame
    /// limit, and grow the buffer without bound.
    #[test]
    fn reassembly_is_bounded_in_total_not_per_fragment() {
        let mut r = Reassembler::new();
        let limit = 1_000u64;
        let chunk = vec![0u8; 400];

        assert_eq!(
            r.push(&frag(flags::BEGIN), &chunk, limit),
            Ok(Reassembly::Buffered)
        );
        assert_eq!(r.push(&frag(0), &chunk, limit), Ok(Reassembly::Buffered));
        // 1200 > 1000, even though each fragment is only 400.
        assert_eq!(
            r.push(&frag(0), &chunk, limit),
            Err(LevinError::FragmentTooLarge {
                length: 1_200,
                limit
            })
        );
        assert!(!r.is_in_progress(), "a rejected stream must be abandoned");
        assert_eq!(r.buffered(), 0);
    }

    /// A stream that ends too short to hold a nested header is an error.
    #[test]
    fn a_truncated_reassembly_is_rejected() {
        let mut r = Reassembler::new();
        r.push(&frag(flags::BEGIN), b"short", DEFAULT_MAX_PACKET_SIZE)
            .unwrap();
        assert_eq!(
            r.push(&frag(flags::END), b"", DEFAULT_MAX_PACKET_SIZE),
            Err(LevinError::FragmentTooShort { found: 5 })
        );
    }

    /// A new BEGIN replaces an abandoned stream rather than erroring.
    #[test]
    fn a_new_begin_restarts_the_reassembly() {
        let inner = Header::notification(command::PING, 0);
        let mut r = Reassembler::new();

        r.push(&frag(flags::BEGIN), b"abandoned", DEFAULT_MAX_PACKET_SIZE)
            .unwrap();
        assert_eq!(r.buffered(), 9);

        r.push(&frag(flags::BEGIN), &inner.write(), DEFAULT_MAX_PACKET_SIZE)
            .unwrap();
        assert_eq!(r.buffered(), HEADER_LEN, "the first stream was dropped");

        match r
            .push(&frag(flags::END), b"", DEFAULT_MAX_PACKET_SIZE)
            .unwrap()
        {
            Reassembly::Complete { header, body } => {
                assert_eq!(header, inner);
                assert!(body.is_empty());
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    /// A non-fragment frame passes straight through.
    #[test]
    fn a_normal_message_is_not_a_fragment() {
        let mut r = Reassembler::new();
        assert_eq!(
            r.push(
                &Header::notification(command::NEW_BLOCK, 0),
                b"",
                DEFAULT_MAX_PACKET_SIZE
            ),
            Ok(Reassembly::NotAFragment)
        );
        assert_eq!(
            r.push(
                &Header::response(command::HANDSHAKE, 0, 1),
                b"",
                DEFAULT_MAX_PACKET_SIZE
            ),
            Ok(Reassembly::NotAFragment)
        );
    }

    /// The advertised `network_config` maximum is a different number from
    /// either framing limit — using it to frame would accept 50 MB
    /// pre-handshake.
    #[test]
    fn the_advertised_maximum_is_not_a_framing_limit() {
        assert_eq!(ADVERTISED_PACKET_MAX_SIZE, 50_000_000);
        assert_ne!(ADVERTISED_PACKET_MAX_SIZE, INITIAL_MAX_PACKET_SIZE);
        assert_ne!(ADVERTISED_PACKET_MAX_SIZE, DEFAULT_MAX_PACKET_SIZE);
    }
}
