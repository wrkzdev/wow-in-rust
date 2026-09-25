//! Whole Levin messages from a socket that times out (`specs/08` §1).
//!
//! [`crate::Peer`] reads with `read_exact`, which suits a connection that does
//! nothing but wait for its answer. A node's connections cannot work that way:
//! each wakes every second to send a timed sync, notice a stalled peer, or see
//! that the node is stopping -- and a `read_exact` cut short by its read timeout
//! throws away whatever part of a message it had consumed, leaving the stream
//! out of step for good.
//!
//! [`FrameReader`] keeps what it has read in its own buffer, so a timeout is
//! only a pause: [`FrameReader::poll`] returns `Ok(None)` and the next call
//! carries on where the last one stopped.
//!
//! The size limit is checked on the header before any of the body is accepted,
//! and the buffer only ever holds bytes the peer actually sent -- a declared
//! length is never used to size an allocation.

use std::io::{ErrorKind, Read};
use std::time::Instant;

use crate::levin::{Header, LevinError, Reassembler, Reassembly, HEADER_LEN, SIGNATURE};

/// Why a connection stopped producing messages.
#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    /// The bytes are not Levin, or break a limit.
    Levin(LevinError),
    /// The peer closed the connection.
    Closed,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "io: {e}"),
            FrameError::Levin(e) => write!(f, "framing: {e}"),
            FrameError::Closed => f.write_str("connection closed"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<LevinError> for FrameError {
    fn from(e: LevinError) -> Self {
        FrameError::Levin(e)
    }
}

/// How much one read takes from the socket.
const CHUNK: usize = 64 * 1024;

/// Buffers a connection's bytes into whole messages.
#[derive(Debug)]
pub struct FrameReader {
    buf: Vec<u8>,
    reassembler: Reassembler,
    limit: u64,
}

impl FrameReader {
    /// A reader enforcing `limit` on each message body. Start with
    /// [`crate::levin::INITIAL_MAX_PACKET_SIZE`] and raise it with
    /// [`FrameReader::set_limit`] once the handshake is done.
    pub fn new(limit: u64) -> FrameReader {
        FrameReader {
            buf: Vec::new(),
            reassembler: Reassembler::new(),
            limit,
        }
    }

    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// The next whole message, reading from `src` as needed.
    ///
    /// `Ok(None)` means the read timed out with no complete message yet;
    /// nothing is lost, and calling again continues. Fragments are
    /// reassembled and dummies discarded, so what comes out is always a real
    /// message.
    pub fn poll<R: Read>(&mut self, src: &mut R) -> Result<Option<(Header, Vec<u8>)>, FrameError> {
        self.read_until(src, None)
    }

    /// [`FrameReader::poll`], but giving up at `deadline` even while bytes are
    /// still arriving.
    ///
    /// `poll` returns `Ok(None)` only when a read times out, so a peer that
    /// sends a byte a little more often than the socket's read timeout keeps
    /// it reading for as long as it likes -- a deadline its caller checks
    /// between polls is never reached. That is the C++'s handshake stall,
    /// whose timer restarted on every partial read (fixed in Monero by an
    /// absolute timeout, #11082). With this, the deadline holds whatever the
    /// peer sends: `Ok(None)` once it has passed, and nothing buffered is
    /// lost.
    pub fn poll_before<R: Read>(
        &mut self,
        src: &mut R,
        deadline: Instant,
    ) -> Result<Option<(Header, Vec<u8>)>, FrameError> {
        self.read_until(src, Some(deadline))
    }

    fn read_until<R: Read>(
        &mut self,
        src: &mut R,
        deadline: Option<Instant>,
    ) -> Result<Option<(Header, Vec<u8>)>, FrameError> {
        let mut chunk = vec![0u8; CHUNK];
        loop {
            if let Some(message) = self.take()? {
                return Ok(Some(message));
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(None);
            }
            match src.read(&mut chunk) {
                Ok(0) => return Err(FrameError::Closed),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                // Unix reports an expired read timeout as `WouldBlock`,
                // Windows as `TimedOut`.
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Ok(None)
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(FrameError::Io(e)),
            }
        }
    }

    /// A message already sitting in the buffer, if there is one.
    fn take(&mut self) -> Result<Option<(Header, Vec<u8>)>, FrameError> {
        loop {
            // The signature is checked as soon as it has arrived, so a stream
            // that is not Levin at all -- an HTTP probe on the port, say -- is
            // refused for what it is rather than read as a peer that hung up.
            if self.buf.len() >= SIGNATURE.len() && self.buf[..SIGNATURE.len()] != SIGNATURE {
                let mut found = [0u8; 8];
                found.copy_from_slice(&self.buf[..8]);
                return Err(FrameError::Levin(LevinError::BadSignature { found }));
            }
            if self.buf.len() < HEADER_LEN {
                return Ok(None);
            }
            // Checked here, before the body is waited for.
            let header = Header::read(&self.buf[..HEADER_LEN], self.limit)?;
            let total = HEADER_LEN + header.length as usize;
            if self.buf.len() < total {
                return Ok(None);
            }
            let body = self.buf[HEADER_LEN..total].to_vec();
            self.buf.drain(..total);

            match self.reassembler.push(&header, &body, self.limit)? {
                Reassembly::NotAFragment => return Ok(Some((header, body))),
                Reassembly::Complete { header, body } => return Ok(Some((header, body))),
                Reassembly::Discarded | Reassembly::Buffered => continue,
            }
        }
    }
}

/// A header and its body as one buffer, ready to write.
pub fn encode(header: &Header, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&header.write());
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::levin::{self, flags, Kind};
    use std::collections::VecDeque;

    /// A socket that hands out bytes in the pieces it is given, with read
    /// timeouts between them.
    struct Script(VecDeque<Option<Vec<u8>>>);

    impl Read for Script {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            match self.0.pop_front() {
                None => Ok(0),
                Some(None) => Err(std::io::Error::from(ErrorKind::WouldBlock)),
                Some(Some(data)) => {
                    let n = data.len().min(out.len());
                    out[..n].copy_from_slice(&data[..n]);
                    if n < data.len() {
                        self.0.push_front(Some(data[n..].to_vec()));
                    }
                    Ok(n)
                }
            }
        }
    }

    fn message(command: u32, body: &[u8]) -> Vec<u8> {
        encode(&Header::notification(command, body.len() as u64), body)
    }

    /// **The reason this exists.** A read timeout in the middle of a message
    /// is a pause, not a loss: the message comes out whole afterwards.
    #[test]
    fn a_timeout_mid_message_loses_nothing() {
        let m = message(2002, b"hello, peer");
        let mut src = Script(VecDeque::from(vec![
            Some(m[..10].to_vec()),
            None,
            Some(m[10..40].to_vec()),
            None,
            Some(m[40..].to_vec()),
        ]));

        let mut r = FrameReader::new(levin::DEFAULT_MAX_PACKET_SIZE);
        assert!(r.poll(&mut src).unwrap().is_none(), "header incomplete");
        assert!(r.poll(&mut src).unwrap().is_none(), "body incomplete");
        let (h, body) = r.poll(&mut src).unwrap().expect("whole message");
        assert_eq!(h.command, 2002);
        assert_eq!(body, b"hello, peer");
    }

    /// A peer that sends one byte at a time, each well inside any read
    /// timeout, so no read ever times out.
    struct Drip {
        bytes: Vec<u8>,
        at: usize,
        pause: std::time::Duration,
    }

    impl Read for Drip {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.pause);
            match self.bytes.get(self.at) {
                Some(b) => {
                    out[0] = *b;
                    self.at += 1;
                    Ok(1)
                }
                None => Err(std::io::Error::from(ErrorKind::WouldBlock)),
            }
        }
    }

    /// A trickle does not stretch a deadline: `poll_before` gives up on time
    /// though every read brought a byte, and keeps what it read.
    #[test]
    fn a_deadline_holds_against_a_trickle() {
        let m = message(1001, &[7u8; 200]);
        let mut src = Drip {
            bytes: m,
            at: 0,
            pause: std::time::Duration::from_millis(1),
        };
        let mut r = FrameReader::new(levin::INITIAL_MAX_PACKET_SIZE);
        let started = Instant::now();
        let got = r
            .poll_before(&mut src, started + std::time::Duration::from_millis(20))
            .unwrap();
        assert!(got.is_none(), "not a whole message by the deadline");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(src.at > 0 && src.at < src.bytes.len());

        src.pause = std::time::Duration::ZERO;
        let (h, body) = r.poll(&mut src).unwrap().expect("the rest follows");
        assert_eq!(h.command, 1001);
        assert_eq!(body, [7u8; 200]);
    }

    #[test]
    fn two_messages_in_one_read_both_come_out() {
        let mut both = message(1, b"a");
        both.extend(message(2, b"bb"));
        let mut src = Script(VecDeque::from(vec![Some(both)]));

        let mut r = FrameReader::new(levin::DEFAULT_MAX_PACKET_SIZE);
        assert_eq!(r.poll(&mut src).unwrap().unwrap().0.command, 1);
        assert_eq!(r.poll(&mut src).unwrap().unwrap().0.command, 2);
        assert!(matches!(r.poll(&mut src), Err(FrameError::Closed)));
    }

    /// Fragments are put back together into the nested message, and a dummy
    /// is dropped without surfacing (`specs/08` §1).
    #[test]
    fn fragments_are_reassembled_and_dummies_skipped() {
        let inner = encode(&Header::request(1003, 2), b"hi");
        let frame = |flag: u32, body: &[u8]| {
            encode(
                &Header {
                    length: body.len() as u64,
                    expect_response: false,
                    command: 0,
                    return_code: 0,
                    flags: flag,
                    version: levin::PROTOCOL_VERSION,
                },
                body,
            )
        };

        let mut stream = frame(flags::BEGIN | flags::END, b"");
        stream.extend(frame(flags::BEGIN, &inner[..20]));
        stream.extend(frame(0, &inner[20..30]));
        stream.extend(frame(flags::END, &inner[30..]));
        let mut src = Script(VecDeque::from(vec![Some(stream)]));

        let mut r = FrameReader::new(levin::DEFAULT_MAX_PACKET_SIZE);
        let (h, body) = r.poll(&mut src).unwrap().expect("reassembled");
        assert_eq!(h.command, 1003);
        assert_eq!(h.kind(), Kind::Request);
        assert_eq!(body, b"hi");
    }

    /// The limit is enforced on the header, with no body sent at all -- which
    /// is what keeps a stranger from making the buffer grow.
    #[test]
    fn an_oversized_message_is_refused_on_its_header() {
        let header = Header::notification(2002, levin::INITIAL_MAX_PACKET_SIZE + 1).write();
        let mut src = Script(VecDeque::from(vec![Some(header.to_vec()), None]));

        let mut r = FrameReader::new(levin::INITIAL_MAX_PACKET_SIZE);
        match r.poll(&mut src) {
            Err(FrameError::Levin(LevinError::TooLarge { .. })) => {}
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn a_non_levin_stream_is_an_error_not_a_panic() {
        let mut src = Script(VecDeque::from(vec![Some(
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        )]));
        let mut r = FrameReader::new(levin::INITIAL_MAX_PACKET_SIZE);
        assert!(matches!(
            r.poll(&mut src),
            Err(FrameError::Levin(LevinError::BadSignature { .. }))
        ));
    }
}
