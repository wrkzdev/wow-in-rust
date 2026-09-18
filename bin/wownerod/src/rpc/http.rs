//! A minimal HTTP/1.1 server.
//!
//! `specs/11-daemon-rpc.md` §1. Only what the RPC surface needs: `POST` with a
//! `Content-Length` body, and a JSON response. No chunked encoding and no
//! pipelining. TLS is below this layer: it reads and writes whatever stream it
//! is handed, plain or `super::tls`'s.
//!
//! # Keep-alive
//!
//! A connection serves request after request until one side ends it, which is
//! what the reference daemon does and what `wallet2` needs. epee's client
//! retries a `401` **on the same socket** without reconnecting
//! (`contrib/epee/include/net/http_client.h`, the `for (sends = 0; sends < 2;)`
//! loop in `invoke`), so a `Connection: close` on the Digest challenge leaves
//! the retry writing to a closed socket and makes HTTP Digest impossible. It
//! also spares a TCP -- and, under `--rpc-ssl autodetect`, a TLS -- handshake
//! per call, and a wallet's refresh makes thousands of calls.
//!
//! The rules are RFC 7230 §6.3: HTTP/1.1 keeps the connection unless
//! `Connection: close` says otherwise, HTTP/1.0 closes it unless
//! `Connection: keep-alive` says otherwise.
//!
//! # This faces the network
//!
//! Every limit `specs/11` §1.1 gives is enforced **before** allocating:
//! `MAX_RPC_CONTENT_LENGTH` on the body, a cap on the request line and headers,
//! and a read timeout. A request that violates one gets a response and the
//! connection is closed, never an allocation sized by the peer.
//!
//! JSON parsing is `serde_json` rather than something hand-rolled here. It is
//! the one part of this file that sees arbitrary bytes from an untrusted
//! client, and `specs/15` §4.4's rule for such code is "never panic".

use std::io::{BufRead, BufReader, Read, Write};
use std::time::Duration;

/// `MAX_RPC_CONTENT_LENGTH` (`specs/11` §1.1).
pub const MAX_CONTENT_LENGTH: usize = 1_048_576;

/// A cap on the request line plus headers, which `specs/11` does not give a
/// constant for. Without one a peer could send headers forever.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// How long a single request may take to arrive, and its answer to leave. Set
/// on the socket by the caller, since a TLS stream has no socket of its own.
///
/// On a kept-alive connection this is also how long an idle client holds its
/// thread and its slot under the connection caps.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// A parsed request.
#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// The minor version of `HTTP/1.<n>`, which decides what happens to the
    /// connection when no `Connection` header says. Anything that is not
    /// `HTTP/1.<n>` counts as 0, the version that closes.
    pub http_minor: u8,
    /// Names as sent; look them up with [`Request::header`].
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// A header's value, by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether the connection stays open once this request is answered
    /// (RFC 7230 §6.3).
    ///
    /// `Connection` is a comma-separated list of tokens, and `close` anywhere
    /// in it wins over anything else there.
    pub fn keep_alive(&self) -> bool {
        let by_version = self.http_minor >= 1;
        match self.header("connection") {
            None => by_version,
            Some(value) => {
                let has = |want: &str| {
                    value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case(want))
                };
                if has("close") {
                    false
                } else if has("keep-alive") {
                    true
                } else {
                    by_version
                }
            }
        }
    }
}

/// Why a request was not served.
#[derive(Debug)]
pub enum HttpError {
    Io(std::io::Error),
    /// The request line or headers exceeded [`MAX_HEADER_BYTES`].
    HeadersTooLarge,
    /// `Content-Length` exceeded [`MAX_CONTENT_LENGTH`] (`specs/11` §1.1).
    BodyTooLarge {
        len: usize,
    },
    /// Malformed request line or headers.
    Malformed(&'static str),
    /// The client closed before sending anything.
    Closed,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Io(e) => write!(f, "io: {e}"),
            HttpError::HeadersTooLarge => write!(f, "headers exceed {MAX_HEADER_BYTES} bytes"),
            HttpError::BodyTooLarge { len } => {
                write!(f, "body of {len} bytes exceeds {MAX_CONTENT_LENGTH}")
            }
            HttpError::Malformed(w) => write!(f, "malformed request: {w}"),
            HttpError::Closed => write!(f, "connection closed"),
        }
    }
}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        HttpError::Io(e)
    }
}

/// Whether a read that had nothing to read failed because the client simply
/// stopped talking.
///
/// A read timeout arrives as `WouldBlock` where `SO_RCVTIMEO` is what expired
/// and as `TimedOut` on Windows, and a client that went away without a clean
/// close gives one of the reset kinds.
fn went_quiet(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{
        BrokenPipe, ConnectionAborted, ConnectionReset, TimedOut, UnexpectedEof, WouldBlock,
    };
    matches!(
        e.kind(),
        WouldBlock | TimedOut | ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof
    )
}

/// Read one request from a connection whose timeouts are already set.
///
/// The reader is the caller's and outlives the request, because on a
/// kept-alive connection it may already hold the first bytes of the next one.
pub fn read_request<S: Read>(reader: &mut BufReader<S>) -> Result<Request, HttpError> {
    let mut header_bytes = 0usize;

    // Request line.
    //
    // Nothing has been read yet, so anything other than a request here is the
    // client having finished rather than a client getting it wrong. A kept-alive
    // connection that goes quiet times out on this very read, and answering
    // that with `400` would leave a reply sitting in the stream for whatever
    // the client sends next -- which it would then read as the answer to *that*
    // request, one call out of step for the rest of the connection.
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => return Err(HttpError::Closed),
        Ok(_) => {}
        Err(e) if went_quiet(&e) => return Err(HttpError::Closed),
        Err(e) => return Err(e.into()),
    }
    header_bytes += line.len();
    if header_bytes > MAX_HEADER_BYTES {
        return Err(HttpError::HeadersTooLarge);
    }

    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or(HttpError::Malformed("no method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or(HttpError::Malformed("no path"))?
        .to_string();
    // A version this server does not know is read as the one that closes the
    // connection afterwards, which is the safe end of the guess.
    let http_minor = parts
        .next()
        .and_then(|v| v.strip_prefix("HTTP/1."))
        .and_then(|minor| minor.trim().parse::<u8>().ok())
        .unwrap_or(0);

    // Headers. `Content-Length` is acted on here; the rest are kept for the
    // router, bounded by the same byte cap.
    let mut content_length = 0usize;
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            return Err(HttpError::Malformed("headers ended early"));
        }
        header_bytes += h.len();
        if header_bytes > MAX_HEADER_BYTES {
            return Err(HttpError::HeadersTooLarge);
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((name, value)) = h.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse()
                    .map_err(|_| HttpError::Malformed("bad Content-Length"))?;
                // Checked here, before the allocation below.
                if content_length > MAX_CONTENT_LENGTH {
                    return Err(HttpError::BodyTooLarge {
                        len: content_length,
                    });
                }
            }
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;

    Ok(Request {
        method,
        path,
        http_minor,
        headers,
        body,
    })
}

/// Write a JSON response.
pub fn write_json(
    stream: &mut impl Write,
    status: u16,
    body: &str,
    keep_alive: bool,
) -> std::io::Result<()> {
    write_json_bytes_with(stream, status, body.as_bytes(), &[], keep_alive)
}

/// Write a JSON response with extra headers, such as a Digest challenge or a
/// CORS grant.
pub fn write_json_with(
    stream: &mut impl Write,
    status: u16,
    body: &str,
    headers: &[(&str, String)],
    keep_alive: bool,
) -> std::io::Result<()> {
    write_json_bytes_with(stream, status, body.as_bytes(), headers, keep_alive)
}

/// Write a JSON response whose body is not necessarily valid UTF-8.
///
/// `/get_transaction_pool_hashes.bin` needs this: it is a JSON endpoint whose
/// `tx_hashes` field is a `KV_SERIALIZE_CONTAINER_POD_AS_BLOB`, so the packed
/// 32-byte hashes go inside a JSON string as **raw bytes**
/// (`super::admin::pool_hashes_as_json`). `serde_json` cannot hold such a
/// string, so that one body is assembled as bytes and handed here.
pub fn write_json_bytes_with(
    stream: &mut impl Write,
    status: u16,
    body: &[u8],
    headers: &[(&str, String)],
    keep_alive: bool,
) -> std::io::Result<()> {
    write_response(
        stream,
        status,
        "application/json",
        body,
        headers,
        keep_alive,
    )
}

/// Write an epee portable-storage response, for the binary endpoints
/// (`specs/11` §5), with any extra headers.
///
/// A wallet reads the body by `Content-Length` rather than by sniffing, so the
/// content type is informational — but sending JSON's type with epee's bytes
/// would be a lie that costs nothing to avoid.
pub fn write_binary_with(
    stream: &mut impl Write,
    status: u16,
    body: &[u8],
    headers: &[(&str, String)],
    keep_alive: bool,
) -> std::io::Result<()> {
    write_response(
        stream,
        status,
        "application/octet-stream",
        body,
        headers,
        keep_alive,
    )
}

fn write_response(
    stream: &mut impl Write,
    status: u16,
    content_type: &str,
    body: &[u8],
    headers: &[(&str, String)],
    keep_alive: bool,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    // The head and the body are written separately: a body that is not UTF-8
    // cannot go through `format!`.
    //
    // No `Access-Control-Allow-Origin` unless the caller passes one: the C++
    // sends it only for the origins `--rpc-access-control-origins` names, and a
    // wildcard would let any web page read this node's answers.
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: {}\r\n",
        body.len(),
        if keep_alive { "keep-alive" } else { "close" }
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// Serve one request from a background thread and hand it back.
    fn round_trip(raw: &[u8]) -> Result<Request, HttpError> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let raw = raw.to_vec();

        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let _ = s.write_all(&raw);
            let _ = s.flush();
            // Hold the socket open so the server's read does not see EOF early.
            std::thread::sleep(std::time::Duration::from_millis(50));
        });

        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        let mut reader = BufReader::new(stream);
        let out = read_request(&mut reader);
        let _ = client.join();
        out
    }

    #[test]
    fn a_post_with_a_body_parses() {
        let req =
            round_trip(b"POST /json_rpc HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
                .expect("parse");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/json_rpc");
        assert_eq!(req.body, b"hello");
        assert_eq!(req.header("host"), Some("x"), "headers are kept");
        assert_eq!(req.header("HOST"), Some("x"), "and found by any case");
        assert_eq!(req.header("origin"), None);
        assert_eq!(req.http_minor, 1);
    }

    #[test]
    fn a_get_without_a_body_parses() {
        let req = round_trip(b"GET /get_height HTTP/1.1\r\nHost: x\r\n\r\n").expect("parse");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/get_height");
        assert!(req.body.is_empty());
    }

    /// `Content-Length` is case-insensitive, as HTTP requires.
    #[test]
    fn the_content_length_header_is_case_insensitive() {
        let req = round_trip(b"POST /x HTTP/1.1\r\ncOnTeNt-LeNgTh: 2\r\n\r\nhi").expect("parse");
        assert_eq!(req.body, b"hi");
    }

    /// **The limit `specs/11` §1.1 gives**, enforced before the allocation.
    /// A peer declaring a gigabyte must not cause a gigabyte to be reserved.
    #[test]
    fn an_oversized_body_is_refused_before_allocating() {
        let raw = format!(
            "POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_CONTENT_LENGTH + 1
        );
        match round_trip(raw.as_bytes()) {
            Err(HttpError::BodyTooLarge { len }) => {
                assert_eq!(len, MAX_CONTENT_LENGTH + 1);
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }

        // Exactly the limit is allowed -- the check is `>`, not `>=`.
        let raw = format!("POST /x HTTP/1.1\r\nContent-Length: {MAX_CONTENT_LENGTH}\r\n\r\n");
        // It will time out waiting for the body, which is an IO error, not a
        // size refusal -- the point is that it got past the limit.
        assert!(!matches!(
            round_trip(raw.as_bytes()),
            Err(HttpError::BodyTooLarge { .. })
        ));
    }

    /// Endless headers are capped too, which `specs/11` does not give a number
    /// for but which is the same class of problem.
    #[test]
    fn endless_headers_are_capped() {
        let mut raw = b"POST /x HTTP/1.1\r\n".to_vec();
        for i in 0..2000 {
            raw.extend_from_slice(format!("X-Pad-{i}: {}\r\n", "a".repeat(64)).as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        assert!(matches!(round_trip(&raw), Err(HttpError::HeadersTooLarge)));
    }

    #[test]
    fn a_malformed_request_line_is_an_error_not_a_panic() {
        assert!(matches!(
            round_trip(b"GARBAGE\r\n\r\n"),
            Err(HttpError::Malformed(_))
        ));
        assert!(matches!(
            round_trip(b"POST /x HTTP/1.1\r\nContent-Length: abc\r\n\r\n"),
            Err(HttpError::Malformed(_))
        ));
    }

    #[test]
    fn an_immediate_close_is_reported_as_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let _ = TcpStream::connect(addr);
        });
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        let mut reader = BufReader::new(stream);
        assert!(matches!(read_request(&mut reader), Err(HttpError::Closed)));
    }

    /// A kept-alive connection that goes quiet reads as closed, not as a bad
    /// request. Answering an idle timeout would put a reply in the stream that
    /// the client reads as the answer to whatever it sends next.
    #[test]
    fn a_connection_that_goes_quiet_is_closed_not_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let s = TcpStream::connect(addr).unwrap();
            // Connected, and then nothing at all.
            std::thread::sleep(std::time::Duration::from_millis(400));
            drop(s);
        });

        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        assert!(matches!(read_request(&mut reader), Err(HttpError::Closed)));
        let _ = client.join();
    }

    /// RFC 7230 §6.3, which is also what `wallet2` relies on: an HTTP/1.1
    /// request without a `Connection` header keeps the connection, and that is
    /// what lets epee retry a `401` on the same socket.
    #[test]
    fn the_connection_rules_are_the_version_defaults() {
        let keeps = |raw: &[u8]| round_trip(raw).expect("parse").keep_alive();

        assert!(keeps(b"POST /x HTTP/1.1\r\nHost: x\r\n\r\n"), "1.1 keeps");
        assert!(!keeps(b"POST /x HTTP/1.0\r\nHost: x\r\n\r\n"), "1.0 closes");
        assert!(
            !keeps(b"POST /x HTTP/1.1\r\nConnection: close\r\n\r\n"),
            "1.1 closes when asked"
        );
        assert!(
            keeps(b"POST /x HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n"),
            "1.0 keeps when asked, whatever the case"
        );
        assert!(
            !keeps(b"POST /x HTTP/1.1\r\nConnection: keep-alive, close\r\n\r\n"),
            "close anywhere in the list wins"
        );
    }

    #[test]
    fn the_response_carries_the_length_and_type() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            write_json(&mut stream, 200, "{\"a\":1}", false).unwrap();
        });

        let mut s = TcpStream::connect(addr).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        server.join().unwrap();

        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(out.contains("Content-Type: application/json"));
        assert!(out.contains("Content-Length: 7"));
        assert!(out.contains("Connection: close"));
        assert!(out.ends_with("{\"a\":1}"));
        assert!(
            !out.contains("Access-Control-Allow-Origin"),
            "no wildcard CORS header: {out}"
        );
    }

    /// A kept-alive answer says so, and a body that is not UTF-8 goes out
    /// whole -- `/get_transaction_pool_hashes.bin` sends packed hashes inside
    /// a JSON string.
    #[test]
    fn a_kept_alive_answer_says_so_and_carries_raw_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            write_json_bytes_with(&mut stream, 200, &[0x80, 0xff, 0x00], &[], true).unwrap();
        });

        let mut s = TcpStream::connect(addr).unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        server.join().unwrap();

        let text = String::from_utf8_lossy(&out).to_string();
        assert!(text.contains("Connection: keep-alive"), "{text}");
        assert!(text.contains("Content-Length: 3"), "{text}");
        assert!(out.ends_with(&[0x80, 0xff, 0x00]));
    }
}
