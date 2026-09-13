//! A minimal HTTP/1.1 server.
//!
//! `specs/11-daemon-rpc.md` §1. Only what the RPC surface needs: `POST` with a
//! `Content-Length` body, and a JSON response. No chunked encoding and no
//! keep-alive pipelining. TLS is below this layer: it reads and writes
//! whatever stream it is handed, plain or `super::tls`'s.
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
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// A parsed request.
#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
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

/// Read one request from a connection whose timeouts are already set.
pub fn read_request<S: Read>(stream: &mut S) -> Result<Request, HttpError> {
    let mut reader = BufReader::new(stream);
    let mut header_bytes = 0usize;

    // Request line.
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(HttpError::Closed);
    }
    header_bytes += line.len();

    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or(HttpError::Malformed("no method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or(HttpError::Malformed("no path"))?
        .to_string();

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
        headers,
        body,
    })
}

/// Write a JSON response.
pub fn write_json(stream: &mut impl Write, status: u16, body: &str) -> std::io::Result<()> {
    write_response(stream, status, "application/json", body.as_bytes(), &[])
}

/// Write a JSON response with extra headers, such as a Digest challenge or a
/// CORS grant.
pub fn write_json_with(
    stream: &mut impl Write,
    status: u16,
    body: &str,
    headers: &[(&str, String)],
) -> std::io::Result<()> {
    write_response(stream, status, "application/json", body.as_bytes(), headers)
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
) -> std::io::Result<()> {
    write_response(stream, status, "application/octet-stream", body, headers)
}

fn write_response(
    stream: &mut impl Write,
    status: u16,
    content_type: &str,
    body: &[u8],
    headers: &[(&str, String)],
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
         Connection: close\r\n",
        body.len()
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

        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        let out = read_request(&mut stream);
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
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        assert!(matches!(read_request(&mut stream), Err(HttpError::Closed)));
    }

    #[test]
    fn the_response_carries_the_length_and_type() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            write_json(&mut stream, 200, "{\"a\":1}").unwrap();
        });

        let mut s = TcpStream::connect(addr).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        server.join().unwrap();

        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(out.contains("Content-Type: application/json"));
        assert!(out.contains("Content-Length: 7"));
        assert!(out.ends_with("{\"a\":1}"));
        assert!(
            !out.contains("Access-Control-Allow-Origin"),
            "no wildcard CORS header: {out}"
        );
    }
}
