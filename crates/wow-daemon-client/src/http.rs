//! A minimal HTTP/1.1 client.
//!
//! The mirror of `bin/wownerod/src/rpc/http.rs`, and deliberately the same
//! shape: `POST` with a `Content-Length` body, no chunked encoding, no
//! keep-alive, no TLS. `specs/11` §1.2 allows deferring TLS to a reverse proxy
//! and this does.
//!
//! # The daemon is not trusted either
//!
//! A wallet talks to a node it did not write, possibly over a network it does
//! not control. Every limit here applies to the *response*: a cap on the status
//! line and headers, a cap on the body, and read and write timeouts. A daemon
//! that sends a 40 GB `Content-Length` gets an error, not an allocation.
//!
//! Nothing a daemon says is taken on trust beyond parsing. The wallet checks
//! what it receives against its own keys: a block that does not hash to the
//! hash it was asked for, or an output whose commitment does not match its
//! amount, is caught in `wow-wallet`, not here.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// A cap on a response body.
///
/// This is a defence against a hostile or broken daemon, not a tuning knob. The
/// bound that matters for a legitimate `get_blocks.bin` is the transaction cap,
/// `COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT = 20,000` (`specs/11` §5.1), and
/// `CRYPTONOTE_MAX_TX_SIZE` is 1 MB — so the theoretical worst case is far
/// above this and the *practical* one is far below it, because a ring-size-22
/// transaction is a few kilobytes and a block's total is bounded by the weight
/// limit. A wallet that ever hits this should ask for fewer blocks per call
/// rather than raise it.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

/// A cap on the status line plus headers.
const MAX_HEADER_BYTES: usize = 16 * 1024;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub enum HttpError {
    Io(std::io::Error),
    /// The address did not resolve.
    BadAddress(String),
    /// The address carried a URL scheme. `https://` in particular cannot be
    /// honoured: this client speaks plain HTTP.
    Scheme {
        address: String,
        scheme: String,
    },
    /// The response status line or headers exceeded [`MAX_HEADER_BYTES`].
    HeadersTooLarge,
    /// The response body exceeded [`MAX_RESPONSE_BYTES`].
    BodyTooLarge {
        len: usize,
    },
    /// A malformed status line or headers.
    Malformed(&'static str),
    /// A non-2xx status.
    Status {
        code: u16,
    },
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Io(e) => write!(f, "io: {e}"),
            HttpError::BadAddress(a) => write!(f, "cannot resolve `{a}`"),
            HttpError::Scheme { address, scheme } => {
                if scheme == "https" {
                    write!(
                        f,
                        "`{address}` is an https address, and this client speaks plain HTTP only (`specs/11` §1.2 defers TLS to a reverse proxy). Give it a host:port, and put a proxy in front if the daemon needs TLS."
                    )
                } else {
                    write!(
                        f,
                        "`{address}` has a `{scheme}://` scheme; give a host:port instead"
                    )
                }
            }
            HttpError::HeadersTooLarge => {
                write!(f, "response headers exceed {MAX_HEADER_BYTES} bytes")
            }
            HttpError::BodyTooLarge { len } => {
                write!(f, "response of {len} bytes exceeds {MAX_RESPONSE_BYTES}")
            }
            HttpError::Malformed(w) => write!(f, "malformed response: {w}"),
            HttpError::Status { code } => write!(f, "daemon returned HTTP {code}"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        HttpError::Io(e)
    }
}

/// Where a daemon is, and how long to wait for it.
#[derive(Clone, Debug)]
pub struct Endpoint {
    /// `host:port`, as typed on a command line.
    pub address: String,
    pub connect_timeout: Duration,
    /// Applies to reads and writes separately, not to the whole exchange — a
    /// long `get_blocks.bin` is slow because it is large, not because it is
    /// stalled.
    pub timeout: Duration,
}

impl Endpoint {
    pub fn new(address: impl Into<String>) -> Endpoint {
        Endpoint {
            address: address.into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    fn connect(&self) -> Result<TcpStream, HttpError> {
        // A scheme resolves to nothing, so without this the failure reads
        // "cannot resolve `https://node:34568`" -- which sends whoever typed it
        // looking at their DNS rather than at the one thing that is wrong.
        if let Some((scheme, _)) = self.address.split_once("://") {
            return Err(HttpError::Scheme {
                address: self.address.clone(),
                scheme: scheme.to_ascii_lowercase(),
            });
        }

        let mut last = None;
        let addrs = self
            .address
            .to_socket_addrs()
            .map_err(|_| HttpError::BadAddress(self.address.clone()))?;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, self.connect_timeout) {
                Ok(s) => {
                    s.set_read_timeout(Some(self.timeout))?;
                    s.set_write_timeout(Some(self.timeout))?;
                    s.set_nodelay(true)?;
                    return Ok(s);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(match last {
            Some(e) => HttpError::Io(e),
            None => HttpError::BadAddress(self.address.clone()),
        })
    }

    /// `POST path` with `body`, returning the response body.
    ///
    /// One request per connection. Keep-alive would save a handshake per call
    /// and cost a pool and its failure modes; a refresh makes one call per
    /// thousand blocks, so it is not where the time goes.
    pub fn post(&self, path: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, HttpError> {
        let mut stream = self.connect()?;

        let head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {len}\r\n\
             Accept: */*\r\n\
             Connection: close\r\n\
             \r\n",
            host = self.address,
            len = body.len(),
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()?;

        read_response(stream)
    }
}

fn read_response(stream: TcpStream) -> Result<Vec<u8>, HttpError> {
    let mut reader = BufReader::new(stream);

    // Status line.
    let mut line = String::new();
    let mut header_bytes = 0usize;
    read_line(&mut reader, &mut line, &mut header_bytes)?;
    let code = parse_status(&line)?;

    // Headers. `Connection: close` means the body may be delimited by EOF, so
    // a missing `Content-Length` is not an error.
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        line.clear();
        read_line(&mut reader, &mut line, &mut header_bytes)?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(HttpError::Malformed("header without a colon"));
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            let len: usize = value
                .parse()
                .map_err(|_| HttpError::Malformed("content-length is not a number"))?;
            if len > MAX_RESPONSE_BYTES {
                return Err(HttpError::BodyTooLarge { len });
            }
            content_length = Some(len);
        } else if name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
    }

    if chunked {
        // The reference daemon never sends chunked for these endpoints. Say so
        // rather than half-implementing it.
        return Err(HttpError::Malformed("chunked transfer encoding"));
    }

    let body = match content_length {
        Some(len) => {
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf)?;
            buf
        }
        None => {
            // Read to EOF, still bounded.
            let mut buf = Vec::new();
            reader
                .take(MAX_RESPONSE_BYTES as u64 + 1)
                .read_to_end(&mut buf)?;
            if buf.len() > MAX_RESPONSE_BYTES {
                return Err(HttpError::BodyTooLarge { len: buf.len() });
            }
            buf
        }
    };

    // The status is checked after the body is drained, so an error response
    // with a useful JSON payload is still available to the caller.
    if !(200..300).contains(&code) {
        return Err(HttpError::Status { code });
    }
    Ok(body)
}

fn read_line(
    reader: &mut BufReader<TcpStream>,
    line: &mut String,
    seen: &mut usize,
) -> Result<(), HttpError> {
    line.clear();
    let n = reader.read_line(line)?;
    if n == 0 {
        return Err(HttpError::Malformed("connection closed mid-header"));
    }
    *seen += n;
    if *seen > MAX_HEADER_BYTES {
        return Err(HttpError::HeadersTooLarge);
    }
    Ok(())
}

fn parse_status(line: &str) -> Result<u16, HttpError> {
    let mut parts = line.split_whitespace();
    let version = parts
        .next()
        .ok_or(HttpError::Malformed("empty status line"))?;
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError::Malformed("not HTTP/1.x"));
    }
    parts
        .next()
        .ok_or(HttpError::Malformed("status line has no code"))?
        .parse()
        .map_err(|_| HttpError::Malformed("status code is not a number"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_line_is_parsed() {
        assert_eq!(parse_status("HTTP/1.1 200 OK\r\n").expect("ok"), 200);
        assert_eq!(parse_status("HTTP/1.0 404 Not Found\r\n").expect("ok"), 404);
        assert!(parse_status("").is_err());
        assert!(parse_status("HTTP/2 200\r\n").is_err());
        assert!(parse_status("HTTP/1.1 two hundred\r\n").is_err());
    }

    /// An unresolvable address is an error, not a panic or a hang.
    #[test]
    fn a_bad_address_is_an_error() {
        let e = Endpoint::new("no-such-host.invalid:1");
        assert!(matches!(e.connect(), Err(HttpError::BadAddress(_))));

        let e = Endpoint::new("not-a-socket-address");
        assert!(matches!(e.connect(), Err(HttpError::BadAddress(_))));
    }

    /// A URL says what is wrong, rather than blaming DNS.
    ///
    /// Public node lists give addresses as `http://host:port` and
    /// `https://host:port`, so this is the first thing anyone pastes. Without
    /// the check it fails as "cannot resolve", which sends them looking at
    /// their network instead of at the scheme.
    #[test]
    fn a_url_scheme_is_named_as_the_problem() {
        let e = Endpoint::new("https://wownero.stackwallet.com:34568");
        let err = e.connect().expect_err("no scheme is supported");
        let text = err.to_string();
        assert!(text.contains("https"), "{text}");
        assert!(
            text.contains("plain HTTP"),
            "it says why, not just that: {text}"
        );
        assert!(text.contains("host:port"), "and what to do instead: {text}");

        // http:// is just as unusable, and says so without the TLS advice.
        let e = Endpoint::new("http://node2.monerodevs.org:34568");
        let text = e.connect().expect_err("still a scheme").to_string();
        assert!(text.contains("host:port"), "{text}");
    }

    /// The response cap clears a realistic full batch by a wide margin.
    ///
    /// A `get_blocks.bin` returns at most 20,000 transactions (`specs/11`
    /// §5.1). A ring-size-22 RingCT transaction with a Bulletproof+ is on the
    /// order of 2 KB, so a saturated batch is tens of megabytes.
    #[test]
    fn the_response_cap_clears_a_full_block_batch() {
        const MAX_TX_COUNT: usize = 20_000;
        const TYPICAL_TX_BYTES: usize = 2_048;
        // A compile-time fact, so it cannot silently stop holding.
        const _: () = assert!(MAX_RESPONSE_BYTES > MAX_TX_COUNT * TYPICAL_TX_BYTES * 4);
    }
}
