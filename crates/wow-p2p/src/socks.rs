//! A SOCKS5 client, for reaching a peer through a proxy (`specs/08` §7.4).
//!
//! `src/net/socks.cpp` in the C++, and RFC 1928 with RFC 1929's user/password
//! authentication. It is the whole of what `--proxy` and `--tx-proxy` need:
//! open a TCP connection to the proxy, ask it for a connection to somewhere
//! else, and hand back the socket once it says yes.
//!
//! # A name is never resolved here
//!
//! [`Target::Host`] is sent to the proxy as a **domain name**
//! (`ATYP = 3`), never looked up locally. That is the point of the option: a
//! `.onion` or `.b32.i2p` address has no meaning to a resolver, and asking one
//! about a clearnet host would tell it whom this node is about to talk to --
//! the leak `--proxy-allow-dns-leaks` is named after.
//!
//! # SOCKS5 only
//!
//! The C++ takes SOCKS 4, 4a and 5, and treats a bare `ip:port` as 4a
//! (`net::socks::endpoint::get`). Only version 5 is spoken here, because it is
//! the one version that carries both a domain name and a password, and a bare
//! `ip:port` is taken as SOCKS5. Tor's `SocksPort` and i2pd's SOCKS proxy both
//! speak 5, so this reaches the proxies the option exists for; a
//! `socks4://` or `socks4a://` value is refused with a reason rather than
//! quietly spoken to in a dialect it may not answer.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// `P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT`: how long the whole negotiation, the
/// connection to the proxy included, may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(45);

const VERSION: u8 = 5;
const METHOD_NONE: u8 = 0;
const METHOD_USERPASS: u8 = 2;
const AUTH_VERSION: u8 = 1;
const CMD_CONNECT: u8 = 1;
const RESERVED: u8 = 0;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;
const REPLY_SUCCESS: u8 = 0;

/// Where a proxied connection is going.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target<'a> {
    /// An address the proxy is asked for by number.
    Ip(SocketAddr),
    /// A host the proxy resolves itself: a hidden service, or a name this
    /// node must not look up.
    Host(&'a str, u16),
}

impl std::fmt::Display for Target<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Ip(a) => write!(f, "{a}"),
            Target::Host(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

/// A proxy to dial through: `[socks5://][user:pass@]ip:port`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proxy {
    pub address: SocketAddr,
    /// Empty for no authentication, as the C++'s `user_and_pass` is.
    pub user: String,
    pub pass: String,
}

impl Proxy {
    /// Parse the option's value, as `net::socks::endpoint::get` parses it
    /// minus the versions this code does not speak.
    ///
    /// The host must be an address, not a name: resolving the proxy's own
    /// name would be a lookup too, and the C++ takes only a literal here
    /// (`net::get_tcp_endpoint`). `user` and `pass` are percent-decoded, so a
    /// password with an `@` or a `:` in it can be given as `%40` or `%3a`.
    pub fn parse(value: &str) -> Result<Proxy, String> {
        let shape = || format!("`{value}` is not [socks5://][user:pass@]ip:port");
        let rest = match value.split_once("://") {
            None => value,
            Some(("socks5", rest)) => rest,
            Some(("socks" | "socks4" | "socks4a", _)) => {
                return Err(format!(
                    "`{value}`: only SOCKS5 is spoken here; give socks5://ip:port"
                ))
            }
            Some(_) => return Err(shape()),
        };
        // The first `@`, as the C++'s `userinfo_and_hostport` splits on.
        let (userinfo, hostport) = match rest.split_once('@') {
            Some((u, h)) => (u, h),
            None => ("", rest),
        };
        let (user, pass) = match userinfo.split_once(':') {
            Some((u, p)) => (u, p),
            None => (userinfo, ""),
        };
        let user = percent_decode(user).map_err(|e| format!("`{value}`: {e}"))?;
        let pass = percent_decode(pass).map_err(|e| format!("`{value}`: {e}"))?;
        if user.len() > usize::from(u8::MAX) || pass.len() > usize::from(u8::MAX) {
            return Err(format!(
                "`{value}`: a SOCKS5 user and password are at most 255 bytes each"
            ));
        }
        let address: SocketAddr = hostport.parse().map_err(|_| shape())?;
        Ok(Proxy {
            address,
            user,
            pass,
        })
    }

    fn authenticates(&self) -> bool {
        !self.user.is_empty() || !self.pass.is_empty()
    }
}

impl std::fmt::Display for Proxy {
    /// The address, and never the password: this goes into the log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.authenticates() {
            write!(f, "{} (with a user and password)", self.address)
        } else {
            write!(f, "{}", self.address)
        }
    }
}

/// Why a proxied connection did not happen.
#[derive(Debug)]
pub enum SocksError {
    Io(std::io::Error),
    /// The proxy answered with something other than version 5.
    UnexpectedVersion { found: u8 },
    /// The proxy took none of the authentication methods offered.
    NoAcceptableMethod { found: u8 },
    /// The proxy refused the user and password (RFC 1929).
    AuthFailure,
    /// The proxy refused the connection. RFC 1928 §6's reply codes.
    Refused { code: u8 },
    /// A reply this code cannot read -- an address type it never asked about.
    BadReply { found: u8 },
    /// A host name SOCKS5 cannot carry: empty, or longer than its one length
    /// byte allows.
    BadHost { len: usize },
}

impl std::fmt::Display for SocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocksError::Io(e) => write!(f, "io: {e}"),
            SocksError::UnexpectedVersion { found } => {
                write!(f, "the proxy replied with version {found}, not 5")
            }
            SocksError::NoAcceptableMethod { found } => write!(
                f,
                "the proxy chose authentication method {found}, which was not offered"
            ),
            SocksError::AuthFailure => f.write_str("the proxy refused the user and password"),
            // The C++'s `socks_category::message`, code for code.
            SocksError::Refused { code } => match code {
                1 => f.write_str("socks general server failure"),
                2 => f.write_str("socks connection not allowed by ruleset"),
                3 => f.write_str("socks network unreachable"),
                4 => f.write_str("socks host unreachable"),
                5 => f.write_str("socks connection refused"),
                6 => f.write_str("socks TTL expired"),
                7 => f.write_str("socks command not supported"),
                8 => f.write_str("socks address type not supported"),
                other => write!(f, "the proxy refused the connection (code {other})"),
            },
            SocksError::BadReply { found } => {
                write!(f, "the proxy replied with address type {found}")
            }
            SocksError::BadHost { len: 0 } => {
                f.write_str("an empty host name cannot be sent to a proxy")
            }
            SocksError::BadHost { len } => {
                write!(f, "a host name of {len} bytes does not fit a SOCKS5 request")
            }
        }
    }
}

impl std::error::Error for SocksError {}

impl From<std::io::Error> for SocksError {
    fn from(e: std::io::Error) -> SocksError {
        SocksError::Io(e)
    }
}

/// Open a connection to `target` through `proxy`.
///
/// `timeout` bounds the connection to the proxy and each read and write of
/// the negotiation. The returned socket has no timeouts of its own left set,
/// as a freshly connected one has none, so the caller's are what apply.
pub fn connect(
    proxy: &Proxy,
    target: Target<'_>,
    timeout: Duration,
) -> Result<TcpStream, SocksError> {
    let mut stream = TcpStream::connect_timeout(&proxy.address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let _ = stream.set_nodelay(true);
    negotiate(&mut stream, proxy, target)?;
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(stream)
}

/// The greeting, the optional authentication and the CONNECT request, each
/// waited for in turn.
///
/// The C++ pipelines all three into one buffer. They are sent in step here:
/// a proxy is free to answer the greeting before reading further, and nothing
/// is gained by guessing which method it will choose.
fn negotiate(stream: &mut TcpStream, proxy: &Proxy, target: Target<'_>) -> Result<(), SocksError> {
    let greeting: &[u8] = if proxy.authenticates() {
        &[VERSION, 2, METHOD_NONE, METHOD_USERPASS]
    } else {
        &[VERSION, 1, METHOD_NONE]
    };
    stream.write_all(greeting)?;

    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen)?;
    if chosen[0] != VERSION {
        return Err(SocksError::UnexpectedVersion { found: chosen[0] });
    }
    match chosen[1] {
        METHOD_NONE => {}
        METHOD_USERPASS if proxy.authenticates() => authenticate(stream, proxy)?,
        // RFC 1928's `0xff` is "no acceptable methods"; anything else is a
        // method this client never offered and would not know how to speak.
        found => return Err(SocksError::NoAcceptableMethod { found }),
    }

    stream.write_all(&request(target)?)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != VERSION {
        return Err(SocksError::UnexpectedVersion { found: head[0] });
    }
    if head[1] != REPLY_SUCCESS {
        return Err(SocksError::Refused { code: head[1] });
    }
    // The address the proxy bound. Nothing here wants it, but it is part of
    // the reply and has to come off the socket before the peer's first byte.
    let left = match head[3] {
        ATYP_IPV4 => 4 + 2,
        ATYP_IPV6 => 16 + 2,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            usize::from(len[0]) + 2
        }
        found => return Err(SocksError::BadReply { found }),
    };
    let mut bound = vec![0u8; left];
    stream.read_exact(&mut bound)?;
    Ok(())
}

/// RFC 1929: the user and password, and a one-byte status in reply.
fn authenticate(stream: &mut TcpStream, proxy: &Proxy) -> Result<(), SocksError> {
    let mut out = Vec::with_capacity(3 + proxy.user.len() + proxy.pass.len());
    out.push(AUTH_VERSION);
    // The lengths fit a byte: `Proxy::parse` refuses longer ones.
    out.push(proxy.user.len() as u8);
    out.extend_from_slice(proxy.user.as_bytes());
    out.push(proxy.pass.len() as u8);
    out.extend_from_slice(proxy.pass.as_bytes());
    stream.write_all(&out)?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    if reply[0] != AUTH_VERSION {
        return Err(SocksError::UnexpectedVersion { found: reply[0] });
    }
    if reply[1] != 0 {
        return Err(SocksError::AuthFailure);
    }
    Ok(())
}

/// A CONNECT request for `target`. The port is big-endian, as every length
/// and port in SOCKS is.
fn request(target: Target<'_>) -> Result<Vec<u8>, SocksError> {
    let mut out = vec![VERSION, CMD_CONNECT, RESERVED];
    match target {
        Target::Ip(SocketAddr::V4(a)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(a)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Host(host, port) => {
            if host.is_empty() || host.len() > usize::from(u8::MAX) {
                return Err(SocksError::BadHost { len: host.len() });
            }
            out.push(ATYP_DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(out)
}

/// `%40` into `@`, as `net::parse.cpp`'s `percent_decoding` does, so a
/// password may hold the characters the syntax uses.
fn percent_decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'%' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        if i + 2 >= b.len() {
            return Err("a `%` with fewer than two hex digits after it".into());
        }
        let pair = &s[i + 1..i + 3];
        let byte = wow_crypto::hex::decode(pair)
            .and_then(|v| v.first().copied())
            .ok_or_else(|| format!("`%{pair}` is not a hex escape"))?;
        out.push(byte);
        i += 3;
    }
    String::from_utf8(out).map_err(|_| "the user or password is not UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc::{channel, Receiver};

    /// What one step of [`fake_proxy`]'s script reads, and answers with.
    struct Step {
        read: usize,
        reply: Vec<u8>,
    }

    fn step(read: usize, reply: Vec<u8>) -> Step {
        Step { read, reply }
    }

    /// A success reply naming 0.0.0.0:0 as the address the proxy bound.
    fn granted() -> Vec<u8> {
        vec![VERSION, REPLY_SUCCESS, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
    }

    /// A proxy that plays a script: it reads what the client sends, records
    /// it, and answers. After the last step it writes `tail`, standing in for
    /// the peer's own first bytes.
    fn fake_proxy(script: Vec<Step>, tail: Vec<u8>) -> (SocketAddr, Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            for s in script {
                let mut buf = vec![0u8; s.read];
                if stream.read_exact(&mut buf).is_err() {
                    return;
                }
                let _ = tx.send(buf);
                if stream.write_all(&s.reply).is_err() {
                    return;
                }
            }
            let _ = stream.write_all(&tail);
            // Held open until the client has read what it was sent.
            std::thread::sleep(Duration::from_millis(500));
        });
        (addr, rx)
    }

    fn plain(address: SocketAddr) -> Proxy {
        Proxy {
            address,
            user: String::new(),
            pass: String::new(),
        }
    }

    fn login(address: SocketAddr, user: &str, pass: &str) -> Proxy {
        Proxy {
            address,
            user: user.to_string(),
            pass: pass.to_string(),
        }
    }

    fn dial(proxy: &Proxy, target: Target<'_>) -> Result<TcpStream, SocksError> {
        connect(proxy, target, Duration::from_secs(5))
    }

    /// **The reason this exists.** A hidden service is asked for by name, so
    /// no resolver ever sees it: `ATYP = 3`, the host as it was written, and
    /// the port big-endian.
    #[test]
    fn a_hidden_service_is_asked_for_by_name() {
        let script = vec![
            step(3, vec![VERSION, METHOD_NONE]),
            step(4 + 1 + 7 + 2, granted()),
        ];
        let (addr, sent) = fake_proxy(script, b"hi".to_vec());
        let target = Target::Host("x.onion", 34_567);
        let mut stream = dial(&plain(addr), target).expect("the proxy said yes");

        assert_eq!(sent.recv().unwrap(), vec![VERSION, 1, METHOD_NONE]);
        let mut want = vec![VERSION, CMD_CONNECT, RESERVED, ATYP_DOMAIN, 7];
        want.extend_from_slice(b"x.onion");
        want.extend_from_slice(&34_567u16.to_be_bytes());
        assert_eq!(sent.recv().unwrap(), want);

        // The bound address was consumed, so what follows is the peer's.
        let timeout = Some(Duration::from_secs(5));
        stream.set_read_timeout(timeout).unwrap();
        let mut peer = [0u8; 2];
        stream.read_exact(&mut peer).expect("the peer's bytes");
        assert_eq!(&peer, b"hi");
    }

    /// An IPv4 target goes as `ATYP = 1`, with the octets in order.
    #[test]
    fn an_address_goes_as_four_octets() {
        let script = vec![
            step(3, vec![VERSION, METHOD_NONE]),
            step(4 + 4 + 2, granted()),
        ];
        let (addr, sent) = fake_proxy(script, Vec::new());
        let target = Target::Ip("10.20.30.40:1234".parse().unwrap());
        dial(&plain(addr), target).expect("the proxy said yes");

        let _ = sent.recv().unwrap();
        let mut want = vec![VERSION, CMD_CONNECT, RESERVED, ATYP_IPV4];
        want.extend_from_slice(&[10, 20, 30, 40]);
        want.extend_from_slice(&1234u16.to_be_bytes());
        assert_eq!(sent.recv().unwrap(), want);
    }

    /// With a user and password both methods are offered, and RFC 1929's
    /// exchange follows when the proxy asks for it.
    #[test]
    fn a_user_and_password_are_offered_and_sent() {
        let script = vec![
            step(4, vec![VERSION, METHOD_USERPASS]),
            step(1 + 1 + 3 + 1 + 6, vec![AUTH_VERSION, 0]),
            step(4 + 4 + 2, granted()),
        ];
        let (addr, sent) = fake_proxy(script, Vec::new());
        let target = Target::Ip("127.0.0.1:1".parse().unwrap());
        let proxy = login(addr, "bob", "secret");
        dial(&proxy, target).expect("the proxy said yes");

        let offered = vec![VERSION, 2, METHOD_NONE, METHOD_USERPASS];
        assert_eq!(sent.recv().unwrap(), offered);
        let mut want = vec![AUTH_VERSION, 3];
        want.extend_from_slice(b"bob");
        want.push(6);
        want.extend_from_slice(b"secret");
        assert_eq!(sent.recv().unwrap(), want);
    }

    #[test]
    fn a_refused_password_says_so() {
        let script = vec![
            step(4, vec![VERSION, METHOD_USERPASS]),
            step(1 + 1 + 1 + 1 + 1, vec![AUTH_VERSION, 1]),
        ];
        let (addr, _sent) = fake_proxy(script, Vec::new());
        let target = Target::Ip("127.0.0.1:1".parse().unwrap());
        let e = dial(&login(addr, "a", "b"), target).expect_err("refused");
        assert!(matches!(e, SocksError::AuthFailure), "{e}");
    }

    /// A refusal carries the proxy's reason, in the C++'s words.
    #[test]
    fn a_refused_connection_says_why() {
        let refusal = vec![VERSION, 4, 0, ATYP_IPV4];
        let script = vec![
            step(3, vec![VERSION, METHOD_NONE]),
            step(4 + 1 + 7 + 2, refusal),
        ];
        let (addr, _sent) = fake_proxy(script, Vec::new());
        let target = Target::Host("x.onion", 1);
        let e = dial(&plain(addr), target).expect_err("refused");
        assert!(matches!(e, SocksError::Refused { code: 4 }), "{e}");
        assert!(e.to_string().contains("host unreachable"));
    }

    /// A proxy that answers in another version, or picks a method nobody
    /// offered, is an error rather than a stream nothing can read.
    #[test]
    fn a_proxy_that_answers_wrongly_is_refused() {
        let target = Target::Host("x.onion", 1);

        let script = vec![step(3, vec![4, METHOD_NONE])];
        let (addr, _sent) = fake_proxy(script, Vec::new());
        let e = dial(&plain(addr), target).expect_err("not version 5");
        assert!(matches!(e, SocksError::UnexpectedVersion { found: 4 }), "{e}");

        let script = vec![step(3, vec![VERSION, METHOD_USERPASS])];
        let (addr, _sent) = fake_proxy(script, Vec::new());
        let e = dial(&plain(addr), target).expect_err("a method never offered");
        assert!(matches!(e, SocksError::NoAcceptableMethod { found: 2 }), "{e}");

        // RFC 1928's "no acceptable methods".
        let script = vec![step(3, vec![VERSION, 0xff])];
        let (addr, _sent) = fake_proxy(script, Vec::new());
        let e = dial(&plain(addr), target).expect_err("no method in common");
        assert!(
            matches!(e, SocksError::NoAcceptableMethod { found: 0xff }),
            "{e}"
        );
    }

    #[test]
    fn a_proxy_value_is_parsed_as_the_cpp_parses_it() {
        let tor: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        assert_eq!(Proxy::parse("127.0.0.1:9050").unwrap(), plain(tor));
        assert_eq!(Proxy::parse("socks5://127.0.0.1:9050").unwrap(), plain(tor));
        let v6: SocketAddr = "[::1]:9050".parse().unwrap();
        assert_eq!(Proxy::parse("[::1]:9050").unwrap(), plain(v6));

        let p = Proxy::parse("socks5://bob:s%40cret@127.0.0.1:9050").unwrap();
        assert_eq!((p.user.as_str(), p.pass.as_str()), ("bob", "s@cret"));
        assert!(p.authenticates());
        // A user with no password, as `user_and_pass::get` reads one.
        let p = Proxy::parse("bob@127.0.0.1:9050").unwrap();
        assert_eq!((p.user.as_str(), p.pass.as_str()), ("bob", ""));
        assert!(!plain(tor).authenticates());

        // The password never reaches the log.
        let p = Proxy::parse("bob:hunter2@127.0.0.1:9050").unwrap();
        assert_eq!(p.to_string(), "127.0.0.1:9050 (with a user and password)");
        assert_eq!(plain(tor).to_string(), "127.0.0.1:9050");

        for bad in [
            "socks4a://127.0.0.1:9050",
            "socks4://127.0.0.1:9050",
            "http://127.0.0.1:9050",
            "localhost:9050",
            "127.0.0.1",
            "",
            "bob:%zz@127.0.0.1:9050",
            "bob:%4@127.0.0.1:9050",
        ] {
            assert!(Proxy::parse(bad).is_err(), "`{bad}` should be refused");
        }
        let e = Proxy::parse("socks4://127.0.0.1:9050").unwrap_err();
        assert!(e.contains("only SOCKS5"), "{e}");
    }

    #[test]
    fn a_host_a_request_cannot_carry_is_refused() {
        let long = "a".repeat(256);
        let e = request(Target::Host(&long, 1)).expect_err("too long");
        assert!(matches!(e, SocksError::BadHost { len: 256 }), "{e}");
        let e = request(Target::Host("", 1)).expect_err("empty");
        assert!(matches!(e, SocksError::BadHost { len: 0 }), "{e}");
        assert!(e.to_string().contains("empty host name"));
    }
}

