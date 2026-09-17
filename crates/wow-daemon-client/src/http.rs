//! A minimal HTTP/1.1 client.
//!
//! The mirror of `bin/wownerod/src/rpc/http.rs`, and deliberately the same
//! shape: `POST` with a `Content-Length` body. Unlike it, a connection is kept
//! for the next call when the framing allows (see `Response::reusable`).
//!
//! An address is `host:port`, as typed on a command line, or that with
//! `http://` or `https://` in front. `https://` is TLS (`specs/11` §1.2), on
//! the node's own pure-Rust provider, with the certificate checked as
//! [`Certificates`] says, or no connection.
//!
//! Any other address is reached as [`TlsMode`] says, which is what
//! `--daemon-ssl` says: by default TLS if the node speaks it and plain HTTP if
//! not, as the C++'s autodetect does (`net_helper.h`, `connect`). The scheme
//! only gives the port, as in the C++. Two things differ from it, both in the
//! wallet's favour: falling back to plain HTTP is logged as a warning rather
//! than as an error nobody sees, and a node that has spoken TLS once to an
//! [`Endpoint`] is never spoken to in the clear by it again, so a connection
//! cut during a handshake cannot quietly turn into a plain one.
//!
//! A reply may come back chunked. A daemon never sends one, but the reverse
//! proxy §1.2 lets a node sit behind may: nginx and Cloudflare both re-frame a
//! node's replies as chunks.
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
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
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

/// The C++ HTTP client's log category, so one `--log-level` means the same to
/// both.
const LOG: &str = "net.http";

/// What a binary request is, to a [`Transport`] that has to say.
///
/// [`Endpoint`] does not say it: epee's `invoke_http_bin` sends no
/// `Content-Type` at all, and a request that carries one is a request no C++
/// wallet made.
pub const BINARY_CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Debug)]
pub enum HttpError {
    Io(std::io::Error),
    /// The address did not resolve.
    BadAddress(String),
    /// The address carried a URL scheme other than `http://` or `https://`.
    Scheme {
        address: String,
        scheme: String,
    },
    /// TLS failed: most often, a certificate that is not trusted.
    Tls(String),
    /// The response status line or headers exceeded [`MAX_HEADER_BYTES`].
    HeadersTooLarge,
    /// The response body exceeded [`MAX_RESPONSE_BYTES`].
    BodyTooLarge {
        len: usize,
    },
    /// A malformed status line or headers.
    Malformed(&'static str),
    /// The connection closed before the body `Content-Length` promised had
    /// all arrived.
    Truncated {
        got: usize,
        expected: usize,
    },
    /// A non-2xx status.
    Status {
        code: u16,
    },
    /// `401`, with the `WWW-Authenticate` header it came with when it had one.
    ///
    /// Its own variant because it is the only status a caller can do something
    /// about: answer the challenge. [`Endpoint::exchange`] handles it and this
    /// never reaches a caller with a login configured — one without a login
    /// gets [`HttpError::Status`] with 401, as before.
    Unauthorized {
        challenge: Option<String>,
    },
    /// The daemon refused the credentials it was given.
    BadLogin {
        user: String,
    },
    /// A [`Transport`] other than [`Endpoint`] failed, in its own words: a
    /// browser refusing a cross-origin request, say.
    Transport(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Io(e) => write!(f, "io: {e}"),
            HttpError::BadAddress(a) => write!(f, "cannot resolve `{a}`"),
            HttpError::Scheme { address, scheme } => write!(
                f,
                "`{address}` has a `{scheme}://` scheme; use http:// or https://, or give a \
                 host:port"
            ),
            HttpError::Tls(what) => write!(f, "TLS: {what}"),
            HttpError::HeadersTooLarge => {
                write!(f, "response headers exceed {MAX_HEADER_BYTES} bytes")
            }
            HttpError::BodyTooLarge { len } => {
                write!(f, "response of {len} bytes exceeds {MAX_RESPONSE_BYTES}")
            }
            HttpError::Malformed(w) => write!(f, "malformed response: {w}"),
            HttpError::Truncated { got, expected } => write!(
                f,
                "the connection closed after {got} of {expected} body bytes"
            ),
            HttpError::Status { code } => write!(f, "daemon returned HTTP {code}"),
            HttpError::Unauthorized { .. } => write!(
                f,
                "the daemon wants a login (it was started with --rpc-login); give one with \
                 --daemon-login <user>:<password>"
            ),
            HttpError::BadLogin { user } => write!(
                f,
                "the daemon refused the login for `{user}`. Check the user name and the \
                 password: three wrong attempts and it blocks this address for a day, \
                 unless it was started with --disable-rpc-ban"
            ),
            HttpError::Transport(what) => write!(f, "{what}"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        match crate::tls::describe(&e) {
            Some(what) => HttpError::Tls(what),
            None => HttpError::Io(e),
        }
    }
}

/// How a request reaches a daemon.
///
/// [`Endpoint`] is this crate's: a socket, and HTTP/1.1 over it. A program with
/// no sockets to open, such as a wallet in a browser, supplies one over `fetch`
/// instead ([`crate::DaemonClient::with_transport`]).
///
/// An implementation holds to the limits [`Endpoint`] does: a body over
/// [`MAX_RESPONSE_BYTES`] is an error rather than an allocation, and a non-2xx
/// status is [`HttpError::Status`].
pub trait Transport: std::fmt::Debug + Send + Sync {
    /// `POST path` with `body`, returning the response body.
    fn post(&self, path: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, HttpError>;

    /// Where the daemon is, as it was given.
    fn address(&self) -> &str;

    /// How the connection to the daemon was last made, when this transport
    /// knows: `None` for one whose TLS is somebody else's, as a browser's is.
    fn security(&self) -> Option<Security> {
        None
    }
}

impl Transport for Endpoint {
    fn post(&self, path: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, HttpError> {
        Endpoint::post(self, path, content_type, body)
    }

    fn address(&self) -> &str {
        &self.address
    }

    fn security(&self) -> Option<Security> {
        Endpoint::security(self)
    }
}

/// `--daemon-ssl`: how a node given as `host:port`, or with `http://`, is
/// reached. `https://` is always TLS, checked, whatever this says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsMode {
    /// TLS if the node speaks it, and plain HTTP if it does not, with a
    /// warning: the C++'s default. A certificate that does not check out is
    /// still taken, as the C++'s verify callback takes it under autodetect,
    /// and [`Security`] says so: the connection is encrypted, but nothing
    /// says who is at the other end of it.
    #[default]
    Autodetect,
    /// TLS with the certificate checked, or no connection.
    Enabled,
    /// Plain HTTP.
    Disabled,
}

impl TlsMode {
    /// `ssl_support_from_string`.
    pub fn parse(text: &str) -> Option<TlsMode> {
        match text {
            "autodetect" => Some(TlsMode::Autodetect),
            "enabled" => Some(TlsMode::Enabled),
            "disabled" => Some(TlsMode::Disabled),
            _ => None,
        }
    }
}

/// How the connection to a node was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    /// TLS; `verified` when the node's certificate checked out as
    /// [`Certificates`] says, and not when any was accepted.
    Tls { verified: bool },
    /// Plain HTTP; `fell_back` when TLS was tried and the node did not speak
    /// it, or something on the way stopped it.
    Plain { fell_back: bool },
}

/// How a TLS connection checks the certificate it is shown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Certificates {
    /// Against the Mozilla roots, for the host's name, as a browser checks it.
    #[default]
    Checked,
    /// Any certificate: a node's self-signed one, as the C++'s
    /// `--daemon-ssl-allow-any-cert`. The connection is still encrypted, but
    /// nothing says who is at the other end of it.
    Any,
    /// Only certificates named ahead: `--daemon-ssl-allowed-fingerprints` and
    /// `--daemon-ssl-ca-certificates`.
    Pinned(Pins),
}

/// The certificates a node may show, named ahead: the C++'s
/// `ssl_verification_t::user_certificates`, and `user_ca` with
/// `allow_chained`. No name is checked, as the C++ checks none for these.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pins {
    /// SHA-256 fingerprints of certificates a node may show.
    pub fingerprints: Vec<[u8; 32]>,
    /// The CA file's certificates, as DER. A node's certificate that is one
    /// of them is accepted.
    pub ca: Vec<Vec<u8>>,
    /// `--daemon-ssl-allow-chained`: and one that chains to one of them.
    pub allow_chained: bool,
}

/// `--daemon-ssl-certificate` and `--daemon-ssl-private-key`: the certificate
/// this wallet shows a node that asks for one, as PEM files. Read when a
/// connection is made, as the C++ reads them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientCertificate {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

/// How a node is reached, whatever its address: what the `--daemon-ssl`
/// options say.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectOptions {
    pub tls: TlsMode,
    pub certificates: Certificates,
    pub client_certificate: Option<ClientCertificate>,
}

/// The `--daemon-ssl` options as given, before they are made sense of.
#[derive(Clone, Debug, Default)]
pub struct SslFlags {
    /// `--daemon-ssl`, `None` when not given.
    pub ssl: Option<String>,
    pub private_key: Option<PathBuf>,
    pub certificate: Option<PathBuf>,
    pub ca_certificates: Option<PathBuf>,
    pub allowed_fingerprints: Vec<String>,
    pub allow_any_cert: bool,
    pub allow_chained: bool,
}

impl ConnectOptions {
    /// Make sense of the `--daemon-ssl` options as `wallet2.cpp`'s
    /// `make_basic` does.
    ///
    /// `--daemon-ssl-allow-any-cert` accepts any certificate; a CA file or
    /// fingerprints accept only what they name, and make TLS required unless
    /// `--daemon-ssl` says otherwise; anything else checks against the roots.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_flags(flags: &SslFlags) -> Result<ConnectOptions, String> {
        let given = match flags.ssl.as_deref() {
            None => None,
            Some(text) => Some(TlsMode::parse(text).ok_or_else(|| {
                format!("--daemon-ssl is enabled, disabled or autodetect, not `{text}`")
            })?),
        };
        let pinned = !flags.allow_any_cert
            && (flags.ca_certificates.is_some() || !flags.allowed_fingerprints.is_empty());
        let certificates = if flags.allow_any_cert {
            Certificates::Any
        } else if pinned {
            let fingerprints = flags
                .allowed_fingerprints
                .iter()
                .map(|f| parse_fingerprint(f))
                .collect::<Result<Vec<_>, _>>()?;
            let ca = match &flags.ca_certificates {
                Some(path) => crate::tls::read_certificates(path)?,
                None => Vec::new(),
            };
            Certificates::Pinned(Pins {
                fingerprints,
                ca,
                allow_chained: flags.allow_chained,
            })
        } else {
            Certificates::Checked
        };
        let tls = given.unwrap_or(if pinned {
            TlsMode::Enabled
        } else {
            TlsMode::Autodetect
        });
        let client_certificate = match (&flags.certificate, &flags.private_key) {
            (None, None) => None,
            (Some(certificate), Some(private_key)) => Some(ClientCertificate {
                certificate: certificate.clone(),
                private_key: private_key.clone(),
            }),
            _ => {
                return Err(
                    "--daemon-ssl-certificate and --daemon-ssl-private-key go together".into(),
                )
            }
        };
        Ok(ConnectOptions {
            tls,
            certificates,
            client_certificate,
        })
    }

    /// Whether `address` needs a certificate named ahead that these options
    /// do not give: `wallet2.cpp`'s `verification_required &&
    /// !has_strong_verification`. Required TLS checked only against the roots
    /// is not enough for the C++ wallet, nor is anything through a proxy
    /// (`proxy`), unless the host is a `.onion` or `.i2p` one, whose name is
    /// its key.
    pub fn lacks_strong_verification(&self, address: &str, proxy: bool) -> bool {
        let required = !matches!(self.certificates, Certificates::Any)
            && (self.tls == TlsMode::Enabled || proxy);
        let host = Target::parse(address)
            .map(|t| t.host.to_ascii_lowercase())
            .unwrap_or_default();
        let strong = matches!(self.certificates, Certificates::Pinned(_))
            || host.ends_with(".onion")
            || host.ends_with(".i2p");
        required && !strong
    }
}

/// A SHA-256 fingerprint as `--daemon-ssl-allowed-fingerprints` takes it:
/// hex, with spaces and colons ignored (`from_hex_locale`).
pub fn parse_fingerprint(text: &str) -> Result<[u8; 32], String> {
    let hex: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    let bytes = wow_crypto::hex::decode(&hex).ok_or_else(|| format!("`{text}` is not hex"))?;
    bytes
        .try_into()
        .map_err(|_| "a SHA-256 fingerprint should be 32 bytes long".to_string())
}

/// Where a daemon is, and how long to wait for it.
#[derive(Clone, Debug)]
pub struct Endpoint {
    /// As it was given: `host:port`, or that with `http://` or `https://` in
    /// front.
    pub address: String,
    pub connect_timeout: Duration,
    /// Applies to reads and writes separately, not to the whole exchange — a
    /// long `get_blocks.bin` is slow because it is large, not because it is
    /// stalled.
    pub timeout: Duration,
    /// For an address without `https://`.
    pub tls: TlsMode,
    /// For a TLS connection.
    pub certificates: Certificates,
    pub client_certificate: Option<ClientCertificate>,
    /// For a node started with `--rpc-login`. Shared rather than owned so a
    /// cloned `Endpoint` keeps answering with the same nonce counter, which
    /// the daemon requires to rise.
    pub login: Option<std::sync::Arc<crate::digest::Login>>,
    /// The connection from the last exchange, when it can carry another.
    ///
    /// Shared, so cloning an `Endpoint` shares the socket rather than opening
    /// a second one. One at a time: a wallet makes one call at a time, and a
    /// pool of several would need a policy for how many and for how long.
    idle: std::sync::Arc<std::sync::Mutex<Option<BufReader<Connection>>>>,
    /// How the node was reached last, which decides how it is reached next:
    /// autodetect does not try again once it has found out. Shared as `idle`
    /// is.
    security: Arc<Mutex<Option<Security>>>,
}

/// What [`Endpoint::connect`] tries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Plan {
    Plain,
    /// `strict`: the certificate must check out. `fallback`: plain HTTP will
    /// do if TLS does not.
    Tls { strict: bool, fallback: bool },
}

impl Endpoint {
    pub fn new(address: impl Into<String>) -> Endpoint {
        Endpoint {
            address: address.into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            timeout: DEFAULT_TIMEOUT,
            tls: TlsMode::Autodetect,
            certificates: Certificates::Checked,
            client_certificate: None,
            login: None,
            idle: std::sync::Arc::new(std::sync::Mutex::new(None)),
            security: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_certificates(mut self, certificates: Certificates) -> Endpoint {
        self.certificates = certificates;
        self
    }

    pub fn with_tls(mut self, tls: TlsMode) -> Endpoint {
        self.tls = tls;
        self
    }

    /// Everything [`ConnectOptions`] says.
    pub fn with_options(mut self, options: &ConnectOptions) -> Endpoint {
        self.tls = options.tls;
        self.certificates = options.certificates.clone();
        self.client_certificate = options.client_certificate.clone();
        self
    }

    /// Log in to a daemon started with `--rpc-login`.
    pub fn with_login(mut self, credentials: crate::digest::Credentials) -> Endpoint {
        self.login = Some(std::sync::Arc::new(crate::digest::Login::new(credentials)));
        self
    }

    /// How the node was last reached, once it has been.
    pub fn security(&self) -> Option<Security> {
        *self.security.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn hold(&self, security: Security) {
        *self.security.lock().unwrap_or_else(|e| e.into_inner()) = Some(security);
    }

    fn connect(&self) -> Result<Connection, HttpError> {
        // The scheme comes off first. One that is neither http nor https is
        // named as the problem, rather than failing as "cannot resolve
        // `ftp://node:34568`", which sends whoever typed it looking at their
        // DNS instead.
        let target = Target::parse(&self.address)?;
        let held = self.security();
        let plan = if target.tls || self.tls == TlsMode::Enabled {
            Plan::Tls {
                strict: true,
                fallback: false,
            }
        } else {
            match (self.tls, held) {
                (TlsMode::Disabled, _) | (_, Some(Security::Plain { .. })) => Plan::Plain,
                // Spoken TLS once, so never plain HTTP again.
                (_, Some(Security::Tls { .. })) => Plan::Tls {
                    strict: false,
                    fallback: false,
                },
                (_, None) => Plan::Tls {
                    strict: false,
                    fallback: true,
                },
            }
        };

        let tcp = self.open(&target)?;
        let Plan::Tls { strict, fallback } = plan else {
            if held.is_none() {
                self.hold(Security::Plain { fell_back: false });
            }
            return Ok(Connection::Plain(tcp));
        };
        match crate::tls::connect(
            tcp,
            &target.host,
            &self.certificates,
            self.client_certificate.as_ref(),
            strict,
            self.connect_timeout,
            self.timeout,
        ) {
            Ok((stream, verified)) => {
                if !verified && !matches!(self.certificates, Certificates::Any) && held.is_none() {
                    // `configure`'s "SSL peer has not been verified".
                    wow_log::warn!(
                        LOG,
                        "{}: the node's certificate does not check out; the connection is \
                         encrypted, but nothing says who is at the other end of it",
                        self.address
                    );
                }
                self.hold(Security::Tls { verified });
                Ok(Connection::Tls(Box::new(stream)))
            }
            Err(e) if fallback => {
                // `connect`'s "SSL handshake failed on an autodetect
                // connection, reconnecting without SSL", where it is seen.
                wow_log::warn!(
                    LOG,
                    "{}: no TLS ({e}); using plain HTTP, where what this wallet asks the node \
                     and every answer can be read and changed on the way",
                    self.address
                );
                let tcp = self.open(&target)?;
                self.hold(Security::Plain { fell_back: true });
                Ok(Connection::Plain(tcp))
            }
            Err(e) => Err(e),
        }
    }

    /// A socket to the node, with the timeouts set.
    fn open(&self, target: &Target) -> Result<TcpStream, HttpError> {
        let mut last = None;
        let addrs = target
            .host_port
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
    /// The connection from the last call is used when there is one. A refresh
    /// makes one call per thousand blocks, which sounds like few until a cold
    /// sync makes nearly a thousand of them — and against an `https://` node
    /// each one was a full TLS handshake, on a provider of pure-Rust crates
    /// that is not the fastest way to do one.
    ///
    /// The connection is only kept when the framing leaves nothing in doubt:
    /// see [`Response::reusable`].
    pub fn post(&self, path: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, HttpError> {
        let started = std::time::Instant::now();
        wow_log::debug!(LOG, "POST {}{path}, {} byte(s)", self.address, body.len());
        let result = self.exchange(path, content_type, body);
        let ms = started.elapsed().as_millis();
        match &result {
            Ok(response) => {
                wow_log::debug!(LOG, "{path}: {} byte(s) in {ms} ms", response.len())
            }
            Err(e) => wow_log::info!(LOG, "{path}: {e}, after {ms} ms"),
        }
        result
    }

    /// One request and its response.
    ///
    /// A daemon with `--rpc-login` answers `401` with a challenge until a
    /// request carries an `Authorization`. The held challenge is sent first,
    /// so the usual call costs one round trip; a `401` is answered and the
    /// request sent again, once. Twice would mean the credentials are wrong,
    /// and a daemon blocks an address after three failures.
    fn exchange(&self, path: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, HttpError> {
        let authorization = self.login.as_ref().and_then(|l| l.authorization("POST", path));
        match self.exchange_once(path, content_type, body, authorization.as_deref()) {
            Err(HttpError::Unauthorized { challenge }) => {
                let Some(login) = self.login.as_ref() else {
                    return Err(HttpError::Status { code: 401 });
                };
                // The nonce we had, if any, is no longer one the daemon will
                // take.
                login.stale();
                let Some(answer) = challenge
                    .as_deref()
                    .and_then(|c| login.answer(c, "POST", path))
                else {
                    return Err(HttpError::Status { code: 401 });
                };
                match self.exchange_once(path, content_type, body, Some(&answer)) {
                    // Answered, and still refused: the user name or the
                    // password is wrong. Said plainly, because "HTTP 401" sends
                    // people to look at their node's logs instead.
                    Err(HttpError::Unauthorized { .. }) => Err(HttpError::BadLogin {
                        user: login.user().to_string(),
                    }),
                    other => other,
                }
            }
            other => other,
        }
    }

    /// One request and its response, on the connection from last time when
    /// there is one.
    ///
    /// A reused connection can be closed by the far end at any moment,
    /// including between the last response and this request, and the failure
    /// looks exactly like a write to a dead socket. That race is not avoidable
    /// -- it is the one thing every keep-alive implementation has to handle --
    /// so a *reused* connection gets exactly one retry on a fresh one. A
    /// connection that was fresh to begin with gets none: a failure there is
    /// the node being unreachable, and retrying would only say so twice.
    fn exchange_once(
        &self,
        path: &str,
        content_type: &str,
        body: &[u8],
        authorization: Option<&str>,
    ) -> Result<Vec<u8>, HttpError> {
        let held = self
            .idle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let reused = held.is_some();
        match self.exchange_on(held, path, content_type, body, authorization) {
            // A server that closed the kept connection while it sat idle is
            // most often seen as nothing to read, not as an I/O error: the
            // request writes into the socket without complaint, and the
            // server's FIN is already waiting behind it.
            Err(HttpError::Io(_) | HttpError::Truncated { .. } | HttpError::Malformed(NO_REPLY))
                if reused =>
            {
                wow_log::debug!(LOG, "{path}: the kept connection was gone; opening a new one");
                self.exchange_on(None, path, content_type, body, authorization)
            }
            other => other,
        }
    }

    fn exchange_on(
        &self,
        held: Option<BufReader<Connection>>,
        path: &str,
        content_type: &str,
        body: &[u8],
        authorization: Option<&str>,
    ) -> Result<Vec<u8>, HttpError> {
        let host = Target::parse(&self.address)?.host_header;
        let mut reader = match held {
            Some(r) => r,
            None => BufReader::new(self.connect()?),
        };

        // No `Connection: close`, and not only because the connection may be
        // kept for the next call. Wownero 0.11.3 stops a
        // connection as soon as it has answered a request that asks for that,
        // cancelling the reply it is still writing, so a large one arrives cut
        // short. `wallet2` never sends it, and neither does this.
        //
        // The head is epee's `http_simple_client::invoke`, field for field and
        // in its order: `Host` without the port, `Content-Length`, the
        // `Content-Type` only `invoke_http_json` adds, then `Authorization`.
        // Nothing else, `Accept` included, so a node or anyone on the path
        // sees the request a C++ wallet sends.
        let mut head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Length: {len}\r\n",
            len = body.len(),
        );
        if content_type != BINARY_CONTENT_TYPE {
            head.push_str("Content-Type: ");
            head.push_str(content_type);
            head.push_str("\r\n");
        }
        if let Some(a) = authorization {
            head.push_str("Authorization: ");
            head.push_str(a);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        {
            let stream = reader.get_mut();
            stream.write_all(head.as_bytes())?;
            stream.write_all(body)?;
            stream.flush()?;
        }

        // The reader is kept, not the socket: after a `Content-Length` body it
        // may hold bytes of the next response already, and dropping it would
        // lose them and misframe everything after.
        let response = read_response(&mut reader, path)?;
        if response.reusable {
            *self.idle.lock().unwrap_or_else(|e| e.into_inner()) = Some(reader);
        }
        Ok(response.body)
    }

    /// `GET path`, for what is not a daemon's RPC: a public list of nodes, say.
    ///
    /// With `Connection: close`, which a web server needs to close the
    /// connection once it has answered. The daemon that cuts replies to it is
    /// not what this is for.
    pub fn get(&self, path: &str) -> Result<Vec<u8>, HttpError> {
        let host = Target::parse(&self.address)?.host_header;
        let mut stream = self.connect()?;
        let head = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Accept: */*\r\n\
             Connection: close\r\n\
             \r\n"
        );
        stream.write_all(head.as_bytes())?;
        stream.flush()?;
        // Never pooled: this asks for `Connection: close`, so there is nothing
        // to keep.
        Ok(read_response(&mut BufReader::new(stream), path)?.body)
    }
}

/// An address, taken apart.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    tls: bool,
    /// What to connect to: with the port the address gave, or else its
    /// scheme's.
    host_port: String,
    /// The host alone, without brackets: the name a certificate is checked
    /// for.
    host: String,
    /// `Host:`: the host alone, as epee's client sends it, with an IPv6
    /// address still in brackets so the header stays one a proxy can read.
    host_header: String,
}

impl Target {
    fn parse(address: &str) -> Result<Target, HttpError> {
        let (scheme, rest) = match address.split_once("://") {
            Some((scheme, rest)) => (Some(scheme.to_ascii_lowercase()), rest),
            None => (None, address),
        };
        let tls = match scheme.as_deref() {
            None | Some("http") => false,
            Some("https") => true,
            Some(other) => {
                return Err(HttpError::Scheme {
                    address: address.to_string(),
                    scheme: other.to_string(),
                })
            }
        };
        let rest = rest.trim_end_matches('/');
        let (host, has_port) = match rest.strip_prefix('[') {
            // `[::1]`, or `[::1]:34568`.
            Some(inner) => match inner.split_once(']') {
                Some((host, after)) => (host, !after.is_empty()),
                None => return Err(HttpError::BadAddress(address.to_string())),
            },
            None => match rest.rsplit_once(':') {
                Some((host, _)) => (host, true),
                None => (rest, false),
            },
        };
        // A bare host with no scheme keeps failing to resolve, as it always
        // has: which port a daemon is on is not this crate's to guess.
        let host_port = match (has_port, &scheme) {
            (false, Some(_)) => format!("{rest}:{}", if tls { 443 } else { 80 }),
            _ => rest.to_string(),
        };
        let host_header = if rest.starts_with('[') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        Ok(Target {
            tls,
            host_port,
            host: host.to_string(),
            host_header,
        })
    }
}

/// A connection to a daemon: plain, or TLS.
enum Connection {
    Plain(TcpStream),
    Tls(Box<crate::tls::Stream>),
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Connection::Plain(_) => "a plain connection",
            Connection::Tls(_) => "a TLS connection",
        })
    }
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Connection::Plain(s) => s.read(buf),
            Connection::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Connection::Plain(s) => s.write(buf),
            Connection::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Connection::Plain(s) => s.flush(),
            Connection::Tls(s) => s.flush(),
        }
    }
}

/// A response, and whether the connection it came on may carry another.
struct Response {
    body: Vec<u8>,
    /// The body was framed by an exact `Content-Length` that was read in full,
    /// the server did not say `Connection: close`, and nothing else about the
    /// exchange is ambiguous.
    ///
    /// Anything less and the socket is dropped. A connection reused when the
    /// framing was not certain hands the *next* call somebody else's bytes,
    /// and a wallet that reads one answer as another is a far worse outcome
    /// than a handshake.
    reusable: bool,
}

/// What [`read_response`] says when not one byte of a reply arrived.
///
/// Its own words because it is what a kept connection the server has since
/// closed reads as, and that is worth a second try on a new one.
const NO_REPLY: &str = "the connection closed before a status line";

fn read_response<S: Read>(reader: &mut BufReader<S>, path: &str) -> Result<Response, HttpError> {
    // Status line. `read_line` only says `Malformed` for a read of nothing at
    // all: a line cut short still reads, and fails in `parse_status` instead.
    let mut line = String::new();
    let mut header_bytes = 0usize;
    match read_line(reader, &mut line, &mut header_bytes) {
        Err(HttpError::Malformed(_)) => return Err(HttpError::Malformed(NO_REPLY)),
        other => other?,
    }
    let code = parse_status(&line)?;

    // Headers. A body without a `Content-Length` runs to the end of the
    // connection, which only a server that closes it can send; the daemons
    // this talks to always give a length.
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    // Kept for a 401: it is what says how to log in.
    let mut challenge: Option<String> = None;
    let mut server_closes = false;
    loop {
        line.clear();
        read_line(reader, &mut line, &mut header_bytes)?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        wow_log::trace!(LOG, "{path}: {trimmed}");
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
        } else if name == "connection" {
            server_closes = value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("close"));
        } else if name == "www-authenticate" && value.len() <= MAX_HEADER_BYTES {
            // A server may offer several schemes in separate headers. Digest
            // is the only one spoken here, so prefer it over whatever came
            // first.
            let digest = value
                .get(..6)
                .is_some_and(|s| s.eq_ignore_ascii_case("digest"));
            if challenge.is_none() || digest {
                challenge = Some(value.to_string());
            }
        }
    }

    wow_log::debug!(
        LOG,
        "{path}: HTTP {code}, Content-Length {}{}",
        content_length.map_or_else(|| "absent".to_string(), |l| l.to_string()),
        if chunked { ", chunked" } else { "" }
    );

    // Chunked wins over any `Content-Length` alongside it (RFC 9112 §6.3).
    let body = match content_length {
        _ if chunked => read_chunked(reader)?,
        Some(len) => {
            let mut buf = vec![0u8; len];
            let mut got = 0;
            while got < len {
                match reader.read(&mut buf[got..]) {
                    // Closed with the body short. `read_exact` would say only
                    // "failed to fill whole buffer", which does not tell a
                    // daemon that cut a response off from one that sent the
                    // wrong length.
                    Ok(0) => return Err(HttpError::Truncated { got, expected: len }),
                    Ok(n) => got += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
            buf
        }
        None => {
            // Read to EOF, still bounded.
            let mut buf = Vec::new();
            match reader
                .take(MAX_RESPONSE_BYTES as u64 + 1)
                .read_to_end(&mut buf)
            {
                Ok(_) => {}
                // A TLS server that closes without saying so first, as many
                // do once they have answered: what arrived is the body.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
                Err(e) => return Err(e.into()),
            }
            if buf.len() > MAX_RESPONSE_BYTES {
                return Err(HttpError::BodyTooLarge { len: buf.len() });
            }
            buf
        }
    };

    // Only an exact `Content-Length`, read in full, on a connection the server
    // did not say it was closing. Chunked is excluded because this reader
    // stops at the terminating chunk and does not consume trailers, and a
    // length-less body ran to end-of-file by definition.
    let reusable = !chunked && content_length.is_some() && !server_closes;

    // The status is checked after the body is drained, so an error response
    // with a useful JSON payload is still available to the caller.
    if code == 401 {
        return Err(HttpError::Unauthorized { challenge });
    }
    if !(200..300).contains(&code) {
        return Err(HttpError::Status { code });
    }
    Ok(Response { body, reusable })
}

fn read_line<S: Read>(
    reader: &mut BufReader<S>,
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

/// A chunked body (RFC 9112 §7.1): chunks, each a hex size line and that many
/// bytes, then a zero-size chunk and any trailers.
///
/// Held to [`MAX_RESPONSE_BYTES`] in total, checked before each chunk is
/// allocated, so a size line cannot ask for more than a `Content-Length` can.
fn read_chunked<S: Read>(reader: &mut BufReader<S>) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    let mut line = String::new();
    loop {
        // Each size line is capped on its own, as a header block is.
        let mut seen = 0;
        read_line(reader, &mut line, &mut seen)?;
        // A size may carry `;name=value` extensions, which mean nothing here.
        let size_text = line.trim_end().split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| HttpError::Malformed("a chunk size is not hex"))?;
        if size == 0 {
            break;
        }
        let start = body.len();
        let end = start
            .checked_add(size)
            .filter(|end| *end <= MAX_RESPONSE_BYTES)
            .ok_or(HttpError::BodyTooLarge {
                len: start.saturating_add(size),
            })?;
        body.resize(end, 0);
        let mut got = start;
        while got < end {
            match reader.read(&mut body[got..end]) {
                Ok(0) => return Err(HttpError::Truncated { got, expected: end }),
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        // The line break that closes the chunk's data.
        let mut seen = 0;
        read_line(reader, &mut line, &mut seen)?;
        if !line.trim_end().is_empty() {
            return Err(HttpError::Malformed("a chunk is longer than its size"));
        }
    }
    // Trailers, if any, and the empty line that ends the message.
    let mut seen = 0;
    loop {
        read_line(reader, &mut line, &mut seen)?;
        if line.trim_end().is_empty() {
            return Ok(body);
        }
    }
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

    /// Public node lists give addresses as `http://host:port` and
    /// `https://host:port`, so this is the first thing anyone pastes. Both
    /// are taken; any other scheme is named as what is wrong, rather than
    /// failing as "cannot resolve", which sends people looking at their
    /// network instead.
    #[test]
    fn a_url_scheme_other_than_http_is_named_as_the_problem() {
        let e = Endpoint::new("ftp://node.example:34568");
        let err = e.connect().expect_err("not a scheme this speaks");
        assert!(matches!(err, HttpError::Scheme { .. }), "{err}");
        let text = err.to_string();
        assert!(text.contains("ftp://"), "{text}");
        assert!(text.contains("https://"), "and what to use instead: {text}");
    }

    #[test]
    fn addresses_are_taken_apart() {
        let t = Target::parse("127.0.0.1:34568").expect("ok");
        assert_eq!(
            t,
            Target {
                tls: false,
                host_port: "127.0.0.1:34568".into(),
                host: "127.0.0.1".into(),
                host_header: "127.0.0.1".into(),
            }
        );

        // A scheme with no port means the scheme's.
        let t = Target::parse("https://wow-node.0z.network/").expect("ok");
        assert!(t.tls);
        assert_eq!(t.host_port, "wow-node.0z.network:443");
        assert_eq!(t.host, "wow-node.0z.network");
        assert_eq!(t.host_header, "wow-node.0z.network");

        // `Host:` never carries the port, as epee's never does.
        let t = Target::parse("HTTPS://wow-node.0z.network:443").expect("ok");
        assert!(t.tls);
        assert_eq!(t.host_port, "wow-node.0z.network:443");
        assert_eq!(t.host_header, "wow-node.0z.network");

        let t = Target::parse("http://[::1]").expect("ok");
        assert!(!t.tls);
        assert_eq!(t.host_port, "[::1]:80");
        assert_eq!(t.host, "::1");

        let t = Target::parse("[::1]:34568").expect("ok");
        assert_eq!(t.host_port, "[::1]:34568");
        assert_eq!(t.host, "::1");
        assert_eq!(t.host_header, "[::1]");

        assert!(matches!(
            Target::parse("http://[::1:34568"),
            Err(HttpError::BadAddress(_))
        ));
    }

    /// Answer one request with `reply`, as it is, and close. Returns the
    /// server's address and its thread.
    fn answer_once(reply: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("an address").to_string();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            // Read the whole request first: closing with some of it unread
            // would reset the connection instead of ending it.
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut chunk).expect("read");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
            }
            s.write_all(reply).expect("write");
        });
        (address, server)
    }

    /// An endpoint that speaks plain HTTP, for a test server that does not
    /// speak TLS: autodetect would try it first.
    fn plain(address: String) -> Endpoint {
        Endpoint::new(address).with_tls(TlsMode::Disabled)
    }

    /// Answer one request with an empty `200`, and hand back the request's
    /// head as it arrived.
    fn capture_head() -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("an address").to_string();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut chunk).expect("read");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
            }
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .expect("write");
            let end = request
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map_or(request.len(), |p| p + 4);
            String::from_utf8_lossy(&request[..end]).into_owned()
        });
        (address, server)
    }

    /// The head of a request is epee's: `Host` without the port, then
    /// `Content-Length`, a `Content-Type` only on JSON, and no `Accept`.
    #[test]
    fn a_request_head_is_the_one_a_cpp_wallet_sends() {
        let (address, server) = capture_head();
        plain(address)
            .post("/getblocks.bin", BINARY_CONTENT_TYPE, b"")
            .expect("ok");
        assert_eq!(
            server.join().expect("the server"),
            "POST /getblocks.bin HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
        );

        let (address, server) = capture_head();
        plain(address)
            .post("/json_rpc", crate::JSON_CONTENT_TYPE, b"")
            .expect("ok");
        assert_eq!(
            server.join().expect("the server"),
            "POST /json_rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\
             Content-Type: application/json; charset=utf-8\r\n\r\n"
        );
    }

    /// A server that answers `replies.len()` requests, all on connections it
    /// accepts, and reports how many it accepted.
    ///
    /// The count is the point: one accept for several requests is the whole
    /// claim being tested.
    fn answer_several(
        replies: Vec<&'static [u8]>,
    ) -> (String, std::thread::JoinHandle<usize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("an address").to_string();
        let server = std::thread::spawn(move || {
            let mut accepted = 0usize;
            let mut kept: Option<std::net::TcpStream> = None;
            for reply in replies {
                // A kept socket that ends before a request is one the client
                // let go of: its request is coming on a new connection.
                let still_used = kept.take().and_then(|mut s| {
                    if read_request(&mut s) {
                        Some(s)
                    } else {
                        None
                    }
                });
                let mut s = match still_used {
                    Some(s) => s,
                    None => {
                        accepted += 1;
                        let mut s = listener.accept().expect("accept").0;
                        if !read_request(&mut s) {
                            return accepted;
                        }
                        s
                    }
                };
                s.write_all(reply).expect("write");
                kept = Some(s);
            }
            accepted
        });
        (address, server)
    }

    /// Read a request's head, returning whether one came before the
    /// connection ended.
    ///
    /// A reset counts as ended: a client that closes with some of a reply
    /// still unread resets the connection rather than ending it.
    fn read_request(s: &mut std::net::TcpStream) -> bool {
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => return false,
                Ok(n) => request.extend_from_slice(&chunk[..n]),
            }
        }
        true
    }

    /// A kept connection the server closed while it sat idle is not an error:
    /// the call goes again on a new one.
    #[test]
    fn a_kept_connection_the_server_closed_is_replaced() {
        const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("an address").to_string();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut s, _) = listener.accept().expect("accept");
                assert!(read_request(&mut s), "a request");
                s.write_all(OK).expect("write");
                // Dropped here: closed, with the client still keeping it.
            }
        });
        let endpoint = plain(address);
        for _ in 0..2 {
            assert_eq!(
                endpoint.post("/get_info", "application/json", b"").expect("ok"),
                b"hi"
            );
        }
        server.join().expect("the server");
    }

    /// A second call goes down the same socket. Over TLS that is a whole
    /// handshake saved, and a cold wallet sync makes hundreds of calls.
    #[test]
    fn a_second_request_reuses_the_connection() {
        const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let (address, server) = answer_several(vec![OK, OK, OK]);
        let endpoint = plain(address);
        for _ in 0..3 {
            assert_eq!(
                endpoint.post("/get_info", "application/json", b"").expect("ok"),
                b"hi"
            );
        }
        assert_eq!(server.join().expect("the server"), 1, "one connection, three calls");
    }

    /// A server that says it is closing is believed, and the next call opens a
    /// new connection rather than writing into a socket that is going away.
    #[test]
    fn a_connection_the_server_is_closing_is_not_kept() {
        const CLOSING: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi";
        let (address, server) = answer_several(vec![CLOSING, CLOSING]);
        let endpoint = plain(address);
        for _ in 0..2 {
            assert_eq!(
                endpoint.post("/get_info", "application/json", b"").expect("ok"),
                b"hi"
            );
        }
        assert_eq!(server.join().expect("the server"), 2, "a connection each");
    }

    /// A chunked answer is never kept: this reader stops at the terminating
    /// chunk and does not consume trailers, so what is left in the socket is
    /// not known.
    #[test]
    fn a_chunked_answer_is_not_kept() {
        const CHUNKED: &[u8] =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n";
        let (address, server) = answer_several(vec![CHUNKED, CHUNKED]);
        let endpoint = plain(address);
        for _ in 0..2 {
            assert_eq!(
                endpoint.post("/get_info", "application/json", b"").expect("ok"),
                b"hi"
            );
        }
        assert_eq!(server.join().expect("the server"), 2, "a connection each");
    }

    /// A request with no body, so the server has read all of it once it has
    /// the headers.
    fn post_to(reply: &'static [u8]) -> Result<Vec<u8>, HttpError> {
        let (address, server) = answer_once(reply);
        let result = plain(address).post("/get_info", "application/json", b"");
        server.join().expect("the server");
        result
    }

    /// A body cut short says how much of it arrived.
    #[test]
    fn a_body_cut_short_says_how_much_arrived() {
        let e =
            post_to(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc").expect_err("cut short");
        assert!(
            matches!(
                e,
                HttpError::Truncated {
                    got: 3,
                    expected: 10
                }
            ),
            "{e}"
        );
        assert!(e.to_string().contains("3 of 10"), "{e}");
    }

    /// A reply a proxy re-framed as chunks reads as the body it carries:
    /// extensions ignored, trailers skipped, and the chunks winning over a
    /// `Content-Length` sent alongside them.
    #[test]
    fn a_chunked_reply_is_read_whole() {
        let body = post_to(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n\
              4\r\nWiki\r\n5;name=value\r\npedia\r\nA\r\n in chunks\r\n0\r\nX-Trailer: 1\r\n\r\n",
        )
        .expect("read");
        assert_eq!(body, b"Wikipedia in chunks");
    }

    /// A chunk size past the cap is refused before anything is allocated.
    #[test]
    fn a_chunk_past_the_cap_is_refused() {
        let e = post_to(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFF\r\nab")
            .expect_err("too large");
        assert!(matches!(e, HttpError::BodyTooLarge { .. }), "{e}");
    }

    /// A chunk cut short, and a size that is not hex, are errors that say so.
    #[test]
    fn a_broken_chunk_is_an_error() {
        let e = post_to(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nabc")
            .expect_err("cut short");
        assert!(
            matches!(
                e,
                HttpError::Truncated {
                    got: 3,
                    expected: 6
                }
            ),
            "{e}"
        );

        let e = post_to(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\nabc\r\n0\r\n\r\n",
        )
        .expect_err("not hex");
        assert!(matches!(e, HttpError::Malformed(_)), "{e}");

        let e =
            post_to(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabc\r\n0\r\n\r\n")
                .expect_err("longer than its size");
        assert!(matches!(e, HttpError::Malformed(_)), "{e}");
    }

    /// A TLS server on `127.0.0.1` with a self-signed certificate, made by the
    /// node's own provider, that answers one request with `reply`.
    #[cfg(not(target_arch = "wasm32"))]
    fn tls_answer_once(reply: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
        let (port, _, server) = tls_server(reply);
        (format!("https://127.0.0.1:{port}"), server)
    }

    /// [`tls_answer_once`], giving the port and the certificate's DER.
    #[cfg(not(target_arch = "wasm32"))]
    fn tls_server(reply: &'static [u8]) -> (u16, Vec<u8>, std::thread::JoinHandle<()>) {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::CertificateDer;
        use std::sync::Arc;

        let (key, _) = wow_tls::provider::generate_p256().expect("a key");
        let signer = wow_tls::provider::CertSigner::new(&key).expect("a signer");
        // rcgen asks for a serial number when the key signing is not its own,
        // as `wownerod` gives its generated certificate one.
        let mut params = rcgen::CertificateParams::default();
        params.serial_number = Some(rcgen::SerialNumber::from(1u64));
        let cert = params.self_signed(&signer).expect("a certificate");
        let der = CertificateDer::from_pem_slice(cert.pem().as_bytes()).expect("its PEM");
        let der_bytes = der.as_ref().to_vec();
        let config =
            rustls::ServerConfig::builder_with_provider(Arc::new(wow_tls::provider::provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .expect("the versions")
                .with_no_client_auth()
                .with_single_cert(vec![der], key)
                .expect("the pair");
        let config = Arc::new(config);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("an address").port();
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            let conn = rustls::ServerConnection::new(config).expect("a connection");
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            // A handshake the client refused ends the read, with nothing to
            // answer.
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match tls.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = tls.write_all(reply);
            tls.conn.send_close_notify();
            let _ = tls.flush();
        });
        (port, der_bytes, server)
    }

    /// Over TLS, a self-signed certificate is refused unless accepted as it
    /// is, and then the reply reads as over plain HTTP.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn tls_checks_the_certificate_unless_told_not_to() {
        const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n{\"height\":1}";

        let (address, server) = tls_answer_once(REPLY);
        let e = Endpoint::new(address)
            .post("/get_info", "application/json", b"")
            .expect_err("a self-signed certificate is not trusted");
        server.join().expect("the server");
        assert!(matches!(e, HttpError::Tls(_)), "{e}");
        assert!(e.to_string().contains("not trusted"), "{e}");

        let (address, server) = tls_answer_once(REPLY);
        let body = Endpoint::new(address)
            .with_certificates(Certificates::Any)
            .post("/get_info", "application/json", b"")
            .expect("accepted as it is");
        server.join().expect("the server");
        assert_eq!(body, b"{\"height\":1}");
    }

    /// Autodetect speaks TLS to a node that does, and takes a certificate that
    /// does not check out as the C++ takes it, saying it did not.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn autodetect_speaks_tls_where_it_is_spoken() {
        const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let (port, _, server) = tls_server(REPLY);
        let endpoint = Endpoint::new(format!("127.0.0.1:{port}"));
        let body = endpoint
            .post("/get_info", "application/json", b"")
            .expect("over TLS");
        server.join().expect("the server");
        assert_eq!(body, b"hi");
        assert_eq!(endpoint.security(), Some(Security::Tls { verified: false }));
    }

    /// A server that does not speak TLS: the first connection gets `400` for
    /// the ClientHello it could not read, and the next ones are answered.
    fn plain_only(replies: usize) -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("an address").port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            let mut hello = [0u8; 1024];
            let _ = s.read(&mut hello);
            let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
            drop(s);
            for _ in 0..replies {
                let (mut s, _) = listener.accept().expect("accept");
                if read_request(&mut s) {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
                }
            }
        });
        (port, server)
    }

    /// Autodetect falls back to plain HTTP for a node that does not speak TLS,
    /// and says it did.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn autodetect_falls_back_where_tls_is_not_spoken() {
        let (port, server) = plain_only(1);
        let endpoint = Endpoint::new(format!("127.0.0.1:{port}"));
        let body = endpoint
            .post("/get_info", "application/json", b"")
            .expect("over plain HTTP");
        server.join().expect("the server");
        assert_eq!(body, b"hi");
        assert_eq!(
            endpoint.security(),
            Some(Security::Plain { fell_back: true })
        );
    }

    /// A node that has spoken TLS to an endpoint is never spoken to in the
    /// clear by it: TLS failing later is an error, not a quiet downgrade.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn a_node_that_spoke_tls_is_not_spoken_to_in_the_clear() {
        let (port, server) = plain_only(0);
        let endpoint = Endpoint::new(format!("127.0.0.1:{port}"));
        endpoint.hold(Security::Tls { verified: true });
        let e = endpoint
            .post("/get_info", "application/json", b"")
            .expect_err("no plain HTTP");
        server.join().expect("the server");
        assert!(matches!(e, HttpError::Tls(_) | HttpError::Io(_)), "{e}");
        assert_eq!(endpoint.security(), Some(Security::Tls { verified: true }));

        // `disabled` never tries TLS at all.
        let (address, server) = answer_once(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
        let endpoint = plain(address);
        endpoint
            .post("/get_info", "application/json", b"")
            .expect("plain");
        server.join().expect("the server");
        assert_eq!(
            endpoint.security(),
            Some(Security::Plain { fell_back: false })
        );
    }

    /// `enabled` takes only a certificate that checks out: here, one pinned by
    /// its fingerprint or found in the CA file.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn enabled_takes_only_a_certificate_that_checks_out() {
        const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let enabled = |port: u16, pins: Option<Pins>| {
            let endpoint =
                Endpoint::new(format!("127.0.0.1:{port}")).with_tls(TlsMode::Enabled);
            match pins {
                Some(pins) => endpoint.with_certificates(Certificates::Pinned(pins)),
                None => endpoint,
            }
        };

        let (port, _, server) = tls_server(REPLY);
        let e = enabled(port, None)
            .post("/get_info", "application/json", b"")
            .expect_err("self-signed, against the roots");
        server.join().expect("the server");
        assert!(matches!(e, HttpError::Tls(_)), "{e}");

        let (port, der, server) = tls_server(REPLY);
        let endpoint = enabled(
            port,
            Some(Pins {
                fingerprints: vec![crate::tls::fingerprint(&der)],
                ..Default::default()
            }),
        );
        endpoint
            .post("/get_info", "application/json", b"")
            .expect("pinned by its fingerprint");
        server.join().expect("the server");
        assert_eq!(endpoint.security(), Some(Security::Tls { verified: true }));

        let (port, der, server) = tls_server(REPLY);
        enabled(
            port,
            Some(Pins {
                ca: vec![der],
                ..Default::default()
            }),
        )
        .post("/get_info", "application/json", b"")
        .expect("in the CA file");
        server.join().expect("the server");

        let (port, _, server) = tls_server(REPLY);
        let e = enabled(
            port,
            Some(Pins {
                fingerprints: vec![[7u8; 32]],
                ..Default::default()
            }),
        )
        .post("/get_info", "application/json", b"")
        .expect_err("another certificate");
        server.join().expect("the server");
        assert!(matches!(e, HttpError::Tls(_)), "{e}");
    }

    /// The `--daemon-ssl` options mean what `make_basic` makes of them.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn the_ssl_options_mean_what_the_cpp_makes_of_them() {
        let o = ConnectOptions::from_flags(&SslFlags::default()).expect("none");
        assert_eq!(o, ConnectOptions::default());
        assert_eq!(o.tls, TlsMode::Autodetect);

        let fp = "ab".repeat(32);
        let pinned = SslFlags {
            allowed_fingerprints: vec![fp.clone()],
            ..Default::default()
        };
        let o = ConnectOptions::from_flags(&pinned).expect("pinned");
        assert_eq!(o.tls, TlsMode::Enabled, "a fingerprint makes TLS required");
        assert_eq!(
            o.certificates,
            Certificates::Pinned(Pins {
                fingerprints: vec![[0xab; 32]],
                ..Default::default()
            })
        );
        let o = ConnectOptions::from_flags(&SslFlags {
            ssl: Some("autodetect".into()),
            ..pinned.clone()
        })
        .expect("said");
        assert_eq!(o.tls, TlsMode::Autodetect, "unless --daemon-ssl says otherwise");

        let o = ConnectOptions::from_flags(&SslFlags {
            allow_any_cert: true,
            ..pinned
        })
        .expect("any");
        assert_eq!(o.certificates, Certificates::Any);
        assert_eq!(o.tls, TlsMode::Autodetect);

        for bad in [
            SslFlags {
                ssl: Some("sometimes".into()),
                ..Default::default()
            },
            SslFlags {
                allowed_fingerprints: vec!["abcd".into()],
                ..Default::default()
            },
            SslFlags {
                certificate: Some("client.crt".into()),
                ..Default::default()
            },
        ] {
            assert!(ConnectOptions::from_flags(&bad).is_err(), "{bad:?}");
        }
    }

    /// Required TLS, or a proxy, needs a certificate named ahead, unless the
    /// host's name is its key (`has_strong_verification`).
    #[test]
    fn required_tls_and_a_proxy_need_a_named_certificate() {
        let enabled = ConnectOptions {
            tls: TlsMode::Enabled,
            ..Default::default()
        };
        assert!(enabled.lacks_strong_verification("node.example:34568", false));
        assert!(!enabled.lacks_strong_verification("http://abc.onion:34568", false));
        assert!(!enabled.lacks_strong_verification("abc.i2p:34568", false));

        let pinned = ConnectOptions {
            certificates: Certificates::Pinned(Pins::default()),
            ..enabled
        };
        assert!(!pinned.lacks_strong_verification("node.example:34568", true));

        let auto = ConnectOptions::default();
        assert!(!auto.lacks_strong_verification("node.example:34568", false));
        assert!(auto.lacks_strong_verification("node.example:34568", true));

        let any = ConnectOptions {
            certificates: Certificates::Any,
            ..Default::default()
        };
        assert!(!any.lacks_strong_verification("node.example:34568", true));
    }

    #[test]
    fn fingerprints_parse_with_or_without_separators() {
        let colons = ["ab"; 32].join(":");
        assert_eq!(parse_fingerprint(&colons).expect("colons"), [0xab; 32]);
        assert_eq!(parse_fingerprint(&"AB ".repeat(32)).expect("spaces"), [0xab; 32]);
        assert!(parse_fingerprint("abcd").expect_err("short").contains("32 bytes"));
        assert!(parse_fingerprint("zz").expect_err("not hex").contains("not hex"));
    }
}
