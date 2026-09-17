//! A client for a Wownero daemon's RPC (`specs/11-daemon-rpc.md`).
//!
//! This is what a wallet talks to a node through. It works against
//! `wownerod` — this workspace's or the C++ one — because it speaks the
//! documented wire format and nothing else.
//!
//! Three transports, all `POST` (`specs/11` §1):
//!
//! | Kind | Path | Body |
//! |---|---|---|
//! | JSON-RPC 2.0 | `/json_rpc` | JSON, `{method, params}` |
//! | direct | `/get_height`, … | JSON |
//! | binary | `/getblocks.bin`, … | **epee portable storage** |
//!
//! The binary ones are the wallet's sync path and are where all the volume is.
//!
//! # How a request reaches the daemon
//!
//! Through a [`Transport`]. [`Endpoint`] opens a socket and speaks HTTP/1.1; a
//! program where there are no sockets to open, such as a wallet in a browser,
//! supplies its own ([`DaemonClient::with_transport`]). The framing above and
//! the typed endpoints are the same either way.
//!
//! # A daemon is not trusted
//!
//! A wallet sends its short chain history to a node and is told what comes
//! next. A hostile node can withhold blocks, or lie about the height, or feed
//! a fork — and the wallet's defence is not in this crate. It is that every
//! output is checked against the wallet's own keys and every amount against its
//! own commitment (`wow-wallet`), and that block hashes chain. What this crate
//! guarantees is narrower and still worth stating: nothing a daemon sends can
//! cause an unbounded allocation, a panic, or a hang.

pub mod digest;
pub mod http;
#[cfg(not(target_arch = "wasm32"))]
mod tls;
pub mod types;

/// A browser build reaches a node through the browser, and its TLS is the
/// browser's.
#[cfg(target_arch = "wasm32")]
mod tls {
    use std::time::Duration;

    use crate::http::{Certificates, ClientCertificate, HttpError};

    pub type Stream = std::net::TcpStream;

    pub fn connect(
        _tcp: std::net::TcpStream,
        _host: &str,
        _certificates: &Certificates,
        _client_certificate: Option<&ClientCertificate>,
        _strict: bool,
        _handshake_timeout: Duration,
        _timeout: Duration,
    ) -> Result<(Stream, bool), HttpError> {
        Err(HttpError::Tls("this build has no TLS of its own".into()))
    }

    pub fn describe(_e: &std::io::Error) -> Option<String> {
        None
    }
}

use std::sync::Arc;

use serde_json::{json, Value as Json};
use wow_serialize::epee::{self, Section};

pub use http::{
    is_onion_or_i2p, parse_fingerprint, Certificates, ClientCertificate, ConnectOptions, Endpoint,
    HttpError, Pins, Proxy, Security, SslFlags, TlsMode, Transport, BINARY_CONTENT_TYPE,
};
#[cfg(not(target_arch = "wasm32"))]
pub use tls::fingerprint;
pub use types::*;

/// What a JSON request says it is, as epee's `invoke_http_json` says it.
pub const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

/// A connection to one daemon. Clones share one transport.
#[derive(Clone, Debug)]
pub struct DaemonClient {
    transport: Arc<dyn Transport>,
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("transport: {0}")]
    Http(#[from] HttpError),
    #[error("the daemon sent malformed JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("the daemon sent malformed epee: {0}")]
    Epee(#[from] wow_serialize::Error),
    #[error("the daemon returned an error: {message} (code {code})")]
    Rpc { code: i64, message: String },
    /// `status` was not `"OK"`. `"BUSY"` means the node is still syncing and
    /// the call should be retried (`specs/11` §6).
    #[error("the daemon is not ready: {0}")]
    Status(String),
    #[error("the response has no `{0}`")]
    Missing(&'static str),
    #[error("the response field `{0}` has the wrong type")]
    BadField(&'static str),
}

type Result<T> = std::result::Result<T, DaemonError>;

impl DaemonClient {
    /// `address` is `host:port`, as typed on a command line, reached over TCP,
    /// or that with `http://` or `https://` in front. An `https://` node's
    /// certificate must be trusted ([`Endpoint::with_certificates`] says
    /// otherwise).
    pub fn new(address: impl Into<String>) -> DaemonClient {
        DaemonClient::with_endpoint(Endpoint::new(address))
    }

    pub fn with_endpoint(endpoint: Endpoint) -> DaemonClient {
        DaemonClient::with_transport(Arc::new(endpoint))
    }

    /// A daemon reached some other way than over this crate's sockets: through
    /// a browser's `fetch`, say, where there are none to open.
    pub fn with_transport(transport: Arc<dyn Transport>) -> DaemonClient {
        DaemonClient { transport }
    }

    pub fn address(&self) -> &str {
        self.transport.address()
    }

    /// How the connection to the daemon was last made, when the transport
    /// knows.
    pub fn security(&self) -> Option<Security> {
        self.transport.security()
    }

    // -- transports ---------------------------------------------------------

    /// A JSON-RPC 2.0 call (`specs/11` §4).
    pub fn json_rpc(&self, method: &str, params: Json) -> Result<Json> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params,
        })
        .to_string();

        let raw = self
            .transport
            .post("/json_rpc", JSON_CONTENT_TYPE, body.as_bytes())?;
        let mut v: Json = serde_json::from_slice(&raw)?;

        if let Some(err) = v.get_mut("error") {
            if !err.is_null() {
                return Err(DaemonError::Rpc {
                    code: err.get("code").and_then(Json::as_i64).unwrap_or(0),
                    message: err
                        .get("message")
                        .and_then(Json::as_str)
                        .unwrap_or("no message")
                        .to_string(),
                });
            }
        }
        v.get_mut("result")
            .map(Json::take)
            .ok_or(DaemonError::Missing("result"))
    }

    /// A direct JSON endpoint (`specs/11` §3).
    pub fn direct(&self, path: &str, params: Json) -> Result<Json> {
        let body = params.to_string();
        let raw = self
            .transport
            .post(path, JSON_CONTENT_TYPE, body.as_bytes())?;
        let v: Json = serde_json::from_slice(&raw)?;
        check_status(&v)?;
        Ok(v)
    }

    /// A `POST` returning the raw body, whatever the status says. The typed
    /// endpoints use it where the `status` field describes the *request's*
    /// subject rather than the daemon — a rejected transaction is a result,
    /// not a transport failure.
    pub(crate) fn raw_post(
        &self,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> std::result::Result<Vec<u8>, HttpError> {
        self.transport.post(path, content_type, body)
    }

    /// `POST` a JSON body and return the raw response, without checking
    /// `status`.
    ///
    /// For endpoints whose `status` describes the *request's subject* rather
    /// than the daemon: a rejected transaction is a successful call that says
    /// no, and the typed helpers would turn that into an error and throw the
    /// rejection flags away.
    pub fn raw_post_for_test(&self, path: &str, body: &str) -> Result<Vec<u8>> {
        Ok(self.raw_post(path, JSON_CONTENT_TYPE, body.as_bytes())?)
    }

    /// A binary endpoint (`specs/11` §5). Request and response are epee
    /// portable storage.
    pub fn binary(&self, path: &str, request: &Section) -> Result<Section> {
        let body = epee::to_bytes(request)?;
        let raw = self.transport.post(path, BINARY_CONTENT_TYPE, &body)?;
        let section = epee::from_bytes(&raw)?;
        check_binary_status(&section)?;
        Ok(section)
    }
}

/// `status` is `"OK"`, `"BUSY"`, or a message (`specs/11` §6). `"BUSY"` is the
/// one wallets retry on, so it must stay distinguishable from a real failure.
fn check_status(v: &Json) -> Result<()> {
    match v.get("status").and_then(Json::as_str) {
        None | Some("OK") => Ok(()),
        Some(other) => Err(DaemonError::Status(other.to_string())),
    }
}

fn check_binary_status(s: &Section) -> Result<()> {
    match s.get("status").and_then(|v| v.as_bytes()) {
        None => Ok(()),
        Some(b) if b == b"OK" => Ok(()),
        Some(b) => Err(DaemonError::Status(String::from_utf8_lossy(b).into_owned())),
    }
}

/// True when an error means "try again shortly" rather than "give up".
///
/// `specs/11` §6: `CORE_BUSY` is returned whenever the node is not ready, and
/// wallets retry on it. Treating it as fatal makes a wallet unusable against a
/// syncing node, which is most of them.
pub fn is_retryable(e: &DaemonError) -> bool {
    match e {
        DaemonError::Status(s) => s == "BUSY",
        DaemonError::Rpc { code, .. } => *code == -9,
        DaemonError::Http(HttpError::Io(_) | HttpError::Truncated { .. }) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_busy_status_is_retryable() {
        assert!(is_retryable(&DaemonError::Status("BUSY".into())));
        assert!(is_retryable(&DaemonError::Rpc {
            code: -9,
            message: "Core is busy".into()
        }));

        assert!(is_retryable(&DaemonError::Http(HttpError::Truncated {
            got: 3,
            expected: 10
        })));

        assert!(!is_retryable(&DaemonError::Status("Failed".into())));
        assert!(!is_retryable(&DaemonError::Missing("result")));
        assert!(!is_retryable(&DaemonError::Rpc {
            code: -2,
            message: "too big height".into()
        }));
    }

    #[test]
    fn the_status_field_is_checked() {
        check_status(&json!({"status": "OK"})).expect("OK");
        // A response without a status is not an error: several endpoints omit
        // it, and inventing a failure would be worse than accepting one.
        check_status(&json!({})).expect("absent");

        let e = check_status(&json!({"status": "BUSY"})).expect_err("busy");
        assert!(matches!(e, DaemonError::Status(s) if s == "BUSY"));
    }

    #[test]
    fn the_binary_status_field_is_checked() {
        let mut s = Section::new();
        s.insert("status".into(), epee::Value::String(b"OK".to_vec()));
        check_binary_status(&s).expect("OK");

        let mut s = Section::new();
        s.insert("status".into(), epee::Value::String(b"BUSY".to_vec()));
        assert!(matches!(
            check_binary_status(&s),
            Err(DaemonError::Status(x)) if x == "BUSY"
        ));
    }

    /// A transport the program supplies carries every call, and says where it
    /// goes.
    #[test]
    fn a_supplied_transport_carries_the_calls() {
        #[derive(Debug)]
        struct Canned;

        impl Transport for Canned {
            fn post(
                &self,
                path: &str,
                _content_type: &str,
                _body: &[u8],
            ) -> std::result::Result<Vec<u8>, HttpError> {
                match path {
                    "/get_height" => Ok(br#"{"height": 873836, "status": "OK"}"#.to_vec()),
                    _ => Err(HttpError::Transport(format!("no route to {path}"))),
                }
            }

            fn address(&self) -> &str {
                "in-memory"
            }
        }

        let client = DaemonClient::with_transport(Arc::new(Canned));
        assert_eq!(client.address(), "in-memory");
        assert_eq!(client.get_height().expect("height"), 873_836);

        let e = client.get_info().expect_err("no route");
        assert!(e.to_string().contains("no route to /get_info"), "{e}");
        assert!(!is_retryable(&e), "a transport's own failure is not BUSY");
    }
}
