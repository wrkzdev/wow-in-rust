//! The JSON-RPC server (`specs/14` §1).
//!
//! One endpoint, `POST /json_rpc`, JSON-RPC 2.0. No binary endpoints and no
//! direct paths — the wallet RPC has neither.
//!
//! # One wallet, one lock
//!
//! `specs/14` §5: "the reference serialises everything under one wallet lock.
//! Do the same; a wallet is not a concurrent data structure." Two refreshes at
//! once would race on the transfer list and the chain hashes; two transfers at
//! once would select the same inputs twice and produce a double spend of the
//! wallet's own money. So every request takes the lock, and a long
//! `rescan_blockchain` blocks the ones behind it — which the spec also says
//! clients expect.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};

use wow_types::Network;
use wow_wallet::files::{Paths, Session};
use wow_wallet::AccountBase;

use crate::errors::{self, Error};
use crate::methods;

const MAX_BODY: usize = 1_048_576;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// A refresh on a fresh wallet can take minutes, and `specs/14` §5 says clients
/// expect to wait rather than poll.
const WRITE_TIMEOUT: Duration = Duration::from_secs(600);

/// How the server was told to find wallets.
pub enum WalletSource {
    /// One wallet, opened at startup and held.
    File { paths: Paths, password: String },
    /// A directory; the client opens and creates within it.
    Dir(std::path::PathBuf),
}

/// The server's shared state.
pub struct State {
    wallet: Mutex<Option<Session>>,
    source: WalletSource,
    network: Network,
    kdf_rounds: u64,
    /// `--rpc-login user:pass`, or `None` when login was explicitly disabled.
    login: Option<(String, String)>,
    /// `--daemon-address`, remembered for wallets opened *later*.
    ///
    /// A `--wallet-dir` server has no wallet at startup, so there is nothing to
    /// point at a daemon then. Without this, every wallet a client created
    /// afterwards came up with no daemon and `refresh` answered "no daemon is
    /// set" -- on a server that had been given one on the command line.
    daemon_address: Mutex<String>,
    stop: AtomicBool,
}

impl State {
    pub fn new(
        source: WalletSource,
        network: Network,
        kdf_rounds: u64,
        login: Option<(String, String)>,
        daemon_address: String,
    ) -> State {
        State {
            wallet: Mutex::new(None),
            source,
            network,
            kdf_rounds,
            login,
            daemon_address: Mutex::new(daemon_address),
            stop: AtomicBool::new(false),
        }
    }

    /// The daemon address newly opened wallets are pointed at.
    pub fn daemon_address(&self) -> String {
        self.daemon_address
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Remember a new daemon address, so wallets opened later use it too.
    pub fn set_daemon_address(&self, address: &str) {
        let mut a = self
            .daemon_address
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *a = address.to_string();
    }

    /// Point a freshly installed wallet at the configured daemon.
    ///
    /// Failure is not fatal: a wallet that cannot reach a daemon is still a
    /// wallet, and the client can call `set_daemon` once one is up. It is
    /// reported on stderr rather than swallowed, because "why is my balance
    /// zero" has exactly this shape.
    pub fn attach_daemon(&self, session: &mut Session) {
        let address = self.daemon_address();
        if address.is_empty() {
            return;
        }
        let client = wow_daemon_client::DaemonClient::new(&address);
        match client.get_info() {
            Ok(info) => {
                session.daemon_height = info.height;
                session.daemon = Some(client);
            }
            Err(e) => eprintln!("cannot reach {address}: {e}"),
        }
    }

    /// The wallet lock. Every method takes it.
    pub fn wallet(&self) -> std::sync::MutexGuard<'_, Option<Session>> {
        self.wallet.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Open the wallet named in `--wallet-file`, at startup.
    pub fn open_at_startup(&self) -> Result<(), String> {
        let WalletSource::File { paths, password } = &self.source else {
            return Ok(());
        };
        let mut session = Session::open(
            paths.clone(),
            password.clone(),
            self.kdf_rounds,
            Some(self.network),
        )?;
        self.attach_daemon(&mut session);
        *self.wallet() = Some(session);
        Ok(())
    }

    /// The directory a `--wallet-dir` server works in.
    fn dir(&self) -> Result<&std::path::Path, Error> {
        match &self.source {
            WalletSource::Dir(d) => Ok(d),
            WalletSource::File { .. } => Err(Error::new(
                errors::NO_WALLET_DIR,
                "this server was started with --wallet-file, so it holds one wallet and \
                 cannot open another",
            )),
        }
    }

    /// A path inside the wallet directory.
    ///
    /// The name is taken as a single file name, never a path: a client that
    /// asks for `../../etc/passwd` gets a rejection rather than a traversal.
    fn path_for(&self, name: &str) -> Result<Paths, Error> {
        let dir = self.dir()?;
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name.contains("..")
            || std::path::Path::new(name).components().count() != 1
        {
            return Err(Error::new(
                errors::UNKNOWN_ERROR,
                "a wallet name is a file name, not a path",
            ));
        }
        Ok(Paths::new(dir.join(name)))
    }

    pub fn open_wallet(&self, params: &Value) -> methods::MethodResult {
        let name = params
            .get("filename")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new(errors::UNKNOWN_ERROR, "filename is missing"))?;
        let password = params
            .get("password")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let paths = self.path_for(name)?;
        // The wallet already open here holds its own keys file, and opening it
        // again would find it locked by this server. So that one closes first.
        self.close_if_open(&paths)?;
        let mut session = Session::open(paths, password, self.kdf_rounds, Some(self.network))
            .map_err(|e| Error::new(errors::INVALID_PASSWORD, e))?;
        self.attach_daemon(&mut session);
        *self.wallet() = Some(session);
        Ok(json!({}))
    }

    pub fn close_wallet(&self) -> methods::MethodResult {
        let mut guard = self.wallet();
        if let Some(session) = guard.as_mut() {
            // An unflushed cache is a long rescan next time (`specs/14` §5).
            session
                .save()
                .map_err(|e| Error::new(errors::UNKNOWN_ERROR, e))?;
        }
        *guard = None;
        Ok(json!({}))
    }

    /// Save and close the open wallet if it is the one at `paths`.
    fn close_if_open(&self, paths: &Paths) -> Result<(), Error> {
        let mut guard = self.wallet();
        let Some(session) = guard.as_mut() else {
            return Ok(());
        };
        if session.paths.keys() != paths.keys() {
            return Ok(());
        }
        session
            .save()
            .map_err(|e| Error::new(errors::UNKNOWN_ERROR, e))?;
        *guard = None;
        Ok(())
    }

    pub fn create_wallet(&self, params: &Value) -> methods::MethodResult {
        let (name, password, language) = self.creation_params(params)?;
        let paths = self.path_for(&name)?;

        let mut rng =
            wow_wallet::entropy::seeded_rng().map_err(|e| Error::new(errors::UNKNOWN_ERROR, e))?;
        let spend = wow_crypto::types::SecretKey(rng.random_scalar());
        let account = AccountBase::from_spend_key(spend, wow_wallet::files::now())
            .ok_or_else(|| Error::new(errors::UNKNOWN_ERROR, "key generation failed"))?;

        self.install(paths, password, account, &language, 0)
    }

    pub fn restore_deterministic(&self, params: &Value) -> methods::MethodResult {
        let (name, password, language) = self.creation_params(params)?;
        let seed = params
            .get("seed")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new(errors::UNKNOWN_ERROR, "seed is missing"))?;
        let restore_height = params
            .get("restore_height")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        let (spend, _) = wow_crypto::mnemonic::words_to_key(seed)
            .map_err(|e| Error::new(errors::WRONG_KEY, format!("that seed is not valid: {e}")))?;
        let account = AccountBase::from_spend_key(spend, wow_wallet::files::now())
            .ok_or_else(|| Error::new(errors::WRONG_KEY, "that seed does not give a valid key"))?;

        let paths = self.path_for(&name)?;
        self.install(paths, password, account, &language, restore_height)
    }

    pub fn generate_from_keys(&self, params: &Value) -> methods::MethodResult {
        let (name, password, language) = self.creation_params(params)?;
        let address = params
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new(errors::WRONG_ADDRESS, "address is missing"))?;
        let view = params
            .get("viewkey")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new(errors::WRONG_KEY, "viewkey is missing"))?;
        let spend = params.get("spendkey").and_then(Value::as_str);
        let restore_height = params
            .get("restore_height")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        let decoded = wow_types::address::Address::decode_for(address, self.network)
            .map_err(|e| Error::new(errors::WRONG_ADDRESS, e.to_string()))?;
        let view = secret(view, "viewkey")?;

        let account = match spend {
            Some(s) => {
                let spend = secret(s, "spendkey")?;
                let a = AccountBase::from_keys(spend, view, wow_wallet::files::now())
                    .ok_or_else(|| Error::new(errors::WRONG_KEY, "those keys are not valid"))?;
                if a.keys.account_address != decoded.keys {
                    return Err(Error::new(
                        errors::WRONG_KEY,
                        "those keys do not belong to that address; nothing was written",
                    ));
                }
                a
            }
            None => {
                let a = AccountBase::view_only(decoded.keys, view, wow_wallet::files::now());
                a.keys.verify().map_err(|e| {
                    Error::new(
                        errors::WRONG_KEY,
                        format!("that view key does not match that address: {e}"),
                    )
                })?;
                a
            }
        };

        let paths = self.path_for(&name)?;
        self.install(paths, password, account, &language, restore_height)
    }

    fn creation_params(&self, params: &Value) -> Result<(String, String, String), Error> {
        let name = params
            .get("filename")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new(errors::UNKNOWN_ERROR, "filename is missing"))?
            .to_string();
        let password = params
            .get("password")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let language = params
            .get("language")
            .and_then(Value::as_str)
            .unwrap_or("English")
            .to_string();
        Ok((name, password, language))
    }

    fn install(
        &self,
        paths: Paths,
        password: String,
        account: AccountBase,
        language: &str,
        restore_height: u64,
    ) -> methods::MethodResult {
        if paths.keys().exists() {
            return Err(Error::new(
                errors::WALLET_ALREADY_EXISTS,
                format!("{} already exists", paths.keys().display()),
            ));
        }
        let mut session = Session::create(
            paths,
            self.network,
            password,
            self.kdf_rounds,
            account,
            language,
            restore_height,
        )
        .map_err(|e| Error::new(errors::UNKNOWN_ERROR, e))?;
        self.attach_daemon(&mut session);

        // A wallet generated just now cannot own anything older than the tip,
        // so it starts there rather than reading the whole chain to find
        // nothing. `restore_height` being zero is what marks it as generated
        // rather than restored -- `start_at_tip` refuses to move a wallet that
        // was told where to start, because doing so would hide its old funds
        // behind a balance of zero that looks perfectly correct.
        if restore_height == 0 {
            let tip = session.daemon_height;
            session.start_at_tip(tip);
        }

        let address = session.primary_address();
        let seed = session.seed(language).unwrap_or_default();
        *self.wallet() = Some(session);
        Ok(
            json!({ "address": address, "seed": seed, "info": "Wallet has been generated successfully." }),
        )
    }

    /// Whether a request carried the right credentials.
    ///
    /// `specs/14` §1 requires either `--rpc-login` or an explicit
    /// `--disable-rpc-login`, and says why: "an unauthenticated wallet RPC on a
    /// reachable interface is a wallet-draining hole". This build uses HTTP
    /// Basic rather than the reference's Digest — it is a different scheme, and
    /// the client has to be told — but it is a real check, not a stub.
    fn authorised(&self, header: Option<&str>) -> bool {
        let Some((user, pass)) = &self.login else {
            return true; // login explicitly disabled
        };
        let Some(value) = header else { return false };
        let Some(encoded) = value.strip_prefix("Basic ") else {
            return false;
        };
        let Some(decoded) = base64_decode(encoded.trim()) else {
            return false;
        };
        let expected = format!("{user}:{pass}");
        // Constant-time enough for a local credential: compare all bytes.
        decoded.len() == expected.len()
            && decoded
                .iter()
                .zip(expected.as_bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }
}

fn secret(s: &str, what: &str) -> Result<wow_crypto::types::SecretKey, Error> {
    let bytes = wow_crypto::hex::decode(s)
        .ok_or_else(|| Error::new(errors::BAD_HEX, format!("the {what} is not hex")))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::new(errors::WRONG_KEY, format!("the {what} is not 32 bytes")))?;
    if !wow_crypto::sc_check(&bytes) {
        return Err(Error::new(
            errors::WRONG_KEY,
            format!("the {what} is not a valid scalar"),
        ));
    }
    Ok(wow_crypto::types::SecretKey(bytes))
}

/// Just enough base64 for HTTP Basic.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = TABLE.iter().position(|t| *t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Serve until stopped.
pub fn serve(state: std::sync::Arc<State>, bind: &str) -> Result<(), String> {
    let listener = TcpListener::bind(bind).map_err(|e| format!("cannot bind {bind}: {e}"))?;
    eprintln!("wownero-wallet-rpc listening on {bind}");

    for stream in listener.incoming() {
        if state.stopping() {
            break;
        }
        let Ok(stream) = stream else { continue };
        // One thread per connection, joined implicitly by process exit. The
        // wallet lock makes the concurrency question moot: requests queue.
        let worker = state.clone();
        std::thread::spawn(move || handle(&worker, stream));
        if state.stopping() {
            break;
        }
    }
    Ok(())
}

fn handle(state: &State, mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));

    let Some((path, auth, body)) = read_request(&stream) else {
        let _ = write_response(&mut stream, 400, "application/json", b"{}");
        return;
    };

    if !state.authorised(auth.as_deref()) {
        let body = json!({"error": {"code": errors::DENIED, "message": "authentication required"}})
            .to_string();
        let _ = write_unauthorised(&mut stream, &body);
        return;
    }
    if path != "/json_rpc" {
        let body = json!({
            "error": {
                "code": errors::UNKNOWN_ERROR,
                "message": "the wallet RPC has one endpoint, /json_rpc (specs/14 §1)"
            }
        })
        .to_string();
        let _ = write_response(&mut stream, 404, "application/json", body.as_bytes());
        return;
    }

    let response = respond(state, &body);
    let _ = write_response(&mut stream, 200, "application/json", response.as_bytes());
}

/// One JSON-RPC exchange.
pub fn respond(state: &State, body: &[u8]) -> String {
    let request: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return envelope_error(
                &json!(null),
                errors::UNKNOWN_ERROR,
                &format!("invalid JSON: {e}"),
            )
        }
    };

    let id = request.get("id").cloned().unwrap_or(json!(0));
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return envelope_error(&id, errors::UNKNOWN_ERROR, "no method");
    };
    let params = request.get("params").cloned().unwrap_or(json!({}));

    match methods::dispatch(state, method, &params) {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string(),
        Err(e) => envelope_error(&id, e.code, &e.message),
    }
}

fn envelope_error(id: &Value, code: i32, message: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
    .to_string()
}

fn read_request(stream: &TcpStream) -> Option<(String, Option<String>, Vec<u8>)> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let mut seen = 0usize;

    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    seen += line.len();
    let path = line.split_whitespace().nth(1)?.to_string();

    let mut length = 0usize;
    let mut auth = None;
    loop {
        line.clear();
        let n = reader.read_line(&mut line).ok()?;
        if n == 0 {
            return None;
        }
        seen += n;
        if seen > MAX_HEADER_BYTES {
            return None;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "content-length" => length = value.trim().parse().ok()?,
                "authorization" => auth = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }
    if length > MAX_BODY {
        return None;
    }

    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).ok()?;
    Some((
        path.split('?').next().unwrap_or("/").to_string(),
        auth,
        body,
    ))
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        match status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            _ => "Unknown",
        },
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn write_unauthorised(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 401 Unauthorized\r\n\
         WWW-Authenticate: Basic realm=\"wownero-wallet-rpc\"\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(login: Option<(&str, &str)>) -> State {
        State::new(
            WalletSource::Dir(std::env::temp_dir()),
            Network::Mainnet,
            1,
            login.map(|(u, p)| (u.to_string(), p.to_string())),
            String::new(),
        )
    }

    #[test]
    fn base64_decodes_basic_credentials() {
        assert_eq!(base64_decode("dXNlcjpwYXNz").expect("ok"), b"user:pass");
        assert_eq!(base64_decode("YQ==").expect("ok"), b"a");
        assert_eq!(base64_decode("YWI=").expect("ok"), b"ab");
        assert_eq!(base64_decode("YWJj").expect("ok"), b"abc");
        assert!(base64_decode("not valid!").is_none());
    }

    /// With a login configured, a request without the right credentials is
    /// refused. This is the check `specs/14` §1 calls a wallet-draining hole
    /// if it is missing.
    #[test]
    fn authentication_is_enforced_when_configured() {
        let s = state(Some(("user", "pass")));
        assert!(s.authorised(Some("Basic dXNlcjpwYXNz")));
        assert!(!s.authorised(None), "no header");
        assert!(!s.authorised(Some("Basic d3Jvbmc=")), "wrong credentials");
        assert!(!s.authorised(Some("Bearer token")), "wrong scheme");
        assert!(!s.authorised(Some("Basic !!!")), "not base64");
    }

    /// With login explicitly disabled, anything passes — which is the point of
    /// making it explicit.
    #[test]
    fn disabling_login_is_explicit() {
        let s = state(None);
        assert!(s.authorised(None));
        assert!(s.authorised(Some("Basic anything")));
    }

    /// A wallet name is a file name. A client that sends a path gets a
    /// rejection rather than writing outside the wallet directory.
    #[test]
    fn a_wallet_name_cannot_escape_the_directory() {
        let s = state(None);
        for bad in [
            "../escape",
            "a/b",
            "a\\b",
            "..",
            "",
            "../../etc/passwd",
            "sub/../../x",
        ] {
            assert!(s.path_for(bad).is_err(), "`{bad}` should be refused");
        }
        assert!(s.path_for("mywallet").is_ok());
    }

    /// Every method returns `-13 NOT_OPEN` before a wallet is open, except the
    /// ones that open one.
    #[test]
    fn methods_need_an_open_wallet() {
        let s = state(None);
        for method in ["get_balance", "get_address", "transfer", "refresh", "store"] {
            let body = json!({"jsonrpc":"2.0","id":"0","method":method}).to_string();
            let response: Value =
                serde_json::from_str(&respond(&s, body.as_bytes())).expect("JSON");
            assert_eq!(
                response["error"]["code"],
                errors::NOT_OPEN,
                "{method} should say the wallet is not open: {response}"
            );
        }

        // `get_version` does not need one.
        let body = json!({"jsonrpc":"2.0","id":"0","method":"get_version"}).to_string();
        let response: Value = serde_json::from_str(&respond(&s, body.as_bytes())).expect("JSON");
        assert_eq!(response["result"]["version"], methods::WALLET_RPC_VERSION);
    }

    /// A malformed request is answered in the JSON-RPC envelope, not dropped.
    #[test]
    fn malformed_requests_are_answered() {
        let s = state(None);
        let response: Value = serde_json::from_str(&respond(&s, b"{not json")).expect("JSON");
        assert_eq!(response["error"]["code"], errors::UNKNOWN_ERROR);

        let response: Value = serde_json::from_str(&respond(&s, b"{}")).expect("JSON");
        assert_eq!(response["error"]["message"], "no method");
    }

    /// A method the reference has and this build does not is refused by name.
    #[test]
    fn disabled_methods_are_named() {
        let s = state(None);
        let body = json!({"jsonrpc":"2.0","id":"0","method":"get_tx_proof"}).to_string();
        let response: Value = serde_json::from_str(&respond(&s, body.as_bytes())).expect("JSON");
        assert_eq!(response["error"]["code"], errors::DISABLED);
        assert!(
            response["error"]["message"]
                .as_str()
                .expect("a message")
                .contains("proofs"),
            "{response}"
        );
    }
}
