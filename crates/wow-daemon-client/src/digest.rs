//! HTTP Digest authentication, from the client's side (RFC 2617, MD5,
//! `qop=auth`).
//!
//! A daemon started with `--rpc-login` answers everything with `401` and a
//! `WWW-Authenticate: Digest` challenge until a request carries a matching
//! `Authorization`. Without this a wallet simply cannot talk to such a node,
//! which is most self-hosted ones — the operator who bothered to set a
//! password is exactly the operator running their own node for a wallet to
//! use.
//!
//! Digest rather than Basic because it is what the reference daemon speaks,
//! and `wownerod`'s own `rpc::auth` is the other half of this exchange. The
//! password never crosses the wire. That does not make plain HTTP private:
//! the requests and the answers are still readable by anyone on the path.
//!
//! # The nonce, and why the client keeps one
//!
//! The server issues a nonce and requires the request counter `nc` to rise
//! with every use of it, so a captured `Authorization` cannot be replayed. A
//! client that threw the nonce away after each request would need two round
//! trips for every call: one to be challenged, one to answer. So the last
//! challenge is kept and tried first, and only a `401` sends us back for a
//! fresh one — the first call of a session pays two trips, the rest pay one.
//!
//! # The client nonce is derived, not random
//!
//! `cnonce` exists so a client can verify the *server* through
//! `Authentication-Info`, which neither the reference daemon nor this one
//! sends. Its only job here is to differ between requests, so it is derived
//! from the server's nonce and the counter rather than drawn from an entropy
//! source this crate would otherwise not need — and would not have in a
//! browser build.

use std::collections::HashMap;
use std::sync::Mutex;

use wow_crypto::md5::md5_hex;

/// A user name and password for a daemon's `--rpc-login`.
#[derive(Clone)]
pub struct Credentials {
    pub user: String,
    pub pass: String,
}

impl Credentials {
    /// `user:password`, as `--daemon-login` takes it. A password may contain
    /// colons; the first one separates.
    pub fn parse(s: &str) -> Option<Credentials> {
        let (user, pass) = s.split_once(':')?;
        (!user.is_empty()).then(|| Credentials {
            user: user.to_string(),
            pass: pass.to_string(),
        })
    }
}

/// Never print a password, including through `{:?}`.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credentials {{ user: {:?}, pass: <hidden> }}", self.user)
    }
}

/// The credentials, and the last challenge seen from this daemon.
#[derive(Debug)]
pub struct Login {
    credentials: Credentials,
    /// The challenge last answered, and the next counter to use with it.
    state: Mutex<Option<Challenge>>,
}

#[derive(Clone, Debug)]
struct Challenge {
    realm: String,
    nonce: String,
    opaque: Option<String>,
    /// The next `nc` to send. Rises with every request against this nonce.
    nc: u64,
}

impl Login {
    pub fn new(credentials: Credentials) -> Login {
        Login {
            credentials,
            state: Mutex::new(None),
        }
    }

    pub fn user(&self) -> &str {
        &self.credentials.user
    }

    /// An `Authorization` header for `method uri` from the challenge last
    /// seen, or `None` when there has not been one yet.
    pub fn authorization(&self, method: &str, uri: &str) -> Option<String> {
        let mut held = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let c = held.as_mut()?;
        let nc = c.nc;
        c.nc += 1;
        Some(header(&self.credentials, c, method, uri, nc))
    }

    /// Take in a `WWW-Authenticate` header and answer it.
    ///
    /// `None` when the header is not a Digest challenge this can answer — an
    /// algorithm it does not implement, say — so the caller reports the `401`
    /// rather than retrying forever.
    pub fn answer(&self, www_authenticate: &str, method: &str, uri: &str) -> Option<String> {
        let rest = strip_scheme(www_authenticate)?;
        let params = parse_params(rest);
        // MD5 or absent. The reference sends neither SHA-256 nor `-sess`.
        if let Some(a) = params.get("algorithm") {
            if !a.eq_ignore_ascii_case("md5") {
                return None;
            }
        }
        // `qop` absent means RFC 2069, which the reference never sends and
        // which is not worth a second code path.
        let has_auth = params.get("qop").is_some_and(|q| {
            q.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("auth"))
        });
        if !has_auth {
            return None;
        }
        let mut c = Challenge {
            realm: params.get("realm")?.clone(),
            nonce: params.get("nonce")?.clone(),
            opaque: params.get("opaque").cloned(),
            nc: 1,
        };
        let out = header(&self.credentials, &c, method, uri, c.nc);
        c.nc += 1;
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = Some(c);
        Some(out)
    }

    /// Forget the challenge, so the next request asks for a fresh one.
    pub fn stale(&self) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// The RFC 2617 `response` for `qop=auth`.
///
/// The daemon's `rpc::auth` computes the same value. If these two ever
/// disagree, this is the side to fix: the reference daemon is the one a
/// wallet has to satisfy.
#[allow(clippy::too_many_arguments)]
pub fn response_for(
    user: &str,
    realm: &str,
    pass: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    nc: &str,
    cnonce: &str,
) -> String {
    let ha1 = md5_hex(format!("{user}:{realm}:{pass}").as_bytes());
    let ha2 = md5_hex(format!("{method}:{uri}").as_bytes());
    md5_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}").as_bytes())
}

fn header(creds: &Credentials, c: &Challenge, method: &str, uri: &str, nc: u64) -> String {
    let nc_text = format!("{nc:08x}");
    let cnonce = client_nonce(&c.nonce, &nc_text);
    let response = response_for(
        &creds.user,
        &c.realm,
        &creds.pass,
        method,
        uri,
        &c.nonce,
        &nc_text,
        &cnonce,
    );
    let mut out = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", \
         algorithm=MD5, response=\"{}\", qop=auth, nc={}, cnonce=\"{}\"",
        escape(&creds.user),
        escape(&c.realm),
        escape(&c.nonce),
        escape(uri),
        response,
        nc_text,
        cnonce,
    );
    if let Some(o) = &c.opaque {
        out.push_str(&format!(", opaque=\"{}\"", escape(o)));
    }
    out
}

/// A `cnonce` that differs per request without needing entropy. The module
/// documentation says why that is enough here.
fn client_nonce(nonce: &str, nc: &str) -> String {
    md5_hex(format!("cnonce:{nonce}:{nc}").as_bytes())[..16].to_string()
}

/// Quoted-string escaping. A realm or a user name containing a `"` would
/// otherwise end the field early and produce a header the server misreads.
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn strip_scheme(h: &str) -> Option<&str> {
    let (scheme, rest) = h.trim().split_once(' ')?;
    scheme.eq_ignore_ascii_case("digest").then_some(rest)
}

/// `key=value, key="quoted, value"` into a map with lowercase keys.
///
/// The same shape as the daemon's `rpc::auth::parse_params`, and separate on
/// purpose: that one lives in a binary crate, and a wallet must not have to
/// depend on the node in order to talk to one.
pub fn parse_params(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut chars = s.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| *c == ',' || c.is_whitespace()) {
            chars.next();
        }
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c == ',' {
                break;
            }
            key.push(c);
            chars.next();
        }
        if key.is_empty() {
            break;
        }
        if chars.peek() != Some(&'=') {
            continue;
        }
        chars.next();
        let mut value = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        if let Some(escaped) = chars.next() {
                            value.push(escaped);
                        }
                    }
                    '"' => break,
                    _ => value.push(c),
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                value.push(c);
                chars.next();
            }
        }
        out.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHALLENGE: &str =
        "Digest qop=\"auth\", realm=\"monero-rpc\", nonce=\"abc123\", stale=false, algorithm=MD5";

    fn login() -> Login {
        Login::new(Credentials {
            user: "bob".into(),
            pass: "hunter2".into(),
        })
    }

    /// `user:password`, with a password free to contain colons.
    #[test]
    fn credentials_split_at_the_first_colon() {
        let c = Credentials::parse("bob:hun:ter2").expect("parsed");
        assert_eq!(c.user, "bob");
        assert_eq!(c.pass, "hun:ter2");
        assert!(Credentials::parse("nocolon").is_none());
        assert!(
            Credentials::parse(":nouser").is_none(),
            "a user is required"
        );
        // An empty password is allowed: the daemon generates one and prints it,
        // and somebody will paste it back without the password part.
        assert_eq!(Credentials::parse("bob:").expect("parsed").pass, "");
    }

    /// The password is not in the debug output, which is what ends up in logs.
    #[test]
    fn a_password_is_never_printed() {
        let c = Credentials {
            user: "bob".into(),
            pass: "hunter2".into(),
        };
        let shown = format!("{c:?}");
        assert!(shown.contains("bob"));
        assert!(!shown.contains("hunter2"), "{shown}");
    }

    /// The response is RFC 2617's, which is what the daemon's
    /// `rpc::auth::response_for` computes.
    #[test]
    fn the_response_is_the_rfc_2617_one() {
        let ha1 = md5_hex(b"bob:monero-rpc:hunter2");
        let ha2 = md5_hex(b"POST:/json_rpc");
        let want = md5_hex(format!("{ha1}:abc123:00000001:0a4f113b:auth:{ha2}").as_bytes());
        assert_eq!(
            response_for(
                "bob",
                "monero-rpc",
                "hunter2",
                "POST",
                "/json_rpc",
                "abc123",
                "00000001",
                "0a4f113b"
            ),
            want
        );
    }

    /// Answering a challenge produces a header carrying everything the daemon
    /// reads, and the counter starts at one.
    #[test]
    fn a_challenge_is_answered_with_every_field_the_daemon_reads() {
        let l = login();
        let h = l.answer(CHALLENGE, "POST", "/json_rpc").expect("answered");
        let p = parse_params(strip_scheme(&h).expect("digest"));
        assert_eq!(p.get("username").map(String::as_str), Some("bob"));
        assert_eq!(p.get("realm").map(String::as_str), Some("monero-rpc"));
        assert_eq!(p.get("nonce").map(String::as_str), Some("abc123"));
        assert_eq!(p.get("uri").map(String::as_str), Some("/json_rpc"));
        assert_eq!(p.get("qop").map(String::as_str), Some("auth"));
        assert_eq!(p.get("nc").map(String::as_str), Some("00000001"));
        assert!(p.contains_key("cnonce"));
        assert!(p.contains_key("response"));
        assert!(
            !h.contains("hunter2"),
            "the password does not go on the wire"
        );
    }

    /// The counter rises with every request against one nonce, which is what
    /// stops a captured header being sent again.
    #[test]
    fn the_request_counter_rises_and_never_repeats() {
        let l = login();
        l.answer(CHALLENGE, "POST", "/json_rpc").expect("answered");

        let mut seen = vec!["00000001".to_string()];
        for _ in 0..3 {
            let h = l.authorization("POST", "/json_rpc").expect("a held nonce");
            let p = parse_params(strip_scheme(&h).expect("digest"));
            seen.push(p.get("nc").cloned().expect("nc"));
        }
        assert_eq!(seen, ["00000001", "00000002", "00000003", "00000004"]);

        // And the client nonce moves with it, so no two requests carry the
        // same response.
        let a = l.authorization("POST", "/json_rpc").expect("held");
        let b = l.authorization("POST", "/json_rpc").expect("held");
        assert_ne!(a, b);
    }

    /// Before any challenge, and after one goes stale, there is nothing to
    /// send and the caller asks for a new one.
    #[test]
    fn there_is_no_header_before_a_challenge_or_after_it_goes_stale() {
        let l = login();
        assert!(l.authorization("POST", "/json_rpc").is_none());
        l.answer(CHALLENGE, "POST", "/json_rpc").expect("answered");
        assert!(l.authorization("POST", "/json_rpc").is_some());
        l.stale();
        assert!(l.authorization("POST", "/json_rpc").is_none());
    }

    /// A challenge this cannot answer is declined rather than answered wrongly,
    /// so the caller reports the 401 instead of retrying forever.
    #[test]
    fn an_unanswerable_challenge_is_declined() {
        let l = login();
        for bad in [
            "Basic realm=\"monero-rpc\"",
            "Digest realm=\"r\", nonce=\"n\", qop=\"auth\", algorithm=SHA-256",
            "Digest realm=\"r\", nonce=\"n\"",
            "Digest realm=\"r\", qop=\"auth\"",
            "Digest nonce=\"n\", qop=\"auth\"",
        ] {
            assert!(l.answer(bad, "POST", "/json_rpc").is_none(), "{bad}");
        }
    }

    /// A quoted value containing a comma is one value, not two fields.
    #[test]
    fn quoted_values_may_contain_commas_and_escapes() {
        let p = parse_params("realm=\"a, b\", nonce=\"n\\\"x\", stale=false");
        assert_eq!(p.get("realm").map(String::as_str), Some("a, b"));
        assert_eq!(p.get("nonce").map(String::as_str), Some("n\"x"));
        assert_eq!(p.get("stale").map(String::as_str), Some("false"));
    }

    /// A realm or a user name with a quote in it must not end the field early.
    #[test]
    fn quotes_in_a_field_are_escaped_on_the_way_out() {
        let l = Login::new(Credentials {
            user: "b\"ob".into(),
            pass: "p".into(),
        });
        let h = l
            .answer(
                "Digest realm=\"m\\\"r\", nonce=\"n\", qop=\"auth\"",
                "POST",
                "/json_rpc",
            )
            .expect("answered");
        let p = parse_params(strip_scheme(&h).expect("digest"));
        assert_eq!(p.get("username").map(String::as_str), Some("b\"ob"));
        assert_eq!(p.get("realm").map(String::as_str), Some("m\"r"));
    }
}
