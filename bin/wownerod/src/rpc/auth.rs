//! `--rpc-login`: HTTP Digest authentication (RFC 2617, MD5, `qop=auth`).
//!
//! Digest because it is what the reference daemon speaks, so a wallet built
//! against it logs in to this one unchanged. The password never crosses the
//! wire. Each response is tied to a nonce this server issued, and the request
//! counter `nc` must rise with every use of that nonce, so a captured
//! `Authorization` header cannot simply be sent again.
//!
//! None of that makes plain HTTP private: requests and answers are still
//! readable by anyone on the path, which is why a non-loopback bind asks for
//! consent (`specs/11` §1.2).
//!
//! # Failed logins
//!
//! `specs/11` §1.2: an address is blocked after `RPC_IP_FAILS_BEFORE_BLOCK (3)`
//! failures, unless `--disable-rpc-ban`. Only a *wrong* `Authorization` counts;
//! a request with none is the ordinary first half of a Digest exchange. The
//! loopback address is never blocked, so a typo at the node's own console does
//! not lock its operator out for a day.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use wow_crypto::md5::md5_hex;
use wow_crypto::random::Rng;

/// The realm the reference's challenge names.
pub const REALM: &str = "monero-rpc";
/// How long an issued nonce stays usable.
const NONCE_LIFETIME: Duration = Duration::from_secs(3_600);
/// Nonces kept at once; the oldest is dropped first.
const MAX_NONCES: usize = 1_024;
/// `RPC_IP_FAILS_BEFORE_BLOCK`.
pub const FAILS_BEFORE_BLOCK: u32 = 3;
/// How long a blocked address stays blocked (`P2P_IP_BLOCKTIME`).
const BLOCK_TIME: Duration = Duration::from_secs(86_400);
/// Failures older than this are forgotten.
const FAIL_WINDOW: Duration = Duration::from_secs(3_600);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct Issued {
    at: Instant,
    last_nc: u64,
}

/// The configured login and the state of the exchanges in flight.
pub struct Login {
    user: String,
    pass: String,
    ban: bool,
    rng: Mutex<Rng>,
    nonces: Mutex<HashMap<String, Issued>>,
    fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    blocked: Mutex<HashMap<IpAddr, Instant>>,
}

impl Login {
    /// `ban` is false under `--disable-rpc-ban`.
    pub fn new(user: &str, pass: &str, ban: bool, rng: Rng) -> Login {
        Login {
            user: user.to_string(),
            pass: pass.to_string(),
            ban,
            rng: Mutex::new(rng),
            nonces: Mutex::new(HashMap::new()),
            fails: Mutex::new(HashMap::new()),
            blocked: Mutex::new(HashMap::new()),
        }
    }

    /// A `WWW-Authenticate` value carrying a fresh nonce.
    pub fn challenge(&self) -> String {
        let mut bytes = [0u8; 16];
        lock(&self.rng).fill(&mut bytes);
        let nonce = wow_crypto::hex::encode(&bytes);

        let now = Instant::now();
        let mut nonces = lock(&self.nonces);
        nonces.retain(|_, i| now.duration_since(i.at) < NONCE_LIFETIME);
        if nonces.len() >= MAX_NONCES {
            let oldest = nonces
                .iter()
                .min_by_key(|(_, i)| i.at)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                nonces.remove(&k);
            }
        }
        nonces.insert(
            nonce.clone(),
            Issued {
                at: now,
                last_nc: 0,
            },
        );
        format!("Digest qop=\"auth\",algorithm=MD5,realm=\"{REALM}\",nonce=\"{nonce}\",stale=false")
    }

    /// Whether `header` authorises a `method` request for `uri`.
    pub fn check(&self, method: &str, uri: &str, header: Option<&str>) -> bool {
        let Some(params) = header.and_then(strip_scheme).map(parse_params) else {
            return false;
        };
        let get = |k: &str| params.get(k).map(String::as_str);
        let (Some(user), Some(realm), Some(nonce), Some(digest_uri), Some(response)) = (
            get("username"),
            get("realm"),
            get("nonce"),
            get("uri"),
            get("response"),
        ) else {
            return false;
        };
        if !constant_time_eq(user, &self.user) || realm != REALM || digest_uri != uri {
            return false;
        }
        if get("algorithm").is_some_and(|a| !a.eq_ignore_ascii_case("MD5")) {
            return false;
        }
        // `qop=auth` is required: without it there is no counter, and so no
        // protection against a replayed header.
        let (Some("auth"), Some(nc), Some(cnonce)) = (get("qop"), get("nc"), get("cnonce")) else {
            return false;
        };
        let Ok(count) = u64::from_str_radix(nc, 16) else {
            return false;
        };

        let mut nonces = lock(&self.nonces);
        let Some(issued) = nonces.get_mut(nonce) else {
            return false;
        };
        if issued.at.elapsed() >= NONCE_LIFETIME || count <= issued.last_nc {
            return false;
        }
        let expected = response_for(
            &self.user, REALM, &self.pass, method, uri, nonce, nc, cnonce,
        );
        if !constant_time_eq(&expected, &response.to_ascii_lowercase()) {
            return false;
        }
        issued.last_nc = count;
        true
    }

    /// Whether `ip` is blocked for failing too often.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        if !self.ban || ip.is_loopback() {
            return false;
        }
        let now = Instant::now();
        let mut blocked = lock(&self.blocked);
        blocked.retain(|_, until| *until > now);
        blocked.contains_key(&ip)
    }

    /// Count a failed login from `ip`; true when that blocks it.
    pub fn record_failure(&self, ip: IpAddr) -> bool {
        if !self.ban || ip.is_loopback() {
            return false;
        }
        let now = Instant::now();
        let mut fails = lock(&self.fails);
        // Forget every stale count, not only this address's: an address that
        // failed once or twice and never came back would otherwise stay here
        // for good, and one caller cycling through addresses -- an IPv6 /64
        // has plenty -- could grow the map without bound. The C++ `host_count`
        // map in `abstract_tcp_server2.inl` has that leak.
        fails.retain(|_, (_, first)| now.duration_since(*first) <= FAIL_WINDOW);
        let entry = fails.entry(ip).or_insert((0, now));
        entry.0 += 1;
        if entry.0 >= FAILS_BEFORE_BLOCK {
            fails.remove(&ip);
            lock(&self.blocked).insert(ip, now + BLOCK_TIME);
            return true;
        }
        false
    }
}

/// The RFC 2617 `response` for `qop=auth`.
#[allow(clippy::too_many_arguments, reason = "the RFC's own list of inputs")]
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

fn strip_scheme(h: &str) -> Option<&str> {
    let (scheme, rest) = h.trim().split_once(' ')?;
    scheme.eq_ignore_ascii_case("digest").then_some(rest)
}

/// `key=value, key="quoted, value"` into a map with lowercase keys.
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
                    other => value.push(other),
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

/// Compare without stopping at the first difference.
fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Login {
        Login::new(
            "alice",
            "correct horse",
            true,
            Rng::from_state([7u8; wow_crypto::keccak::HASH_STATE_BYTES]),
        )
    }

    fn nonce_of(challenge: &str) -> String {
        strip_scheme(challenge)
            .map(parse_params)
            .and_then(|p| p.get("nonce").cloned())
            .expect("a nonce")
    }

    fn header(nonce: &str, nc: &str, response: &str, uri: &str) -> String {
        format!(
            "Digest username=\"alice\", realm=\"{REALM}\", nonce=\"{nonce}\", uri=\"{uri}\", \
             algorithm=MD5, response=\"{response}\", qop=auth, nc={nc}, cnonce=\"0a4f113b\""
        )
    }

    /// The worked example in RFC 2617 §3.5.
    #[test]
    fn the_rfc_2617_example_computes() {
        assert_eq!(
            response_for(
                "Mufasa",
                "testrealm@host.com",
                "Circle Of Life",
                "GET",
                "/dir/index.html",
                "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                "00000001",
                "0a4f113b",
            ),
            "6629fae49393a05397450978507c4ef1"
        );
    }

    /// A client answering a challenge gets in; the same header again does not.
    #[test]
    fn a_challenge_answered_once_authorises_once() {
        let l = login();
        let nonce = nonce_of(&l.challenge());
        let good = response_for(
            "alice",
            REALM,
            "correct horse",
            "POST",
            "/json_rpc",
            &nonce,
            "00000001",
            "0a4f113b",
        );
        let h = header(&nonce, "00000001", &good, "/json_rpc");
        assert!(l.check("POST", "/json_rpc", Some(&h)));
        assert!(
            !l.check("POST", "/json_rpc", Some(&h)),
            "a replay is refused"
        );

        // The next count on the same nonce is fine.
        let next = response_for(
            "alice",
            REALM,
            "correct horse",
            "POST",
            "/json_rpc",
            &nonce,
            "00000002",
            "0a4f113b",
        );
        assert!(l.check(
            "POST",
            "/json_rpc",
            Some(&header(&nonce, "00000002", &next, "/json_rpc"))
        ));
    }

    #[test]
    fn wrong_credentials_and_foreign_nonces_are_refused() {
        let l = login();
        let nonce = nonce_of(&l.challenge());

        let wrong_pass = response_for(
            "alice",
            REALM,
            "wrong",
            "POST",
            "/json_rpc",
            &nonce,
            "00000001",
            "0a4f113b",
        );
        assert!(!l.check(
            "POST",
            "/json_rpc",
            Some(&header(&nonce, "00000001", &wrong_pass, "/json_rpc"))
        ));

        // Right password, but for another path than the one requested.
        let other_uri = response_for(
            "alice",
            REALM,
            "correct horse",
            "POST",
            "/get_info",
            &nonce,
            "00000001",
            "0a4f113b",
        );
        assert!(!l.check(
            "POST",
            "/json_rpc",
            Some(&header(&nonce, "00000001", &other_uri, "/get_info"))
        ));

        // A nonce this server never issued.
        let made_up = response_for(
            "alice",
            REALM,
            "correct horse",
            "POST",
            "/json_rpc",
            "feedface",
            "00000001",
            "0a4f113b",
        );
        assert!(!l.check(
            "POST",
            "/json_rpc",
            Some(&header("feedface", "00000001", &made_up, "/json_rpc"))
        ));

        assert!(!l.check("POST", "/json_rpc", None));
        assert!(!l.check("POST", "/json_rpc", Some("Basic YWxpY2U6eA==")));
    }

    /// Three failures block an address; loopback is never blocked, and
    /// `--disable-rpc-ban` blocks nobody.
    #[test]
    fn repeated_failures_block_an_address() {
        let l = login();
        let far: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(!l.record_failure(far));
        assert!(!l.record_failure(far));
        assert!(l.record_failure(far), "the third blocks");
        assert!(l.is_blocked(far));

        let local: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..10 {
            assert!(!l.record_failure(local));
        }
        assert!(!l.is_blocked(local));

        let lenient = Login::new(
            "alice",
            "x",
            false,
            Rng::from_state([1u8; wow_crypto::keccak::HASH_STATE_BYTES]),
        );
        for _ in 0..10 {
            lenient.record_failure(far);
        }
        assert!(!lenient.is_blocked(far));
    }

    #[test]
    fn quoted_parameters_parse() {
        let p = parse_params(r#"username="a, b", qop=auth, nc=00000001, realm="x\"y""#);
        assert_eq!(p["username"], "a, b");
        assert_eq!(p["qop"], "auth");
        assert_eq!(p["nc"], "00000001");
        assert_eq!(p["realm"], "x\"y");
        assert!(parse_params("").is_empty());
        assert!(parse_params("novalue, ,").is_empty());
    }
}
