//! Choosing a node: the public list, and addresses as people type them.

use serde::{Deserialize, Serialize};

use crate::protocol::Net;

/// A Wownero node's RPC port, when an address gives none.
pub const DEFAULT_PORT: u16 = 34568;

/// monero.fail's list of healthy nodes on a network. It answers any origin,
/// so a web page can fetch it.
pub fn list_url(network: Net) -> String {
    format!(
        "https://monero.fail/api/v1/nodes/?crypto=wownero&network={}&type=all&healthy=true&page=1&per_page=50",
        network.name()
    )
}

/// One node, as monero.fail lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub url: String,
    /// Whether it answers requests from web pages (CORS).
    #[serde(default)]
    pub web_compatible: bool,
    #[serde(default)]
    pub is_tor: bool,
    #[serde(default)]
    pub is_i2p: bool,
    #[serde(default)]
    pub last_height: Option<u64>,
    #[serde(default)]
    pub country_name: Option<String>,
}

#[derive(Deserialize)]
struct Listing {
    nodes: Vec<Node>,
}

pub fn parse_listing(json: &str) -> Result<Vec<Node>, String> {
    serde_json::from_str::<Listing>(json)
        .map(|l| l.nodes)
        .map_err(|e| format!("the node list could not be read: {e}"))
}

/// The mainnet list as monero.fail gave it on 15 September 2026, for when it
/// cannot be fetched: the desktop wallet cannot fetch it before it speaks TLS.
pub fn snapshot(network: Net) -> Vec<Node> {
    if network != Net::Mainnet {
        return Vec::new();
    }
    let node = |url: &str, is_tor: bool, height: u64, country: Option<&str>| Node {
        url: url.to_string(),
        web_compatible: false,
        is_tor,
        is_i2p: false,
        last_height: Some(height),
        country_name: country.map(str::to_string),
    };
    vec![
        node(
            "https://wownero.stackwallet.com:34568",
            false,
            873_836,
            Some("Canada"),
        ),
        node(
            "http://77uase4p6y6jsjdf6z2kdgpxgh7nkvywagvhurzphbm7vrkyj2d2gdid.onion:34568",
            true,
            873_901,
            None,
        ),
        node(
            "http://node3.monerodevs.org:34568",
            false,
            873_882,
            Some("Germany"),
        ),
        node(
            "http://node2.monerodevs.org:34568",
            false,
            873_882,
            None,
        ),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

/// A node's address: `host:port`, with the scheme to reach it by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAddress {
    pub scheme: Scheme,
    /// Lower case; an IPv6 address keeps its brackets.
    pub host: String,
    pub port: u16,
}

impl NodeAddress {
    /// Read an address as typed: `host`, `host:port`, `http://host:port`,
    /// `https://host:port` or `[::1]:34568`. No scheme means plain HTTP, as
    /// wallet-cli's `--daemon-address` means it; no port means 34568.
    pub fn parse(text: &str) -> Result<NodeAddress, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("no node address given".into());
        }
        let (scheme, rest) = match text.split_once("://") {
            None => (Scheme::Http, text),
            Some((s, rest)) => match s.to_ascii_lowercase().as_str() {
                "http" => (Scheme::Http, rest),
                "https" => (Scheme::Https, rest),
                other => {
                    return Err(format!(
                        "`{other}://` is not a node address; use http:// or https://"
                    ))
                }
            },
        };
        let rest = rest.trim_end_matches('/');
        if rest.contains(['/', '?', '#', '@']) {
            return Err("a node address is a host and a port, with no path".into());
        }

        let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
            let (host, after) = inner
                .split_once(']')
                .ok_or("an IPv6 address needs its closing `]`")?;
            let port = match after {
                "" => None,
                p => Some(
                    p.strip_prefix(':')
                        .ok_or("expected `:port` after the IPv6 address")?,
                ),
            };
            (format!("[{host}]"), port)
        } else {
            match rest.rsplit_once(':') {
                Some((h, _)) if h.contains(':') => {
                    return Err("put an IPv6 address in brackets: [::1]:34568".into())
                }
                Some((h, p)) => (h.to_string(), Some(p)),
                None => (rest.to_string(), None),
            }
        };
        if host.is_empty() || host == "[]" {
            return Err("the node address has no host".into());
        }
        let port = match port {
            None => DEFAULT_PORT,
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("`{p}` is not a port"))?,
        };
        Ok(NodeAddress {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// `host:port`, as a socket address.
    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Where requests go, with no trailing slash.
    pub fn url(&self) -> String {
        let scheme = match self.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        format!("{scheme}://{}:{}", self.host, self.port)
    }

    pub fn is_onion(&self) -> bool {
        self.host.ends_with(".onion")
    }

    pub fn is_i2p(&self) -> bool {
        self.host.ends_with(".i2p")
    }

    /// Why this program cannot reach the node, when that is known before
    /// trying. `secure_page` is whether a browser loaded the wallet over https.
    pub fn unreachable_reason(&self, in_browser: bool, secure_page: bool) -> Option<&'static str> {
        if in_browser {
            // Tor Browser reaches .onion from any page; mixed-content rules
            // leave it alone.
            if secure_page && self.scheme == Scheme::Http && !self.is_onion() {
                return Some(
                    "this page was loaded over https, so the browser blocks http:// nodes; use an https:// node",
                );
            }
            return None;
        }
        if self.is_onion() {
            return Some("a .onion node is reached through Tor, which this wallet does not use yet");
        }
        if self.is_i2p() {
            return Some("an .i2p node is reached through I2P, which this wallet does not use yet");
        }
        if self.scheme == Scheme::Https {
            return Some("the desktop wallet does not speak TLS yet; use an http:// node");
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_read_as_typed() {
        let a = NodeAddress::parse("node3.monerodevs.org:34568").expect("ok");
        assert_eq!(a.scheme, Scheme::Http);
        assert_eq!(a.url(), "http://node3.monerodevs.org:34568");

        let a = NodeAddress::parse(" HTTPS://Wownero.StackWallet.com:34568/ ").expect("ok");
        assert_eq!(a.scheme, Scheme::Https);
        assert_eq!(a.host_port(), "wownero.stackwallet.com:34568");

        assert_eq!(NodeAddress::parse("127.0.0.1").expect("ok").port, DEFAULT_PORT);
        assert_eq!(
            NodeAddress::parse("[::1]:18081").expect("ok").url(),
            "http://[::1]:18081"
        );
        assert_eq!(NodeAddress::parse("[::1]").expect("ok").port, DEFAULT_PORT);
    }

    #[test]
    fn what_is_not_an_address_is_refused() {
        for bad in [
            "",
            "ftp://node:34568",
            "node:0",
            "node:65536",
            "node:port",
            "::1:34568",
            "[::1",
            "http://node:34568/json_rpc",
            "user@node:34568",
            ":34568",
        ] {
            assert!(NodeAddress::parse(bad).is_err(), "`{bad}` should be refused");
        }
    }

    #[test]
    fn reachability_depends_on_where_the_wallet_runs() {
        let http = NodeAddress::parse("http://node:34568").expect("ok");
        let https = NodeAddress::parse("https://node:34568").expect("ok");
        let onion = NodeAddress::parse("http://abc.onion:34568").expect("ok");

        assert!(http.unreachable_reason(false, false).is_none());
        assert!(https.unreachable_reason(false, false).is_some());
        assert!(onion.unreachable_reason(false, false).is_some());

        assert!(http.unreachable_reason(true, true).is_some());
        assert!(http.unreachable_reason(true, false).is_none());
        assert!(https.unreachable_reason(true, true).is_none());
        assert!(onion.unreachable_reason(true, true).is_none());
    }

    #[test]
    fn the_public_list_parses() {
        let json = r#"{"total": 1, "nodes": [{"url": "http://node3.monerodevs.org:34568",
            "available": true, "web_compatible": false, "is_tor": false, "is_i2p": false,
            "nettype": "mainnet", "last_height": 873882, "country_name": "Germany",
            "lat": 51.2993, "lon": 9.491}]}"#;
        let nodes = parse_listing(json).expect("parses");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].last_height, Some(873_882));
        assert!(parse_listing("{}").is_err());
        assert_eq!(snapshot(Net::Mainnet).len(), 4);
        for n in snapshot(Net::Mainnet) {
            assert!(NodeAddress::parse(&n.url).is_ok(), "{}", n.url);
        }
    }
}
