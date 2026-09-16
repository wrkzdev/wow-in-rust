//! What the interface and the wallet say to each other.
//!
//! Plain data. On the desktop it crosses a channel to the wallet's thread as it
//! is; in a browser it crosses `postMessage` to a web worker as JSON.

use serde::{Deserialize, Serialize};
use wow_types::Network;

use crate::nodes::Node;

/// The networks a wallet can be made for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Net {
    #[default]
    Mainnet,
    Testnet,
    Stagenet,
}

impl Net {
    pub const ALL: [Net; 3] = [Net::Mainnet, Net::Testnet, Net::Stagenet];

    pub fn network(self) -> Network {
        match self {
            Net::Mainnet => Network::Mainnet,
            Net::Testnet => Network::Testnet,
            Net::Stagenet => Network::Stagenet,
        }
    }

    /// Fakechain shares mainnet's addresses, so it reads as mainnet.
    pub fn of(network: Network) -> Net {
        match network {
            Network::Testnet => Net::Testnet,
            Network::Stagenet => Net::Stagenet,
            Network::Mainnet | Network::Fakechain => Net::Mainnet,
        }
    }

    /// As a daemon's `nettype` and monero.fail's `network` spell it.
    pub fn name(self) -> &'static str {
        self.network().name()
    }
}

/// From the interface to the wallet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Command {
    /// The wallets kept, answered by [`Event::Wallets`].
    ListWallets,
    /// Keep wallets in this folder from now on. The desktop only.
    SetFolder(String),
    /// A wallet from new keys.
    Create(NewWallet),
    /// A wallet from a seed phrase.
    Restore(Restore),
    Open(OpenWallet),
    /// Save the open wallet and close it.
    Close,
    /// Use this node for the open wallet. An empty address uses none.
    UseNode(String),
    /// Ask a node what it is, without using it.
    TestNode { address: String, network: Net },
    /// Whether an https node's certificate is accepted whoever signed it, as a
    /// node with a self-signed certificate needs. The desktop only: a browser
    /// decides that itself.
    AcceptAnyCertificate(bool),
    /// Log from now on at `level`, 0 to 4 as `--log-level` takes it, or not
    /// at all with `None`; and to a file too, where the platform has one.
    SetLog { level: Option<u8>, to_file: bool },
    /// The log lines kept in memory, answered by [`Event::Log`].
    ReadLog,
    /// Forget the log lines kept in memory, answered by [`Event::Log`].
    ClearLog,
    /// Forget what the open wallet scanned and scan again from `height`, as
    /// wallet-cli's `rescan_bc` does. With `keep`, that height becomes its
    /// restore height too.
    Rescan { height: u64, keep: bool },
    /// The height the chain had reached by `date`, in seconds since 1970:
    /// reckoned from the open wallet's node, or from `node` when no wallet
    /// is open. Answered by [`Event::HeightOn`].
    HeightOn { date: u64, node: String },
    /// Look for new blocks now rather than at the next interval.
    Refresh,
    /// Build and sign a transaction and relay nothing, answered by
    /// [`Event::Prepared`].
    PrepareSend(SendForm),
    /// What a send would pay, planned and not built, answered by
    /// [`Event::FeeEstimate`].
    EstimateFee(SendForm),
    /// Relay the transaction last prepared.
    CommitSend,
    /// Forget the transaction last prepared.
    DiscardSend,
    ShowSeed { password: String },
    /// The secret view key, answered by [`Event::ViewKey`].
    ShowViewKey { password: String },
    /// Keep the open wallet under `new` from now on; `old` must be its
    /// password now. Answered by [`Event::PasswordChanged`].
    ChangePassword { old: String, new: String },
    /// A view-only keys file of the open wallet under `copy_password`,
    /// answered by [`Event::ViewOnlyExported`]. `password` must be the
    /// wallet's.
    ExportViewOnly {
        password: String,
        copy_password: String,
    },
    /// The subaddress at this index of the first account.
    Subaddress(u32),
    /// Keep a wallet's files, as exported from here or written by another
    /// wallet. The browser only.
    Import {
        name: String,
        keys: Bytes,
        cache: Option<Bytes>,
    },
    /// A wallet's files, answered by [`Event::Exported`]. The browser only.
    Export(String),
    /// Delete a kept wallet. The browser only.
    Forget(String),
    /// Save and close, because the program is exiting.
    Shutdown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewWallet {
    pub name: String,
    pub password: String,
    pub network: Net,
    /// A seed language's name, as `wow_crypto::mnemonic::by_name` reads it.
    pub language: String,
    /// The node to use once it is open; empty for none.
    pub node: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Restore {
    pub name: String,
    pub password: String,
    pub network: Net,
    pub seed: String,
    /// The seed offset passphrase, empty for none.
    pub passphrase: String,
    /// Where scanning starts. Too high hides older payments.
    pub restore_height: u64,
    pub node: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenWallet {
    pub name: String,
    pub password: String,
    pub node: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendForm {
    pub address: String,
    /// `None` sends everything unlocked, less the fee.
    pub amount: Option<u64>,
    /// 0 to 4, where 0 lets the wallet choose.
    pub priority: u32,
    /// 16 hex characters, or empty.
    pub payment_id: String,
}

/// From the wallet to the interface.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    /// The wallet side is up and listening.
    Ready,
    Wallets {
        names: Vec<String>,
        /// Where they are kept, for people to read.
        location: String,
    },
    /// Something slow has started: opening, creating, building, sending.
    Working(String),
    /// Nothing slow is running any more.
    Idle,
    Opened(Summary),
    /// A new wallet's seed phrase, shown once.
    NewSeed(String),
    Closed,
    Status(Status),
    History(Vec<Row>),
    NodeTested {
        address: String,
        result: Result<NodeReport, String>,
    },
    Prepared(Preview),
    Sent {
        txid: String,
    },
    /// The node refused the transaction, for these reasons.
    Rejected(Vec<String>),
    /// A send could not be prepared or estimated, and why.
    SendFailed(String),
    /// What a send would pay: the amount it sends, and the fee.
    FeeEstimate {
        amount: u64,
        fee: u64,
    },
    /// The log lines kept, oldest first, and the file the log is written to.
    Log {
        lines: Vec<String>,
        file: Option<String>,
    },
    /// The open wallet's restore height is now this.
    RestoreHeight(u64),
    /// The height the chain had reached by `date`, as [`Command::HeightOn`]
    /// asked.
    HeightOn { date: u64, height: u64 },
    Seed(String),
    /// The open wallet's secret view key, in hex.
    ViewKey(String),
    /// The open wallet is under the new password now.
    PasswordChanged,
    /// A view-only keys file of the wallet named `name`.
    ViewOnlyExported {
        name: String,
        keys: Bytes,
    },
    Subaddress {
        index: u32,
        address: String,
    },
    Exported {
        name: String,
        keys: Bytes,
        cache: Option<Bytes>,
    },
    /// Worth telling, and not a failure: a payment found, a node in use.
    Notice(String),
    Error(String),

    // The two below come from the interface's own host, not the wallet side.
    /// The public node list, fetched.
    NodeList(Result<Vec<Node>, String>),
    /// A file the user chose.
    Picked {
        purpose: Pick,
        name: String,
        bytes: Bytes,
    },
}

/// What a chosen file is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pick {
    Keys,
    Cache,
}

impl Pick {
    /// For the file chooser's filter.
    pub fn accept(self) -> &'static str {
        match self {
            Pick::Keys => ".keys",
            Pick::Cache => ".rscache",
        }
    }
}

/// An open wallet, as it does not change while open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub name: String,
    pub address: String,
    pub network: Net,
    pub view_only: bool,
    pub location: String,
    pub restore_height: u64,
    /// The default fee priority saved in the wallet.
    pub priority: u32,
}

/// An open wallet, as it changes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub balance: u64,
    pub unlocked: u64,
    /// What is not spendable yet, and how many blocks until the first of it
    /// is: `None` when nothing is locked.
    pub locked: u64,
    pub unlock_blocks: Option<u64>,
    /// How far the wallet has scanned, and the chain's height as last seen.
    pub scanned: u64,
    pub chain: u64,
    /// The node in use.
    pub node: Option<String>,
    /// Why the node could not be used, last time it was tried.
    pub node_error: Option<String>,
    pub syncing: bool,
}

/// One line of the transfer history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    /// `in`, `block`, `out`, `pending` or `failed`.
    pub kind: String,
    pub incoming: bool,
    pub txid: String,
    pub height: Option<u64>,
    pub timestamp: u64,
    pub amount: u64,
    pub fee: u64,
    pub unlocked: bool,
    /// Sent: where it went, and how much, as this wallet wrote them down.
    pub destinations: Vec<(String, u64)>,
    /// The payment ID it carried, in hex.
    pub payment_id: Option<String>,
    /// Received: the subaddress it came in on. Sent: those it spent from.
    pub minors: Vec<u32>,
}

/// What a node said when tested.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeReport {
    pub height: u64,
    pub target_height: u64,
    /// As the node spells it; empty if it did not say.
    pub network: String,
    pub synchronized: bool,
    /// How long it took to answer.
    pub millis: u64,
    /// Whether it is on the network asked about.
    pub right_network: bool,
}

/// A transaction built and signed, waiting for a yes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preview {
    pub address: String,
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
    pub inputs: usize,
    pub weight: u64,
    /// The fee tier's name.
    pub priority: String,
    pub payment_id: Option<String>,
    /// Outputs a sweep is leaving behind because taking them would make the
    /// transaction too heavy to relay. Zero for an ordinary send.
    ///
    /// Shown before the send is confirmed, not after: someone who asked to
    /// empty a wallet and was told nothing would reasonably believe it is now
    /// empty.
    pub left_behind: usize,
}

/// Bytes that travel as base64 in JSON rather than as an array of numbers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

impl Serialize for Bytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        base64::decode(&text)
            .map(Bytes)
            .ok_or_else(|| serde::de::Error::custom("not base64"))
    }
}

/// RFC 4648 base64, with padding.
mod base64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            let n = (u32::from(chunk[0]) << 16) | (u32::from(b1) << 8) | u32::from(b2);
            for i in 0..4usize {
                if i <= chunk.len() {
                    out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    pub fn decode(text: &str) -> Option<Vec<u8>> {
        let text = text.trim_end_matches('=');
        let mut out = Vec::with_capacity(text.len() * 3 / 4);
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for c in text.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return None,
            };
            acc = (acc << 6) | u32::from(v);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1u32 << bits) - 1;
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_every_padding() {
        let data: Vec<u8> = (0..=255).collect();
        for len in 0..10 {
            let text = base64::encode(&data[..len]);
            assert_eq!(text.len() % 4, 0, "{text}");
            assert_eq!(base64::decode(&text).expect("decodes"), &data[..len]);
        }
        assert_eq!(base64::encode(b"Wow"), "V293");
        assert_eq!(base64::encode(b"Wo"), "V28=");
        assert_eq!(base64::encode(b"W"), "Vw==");
        assert!(base64::decode("V2*=").is_none());
    }

    #[test]
    fn bytes_travel_as_text() {
        let command = Command::Import {
            name: "w".into(),
            keys: Bytes(vec![0, 1, 2, 250]),
            cache: None,
        };
        let json = serde_json::to_string(&command).expect("serializes");
        assert!(json.contains("\"AAEC+g==\""), "{json}");
        match serde_json::from_str::<Command>(&json).expect("parses") {
            Command::Import { keys, cache, .. } => {
                assert_eq!(keys.0, vec![0, 1, 2, 250]);
                assert!(cache.is_none());
            }
            other => panic!("came back as {other:?}"),
        }
    }

    /// `worker.js` writes this shape by hand when the wallet cannot start.
    #[test]
    fn an_error_is_a_one_key_object() {
        let json = serde_json::to_string(&Event::Error("x".into())).expect("serializes");
        assert_eq!(json, r#"{"Error":"x"}"#);
        assert!(matches!(
            serde_json::from_str::<Event>(r#"{"Error":"no"}"#),
            Ok(Event::Error(e)) if e == "no"
        ));
    }
}
