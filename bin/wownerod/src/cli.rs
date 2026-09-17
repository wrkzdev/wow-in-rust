//! Command line parsing.
//!
//! `specs/09-daemon.md` §3. Only the options this node can honour are accepted;
//! an option from §3.2 that is recognised but not yet implemented is rejected
//! with a message saying so, rather than being parsed and ignored. A daemon
//! that silently drops `--db-sync-mode` is worse than one that refuses it.

use std::collections::HashSet;
use std::path::PathBuf;

use wow_storage::env::SyncMode;
use wow_types::Network;

/// What to do after opening the database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Report the tip and the database's identity, then exit.
    Status,
    /// `--check-difficulty-checkpoints` (`specs/07` §6, `specs/10` §7).
    CheckDifficultyCheckpoints,
    /// Replay the whole chain's difficulty, not just the checkpointed heights.
    VerifyDifficulty { from: u64, to: Option<u64> },
    /// Print the genesis hash for each network and exit.
    Genesis,
    /// Serve the RPC and stay running (`specs/11`).
    Serve,
    /// Sync the chain from one peer (`specs/08` §5), then exit.
    SyncFrom { address: String, max_batches: usize },
}

/// Parsed options.
#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub network: Network,
    /// `--regtest` reaches Fakechain with `fake` already appended to the data
    /// directory (`specs/10` §2).
    pub regtest: bool,
    pub read_only: bool,
    pub sync_mode: SyncMode,
    pub salvage: bool,
    pub command: Command,

    // -- RPC (`specs/11`) --
    pub rpc_bind_ip: String,
    pub rpc_bind_port: u16,
    /// `--restricted-rpc` (`specs/11` §1.3).
    pub restricted_rpc: bool,
    /// Required to bind `--rpc-bind-ip` or `--rpc-bind-ipv6-address` to a
    /// non-loopback address, restricted or not, login or not (`specs/11`
    /// §1.2).
    pub confirm_external_bind: bool,
    /// `--rpc-ssl` and its companions (`specs/11` §1.2, [`crate::rpc::tls`]).
    pub rpc_ssl: RpcSsl,
    pub rpc_ssl_private_key: Option<PathBuf>,
    pub rpc_ssl_certificate: Option<PathBuf>,
    pub rpc_ssl_ca_certificates: Option<PathBuf>,
    /// SHA-256 fingerprints of the client certificates to accept.
    pub rpc_ssl_allowed_fingerprints: Vec<[u8; 32]>,
    pub rpc_ssl_allow_chained: bool,
    pub rpc_ssl_allow_any_cert: bool,
    /// A second, restricted listener (`specs/11` §1.3). Loopback by default,
    /// as in the C++, and not `--rpc-bind-ip`: a node exposing its main RPC
    /// has not thereby asked for a second port on the same address.
    pub rpc_restricted_bind_ip: String,
    pub rpc_restricted_bind_port: Option<u16>,
    /// `--rpc-bind-ipv6-address` and `--rpc-restricted-bind-ipv6-address`,
    /// listened on as well with `--rpc-use-ipv6`.
    pub rpc_bind_ipv6_address: String,
    pub rpc_restricted_bind_ipv6_address: String,
    pub rpc_use_ipv6: bool,
    /// `--rpc-ignore-ipv4`: carry on when the IPv4 listener cannot bind.
    pub rpc_ignore_ipv4: bool,
    /// Advertise the restricted RPC port to peers.
    pub public_node: bool,
    /// `--rpc-login user[:password]`; a missing password is generated at start.
    pub rpc_login: Option<(String, Option<String>)>,
    pub rpc_access_control_origins: Vec<String>,
    pub disable_rpc_ban: bool,
    pub rpc_max_connections: usize,
    pub rpc_max_connections_per_public_ip: usize,
    pub rpc_max_connections_per_private_ip: usize,

    // -- ZMQ (`specs/09` §3.2, [`crate::zmq`]) --
    /// `--no-zmq`. The ZMQ RPC runs otherwise, as in the C++.
    pub no_zmq: bool,
    pub zmq_rpc_bind_ip: String,
    pub zmq_rpc_bind_port: u16,
    /// `--zmq-pub tcp://ip:port`, repeatable.
    pub zmq_pub: Vec<std::net::SocketAddr>,
    pub restricted_zmq_rpc: bool,
    /// Required to bind the ZMQ RPC, which has no TLS or login, beyond
    /// loopback.
    pub confirm_zmq_rpc_external_bind: bool,

    // -- peer-to-peer (`specs/08`) --
    pub p2p_bind_ip: String,
    pub p2p_bind_port: u16,
    /// `--p2p-bind-ipv6-address` and `--p2p-bind-port-ipv6`, listened on with
    /// `--p2p-use-ipv6`. IPv6 peers are dialled either way, as in the C++.
    pub p2p_bind_ipv6_address: String,
    pub p2p_bind_port_ipv6: u16,
    pub p2p_use_ipv6: bool,
    /// `--p2p-ignore-ipv4`: carry on when the IPv4 listener cannot bind.
    pub p2p_ignore_ipv4: bool,
    pub p2p_external_port: Option<u16>,
    pub hide_my_port: bool,
    /// `host[:port]`, resolved when the node starts.
    pub add_peers: Vec<String>,
    pub priority_nodes: Vec<String>,
    pub exclusive_nodes: Vec<String>,
    /// Replaces the hard-coded seeds when any are given.
    pub seed_nodes: Vec<String>,
    pub out_peers: usize,
    /// `usize::MAX` for no limit, the C++'s default.
    pub in_peers: usize,
    pub max_connections_per_ip: usize,
    pub allow_local_ip: bool,
    pub no_sync: bool,
    pub offline: bool,
    pub ban_list: Option<PathBuf>,
    pub keep_alt_blocks: bool,
    /// `--pad-transactions`: relayed transactions go out padded to a multiple
    /// of a kilobyte. Off by default, as in the C++.
    pub pad_transactions: bool,

    // -- logging (`specs/09` §8) --
    /// `0`-`4` or `category:LEVEL,...`.
    pub log_level: Option<String>,
    pub log_file: Option<PathBuf>,
    pub max_log_file_size: u64,
    pub max_log_files: usize,

    // -- the node --
    /// `--max-txpool-weight`.
    pub max_txpool_weight: u64,
    pub pidfile: Option<PathBuf>,
    /// No console, even at a terminal.
    pub non_interactive: bool,

    // -- mining (`specs/09` §6) --
    /// `--start-mining`: the address to mine to from the start.
    pub start_mining: Option<String>,
    pub mining_threads: usize,
    /// `--spendkey`, which signs block headers from HF 18.
    pub spendkey: Option<crate::miner::SpendKey>,
    /// `--vote`: 0 none, 1 yes, 2 no (`specs/06` §4.3).
    pub vote: u16,
    /// `--fixed-difficulty`, regtest only.
    pub fixed_difficulty: Option<u128>,
}

/// `--rpc-ssl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcSsl {
    Enabled,
    Disabled,
    /// Plain and TLS clients on the same port -- the C++'s default.
    Autodetect,
}

/// The config file's name in the data directory (`specs/09` §3).
pub const CONFIG_FILENAME: &str = "wownero.conf";

/// `RPC_DEFAULT_PORT` per network (`cryptonote_config.h`).
pub const fn default_rpc_port(network: Network) -> u16 {
    match network {
        Network::Testnet => 28_081,
        Network::Stagenet => 38_081,
        // Fakechain shares mainnet's, as the C++ does.
        _ => 34_568,
    }
}

/// `ZMQ_RPC_DEFAULT_PORT` per network.
pub const fn default_zmq_rpc_port(network: Network) -> u16 {
    match network {
        Network::Testnet => 28_082,
        Network::Stagenet => 38_082,
        _ => 34_569,
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            data_dir: default_data_dir(Network::Mainnet),
            network: Network::Mainnet,
            regtest: false,
            read_only: false,
            // `specs/09` §3.2: the default is `fast:async:250000000bytes`.
            sync_mode: SyncMode::Fast,
            salvage: false,
            command: Command::Status,
            rpc_bind_ip: "127.0.0.1".into(),
            rpc_bind_port: default_rpc_port(Network::Mainnet),
            restricted_rpc: false,
            confirm_external_bind: false,
            rpc_ssl: RpcSsl::Autodetect,
            rpc_ssl_private_key: None,
            rpc_ssl_certificate: None,
            rpc_ssl_ca_certificates: None,
            rpc_ssl_allowed_fingerprints: Vec::new(),
            rpc_ssl_allow_chained: false,
            rpc_ssl_allow_any_cert: false,
            rpc_restricted_bind_ip: "127.0.0.1".into(),
            rpc_restricted_bind_port: None,
            rpc_bind_ipv6_address: "::1".into(),
            rpc_restricted_bind_ipv6_address: "::1".into(),
            rpc_use_ipv6: false,
            rpc_ignore_ipv4: false,
            public_node: false,
            rpc_login: None,
            rpc_access_control_origins: Vec::new(),
            disable_rpc_ban: false,
            rpc_max_connections: crate::rpc::MAX_CONNECTIONS,
            rpc_max_connections_per_public_ip: crate::rpc::MAX_CONNECTIONS_PER_PUBLIC_IP,
            rpc_max_connections_per_private_ip: crate::rpc::MAX_CONNECTIONS_PER_PRIVATE_IP,
            no_zmq: false,
            zmq_rpc_bind_ip: "127.0.0.1".into(),
            zmq_rpc_bind_port: default_zmq_rpc_port(Network::Mainnet),
            zmq_pub: Vec::new(),
            restricted_zmq_rpc: false,
            confirm_zmq_rpc_external_bind: false,
            p2p_bind_ip: "0.0.0.0".into(),
            p2p_bind_port: default_p2p_port(Network::Mainnet),
            p2p_bind_ipv6_address: "::".into(),
            p2p_bind_port_ipv6: default_p2p_port(Network::Mainnet),
            p2p_use_ipv6: false,
            p2p_ignore_ipv4: false,
            p2p_external_port: None,
            hide_my_port: false,
            add_peers: Vec::new(),
            priority_nodes: Vec::new(),
            exclusive_nodes: Vec::new(),
            seed_nodes: Vec::new(),
            // `P2P_DEFAULT_CONNECTIONS_COUNT`.
            out_peers: 12,
            in_peers: usize::MAX,
            max_connections_per_ip: 1,
            allow_local_ip: false,
            no_sync: false,
            offline: false,
            ban_list: None,
            keep_alt_blocks: false,
            pad_transactions: false,
            log_level: None,
            log_file: None,
            max_log_file_size: 104_850_000,
            max_log_files: 50,
            // `DEFAULT_TXPOOL_MAX_WEIGHT`.
            max_txpool_weight: 648_000_000,
            pidfile: None,
            non_interactive: false,
            start_mining: None,
            mining_threads: 1,
            spendkey: None,
            vote: 0,
            fixed_difficulty: None,
        }
    }
}

/// `P2P_DEFAULT_PORT` per network.
pub fn default_p2p_port(network: Network) -> u16 {
    wow_p2p::messages::default_port(network)
}

/// `tools::get_default_data_dir()`: `~/.wownero`, or `%ProgramData%\wownero`
/// on Windows.
///
/// The Windows location is `CSIDL_COMMON_APPDATA`, not the user's profile, so
/// a C++ node's `data.mdb` is found without `--data-dir` only if this matches.
/// Deriving it from `HOME` would also make the default depend on the shell --
/// Git Bash sets `HOME`, `cmd.exe` does not.
///
/// The network subdirectory is added by [`wow_storage::env::db_dir`], so this
/// is the base only.
pub fn default_data_dir(_network: Network) -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("wownero")
    }
    #[cfg(not(windows))]
    {
        // The C++ falls back to `/` when `HOME` is unset or empty.
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        home.join(".wownero")
    }
}

/// Parsing stopped, and why.
pub enum ParseOutcome {
    Run(Box<Config>),
    /// `--help` or `--version`: print and exit 0.
    Print(String),
    Error(String),
}

pub const VERSION: &str = concat!(
    "wownerod ",
    env!("CARGO_PKG_VERSION"),
    " (wownero-rs, tracking the C++ tree at 0.11.4.0 \"Kunty Karen\")"
);

pub fn help() -> String {
    format!(
        "{VERSION}

USAGE:
    wownerod [OPTIONS]

A Rust Wownero node. It syncs from and serves the peer-to-peer network,
relays blocks and transactions, keeps a transaction pool and serves RPC. It
can also open and inspect a `data.mdb` written by the C++ `wownerod`
(specs/10 §7).

NETWORK
    --testnet                 use the test network
    --stagenet                use the stage network
    --regtest                 use a fake chain (implies the data dir already
                              ends in `fake`)

DATABASE
    --data-dir <path>         default: ~/.wownero (%ProgramData%\\wownero on Windows)
    --db-readonly             open read-only; safe against a running C++ node
    --db-sync-mode <mode>     safe | fast | fastest        (default: fast)
    --db-salvage              open the previous meta page

RPC (specs/11)
    --rpc-bind-ip <ip>        default: 127.0.0.1
    --rpc-bind-port <port>    default: 34568 (28081 testnet, 38081 stagenet)
    --restricted-rpc          run the server in restricted mode
    --rpc-restricted-bind-ip <ip>                               (default: 127.0.0.1)
    --rpc-restricted-bind-port <port>
                              also serve a restricted RPC here
    --rpc-use-ipv6            listen on IPv6 as well, on the same ports
    --rpc-bind-ipv6-address <ip>                                (default: ::1)
    --rpc-restricted-bind-ipv6-address <ip>                     (default: ::1)
    --rpc-ignore-ipv4         carry on if the IPv4 listener cannot bind
    --public-node             advertise the restricted RPC port to peers
    --rpc-login <user[:password]>
                              require HTTP Digest login; a password left out is
                              generated and printed at start
    --rpc-access-control-origins <origin,...>
                              web origins allowed to call the RPC (needs --rpc-login)
    --disable-rpc-ban         do not block addresses that fail to log in
    --rpc-max-connections <n>                                   (default: 100)
    --rpc-max-connections-per-public-ip <n>                     (default: 3)
    --rpc-max-connections-per-private-ip <n>                    (default: 25)
    --rpc-ssl <enabled|disabled|autodetect>
                              TLS on the RPC ports; autodetect takes plain and
                              TLS clients on the same port  (default: autodetect)
    --rpc-ssl-certificate <file>  --rpc-ssl-private-key <file>
                              the PEM certificate chain and key to serve; without
                              them a self-signed pair is made once and kept as
                              rpc_ssl.crt and rpc_ssl.key in the data directory
    --rpc-ssl-allowed-fingerprints <sha256>
                              accept only clients whose certificate has this
                              fingerprint (repeatable); makes TLS mandatory
    --rpc-ssl-ca-certificates <file>
                              accept clients whose certificate is in this PEM
                              file; makes TLS mandatory
    --rpc-ssl-allow-chained   ... or chains to a certificate in it
    --rpc-ssl-allow-any-cert  check no client certificates
    --confirm-external-bind   required to bind --rpc-bind-ip or
                              --rpc-bind-ipv6-address to a non-loopback
                              address, even restricted or behind a login

ZMQ (specs/09 §3.2)
    --zmq-rpc-bind-ip <ip>    default: 127.0.0.1
    --zmq-rpc-bind-port <port>
                              the ZMQ JSON-RPC  (default: 34569, 28082 testnet,
                              38082 stagenet)
    --zmq-pub <tcp://ip:port> publish blocks, miner data and pool additions
                              there (repeatable; no ipc://)
    --restricted-zmq-rpc      refuse mining, logging and save_bc over ZMQ
    --confirm-zmq-rpc-external-bind
                              required to bind the ZMQ RPC, which has no TLS
                              or login, to a non-loopback address
    --no-zmq                  no ZMQ at all

PEER-TO-PEER (specs/08)
    --p2p-bind-ip <ip>        default: 0.0.0.0
    --p2p-bind-port <port>    default: 34567 (28080 testnet, 38080 stagenet)
    --p2p-use-ipv6            listen for peers on IPv6 too
    --p2p-bind-ipv6-address <ip>                                (default: ::)
    --p2p-bind-port-ipv6 <port>                                 (default: as IPv4)
    --p2p-ignore-ipv4         carry on if the IPv4 listener cannot bind
    --p2p-external-port <port>
                              the port to advertise when it differs, as behind NAT
    --hide-my-port            advertise no port, so peers do not list this node
    --no-igd                  accepted; this build does no UPnP port mapping
    --add-peer <host[:port]>  add to the peer list              (repeatable)
    --add-priority-node <host[:port]>
                              keep connected, besides the rest  (repeatable)
    --add-exclusive-node <host[:port]>
                              connect to these and no others    (repeatable)
    --seed-node <host[:port]> use instead of the built-in seeds (repeatable)
    --out-peers <n>           outgoing connections to keep      (default: 12)
    --in-peers <n>            incoming connections to allow     (default: no limit)
    --max-connections-per-ip <n>                                (default: 1)
    --allow-local-ip          let private and loopback addresses into peer lists
    --ban-list <file>         addresses or subnets to ban, one per line
    --no-sync                 serve and relay, but download no blocks
    --offline                 no peer-to-peer at all
    --keep-alt-blocks         keep alternative blocks across restarts
    --pad-transactions        pad relayed transactions to a multiple of 1 KiB,
                              against traffic volume analysis

LOGGING (specs/09 §8)
    --log-level <0-4 | category:LEVEL,...>                      (default: 0)
    --log-file <path>         also write the log here
    --max-log-file-size <bytes>                                 (default: 104850000)
    --max-log-files <n>       rotated files to keep             (default: 50)

MINING (specs/09 §6)
    --start-mining <address>  mine to this address while the node runs
    --mining-threads <n>                                        (default: 1)
    --spendkey <hex>          the address's secret spend key. Required from
                              hard fork 18, where every block header is signed
                              with it; anyone who can read it can spend what
                              is mined, so keep it in a config file only you
                              can read rather than on the command line
    --vote <yes|no>           the vote mined block headers carry
    --fixed-difficulty <n>    regtest only: every block after genesis needs n

COMMANDS
    --serve                   run the node: sync, serve peers and RPC, stay up.
                              Creates the database if there is none. Ctrl-C or
                              the stop_daemon RPC stops it cleanly
    --status                  report the tip and exit                (default)
    --check-difficulty-checkpoints
                              verify cumulative difficulty at every checkpoint.
                              specs/07 §6: \"a cheap and very effective
                              integration test: if your difficulty
                              implementation is wrong anywhere, this fires at
                              the first checkpoint past the error\"
    --verify-difficulty [from[..to]]
                              recompute every block's difficulty over a range
    --genesis                 print each network's genesis hash and exit
    --sync-from <host:port>   pull blocks from that one peer, then exit. --serve
                              does the same continuously, from many peers

GENERAL
    --config-file <path>      key=value options, as on the command line without
                              the `--`; default <data dir>/wownero.conf. The
                              command line wins where both name an option
    --max-txpool-weight <bytes>                                 (default: 648000000)
    --pidfile <path>          write the process id here while running
    --non-interactive         no console, even at a terminal
    --disable-dns-checkpoints accepted; Wownero has no DNS checkpoints
    --os-version              print the operating system and exit
    --help                    this text
    --version                 version string

RPC METHODS SERVED   (R: not routed with --restricted-rpc)
    POST /get_height  /get_info  /get_checkpoints  /get_transactions
         /send_raw_transaction  /is_key_image_spent  /get_transaction_pool
         /get_transaction_pool_hashes  /get_transaction_pool_stats
         /get_public_nodes
    POST /get_peer_list  /in_peers  /out_peers  /stop_daemon  /save_bc
         /pop_blocks  /get_net_stats  /set_log_level  /set_log_categories
         /start_mining  /stop_mining  /mining_status                      (R)
    POST /json_rpc    get_info, get_version, hard_fork_info, get_fee_estimate,
                      get_block_hash, get_last_block_header,
                      get_block_header_by_height, get_block_header_by_hash,
                      get_block_headers_range, get_block, get_checkpoints,
                      get_block_template, submit_block;
                      (R) sync_info, get_connections, get_bans, set_bans,
                      banned, flush_txpool, relay_tx, generateblocks
    POST /get_blocks.bin  /get_hashes.bin  /get_o_indexes.bin  /get_outs.bin
         /get_output_distribution.bin  /get_transaction_pool_hashes.bin
    ZMQ  get_block_hash, get_block_header_by_hash, get_block_header_by_height,
         get_block_headers_by_height, get_blocks_fast, get_dynamic_fee_estimate,
         get_hashes_fast, get_height, get_info, get_last_block_header,
         get_output_distribution, get_output_histogram, get_output_keys,
         get_rpc_version, get_transaction_pool, get_transactions,
         get_tx_global_output_indices, hard_fork_info, key_images_spent,
         send_raw_tx, send_raw_tx_hex; refused with --restricted-zmq-rpc:
         mining_status, save_bc, set_log_level, start_mining, stop_mining
    ZMQ topics  json-full-chain_main  json-minimal-chain_main
                json-full-miner_data  json-full-txpool_add
                json-minimal-txpool_add

NOT YET IMPLEMENTED
    Proxies, i2p/Tor, rate limits, pruning, bootstrap daemons,
    background mining and extra messages in mined blocks are not built.

    Proof of work is checked for RandomWOW (major version 13 and up) and
    CryptoNight variant 1 (versions 7-8). Variants 2 and 4, which cover
    versions 9 through 12, are missing. On mainnet those heights sit below
    the last checkpoint, where the proof is not recomputed -- as the C++ does
    not recompute it -- but a chain with no checkpoints stops at the version 9
    fork rather than accept a block it cannot verify.

    Options for what is missing are refused rather than accepted and ignored,
    and RPC methods needing it return UNSUPPORTED_RPC (-11) rather than a
    plausible empty answer.
"
    )
}

/// Options `specs/09` §3.2 lists that this build cannot honour.
///
/// Refused explicitly: accepting and ignoring them would make a node look
/// configured when it is not.
const NOT_IMPLEMENTED: &[(&str, &str)] = &[
    ("--proxy", "connecting through a proxy is not implemented"),
    (
        "--tx-proxy",
        "the i2p/Tor transaction proxy is not implemented",
    ),
    (
        "--anonymous-inbound",
        "i2p/Tor inbound connections are not implemented",
    ),
    (
        "--enable-dns-blocklist",
        "the DNS blocklist is not implemented",
    ),
    ("--limit-rate", "rate limiting is not implemented"),
    ("--limit-rate-up", "rate limiting is not implemented"),
    ("--limit-rate-down", "rate limiting is not implemented"),
    (
        "--bootstrap-daemon-address",
        "bootstrap daemons are not implemented",
    ),
    (
        "--bootstrap-daemon-login",
        "bootstrap daemons are not implemented",
    ),
    (
        "--bootstrap-daemon-proxy",
        "bootstrap daemons are not implemented",
    ),
    ("--rpc-payment-address", "RPC payments are not implemented"),
    (
        "--rpc-payment-difficulty",
        "RPC payments are not implemented",
    ),
    ("--rpc-payment-credits", "RPC payments are not implemented"),
    ("--prune-blockchain", "pruning is not implemented"),
    ("--sync-pruned-blocks", "pruning is not implemented"),
    (
        "--fast-block-sync",
        "the checkpointed range is always trusted, as it is by default in the C++",
    ),
    (
        "--prep-blocks-threads",
        "parallel block preparation is not implemented",
    ),
    (
        "--show-time-stats",
        "per-block timing statistics are not implemented",
    ),
    ("--check-updates", "update checks are not implemented"),
    (
        "--enforce-dns-checkpointing",
        "Wownero has no DNS checkpoints to enforce",
    ),
    ("--tos-flag", "setting the IP TOS field is not implemented"),
    (
        "--block-download-max-size",
        "the sync queue is not configurable",
    ),
    (
        "--keep-fakechain",
        "regtest data is never wiped here, so there is nothing to keep",
    ),
    ("--test-drop-download", "the test hooks are not implemented"),
    (
        "--test-drop-download-height",
        "the test hooks are not implemented",
    ),
    ("--max-concurrency", "the thread count is not configurable"),
    (
        "--extra-messages-file",
        "extra messages in mined blocks are not implemented",
    ),
    ("--bg-mining-enable", "background mining is not implemented"),
    (
        "--bg-mining-ignore-battery",
        "background mining is not implemented",
    ),
    (
        "--bg-mining-min-idle-interval",
        "background mining is not implemented",
    ),
    (
        "--bg-mining-idle-threshold",
        "background mining is not implemented",
    ),
    (
        "--bg-mining-miner-target",
        "background mining is not implemented",
    ),
    (
        "--block-sync-size",
        "the sync batch size is adaptive and not configurable",
    ),
    ("--detach", "this build runs in the foreground only"),
];

/// The flags that choose what the process does. At most one may be given.
const COMMANDS: &[&str] = &[
    "--serve",
    "--status",
    "--genesis",
    "--check-difficulty-checkpoints",
    "--verify-difficulty",
    "--sync-from",
];

/// Unwrap a parsing step, or return its error from [`parse`].
macro_rules! take {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return ParseOutcome::Error(e),
        }
    };
}

fn value(it: &mut impl Iterator<Item = String>, flag: &str, what: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} needs {what}"))
}

fn number<T: std::str::FromStr>(v: &str, flag: &str) -> Result<T, String> {
    v.parse()
        .map_err(|_| format!("{flag}: `{v}` is not a number"))
}

fn port(v: &str, flag: &str) -> Result<u16, String> {
    v.parse()
        .map_err(|_| format!("{flag}: `{v}` is not a port number"))
}

/// `--zmq-pub`'s `tcp://ip:port`, with libzmq's `*` for every interface.
/// `ipc://` is refused: nothing here speaks it.
fn zmq_endpoint(v: &str, flag: &str) -> Result<std::net::SocketAddr, String> {
    let shape = || format!("{flag}: `{v}` is not tcp://ip:port");
    let Some(rest) = v.strip_prefix("tcp://") else {
        return Err(if v.starts_with("ipc://") {
            format!("{flag}: `{v}`: ipc:// endpoints are not supported; give tcp://ip:port")
        } else {
            shape()
        });
    };
    let (host, port) = rest.rsplit_once(':').ok_or_else(shape)?;
    let port: u16 = port.parse().map_err(|_| shape())?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let ip: std::net::IpAddr = if host == "*" {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    } else {
        host.parse().map_err(|_| shape())?
    };
    Ok(std::net::SocketAddr::new(ip, port))
}

/// A connection count, where `-1` means the default, as the C++ takes it.
fn peer_count(v: &str, flag: &str, default: usize) -> Result<usize, String> {
    match v.parse::<i64>() {
        Ok(-1) => Ok(default),
        Ok(n) if n >= 0 => Ok(n as usize),
        _ => Err(format!("{flag}: `{v}` is not a count")),
    }
}

/// `host[:port]`, checked for shape here and resolved when the node starts.
fn peer(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    let v = value(it, flag, "host[:port]")?;
    if v.is_empty() || v.chars().any(char::is_whitespace) {
        return Err(format!("{flag}: `{v}` is not host[:port]"));
    }
    // One colon means `host:port`; more is an IPv6 address, bracketed when it
    // carries a port.
    if v.matches(':').count() == 1 {
        let (_, p) = v.split_once(':').unwrap_or_default();
        if p.parse::<u16>().is_err() {
            return Err(format!("{flag}: `{v}` does not end in a port number"));
        }
    }
    Ok(v)
}

/// Options a config file may give as flags, with `1`/`true`/`yes` for on.
const FLAGS: &[&str] = &[
    "testnet",
    "stagenet",
    "regtest",
    "db-readonly",
    "db-salvage",
    "restricted-rpc",
    "confirm-external-bind",
    "restricted-zmq-rpc",
    "confirm-zmq-rpc-external-bind",
    "public-node",
    "disable-rpc-ban",
    "hide-my-port",
    "p2p-use-ipv6",
    "p2p-ignore-ipv4",
    "rpc-use-ipv6",
    "rpc-ignore-ipv4",
    "rpc-ssl-allow-chained",
    "rpc-ssl-allow-any-cert",
    "no-igd",
    "allow-local-ip",
    "no-sync",
    "offline",
    "keep-alt-blocks",
    "pad-transactions",
    "non-interactive",
    "no-zmq",
    "disable-dns-checkpoints",
];

/// Merge the config file into the command line (`specs/09` §3).
///
/// The file is `--config-file`, or [`CONFIG_FILENAME`] in the network's data
/// directory. Each line is `key=value`, with a long option's name and no
/// leading `--`; `#` starts a comment. A flag is on for `1`, `true` or `yes`.
///
/// **The command line wins.** An option named on both keeps only the command
/// line's value -- for a repeatable one as well, so an `--add-peer` typed now
/// is not quietly joined by the file's.
pub fn with_config_file(cli: Vec<String>) -> Result<Vec<String>, String> {
    if cli
        .iter()
        .any(|a| matches!(a.as_str(), "--help" | "-h" | "--version" | "-V"))
    {
        return Ok(cli);
    }

    let mut explicit: Option<PathBuf> = None;
    let mut rest = Vec::with_capacity(cli.len());
    let mut it = cli.into_iter();
    while let Some(a) = it.next() {
        if a == "--config-file" {
            explicit = Some(PathBuf::from(
                it.next().ok_or("--config-file needs a path")?,
            ));
        } else {
            rest.push(a);
        }
    }

    let path = match &explicit {
        Some(p) => p.clone(),
        None => {
            let has = |flag: &str| rest.iter().any(|a| a == flag);
            let (network, regtest) = if has("--testnet") {
                (Network::Testnet, false)
            } else if has("--stagenet") {
                (Network::Stagenet, false)
            } else if has("--regtest") {
                (Network::Fakechain, true)
            } else {
                (Network::Mainnet, false)
            };
            let data_dir = rest
                .windows(2)
                .find(|w| w[0] == "--data-dir")
                .map(|w| PathBuf::from(&w[1]))
                .unwrap_or_else(|| default_data_dir(network));
            wow_storage::env::db_dir(&data_dir, network, regtest)
                .parent()
                .map(|d| d.join(CONFIG_FILENAME))
                .unwrap_or_else(|| PathBuf::from(CONFIG_FILENAME))
        }
    };

    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if explicit.is_none() && e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(rest)
        }
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };

    let given: HashSet<&str> = rest
        .iter()
        .filter(|a| a.starts_with("--"))
        .map(String::as_str)
        .collect();
    let mut from_file = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let at = || format!("{}:{}", path.display(), n + 1);
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (line, ""),
        };
        if key.is_empty() || key.starts_with('-') || key == "config-file" {
            return Err(format!("{}: `{line}` is not key=value", at()));
        }
        let flag = format!("--{key}");
        if given.contains(flag.as_str()) {
            continue;
        }
        if FLAGS.contains(&key) {
            match value.to_ascii_lowercase().as_str() {
                "" | "1" | "true" | "yes" => from_file.push(flag),
                "0" | "false" | "no" => {}
                _ => return Err(format!("{}: {key} is a flag; give 1 or 0", at())),
            }
        } else if value.is_empty() {
            return Err(format!("{}: {key} needs a value", at()));
        } else {
            from_file.push(flag);
            from_file.push(value.to_string());
        }
    }
    from_file.extend(rest);
    Ok(from_file)
}

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> ParseOutcome {
    let mut cfg = Config::default();
    let mut network_set = false;
    let mut rpc_port_set = false;
    let mut p2p_port_set = false;
    let mut p2p_port_v6_set = false;
    let mut zmq_port_set = false;
    let mut data_dir: Option<PathBuf> = None;
    // The command flag already given, so a second one is refused rather than
    // silently replacing the first: `--serve --sync-from X` must not quietly
    // become a sync that exits.
    let mut command_flag: Option<String> = None;

    let mut it = args.into_iter().peekable();
    while let Some(arg) = it.next() {
        if COMMANDS.contains(&arg.as_str()) {
            match &command_flag {
                Some(prev) if *prev != arg => {
                    return ParseOutcome::Error(format!(
                        "{prev} and {arg} are separate commands; give one"
                    ))
                }
                _ => command_flag = Some(arg.clone()),
            }
        }
        match arg.as_str() {
            "--help" | "-h" => return ParseOutcome::Print(help()),
            "--version" | "-V" => return ParseOutcome::Print(VERSION.to_string()),

            "--testnet" | "--stagenet" | "--regtest" => {
                if network_set {
                    return ParseOutcome::Error(
                        "--testnet, --stagenet and --regtest are mutually exclusive".into(),
                    );
                }
                network_set = true;
                cfg.network = match arg.as_str() {
                    "--testnet" => Network::Testnet,
                    "--stagenet" => Network::Stagenet,
                    _ => {
                        cfg.regtest = true;
                        Network::Fakechain
                    }
                };
            }

            "--data-dir" => match it.next() {
                Some(v) => data_dir = Some(PathBuf::from(v)),
                None => return ParseOutcome::Error("--data-dir needs a path".into()),
            },
            "--db-readonly" => cfg.read_only = true,
            "--restricted-rpc" => cfg.restricted_rpc = true,
            "--confirm-external-bind" => cfg.confirm_external_bind = true,
            "--zmq-rpc-bind-ip" => cfg.zmq_rpc_bind_ip = take!(value(&mut it, &arg, "an address")),
            "--zmq-rpc-bind-port" => {
                cfg.zmq_rpc_bind_port = take!(port(&take!(value(&mut it, &arg, "a port")), &arg));
                zmq_port_set = true;
            }
            "--zmq-pub" => {
                let v = take!(value(&mut it, &arg, "tcp://ip:port"));
                cfg.zmq_pub.push(take!(zmq_endpoint(&v, &arg)));
            }
            "--restricted-zmq-rpc" => cfg.restricted_zmq_rpc = true,
            "--confirm-zmq-rpc-external-bind" => cfg.confirm_zmq_rpc_external_bind = true,
            "--no-zmq" => cfg.no_zmq = true,
            "--rpc-bind-ip" => match it.next() {
                Some(v) => cfg.rpc_bind_ip = v,
                None => return ParseOutcome::Error("--rpc-bind-ip needs an address".into()),
            },
            "--rpc-bind-port" => match it.next() {
                Some(v) => match v.parse::<u16>() {
                    Ok(p) => {
                        cfg.rpc_bind_port = p;
                        rpc_port_set = true;
                    }
                    Err(_) => {
                        return ParseOutcome::Error(format!(
                            "--rpc-bind-port: `{v}` is not a port number"
                        ))
                    }
                },
                None => return ParseOutcome::Error("--rpc-bind-port needs a port".into()),
            },
            "--db-salvage" => cfg.salvage = true,

            "--p2p-bind-ip" => cfg.p2p_bind_ip = take!(value(&mut it, &arg, "an address")),
            "--p2p-bind-port" => {
                cfg.p2p_bind_port = take!(port(&take!(value(&mut it, &arg, "a port")), &arg));
                p2p_port_set = true;
            }
            "--p2p-bind-ipv6-address" => {
                cfg.p2p_bind_ipv6_address = take!(value(&mut it, &arg, "an IPv6 address"));
            }
            "--p2p-bind-port-ipv6" => {
                cfg.p2p_bind_port_ipv6 = take!(port(&take!(value(&mut it, &arg, "a port")), &arg));
                p2p_port_v6_set = true;
            }
            "--p2p-use-ipv6" => cfg.p2p_use_ipv6 = true,
            "--p2p-ignore-ipv4" => cfg.p2p_ignore_ipv4 = true,
            "--p2p-external-port" => {
                cfg.p2p_external_port =
                    Some(take!(port(&take!(value(&mut it, &arg, "a port")), &arg)));
            }
            "--hide-my-port" => cfg.hide_my_port = true,
            // There is no UPnP here to turn off.
            "--no-igd" => {}
            "--igd" => {
                let v = take!(value(&mut it, &arg, "disabled, enabled or delayed"));
                if v != "disabled" {
                    return ParseOutcome::Error(format!(
                        "--igd {v}: UPnP port mapping is not implemented; forward the \
                         port by hand, or pass --no-igd"
                    ));
                }
            }
            "--add-peer" => cfg.add_peers.push(take!(peer(&mut it, &arg))),
            "--add-priority-node" => cfg.priority_nodes.push(take!(peer(&mut it, &arg))),
            "--add-exclusive-node" => cfg.exclusive_nodes.push(take!(peer(&mut it, &arg))),
            "--seed-node" => cfg.seed_nodes.push(take!(peer(&mut it, &arg))),
            "--out-peers" => {
                cfg.out_peers = take!(peer_count(
                    &take!(value(&mut it, &arg, "a count")),
                    &arg,
                    12
                ));
            }
            "--in-peers" => {
                cfg.in_peers = take!(peer_count(
                    &take!(value(&mut it, &arg, "a count")),
                    &arg,
                    usize::MAX
                ));
            }
            "--max-connections-per-ip" => {
                let n: usize = take!(number(&take!(value(&mut it, &arg, "a count")), &arg));
                if n == 0 {
                    return ParseOutcome::Error(
                        "--max-connections-per-ip must be at least 1".into(),
                    );
                }
                cfg.max_connections_per_ip = n;
            }
            "--allow-local-ip" => cfg.allow_local_ip = true,
            "--no-sync" => cfg.no_sync = true,
            "--offline" => cfg.offline = true,
            "--ban-list" => {
                cfg.ban_list = Some(PathBuf::from(take!(value(&mut it, &arg, "a file"))));
            }
            "--keep-alt-blocks" => cfg.keep_alt_blocks = true,
            "--pad-transactions" => cfg.pad_transactions = true,

            "--log-level" => {
                cfg.log_level = Some(take!(value(&mut it, &arg, "0-4 or category:LEVEL,...")));
            }
            "--log-file" => {
                cfg.log_file = Some(PathBuf::from(take!(value(&mut it, &arg, "a path"))));
            }
            "--max-log-file-size" => {
                cfg.max_log_file_size = take!(number(
                    &take!(value(&mut it, &arg, "a size in bytes")),
                    &arg
                ));
            }
            "--max-log-files" => {
                cfg.max_log_files = take!(number(&take!(value(&mut it, &arg, "a count")), &arg));
            }
            "--rpc-restricted-bind-ip" => {
                cfg.rpc_restricted_bind_ip = take!(value(&mut it, &arg, "an address"));
            }
            "--rpc-restricted-bind-port" => {
                cfg.rpc_restricted_bind_port =
                    Some(take!(port(&take!(value(&mut it, &arg, "a port")), &arg)));
            }
            "--rpc-bind-ipv6-address" => {
                cfg.rpc_bind_ipv6_address = take!(value(&mut it, &arg, "an IPv6 address"));
            }
            "--rpc-restricted-bind-ipv6-address" => {
                cfg.rpc_restricted_bind_ipv6_address =
                    take!(value(&mut it, &arg, "an IPv6 address"));
            }
            "--rpc-use-ipv6" => cfg.rpc_use_ipv6 = true,
            "--rpc-ignore-ipv4" => cfg.rpc_ignore_ipv4 = true,
            "--public-node" => cfg.public_node = true,
            "--rpc-login" => {
                let v = take!(value(&mut it, &arg, "user[:password]"));
                let (user, pass) = match v.split_once(':') {
                    Some((u, p)) => (u.to_string(), Some(p.to_string())),
                    None => (v, None),
                };
                if user.is_empty() {
                    return ParseOutcome::Error("--rpc-login needs a user name".into());
                }
                cfg.rpc_login = Some((user, pass));
            }
            "--rpc-access-control-origins" => {
                let v = take!(value(&mut it, &arg, "a comma-separated list of origins"));
                cfg.rpc_access_control_origins.extend(
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                );
            }
            "--disable-rpc-ban" => cfg.disable_rpc_ban = true,
            "--rpc-max-connections" => {
                cfg.rpc_max_connections =
                    take!(number(&take!(value(&mut it, &arg, "a count")), &arg));
            }
            "--rpc-max-connections-per-public-ip" => {
                cfg.rpc_max_connections_per_public_ip =
                    take!(number(&take!(value(&mut it, &arg, "a count")), &arg));
            }
            "--rpc-max-connections-per-private-ip" => {
                cfg.rpc_max_connections_per_private_ip =
                    take!(number(&take!(value(&mut it, &arg, "a count")), &arg));
            }
            "--rpc-ssl" => {
                let v = take!(value(&mut it, &arg, "enabled, disabled or autodetect"));
                cfg.rpc_ssl = match v.as_str() {
                    "enabled" => RpcSsl::Enabled,
                    "disabled" => RpcSsl::Disabled,
                    "autodetect" => RpcSsl::Autodetect,
                    other => {
                        return ParseOutcome::Error(format!(
                            "--rpc-ssl: expected enabled, disabled or autodetect, got `{other}`"
                        ))
                    }
                };
            }
            "--rpc-ssl-private-key" => {
                cfg.rpc_ssl_private_key =
                    Some(PathBuf::from(take!(value(&mut it, &arg, "a PEM file"))));
            }
            "--rpc-ssl-certificate" => {
                cfg.rpc_ssl_certificate =
                    Some(PathBuf::from(take!(value(&mut it, &arg, "a PEM file"))));
            }
            "--rpc-ssl-ca-certificates" => {
                cfg.rpc_ssl_ca_certificates =
                    Some(PathBuf::from(take!(value(&mut it, &arg, "a PEM file"))));
            }
            "--rpc-ssl-allowed-fingerprints" => {
                let v = take!(value(&mut it, &arg, "a SHA-256 fingerprint"));
                let fp = take!(
                    crate::rpc::tls::parse_fingerprint(&v).map_err(|e| format!("{arg}: {e}"))
                );
                cfg.rpc_ssl_allowed_fingerprints.push(fp);
            }
            "--rpc-ssl-allow-chained" => cfg.rpc_ssl_allow_chained = true,
            "--rpc-ssl-allow-any-cert" => cfg.rpc_ssl_allow_any_cert = true,
            "--max-txpool-weight" => {
                cfg.max_txpool_weight = take!(number(
                    &take!(value(&mut it, &arg, "a weight in bytes")),
                    &arg
                ));
            }
            "--pidfile" => {
                cfg.pidfile = Some(PathBuf::from(take!(value(&mut it, &arg, "a path"))));
            }
            "--non-interactive" => cfg.non_interactive = true,
            "--start-mining" => {
                cfg.start_mining = Some(take!(value(&mut it, &arg, "an address")));
            }
            "--mining-threads" => {
                let n: usize = take!(number(&take!(value(&mut it, &arg, "a thread count")), &arg));
                if n == 0 {
                    return ParseOutcome::Error("--mining-threads must be at least 1".into());
                }
                cfg.mining_threads = n;
            }
            "--spendkey" => {
                let hex = take!(value(&mut it, &arg, "a secret spend key in hex"));
                cfg.spendkey = Some(take!(crate::miner::SpendKey::parse(&hex)));
            }
            "--vote" => {
                let v = take!(value(&mut it, &arg, "yes or no"));
                cfg.vote = take!(crate::miner::parse_vote(&v));
            }
            "--fixed-difficulty" => {
                let d: u128 = take!(number(&take!(value(&mut it, &arg, "a difficulty")), &arg));
                if d == 0 {
                    return ParseOutcome::Error("--fixed-difficulty must be at least 1".into());
                }
                cfg.fixed_difficulty = Some(d);
            }
            // Wownero has no DNS checkpoints, so there are none to turn off.
            "--disable-dns-checkpoints" => {}
            // Already merged by `with_config_file`; accepted here so a direct
            // caller of `parse` does not trip over it.
            "--config-file" => {
                take!(value(&mut it, &arg, "a path"));
            }
            "--os-version" => {
                return ParseOutcome::Print(format!(
                    "OS: {} {}",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                ))
            }
            "--db-sync-mode" => match it.next().as_deref() {
                Some(v) => {
                    // The C++ form is `<mode>[:sync|async][:<n>[blocks|bytes]]`;
                    // only the mode affects the LMDB flags (`specs/10` §2.1).
                    match v.split(':').next().unwrap_or("") {
                        "safe" => cfg.sync_mode = SyncMode::Safe,
                        "fast" => cfg.sync_mode = SyncMode::Fast,
                        "fastest" => cfg.sync_mode = SyncMode::Fastest,
                        other => {
                            return ParseOutcome::Error(format!(
                                "--db-sync-mode: expected safe, fast or fastest, got `{other}`"
                            ))
                        }
                    }
                }
                None => return ParseOutcome::Error("--db-sync-mode needs a value".into()),
            },

            "--serve" => cfg.command = Command::Serve,
            "--sync-from" => {
                let Some(address) = it.next() else {
                    return ParseOutcome::Error("--sync-from needs a host:port".into());
                };
                cfg.command = Command::SyncFrom {
                    address,
                    max_batches: 1_000,
                };
            }
            "--status" => cfg.command = Command::Status,
            "--genesis" => cfg.command = Command::Genesis,
            "--check-difficulty-checkpoints" => cfg.command = Command::CheckDifficultyCheckpoints,
            "--verify-difficulty" => {
                let range = it.peek().filter(|s| !s.starts_with("--")).cloned();
                if range.is_some() {
                    it.next();
                }
                match parse_range(range.as_deref()) {
                    Ok((from, to)) => cfg.command = Command::VerifyDifficulty { from, to },
                    Err(e) => return ParseOutcome::Error(e),
                }
            }

            other => {
                if let Some((_, why)) = NOT_IMPLEMENTED.iter().find(|(o, _)| *o == other) {
                    return ParseOutcome::Error(format!("{other}: {why}"));
                }
                return ParseOutcome::Error(format!("unrecognised option `{other}` (try --help)"));
            }
        }
    }

    cfg.data_dir = data_dir.unwrap_or_else(|| default_data_dir(cfg.network));
    // The default port follows the network, so it is resolved after parsing
    // rather than at construction -- `--testnet` may come after `--serve`.
    if !rpc_port_set {
        cfg.rpc_bind_port = default_rpc_port(cfg.network);
    }
    if !p2p_port_set {
        cfg.p2p_bind_port = default_p2p_port(cfg.network);
    }
    if !p2p_port_v6_set {
        cfg.p2p_bind_port_ipv6 = default_p2p_port(cfg.network);
    }
    if !zmq_port_set {
        cfg.zmq_rpc_bind_port = default_zmq_rpc_port(cfg.network);
    }

    // The C++ parses these even when IPv6 is off, so a typo is found now
    // rather than the day IPv6 is turned on.
    for (flag, addr) in [
        ("--p2p-bind-ipv6-address", &cfg.p2p_bind_ipv6_address),
        ("--rpc-bind-ipv6-address", &cfg.rpc_bind_ipv6_address),
        (
            "--rpc-restricted-bind-ipv6-address",
            &cfg.rpc_restricted_bind_ipv6_address,
        ),
    ] {
        let bare = addr
            .strip_prefix('[')
            .and_then(|a| a.strip_suffix(']'))
            .unwrap_or(addr);
        if bare.parse::<std::net::Ipv6Addr>().is_err() {
            return ParseOutcome::Error(format!("{flag}: `{addr}` is not an IPv6 address"));
        }
    }

    // `verify_zmq_rpc_bind`, in the C++'s words: the ZMQ RPC has neither TLS
    // nor a login.
    if !cfg.no_zmq {
        let bare = cfg
            .zmq_rpc_bind_ip
            .strip_prefix('[')
            .and_then(|a| a.strip_suffix(']'))
            .unwrap_or(&cfg.zmq_rpc_bind_ip);
        match bare.parse::<std::net::IpAddr>() {
            Err(_) => {
                return ParseOutcome::Error("Invalid IP address given for --zmq-rpc-bind-ip".into())
            }
            Ok(ip) if !ip.is_loopback() && !cfg.confirm_zmq_rpc_external_bind => {
                return ParseOutcome::Error(
                    "--zmq-rpc-bind-ip permits inbound unencrypted external connections. \
                     Consider SSH tunnel or SSL proxy instead. Override with \
                     --confirm-zmq-rpc-external-bind"
                        .into(),
                )
            }
            Ok(_) => {}
        }
    }

    // Options that only make sense together.
    if cfg.public_node && !cfg.restricted_rpc && cfg.rpc_restricted_bind_port.is_none() {
        return ParseOutcome::Error(
            "--public-node needs --restricted-rpc or --rpc-restricted-bind-port: it \
             advertises the RPC port to anyone, which must not be the unrestricted one"
                .into(),
        );
    }
    if !cfg.rpc_access_control_origins.is_empty() && cfg.rpc_login.is_none() {
        return ParseOutcome::Error(
            "--rpc-access-control-origins needs --rpc-login, as in the C++: a web page \
             allowed in must still have to log in"
                .into(),
        );
    }
    if cfg.rpc_ssl_private_key.is_some() != cfg.rpc_ssl_certificate.is_some() {
        return ParseOutcome::Error(
            "--rpc-ssl-private-key and --rpc-ssl-certificate go together: give both or neither"
                .into(),
        );
    }
    if cfg.fixed_difficulty.is_some() && !cfg.regtest {
        return ParseOutcome::Error(
            "--fixed-difficulty needs --regtest: on a real network it would accept blocks \
             every other node rejects"
                .into(),
        );
    }
    if cfg.start_mining.is_some() && cfg.read_only {
        return ParseOutcome::Error(
            "--start-mining needs a writable database, since a mined block has to be \
             added to it; drop --db-readonly"
                .into(),
        );
    }
    if cfg.start_mining.is_some() && cfg.command != Command::Serve {
        return ParseOutcome::Error("--start-mining mines on a running node; add --serve".into());
    }
    if cfg.rpc_restricted_bind_port == Some(cfg.rpc_bind_port) {
        return ParseOutcome::Error(format!(
            "--rpc-restricted-bind-port {} is the same port as the main RPC listener",
            cfg.rpc_bind_port
        ));
    }
    ParseOutcome::Run(Box::new(cfg))
}

/// `from`, `from..`, `from..to` or nothing.
fn parse_range(s: Option<&str>) -> Result<(u64, Option<u64>), String> {
    let Some(s) = s else {
        return Ok((0, None));
    };
    let bad = |what: &str| format!("--verify-difficulty: {what} in `{s}`");
    match s.split_once("..") {
        None => s
            .parse::<u64>()
            .map(|f| (f, None))
            .map_err(|_| bad("not a height")),
        Some((f, "")) => f
            .parse::<u64>()
            .map(|f| (f, None))
            .map_err(|_| bad("not a height")),
        Some((f, t)) => {
            let from = f.parse::<u64>().map_err(|_| bad("bad start"))?;
            let to = t.parse::<u64>().map_err(|_| bad("bad end"))?;
            if to < from {
                return Err(bad("end before start"));
            }
            Ok((from, Some(to)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(a: &[&str]) -> ParseOutcome {
        parse(a.iter().map(|s| s.to_string()))
    }

    fn run(a: &[&str]) -> Config {
        match parse_args(a) {
            ParseOutcome::Run(c) => *c,
            ParseOutcome::Print(p) => panic!("expected Run, got Print: {p}"),
            ParseOutcome::Error(e) => panic!("expected Run, got Error: {e}"),
        }
    }

    fn err(a: &[&str]) -> String {
        match parse_args(a) {
            ParseOutcome::Error(e) => e,
            ParseOutcome::Run(_) => panic!("expected an error, got Run"),
            ParseOutcome::Print(p) => panic!("expected an error, got Print: {p}"),
        }
    }

    #[test]
    fn the_defaults_are_mainnet_read_write_and_status() {
        let c = run(&[]);
        assert_eq!(c.network, Network::Mainnet);
        assert!(!c.read_only);
        assert!(!c.regtest);
        assert_eq!(c.command, Command::Status);
        // `specs/09` §3.2 gives `fast` as the default sync mode.
        assert_eq!(c.sync_mode, SyncMode::Fast);
        #[cfg(not(windows))]
        assert!(c.data_dir.ends_with(".wownero"));
        // `CSIDL_COMMON_APPDATA`, as the C++ uses, not the user's profile.
        #[cfg(windows)]
        assert!(c.data_dir.ends_with("wownero") && !c.data_dir.ends_with(".wownero"));
    }

    /// Two commands are refused, whichever order they come in, rather than the
    /// last one silently winning.
    #[test]
    fn two_commands_are_refused() {
        let e = err(&["--serve", "--sync-from", "1.2.3.4:34567"]);
        assert!(e.contains("--serve") && e.contains("--sync-from"), "{e}");
        assert!(e.contains("separate commands"), "{e}");

        let e = err(&["--status", "--serve"]);
        assert!(e.contains("--status") && e.contains("--serve"), "{e}");

        // The same command twice is not a conflict.
        assert_eq!(run(&["--serve", "--serve"]).command, Command::Serve);
        // Nor is a command alongside ordinary options.
        assert_eq!(
            run(&["--serve", "--db-readonly", "--testnet"]).command,
            Command::Serve
        );
    }

    /// `specs/09` §3.1: the three network flags are mutually exclusive.
    #[test]
    fn the_network_flags_are_mutually_exclusive() {
        assert_eq!(run(&["--testnet"]).network, Network::Testnet);
        assert_eq!(run(&["--stagenet"]).network, Network::Stagenet);
        assert_eq!(run(&["--regtest"]).network, Network::Fakechain);
        assert!(run(&["--regtest"]).regtest, "regtest sets the flag too");

        for pair in [
            ["--testnet", "--stagenet"],
            ["--testnet", "--regtest"],
            ["--stagenet", "--regtest"],
        ] {
            assert!(
                err(&pair).contains("mutually exclusive"),
                "{pair:?} should conflict"
            );
        }
    }

    /// `specs/10` §2.1: only the mode part of `--db-sync-mode` affects the LMDB
    /// flags, so the C++'s longer form is accepted and its tail ignored.
    #[test]
    fn the_sync_mode_accepts_the_cpp_form() {
        assert_eq!(run(&["--db-sync-mode", "safe"]).sync_mode, SyncMode::Safe);
        assert_eq!(run(&["--db-sync-mode", "fast"]).sync_mode, SyncMode::Fast);
        assert_eq!(
            run(&["--db-sync-mode", "fastest"]).sync_mode,
            SyncMode::Fastest
        );
        assert_eq!(
            run(&["--db-sync-mode", "fast:async:250000000bytes"]).sync_mode,
            SyncMode::Fast,
            "the default from specs/09 §3.2"
        );

        assert!(err(&["--db-sync-mode", "quick"]).contains("safe, fast or fastest"));
        assert!(err(&["--db-sync-mode"]).contains("needs a value"));
    }

    /// An option this build cannot honour is **refused**, not accepted and
    /// dropped. A command line that looks like it worked should have.
    #[test]
    fn unimplemented_options_are_refused_with_a_reason() {
        for (opt, _) in NOT_IMPLEMENTED {
            let e = err(&[opt]);
            assert!(e.starts_with(opt), "{opt}: {e}");
            // Every refusal explains itself; the exact wording varies.
            assert!(e.len() > opt.len() + 2, "{opt}: no reason given");
            assert!(e.contains(": "), "{opt}: {e}");
        }
        assert!(err(&["--proxy"]).contains("proxy"));
        assert!(err(&["--bg-mining-enable"]).contains("background mining"));

        // The RPC options are real now, so they must *not* be refused.
        assert_eq!(run(&["--rpc-bind-port", "1234"]).rpc_bind_port, 1234);
        assert!(run(&["--restricted-rpc"]).restricted_rpc);
        // Nor is transaction padding, which is off unless asked for.
        assert!(run(&["--pad-transactions"]).pad_transactions);
        assert!(!run(&[]).pad_transactions);
    }

    #[test]
    fn the_zmq_options_parse() {
        let c = run(&[]);
        assert!(!c.no_zmq, "on by default, as in the C++");
        assert_eq!(c.zmq_rpc_bind_ip, "127.0.0.1");
        assert_eq!(c.zmq_rpc_bind_port, 34_569);
        assert_eq!(run(&["--testnet"]).zmq_rpc_bind_port, 28_082);
        assert_eq!(run(&["--stagenet"]).zmq_rpc_bind_port, 38_082);

        let c = run(&[
            "--zmq-rpc-bind-port",
            "4000",
            "--zmq-pub",
            "tcp://127.0.0.1:4001",
            "--zmq-pub",
            "tcp://*:4002",
            "--zmq-pub",
            "tcp://[::1]:4003",
            "--restricted-zmq-rpc",
        ]);
        assert_eq!(c.zmq_rpc_bind_port, 4000);
        assert_eq!(
            c.zmq_pub,
            vec![
                "127.0.0.1:4001".parse().unwrap(),
                "0.0.0.0:4002".parse().unwrap(),
                "[::1]:4003".parse().unwrap()
            ]
        );
        assert!(c.restricted_zmq_rpc && !c.no_zmq);
        assert!(run(&["--no-zmq"]).no_zmq);

        assert!(err(&["--zmq-pub", "ipc:///tmp/w"]).contains("ipc://"));
        assert!(err(&["--zmq-pub", "tcp://x"]).contains("tcp://ip:port"));
        assert!(err(&["--zmq-rpc-bind-ip", "0.0.0.0"]).contains("--confirm-zmq-rpc-external-bind"));
        assert!(err(&["--zmq-rpc-bind-ip", "localhost"]).contains("Invalid IP address"));
        assert!(
            run(&[
                "--zmq-rpc-bind-ip",
                "0.0.0.0",
                "--confirm-zmq-rpc-external-bind"
            ])
            .confirm_zmq_rpc_external_bind
        );
        assert!(
            run(&["--zmq-rpc-bind-ip", "0.0.0.0", "--no-zmq"]).no_zmq,
            "nothing to check with ZMQ off"
        );
        assert_eq!(
            run(&["--zmq-rpc-bind-ip", "[::1]"]).zmq_rpc_bind_ip,
            "[::1]"
        );
    }

    #[test]
    fn an_unknown_option_is_an_error() {
        let e = err(&["--frobnicate"]);
        assert!(e.contains("unrecognised"));
        assert!(e.contains("--help"));
    }

    #[test]
    fn help_and_version_print_rather_than_run() {
        for flag in ["--help", "-h"] {
            match parse_args(&[flag]) {
                ParseOutcome::Print(p) => {
                    assert!(p.contains("USAGE"));
                    assert!(p.contains("--check-difficulty-checkpoints"));
                    assert!(p.contains("NOT YET IMPLEMENTED"));
                }
                _ => panic!("{flag} should print"),
            }
        }
        for flag in ["--version", "-V"] {
            match parse_args(&[flag]) {
                ParseOutcome::Print(p) => assert!(p.starts_with("wownerod ")),
                _ => panic!("{flag} should print"),
            }
        }
    }

    #[test]
    fn the_commands_parse() {
        assert_eq!(run(&["--status"]).command, Command::Status);
        assert_eq!(run(&["--genesis"]).command, Command::Genesis);
        assert_eq!(
            run(&["--check-difficulty-checkpoints"]).command,
            Command::CheckDifficultyCheckpoints
        );
    }

    /// `--verify-difficulty` takes an optional `from`, `from..` or `from..to`.
    #[test]
    fn the_verify_range_parses_every_form() {
        assert_eq!(
            run(&["--verify-difficulty"]).command,
            Command::VerifyDifficulty { from: 0, to: None }
        );
        assert_eq!(
            run(&["--verify-difficulty", "100"]).command,
            Command::VerifyDifficulty {
                from: 100,
                to: None
            }
        );
        assert_eq!(
            run(&["--verify-difficulty", "100.."]).command,
            Command::VerifyDifficulty {
                from: 100,
                to: None
            }
        );
        assert_eq!(
            run(&["--verify-difficulty", "100..200"]).command,
            Command::VerifyDifficulty {
                from: 100,
                to: Some(200)
            }
        );

        // A following option is not swallowed as a range.
        let c = run(&["--verify-difficulty", "--db-readonly"]);
        assert_eq!(c.command, Command::VerifyDifficulty { from: 0, to: None });
        assert!(c.read_only);

        assert!(err(&["--verify-difficulty", "200..100"]).contains("end before start"));
        assert!(err(&["--verify-difficulty", "abc"]).contains("not a height"));
    }

    #[test]
    fn the_data_dir_is_taken_verbatim() {
        let c = run(&["--data-dir", "/srv/wow"]);
        assert_eq!(c.data_dir, PathBuf::from("/srv/wow"));
        assert!(err(&["--data-dir"]).contains("needs a path"));
    }

    /// `RPC_DEFAULT_PORT` follows the network, and is resolved after parsing so
    /// the flag order does not matter.
    #[test]
    fn the_rpc_port_defaults_to_the_networks() {
        assert_eq!(run(&[]).rpc_bind_port, 34_568);
        assert_eq!(run(&["--testnet"]).rpc_bind_port, 28_081);
        assert_eq!(run(&["--stagenet"]).rpc_bind_port, 38_081);
        assert_eq!(
            run(&["--regtest"]).rpc_bind_port,
            34_568,
            "fakechain shares mainnet's"
        );

        // Order does not matter.
        assert_eq!(run(&["--serve", "--testnet"]).rpc_bind_port, 28_081);
        assert_eq!(run(&["--testnet", "--serve"]).rpc_bind_port, 28_081);

        // An explicit port wins over the network default, in either order.
        assert_eq!(
            run(&["--rpc-bind-port", "9999", "--testnet"]).rpc_bind_port,
            9999
        );
        assert_eq!(
            run(&["--testnet", "--rpc-bind-port", "9999"]).rpc_bind_port,
            9999
        );
    }

    #[test]
    fn the_rpc_options_parse() {
        assert_eq!(run(&[]).rpc_bind_ip, "127.0.0.1", "loopback by default");
        assert_eq!(run(&["--rpc-bind-ip", "0.0.0.0"]).rpc_bind_ip, "0.0.0.0");
        assert!(run(&["--restricted-rpc"]).restricted_rpc);
        assert!(run(&["--confirm-external-bind"]).confirm_external_bind);
        assert!(!run(&[]).confirm_external_bind, "off unless asked for");

        assert!(err(&["--rpc-bind-port", "notaport"]).contains("not a port"));
        assert!(err(&["--rpc-bind-port", "70000"]).contains("not a port"));
        assert!(err(&["--rpc-bind-port"]).contains("needs a port"));
        assert!(err(&["--rpc-bind-ip"]).contains("needs an address"));
    }

    #[test]
    fn serve_is_a_command() {
        assert_eq!(run(&["--serve"]).command, Command::Serve);
    }

    fn run_owned(args: Vec<String>) -> Config {
        match parse(args) {
            ParseOutcome::Run(c) => *c,
            ParseOutcome::Print(p) => panic!("expected Run, got Print: {p}"),
            ParseOutcome::Error(e) => panic!("expected Run, got Error: {e}"),
        }
    }

    fn strings(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// `specs/09` §3: the file fills in what the command line leaves out, and
    /// the command line wins where both speak -- for a list option too.
    #[test]
    fn the_config_file_fills_in_what_the_command_line_leaves_out() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("wownerod-conf-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("my.conf");
        std::fs::write(
            &conf,
            "# a comment\n\nrpc-bind-port = 4444\nadd-peer=1.2.3.4:34567\nno-sync=1\n\
             offline=0\nout-peers=3\n",
        )
        .unwrap();

        let c = run_owned(
            with_config_file(strings(&[
                "--config-file",
                conf.to_str().unwrap(),
                "--add-peer",
                "5.6.7.8",
                "--out-peers",
                "9",
            ]))
            .unwrap(),
        );
        assert_eq!(c.rpc_bind_port, 4444, "from the file");
        assert!(c.no_sync, "a flag set to 1");
        assert!(!c.offline, "a flag set to 0");
        assert_eq!(c.out_peers, 9, "the command line wins");
        assert_eq!(
            c.add_peers,
            vec!["5.6.7.8"],
            "the command line's list replaces the file's"
        );

        // Without --config-file, `wownero.conf` in the data directory is read.
        std::fs::write(dir.join(CONFIG_FILENAME), "rpc-bind-port=5555\n").unwrap();
        let c =
            run_owned(with_config_file(strings(&["--data-dir", dir.to_str().unwrap()])).unwrap());
        assert_eq!(c.rpc_bind_port, 5555);

        // A missing default file is no config; a missing named one is an error.
        let elsewhere = dir.join("empty");
        std::fs::create_dir_all(&elsewhere).unwrap();
        assert!(with_config_file(strings(&["--data-dir", elsewhere.to_str().unwrap()])).is_ok());
        let missing = dir.join("nope.conf");
        assert!(with_config_file(strings(&["--config-file", missing.to_str().unwrap()])).is_err());

        // A bad line is named.
        std::fs::write(&conf, "no-sync=maybe\n").unwrap();
        let e = with_config_file(strings(&["--config-file", conf.to_str().unwrap()])).unwrap_err();
        assert!(e.contains(":1:") && e.contains("flag"), "{e}");
        std::fs::write(&conf, "rpc-bind-port\n").unwrap();
        let e = with_config_file(strings(&["--config-file", conf.to_str().unwrap()])).unwrap_err();
        assert!(e.contains("needs a value"), "{e}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_rpc_access_options_parse_and_check_each_other() {
        let c = run(&[
            "--rpc-restricted-bind-port",
            "34570",
            "--public-node",
            "--rpc-login",
            "alice:s3cret:with:colons",
            "--rpc-access-control-origins",
            "https://a.example, https://b.example",
            "--disable-rpc-ban",
            "--rpc-max-connections-per-public-ip",
            "5",
            "--rpc-ssl",
            "disabled",
            "--max-txpool-weight",
            "1000000",
            "--pidfile",
            "w.pid",
            "--non-interactive",
            "--no-zmq",
            "--disable-dns-checkpoints",
        ]);
        assert_eq!(c.rpc_restricted_bind_port, Some(34_570));
        assert!(c.public_node && c.disable_rpc_ban && c.non_interactive);
        assert_eq!(
            c.rpc_login,
            Some(("alice".into(), Some("s3cret:with:colons".into())))
        );
        assert_eq!(
            c.rpc_access_control_origins,
            vec!["https://a.example", "https://b.example"]
        );
        assert_eq!(c.rpc_max_connections_per_public_ip, 5);
        assert_eq!(c.rpc_max_connections_per_private_ip, 25, "the default");
        assert_eq!(c.max_txpool_weight, 1_000_000);
        assert_eq!(c.pidfile, Some(PathBuf::from("w.pid")));

        assert_eq!(
            run(&["--rpc-login", "bob"]).rpc_login,
            Some(("bob".into(), None)),
            "a password may be left to be generated"
        );
        assert!(err(&["--public-node"]).contains("--restricted-rpc"));
        assert!(run(&["--public-node", "--restricted-rpc"]).public_node);
        assert!(err(&["--rpc-access-control-origins", "https://a.example"]).contains("--rpc-login"));
        assert!(err(&["--rpc-ssl", "sometimes"]).contains("enabled, disabled or autodetect"));
        assert!(err(&["--rpc-restricted-bind-port", "34568"]).contains("same port"));
        assert!(err(&["--rpc-login", ":pw"]).contains("user name"));

        match parse_args(&["--os-version"]) {
            ParseOutcome::Print(p) => assert!(p.starts_with("OS: ")),
            _ => panic!("--os-version prints"),
        }
    }

    /// The peer-to-peer options, with the C++'s defaults and its `-1`.
    #[test]
    fn the_p2p_options_parse() {
        let c = run(&[]);
        assert_eq!(c.p2p_bind_ip, "0.0.0.0");
        assert_eq!(c.p2p_bind_port, 34_567);
        assert_eq!(c.out_peers, 12);
        assert_eq!(c.in_peers, usize::MAX, "no limit, as the C++'s -1");
        assert_eq!(c.max_connections_per_ip, 1);
        assert_eq!(run(&["--testnet"]).p2p_bind_port, 28_080);
        assert_eq!(
            run(&["--p2p-bind-port", "4000", "--stagenet"]).p2p_bind_port,
            4000,
            "an explicit port wins, in either order"
        );

        let c = run(&[
            "--add-peer",
            "1.2.3.4:34567",
            "--add-peer",
            "node.example",
            "--add-exclusive-node",
            "[::1]:28080",
            "--add-priority-node",
            "5.6.7.8",
            "--seed-node",
            "9.9.9.9:1",
            "--out-peers",
            "-1",
            "--in-peers",
            "8",
            "--max-connections-per-ip",
            "2",
            "--p2p-external-port",
            "5555",
            "--hide-my-port",
            "--allow-local-ip",
            "--no-sync",
            "--offline",
            "--no-igd",
            "--igd",
            "disabled",
            "--keep-alt-blocks",
            "--ban-list",
            "bans.txt",
            "--log-level",
            "net.p2p:DEBUG",
        ]);
        assert_eq!(c.add_peers, vec!["1.2.3.4:34567", "node.example"]);
        assert_eq!(c.exclusive_nodes, vec!["[::1]:28080"]);
        assert_eq!(c.priority_nodes, vec!["5.6.7.8"]);
        assert_eq!(c.seed_nodes, vec!["9.9.9.9:1"]);
        assert_eq!(c.out_peers, 12, "-1 is the default");
        assert_eq!(c.in_peers, 8);
        assert_eq!(c.max_connections_per_ip, 2);
        assert_eq!(c.p2p_external_port, Some(5555));
        assert!(c.hide_my_port && c.allow_local_ip && c.no_sync && c.offline && c.keep_alt_blocks);
        assert_eq!(c.ban_list, Some(PathBuf::from("bans.txt")));
        assert_eq!(c.log_level.as_deref(), Some("net.p2p:DEBUG"));

        assert!(err(&["--add-peer", "1.2.3.4:notaport"]).contains("port"));
        assert!(err(&["--add-peer"]).contains("needs"));
        assert!(err(&["--igd", "enabled"]).contains("UPnP"));
        assert!(err(&["--out-peers", "-5"]).contains("count"));
        assert!(err(&["--max-connections-per-ip", "0"]).contains("at least 1"));
        assert!(err(&["--p2p-bind-port", "70000"]).contains("port"));
    }

    /// The TLS options, with autodetect as the default and the key and
    /// certificate given together or not at all.
    #[test]
    fn the_tls_options_parse() {
        let c = run(&[]);
        assert_eq!(c.rpc_ssl, RpcSsl::Autodetect);
        assert!(c.rpc_ssl_allowed_fingerprints.is_empty());

        let fp = "ab:".repeat(31) + "ab";
        let c = run(&[
            "--rpc-ssl",
            "enabled",
            "--rpc-ssl-certificate",
            "node.crt",
            "--rpc-ssl-private-key",
            "node.key",
            "--rpc-ssl-ca-certificates",
            "clients.pem",
            "--rpc-ssl-allowed-fingerprints",
            fp.as_str(),
            "--rpc-ssl-allowed-fingerprints",
            &"01".repeat(32),
            "--rpc-ssl-allow-chained",
            "--rpc-ssl-allow-any-cert",
        ]);
        assert_eq!(c.rpc_ssl, RpcSsl::Enabled);
        assert_eq!(c.rpc_ssl_certificate, Some(PathBuf::from("node.crt")));
        assert_eq!(c.rpc_ssl_private_key, Some(PathBuf::from("node.key")));
        assert_eq!(
            c.rpc_ssl_ca_certificates,
            Some(PathBuf::from("clients.pem"))
        );
        assert_eq!(c.rpc_ssl_allowed_fingerprints, vec![[0xab; 32], [0x01; 32]]);
        assert!(c.rpc_ssl_allow_chained && c.rpc_ssl_allow_any_cert);
        assert_eq!(run(&["--rpc-ssl", "disabled"]).rpc_ssl, RpcSsl::Disabled);

        assert!(err(&["--rpc-ssl-certificate", "a.crt"]).contains("go together"));
        assert!(err(&["--rpc-ssl-private-key", "a.key"]).contains("go together"));
        assert!(err(&["--rpc-ssl-allowed-fingerprints", "abcd"]).contains("32 bytes"));
    }

    /// The IPv6 options, with the C++'s defaults: off, `::` for peers, `::1`
    /// for RPC, and the IPv6 peer port following the network like the IPv4
    /// one.
    #[test]
    fn the_ipv6_options_parse() {
        let c = run(&[]);
        assert!(!c.p2p_use_ipv6 && !c.rpc_use_ipv6);
        assert!(!c.p2p_ignore_ipv4 && !c.rpc_ignore_ipv4);
        assert_eq!(c.p2p_bind_ipv6_address, "::");
        assert_eq!(c.p2p_bind_port_ipv6, 34_567);
        assert_eq!(c.rpc_bind_ipv6_address, "::1");
        assert_eq!(c.rpc_restricted_bind_ipv6_address, "::1");
        assert_eq!(run(&["--testnet"]).p2p_bind_port_ipv6, 28_080);

        let c = run(&[
            "--p2p-use-ipv6",
            "--p2p-ignore-ipv4",
            "--p2p-bind-ipv6-address",
            "[2001:db8::1]",
            "--p2p-bind-port-ipv6",
            "4567",
            "--rpc-use-ipv6",
            "--rpc-ignore-ipv4",
            "--rpc-bind-ipv6-address",
            "::",
            "--rpc-restricted-bind-ipv6-address",
            "::1",
            "--stagenet",
        ]);
        assert!(c.p2p_use_ipv6 && c.p2p_ignore_ipv4 && c.rpc_use_ipv6 && c.rpc_ignore_ipv4);
        assert_eq!(c.p2p_bind_ipv6_address, "[2001:db8::1]");
        assert_eq!(c.p2p_bind_port_ipv6, 4567, "an explicit port wins");
        assert_eq!(c.rpc_bind_ipv6_address, "::");

        assert!(err(&["--p2p-bind-ipv6-address", "1.2.3.4"]).contains("not an IPv6 address"));
        assert!(err(&["--rpc-bind-ipv6-address", "localhost"]).contains("not an IPv6 address"));
        assert!(err(&["--p2p-bind-port-ipv6", "99999"]).contains("port"));
    }

    #[test]
    fn read_only_and_salvage_are_flags() {
        let c = run(&["--db-readonly", "--db-salvage"]);
        assert!(c.read_only);
        assert!(c.salvage);
    }

    #[test]
    fn the_mining_options_parse_and_the_key_stays_out_of_debug_output() {
        let c = run(&[]);
        assert_eq!(
            (c.start_mining.as_deref(), c.mining_threads, c.vote),
            (None, 1, 0)
        );
        assert!(c.spendkey.is_none() && c.fixed_difficulty.is_none());

        let key = "01".repeat(32);
        let c = run(&[
            "--serve",
            "--regtest",
            "--start-mining",
            "WWaddress",
            "--mining-threads",
            "4",
            "--spendkey",
            key.as_str(),
            "--vote",
            "yes",
            "--fixed-difficulty",
            "1",
        ]);
        assert_eq!(c.start_mining.as_deref(), Some("WWaddress"));
        assert_eq!(c.mining_threads, 4);
        assert_eq!(c.vote, 1);
        assert_eq!(c.fixed_difficulty, Some(1));
        assert!(c.spendkey.is_some());
        assert!(
            !format!("{c:?}").contains(&key),
            "a secret key is not printed"
        );
        assert_eq!(run(&["--vote", "no"]).vote, 2);

        assert!(err(&["--vote", "maybe"]).contains("yes or no"));
        assert!(err(&["--fixed-difficulty", "1"]).contains("--regtest"));
        assert!(err(&["--regtest", "--fixed-difficulty", "0"]).contains("at least 1"));
        assert!(err(&["--mining-threads", "0"]).contains("at least 1"));
        assert!(err(&["--spendkey", "abcd"]).contains("32 bytes"));
        assert!(err(&["--serve", "--start-mining", "x", "--db-readonly"]).contains("writable"));
        assert!(err(&["--start-mining", "x"]).contains("--serve"));
    }
}
