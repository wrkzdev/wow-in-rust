//! Command line parsing.
//!
//! `specs/09-daemon.md` §3. Only the options this node can honour are accepted;
//! an option from §3.2 that is recognised but not yet implemented is rejected
//! with a message saying so, rather than being parsed and ignored. A daemon
//! that silently drops `--db-sync-mode` is worse than one that refuses it.

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
    /// Required to bind a non-loopback address, since this build has no TLS
    /// and no RPC authentication (`specs/11` §1.2).
    pub confirm_external_bind: bool,
}

/// `RPC_DEFAULT_PORT` per network (`cryptonote_config.h`).
pub const fn default_rpc_port(network: Network) -> u16 {
    match network {
        Network::Testnet => 28_081,
        Network::Stagenet => 38_081,
        // Fakechain shares mainnet's, as the C++ does.
        _ => 34_568,
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
        }
    }
}

/// `~/.wownero`, with the network subdirectory the C++ adds.
///
/// The subdirectory is added by [`wow_storage::env::db_dir`], so this is the
/// base only.
pub fn default_data_dir(_network: Network) -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".wownero")
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

A Rust Wownero node. This build can open and inspect a `data.mdb` written by
the C++ `wownerod` (specs/10 §7), serve RPC, hold a transaction pool, and
pull blocks from one peer at a time over the peer protocol.

NETWORK
    --testnet                 use the test network
    --stagenet                use the stage network
    --regtest                 use a fake chain (implies the data dir already
                              ends in `fake`)

DATABASE
    --data-dir <path>         default: ~/.wownero
    --db-readonly             open read-only; safe against a running C++ node
    --db-sync-mode <mode>     safe | fast | fastest        (default: fast)
    --db-salvage              open the previous meta page

RPC (specs/11)
    --rpc-bind-ip <ip>        default: 127.0.0.1
    --rpc-bind-port <port>    default: 34568 (28081 testnet, 38081 stagenet)
    --restricted-rpc          run the server in restricted mode
    --confirm-external-bind   required to bind a non-loopback address, since
                              this build has no TLS and no RPC login

COMMANDS
    --serve                   run the RPC server and stay up
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
    --sync-from <host:port>   handshake with that peer and pull blocks from it,
                              then exit. Wownero has no DNS seeds, so there is
                              no automatic bootstrap yet -- specs/01 §12.2 lists
                              the hard-coded mainnet seeds.

GENERAL
    --help                    this text
    --version                 version string

RPC METHODS SERVED
    POST /get_height  /get_info  /get_checkpoints  /get_transactions
         /send_raw_transaction
    POST /json_rpc    get_info, get_version, hard_fork_info, get_fee_estimate,
                      get_block_hash, get_last_block_header,
                      get_block_header_by_height, get_block_header_by_hash,
                      get_block_headers_range, get_block, get_checkpoints
    POST /get_blocks.bin  /get_hashes.bin  /get_o_indexes.bin  /get_outs.bin
         /get_output_distribution.bin  /get_transaction_pool_hashes.bin

NOT YET IMPLEMENTED
    Mining, inbound peer connections and block propagation are not built, so
    this node never announces a block and never earns one. Sync is manual
    (--sync-from) and one peer at a time.

    Proof of work is checked for RandomWOW (major version 13 and up) and
    CryptoNight variant 1 (versions 7-8). Variants 2 and 4, which cover
    versions 9 through 12, are missing -- a sync from genesis stops at the
    version 9 fork rather than accept a block it cannot verify.

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
    ("--p2p-bind-ip", "peer-to-peer sync is not implemented"),
    ("--p2p-bind-port", "peer-to-peer sync is not implemented"),
    ("--add-peer", "peer-to-peer sync is not implemented"),
    (
        "--add-priority-node",
        "peer-to-peer sync is not implemented",
    ),
    (
        "--add-exclusive-node",
        "peer-to-peer sync is not implemented",
    ),
    ("--seed-node", "peer-to-peer sync is not implemented"),
    ("--start-mining", "the miner is not implemented"),
    ("--mining-threads", "the miner is not implemented"),
    ("--block-sync-size", "peer-to-peer sync is not implemented"),
    ("--offline", "there is nothing to go offline from yet"),
    ("--detach", "this build runs in the foreground only"),
];

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> ParseOutcome {
    let mut cfg = Config::default();
    let mut network_set = false;
    let mut rpc_port_set = false;
    let mut data_dir: Option<PathBuf> = None;

    let mut it = args.into_iter().peekable();
    while let Some(arg) = it.next() {
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
        assert!(c.data_dir.ends_with(".wownero"));
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
        assert!(err(&["--p2p-bind-port"]).contains("peer-to-peer"));
        assert!(err(&["--start-mining"]).contains("miner"));

        // The RPC options are real now, so they must *not* be refused.
        assert_eq!(run(&["--rpc-bind-port", "1234"]).rpc_bind_port, 1234);
        assert!(run(&["--restricted-rpc"]).restricted_rpc);
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

    #[test]
    fn read_only_and_salvage_are_flags() {
        let c = run(&["--db-readonly", "--db-salvage"]);
        assert!(c.read_only);
        assert!(c.salvage);
    }
}
