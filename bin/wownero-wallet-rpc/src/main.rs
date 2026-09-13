//! `wownero-wallet-rpc` — the wallet's programmatic surface (`specs/14`).
//!
//! Exchanges and payment processors depend on this, so method names, parameter
//! names and error codes are a **compatibility surface**: a rename is a break,
//! and a wrong error code sends a client down the wrong recovery path silently.
//!
//! # Authentication is not optional
//!
//! `specs/14` §1 requires either `--rpc-login` or an explicit
//! `--disable-rpc-login`, and says why: "an unauthenticated wallet RPC on a
//! reachable interface is a wallet-draining hole". Starting with neither is
//! refused here rather than defaulting to open, because the default that is
//! convenient is the one that loses money.

mod errors;
mod methods;
mod server;

use std::path::PathBuf;
use std::sync::Arc;

use wow_types::Network;
use wow_wallet::files::Paths;

use server::{State, WalletSource};

const USAGE: &str = "\
wownero-wallet-rpc — the Wownero wallet RPC (specs/14)

  --rpc-bind-port <port>            required
  --rpc-bind-ip <ip>                default 127.0.0.1
  --confirm-external-bind           needed to bind anything else

  --wallet-file <path>              hold one wallet
  --password <pass>                 its password
  --password-file <path>
  --wallet-dir <dir>                or let clients open and create in a directory

  --rpc-login <user:pass>           HTTP Basic
  --disable-rpc-login               explicitly run without authentication

  --daemon-address <host:port>      default 127.0.0.1:34568
  --testnet / --stagenet
  --kdf-rounds <n>                  default 1
  --no-initial-sync
  --help

Either --rpc-login or --disable-rpc-login must be given. There is no default:
an unauthenticated wallet RPC is a wallet-draining hole, and choosing to run
one should be something you typed.";

struct Options {
    bind_ip: String,
    bind_port: Option<u16>,
    confirm_external_bind: bool,
    wallet_file: Option<PathBuf>,
    wallet_dir: Option<PathBuf>,
    password: Option<String>,
    login: Option<(String, String)>,
    disable_login: bool,
    daemon: String,
    network: Network,
    kdf_rounds: u64,
    no_initial_sync: bool,
}

/// Written by hand rather than derived: this struct holds a wallet password
/// and an RPC credential, and deriving would put both one `{:?}` away from a
/// log file.
impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("bind_ip", &self.bind_ip)
            .field("bind_port", &self.bind_port)
            .field("confirm_external_bind", &self.confirm_external_bind)
            .field("wallet_file", &self.wallet_file)
            .field("wallet_dir", &self.wallet_dir)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field(
                "login",
                &self.login.as_ref().map(|(u, _)| format!("{u}:<redacted>")),
            )
            .field("disable_login", &self.disable_login)
            .field("daemon", &self.daemon)
            .field("network", &self.network)
            .field("kdf_rounds", &self.kdf_rounds)
            .field("no_initial_sync", &self.no_initial_sync)
            .finish()
    }
}

impl Default for Options {
    fn default() -> Self {
        Options {
            bind_ip: "127.0.0.1".into(),
            bind_port: None,
            confirm_external_bind: false,
            wallet_file: None,
            wallet_dir: None,
            password: None,
            login: None,
            disable_login: false,
            daemon: "127.0.0.1:34568".into(),
            network: Network::Mainnet,
            kdf_rounds: 1,
            no_initial_sync: false,
        }
    }
}

fn parse(args: Vec<String>) -> Result<Options, String> {
    let mut o = Options::default();
    let mut it = args.into_iter().skip(1);
    while let Some(arg) = it.next() {
        let mut next = |what: &str| -> Result<String, String> {
            it.next().ok_or(format!("{what} needs a value"))
        };
        match arg.as_str() {
            "--help" | "-h" => return Err(USAGE.into()),
            "--rpc-bind-port" => {
                o.bind_port = Some(
                    next("--rpc-bind-port")?
                        .parse()
                        .map_err(|_| "--rpc-bind-port needs a number".to_string())?,
                )
            }
            "--rpc-bind-ip" => o.bind_ip = next("--rpc-bind-ip")?,
            "--confirm-external-bind" => o.confirm_external_bind = true,
            "--wallet-file" => o.wallet_file = Some(PathBuf::from(next("--wallet-file")?)),
            "--wallet-dir" => o.wallet_dir = Some(PathBuf::from(next("--wallet-dir")?)),
            "--password" => o.password = Some(next("--password")?),
            "--password-file" => {
                let path = next("--password-file")?;
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| format!("cannot read {path}: {e}"))?;
                o.password = Some(text.trim_end_matches(['\r', '\n']).to_string());
            }
            "--rpc-login" => {
                let value = next("--rpc-login")?;
                let (user, pass) = value
                    .split_once(':')
                    .ok_or("--rpc-login takes user:pass".to_string())?;
                o.login = Some((user.to_string(), pass.to_string()));
            }
            "--disable-rpc-login" => o.disable_login = true,
            "--daemon-address" => o.daemon = next("--daemon-address")?,
            "--testnet" => o.network = Network::Testnet,
            "--stagenet" => o.network = Network::Stagenet,
            "--kdf-rounds" => {
                o.kdf_rounds = next("--kdf-rounds")?
                    .parse()
                    .map_err(|_| "--kdf-rounds needs a number".to_string())?;
                if o.kdf_rounds == 0 {
                    return Err("--kdf-rounds must be at least 1".into());
                }
            }
            "--no-initial-sync" => o.no_initial_sync = true,
            other => return Err(format!("unknown option `{other}`. Try --help.")),
        }
    }
    validate(&o)?;
    Ok(o)
}

fn validate(o: &Options) -> Result<(), String> {
    if o.bind_port.is_none() {
        return Err("--rpc-bind-port is required".into());
    }
    if o.wallet_file.is_none() && o.wallet_dir.is_none() {
        return Err("one of --wallet-file or --wallet-dir is required".into());
    }
    if o.wallet_file.is_some() && o.wallet_dir.is_some() {
        return Err("--wallet-file and --wallet-dir are alternatives, not both".into());
    }
    // `specs/14` §1: one or the other, never neither.
    if o.login.is_some() && o.disable_login {
        return Err("--rpc-login and --disable-rpc-login contradict each other".into());
    }
    if o.login.is_none() && !o.disable_login {
        return Err(
            "either --rpc-login <user:pass> or --disable-rpc-login is required.\n\
             There is no default: an unauthenticated wallet RPC on a reachable interface \
             lets anyone who can connect drain the wallet."
                .into(),
        );
    }
    // A wallet RPC without authentication, bound where others can reach it, is
    // the specific thing the requirement above exists to prevent.
    let loopback = o
        .bind_ip
        .parse::<std::net::IpAddr>()
        .map(|a| a.is_loopback())
        .unwrap_or(false);
    if !loopback && !o.confirm_external_bind {
        return Err(format!(
            "refusing to bind {}: this build has no TLS, so a non-loopback bind exposes \
             credentials and wallet operations in the clear.\n\
             Pass --confirm-external-bind if that is what you want, or put a reverse proxy \
             in front of 127.0.0.1.",
            o.bind_ip
        ));
    }
    Ok(())
}

fn main() {
    let options = match parse(std::env::args().collect()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(if e == USAGE { 0 } else { 1 });
        }
    };

    if let Err(e) = run(options) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(options: Options) -> Result<(), String> {
    let source = match (&options.wallet_file, &options.wallet_dir) {
        (Some(f), None) => WalletSource::File {
            paths: Paths::new(f.clone()),
            password: options.password.clone().unwrap_or_default(),
        },
        (None, Some(d)) => {
            if !d.is_dir() {
                return Err(format!("{} is not a directory", d.display()));
            }
            WalletSource::Dir(d.clone())
        }
        _ => unreachable!("validated above"),
    };

    let state = Arc::new(State::new(
        source,
        options.network,
        options.kdf_rounds,
        options.login.clone(),
        // Held on the server, not just applied once: a --wallet-dir server has
        // no wallet yet, and every wallet a client opens or creates later must
        // reach the same daemon.
        options.daemon.clone(),
    ));

    state.open_at_startup()?;

    // Point the wallet at a daemon, and sync, if one is open.
    if state.wallet().is_some() {
        let params = serde_json::json!({ "address": options.daemon });
        match methods::dispatch(&state, "set_daemon", &params) {
            Ok(_) => {
                if !options.no_initial_sync {
                    if let Err(e) = methods::dispatch(&state, "refresh", &serde_json::json!({})) {
                        eprintln!("Could not refresh: {}", e.message);
                    }
                }
            }
            Err(e) => {
                eprintln!("{}", e.message);
                eprintln!("(carrying on; call set_daemon when one is reachable)");
            }
        }
    } else {
        eprintln!(
            "Wallets opened here will use the daemon at {}.",
            options.daemon
        );
    }

    if options.login.is_none() {
        eprintln!(
            "warning: running without authentication (--disable-rpc-login). Anyone who can \
             reach {}:{} can spend this wallet.",
            options.bind_ip,
            options.bind_port.expect("validated")
        );
    }

    let bind = format!(
        "{}:{}",
        options.bind_ip,
        options.bind_port.expect("validated")
    );
    server::serve(state, &bind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(args: &[&str]) -> Result<Options, String> {
        let mut v = vec!["wownero-wallet-rpc".to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        parse(v)
    }

    const MINIMUM: &[&str] = &[
        "--rpc-bind-port",
        "18082",
        "--wallet-dir",
        ".",
        "--disable-rpc-login",
    ];

    #[test]
    fn the_minimum_parses() {
        let o = opts(MINIMUM).expect("parses");
        assert_eq!(o.bind_port, Some(18082));
        assert_eq!(o.bind_ip, "127.0.0.1");
        assert!(o.disable_login);
        assert_eq!(o.kdf_rounds, 1);
    }

    /// The requirement `specs/14` §1 calls a wallet-draining hole if it is
    /// missing: authentication is a decision, never a default.
    #[test]
    fn running_without_a_login_decision_is_refused() {
        let e = opts(&["--rpc-bind-port", "18082", "--wallet-dir", "."])
            .expect_err("must not default to open");
        assert!(e.contains("--rpc-login"), "{e}");
        assert!(e.contains("drain"), "it says why: {e}");

        // And the two cannot both be given.
        let e = opts(&[
            "--rpc-bind-port",
            "18082",
            "--wallet-dir",
            ".",
            "--disable-rpc-login",
            "--rpc-login",
            "u:p",
        ])
        .expect_err("contradictory");
        assert!(e.contains("contradict"), "{e}");
    }

    #[test]
    fn a_login_parses_into_its_parts() {
        let mut args = MINIMUM.to_vec();
        args.retain(|a| *a != "--disable-rpc-login");
        args.extend_from_slice(&["--rpc-login", "alice:secret"]);
        let o = opts(&args).expect("parses");
        assert_eq!(o.login, Some(("alice".into(), "secret".into())));

        args.pop();
        args.push("nocolon");
        assert!(opts(&args).is_err(), "a login needs a colon");
    }

    /// A non-loopback bind without TLS needs saying so out loud.
    #[test]
    fn an_external_bind_needs_confirmation() {
        let mut args = MINIMUM.to_vec();
        args.extend_from_slice(&["--rpc-bind-ip", "0.0.0.0"]);
        let e = opts(&args).expect_err("refused");
        assert!(e.contains("--confirm-external-bind"), "{e}");

        args.push("--confirm-external-bind");
        assert!(opts(&args).is_ok());
    }

    #[test]
    fn a_wallet_source_is_required_and_exclusive() {
        let e =
            opts(&["--rpc-bind-port", "18082", "--disable-rpc-login"]).expect_err("needs a wallet");
        assert!(e.contains("--wallet-file"), "{e}");

        let e = opts(&[
            "--rpc-bind-port",
            "18082",
            "--disable-rpc-login",
            "--wallet-dir",
            ".",
            "--wallet-file",
            "w",
        ])
        .expect_err("exclusive");
        assert!(e.contains("alternatives"), "{e}");
    }

    #[test]
    fn a_port_is_required() {
        let e = opts(&["--wallet-dir", ".", "--disable-rpc-login"]).expect_err("needs a port");
        assert!(e.contains("--rpc-bind-port"), "{e}");
    }

    #[test]
    fn an_unknown_option_is_an_error() {
        let mut args = MINIMUM.to_vec();
        args.push("--mine-please");
        let e = opts(&args).expect_err("rejected");
        assert!(e.contains("--mine-please"), "{e}");
    }
}
