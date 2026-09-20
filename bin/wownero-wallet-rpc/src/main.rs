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

use wow_crypto::Zeroizing;
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

  --daemon-login <user>:<pass>      for a daemon started with --rpc-login
  --daemon-address <address>        host:port, or https://host:port for TLS;
                                    default 127.0.0.1:34568
  --daemon-ssl <autodetect|enabled|disabled>
                                    TLS to a daemon given without https://;
                                    default autodetect: TLS if it speaks it,
                                    plain HTTP with a warning if not
  --daemon-ssl-allowed-fingerprints <sha256>
                                    accept only this certificate; repeatable
  --daemon-ssl-ca-certificates <path>
                                    or one in this PEM file
  --daemon-ssl-allow-chained        or one chained to a certificate in it
  --daemon-ssl-allow-any-cert       accept any certificate
  --daemon-ssl-certificate <path> --daemon-ssl-private-key <path>
                                    a certificate to show a daemon that asks
  --proxy [socks5://][<user>:<pass>@][<host>:]<port>
                                    reach the daemon through a SOCKS5 proxy,
                                    Tor's say; its name is not looked up here
  --trusted-daemon / --untrusted-daemon
                                    whether the daemon may see what reveals
                                    the wallet; default: trusted only on
                                    this machine
  --offline                         do not connect to a daemon, nor use DNS.
                                    How a server that only signs is run
  --testnet / --stagenet
  --kdf-rounds <n>                  default 1
  --no-initial-sync
  --log-file <path>                 also log here
  --log-level <0-4 | category:LEVEL,...>
                                    default 0; given alone, also logs to
                                    wownero-wallet-rpc.log beside the program
  --max-log-file-size <bytes>       default 104850000
  --max-log-files <n>               rotated files to keep, default 50
  --help
  --version

Either --rpc-login or --disable-rpc-login must be given. There is no default:
an unauthenticated wallet RPC is a wallet-draining hole, and choosing to run
one should be something you typed.";

/// `--version`. The number is this project's own; the C++ release named after
/// it is the one this build aims to be compatible with (`specs/00` §1):
/// `wownero-project/wownero` tag `v0.11.4.0`, commit `9f4f22c72`.
const VERSION: &str = concat!(
    "wownero-wallet-rpc ",
    env!("CARGO_PKG_VERSION"),
    " (wownero-rs, compatible with Wownero C++ 0.11.4.0 \"Kunty Karen\")"
);

struct Options {
    bind_ip: String,
    bind_port: Option<u16>,
    confirm_external_bind: bool,
    wallet_file: Option<PathBuf>,
    wallet_dir: Option<PathBuf>,
    /// `--password` or `--password-file`. Wiped when the options go.
    password: Option<Zeroizing<String>>,
    login: Option<(String, String)>,
    disable_login: bool,
    daemon: String,
    /// `--daemon-login <user>:<password>`, for a node started with
    /// `--rpc-login`.
    daemon_login: Option<String>,
    /// `--daemon-ssl` and the options beside it, as given.
    ssl: wow_daemon_client::SslFlags,
    /// `--proxy`, as given: it may carry a password.
    proxy: Option<String>,
    /// `--trusted-daemon` and `--untrusted-daemon`: `None` when neither was
    /// given, and a daemon on this machine is trusted.
    trusted_daemon: Option<bool>,
    /// `--offline`: contact no node. A server started this way is the cold
    /// half of a cold-signing pair.
    offline: bool,
    network: Network,
    kdf_rounds: u64,
    no_initial_sync: bool,
    /// `--log-level`, as given.
    log_level: Option<String>,
    log_file: Option<PathBuf>,
    max_log_file_size: u64,
    max_log_files: usize,
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
            .field(
                "daemon_login",
                &self.daemon_login.as_ref().map(|_| "<redacted>"),
            )
            .field("ssl", &self.ssl)
            .field("proxy", &self.proxy.as_ref().map(|_| "<redacted>"))
            .field("trusted_daemon", &self.trusted_daemon)
            .field("offline", &self.offline)
            .field("network", &self.network)
            .field("kdf_rounds", &self.kdf_rounds)
            .field("no_initial_sync", &self.no_initial_sync)
            .field("log_level", &self.log_level)
            .field("log_file", &self.log_file)
            .field("max_log_file_size", &self.max_log_file_size)
            .field("max_log_files", &self.max_log_files)
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
            daemon_login: None,
            ssl: Default::default(),
            proxy: None,
            trusted_daemon: None,
            offline: false,
            network: Network::Mainnet,
            kdf_rounds: 1,
            no_initial_sync: false,
            log_level: None,
            log_file: None,
            max_log_file_size: 104_850_000,
            max_log_files: 50,
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
            "--version" | "-V" => return Err(VERSION.into()),
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
            "--password" => o.password = Some(Zeroizing::new(next("--password")?)),
            "--password-file" => {
                let path = next("--password-file")?;
                // Both the file's contents and the trimmed copy are wiped: the
                // whole point of a password file is that the password is not on
                // the command line, so it should not outlive the read either.
                let text = Zeroizing::new(
                    std::fs::read_to_string(&path)
                        .map_err(|e| format!("cannot read {path}: {e}"))?,
                );
                o.password = Some(Zeroizing::new(
                    text.trim_end_matches(['\r', '\n']).to_string(),
                ));
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
            "--daemon-login" => o.daemon_login = Some(next("--daemon-login")?),
            "--daemon-ssl" => o.ssl.ssl = Some(next("--daemon-ssl")?),
            "--daemon-ssl-private-key" => {
                o.ssl.private_key = Some(PathBuf::from(next("--daemon-ssl-private-key")?))
            }
            "--daemon-ssl-certificate" => {
                o.ssl.certificate = Some(PathBuf::from(next("--daemon-ssl-certificate")?))
            }
            "--daemon-ssl-ca-certificates" => {
                o.ssl.ca_certificates = Some(PathBuf::from(next("--daemon-ssl-ca-certificates")?))
            }
            "--daemon-ssl-allowed-fingerprints" => o
                .ssl
                .allowed_fingerprints
                .push(next("--daemon-ssl-allowed-fingerprints")?),
            "--daemon-ssl-allow-any-cert" => o.ssl.allow_any_cert = true,
            "--daemon-ssl-allow-chained" => o.ssl.allow_chained = true,
            "--proxy" => o.proxy = Some(next("--proxy")?),
            "--trusted-daemon" | "--untrusted-daemon" => {
                let trusted = arg == "--trusted-daemon";
                if o.trusted_daemon.is_some_and(|t| t != trusted) {
                    return Err(
                        "--trusted-daemon and --untrusted-daemon contradict each other; \
                                give one"
                            .into(),
                    );
                }
                o.trusted_daemon = Some(trusted);
            }
            "--offline" => o.offline = true,
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
            "--log-level" => o.log_level = Some(next("--log-level")?),
            "--log-file" => o.log_file = Some(PathBuf::from(next("--log-file")?)),
            "--max-log-file-size" => {
                o.max_log_file_size = next("--max-log-file-size")?
                    .parse()
                    .map_err(|_| "--max-log-file-size needs a number".to_string())?;
            }
            "--max-log-files" => {
                o.max_log_files = next("--max-log-files")?
                    .parse()
                    .map_err(|_| "--max-log-files needs a number".to_string())?;
            }
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
            std::process::exit(if e == USAGE || e == VERSION { 0 } else { 1 });
        }
    };

    if let Err(e) = run(options) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

/// Where the log goes (`wallet_args::main`): to stderr, as a server's does, and
/// to `--log-file` as well. When only `--log-level` is given, the file is
/// `wownero-wallet-rpc.log` beside the program, where the C++ writes it.
fn start_logging(o: &Options) -> Result<(), String> {
    if let Some(spec) = &o.log_level {
        wow_log::configure(spec).map_err(|e| format!("--log-level: {e}"))?;
    }
    if o.log_level.is_none() && o.log_file.is_none() {
        return Ok(());
    }
    let path = o
        .log_file
        .clone()
        .unwrap_or_else(|| wow_log::beside_program("wownero-wallet-rpc.log"));
    wow_log::set_file(path.clone(), o.max_log_file_size, o.max_log_files, false)?;
    eprintln!("Logging to {}", path.display());
    wow_log::info!("global", "{VERSION}");
    // Safe to log only because `Options`' `Debug` redacts every secret.
    wow_log::debug!("global", "{o:?}");
    Ok(())
}

fn run(options: Options) -> Result<(), String> {
    start_logging(&options)?;
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

    let daemon_login = match &options.daemon_login {
        Some(text) => Some(
            wow_daemon_client::digest::Credentials::parse(text)
                .ok_or("--daemon-login takes <user>:<password>")?,
        ),
        None => None,
    };
    // Refused where `make_basic` refuses it, before any wallet is opened.
    let mut daemon_options = wow_daemon_client::ConnectOptions::from_flags(&options.ssl)?;
    if let Some(text) = &options.proxy {
        let proxy = wow_daemon_client::Proxy::parse(text).map_err(|e| format!("--proxy: {e}"))?;
        // A login of this server's own, so Tor keeps its circuits apart.
        let mut token = [0u8; 16];
        wow_wallet::entropy::seeded_rng()?.fill(&mut token);
        daemon_options.proxy = Some(proxy.isolated(&token));
    }
    if daemon_options.lacks_strong_verification(&options.daemon) {
        let flag = if daemon_options.proxy.is_some() {
            "--proxy"
        } else {
            "--daemon-ssl"
        };
        return Err(format!(
            "Enabling {flag} requires --daemon-ssl-allow-any-cert or \
             --daemon-ssl-ca-certificates or --daemon-ssl-allowed-fingerprints or use of a \
             .onion/.i2p domain"
        ));
    }

    let state = Arc::new(State::new(
        source,
        options.network,
        options.kdf_rounds,
        options.login.clone(),
        // Held on the server, not just applied once: a --wallet-dir server has
        // no wallet yet, and every wallet a client opens or creates later must
        // reach the same daemon.
        options.daemon.clone(),
        daemon_login,
    ));
    state.set_proxy_option(daemon_options.proxy.is_some());
    state.set_daemon_options(daemon_options);
    state.set_trusted_daemon(options.trusted_daemon);
    state.set_offline(options.offline);

    state.open_at_startup()?;

    if options.offline {
        eprintln!("Offline: no wallet this server opens will contact a daemon.");
    }

    // Point the wallet at a daemon, and sync, if one is open. Not when
    // `--offline` was given: there is nothing to point at.
    if !options.offline && state.wallet().is_some() {
        let params = serde_json::json!({
            "address": options.daemon,
            "trusted": state.trusted_daemon_for(&options.daemon),
        });
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

    /// `--version` prints and exits 0, so packagers and scripts can read it.
    /// The C++ release it names is what this build targets, not its own number.
    #[test]
    fn version_prints_and_names_the_cpp_release() {
        for flag in ["--version", "-V"] {
            match opts(&[flag]) {
                Err(e) => {
                    assert_eq!(e, VERSION);
                    assert!(e.starts_with("wownero-wallet-rpc "), "{e}");
                    assert!(e.contains("Kunty Karen"), "{e}");
                }
                Ok(_) => panic!("{flag} should print, not run"),
            }
        }
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

    /// `--proxy` and the `--daemon-ssl` options, by the C++'s names, and a
    /// proxy kept out of `{:?}`: it can carry a password.
    #[test]
    fn the_proxy_and_ssl_options_parse() {
        let mut args = MINIMUM.to_vec();
        args.extend_from_slice(&[
            "--proxy",
            "socks5://u:hunter2@127.0.0.1:9050",
            "--daemon-ssl",
            "enabled",
            "--daemon-ssl-allowed-fingerprints",
            "aa",
            "--daemon-ssl-allow-any-cert",
        ]);
        let o = opts(&args).expect("parses");
        assert_eq!(
            o.proxy.as_deref(),
            Some("socks5://u:hunter2@127.0.0.1:9050")
        );
        assert_eq!(o.ssl.ssl.as_deref(), Some("enabled"));
        assert_eq!(o.ssl.allowed_fingerprints, ["aa"]);
        assert!(o.ssl.allow_any_cert);
        assert!(!format!("{o:?}").contains("hunter2"));

        assert_eq!(o.trusted_daemon, None);
        let mut trusted = MINIMUM.to_vec();
        trusted.push("--untrusted-daemon");
        assert_eq!(opts(&trusted).expect("parses").trusted_daemon, Some(false));
        trusted.push("--trusted-daemon");
        assert!(opts(&trusted).is_err(), "not both");
    }

    /// The log options, with the C++'s rotation defaults.
    #[test]
    fn the_log_options_parse() {
        let o = opts(MINIMUM).expect("parses");
        assert!(o.log_level.is_none() && o.log_file.is_none());
        assert_eq!((o.max_log_file_size, o.max_log_files), (104_850_000, 50));

        let mut args = MINIMUM.to_vec();
        args.extend_from_slice(&[
            "--log-level",
            "2",
            "--log-file",
            "rpc.log",
            "--max-log-files",
            "7",
        ]);
        let o = opts(&args).expect("parses");
        assert_eq!(o.log_level.as_deref(), Some("2"));
        assert_eq!(o.log_file, Some(PathBuf::from("rpc.log")));
        assert_eq!(o.max_log_files, 7);

        args.push("--max-log-file-size");
        assert!(opts(&args).is_err(), "a missing value");
    }
}
