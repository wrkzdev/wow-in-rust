//! `wownero-wallet-cli` — the command-line wallet.
//!
//! `specs/13`. The M4 minimum set from §4: open, create and restore a wallet,
//! show its keys and addresses, sync against a daemon, and send.
//!
//! # Options or questions
//!
//! Anything needed to open or restore a wallet can be given as an option, and
//! whatever is not given is asked for ([`startup`]). A seed or key typed at a
//! prompt stays out of the process list and the shell history; an option does
//! not.
//!
//! # `--command` is the one that matters for testing
//!
//! `specs/13` §3 asks for a way to run a single command and exit with a status,
//! "which is how scripts drive the wallet". Everything below can be driven that
//! way, and the integration tests do.

mod commands;
mod fmt;
mod progress;
mod session;
mod startup;
mod term;

use std::path::PathBuf;

use wow_crypto::mnemonic::Language;
use wow_crypto::Zeroizing;
use wow_types::Network;

/// How the wallet gets its keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// Open an existing wallet.
    Open,
    /// Make up new keys.
    GenerateNew,
    /// Restore from a 25-word seed.
    Seed,
    /// Restore from the secret spend key, deriving the view key from it.
    SpendKey,
    /// Restore from an address and both secret keys.
    Keys,
    /// A view-only wallet, from an address and the secret view key.
    ViewKey,
}

impl Source {
    /// Whether this brings back a wallet that may already own funds.
    fn restores(self) -> bool {
        !matches!(self, Source::Open | Source::GenerateNew)
    }
}

struct Options {
    wallet: Option<PathBuf>,
    source: Source,
    network: Network,
    /// The secrets an option can carry, held so they are wiped when the
    /// options go rather than left in the process's memory for the rest of
    /// the session.
    password: Option<Zeroizing<String>>,
    seed: Option<Zeroizing<String>>,
    address: Option<String>,
    view_key: Option<Zeroizing<String>>,
    spend_key: Option<Zeroizing<String>>,
    daemon: Option<String>,
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
    /// `--offline`: talk to no node at all. What the cold half of a
    /// cold-signing pair is run with.
    offline: bool,
    /// `None` when not given, so a restore knows to ask.
    restore_height: Option<u64>,
    kdf_rounds: u64,
    /// `None` when not given, so a new wallet knows to ask.
    language: Option<String>,
    commands: Vec<String>,
    no_initial_sync: bool,
    /// `--log-level`, as given.
    log_level: Option<String>,
    log_file: Option<PathBuf>,
    max_log_file_size: u64,
    max_log_files: usize,
}

/// Written by hand rather than derived, so a password, seed or secret key
/// cannot reach a log through a `{:?}`.
impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn redacted<T>(v: &Option<T>) -> Option<&'static str> {
            v.as_ref().map(|_| "<redacted>")
        }
        f.debug_struct("Options")
            .field("wallet", &self.wallet)
            .field("source", &self.source)
            .field("network", &self.network)
            .field("password", &redacted(&self.password))
            .field("seed", &redacted(&self.seed))
            .field("address", &self.address)
            .field("view_key", &redacted(&self.view_key))
            .field("spend_key", &redacted(&self.spend_key))
            .field("daemon", &self.daemon)
            .field("daemon_login", &redacted(&self.daemon_login))
            .field("ssl", &self.ssl)
            .field("proxy", &redacted(&self.proxy))
            .field("trusted_daemon", &self.trusted_daemon)
            .field("offline", &self.offline)
            .field("restore_height", &self.restore_height)
            .field("kdf_rounds", &self.kdf_rounds)
            .field("language", &self.language)
            .field("commands", &self.commands)
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
            wallet: None,
            source: Source::Open,
            network: Network::Mainnet,
            password: None,
            seed: None,
            address: None,
            view_key: None,
            spend_key: None,
            daemon: None,
            daemon_login: None,
            ssl: Default::default(),
            proxy: None,
            trusted_daemon: None,
            offline: false,
            restore_height: None,
            kdf_rounds: 1,
            language: None,
            commands: Vec::new(),
            no_initial_sync: false,
            log_level: None,
            log_file: None,
            max_log_file_size: 104_850_000,
            max_log_files: 50,
        }
    }
}

const USAGE: &str = "\
wownero-wallet-cli — the Wownero command-line wallet

Run it with no options to be asked which wallet to open, create or restore.
Whatever the options below leave out is asked for.

  --wallet-file <name>              open an existing wallet
  --generate-new-wallet <name>      create one
  --restore-deterministic-wallet    restore from a 25-word seed
  --generate-from-spend-key <name>  restore from a secret spend key
  --generate-from-keys <name>       restore from an address and both secret keys
  --generate-from-view-key <name>   restore a view-only wallet
  --restore-from-keys               restore from keys, named by
                                    --generate-new-wallet; view-only when
                                    --viewkey is given without --spendkey

  --electrum-seed \"<25 words>\"      the seed, instead of being asked for it
  --address <addr>                  the address, likewise
  --viewkey <hex> --spendkey <hex>  the secret keys, likewise

  --password <pass>                 (a password file is safer; see below)
  --password-file <path>
  --daemon-address <address>        host:port, or https://host:port for TLS;
                                    default 127.0.0.1:34568
  --daemon-login <user>:<pass>      for a daemon started with --rpc-login
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
                                    this wallet; default: trusted only on
                                    this machine
  --offline                         do not connect to a daemon, nor use DNS.
                                    How the half of a cold-signing pair that
                                    holds the spend key is run
  --testnet / --stagenet
  --restore-height <n>
  --mnemonic-language <lang>
  --kdf-rounds <n>                  default 1
  --no-initial-sync
  --log-file <path>                 log here; never to the terminal
  --log-level <0-4 | category:LEVEL,...>
                                    default 0; given alone, logs to
                                    wownero-wallet-cli.log beside the program
  --max-log-file-size <bytes>       default 104850000
  --max-log-files <n>               rotated files to keep, default 50
  --command <cmd ...>               run one command and exit
  --help
  --version

A seed, key or password given as an option can be read from the process list
by other users, and stays in the shell history. Leave it out to be asked.";

/// `--version`. The number is this project's own; the C++ release named after
/// it is the one this build aims to be compatible with (`specs/00` §1):
/// `wownero-project/wownero` tag `v0.11.4.0`, commit `9f4f22c72`.
pub(crate) const VERSION: &str = concat!(
    "wownero-wallet-cli ",
    env!("CARGO_PKG_VERSION"),
    " (wownero-rs, compatible with Wownero C++ 0.11.4.0 \"Kunty Karen\")"
);

/// The options that name a new wallet and say what to restore it from, as the
/// C++ wallet spells them.
const GENERATE_FROM: [(&str, Source); 3] = [
    ("--generate-from-spend-key", Source::SpendKey),
    ("--generate-from-keys", Source::Keys),
    ("--generate-from-view-key", Source::ViewKey),
];

fn parse(args: Vec<String>) -> Result<Options, String> {
    let mut o = Options::default();
    // Every option that named the wallet, so two names can be refused.
    let mut named_by: Vec<&'static str> = Vec::new();
    // What to restore from, and the option that said so.
    let mut restore: Option<(Source, &'static str)> = None;

    let mut it = args.into_iter().skip(1);
    while let Some(arg) = it.next() {
        let mut next = |what: &str| -> Result<String, String> {
            it.next().ok_or(format!("{what} needs a value"))
        };
        match arg.as_str() {
            "--help" | "-h" => return Err(USAGE.into()),
            "--version" | "-V" => return Err(VERSION.into()),
            "--wallet-file" => {
                o.wallet = Some(PathBuf::from(next("--wallet-file")?));
                named_by.push("--wallet-file");
            }
            "--generate-new-wallet" => {
                o.wallet = Some(PathBuf::from(next("--generate-new-wallet")?));
                named_by.push("--generate-new-wallet");
            }
            "--restore-deterministic-wallet" | "--restore-from-seed" => {
                restore_from(&mut restore, Source::Seed, "--restore-deterministic-wallet")?
            }
            "--restore-from-keys" => {
                restore_from(&mut restore, Source::Keys, "--restore-from-keys")?
            }
            "--electrum-seed" => o.seed = Some(Zeroizing::new(next("--electrum-seed")?)),
            "--address" => o.address = Some(next("--address")?),
            "--viewkey" => o.view_key = Some(Zeroizing::new(next("--viewkey")?)),
            "--spendkey" => o.spend_key = Some(Zeroizing::new(next("--spendkey")?)),
            "--password" => o.password = Some(Zeroizing::new(next("--password")?)),
            "--password-file" => {
                let path = next("--password-file")?;
                // Both the contents and the trimmed copy are wiped: the point
                // of a password file is that the password is not on the
                // command line, so it should not outlive the read either.
                let text = Zeroizing::new(
                    std::fs::read_to_string(&path)
                        .map_err(|e| format!("cannot read {path}: {e}"))?,
                );
                o.password = Some(Zeroizing::new(
                    text.trim_end_matches(['\r', '\n']).to_string(),
                ));
            }
            "--daemon-address" => o.daemon = Some(next("--daemon-address")?),
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
            "--daemon-host" => {
                let host = next("--daemon-host")?;
                o.daemon = Some(format!("{host}:34568"));
            }
            "--testnet" => o.network = Network::Testnet,
            "--stagenet" => o.network = Network::Stagenet,
            "--restore-height" => {
                let height = next("--restore-height")?
                    .parse()
                    .map_err(|_| "--restore-height needs a number".to_string())?;
                o.restore_height = Some(height);
            }
            "--kdf-rounds" => {
                o.kdf_rounds = next("--kdf-rounds")?
                    .parse()
                    .map_err(|_| "--kdf-rounds needs a number".to_string())?;
                if o.kdf_rounds == 0 {
                    return Err("--kdf-rounds must be at least 1".into());
                }
            }
            "--mnemonic-language" => {
                let name = next("--mnemonic-language")?;
                // Either name of a language is accepted; the keys file gets
                // its own name for itself, as the C++ writes it.
                match wow_crypto::mnemonic::by_name(&name) {
                    Some(l) if l.language != Language::EnglishOld => {
                        o.language = Some(l.name.to_string())
                    }
                    _ => return Err(format!("`{name}` is not a seed language")),
                }
            }
            "--offline" => o.offline = true,
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
            // Everything after `--command` is one command line.
            "--command" => {
                let rest: Vec<String> = it.by_ref().collect();
                if rest.is_empty() {
                    return Err("--command needs a command".into());
                }
                o.commands.push(rest.join(" "));
                break;
            }
            other => {
                let Some(&(flag, source)) = GENERATE_FROM.iter().find(|(f, _)| *f == other) else {
                    return Err(format!("unknown option `{other}`. Try --help."));
                };
                o.wallet = Some(PathBuf::from(next(flag)?));
                named_by.push(flag);
                restore_from(&mut restore, source, flag)?;
            }
        }
    }

    if let &[first, second, ..] = named_by.as_slice() {
        return Err(format!("{first} and {second} both name a wallet; give one"));
    }
    match restore {
        Some((_, flag)) if named_by == ["--wallet-file"] => {
            return Err(format!(
                "{flag} makes a new wallet: name it with --generate-new-wallet, not --wallet-file"
            ));
        }
        Some((source, flag)) => {
            o.source = source;
            if flag == "--restore-from-keys" && o.view_key.is_some() && o.spend_key.is_none() {
                o.source = Source::ViewKey;
            }
        }
        None if named_by == ["--generate-new-wallet"] => o.source = Source::GenerateNew,
        None => {}
    }

    Ok(o)
}

/// Record what to restore from, refusing a second, different answer.
fn restore_from(
    slot: &mut Option<(Source, &'static str)>,
    source: Source,
    flag: &'static str,
) -> Result<(), String> {
    match *slot {
        Some((s, first)) if s != source => Err(format!(
            "{first} and {flag} are different ways to restore; give one"
        )),
        Some(_) => Ok(()),
        None => {
            *slot = Some((source, flag));
            Ok(())
        }
    }
}

fn main() {
    let options = match parse(std::env::args().collect()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(if e == USAGE || e == VERSION { 0 } else { 1 });
        }
    };

    match run(options) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

/// Where the log goes (`wallet_args::main`).
///
/// Never to the terminal, which is the wallet's prompt: to `--log-file`, or,
/// when only `--log-level` is given, to `wownero-wallet-cli.log` beside the
/// program, where the C++ writes it. With neither, nothing is logged. The C++
/// opens that file on every run, and without `--log-level` enables no category
/// to write to it.
fn start_logging(o: &Options) -> Result<(), String> {
    wow_log::set_stderr(false);
    if o.log_level.is_none() && o.log_file.is_none() {
        return Ok(());
    }
    if let Some(spec) = &o.log_level {
        wow_log::configure(spec).map_err(|e| format!("--log-level: {e}"))?;
    }
    let path = o
        .log_file
        .clone()
        .unwrap_or_else(|| wow_log::beside_program("wownero-wallet-cli.log"));
    wow_log::set_file(path.clone(), o.max_log_file_size, o.max_log_files, true)?;
    eprintln!("Logging to {}", path.display());
    wow_log::info!("global", "{VERSION}");
    // Safe to log only because `Options`' `Debug` redacts every secret.
    wow_log::debug!("global", "{o:?}");
    Ok(())
}

/// The `--daemon-ssl` and `--proxy` options made sense of, and refused where
/// `make_basic` refuses them: before any password is asked for.
fn daemon_options(o: &Options, daemon: &str) -> Result<wow_daemon_client::ConnectOptions, String> {
    let mut options = wow_daemon_client::ConnectOptions::from_flags(&o.ssl)?;
    if let Some(text) = &o.proxy {
        let proxy = wow_daemon_client::Proxy::parse(text).map_err(|e| format!("--proxy: {e}"))?;
        // A login of this session's own, so Tor keeps its circuits apart.
        let mut token = [0u8; 16];
        term::seeded_rng()?.fill(&mut token);
        options.proxy = Some(proxy.isolated(&token));
    }
    if options.lacks_strong_verification(daemon) {
        let flag = if options.proxy.is_some() {
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
    Ok(options)
}

/// `simple_wallet::init`'s warning about a daemon that is not trusted, on
/// standard error so a `--command` script's output stays clean.
fn warn_untrusted(session: &session::Session) {
    let Some(daemon) = &session.daemon else {
        return;
    };
    eprintln!("Warning: using an untrusted daemon at {}", daemon.address());
    eprintln!("Using a third party daemon can be detrimental to your security and privacy");
    if !matches!(
        daemon.security(),
        Some(wow_daemon_client::Security::Tls { .. })
    ) {
        eprintln!("Using your own without SSL exposes your RPC traffic to monitoring");
    }
    eprintln!(
        "You are strongly encouraged to connect to the Wownero network using your own daemon"
    );
    eprintln!(
        "If you or someone you trust are operating this daemon, you can use --trusted-daemon"
    );
}

fn run(mut options: Options) -> Result<(), String> {
    start_logging(&options)?;
    let daemon = options
        .daemon
        .clone()
        .unwrap_or_else(|| "127.0.0.1:34568".to_string());
    let connect = daemon_options(&options, &daemon)?;
    let mut session = startup::start(&mut options)?;
    session.daemon_options = connect;

    // Before the first connection: a daemon with --rpc-login refuses
    // everything, including the get_info that `set_daemon` checks with.
    if let Some(text) = &options.daemon_login {
        match wow_daemon_client::digest::Credentials::parse(text) {
            Some(c) => session.daemon_login = Some(c),
            None => return Err("--daemon-login takes <user>:<password>".into()),
        }
    }

    // `--offline`, `wallet2::set_offline`: no node is contacted, so none is
    // named. The reference makes every HTTP call fail without trying; here
    // there is simply nothing to fail. This is how the cold half of a
    // cold-signing pair is run, and it is the whole point of the flag.
    if options.offline {
        session.offline = true;
        eprintln!("Offline: this wallet will not contact a daemon.");
        return interactive_or_commands(session, &options);
    }

    // Connect, and sync unless told not to. `set_daemon` trusts a daemon on
    // this machine unless told otherwise, as `make_basic` does.
    let trust = match options.trusted_daemon {
        Some(true) => " trusted",
        Some(false) => " untrusted",
        None => "",
    };
    match commands::run_one(&mut session, &format!("set_daemon {daemon}{trust}")) {
        Err(e) => {
            // Diagnostics go to stderr, so `--command bc_height` prints a
            // height on stdout and nothing else. A script reading stdout must
            // not have to filter our chatter out of it.
            eprintln!("{e}");
            eprintln!("(carrying on offline; `set_daemon <host:port>` to try again)");
        }
        Ok(_) => {
            if !session.state.trusted_daemon {
                warn_untrusted(&session);
            }

            // A wallet whose keys were generated moments ago cannot own an
            // output older than the tip, so it starts there rather than
            // reading the whole chain to find nothing. `wallet2::generate`
            // does the same.
            //
            // Only for a new wallet, and only when no `--restore-height` was
            // given: a wallet restored from a seed may own old outputs, and
            // starting it at the tip would hide them behind a balance of zero
            // that looks perfectly correct.
            if options.source == Source::GenerateNew && options.restore_height.unwrap_or(0) == 0 {
                let tip = session.chain_height();
                session.start_at_tip(tip);
                if tip > 0 {
                    eprintln!(
                        "New wallet: scanning from height {} (nothing older can be ours).",
                        tip - 1
                    );
                }
            }

            if !options.no_initial_sync {
                if let Err(e) = commands::run_one(&mut session, "refresh") {
                    eprintln!("Could not refresh: {e}");
                }
            }
        }
    }

    interactive_or_commands(session, &options)
}

/// Run the `--command` lines and exit, or prompt.
///
/// Split out so that `--offline` can reach it without a daemon: there is no
/// node to name, nothing to connect to, and nothing to sync.
fn interactive_or_commands(
    mut session: crate::session::Session,
    options: &Options,
) -> Result<(), String> {
    // `--command` runs and exits.
    if !options.commands.is_empty() {
        let mut failed = false;
        for line in &options.commands {
            let (outcome, err) = commands::run(&mut session, line);
            failed |= err;
            if matches!(outcome, commands::Outcome::Quit) {
                break;
            }
        }
        if session.dirty {
            session.save()?;
        }
        if failed {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Otherwise, a prompt.
    println!("Type `help` for commands.");
    while let Some(line) = term::read_command("[wallet]: ") {
        if matches!(
            commands::run(&mut session, line.trim()).0,
            commands::Outcome::Quit
        ) {
            break;
        }
    }

    if session.dirty {
        session.save()?;
        println!("Saved.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(args: &[&str]) -> Result<Options, String> {
        let mut v = vec!["wownero-wallet-cli".to_string()];
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
                    assert!(e.starts_with("wownero-wallet-cli "), "{e}");
                    assert!(e.contains("Kunty Karen"), "{e}");
                }
                Ok(_) => panic!("{flag} should print, not run"),
            }
        }
    }

    #[test]
    fn the_defaults_are_the_documented_ones() {
        let o = opts(&["--wallet-file", "w"]).expect("parses");
        assert_eq!(o.source, Source::Open);
        assert_eq!(o.network, Network::Mainnet);
        assert_eq!(o.kdf_rounds, 1);
        assert!(o.language.is_none(), "a new wallet asks, or uses English");
        assert!(o.restore_height.is_none(), "a restore asks, or starts at 0");
        assert!(o.daemon.is_none(), "the default is applied at connect time");
    }

    #[test]
    fn the_networks_are_selectable() {
        assert_eq!(
            opts(&["--wallet-file", "w", "--testnet"])
                .expect("ok")
                .network,
            Network::Testnet
        );
        assert_eq!(
            opts(&["--wallet-file", "w", "--stagenet"])
                .expect("ok")
                .network,
            Network::Stagenet
        );
    }

    /// Everything after `--command` is the command, so a transfer with
    /// arguments survives.
    #[test]
    fn command_takes_the_rest_of_the_line() {
        let o = opts(&[
            "--wallet-file",
            "w",
            "--command",
            "transfer",
            "Wo1abc",
            "1.5",
        ])
        .expect("parses");
        assert_eq!(o.commands, vec!["transfer Wo1abc 1.5"]);
    }

    #[test]
    fn a_missing_value_is_an_error() {
        assert!(opts(&["--wallet-file"]).is_err());
        assert!(opts(&["--generate-from-keys"]).is_err());
        assert!(opts(&["--restore-height"]).is_err());
        assert!(opts(&["--command"]).is_err());
        assert!(opts(&["--kdf-rounds", "0"]).is_err());
    }

    #[test]
    fn an_unknown_option_is_an_error() {
        let e = opts(&["--wallet-file", "w", "--mine-please"]).expect_err("rejected");
        assert!(e.contains("--mine-please"), "{e}");
    }

    /// The log options, with the C++'s rotation defaults.
    #[test]
    fn the_log_options_parse() {
        let o = opts(&["--wallet-file", "w"]).expect("parses");
        assert!(o.log_level.is_none() && o.log_file.is_none());
        assert_eq!((o.max_log_file_size, o.max_log_files), (104_850_000, 50));

        let o = opts(&[
            "--wallet-file",
            "w",
            "--log-level",
            "net.http:DEBUG,wallet.*:INFO",
            "--log-file",
            "wallet.log",
            "--max-log-file-size",
            "1000",
            "--max-log-files",
            "3",
        ])
        .expect("parses");
        assert_eq!(o.log_level.as_deref(), Some("net.http:DEBUG,wallet.*:INFO"));
        assert_eq!(o.log_file, Some(PathBuf::from("wallet.log")));
        assert_eq!((o.max_log_file_size, o.max_log_files), (1000, 3));

        assert!(opts(&["--wallet-file", "w", "--log-level"]).is_err());
        assert!(opts(&["--wallet-file", "w", "--max-log-files", "many"]).is_err());
    }

    /// A restore needs nothing up front: the name, seed and keys it is not
    /// given are asked for.
    #[test]
    fn a_restore_parses_without_its_material() {
        let o = opts(&["--restore-deterministic-wallet"]).expect("parses");
        assert_eq!(o.source, Source::Seed);
        assert!(o.wallet.is_none() && o.seed.is_none());

        let o = opts(&["--generate-from-keys", "w"]).expect("parses");
        assert_eq!(o.source, Source::Keys);
        assert_eq!(o.wallet, Some(PathBuf::from("w")));

        let o = opts(&["--generate-from-view-key", "w"]).expect("parses");
        assert_eq!(o.source, Source::ViewKey);
    }

    /// One name, and one thing to restore from. `--wallet-file` opens a wallet,
    /// so it cannot name one being restored.
    #[test]
    fn a_wallet_is_named_once_and_restored_one_way() {
        let e = opts(&["--wallet-file", "a", "--generate-new-wallet", "b"]).expect_err("two names");
        assert!(
            e.contains("--wallet-file") && e.contains("--generate-new-wallet"),
            "{e}"
        );

        let e = opts(&["--wallet-file", "w", "--restore-deterministic-wallet"])
            .expect_err("--wallet-file opens");
        assert!(e.contains("--generate-new-wallet"), "{e}");

        let e = opts(&[
            "--generate-new-wallet",
            "w",
            "--restore-deterministic-wallet",
            "--restore-from-keys",
        ])
        .expect_err("two ways to restore");
        assert!(e.contains("different ways"), "{e}");
    }

    /// `--restore-from-keys` with a view key and no spend key has always meant
    /// a view-only wallet. With neither, the spend key is asked for.
    #[test]
    fn restore_from_keys_is_view_only_without_a_spend_key() {
        let o = opts(&[
            "--generate-new-wallet",
            "w",
            "--restore-from-keys",
            "--address",
            "Wo1",
            "--viewkey",
            "00",
        ])
        .expect("parses");
        assert_eq!(o.source, Source::ViewKey);

        let o = opts(&["--generate-new-wallet", "w", "--restore-from-keys"]).expect("parses");
        assert_eq!(o.source, Source::Keys);
    }

    #[test]
    fn a_seed_restore_is_recognised() {
        let o = opts(&[
            "--generate-new-wallet",
            "w",
            "--restore-deterministic-wallet",
            "--electrum-seed",
            "one two three",
        ])
        .expect("parses");
        assert_eq!(o.source, Source::Seed);
        assert_eq!(o.seed.as_deref().map(String::as_str), Some("one two three"));
    }

    #[test]
    fn the_seed_language_is_checked() {
        let o = opts(&[
            "--generate-new-wallet",
            "w",
            "--mnemonic-language",
            "Spanish",
        ])
        .expect("the English name works");
        assert_eq!(
            o.language.as_deref(),
            Some("Español"),
            "stored by its own name"
        );

        assert!(opts(&[
            "--generate-new-wallet",
            "w",
            "--mnemonic-language",
            "Klingon"
        ])
        .is_err());
        assert!(
            opts(&[
                "--generate-new-wallet",
                "w",
                "--mnemonic-language",
                "EnglishOld"
            ])
            .is_err(),
            "the old list is not offered for new seeds"
        );
    }

    /// The `--daemon-ssl` options, by the C++'s names, and required TLS
    /// refused without a certificate named ahead, as `make_basic` refuses it.
    #[test]
    fn the_ssl_options_parse() {
        let o = opts(&[
            "--wallet-file",
            "w",
            "--daemon-ssl",
            "enabled",
            "--daemon-ssl-allowed-fingerprints",
            "aa",
            "--daemon-ssl-allowed-fingerprints",
            "bb",
            "--daemon-ssl-ca-certificates",
            "ca.pem",
            "--daemon-ssl-allow-chained",
            "--daemon-ssl-allow-any-cert",
            "--daemon-ssl-certificate",
            "wallet.crt",
            "--daemon-ssl-private-key",
            "wallet.key",
        ])
        .expect("parses");
        assert_eq!(o.ssl.ssl.as_deref(), Some("enabled"));
        assert_eq!(o.ssl.allowed_fingerprints, ["aa", "bb"]);
        assert_eq!(o.ssl.ca_certificates, Some(PathBuf::from("ca.pem")));
        assert!(o.ssl.allow_chained && o.ssl.allow_any_cert);
        assert_eq!(o.ssl.certificate, Some(PathBuf::from("wallet.crt")));
        assert_eq!(o.ssl.private_key, Some(PathBuf::from("wallet.key")));
        assert!(opts(&["--wallet-file", "w", "--daemon-ssl"]).is_err());

        let enabled = opts(&["--wallet-file", "w", "--daemon-ssl", "enabled"]).expect("parses");
        let e = daemon_options(&enabled, "node.example:34568").expect_err("nothing named");
        assert!(e.contains("--daemon-ssl-allowed-fingerprints"), "{e}");
        assert!(daemon_options(&enabled, "abc.onion:34568").is_ok());
        let plain = opts(&["--wallet-file", "w"]).expect("parses");
        assert!(daemon_options(&plain, "node.example:34568").is_ok());
    }

    /// `--trusted-daemon` and `--untrusted-daemon`, and not both.
    #[test]
    fn the_trust_options_parse() {
        assert_eq!(
            opts(&["--wallet-file", "w"]).expect("ok").trusted_daemon,
            None
        );
        let o = opts(&["--wallet-file", "w", "--trusted-daemon"]).expect("ok");
        assert_eq!(o.trusted_daemon, Some(true));
        let o = opts(&["--wallet-file", "w", "--untrusted-daemon"]).expect("ok");
        assert_eq!(o.trusted_daemon, Some(false));
        let e = opts(&[
            "--wallet-file",
            "w",
            "--trusted-daemon",
            "--untrusted-daemon",
        ])
        .expect_err("both");
        assert!(e.contains("contradict"), "{e}");
    }

    /// `--proxy`, and what `make_basic` asks of a node reached through one: a
    /// certificate named ahead, or an onion address.
    #[test]
    fn a_proxy_needs_a_named_certificate_or_an_onion() {
        let o = opts(&["--wallet-file", "w", "--proxy", "127.0.0.1:9050"]).expect("parses");
        assert_eq!(o.proxy.as_deref(), Some("127.0.0.1:9050"));
        let e = daemon_options(&o, "node.example:34568").expect_err("clearnet, unchecked");
        assert!(e.contains("Enabling --proxy"), "{e}");
        let options = daemon_options(&o, "abc.onion:34568").expect("an onion");
        let proxy = options.proxy.expect("the proxy");
        assert_eq!(proxy.address, "127.0.0.1:9050");
        assert!(proxy.login.is_some(), "a login of the session's own");

        let any = opts(&[
            "--wallet-file",
            "w",
            "--proxy",
            "9050",
            "--daemon-ssl-allow-any-cert",
        ])
        .expect("parses");
        assert!(daemon_options(&any, "node.example:34568").is_ok());

        let socks4 =
            opts(&["--wallet-file", "w", "--proxy", "socks4://127.0.0.1:9050"]).expect("parses");
        assert!(daemon_options(&socks4, "abc.onion:34568").is_err());
    }

    #[test]
    fn debug_output_hides_secrets() {
        let o = opts(&[
            "--generate-new-wallet",
            "w",
            "--restore-from-keys",
            "--password",
            "secret-password",
            "--spendkey",
            "secret-spend",
            "--viewkey",
            "secret-view",
            "--electrum-seed",
            "secret-seed",
        ])
        .expect("parses");
        let shown = format!("{o:?}");
        assert!(!shown.contains("secret-"), "{shown}");
    }
}
