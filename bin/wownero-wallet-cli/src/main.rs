//! `wownero-wallet-cli` — the command-line wallet.
//!
//! `specs/13`. The M4 minimum set from §4: open, create and restore a wallet,
//! show its keys and addresses, sync against a daemon, and send.
//!
//! # `--command` is the one that matters for testing
//!
//! `specs/13` §3 asks for a way to run a single command and exit with a status,
//! "which is how scripts drive the wallet". Everything below can be driven that
//! way, and the integration tests do.

mod commands;
mod fmt;
mod session;
mod term;

use std::path::PathBuf;

use wow_types::Network;
use wow_wallet::AccountBase;

use session::{Paths, Session};

/// How the wallet was asked to get its keys.
#[derive(Debug)]
enum Source {
    Open,
    GenerateNew,
    RestoreSeed(String),
    RestoreKeys {
        address: String,
        view: String,
        spend: Option<String>,
    },
}

struct Options {
    wallet: Option<PathBuf>,
    source: Source,
    network: Network,
    password: Option<String>,
    daemon: Option<String>,
    restore_height: u64,
    kdf_rounds: u64,
    language: String,
    commands: Vec<String>,
    no_initial_sync: bool,
}

/// Written by hand rather than derived, so a password cannot reach a log
/// through a `{:?}`. A seed phrase is redacted for the same reason.
impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("wallet", &self.wallet)
            .field(
                "source",
                &match &self.source {
                    Source::RestoreSeed(_) => "RestoreSeed(<redacted>)".to_string(),
                    other => format!("{other:?}"),
                },
            )
            .field("network", &self.network)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("daemon", &self.daemon)
            .field("restore_height", &self.restore_height)
            .field("kdf_rounds", &self.kdf_rounds)
            .field("language", &self.language)
            .field("commands", &self.commands)
            .field("no_initial_sync", &self.no_initial_sync)
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
            daemon: None,
            restore_height: 0,
            kdf_rounds: 1,
            language: "English".into(),
            commands: Vec::new(),
            no_initial_sync: false,
        }
    }
}

const USAGE: &str = "\
wownero-wallet-cli — the Wownero command-line wallet

  --wallet-file <name>              open an existing wallet
  --generate-new-wallet <name>      create one
  --restore-deterministic-wallet    restore from a 25-word seed
  --electrum-seed \"<25 words>\"      the seed, for the above
  --restore-from-keys               restore from an address and keys
  --address <addr> --viewkey <hex> [--spendkey <hex>]

  --password <pass>                 (a password file is safer; see below)
  --password-file <path>
  --daemon-address <host:port>      default 127.0.0.1:34568
  --testnet / --stagenet
  --restore-height <n>
  --mnemonic-language <lang>
  --kdf-rounds <n>                  default 1
  --no-initial-sync
  --command <cmd ...>               run one command and exit
  --help

A wallet with no --wallet-file and no --generate-new-wallet has nothing to do,
so it says what its options are rather than starting an empty prompt.";

fn parse(args: Vec<String>) -> Result<Options, String> {
    let mut o = Options::default();
    let mut address = None;
    let mut view = None;
    let mut spend = None;
    let mut seed = None;
    let mut restore_seed = false;
    let mut restore_keys = false;

    let mut it = args.into_iter().skip(1);
    while let Some(arg) = it.next() {
        let mut next = |what: &str| -> Result<String, String> {
            it.next().ok_or(format!("{what} needs a value"))
        };
        match arg.as_str() {
            "--help" | "-h" => return Err(USAGE.into()),
            "--wallet-file" => o.wallet = Some(PathBuf::from(next("--wallet-file")?)),
            "--generate-new-wallet" => {
                o.wallet = Some(PathBuf::from(next("--generate-new-wallet")?));
                o.source = Source::GenerateNew;
            }
            "--restore-deterministic-wallet" => restore_seed = true,
            "--restore-from-keys" | "--generate-from-keys" => restore_keys = true,
            "--electrum-seed" => seed = Some(next("--electrum-seed")?),
            "--address" => address = Some(next("--address")?),
            "--viewkey" => view = Some(next("--viewkey")?),
            "--spendkey" => spend = Some(next("--spendkey")?),
            "--password" => o.password = Some(next("--password")?),
            "--password-file" => {
                let path = next("--password-file")?;
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| format!("cannot read {path}: {e}"))?;
                o.password = Some(text.trim_end_matches(['\r', '\n']).to_string());
            }
            "--daemon-address" => o.daemon = Some(next("--daemon-address")?),
            "--daemon-host" => {
                let host = next("--daemon-host")?;
                o.daemon = Some(format!("{host}:34568"));
            }
            "--testnet" => o.network = Network::Testnet,
            "--stagenet" => o.network = Network::Stagenet,
            "--restore-height" => {
                o.restore_height = next("--restore-height")?
                    .parse()
                    .map_err(|_| "--restore-height needs a number".to_string())?;
            }
            "--kdf-rounds" => {
                o.kdf_rounds = next("--kdf-rounds")?
                    .parse()
                    .map_err(|_| "--kdf-rounds needs a number".to_string())?;
                if o.kdf_rounds == 0 {
                    return Err("--kdf-rounds must be at least 1".into());
                }
            }
            "--mnemonic-language" => o.language = next("--mnemonic-language")?,
            "--no-initial-sync" => o.no_initial_sync = true,
            // Everything after `--command` is one command line.
            "--command" => {
                let rest: Vec<String> = it.by_ref().collect();
                if rest.is_empty() {
                    return Err("--command needs a command".into());
                }
                o.commands.push(rest.join(" "));
                break;
            }
            other => return Err(format!("unknown option `{other}`. Try --help.")),
        }
    }

    if restore_seed {
        let s = seed.ok_or("--restore-deterministic-wallet needs --electrum-seed")?;
        o.source = Source::RestoreSeed(s);
    } else if restore_keys {
        o.source = Source::RestoreKeys {
            address: address.ok_or("--restore-from-keys needs --address")?,
            view: view.ok_or("--restore-from-keys needs --viewkey")?,
            spend,
        };
    }

    Ok(o)
}

fn main() {
    let options = match parse(std::env::args().collect()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(if e == USAGE { 0 } else { 1 });
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

fn run(options: Options) -> Result<(), String> {
    let Some(path) = options.wallet.clone() else {
        eprintln!("{USAGE}");
        return Err("no wallet named".into());
    };
    let paths = Paths::new(path);

    let password = match options.password.clone() {
        Some(p) => p,
        None => term::read_password("Wallet password: ").ok_or("no password given")?,
    };

    let mut session = match &options.source {
        Source::Open => Session::open(paths, password, options.kdf_rounds, Some(options.network))?,
        _ => {
            let account = build_account(&options)?;
            let s = Session::create(
                paths,
                options.network,
                password,
                options.kdf_rounds,
                account,
                &options.language,
                options.restore_height,
            )?;
            println!("Created {}", s.paths.keys().display());
            println!("Address: {}", s.primary_address());
            if matches!(options.source, Source::GenerateNew) {
                match s.seed(&options.language) {
                    Ok(seed) => {
                        println!();
                        println!("Write this down. It is the only way to recover this wallet:");
                        println!("  {seed}");
                        println!();
                    }
                    Err(e) => println!("(no seed phrase: {e})"),
                }
            }
            s
        }
    };

    // Connect, and sync unless told not to.
    let daemon = options
        .daemon
        .clone()
        .unwrap_or_else(|| "127.0.0.1:34568".to_string());
    match commands::run_one(&mut session, &format!("set_daemon {daemon}")) {
        Err(e) => {
            // Diagnostics go to stderr, so `--command bc_height` prints a
            // height on stdout and nothing else. A script reading stdout must
            // not have to filter our chatter out of it.
            eprintln!("{e}");
            eprintln!("(carrying on offline; `set_daemon <host:port>` to try again)");
        }
        Ok(_) => {
            // A wallet whose keys were generated moments ago cannot own an
            // output older than the tip, so it starts there rather than
            // reading the whole chain to find nothing. `wallet2::generate`
            // does the same.
            //
            // Only for `--generate-new-wallet`, and only when no
            // `--restore-height` was given: a wallet restored from a seed may
            // own old outputs, and starting it at the tip would hide them
            // behind a balance of zero that looks perfectly correct.
            if matches!(options.source, Source::GenerateNew) && options.restore_height == 0 {
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
    while let Some(line) = term::read_line("[wallet]: ") {
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

fn build_account(options: &Options) -> Result<AccountBase, String> {
    let created = session::now();
    match &options.source {
        Source::GenerateNew => {
            let mut rng = term::seeded_rng()?;
            let spend = wow_crypto::types::SecretKey(rng.random_scalar());
            AccountBase::from_spend_key(spend, created)
                .ok_or_else(|| "could not derive keys from the generated secret".into())
        }
        Source::RestoreSeed(phrase) => {
            let (spend, list) = wow_crypto::mnemonic::words_to_key(phrase)
                .map_err(|e| format!("that seed phrase is not valid: {e}"))?;
            println!("Seed language: {}", list.name);
            AccountBase::from_spend_key(spend, created)
                .ok_or_else(|| "that seed does not produce a valid key".into())
        }
        Source::RestoreKeys {
            address,
            view,
            spend,
        } => {
            let decoded = wow_types::address::Address::decode_for(address, options.network)
                .map_err(|e| format!("that address is not valid: {e}"))?;
            let view = secret_from_hex(view, "view key")?;

            match spend {
                Some(s) => {
                    let spend = secret_from_hex(s, "spend key")?;
                    let a = AccountBase::from_keys(spend, view, created)
                        .ok_or("those keys are not valid")?;
                    if a.keys.account_address != decoded.keys {
                        return Err(
                            "those keys do not belong to that address; nothing was written".into(),
                        );
                    }
                    Ok(a)
                }
                None => {
                    let a = AccountBase::view_only(decoded.keys, view, created);
                    a.keys
                        .verify()
                        .map_err(|e| format!("that view key does not match that address: {e}"))?;
                    println!("(view-only: this wallet can watch but not spend)");
                    Ok(a)
                }
            }
        }
        Source::Open => unreachable!("handled above"),
    }
}

fn secret_from_hex(s: &str, what: &str) -> Result<wow_crypto::types::SecretKey, String> {
    let bytes = wow_crypto::hex::decode(s).ok_or(format!("the {what} is not hex"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("the {what} is not 32 bytes"))?;
    if !wow_crypto::sc_check(&bytes) {
        return Err(format!("the {what} is not a valid scalar"));
    }
    Ok(wow_crypto::types::SecretKey(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(args: &[&str]) -> Result<Options, String> {
        let mut v = vec!["wownero-wallet-cli".to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        parse(v)
    }

    #[test]
    fn the_defaults_are_the_documented_ones() {
        let o = opts(&["--wallet-file", "w"]).expect("parses");
        assert_eq!(o.network, Network::Mainnet);
        assert_eq!(o.kdf_rounds, 1);
        assert_eq!(o.language, "English");
        assert_eq!(o.restore_height, 0);
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
        assert!(opts(&["--restore-height"]).is_err());
        assert!(opts(&["--command"]).is_err());
        assert!(opts(&["--kdf-rounds", "0"]).is_err());
    }

    #[test]
    fn an_unknown_option_is_an_error() {
        let e = opts(&["--wallet-file", "w", "--mine-please"]).expect_err("rejected");
        assert!(e.contains("--mine-please"), "{e}");
    }

    /// Restoring needs the material it says it needs, rather than silently
    /// creating a different wallet.
    #[test]
    fn restoring_needs_its_inputs() {
        let e = opts(&["--wallet-file", "w", "--restore-deterministic-wallet"])
            .expect_err("needs a seed");
        assert!(e.contains("--electrum-seed"), "{e}");

        let e = opts(&["--wallet-file", "w", "--restore-from-keys"]).expect_err("needs an address");
        assert!(e.contains("--address"), "{e}");

        let e = opts(&[
            "--wallet-file",
            "w",
            "--restore-from-keys",
            "--address",
            "Wo1",
        ])
        .expect_err("needs a view key");
        assert!(e.contains("--viewkey"), "{e}");
    }

    #[test]
    fn a_seed_restore_is_recognised() {
        let o = opts(&[
            "--wallet-file",
            "w",
            "--restore-deterministic-wallet",
            "--electrum-seed",
            "one two three",
        ])
        .expect("parses");
        assert!(matches!(o.source, Source::RestoreSeed(s) if s == "one two three"));
    }

    /// A hex key that is not a canonical scalar is refused. Accepting one would
    /// build a wallet whose keys do not behave.
    #[test]
    fn a_bad_secret_key_is_refused() {
        assert!(secret_from_hex("not hex", "view key").is_err());
        assert!(secret_from_hex("00", "view key").is_err());
        assert!(secret_from_hex(&"ff".repeat(32), "view key").is_err());
        // A valid one.
        let ok = wow_crypto::hex::encode(&wow_crypto::ops::sc_reduce32(&[7u8; 32]));
        assert!(secret_from_hex(&ok, "view key").is_ok());
    }
}
