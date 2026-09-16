//! Getting a wallet open, and asking for whatever the options left out.
//!
//! `simple_wallet::init` in `simplewallet.cpp` asks for anything the command
//! line did not say, and so does this:
//!
//! * no wallet named: ask for a name, open it if it exists, and otherwise offer
//!   to create or restore one (`ask_wallet_create_if_needed`, plus the choice
//!   `specs/13` §1 asks for);
//! * a restore with no seed or keys given: ask for them, the secret ones
//!   without echo, and ask again if what was typed is wrong;
//! * no password given: ask, and ask twice for a new wallet;
//! * a new wallet with no `--mnemonic-language`: offer the list;
//! * a restore with no `--restore-height`: ask for one.
//!
//! The last two have defaults, so they are asked only at a terminal. The rest
//! are read from standard input even when it is a pipe, as the C++ reads them,
//! so a script can hand over a seed or a password without putting it in the
//! process list.

use std::path::PathBuf;

use wow_crypto::mnemonic::{self, Language, WordList};
use wow_crypto::types::{PublicKey, SecretKey};
use wow_types::address::{Address, AddressKind};
use wow_wallet::{AccountBase, KeysFile, KeysFileError};

use crate::session::{self, Paths, Session};
use crate::{term, Options, Source};

/// Open or create the wallet the options describe.
pub fn start(o: &mut Options) -> Result<Session, String> {
    if o.wallet.is_none() {
        ask_for_wallet(o)?;
    }
    let paths = Paths::new(o.wallet.clone().expect("named above"));
    match o.source {
        Source::Open => open(paths, o),
        _ => create(paths, o),
    }
}

/// `ask_wallet_create_if_needed`: a name, and what to do with it.
fn ask_for_wallet(o: &mut Options) -> Result<(), String> {
    let restoring = o.source.restores();
    println!(
        "{}",
        if restoring {
            "Specify a new wallet file name for your restored wallet (e.g., MyWallet)."
        } else {
            "Specify wallet file name (e.g., MyWallet). If the wallet doesn't exist, it will be created."
        }
    );
    let path = term::ask("Wallet file name (or Ctrl-C to quit): ", false, |name| {
        if name.is_empty() {
            return Err("a wallet needs a name".into());
        }
        if restoring && Paths::new(name).keys().exists() {
            return Err(format!(
                "{name} already exists, and restoring would overwrite it"
            ));
        }
        Ok(Some(PathBuf::from(name)))
    })?;

    let exists = Paths::new(&path).keys().exists();
    o.wallet = Some(path);
    if restoring {
        return Ok(());
    }
    if exists {
        println!("Wallet found; opening it.");
        return Ok(());
    }

    const CHOICES: [(Source, &str); 5] = [
        (Source::GenerateNew, "a new wallet"),
        (Source::Seed, "restored from a 25-word seed"),
        (Source::SpendKey, "restored from a secret spend key"),
        (
            Source::Keys,
            "restored from an address, a secret spend key and a secret view key",
        ),
        (
            Source::ViewKey,
            "view-only, from an address and a secret view key",
        ),
    ];
    println!("No wallet with that name. What should it be?");
    let names: Vec<String> = CHOICES.iter().map(|(_, n)| n.to_string()).collect();
    let i = term::choose("Enter the number of your choice: ", &names)?;
    o.source = CHOICES[i].0;
    Ok(())
}

/// Open an existing wallet.
fn open(paths: Paths, o: &Options) -> Result<Session, String> {
    // Checked before the password prompt, so a mistyped name is not found out
    // only after typing a password for it.
    if !paths.keys().exists() {
        return Err(format!(
            "{} not found; there is no wallet to open",
            paths.keys().display()
        ));
    }
    let password = match &o.password {
        Some(p) => p.clone(),
        None => ask_password(&paths, o.kdf_rounds)?,
    };
    let session = Session::open(paths, password, o.kdf_rounds, Some(o.network))?;
    if o.commands.is_empty() {
        let kind = if session.is_view_only() {
            "view-only wallet"
        } else {
            "wallet"
        };
        println!("Opened {kind}: {}", session.primary_address());
    }
    Ok(session)
}

/// Ask for an existing wallet's password, giving a terminal three tries.
///
/// The password is checked by decrypting the keys file, which `Session::open`
/// then does again. That costs one more key derivation, and it turns a typo
/// into a second chance rather than starting over. After the last try the
/// password is returned anyway, so `Session::open` reports why it failed.
fn ask_password(paths: &Paths, kdf_rounds: u64) -> Result<String, String> {
    let blob = std::fs::read(paths.keys())
        .map_err(|e| format!("cannot read {}: {e}", paths.keys().display()))?;
    let mut tries = 0;
    loop {
        let password = term::read_password("Wallet password: ").ok_or("no password given")?;
        tries += 1;
        match KeysFile::open(&blob, password.as_bytes(), kdf_rounds) {
            Err(KeysFileError::NotJson) if tries < 3 && term::interactive() => {
                println!("That password does not open this wallet.");
            }
            _ => return Ok(password),
        }
    }
}

/// Make a new wallet, from new keys or restored ones.
///
/// The questions come in the C++ order: what to restore from, the password,
/// the seed language, the restore height. Nothing is written until all of
/// them are answered.
fn create(paths: Paths, o: &Options) -> Result<Session, String> {
    // `Session::create` refuses too, but only after 25 words have been typed.
    if paths.keys().exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite a wallet",
            paths.keys().display()
        ));
    }

    let (account, seed_list) = build_account(o, session::now())?;

    let password = match &o.password {
        Some(p) => p.clone(),
        None => term::read_new_password().ok_or("no password given")?,
    };

    let keys = &account.keys;
    let has_seed = !keys.is_view_only() && keys.is_deterministic();
    let language = match seed_list {
        Some(list) => list,
        None if has_seed => seed_language(o)?,
        None => o
            .language
            .as_deref()
            .and_then(mnemonic::by_name)
            .unwrap_or_else(mnemonic::english),
    };

    let restore_height = match o.restore_height {
        Some(h) => h,
        None if o.source.restores() && term::interactive() => ask_restore_height()?,
        None => 0,
    };

    let session = Session::create(
        paths,
        o.network,
        password,
        o.kdf_rounds,
        account,
        language.name,
        restore_height,
    )?;
    println!("Created {}", session.location());
    println!("Address: {}", session.primary_address());

    // A new wallet's seed is the only copy of it. A seed in the old English
    // list is shown again in the list it will be written in from now on, as
    // the C++ does.
    let old_seed = o.source == Source::Seed && seed_list.is_none();
    if o.source == Source::GenerateNew || old_seed {
        match session.seed(language.name) {
            Ok(seed) => {
                println!();
                println!("Write this down. It is the only way to recover this wallet:");
                println!("  {seed}");
                println!();
            }
            Err(e) => println!("(no seed phrase: {e})"),
        }
    }
    Ok(session)
}

/// The keys, from wherever the options say to get them.
///
/// A typed seed also brings its language, which then decides the wallet's
/// rather than any option. The old English list is not one a seed is written
/// in any more, so it comes back as `None`.
fn build_account(
    o: &Options,
    created: u64,
) -> Result<(AccountBase, Option<&'static WordList>), String> {
    match o.source {
        Source::GenerateNew => {
            let mut rng = term::seeded_rng()?;
            let spend = SecretKey(rng.random_scalar());
            Ok((deterministic(spend, created)?, None))
        }
        Source::Seed => {
            let (spend, list) = seed_key(o)?;
            println!("Seed language: {}", list.name);
            let list = (list.language != Language::EnglishOld).then_some(list);
            Ok((deterministic(spend, created)?, list))
        }
        Source::SpendKey => {
            let spend = given_or_asked(o.spend_key.as_deref(), "Secret spend key: ", true, |s| {
                secret_from_hex(s, "spend key")
            })?;
            Ok((deterministic(spend, created)?, None))
        }
        Source::Keys => {
            let address = standard_address(o)?;
            let spend = given_or_asked(o.spend_key.as_deref(), "Secret spend key: ", true, |s| {
                key_for(s, "spend key", &address.keys.spend_public_key)
            })?;
            let view = given_or_asked(o.view_key.as_deref(), "Secret view key: ", true, |s| {
                key_for(s, "view key", &address.keys.view_public_key)
            })?;
            let account =
                AccountBase::from_keys(spend, view, created).ok_or("those keys are not valid")?;
            Ok((account, None))
        }
        Source::ViewKey => {
            let address = standard_address(o)?;
            let view = given_or_asked(o.view_key.as_deref(), "Secret view key: ", true, |s| {
                key_for(s, "view key", &address.keys.view_public_key)
            })?;
            let account = AccountBase::view_only(address.keys, view, created);
            account
                .keys
                .verify()
                .map_err(|e| format!("that view key does not match that address: {e}"))?;
            println!("(view-only: this wallet can watch but not spend)");
            Ok((account, None))
        }
        Source::Open => unreachable!("an existing wallet is opened, not built"),
    }
}

fn deterministic(spend: SecretKey, created: u64) -> Result<AccountBase, String> {
    AccountBase::from_spend_key(spend, created)
        .ok_or_else(|| "that spend key does not make a valid wallet".into())
}

/// The value of an option if it was given, and otherwise the answer to
/// `prompt`. An empty answer cancels.
///
/// A wrong option value is an error, not a question: the fix belongs in the
/// command that was typed.
fn given_or_asked<T>(
    given: Option<&str>,
    prompt: &str,
    hidden: bool,
    check: impl Fn(&str) -> Result<T, String>,
) -> Result<T, String> {
    match given {
        Some(s) => check(s.trim()),
        None => term::ask(prompt, hidden, |s| {
            if s.is_empty() {
                Ok(None)
            } else {
                check(s).map(Some)
            }
        }),
    }
}

/// The wallet's own address.
///
/// A subaddress's keys are derived from the wallet's rather than being them,
/// so no secret key can be checked against one. An integrated address carries
/// the wallet's keys and is accepted, as the C++ accepts it.
fn standard_address(o: &Options) -> Result<Address, String> {
    given_or_asked(o.address.as_deref(), "Standard address: ", false, |s| {
        let a = Address::decode_for(s, o.network)
            .map_err(|e| format!("that address is not valid: {e}"))?;
        if a.kind == AddressKind::Subaddress {
            return Err(
                "that is a subaddress; restoring needs the wallet's primary address".into(),
            );
        }
        Ok(a)
    })
}

/// A secret key, accepted only if it is the one behind `public`.
fn key_for(hex: &str, what: &str, public: &PublicKey) -> Result<SecretKey, String> {
    let key = secret_from_hex(hex, what)?;
    match wow_crypto::secret_key_to_public_key(&key) {
        Some(p) if p == *public => Ok(key),
        _ => Err(format!("that {what} does not belong to that address")),
    }
}

fn secret_from_hex(s: &str, what: &str) -> Result<SecretKey, String> {
    let bytes = wow_crypto::hex::decode(s).ok_or(format!("the {what} is not hex"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("the {what} is not 32 bytes"))?;
    if !wow_crypto::sc_check(&bytes) {
        return Err(format!("the {what} is not a valid scalar"));
    }
    Ok(SecretKey(bytes))
}

/// The key behind a seed and the seed's language, with the seed offset
/// passphrase taken off if there is one.
fn seed_key(o: &Options) -> Result<(SecretKey, &'static WordList), String> {
    let (key, list) = match &o.seed {
        Some(phrase) => mnemonic::words_to_key(phrase)
            .map_err(|e| format!("that seed phrase is not valid: {e}"))?,
        None => ask_seed()?,
    };

    // A seed passed as an option is only asked about at a terminal. A script
    // that put the seed on the command line may be piping in a password, and
    // reading that as a passphrase would restore a different wallet without a
    // word of complaint.
    if o.seed.is_some() && !term::interactive() {
        return Ok((key, list));
    }
    let passphrase =
        term::read_password("Enter seed offset passphrase, empty if none: ").unwrap_or_default();
    if passphrase.is_empty() {
        return Ok((key, list));
    }
    Ok((remove_seed_offset(&key, &passphrase), list))
}

/// Read a seed a line at a time until it has enough words, so a seed pasted
/// over two lines is not refused as a short one (`might_be_partial_seed`).
fn ask_seed() -> Result<(SecretKey, &'static WordList), String> {
    let mut phrase = String::new();
    loop {
        let prompt = if phrase.is_empty() {
            "Seed (25 words): "
        } else {
            "Seed, continued: "
        };
        let line = term::read_password(prompt).unwrap_or_default();
        if line.trim().is_empty() {
            return Err("no seed given; cancelled".into());
        }
        phrase.push_str(&line);
        phrase.push(' ');

        let words = phrase.split_whitespace().count();
        if words < mnemonic::SEED_DATA_WORDS {
            // Nothing was echoed, so say how far along it is.
            println!("({words} words so far)");
            continue;
        }
        match mnemonic::words_to_key(&phrase) {
            Ok(found) => return Ok(found),
            Err(e) if term::interactive() => {
                println!("that seed phrase is not valid: {e}; try again");
                phrase.clear();
            }
            Err(e) => return Err(format!("that seed phrase is not valid: {e}")),
        }
    }
}

/// `cryptonote::decrypt_key`: the key minus `cn_slow_hash(passphrase)`.
///
/// The C++ `encrypted_seed` command adds that hash before writing the words,
/// so the words alone restore a different, empty wallet.
fn remove_seed_offset(key: &SecretKey, passphrase: &str) -> SecretKey {
    let offset = wow_crypto::cn::slow_hash::cn_slow_hash(passphrase.as_bytes());
    SecretKey(wow_crypto::ops::sc_sub(&key.0, &offset))
}

/// `get_mnemonic_language`: `--mnemonic-language`, or chosen from the list at a
/// terminal, or English.
fn seed_language(o: &Options) -> Result<&'static WordList, String> {
    if let Some(name) = &o.language {
        return mnemonic::by_name(name).ok_or_else(|| format!("`{name}` is not a seed language"));
    }
    if !term::interactive() {
        return Ok(mnemonic::english());
    }

    // The C++ list's order, so the numbers are the ones its users know.
    use Language::*;
    const ORDER: [Language; 12] = [
        German,
        English,
        Spanish,
        French,
        Italian,
        Dutch,
        Portuguese,
        Russian,
        Japanese,
        ChineseSimplified,
        Esperanto,
        Lojban,
    ];
    let lists: Vec<&'static WordList> = ORDER.iter().map(|&l| mnemonic::by_language(l)).collect();
    // Each language's own name, and the English one beside it for a terminal
    // that cannot draw the first.
    let names: Vec<String> = lists
        .iter()
        .map(|l| {
            if l.name == l.english_name {
                l.name.to_string()
            } else {
                format!("{} ({})", l.name, l.english_name)
            }
        })
        .collect();
    println!("List of available languages for your wallet's seed:");
    let i = term::choose(
        "Enter the number corresponding to the language of your choice: ",
        &names,
    )?;
    Ok(lists[i])
}

fn ask_restore_height() -> Result<u64, String> {
    term::ask(
        "Restore from specific blockchain height (optional, default 0): ",
        false,
        |s| {
            if s.is_empty() {
                return Ok(Some(0));
            }
            s.parse()
                .map(Some)
                .map_err(|_| format!("`{s}` is not a block height"))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A key is accepted only for the address it belongs to, which is what
    /// stops a restore from writing a wallet that can see nothing.
    #[test]
    fn a_key_must_belong_to_the_address() {
        let spend = SecretKey(wow_crypto::ops::sc_reduce32(&[7u8; 32]));
        let account = AccountBase::from_spend_key(spend, 0).expect("keys");
        let address = account.keys.account_address;
        let hex = wow_crypto::hex::encode(&account.keys.spend_secret_key.0);

        assert!(key_for(&hex, "spend key", &address.spend_public_key).is_ok());
        let e = key_for(&hex, "spend key", &address.view_public_key).expect_err("the wrong key");
        assert!(e.contains("does not belong"), "{e}");
    }

    /// Taking the offset off undoes `cryptonote::encrypt_key`, which adds
    /// `cn_slow_hash(passphrase)` to the key.
    #[test]
    fn a_seed_offset_comes_off() {
        let key = SecretKey(wow_crypto::ops::sc_reduce32(&[9u8; 32]));
        let offset = wow_crypto::cn::slow_hash::cn_slow_hash(b"correct horse");
        let encrypted = SecretKey(wow_crypto::ops::sc_add(&key.0, &offset));

        assert_eq!(remove_seed_offset(&encrypted, "correct horse").0, key.0);
        assert_ne!(remove_seed_offset(&encrypted, "wrong horse").0, key.0);
    }
}
