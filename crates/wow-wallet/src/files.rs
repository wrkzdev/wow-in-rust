//! An open wallet: its files, its state, and its daemon.
//!
//! `specs/12` §2. A wallet is three files:
//!
//! ```text
//! <name>.keys          the keys and settings, shared with the C++ wallet
//! <name>.rscache       this implementation's cache
//! <name>.address.txt   the primary address, as text
//! ```
//!
//! # The cache is deliberately not the C++ one
//!
//! `specs/12` §2.2 says so: the C++ cache is a Boost portable binary archive,
//! and the instruction is to define our own format and rebuild from the chain
//! when a C++ cache is found. So this writes `<name>.rscache` — a different
//! name, so both implementations can hold the same wallet without either
//! corrupting the other's cache.
//!
//! The keys file **is** shared, and is read and written compatibly. That is
//! where the money is; a cache is a few minutes of rescanning.

use std::path::{Path, PathBuf};

use crate::refresh::{Transfer, WalletState};
use crate::subaddress::SubaddressTable;
use crate::{AccountBase, KeysFile};
use wow_daemon_client::DaemonClient;
use wow_types::Network;

/// A wallet's files.
#[derive(Clone, Debug)]
pub struct Paths {
    pub base: PathBuf,
}

impl Paths {
    pub fn new(base: impl Into<PathBuf>) -> Paths {
        Paths { base: base.into() }
    }

    pub fn keys(&self) -> PathBuf {
        let mut p = self.base.clone().into_os_string();
        p.push(".keys");
        PathBuf::from(p)
    }

    pub fn cache(&self) -> PathBuf {
        let mut p = self.base.clone().into_os_string();
        p.push(".rscache");
        PathBuf::from(p)
    }

    pub fn address_txt(&self) -> PathBuf {
        let mut p = self.base.clone().into_os_string();
        p.push(".address.txt");
        PathBuf::from(p)
    }

    /// The C++ cache, which this implementation does not read.
    pub fn cpp_cache(&self) -> PathBuf {
        self.base.clone()
    }
}

/// An open wallet.
pub struct Session {
    pub paths: Paths,
    pub keys_file: KeysFile,
    pub state: WalletState,
    pub network: Network,
    pub password: String,
    pub kdf_rounds: u64,
    pub daemon: Option<DaemonClient>,
    /// The daemon's height at the last refresh, for progress reporting.
    pub daemon_height: u64,
    /// Set when anything has changed since the last save.
    pub dirty: bool,
}

impl Session {
    /// Create a new wallet and write its files.
    pub fn create(
        paths: Paths,
        network: Network,
        password: String,
        kdf_rounds: u64,
        account: AccountBase,
        seed_language: &str,
        restore_height: u64,
    ) -> Result<Session, String> {
        if paths.keys().exists() {
            return Err(format!(
                "{} already exists; refusing to overwrite a wallet",
                paths.keys().display()
            ));
        }

        let mut keys_file = KeysFile::new(account, network, seed_language);
        keys_file.set_refresh_height(restore_height);

        let (major, minor) = keys_file.subaddress_lookahead();
        let subaddresses = SubaddressTable::new(
            &keys_file.account.keys.account_address,
            &keys_file.account.keys.view_secret_key,
            major,
            minor,
        );
        let state = WalletState::new(
            keys_file.account.clone(),
            subaddresses,
            restore_height,
            network,
        );

        let s = Session {
            paths,
            keys_file,
            state,
            network,
            password,
            kdf_rounds,
            daemon: None,
            daemon_height: 0,
            dirty: true,
        };
        s.save()?;
        s.write_address_file()?;
        Ok(s)
    }

    /// Open an existing wallet.
    pub fn open(
        paths: Paths,
        password: String,
        kdf_rounds: u64,
        network: Option<Network>,
    ) -> Result<Session, String> {
        let blob = std::fs::read(paths.keys())
            .map_err(|e| format!("cannot read {}: {e}", paths.keys().display()))?;
        let keys_file = KeysFile::open(&blob, password.as_bytes(), kdf_rounds)
            .map_err(|e| format!("cannot open the wallet: {e}"))?;

        // A wallet knows its own network. Opening a mainnet wallet as testnet
        // would print addresses under the wrong prefix, which look like someone
        // else's.
        let file_network = keys_file.network();
        if let Some(n) = network {
            if n != file_network {
                return Err(format!(
                    "this wallet is a {} wallet; it cannot be opened as {}",
                    file_network.name(),
                    n.name()
                ));
            }
        }

        let (major, minor) = keys_file.subaddress_lookahead();
        let subaddresses = SubaddressTable::new(
            &keys_file.account.keys.account_address,
            &keys_file.account.keys.view_secret_key,
            major,
            minor,
        );

        let mut state = WalletState::new(
            keys_file.account.clone(),
            subaddresses,
            keys_file.refresh_height(),
            // The wallet's own network, not the flag: the flag is optional and
            // has already been checked against this above.
            file_network,
        );

        // Load the cache if there is one; otherwise the wallet rescans.
        match std::fs::read(paths.cache()) {
            Ok(raw) => cache::load(&mut state, &raw)?,
            Err(_) if paths.cpp_cache().exists() => {
                println!(
                    "This wallet's cache was written by the C++ wallet, whose format is a Boost\n\
                     archive this implementation does not read. Rescanning from height {}.\n\
                     The C++ cache is left alone; this wallet writes {}.",
                    keys_file.refresh_height(),
                    paths.cache().display()
                );
            }
            Err(_) => {}
        }

        Ok(Session {
            paths,
            keys_file,
            state,
            network: file_network,
            password,
            kdf_rounds,
            daemon: None,
            daemon_height: 0,
            dirty: false,
        })
    }

    /// Write the keys file and the cache.
    pub fn save(&self) -> Result<(), String> {
        let mut rng = crate::entropy::seeded_rng()?;
        let iv = random_iv(&mut rng);
        let key_iv = random_iv(&mut rng);

        let blob = self
            .keys_file
            .to_blob(self.password.as_bytes(), self.kdf_rounds, iv, key_iv)
            .map_err(|e| format!("cannot serialize the wallet: {e}"))?;
        write_atomically(&self.paths.keys(), &blob)?;
        write_atomically(&self.paths.cache(), &cache::store(&self.state))?;
        Ok(())
    }

    fn write_address_file(&self) -> Result<(), String> {
        let text = format!("{}\n", self.primary_address());
        write_atomically(&self.paths.address_txt(), text.as_bytes())
    }

    pub fn primary_address(&self) -> String {
        wow_types::address::Address::standard(
            self.network,
            self.keys_file.account.keys.account_address,
        )
        .encode()
    }

    /// The address at `(major, minor)`.
    pub fn address_at(&self, major: u32, minor: u32) -> Option<String> {
        let index = wow_crypto::types::SubaddressIndex::new(major, minor);
        let keys = wow_crypto::get_subaddress(
            &self.keys_file.account.keys.account_address,
            &self.keys_file.account.keys.view_secret_key,
            index,
        )?;
        Some(if index.is_main() {
            wow_types::address::Address::standard(self.network, keys).encode()
        } else {
            wow_types::address::Address::subaddress(self.network, keys).encode()
        })
    }

    pub fn is_view_only(&self) -> bool {
        self.keys_file.is_watch_only()
    }

    /// The seed phrase, for a deterministic wallet.
    pub fn seed(&self, language: &str) -> Result<String, String> {
        let keys = &self.keys_file.account.keys;
        if keys.is_view_only() {
            return Err("a view-only wallet has no seed".into());
        }
        if !keys.is_deterministic() {
            return Err(
                "this wallet was restored from separate keys, so it is not deterministic and \
                 has no seed phrase (`specs/12` §1.2)"
                    .into(),
            );
        }
        let list = wow_crypto::mnemonic::by_name(language)
            .ok_or_else(|| format!("unknown seed language `{language}`"))?;
        Ok(wow_crypto::mnemonic::key_to_words(
            &keys.spend_secret_key,
            list,
        ))
    }

    /// Balance and unlocked balance, as a pair.
    pub fn balances(&self) -> (u64, u64) {
        let height = self.chain_height();
        let now = now();
        (
            self.state.balance(),
            self.state.unlocked_balance(height, now),
        )
    }

    /// Start a *brand-new* wallet at the daemon's current height.
    ///
    /// A wallet whose keys were generated a moment ago cannot own an output
    /// older than that, so scanning from genesis would read 873,000 blocks to
    /// find nothing. `wallet2::generate` does the same thing for the same
    /// reason, taking the height from the daemon at creation.
    ///
    /// **Only ever for freshly generated keys.** A wallet restored from a seed
    /// or from keys may well own old outputs, and starting it at the tip would
    /// silently hide them -- the balance would read zero and look correct.
    /// Callers must not reach for this on a restore.
    ///
    /// `height` is the daemon's *count* of blocks; scanning starts one below
    /// it, at the tip block itself. Two reasons, and either alone is enough:
    ///
    /// * `find_blockchain_supplement` refuses `req_start_block >= m_db->height()`
    ///   and answers `status: "Failed"`, so asking for the count is asking for
    ///   a block that does not exist yet;
    /// * scanning the tip gives the wallet a real block hash to anchor its
    ///   chain history on, which is what makes the next reorg detectable.
    ///
    /// Does nothing if the wallet has already scanned something, or if a
    /// restore height was chosen deliberately.
    pub fn start_at_tip(&mut self, height: u64) {
        // `scan_height() > 1` rather than a non-empty `hashes`: a wallet
        // starting at zero holds the genesis hash from the moment it is made,
        // so "has it scanned anything" is one block further along than
        // "does it know any hashes".
        if height == 0 || self.keys_file.refresh_height() != 0 || self.state.scan_height() > 1 {
            return;
        }
        let start = height - 1;
        self.keys_file.set_refresh_height(start);
        self.state.start_height = start;
        // The genesis anchor belongs to height zero and this wallet no longer
        // starts there. Leaving it would claim a hash for the wrong height.
        self.state.hashes.clear();
        self.dirty = true;
    }

    /// The height the wallet reckons the chain is at: the daemon's if known,
    /// otherwise how far it has scanned.
    pub fn chain_height(&self) -> u64 {
        self.daemon_height.max(self.state.scan_height())
    }

    pub fn describe_progress(&self) -> String {
        let scanned = self.state.scan_height();
        let target = self.chain_height();
        if target == 0 {
            "not synced with any daemon".into()
        } else if scanned >= target {
            format!("synced at height {scanned}")
        } else {
            format!(
                "height {scanned} / {target} ({:.1}%)",
                scanned as f64 * 100.0 / target as f64
            )
        }
    }

    /// The transfers, newest first.
    pub fn transfers(&self) -> &[Transfer] {
        &self.state.transfers
    }
}

fn random_iv(rng: &mut wow_crypto::random::Rng) -> [u8; 8] {
    let mut iv = [0u8; 8];
    rng.fill(&mut iv);
    iv
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write to a temporary file and rename over the target.
///
/// A keys file half-written is a wallet lost. The rename is atomic on both
/// platforms this builds for, so a crash leaves either the old file or the new
/// one.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".new");
    let tmp = PathBuf::from(tmp);

    std::fs::write(&tmp, bytes).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot replace {}: {e}", path.display())
    })
}

/// This implementation's cache format.
///
/// JSON, because the cache is not performance-critical — a refresh is bounded
/// by the daemon, not by parsing — and because a cache a user can read is a
/// cache a user can diagnose. `specs/12` §2.2 leaves the choice open.
pub mod cache {
    use super::*;
    use serde_json::{json, Value};

    const VERSION: u64 = 1;

    pub fn store(state: &WalletState) -> Vec<u8> {
        let transfers: Vec<Value> = state
            .transfers
            .iter()
            .map(|t| {
                json!({
                    "block_height": t.block_height,
                    "txid": wow_crypto::hex::encode(&t.txid),
                    "internal_output_index": t.internal_output_index,
                    "global_output_index": t.global_output_index,
                    "public_key": wow_crypto::hex::encode(&t.public_key.0),
                    "derivation": wow_crypto::hex::encode(&t.derivation.0),
                    "key_image": t.key_image.map(|k| wow_crypto::hex::encode(&k.0)),
                    "mask": wow_crypto::hex::encode(&t.mask),
                    "amount": t.amount,
                    "major": t.subaddress.major,
                    "minor": t.subaddress.minor,
                    "spent": t.spent,
                    "spent_height": t.spent_height,
                    "unlock_time": t.unlock_time,
                    "is_coinbase": t.is_coinbase,
                })
            })
            .collect();

        let hashes: Vec<String> = state
            .hashes
            .iter()
            .map(|h| wow_crypto::hex::encode(h))
            .collect();

        json!({
            "version": VERSION,
            "start_height": state.start_height,
            "hashes": hashes,
            "transfers": transfers,
        })
        .to_string()
        .into_bytes()
    }

    pub fn load(state: &mut WalletState, raw: &[u8]) -> Result<(), String> {
        let v: Value =
            serde_json::from_slice(raw).map_err(|e| format!("the cache is not readable: {e}"))?;

        // A cache from a future version is ignored rather than guessed at: a
        // rescan costs minutes, a misread cache costs correctness.
        if v.get("version").and_then(Value::as_u64) != Some(VERSION) {
            println!("The cache is from a different version; rescanning.");
            return Ok(());
        }

        state.start_height = v
            .get("start_height")
            .and_then(Value::as_u64)
            .unwrap_or(state.start_height);

        state.hashes = v
            .get("hashes")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|h| h.as_str())
                    .filter_map(wow_crypto::hex::decode)
                    .filter_map(|b| <[u8; 32]>::try_from(b).ok())
                    .collect()
            })
            .unwrap_or_default();

        state.transfers = v
            .get("transfers")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(transfer_from_json).collect())
            .unwrap_or_default();

        state.by_key_image = state
            .transfers
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.key_image.map(|k| (k, i)))
            .collect();
        Ok(())
    }

    fn transfer_from_json(v: &Value) -> Option<Transfer> {
        let bytes32 = |name: &str| -> Option<[u8; 32]> {
            <[u8; 32]>::try_from(wow_crypto::hex::decode(v.get(name)?.as_str()?)?).ok()
        };
        Some(Transfer {
            block_height: v.get("block_height")?.as_u64()?,
            txid: bytes32("txid")?,
            internal_output_index: v.get("internal_output_index")?.as_u64()?,
            global_output_index: v.get("global_output_index")?.as_u64()?,
            public_key: wow_crypto::types::PublicKey(bytes32("public_key")?),
            derivation: wow_crypto::types::KeyDerivation(bytes32("derivation")?),
            key_image: bytes32("key_image").map(wow_crypto::types::KeyImage),
            mask: bytes32("mask")?,
            amount: v.get("amount")?.as_u64()?,
            subaddress: wow_crypto::types::SubaddressIndex::new(
                v.get("major")?.as_u64()? as u32,
                v.get("minor")?.as_u64()? as u32,
            ),
            spent: v.get("spent")?.as_bool()?,
            spent_height: v.get("spent_height")?.as_u64()?,
            unlock_time: v.get("unlock_time")?.as_u64()?,
            is_coinbase: v.get("is_coinbase")?.as_bool()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_names_are_the_documented_ones() {
        let p = Paths::new("/tmp/mywallet");
        assert!(p.keys().to_string_lossy().ends_with("mywallet.keys"));
        assert!(p.address_txt().to_string_lossy().ends_with(".address.txt"));
        // Our cache, not the C++ one, so both can coexist (`specs/12` §2.2).
        assert!(p.cache().to_string_lossy().ends_with("mywallet.rscache"));
        assert_ne!(p.cache(), p.cpp_cache());
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("wow-files-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).expect("scratch");
        p
    }

    fn fresh_session(dir: &std::path::Path, restore_height: u64) -> Session {
        let spend = wow_crypto::types::SecretKey(wow_crypto::ops::sc_reduce32(&[1u8; 32]));
        let account = crate::account::AccountBase::from_spend_key(spend, 0).expect("keys");
        Session::create(
            Paths::new(dir.join("w")),
            Network::Mainnet,
            String::new(),
            1,
            account,
            "English",
            restore_height,
        )
        .expect("create")
    }

    /// A freshly generated wallet starts at the tip, because keys made a moment
    /// ago cannot own anything older -- and it starts at the tip *block*, one
    /// below the daemon's block count.
    ///
    /// Both halves matter. Without the first, a new wallet reads 873,000 blocks
    /// to find nothing. Without the second,
    /// `Blockchain::find_blockchain_supplement` refuses
    /// `req_start_block >= m_db->height()` and the refresh fails outright.
    #[test]
    fn a_new_wallet_starts_at_the_tip_block() {
        let dir = scratch("attip");
        let mut s = fresh_session(&dir, 0);
        assert_eq!(s.state.start_height, 0);

        s.start_at_tip(873_427);
        assert_eq!(
            s.state.start_height, 873_426,
            "the tip block, not the block count"
        );
        assert_eq!(s.keys_file.refresh_height(), 873_426);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A deliberately chosen restore height is never overridden.
    ///
    /// This is the guard that keeps a restored wallet's old funds visible: move
    /// its start to the tip and the balance reads zero, which looks exactly
    /// like a correct answer.
    #[test]
    fn a_chosen_restore_height_is_left_alone() {
        let dir = scratch("chosen");
        let mut s = fresh_session(&dir, 500_000);
        s.start_at_tip(873_427);
        assert_eq!(
            s.state.start_height, 500_000,
            "the wallet was told where to start"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A wallet that has already scanned is left alone too -- otherwise a
    /// second call would throw away everything it knows.
    #[test]
    fn a_wallet_that_has_scanned_is_left_alone() {
        let dir = scratch("scanned");
        let mut s = fresh_session(&dir, 0);
        s.state.hashes.push([7u8; 32]);
        s.start_at_tip(873_427);
        assert_eq!(s.state.start_height, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
