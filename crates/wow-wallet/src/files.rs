//! An open wallet: its state, its daemon, and where its files are kept.
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
//! corrupting the other's cache. It is sealed the way the C++ seals its own,
//! under the same key ([`cache::seal`]).
//!
//! The keys file **is** shared, and is read and written compatibly. That is
//! where the money is; a cache is a few minutes of rescanning.
//!
//! # Where they are kept
//!
//! In a [`Store`]: files on disk, or bytes a program keeps itself, as a browser
//! does. [`Session::create`] and [`Session::open`] take paths, and
//! [`Session::create_in`] and [`Session::open_in`] take any store.
//!
//! # One program at a time
//!
//! A wallet open from files holds a lock on its keys file ([`crate::lock`]), as
//! the C++ does. A second open, here or in the C++ wallet, is refused rather
//! than left to spend the same outputs and write over this one's files.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::history::{PooledTx, SentDestination, SentState, SentTx};
use crate::refresh::{Transfer, WalletState};
use crate::store::{CacheRead, FileStore, Store};
use crate::subaddress::SubaddressTable;
use crate::{AccountBase, KeysFile};
use wow_crypto::types::Hash256;
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
    pub keys_file: KeysFile,
    pub state: WalletState,
    pub network: Network,
    pub password: String,
    pub kdf_rounds: u64,
    pub daemon: Option<DaemonClient>,
    /// For a daemon started with `--rpc-login`. Kept on the session rather
    /// than on the client so that changing the node's address does not lose
    /// it, and never written to the wallet file: a node's password is not the
    /// wallet's to keep.
    pub daemon_login: Option<wow_daemon_client::digest::Credentials>,
    /// The daemon's height at the last refresh, for progress reporting.
    pub daemon_height: u64,
    /// Set when anything has changed since the last save.
    pub dirty: bool,
    /// Where the keys file and the cache are read from and written to.
    store: Box<dyn Store>,
    /// The key the cache is sealed under, derived from the password once
    /// rather than by a CryptoNight on every save.
    cache_key: crate::chacha::Key,
    /// The RingCT output distribution, so a second send does not fetch the
    /// whole of it again. Not saved with the wallet: it is the chain's, not
    /// this wallet's, and a node answers for the part that is missing.
    pub(crate) distribution: crate::decoys::DistributionCache,
}

impl Session {
    /// Create a new wallet as files at `paths`, and write them.
    pub fn create(
        paths: Paths,
        network: Network,
        password: String,
        kdf_rounds: u64,
        account: AccountBase,
        seed_language: &str,
        restore_height: u64,
    ) -> Result<Session, String> {
        Session::create_in(
            Box::new(FileStore::new(paths)),
            network,
            password,
            kdf_rounds,
            account,
            seed_language,
            restore_height,
        )
    }

    /// Create a new wallet in `store`, and write it there.
    pub fn create_in(
        store: Box<dyn Store>,
        network: Network,
        password: String,
        kdf_rounds: u64,
        account: AccountBase,
        seed_language: &str,
        restore_height: u64,
    ) -> Result<Session, String> {
        if store.exists() {
            return Err(format!(
                "{} already exists; refusing to overwrite a wallet",
                store.location()
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
        let cache_key = KeysFile::cache_key(password.as_bytes(), kdf_rounds);

        let mut s = Session {
            keys_file,
            state,
            network,
            password,
            kdf_rounds,
            daemon: None,
            daemon_login: None,
            daemon_height: 0,
            dirty: true,
            store,
            cache_key,
            distribution: Default::default(),
        };
        s.save()?;
        let address = s.primary_address();
        s.store.write_address(&address)?;
        Ok(s)
    }

    /// Open an existing wallet from files at `paths`.
    pub fn open(
        paths: Paths,
        password: String,
        kdf_rounds: u64,
        network: Option<Network>,
    ) -> Result<Session, String> {
        Session::open_in(
            Box::new(FileStore::new(paths)),
            password,
            kdf_rounds,
            network,
        )
    }

    /// Open the wallet in `store`.
    pub fn open_in(
        mut store: Box<dyn Store>,
        password: String,
        kdf_rounds: u64,
        network: Option<Network>,
    ) -> Result<Session, String> {
        let blob = store.open_keys()?;
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
        let cache_key = KeysFile::cache_key(password.as_bytes(), kdf_rounds);
        match store.read_cache()? {
            CacheRead::Found(raw) => cache::load_sealed(&mut state, &raw, &cache_key)?,
            CacheRead::WrittenByCpp { ours } => {
                println!(
                    "This wallet's cache was written by the C++ wallet, whose format is a Boost\n\
                     archive this implementation does not read. Rescanning from height {}.\n\
                     The C++ cache is left alone; this wallet writes {ours}.",
                    keys_file.refresh_height()
                );
            }
            CacheRead::Missing => {}
        }

        Ok(Session {
            keys_file,
            state,
            network: file_network,
            password,
            kdf_rounds,
            daemon: None,
            daemon_login: None,
            daemon_height: 0,
            dirty: false,
            store,
            cache_key,
            distribution: Default::default(),
        })
    }

    /// Write the keys file and the sealed cache.
    pub fn save(&mut self) -> Result<(), String> {
        let mut rng = crate::entropy::seeded_rng()?;
        let iv = random_iv(&mut rng);
        let key_iv = random_iv(&mut rng);
        let cache_iv = random_iv(&mut rng);

        let blob = self
            .keys_file
            .to_blob(self.password.as_bytes(), self.kdf_rounds, iv, key_iv)
            .map_err(|e| format!("cannot serialize the wallet: {e}"))?;
        self.store.write_keys(&blob)?;
        let sealed = cache::seal(&cache::store(&self.state), &self.cache_key, cache_iv);
        self.store.write_cache(&sealed)?;
        Ok(())
    }

    /// Where the wallet is kept: its keys file's path, or the name its store
    /// was given.
    pub fn location(&self) -> String {
        self.store.location()
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

    /// Keep the wallet under a new password from now on: the keys file and
    /// the cache are written again under it at once, as `change_password`
    /// does.
    ///
    /// The two are written one after the other, so if the second fails the
    /// first is put back under the old password: keys and cache under
    /// different passwords would leave a wallet that does not open.
    pub fn change_password(&mut self, new: String) -> Result<(), String> {
        let mut rng = crate::entropy::seeded_rng()?;
        let serialize = |password: &str, rng: &mut wow_crypto::random::Rng| {
            self.keys_file
                .to_blob(
                    password.as_bytes(),
                    self.kdf_rounds,
                    random_iv(rng),
                    random_iv(rng),
                )
                .map_err(|e| format!("cannot serialize the wallet: {e}"))
        };
        let keys = serialize(&new, &mut rng)?;
        let old_keys = serialize(&self.password, &mut rng)?;
        let cache_key = KeysFile::cache_key(new.as_bytes(), self.kdf_rounds);
        let sealed = cache::seal(&cache::store(&self.state), &cache_key, random_iv(&mut rng));

        self.store.write_keys(&keys)?;
        if let Err(e) = self.store.write_cache(&sealed) {
            return Err(match self.store.write_keys(&old_keys) {
                Ok(()) => format!("the password was not changed: {e}"),
                Err(again) => format!(
                    "the keys file is under the new password but the cache could not be \
                     written ({e}), and the keys file could not be put back ({again}); open \
                     the wallet with the new password, and it will scan again"
                ),
            });
        }
        self.password = new;
        self.cache_key = cache_key;
        self.dirty = false;
        Ok(())
    }

    /// This wallet as a view-only keys file under `password`: the address and
    /// the view key, and no spend key, so a copy of it sees what is paid in
    /// and can spend nothing. The rest of its settings come with it: the
    /// network and the restore height.
    pub fn view_only_keys(&self, password: &str) -> Result<Vec<u8>, String> {
        let mut account = self.keys_file.account.clone();
        account.forget_spend_key();
        let mut keys_file = KeysFile {
            account,
            settings: self.keys_file.settings.clone(),
        };
        keys_file
            .settings
            .insert("watch_only".into(), serde_json::Value::from(1u64));
        let mut rng = crate::entropy::seeded_rng()?;
        let (iv, key_iv) = (random_iv(&mut rng), random_iv(&mut rng));
        keys_file
            .to_blob(password.as_bytes(), self.kdf_rounds, iv, key_iv)
            .map_err(|e| format!("cannot serialize the view-only wallet: {e}"))
    }

    /// The secret view key, in hex: what lets its holder see every payment to
    /// this wallet, and spend none of it.
    pub fn view_key_hex(&self) -> String {
        wow_crypto::hex::encode(&self.keys_file.account.keys.view_secret_key.0)
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
        self.state.refresh_from_height = start;
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

    /// A client for `address`, carrying this session's daemon login if it has
    /// one.
    ///
    /// Every place that points a wallet at a node goes through here, so a
    /// login survives `set_daemon` and is not something each front end has to
    /// remember to apply.
    pub fn client_for(&self, address: &str) -> DaemonClient {
        let mut endpoint = wow_daemon_client::Endpoint::new(address);
        if let Some(c) = &self.daemon_login {
            endpoint = endpoint.with_login(c.clone());
        }
        DaemonClient::with_endpoint(endpoint)
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

    /// Read the daemon's pool: take note of spends of this wallet's outputs
    /// that were not sent from here ([`WalletState::note_pool_spends`]), then
    /// judge every transaction not yet in a block by it
    /// ([`WalletState::update_pending`]).
    ///
    /// Only once a refresh has caught up; `update_pending` says why.
    ///
    /// Always, whatever the wallet holds: a view-only wallet and an empty one
    /// included. `wallet2::refresh` reads the pool on every refresh. A wallet
    /// that only started asking once it owned a key image told the daemon,
    /// by the first request, which block had just paid it.
    pub fn check_pending(&mut self) -> Result<PoolCheck, String> {
        let pool = self.read_pool()?;
        let ids: HashSet<Hash256> = pool.iter().map(|p| p.txid).collect();
        let noted = self.state.note_pool_spends(&pool, now());
        let failed = self.state.update_pending(&ids, now());
        self.dirty = true;
        Ok(PoolCheck { noted, failed })
    }

    /// The first half of [`check_pending`](Self::check_pending), which needs
    /// no refresh first because it can only spend outputs, never give them
    /// back. For just before sending, and just after a send is refused as a
    /// double spend.
    pub fn note_pool_spends(&mut self) -> Result<Vec<Hash256>, String> {
        if self.state.by_key_image.is_empty() {
            return Ok(Vec::new());
        }
        let pool = self.read_pool()?;
        let noted = self.state.note_pool_spends(&pool, now());
        if !noted.is_empty() {
            self.dirty = true;
        }
        Ok(noted)
    }

    /// The daemon's pool, parsed. A transaction whose blob does not parse is
    /// left out rather than failing the rest.
    fn read_pool(&self) -> Result<Vec<PooledTx>, String> {
        let daemon = self.daemon.as_ref().ok_or("no daemon set")?;
        let listed = daemon
            .get_transaction_pool()
            .map_err(|e| format!("cannot read the daemon's pool: {e}"))?;
        Ok(listed
            .into_iter()
            .filter_map(|p| {
                let tx = wow_types::tx::Transaction::from_blob(&p.blob).ok()?;
                // The id from the blob, not the daemon's word for it: it has to
                // match what a block or a send from here would call it.
                let txid = wow_types::hashes::transaction_hash_from_blob(&tx, &p.blob)?;
                Some(PooledTx {
                    txid,
                    tx,
                    receive_time: p.receive_time,
                })
            })
            .collect())
    }
}

/// What [`Session::check_pending`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolCheck {
    /// Transactions in the pool spending this wallet's outputs, not sent from
    /// here, recorded just now.
    pub noted: Vec<Hash256>,
    /// Sent transactions in neither a block nor the pool past the timeout,
    /// judged failed just now.
    pub failed: Vec<Hash256>,
}

fn random_iv(rng: &mut wow_crypto::random::Rng) -> [u8; 8] {
    let mut iv = [0u8; 8];
    rng.fill(&mut iv);
    iv
}

/// The time now, in seconds since 1970 ([`crate::clock`]).
pub fn now() -> u64 {
    crate::clock::now()
}

/// This implementation's cache format.
///
/// JSON inside, because the cache is not performance-critical — a refresh is
/// bounded by the daemon, not by parsing — and because a cache that decrypts to
/// text is one a user can diagnose. `specs/12` §2.2 leaves the choice open.
/// Sealed outside, as the C++ seals its own ([`seal`]).
pub mod cache {
    use super::*;
    use crate::chacha::{self, Iv, Key};
    use serde_json::{json, Value};
    use wow_serialize::binary::{Reader, Writer};

    const VERSION: u64 = 1;

    /// A sealed cache cannot plausibly exceed this. It is here so that a
    /// corrupt length is an error, not an allocation.
    const MAX_SEALED: usize = 1 << 30;

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
                    "timestamp": t.timestamp,
                    "payment_id": t.payment_id.map(|p| wow_crypto::hex::encode(&p)),
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
            "refresh_from_height": state.refresh_from_height,
            "hashes": hashes,
            "transfers": transfers,
            "sent": state.sent.iter().map(sent_to_json).collect::<Vec<_>>(),
        })
        .to_string()
        .into_bytes()
    }

    /// Seal a cache for writing: `cache_file_data { iv, cache_data }`, framed
    /// as the C++ frames its own (`specs/12` §2.2), ChaCha20 under the wallet's
    /// cache key.
    ///
    /// The cache holds every output's amount, mask and key image, and every
    /// payee when `store-tx-info` is on. Nothing in it spends, but it is the
    /// wallet's whole history.
    pub fn seal(plaintext: &[u8], key: &Key, iv: Iv) -> Vec<u8> {
        let ciphertext = chacha::chacha20(plaintext, key, &iv);
        let mut w = Writer::with_capacity(ciphertext.len() + 16);
        w.write_bytes(&iv);
        w.write_bytes_prefixed(&ciphertext);
        w.into_vec()
    }

    /// Load a cache as a store holds it: sealed, or in the clear as a build
    /// from before the cache was sealed wrote it, which the next save seals.
    ///
    /// Taken as sealed only when the container accounts for every byte and
    /// what it decrypts to parses, so a cache in the clear is never mistaken
    /// for one.
    pub fn load_sealed(state: &mut WalletState, raw: &[u8], key: &Key) -> Result<(), String> {
        if let Some((iv, ciphertext)) = container(raw) {
            let plaintext = chacha::chacha20(ciphertext, key, &iv);
            if let Ok(v) = serde_json::from_slice::<Value>(&plaintext) {
                return load_value(state, v);
            }
        }
        let v: Value = serde_json::from_slice(raw)
            .map_err(|_| "the cache does not decrypt under this wallet's key".to_string())?;
        load_value(state, v)
    }

    /// `cache_file_data`, when `raw` is one and nothing more.
    fn container(raw: &[u8]) -> Option<(Iv, &[u8])> {
        let mut r = Reader::new(raw);
        let iv: Iv = r.read_array().ok()?;
        let data = r.read_bytes_prefixed(MAX_SEALED, "cache").ok()?;
        r.is_empty().then_some((iv, data))
    }

    /// Load a cache in the clear.
    pub fn load(state: &mut WalletState, raw: &[u8]) -> Result<(), String> {
        let v: Value =
            serde_json::from_slice(raw).map_err(|e| format!("the cache is not readable: {e}"))?;
        load_value(state, v)
    }

    fn load_value(state: &mut WalletState, v: Value) -> Result<(), String> {
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
        // Added without a version bump: a cache from before has hashes from
        // where scanning started, and the restore height stands for it.
        state.refresh_from_height = v
            .get("refresh_from_height")
            .and_then(Value::as_u64)
            .unwrap_or(state.refresh_from_height);

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

        // Added without a version bump: a cache from before simply has no
        // record of anything sent, and bumping would throw its transfers away.
        state.sent = v
            .get("sent")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(sent_from_json).collect())
            .unwrap_or_default();

        state.reindex();
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
            timestamp: v.get("timestamp").and_then(Value::as_u64).unwrap_or(0),
            // Absent from a cache written before it was kept; a rescan reads it.
            payment_id: v
                .get("payment_id")
                .and_then(Value::as_str)
                .and_then(wow_crypto::hex::decode)
                .and_then(|b| b.try_into().ok()),
        })
    }

    fn sent_to_json(s: &SentTx) -> Value {
        json!({
            "txid": wow_crypto::hex::encode(&s.txid),
            "state": match s.state {
                SentState::Pending => "pending",
                SentState::Failed => "failed",
                SentState::Confirmed(_) => "confirmed",
            },
            "height": s.height(),
            "amount_in": s.amount_in,
            "amount_out": s.amount_out,
            "change": s.change,
            "destinations": s
                .destinations
                .iter()
                .map(|d| json!({ "address": d.address, "amount": d.amount }))
                .collect::<Vec<_>>(),
            "payment_id": s.payment_id.map(|p| wow_crypto::hex::encode(&p)),
            "timestamp": s.timestamp,
            "sent_time": s.sent_time,
            "unlock_time": s.unlock_time,
            "account": s.account,
            "minors": s.minors,
            "key_images": s
                .key_images
                .iter()
                .map(|k| wow_crypto::hex::encode(&k.0))
                .collect::<Vec<_>>(),
        })
    }

    fn sent_from_json(v: &Value) -> Option<SentTx> {
        let bytes32 = |s: &Value| <[u8; 32]>::try_from(wow_crypto::hex::decode(s.as_str()?)?).ok();
        let number = |name: &str| v.get(name).and_then(Value::as_u64);
        let state = match v.get("state")?.as_str()? {
            "pending" => SentState::Pending,
            "failed" => SentState::Failed,
            "confirmed" => SentState::Confirmed(number("height")?),
            _ => return None,
        };
        Some(SentTx {
            txid: bytes32(v.get("txid")?)?,
            state,
            amount_in: number("amount_in")?,
            amount_out: number("amount_out")?,
            change: number("change")?,
            destinations: v
                .get("destinations")?
                .as_array()?
                .iter()
                .map(|d| {
                    Some(SentDestination {
                        address: d.get("address")?.as_str()?.to_string(),
                        amount: d.get("amount")?.as_u64()?,
                    })
                })
                .collect::<Option<_>>()?,
            payment_id: v
                .get("payment_id")
                .and_then(Value::as_str)
                .and_then(wow_crypto::hex::decode)
                .and_then(|b| b.try_into().ok()),
            timestamp: number("timestamp")?,
            sent_time: number("sent_time")?,
            unlock_time: number("unlock_time")?,
            account: number("account")? as u32,
            minors: v
                .get("minors")?
                .as_array()?
                .iter()
                .map(|m| m.as_u64().map(|m| m as u32))
                .collect::<Option<_>>()?,
            key_images: v
                .get("key_images")?
                .as_array()?
                .iter()
                .map(|k| bytes32(k).map(wow_crypto::types::KeyImage))
                .collect::<Option<_>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

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
        assert_eq!(s.state.refresh_from_height, 873_426, "and scanning starts there");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Where scanning starts survives the cache apart from where the hashes
    /// begin, and a cache from before it was kept takes the restore height.
    #[test]
    fn where_scanning_starts_survives_the_cache() {
        let dir = scratch("refresh-from");
        let mut s = fresh_session(&dir, 0);
        s.state.start_height = 838_800;
        s.state.refresh_from_height = 850_000;
        s.state.hashes.push([7u8; 32]);
        let raw = cache::store(&s.state);

        let fresh = || {
            let keys = &s.keys_file.account.keys;
            let table = SubaddressTable::new(&keys.account_address, &keys.view_secret_key, 1, 1);
            WalletState::new(s.keys_file.account.clone(), table, 42, Network::Mainnet)
        };
        let mut back = fresh();
        cache::load(&mut back, &raw).expect("loads");
        assert_eq!(back.start_height, 838_800);
        assert_eq!(back.refresh_from_height, 850_000);

        let mut older: serde_json::Value = serde_json::from_slice(&raw).expect("json");
        older
            .as_object_mut()
            .expect("an object")
            .remove("refresh_from_height");
        let mut old = fresh();
        cache::load(&mut old, older.to_string().as_bytes()).expect("loads");
        assert_eq!(old.refresh_from_height, 42, "the restore height");

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

    /// A record of what was sent survives the cache. The chain cannot say where
    /// a transaction went, so a record lost on reopening is lost for good.
    #[test]
    fn a_sent_record_survives_the_cache() {
        let dir = scratch("sent");
        let mut s = fresh_session(&dir, 0);
        s.state.sent.push(SentTx {
            txid: [4u8; 32],
            state: SentState::Confirmed(12),
            amount_in: 10_000,
            amount_out: 9_500,
            change: 2_500,
            destinations: vec![SentDestination {
                address: "Wo1payee".into(),
                amount: 7_000,
            }],
            payment_id: Some([3u8; 8]),
            timestamp: 1_700_000_100,
            sent_time: 1_700_000_000,
            unlock_time: 0,
            account: 0,
            minors: vec![0, 2],
            key_images: vec![wow_crypto::types::KeyImage([9u8; 32])],
        });
        let raw = cache::store(&s.state);

        let keys = &s.keys_file.account.keys;
        let table = SubaddressTable::new(&keys.account_address, &keys.view_secret_key, 1, 1);
        let mut back = WalletState::new(s.keys_file.account.clone(), table, 0, Network::Mainnet);
        cache::load(&mut back, &raw).expect("loads");
        assert_eq!(back.sent, s.state.sent);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An output's payment id survives the cache, and an output from a cache
    /// written before it was kept reads back with none.
    #[test]
    fn a_payment_id_survives_the_cache() {
        let dir = scratch("payment-id");
        let mut s = fresh_session(&dir, 0);
        s.state.transfers.push(Transfer {
            block_height: 12,
            txid: [4u8; 32],
            internal_output_index: 0,
            global_output_index: 30,
            public_key: wow_crypto::types::PublicKey([5u8; 32]),
            derivation: wow_crypto::types::KeyDerivation([6u8; 32]),
            key_image: Some(wow_crypto::types::KeyImage([7u8; 32])),
            mask: [8u8; 32],
            amount: 5_000,
            subaddress: wow_crypto::types::SubaddressIndex::MAIN,
            spent: false,
            spent_height: 0,
            unlock_time: 0,
            is_coinbase: false,
            timestamp: 1_700_000_000,
            payment_id: Some([0xf9, 0x33, 0x77, 0x88, 0xdd, 0x75, 0x25, 0x55]),
        });
        let raw = cache::store(&s.state);

        let fresh = || {
            let keys = &s.keys_file.account.keys;
            let table = SubaddressTable::new(&keys.account_address, &keys.view_secret_key, 1, 1);
            WalletState::new(s.keys_file.account.clone(), table, 0, Network::Mainnet)
        };

        let mut back = fresh();
        cache::load(&mut back, &raw).expect("loads");
        assert_eq!(back.transfers, s.state.transfers);

        let mut older: serde_json::Value = serde_json::from_slice(&raw).expect("json");
        older["transfers"][0]
            .as_object_mut()
            .expect("an object")
            .remove("payment_id");
        let mut old = fresh();
        cache::load(&mut old, older.to_string().as_bytes()).expect("loads");
        assert_eq!(old.transfers.len(), 1, "the output is kept");
        assert_eq!(old.transfers[0].payment_id, None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The cache is sealed: none of its JSON shows in the sealed bytes, it
    /// opens under the wallet's key and not another, and a cache an earlier
    /// build wrote in the clear still opens.
    #[test]
    fn the_cache_is_sealed_and_an_old_clear_one_still_opens() {
        let dir = scratch("sealed");
        let mut s = fresh_session(&dir, 0);
        s.state.hashes.push([7u8; 32]);
        let clear = cache::store(&s.state);
        let key = KeysFile::cache_key(b"", 1);
        let sealed = cache::seal(&clear, &key, [9; 8]);
        assert!(!sealed.windows(6).any(|w| w == b"hashes"), "sealed");

        let fresh = || {
            let keys = &s.keys_file.account.keys;
            let table = SubaddressTable::new(&keys.account_address, &keys.view_secret_key, 1, 1);
            WalletState::new(s.keys_file.account.clone(), table, 0, Network::Mainnet)
        };

        let mut back = fresh();
        cache::load_sealed(&mut back, &sealed, &key).expect("opens");
        assert_eq!(back.hashes, s.state.hashes);

        let other = KeysFile::cache_key(b"another password", 1);
        assert!(cache::load_sealed(&mut fresh(), &sealed, &other).is_err());

        let mut old = fresh();
        cache::load_sealed(&mut old, &clear, &key).expect("in the clear");
        assert_eq!(old.hashes, s.state.hashes);

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

    /// An open wallet holds its keys file: a second open is refused while the
    /// first is open, a save keeps it held, and closing lets it go.
    #[cfg(any(unix, windows))]
    #[test]
    fn an_open_wallet_is_held() {
        let dir = scratch("held");
        let mut s = fresh_session(&dir, 0);
        let reopen = || Session::open(Paths::new(dir.join("w")), String::new(), 1, None);

        match reopen() {
            Ok(_) => panic!("opened a wallet that is already open"),
            Err(e) => assert!(e.contains("another wallet program"), "{e}"),
        }

        s.save().expect("save");
        assert!(reopen().is_err(), "still held after a save");

        drop(s);
        reopen().expect("free once the first is closed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A new password opens the wallet and the old one no longer does, and the
    /// cache comes back under the new one.
    #[test]
    fn a_changed_password_opens_the_wallet_and_the_old_one_does_not() {
        let spend = wow_crypto::types::SecretKey(wow_crypto::ops::sc_reduce32(&[3u8; 32]));
        let account = crate::account::AccountBase::from_spend_key(spend, 0).expect("keys");
        let kept = MemoryStore::new("browser");
        let mut s = Session::create_in(
            Box::new(kept.clone()),
            Network::Mainnet,
            "old".into(),
            1,
            account,
            "English",
            5,
        )
        .expect("create");
        s.state.hashes.push([9u8; 32]);
        s.change_password("new".into()).expect("changed");
        assert_eq!(s.password, "new");

        let files = kept.files();
        let open = |password: &str| {
            let store = MemoryStore::holding(
                "browser",
                files.keys.clone().expect("a keys file"),
                files.cache.clone(),
            );
            Session::open_in(Box::new(store), password.into(), 1, None)
        };
        assert!(open("old").is_err(), "the old password no longer opens it");
        let back = open("new").expect("the new one does");
        assert_eq!(back.primary_address(), s.primary_address());
        assert_eq!(
            back.state.hashes, s.state.hashes,
            "and the cache came with it"
        );
    }

    /// A view-only copy has the wallet's address and view key and no spend
    /// key: it opens as view-only, with no seed phrase to show.
    #[test]
    fn a_view_only_copy_watches_and_cannot_spend() {
        let dir = scratch("viewonly");
        let s = fresh_session(&dir, 42);
        let blob = s.view_only_keys("watch").expect("a view-only keys file");
        let copy = Session::open_in(
            Box::new(MemoryStore::holding("copy", blob, None)),
            "watch".into(),
            1,
            None,
        )
        .expect("it opens");
        assert!(copy.is_view_only());
        assert!(!s.is_view_only());
        assert_eq!(copy.primary_address(), s.primary_address());
        assert_eq!(copy.keys_file.refresh_height(), 42);
        assert_eq!(copy.view_key_hex(), s.view_key_hex());
        assert!(copy.seed("English").is_err(), "no seed without a spend key");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A wallet kept in memory, as a browser keeps one, opens again from the
    /// bytes it saved, and no second wallet is created over it.
    #[test]
    fn a_wallet_in_memory_opens_from_what_it_saved() {
        let spend = wow_crypto::types::SecretKey(wow_crypto::ops::sc_reduce32(&[2u8; 32]));
        let account = crate::account::AccountBase::from_spend_key(spend, 0).expect("keys");
        let kept = MemoryStore::new("browser");

        let mut s = Session::create_in(
            Box::new(kept.clone()),
            Network::Mainnet,
            "pw".into(),
            1,
            account.clone(),
            "English",
            5,
        )
        .expect("create");
        s.state.hashes.push([7u8; 32]);
        s.save().expect("save");

        let files = kept.files();
        assert_eq!(files.address, Some(s.primary_address()));
        let sealed = files.cache.clone().expect("a cache");
        assert!(!sealed.windows(6).any(|w| w == b"hashes"), "sealed");

        let keys = files.keys.expect("a keys file");
        let reopened = MemoryStore::holding("browser", keys, files.cache);
        let back = Session::open_in(Box::new(reopened), "pw".into(), 1, None).expect("open");
        assert_eq!(back.primary_address(), s.primary_address());
        assert_eq!(back.state.hashes, s.state.hashes, "the cache came back");
        assert_eq!(back.location(), "browser");

        let over = Session::create_in(
            Box::new(kept),
            Network::Mainnet,
            "pw".into(),
            1,
            account,
            "English",
            0,
        );
        assert!(over.is_err(), "not written over");
    }
}
