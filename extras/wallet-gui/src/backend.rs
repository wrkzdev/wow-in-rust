//! The wallet side: it holds the open wallet, talks to the node, and answers
//! the interface's commands.
//!
//! Synchronous throughout, because the wallet library is, so it runs where
//! blocking is allowed: a thread of its own on the desktop, a web worker in a
//! browser. Syncing comes in steps ([`Backend::tick`]), one batch of blocks
//! each, so a command never waits long behind it.
//!
//! What differs between the two is a [`Platform`]: where wallets are kept, and
//! how a node is reached.

use wow_crypto::mnemonic::{self, Language};
use wow_crypto::types::SecretKey;
use wow_daemon_client::{DaemonClient, Info};
use wow_wallet::files::Session;
use wow_wallet::send::SendRequest;
use wow_wallet::store::Store;
use wow_wallet::{AccountBase, EntryKind, RefreshEvent};

use crate::format;
use crate::nodes::NodeAddress;
use crate::protocol::{
    Bytes, Command, Event, Link, Net, NewWallet, NodeReport, OpenWallet, Preview, Restore, Row,
    SendForm, Status, Summary,
};

/// How often a synced wallet looks for new blocks and checks the pool.
const SYNC_INTERVAL_SECS: u64 = 30;

/// Batches of blocks between saves during a long sync, so a crash or a closed
/// tab loses little of it.
const SAVE_EVERY_BATCHES: u32 = 20;

/// wallet-cli's `--kdf-rounds` default, and the C++ one.
const KDF_ROUNDS: u64 = 1;

/// The most history rows sent at once, newest first.
const HISTORY_ROWS: usize = 1_000;

const NO_WALLET: &str = "no wallet is open";

/// What the desktop and the browser do differently.
pub trait Platform {
    /// The names of the wallets kept.
    fn list(&self) -> Result<Vec<String>, String>;
    /// Where they are kept, for people to read.
    fn location(&self) -> String;
    fn exists(&self, name: &str) -> bool;
    /// Where the wallet named `name` is read from and written to, whether it
    /// exists yet or not.
    fn store(&mut self, name: &str) -> Result<Box<dyn Store>, String>;
    /// The wallet named `name` has just been written: keep it, if its store
    /// does not already.
    fn saved(&mut self, name: &str);
    fn import(&mut self, name: &str, keys: Vec<u8>, cache: Option<Vec<u8>>) -> Result<(), String>;
    fn export(&mut self, name: &str) -> Result<(Vec<u8>, Option<Vec<u8>>), String>;
    fn forget(&mut self, name: &str) -> Result<(), String>;
    fn set_folder(&mut self, path: &str) -> Result<(), String>;
    fn in_browser(&self) -> bool;
    /// Whether a browser loaded the wallet over https.
    fn secure_page(&self) -> bool;
    /// A client for `node`. `any_certificate` accepts the node's TLS
    /// certificate whoever signed it, where the platform decides that.
    /// `login` is for a node started with `--rpc-login`, and `proxy` what to
    /// reach it through, where the platform can use them.
    fn connect(
        &self,
        node: &NodeAddress,
        any_certificate: bool,
        login: Option<&wow_daemon_client::digest::Credentials>,
        proxy: Option<&wow_daemon_client::Proxy>,
    ) -> DaemonClient;
    /// A clock for timing a node's answer, in milliseconds from any start.
    fn millis(&self) -> f64;
    /// Where the log is written, when it is written to a file; `None` where
    /// there are no files.
    fn log_file(&self) -> Option<std::path::PathBuf>;
}

/// The open wallet and what is known about it.
struct Open {
    name: String,
    session: Session,
    prepared: Option<wow_wallet::send::PreparedSend>,
    node_error: Option<String>,
    syncing: bool,
    /// When a sync last caught up or failed, in seconds since 1970.
    last_sync: u64,
    /// Batches synced since the last save.
    batches: u32,
    /// Keys made moments ago, not yet moved to start at the chain's tip.
    fresh: bool,
}

pub struct Backend<P: Platform> {
    platform: P,
    emit: Box<dyn FnMut(Event)>,
    wallet: Option<Open>,
    /// Whether the command being handled said it was working.
    working: bool,
    /// [`Command::AcceptAnyCertificate`]: the nodes, as `host:port`, whose
    /// certificate is accepted as it is, from the next connection.
    any_certificate: Vec<String>,
    /// [`Command::SetNodeLogin`], for a node started with `--rpc-login`. In
    /// memory only, and never written with the settings.
    node_login: Option<wow_daemon_client::digest::Credentials>,
    /// [`Command::SetProxy`], with a login of this run's own.
    proxy: Option<wow_daemon_client::Proxy>,
}

impl<P: Platform> Backend<P> {
    pub fn new(platform: P, emit: impl FnMut(Event) + 'static) -> Self {
        Backend {
            platform,
            emit: Box::new(emit),
            wallet: None,
            working: false,
            any_certificate: Vec::new(),
            node_login: None,
            proxy: None,
        }
    }

    /// Say it is listening, and which wallets it holds.
    pub fn start(&mut self) {
        self.send(Event::Ready);
        self.send_wallets();
    }

    /// Report a failure that came from outside a command.
    pub fn error(&mut self, message: impl Into<String>) {
        self.send(Event::Error(message.into()));
    }

    pub fn handle(&mut self, command: Command) {
        let result = self.run(command);
        if std::mem::take(&mut self.working) {
            self.send(Event::Idle);
        }
        if let Err(e) = result {
            self.send(Event::Error(e));
        }
    }

    /// One step of background work: a batch of blocks, or nothing if none is
    /// due. Returns how many milliseconds to wait before the next step, or
    /// `None` when nothing will be due until a command arrives.
    pub fn tick(&mut self) -> Option<u32> {
        let now = wow_wallet::clock::now();
        let w = self.wallet.as_mut()?;
        w.session.daemon.as_ref()?;
        if !w.syncing {
            let due = w.last_sync + SYNC_INTERVAL_SECS;
            if now < due {
                return Some(((due - now) * 1_000).min(u64::from(u32::MAX)) as u32);
            }
            w.syncing = true;
        }
        self.sync_step();
        match &self.wallet {
            Some(w) if w.syncing => Some(0),
            _ => Some((SYNC_INTERVAL_SECS * 1_000) as u32),
        }
    }

    fn run(&mut self, command: Command) -> Result<(), String> {
        match command {
            Command::ListWallets => {
                self.send_wallets();
                Ok(())
            }
            Command::SetFolder(path) => {
                if self.wallet.is_some() {
                    return Err("close the wallet before changing the folder".into());
                }
                self.platform.set_folder(&path)?;
                self.send_wallets();
                Ok(())
            }
            Command::Create(n) => self.create(n),
            Command::Restore(r) => self.restore(r),
            Command::Open(o) => self.open(o),
            Command::Close => self.close(false),
            Command::Shutdown => self.close(true),
            Command::UseNode(address) => self.use_node(&address),
            Command::TestNode { address, network } => {
                let result = self.test_node(&address, network);
                self.send(Event::NodeTested { address, result });
                Ok(())
            }
            Command::AcceptAnyCertificate(nodes) => {
                self.any_certificate = nodes;
                Ok(())
            }
            Command::SetProxy(text) => {
                self.proxy = match text.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
                    None => None,
                    Some(text) => {
                        let proxy = wow_daemon_client::Proxy::parse(text)?;
                        // A login of this run's own, so Tor keeps this
                        // wallet's circuits apart from other programs'.
                        let mut token = [0u8; 16];
                        wow_wallet::entropy::seeded_rng()?.fill(&mut token);
                        Some(proxy.isolated(&token))
                    }
                };
                let in_use = self
                    .wallet
                    .as_ref()
                    .and_then(|w| w.session.daemon.as_ref())
                    .map(|d| d.address().to_string());
                match in_use {
                    Some(address) => self.use_node(&address),
                    None => Ok(()),
                }
            }
            Command::SetNodeLogin(login) => {
                self.node_login = login
                    .map(|(user, pass)| wow_daemon_client::digest::Credentials { user, pass });
                Ok(())
            }
            Command::SetLog { level, to_file } => {
                // Lines kept for the log window, and how the file rotates.
                const KEPT_LINES: usize = 2_000;
                const FILE_BYTES: u64 = 10 * 1024 * 1024;
                const OLD_FILES: usize = 5;
                match level {
                    Some(n) => wow_log::set_level(n)?,
                    // Nothing logs at FATAL, so this is as good as off.
                    None => wow_log::set_categories("*:FATAL")?,
                }
                wow_log::set_memory(KEPT_LINES);
                // A window has no terminal to write to.
                wow_log::set_stderr(false);
                let file = self
                    .platform
                    .log_file()
                    .filter(|_| to_file && level.is_some());
                match file {
                    Some(path) if wow_log::file().as_ref() != Some(&path) => {
                        if let Some(dir) = path.parent() {
                            std::fs::create_dir_all(dir)
                                .map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
                        }
                        wow_log::set_file(path, FILE_BYTES, OLD_FILES, true)?;
                    }
                    Some(_) => {}
                    None => wow_log::close_file(),
                }
                wow_log::info!(
                    "global",
                    "wownero-wallet-gui {}, logging at {}",
                    env!("CARGO_PKG_VERSION"),
                    level.map_or_else(|| "nothing".to_string(), |n| format!("level {n}"))
                );
                Ok(())
            }
            Command::ReadLog => {
                self.send_log();
                Ok(())
            }
            Command::ClearLog => {
                wow_log::clear_recent();
                self.send_log();
                Ok(())
            }
            Command::Rescan { height, keep } => self.rescan(height, keep),
            Command::HeightOn { date, node } => {
                let height = self.height_on(date, &node)?;
                self.send(Event::HeightOn { date, height });
                Ok(())
            }
            Command::ShowViewKey { password } => {
                let w = self.wallet.as_ref().ok_or(NO_WALLET)?;
                if password != w.session.password {
                    return Err("that is not this wallet's password".into());
                }
                let key = w.session.view_key_hex();
                self.send(Event::ViewKey(key));
                Ok(())
            }
            Command::ChangePassword { old, new } => {
                match &self.wallet {
                    None => return Err(NO_WALLET.into()),
                    Some(w) if old != w.session.password => {
                        return Err("that is not this wallet's password".into())
                    }
                    Some(_) => {}
                }
                // Two CryptoNight hashes, one for each file's key: a moment.
                self.working("Changing the password…");
                let w = self.wallet.as_mut().ok_or(NO_WALLET)?;
                w.session.change_password(new)?;
                let name = w.name.clone();
                self.platform.saved(&name);
                self.send(Event::PasswordChanged);
                Ok(())
            }
            Command::ExportViewOnly {
                password,
                copy_password,
            } => {
                let w = self.wallet.as_ref().ok_or(NO_WALLET)?;
                if password != w.session.password {
                    return Err("that is not this wallet's password".into());
                }
                let keys = w.session.view_only_keys(&copy_password)?;
                let name = w.name.clone();
                self.send(Event::ViewOnlyExported {
                    name,
                    keys: Bytes(keys),
                });
                Ok(())
            }
            Command::Refresh => {
                let w = self.wallet.as_mut().ok_or(NO_WALLET)?;
                if w.session.daemon.is_none() {
                    return Err("choose a node first".into());
                }
                w.syncing = true;
                self.send_status();
                Ok(())
            }
            // Said beside the send form, where it is read, rather than as a
            // notice at the foot of the window.
            Command::PrepareSend(form) => {
                if let Err(e) = self.prepare(form) {
                    self.send(Event::SendFailed(e));
                }
                Ok(())
            }
            Command::EstimateFee(form) => {
                match self.estimate_fee(&form) {
                    Ok((amount, fee)) => self.send(Event::FeeEstimate { amount, fee }),
                    Err(e) => self.send(Event::SendFailed(e)),
                }
                Ok(())
            }
            Command::CommitSend => self.commit(),
            Command::DiscardSend => {
                if let Some(w) = self.wallet.as_mut() {
                    w.prepared = None;
                }
                Ok(())
            }
            Command::ShowSeed { password } => {
                let w = self.wallet.as_ref().ok_or(NO_WALLET)?;
                if password != w.session.password {
                    return Err("that is not this wallet's password".into());
                }
                let language = w
                    .session
                    .keys_file
                    .seed_language()
                    .unwrap_or("English")
                    .to_string();
                let seed = w.session.seed(&language)?;
                self.send(Event::Seed(seed));
                Ok(())
            }
            Command::Subaddress(index) => {
                let w = self.wallet.as_ref().ok_or(NO_WALLET)?;
                let address = w
                    .session
                    .address_at(0, index)
                    .ok_or("that subaddress could not be derived")?;
                self.send(Event::Subaddress { index, address });
                Ok(())
            }
            Command::Import { name, keys, cache } => {
                check_name(&name)?;
                if self.platform.exists(&name) {
                    return Err(format!(
                        "a wallet named {name} already exists; import this one under another name"
                    ));
                }
                // A keys file is a few kilobytes; this is something else.
                if keys.0.is_empty() || keys.0.len() > 1 << 20 {
                    return Err("that does not look like a .keys file".into());
                }
                self.platform.import(&name, keys.0, cache.map(|c| c.0))?;
                self.send(Event::Notice(format!(
                    "Imported {name}. Open it with its password."
                )));
                self.send_wallets();
                Ok(())
            }
            Command::Export(name) => {
                if let Some(w) = self.wallet.as_mut().filter(|w| w.name == name) {
                    if w.session.dirty {
                        save(&mut self.platform, w)?;
                    }
                }
                let (keys, cache) = self.platform.export(&name)?;
                self.send(Event::Exported {
                    name,
                    keys: Bytes(keys),
                    cache: cache.map(Bytes),
                });
                Ok(())
            }
            Command::Forget(name) => {
                if self.wallet.as_ref().is_some_and(|w| w.name == name) {
                    return Err("close the wallet before deleting it".into());
                }
                self.platform.forget(&name)?;
                self.send(Event::Notice(format!("Deleted {name}.")));
                self.send_wallets();
                Ok(())
            }
        }
    }

    fn create(&mut self, n: NewWallet) -> Result<(), String> {
        self.make_room(&n.name)?;
        let language = mnemonic::by_name(&n.language).unwrap_or_else(mnemonic::english);
        self.working("Creating the wallet…");

        let mut rng = wow_wallet::entropy::seeded_rng()?;
        let spend = SecretKey(rng.random_scalar());
        let account = AccountBase::from_spend_key(spend, wow_wallet::clock::now())
            .ok_or("the new keys are not valid; try again")?;
        let store = self.platform.store(&n.name)?;
        let session = Session::create_in(
            store,
            n.network.network(),
            n.password,
            KDF_ROUNDS,
            account,
            language.name,
            0,
        )?;
        self.platform.saved(&n.name);

        let seed = session.seed(language.name).ok();
        self.opened(n.name, session, true, &n.node);
        if let Some(seed) = seed {
            self.send(Event::NewSeed(seed));
        }
        Ok(())
    }

    fn restore(&mut self, r: Restore) -> Result<(), String> {
        let (key, list) = mnemonic::words_to_key(&r.seed)
            .map_err(|e| format!("that seed phrase is not valid: {e}"))?;
        self.make_room(&r.name)?;
        self.working("Restoring the wallet…");

        // `cryptonote::decrypt_key`: a seed written with an offset passphrase
        // is the key plus `cn_slow_hash(passphrase)`.
        let key = if r.passphrase.is_empty() {
            key
        } else {
            let offset = wow_crypto::cn::slow_hash::cn_slow_hash(r.passphrase.as_bytes());
            SecretKey(wow_crypto::ops::sc_sub(&key.0, &offset))
        };
        // A seed in the old English list is written in the current one from now
        // on, as the C++ does.
        let language = if list.language == Language::EnglishOld {
            mnemonic::english()
        } else {
            list
        };
        let account = AccountBase::from_spend_key(key, wow_wallet::clock::now())
            .ok_or("that seed does not make a valid wallet")?;
        let store = self.platform.store(&r.name)?;
        let session = Session::create_in(
            store,
            r.network.network(),
            r.password,
            KDF_ROUNDS,
            account,
            language.name,
            r.restore_height,
        )?;
        self.platform.saved(&r.name);
        self.opened(r.name, session, false, &r.node);
        Ok(())
    }

    fn open(&mut self, o: OpenWallet) -> Result<(), String> {
        if self.wallet.as_ref().is_some_and(|w| w.name == o.name) {
            return Err(format!("{} is already open", o.name));
        }
        self.close(false)?;
        if !self.platform.exists(&o.name) {
            return Err(format!("there is no wallet named {}", o.name));
        }
        self.working(format!("Opening {}…", o.name));
        let store = self.platform.store(&o.name)?;
        let session = Session::open_in(store, o.password, KDF_ROUNDS, None).map_err(|e| {
            if e.contains("not JSON") {
                "That password does not open this wallet.".to_string()
            } else {
                e
            }
        })?;
        self.opened(o.name, session, false, &o.node);
        Ok(())
    }

    /// Check a new wallet's name, and close the open wallet to make way.
    fn make_room(&mut self, name: &str) -> Result<(), String> {
        check_name(name)?;
        if self.platform.exists(name) {
            return Err(format!("a wallet named {name} already exists"));
        }
        self.close(false)
    }

    fn opened(&mut self, name: String, session: Session, fresh: bool, node: &str) {
        let summary = summary(&name, &session);
        self.wallet = Some(Open {
            name,
            session,
            prepared: None,
            node_error: None,
            syncing: false,
            last_sync: 0,
            batches: 0,
            fresh,
        });
        self.send(Event::Opened(summary));
        self.send_wallets();
        if !node.trim().is_empty() {
            // Shown in the status rather than as an error: the wallet is open,
            // and a node is easy to change.
            let _ = self.use_node(node);
        }
        self.send_history();
        self.send_status();
    }

    /// Save the open wallet if it has changed, and close it. A wallet that
    /// cannot be saved stays open unless `force`.
    fn close(&mut self, force: bool) -> Result<(), String> {
        let dirty = match &self.wallet {
            None => return Ok(()),
            Some(w) => w.session.dirty,
        };
        let mut saved: Result<(), String> = Ok(());
        if dirty {
            self.working("Saving the wallet…");
            if let Some(w) = self.wallet.as_mut() {
                saved = save(&mut self.platform, w);
            }
        }
        if saved.is_err() && !force {
            return saved;
        }
        self.wallet = None;
        self.send(Event::Closed);
        self.send_wallets();
        saved
    }

    fn use_node(&mut self, address: &str) -> Result<(), String> {
        let network = match &self.wallet {
            None => return Err(NO_WALLET.into()),
            Some(w) => Net::of(w.session.network),
        };
        let address = address.trim();
        let outcome = if address.is_empty() {
            Ok(None)
        } else {
            self.working(format!("Connecting to {address}…"));
            self.connect_checked(address, network).map(Some)
        };

        let Some(w) = self.wallet.as_mut() else {
            return Err(NO_WALLET.into());
        };
        let result = match outcome {
            Ok(None) => {
                w.session.daemon = None;
                w.node_error = None;
                w.syncing = false;
                Ok(())
            }
            Ok(Some((client, info))) => {
                w.session.daemon_height = info.height;
                // A node on this machine is trusted, and any other is not, as
                // wallet-cli decides without --trusted-daemon.
                w.session.state.trusted_daemon =
                    wow_daemon_client::is_local_address(client.address());
                w.session.daemon = Some(client);
                w.node_error = None;
                // As wallet-cli does for a new wallet: keys made moments ago
                // own nothing older than the tip.
                if std::mem::take(&mut w.fresh) {
                    let tip = w.session.chain_height();
                    w.session.start_at_tip(tip);
                }
                w.syncing = true;
                Ok(())
            }
            Err(e) => {
                w.session.daemon = None;
                w.syncing = false;
                w.node_error = Some(e.clone());
                Err(e)
            }
        };
        self.send_status();
        result
    }

    /// A client for the node at `address`, which has answered and is on
    /// `network`.
    fn connect_checked(&self, address: &str, network: Net) -> Result<(DaemonClient, Info), String> {
        let node = NodeAddress::parse(address)?;
        if let Some(why) = self.unreachable(&node) {
            return Err(why.to_string());
        }
        let client = self.platform.connect(
            &node,
            self.accepts_any(&node),
            self.node_login.as_ref(),
            self.proxy.as_ref(),
        );
        let info = client
            .get_info()
            .map_err(|e| self.unanswered(&node, &e.to_string()))?;
        if !info.nettype.is_empty() && info.nettype != network.name() {
            return Err(format!(
                "{} is a {} node, and this is a {} wallet",
                node.url(),
                info.nettype,
                network.name()
            ));
        }
        Ok((client, info))
    }

    fn test_node(&self, address: &str, network: Net) -> Result<NodeReport, String> {
        let node = NodeAddress::parse(address)?;
        if let Some(why) = self.unreachable(&node) {
            return Err(why.to_string());
        }
        let started = self.platform.millis();
        let info = self
            .platform
            .connect(
                &node,
                self.accepts_any(&node),
                self.node_login.as_ref(),
                self.proxy.as_ref(),
            )
            .get_info()
            .map_err(|e| self.unanswered(&node, &e.to_string()))?;
        let millis = (self.platform.millis() - started).max(0.0) as u64;
        let right_network = info.nettype.is_empty() || info.nettype == network.name();
        Ok(NodeReport {
            height: info.height,
            target_height: info.target_height,
            network: info.nettype,
            synchronized: info.synchronized,
            millis,
            right_network,
        })
    }

    /// Whether `node`'s certificate is accepted whoever signed it.
    fn accepts_any(&self, node: &NodeAddress) -> bool {
        self.any_certificate.contains(&node.host_port())
    }

    /// Why `node` cannot be reached from here, when that is known before
    /// trying.
    fn unreachable(&self, node: &NodeAddress) -> Option<&'static str> {
        node.unreachable_reason(
            self.platform.in_browser(),
            self.platform.secure_page(),
            self.proxy.is_some(),
        )
    }

    fn unanswered(&self, node: &NodeAddress, error: &str) -> String {
        if self.platform.in_browser() {
            format!(
                "{} did not answer: {error}. A browser can only use a node that allows requests \
                 from web pages (CORS), and many do not.",
                node.url()
            )
        } else if self.proxy.is_some() && !node.is_onion() && !node.is_i2p() {
            format!(
                "{} did not answer: {error}. Through a proxy, a node that is not a .onion or \
                 .i2p one is reached only over TLS, so whoever runs the proxy's exit can neither \
                 read it nor pose as the node: use one that answers TLS, or an onion node.",
                node.url()
            )
        } else {
            format!("{} did not answer: {error}", node.url())
        }
    }

    fn prepare(&mut self, form: SendForm) -> Result<(), String> {
        let payment_id = parse_payment_id(&form.payment_id)?;
        match &self.wallet {
            None => return Err(NO_WALLET.into()),
            Some(w) if w.syncing => {
                return Err(
                    "the wallet is still syncing; send once it has caught up, so it does not \
                     spend outputs that are already spent"
                        .into(),
                )
            }
            Some(_) => {}
        }
        self.working("Building the transaction…");

        let w = self.wallet.as_mut().ok_or(NO_WALLET)?;
        w.prepared = None;
        let request = SendRequest {
            address: form.address.trim(),
            amount: form.amount,
            priority: form.priority,
            ring_size: wow_wallet::decoys::RING_SIZE,
            payment_id,
            // The GUI has no way to pick one output yet; sweeping there means
            // the whole wallet.
            sweep_output: None,
        };
        let prepared = w
            .session
            .prepare_send(&request)
            .map_err(|e| e.to_string())?;

        let mut notices = Vec::new();
        if let Some(e) = &prepared.pool_unread {
            notices.push(format!("The node's pool could not be read: {e}"));
        }
        if !prepared.noted_in_pool.is_empty() {
            notices.push(format!(
                "{} transaction(s) in the node's pool spend this wallet's outputs; those outputs \
                 now count as spent.",
                prepared.noted_in_pool.len()
            ));
        }
        let plan = &prepared.plan;
        let preview = Preview {
            address: prepared.address.clone(),
            amount: plan.amounts.first().copied().unwrap_or(0),
            fee: plan.fee,
            change: plan.change,
            inputs: plan.inputs.len(),
            weight: plan.estimated_weight,
            priority: tier_name(prepared.priority).to_string(),
            payment_id: prepared.payment_id.map(|p| wow_crypto::hex::encode(&p)),
            left_behind: plan.left_behind,
        };
        w.prepared = Some(prepared);

        for n in notices {
            self.send(Event::Notice(n));
        }
        self.send(Event::Prepared(preview));
        Ok(())
    }

    /// Forget what the open wallet scanned and scan it again from `height`, as
    /// wallet-cli's `rescan_bc` does; with `keep`, that height becomes the
    /// wallet's restore height too.
    ///
    /// Where this wallet's own transactions went is not on the chain, so
    /// those records are kept (`WalletState::rescan_from`).
    fn rescan(&mut self, height: u64, keep: bool) -> Result<(), String> {
        let w = self.wallet.as_mut().ok_or(NO_WALLET)?;
        if w.prepared.is_some() {
            return Err("send or cancel the transaction waiting first".into());
        }
        let chain = w.session.chain_height();
        if chain > 0 && height >= chain {
            return Err(format!(
                "height {} is past the chain, which is {} blocks long",
                format::grouped(height),
                format::grouped(chain)
            ));
        }
        w.session.state.rescan_from(height);
        if keep {
            w.session.keys_file.set_refresh_height(height);
        }
        w.session.dirty = true;
        w.syncing = w.session.daemon.is_some();
        save(&mut self.platform, w)?;
        if keep {
            self.send(Event::RestoreHeight(height));
        }
        self.send(Event::Notice(format!(
            "Scanning again from height {}. The balance and the history fill in as it goes.",
            format::grouped(height)
        )));
        self.send_history();
        self.send_status();
        Ok(())
    }

    /// The height the chain had reached by `date`: counted back from the open
    /// wallet's node, or from `node` when no wallet is open.
    fn height_on(&self, date: u64, node: &str) -> Result<u64, String> {
        let open = self
            .wallet
            .as_ref()
            .filter(|w| w.session.daemon.is_some());
        let chain = match open {
            Some(w) => w.session.chain_height(),
            None => {
                let address = NodeAddress::parse(node)?;
                if let Some(why) = self.unreachable(&address) {
                    return Err(why.to_string());
                }
                self.platform
                    .connect(
                        &address,
                        self.accepts_any(&address),
                        self.node_login.as_ref(),
                        self.proxy.as_ref(),
                    )
                    .get_info()
                    .map_err(|e| self.unanswered(&address, &e.to_string()))?
                    .height
            }
        };
        if chain == 0 {
            return Err("the node does not know how long the chain is yet".into());
        }
        Ok(format::height_on(date, chain, wow_wallet::clock::now()))
    }

    /// What a send would pay: planned against this wallet's unlocked outputs
    /// at the fee the node asks now, and not built, so the fee is the one
    /// `spend::plan` estimates from the weight. Returns the amount it sends
    /// and the fee.
    fn estimate_fee(&self, form: &SendForm) -> Result<(u64, u64), String> {
        use wow_types::address::Address;
        use wow_wallet::{priority, spend};

        let w = self.wallet.as_ref().ok_or(NO_WALLET)?;
        let client = w.session.daemon.clone().ok_or("choose a node first")?;
        let tiers = client
            .get_fee_estimate(priority::FEE_ESTIMATE_GRACE_BLOCKS)
            .map_err(|e| format!("the node gave no fee estimate: {e}"))?;
        let tier = priority::adjust_priority(
            &client,
            form.priority,
            priority::PrioritySettings::from_keys_file(&w.session.keys_file),
            w.session.state.scan_height(),
            &tiers,
        );
        // What the address says of itself, so the estimate's extra field is
        // the size the transaction's will be. One payee and change never need
        // per-output keys, a subaddress included. One not yet valid estimates
        // as a plain address.
        let address = Address::decode_for(form.address.trim(), w.session.network).ok();
        let payment_id = address.is_some_and(|a| a.payment_id.is_some())
            || !form.payment_id.trim().is_empty();
        let options = spend::SpendOptions {
            ring_size: wow_wallet::decoys::RING_SIZE,
            fee_per_byte: priority::fee_per_byte(&tiers, tier),
            extra_size: spend::extra_size(2, payment_id, false),
            chain_height: w.session.chain_height(),
            now: wow_wallet::clock::now(),
            ..Default::default()
        };
        let transfers = w.session.transfers();
        // An estimate, not the transaction: its own source, so asking what a
        // send would cost does not consume the one the send itself will use.
        let mut rng = wow_wallet::entropy::seeded_rng().map_err(|e| e.to_string())?;
        let plan = match form.amount {
            Some(amount) => spend::plan(transfers, &[amount], &options, &mut rng),
            None => spend::plan_sweep(transfers, &options),
        }
        .map_err(|e| e.to_string())?;
        Ok((plan.amounts.first().copied().unwrap_or(0), plan.fee))
    }

    fn commit(&mut self) -> Result<(), String> {
        let prepared = self
            .wallet
            .as_mut()
            .ok_or(NO_WALLET)?
            .prepared
            .take()
            .ok_or("there is no transaction waiting to be sent")?;
        self.working("Sending…");

        let w = self.wallet.as_mut().ok_or(NO_WALLET)?;
        let relayed = w
            .session
            .commit_send(&prepared, false)
            .map_err(|e| e.to_string())?;
        let result = relayed.result;

        if result.accepted() {
            // Saved at once: a wallet that forgot this send would offer the
            // same outputs to the next one.
            let saved = save(&mut self.platform, w);
            self.send(Event::Sent {
                txid: wow_crypto::hex::encode(&prepared.txid),
            });
            if let Err(e) = saved {
                self.send(Event::Error(format!("Sent, but {e}")));
            }
            self.send_history();
        } else {
            let mut reasons = Vec::new();
            if !result.reason.is_empty() {
                reasons.push(result.reason.clone());
            }
            for (flag, what) in [
                (result.double_spend, "an input was already spent"),
                (result.invalid_input, "an input was not accepted"),
                (result.invalid_output, "an output was not accepted"),
                (result.low_mixin, "the ring size is wrong"),
                (result.too_big, "the transaction is too large"),
                (result.overspend, "the amounts do not balance"),
                (result.fee_too_low, "the fee is too low"),
            ] {
                if flag {
                    reasons.push(what.to_string());
                }
            }
            if result.double_spend {
                reasons.push(
                    "Spends of this wallet's outputs found in the node's pool now count as \
                     spent, so sending again picks other outputs."
                        .into(),
                );
            }
            reasons.push(format!("status: {}", result.status));
            self.send(Event::Rejected(reasons));
        }
        self.send_status();
        Ok(())
    }

    /// One batch of blocks, and what follows from catching up.
    fn sync_step(&mut self) {
        let Some(w) = self.wallet.as_mut() else {
            return;
        };
        let Some(client) = w.session.daemon.clone() else {
            w.syncing = false;
            return;
        };

        let mut notices = Vec::new();
        let mut problems = Vec::new();
        let mut caught_up = false;
        match w.session.state.refresh_once(&client) {
            Ok(s) => {
                w.node_error = None;
                if s.current_height > 0 {
                    w.session.daemon_height = s.current_height;
                }
                if s.blocks_scanned > 0 || s.reorg_to.is_some() || !s.events.is_empty() {
                    w.session.dirty = true;
                    w.batches += 1;
                }
                if let Some(h) = s.reorg_to {
                    notices.push(format!(
                        "The chain changed below height {}; the wallet scanned it again.",
                        format::grouped(h)
                    ));
                }
                let (mut received, mut received_amount) = (0usize, 0u64);
                let (mut spent, mut spent_amount) = (0usize, 0u64);
                for e in &s.events {
                    match *e {
                        RefreshEvent::Received { amount, burnt, .. } => {
                            received += 1;
                            received_amount += amount.saturating_sub(burnt);
                        }
                        RefreshEvent::Spent { amount, .. } => {
                            spent += 1;
                            spent_amount += amount;
                        }
                    }
                }
                if received > 0 {
                    notices.push(format!(
                        "Received {received} payment(s): {} WOW.",
                        format::amount_short(received_amount)
                    ));
                }
                if spent > 0 {
                    notices.push(format!(
                        "{spent} of this wallet's outputs were spent: {} WOW.",
                        format::amount_short(spent_amount)
                    ));
                }
                caught_up = s.caught_up;
            }
            Err(e) => {
                w.node_error = Some(format!("syncing failed: {e}"));
                w.syncing = false;
                w.last_sync = wow_wallet::clock::now();
            }
        }

        if caught_up {
            w.syncing = false;
            w.last_sync = wow_wallet::clock::now();
            // Caught up, so a sent transaction in neither a block nor the pool
            // really is missing.
            match w.session.check_pending() {
                Ok(check) => {
                    if !check.failed.is_empty() {
                        notices.push(format!(
                            "{} sent transaction(s) never reached a block, and count as failed.",
                            check.failed.len()
                        ));
                    }
                }
                Err(e) => problems.push(e),
            }
            if w.session.dirty {
                if let Err(e) = save(&mut self.platform, w) {
                    problems.push(e);
                }
            }
        } else if w.batches >= SAVE_EVERY_BATCHES {
            if let Err(e) = save(&mut self.platform, w) {
                problems.push(e);
            }
        }

        let history = caught_up || !notices.is_empty();
        for n in notices {
            self.send(Event::Notice(n));
        }
        for p in problems {
            self.send(Event::Error(p));
        }
        if history {
            self.send_history();
        }
        self.send_status();
    }

    /// The log lines kept in memory, and the file the log goes to.
    fn send_log(&mut self) {
        let file = wow_log::file().map(|p| p.display().to_string());
        self.send(Event::Log {
            lines: wow_log::recent(),
            file,
        });
    }

    fn working(&mut self, what: impl Into<String>) {
        self.working = true;
        self.send(Event::Working(what.into()));
    }

    fn send(&mut self, event: Event) {
        (self.emit)(event);
    }

    fn send_wallets(&mut self) {
        match self.platform.list() {
            Ok(names) => {
                let location = self.platform.location();
                self.send(Event::Wallets { names, location });
            }
            Err(e) => self.send(Event::Error(e)),
        }
    }

    fn send_status(&mut self) {
        let Some(w) = &self.wallet else {
            return;
        };
        let (balance, unlocked) = w.session.balances();
        let chain = w.session.chain_height();
        let (locked, unlock_blocks) = w.session.state.locked(chain, wow_wallet::clock::now());
        let status = Status {
            balance,
            unlocked,
            locked,
            unlock_blocks,
            scanned: w.session.state.scan_height(),
            chain,
            node: w.session.daemon.as_ref().map(|d| d.address().to_string()),
            link: link(w.session.daemon.as_ref(), self.platform.in_browser()),
            node_error: w.node_error.clone(),
            syncing: w.syncing,
        };
        self.send(Event::Status(status));
    }

    fn send_history(&mut self) {
        let Some(w) = &self.wallet else {
            return;
        };
        let chain = w.session.chain_height();
        let now = wow_wallet::clock::now();
        let rows: Vec<Row> = w
            .session
            .state
            .history()
            .into_iter()
            .rev()
            .take(HISTORY_ROWS)
            .map(|e| Row {
                kind: e.kind.name().to_string(),
                incoming: matches!(e.kind, EntryKind::In | EntryKind::Coinbase),
                txid: wow_crypto::hex::encode(&e.txid),
                unlocked: e.unlocked(chain, now),
                height: e.height,
                timestamp: e.timestamp,
                amount: e.amount,
                fee: e.fee,
                destinations: e
                    .destinations
                    .iter()
                    .map(|d| (d.address.clone(), d.amount))
                    .collect(),
                payment_id: e.payment_id.map(|p| wow_crypto::hex::encode(&p)),
                minors: e.minors.clone(),
            })
            .collect();
        self.send(Event::History(rows));
    }
}

fn save<P: Platform>(platform: &mut P, w: &mut Open) -> Result<(), String> {
    w.session
        .save()
        .map_err(|e| format!("the wallet could not be saved: {e}"))?;
    w.session.dirty = false;
    w.batches = 0;
    platform.saved(&w.name);
    Ok(())
}

/// How the node in use is reached, as far as is known.
fn link(daemon: Option<&DaemonClient>, in_browser: bool) -> Link {
    use wow_daemon_client::Security;
    let Some(daemon) = daemon else {
        return Link::Unknown;
    };
    match daemon.security() {
        Some(Security::Tls { verified: true }) => Link::Tls,
        Some(Security::Tls { verified: false }) => Link::TlsUnchecked,
        Some(Security::Plain { fell_back: false }) => Link::Plain,
        Some(Security::Plain { fell_back: true }) => Link::PlainFallback,
        // A browser's own requests: TLS is what the address says, and the
        // browser checks the certificate.
        None if in_browser => {
            if daemon.address().starts_with("https://") {
                Link::Tls
            } else {
                Link::Plain
            }
        }
        None => Link::Unknown,
    }
}

fn summary(name: &str, session: &Session) -> Summary {
    Summary {
        name: name.to_string(),
        address: session.primary_address(),
        network: Net::of(session.network),
        view_only: session.is_view_only(),
        location: session.location(),
        restore_height: session.keys_file.refresh_height(),
        priority: session.keys_file.default_priority(),
    }
}

/// The name of the fee tier a priority pays. A 0 left unadjusted pays the
/// lowest.
fn tier_name(priority: u32) -> &'static str {
    wow_wallet::priority::PRIORITY_NAMES[priority.clamp(1, 4) as usize]
}

/// A name that is also a safe file name, on every platform.
pub fn check_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("a wallet needs a name".into());
    }
    if name != name.trim() {
        return Err("a wallet's name cannot start or end with a space".into());
    }
    if name.chars().count() > 64 {
        return Err("a wallet's name can be at most 64 characters".into());
    }
    if name.starts_with('.') {
        return Err("a wallet's name cannot start with a dot".into());
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
    {
        return Err("a wallet's name can hold letters, digits, spaces, - _ and . only".into());
    }
    Ok(())
}

fn parse_payment_id(text: &str) -> Result<Option<[u8; 8]>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let bytes = wow_crypto::hex::decode(text).ok_or("the payment id is not hex")?;
    let id: [u8; 8] = bytes
        .try_into()
        .map_err(|_| "a payment id is 16 hex characters".to_string())?;
    Ok(Some(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_safe_file_names() {
        for good in ["main", "My wallet 2", "savings_2026-09", "wow.old"] {
            assert!(check_name(good).is_ok(), "{good}");
        }
        for bad in ["", " ", " lead", "trail ", ".hidden", "a/b", "a\\b", "c:d", "x*"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
        assert!(check_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn payment_ids_are_eight_bytes_of_hex() {
        assert_eq!(parse_payment_id("").expect("none"), None);
        assert_eq!(
            parse_payment_id(" 0102030405060708 ").expect("ok"),
            Some([1, 2, 3, 4, 5, 6, 7, 8])
        );
        assert!(parse_payment_id("0102").is_err());
        assert!(parse_payment_id("zz02030405060708").is_err());
    }
}
