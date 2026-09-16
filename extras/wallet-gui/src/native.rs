//! The desktop application: the interface in a window, the wallet in a thread
//! of its own, and wallets as files in a folder.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::time::{Duration, Instant};

use wow_daemon_client::{Certificates, DaemonClient, Endpoint};
use wow_wallet::files::Paths;
use wow_wallet::store::{FileStore, Store};

use crate::app::{Host, Settings, WalletApp};
use crate::backend::{Backend, Platform};
use crate::nodes::{self, Node, NodeAddress};
use crate::protocol::{Command, Event, Pick};

/// How long an exiting program waits for the open wallet to be saved.
const SAVE_ON_EXIT: Duration = Duration::from_secs(30);

pub fn run() -> eframe::Result {
    let (to_wallet, commands) = mpsc::channel::<Command>();
    let (events_out, events) = mpsc::channel::<Event>();
    let (stopped, wallet_stopped) = mpsc::channel::<()>();
    let shutdown = to_wallet.clone();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Wownero Wallet")
            .with_inner_size([1040.0, 720.0])
            .with_min_inner_size([420.0, 480.0]),
        ..Default::default()
    };

    let result = eframe::run_native(
        "Wownero Wallet",
        options,
        Box::new(move |cc| {
            let settings = Settings::load(cc.storage);
            let folder = match settings.folder.trim() {
                "" => default_folder(),
                path => PathBuf::from(path),
            };
            let ctx = cc.egui_ctx.clone();
            let host_events = events_out.clone();
            let host_ctx = ctx.clone();
            let spawned = std::thread::Builder::new()
                .name("wallet".into())
                .spawn(move || {
                    let emit = move |event: Event| {
                        if events_out.send(event).is_ok() {
                            ctx.request_repaint();
                        }
                    };
                    let mut backend = Backend::new(Folder::new(folder), emit);
                    backend.start();
                    serve(&mut backend, &commands);
                    let _ = stopped.send(());
                });
            if let Err(e) = spawned {
                return Err(format!("cannot start the wallet's thread: {e}").into());
            }
            let host = NativeHost {
                to_wallet,
                events,
                local: Vec::new(),
                events_out: host_events,
                ctx: host_ctx,
            };
            Ok(Box::new(WalletApp::new(settings, Box::new(host))))
        }),
    );

    // The window has closed. The wallet's thread would die with the process,
    // so give it the chance to save first.
    let _ = shutdown.send(Command::Shutdown);
    let _ = wallet_stopped.recv_timeout(SAVE_ON_EXIT);
    result
}

/// Handle commands as they come, and sync in between.
fn serve(backend: &mut Backend<Folder>, commands: &Receiver<Command>) {
    loop {
        let next = match backend.tick() {
            Some(0) => match commands.try_recv() {
                Ok(c) => Some(c),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => break,
            },
            Some(ms) => match commands.recv_timeout(Duration::from_millis(u64::from(ms))) {
                Ok(c) => Some(c),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => break,
            },
            None => match commands.recv() {
                Ok(c) => Some(c),
                Err(_) => break,
            },
        };
        if let Some(command) = next {
            let last = matches!(command, Command::Shutdown);
            backend.handle(command);
            if last {
                return;
            }
        }
    }
    backend.handle(Command::Shutdown);
}

/// Where the desktop keeps wallets unless told otherwise: the user's
/// application data folder.
pub fn default_folder() -> PathBuf {
    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    #[cfg(windows)]
    let base = var("APPDATA");
    #[cfg(target_os = "macos")]
    let base = var("HOME").map(|h| h.join("Library").join("Application Support"));
    #[cfg(not(any(windows, target_os = "macos")))]
    let base = var("XDG_DATA_HOME").or_else(|| var("HOME").map(|h| h.join(".local").join("share")));
    base.map(|b| b.join("wownero-rs").join("wallets"))
        .unwrap_or_else(|| PathBuf::from("wallets"))
}

/// Wallets as files in a folder: `<name>.keys`, `<name>.rscache` and
/// `<name>.address.txt`, as wallet-cli writes them.
struct Folder {
    path: PathBuf,
    started: Instant,
}

impl Folder {
    fn new(path: PathBuf) -> Folder {
        Folder {
            path,
            started: Instant::now(),
        }
    }

    fn paths(&self, name: &str) -> Paths {
        Paths::new(self.path.join(name))
    }
}

impl Platform for Folder {
    fn list(&self) -> Result<Vec<String>, String> {
        let entries = match std::fs::read_dir(&self.path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("cannot read {}: {e}", self.path.display())),
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                name.strip_suffix(".keys").map(str::to_string)
            })
            .collect();
        names.sort();
        Ok(names)
    }

    fn location(&self) -> String {
        self.path.display().to_string()
    }

    fn exists(&self, name: &str) -> bool {
        self.paths(name).keys().exists()
    }

    fn store(&mut self, name: &str) -> Result<Box<dyn Store>, String> {
        std::fs::create_dir_all(&self.path)
            .map_err(|e| format!("cannot make {}: {e}", self.path.display()))?;
        Ok(Box::new(FileStore::new(self.paths(name))))
    }

    /// Files are kept as they are written.
    fn saved(&mut self, _name: &str) {}

    fn import(&mut self, _name: &str, _keys: Vec<u8>, _cache: Option<Vec<u8>>) -> Result<(), String> {
        Err(format!(
            "on the desktop a wallet is its files: copy them into {}",
            self.path.display()
        ))
    }

    fn export(&mut self, _name: &str) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
        Err(format!(
            "on the desktop a wallet is its files, in {}",
            self.path.display()
        ))
    }

    fn forget(&mut self, _name: &str) -> Result<(), String> {
        Err(format!(
            "on the desktop, delete a wallet's files from {} yourself",
            self.path.display()
        ))
    }

    fn set_folder(&mut self, path: &str) -> Result<(), String> {
        self.path = match path.trim() {
            "" => default_folder(),
            path => PathBuf::from(path),
        };
        Ok(())
    }

    fn in_browser(&self) -> bool {
        false
    }

    fn secure_page(&self) -> bool {
        false
    }

    fn connect(
        &self,
        node: &NodeAddress,
        any_certificate: bool,
        login: Option<&wow_daemon_client::digest::Credentials>,
    ) -> DaemonClient {
        let certificates = if any_certificate {
            Certificates::Any
        } else {
            Certificates::Checked
        };
        let mut endpoint = Endpoint::new(node.url()).with_certificates(certificates);
        if let Some(c) = login {
            endpoint = endpoint.with_login(c.clone());
        }
        DaemonClient::with_endpoint(endpoint)
    }

    fn millis(&self) -> f64 {
        self.started.elapsed().as_secs_f64() * 1_000.0
    }

    /// `wownero-wallet-gui.log`, beside the default wallets folder rather
    /// than in whichever folder is chosen: in `%APPDATA%\wownero-rs` on
    /// Windows, say.
    fn log_file(&self) -> Option<PathBuf> {
        let wallets = default_folder();
        let dir = wallets.parent().map(PathBuf::from).unwrap_or_default();
        Some(dir.join("wownero-wallet-gui.log"))
    }
}

struct NativeHost {
    to_wallet: Sender<Command>,
    events: Receiver<Event>,
    /// Answers the host gives itself.
    local: Vec<Event>,
    /// For what the host fetches on a thread of its own: the public list.
    events_out: Sender<Event>,
    ctx: egui::Context,
}

impl Host for NativeHost {
    fn send(&mut self, command: Command) {
        if self.to_wallet.send(command).is_err() {
            self.local.push(Event::Error(
                "the wallet has stopped; restart the program".into(),
            ));
        }
    }

    fn receive(&mut self) -> Vec<Event> {
        let mut events = std::mem::take(&mut self.local);
        events.extend(self.events.try_iter());
        events
    }

    fn in_browser(&self) -> bool {
        false
    }

    fn secure_page(&self) -> bool {
        false
    }

    /// Save where the person says, in the system's own save dialog.
    fn download(&mut self, name: &str, bytes: &[u8]) {
        let Some(path) = rfd::FileDialog::new().set_file_name(name).save_file() else {
            return;
        };
        self.local.push(match std::fs::write(&path, bytes) {
            Ok(()) => Event::Notice(format!("Saved {}.", path.display())),
            Err(e) => Event::Error(format!("{} could not be written: {e}", path.display())),
        });
    }

    fn pick_file(&mut self, _purpose: Pick) {}

    fn utc_offset(&self, timestamp: u64) -> i64 {
        use chrono::{Offset, TimeZone};
        chrono::Local
            .timestamp_opt(timestamp as i64, 0)
            .single()
            .map_or(0, |t| i64::from(t.offset().fix().local_minus_utc()))
    }

    fn pick_folder(&mut self, start: &str) -> Option<String> {
        let mut dialog = rfd::FileDialog::new();
        if !start.trim().is_empty() {
            dialog = dialog.set_directory(start.trim());
        }
        dialog.pick_folder().map(|p| p.display().to_string())
    }

    /// Files on a disk stay where they are put.
    fn storage_persisted(&self) -> Option<bool> {
        None
    }

    /// The folder, in the system's own file manager.
    fn open_folder(&mut self, path: &str) {
        #[cfg(windows)]
        let program = "explorer";
        #[cfg(target_os = "macos")]
        let program = "open";
        #[cfg(not(any(windows, target_os = "macos")))]
        let program = "xdg-open";
        if let Err(e) = std::process::Command::new(program).arg(path).spawn() {
            self.local
                .push(Event::Error(format!("{path} could not be opened: {e}")));
        }
    }

    fn fetch_nodes(&mut self, url: &str) {
        let events = self.events_out.clone();
        let ctx = self.ctx.clone();
        let url = url.to_string();
        let spawned = std::thread::Builder::new()
            .name("node list".into())
            .spawn(move || {
                let result = fetch_list(&url).map_err(|e| unfetched(&e));
                if events.send(Event::NodeList(result)).is_ok() {
                    ctx.request_repaint();
                }
            });
        if let Err(e) = spawned {
            self.local
                .push(Event::NodeList(Err(unfetched(&e.to_string()))));
        }
    }
}

/// The public list, over https. `url` is on [`nodes::LIST_SITE`].
fn fetch_list(url: &str) -> Result<Vec<Node>, String> {
    let path = url
        .strip_prefix(nodes::LIST_SITE)
        .ok_or_else(|| format!("{url} is not on {}", nodes::LIST_SITE))?;
    let body = Endpoint::new(nodes::LIST_SITE)
        .get(path)
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8(body).map_err(|e| e.to_string())?;
    nodes::parse_listing(&text)
}

fn unfetched(why: &str) -> String {
    format!(
        "The public node list could not be fetched ({why}), so this is the list as it stood on \
         15 September 2026."
    )
}
