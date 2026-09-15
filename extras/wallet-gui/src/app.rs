//! The interface: one egui app, on the desktop and in a browser.
//!
//! It holds no wallet. It sends [`Command`]s through its [`Host`] and draws
//! what the [`Event`]s that come back say.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use egui::{
    Align, Align2, Button, Color32, FontFamily, FontId, Layout, RichText, TextEdit, TextStyle,
    ThemePreference, Ui,
};
use serde::{Deserialize, Serialize};
use wow_crypto::mnemonic::{self, Language, WordList};

use crate::format;
use crate::nodes::{self, Node, NodeAddress};
use crate::protocol::{
    Bytes, Command, Event, Net, NewWallet, NodeReport, OpenWallet, Pick, Preview, Restore, Row,
    SendForm, Status, Summary,
};

/// Where the settings are kept between runs.
pub const SETTINGS_KEY: &str = "wownero-wallet";

pub const DISCLAIMER: &str = "This wallet is very new software. It has not been fully audited or \
    tested, and it may have bugs that lose funds. Use it at your own risk, with amounts you can \
    afford to lose.";

/// Seconds a notice stays up. Errors stay until dismissed.
const NOTICE_SECS: f64 = 12.0;

/// Seconds a Copy button says Copied.
const COPIED_SECS: f64 = 2.0;

/// The wallet watches subaddresses up to its lookahead, 200 by default.
const MAX_SUBADDRESS: u32 = 199;

/// Below this width the pages are tabs across the top, as on a phone.
const NARROW: f32 = 700.0;

/// The sizes the interface can be zoomed to, and the step between them.
const MIN_SCALE: f32 = 0.8;
const MAX_SCALE: f32 = 1.6;
const SCALE_STEP: f32 = 0.1;

/// The colours that say how something went, for the theme in force: those
/// that read well on a dark background are too pale on a light one.
#[derive(Clone, Copy)]
struct Tones {
    accent: Color32,
    good: Color32,
    bad: Color32,
    warn: Color32,
}

fn tones(ui: &Ui) -> Tones {
    if ui.visuals().dark_mode {
        Tones {
            accent: Color32::from_rgb(0xe0, 0x4f, 0xd8),
            good: Color32::from_rgb(0x4c, 0xb8, 0x6a),
            bad: Color32::from_rgb(0xe0, 0x5c, 0x50),
            warn: Color32::from_rgb(0xe0, 0xa0, 0x30),
        }
    } else {
        Tones {
            accent: Color32::from_rgb(0xa0, 0x1e, 0x98),
            good: Color32::from_rgb(0x1b, 0x7a, 0x3a),
            bad: Color32::from_rgb(0xb4, 0x23, 0x18),
            warn: Color32::from_rgb(0x96, 0x58, 0x00),
        }
    }
}

/// What the interface needs from where it runs.
pub trait Host {
    fn send(&mut self, command: Command);
    /// What has arrived since the last call.
    fn receive(&mut self) -> Vec<Event>;
    fn in_browser(&self) -> bool;
    /// Whether a browser loaded the wallet over https.
    fn secure_page(&self) -> bool;
    /// Offer bytes as a file to save: a download in a browser, the save
    /// dialog on the desktop.
    fn download(&mut self, name: &str, bytes: &[u8]);
    /// Ask for a file, which arrives as [`Event::Picked`]. The browser only.
    fn pick_file(&mut self, purpose: Pick);
    /// Fetch the public node list, which arrives as [`Event::NodeList`].
    fn fetch_nodes(&mut self, url: &str);
    /// Seconds east of UTC where the wallet runs, at `timestamp`: for times
    /// as the local clock reads them.
    fn utc_offset(&self, timestamp: u64) -> i64;
    /// Ask for a folder, starting at `start`; `None` when none was chosen.
    /// The desktop only.
    fn pick_folder(&mut self, start: &str) -> Option<String>;
    /// Show a folder in the system's file manager. The desktop only.
    fn open_folder(&mut self, path: &str);
    /// Whether the browser promised to keep this site's storage: `None`
    /// where that is not a question, or while it has not answered.
    fn storage_persisted(&self) -> Option<bool>;
}

/// Light or dark, or as the system is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

impl Theme {
    const ALL: [(Theme, &'static str); 3] = [
        (Theme::System, "As the system is"),
        (Theme::Light, "Light"),
        (Theme::Dark, "Dark"),
    ];

    fn preference(self) -> ThemePreference {
        match self {
            Theme::System => ThemePreference::System,
            Theme::Light => ThemePreference::Light,
            Theme::Dark => ThemePreference::Dark,
        }
    }
}

/// What is remembered between runs. Never a password or a seed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub node: String,
    pub network: Net,
    /// Where the desktop keeps wallets; empty for the default.
    pub folder: String,
    pub accepted_risk: bool,
    pub last_wallet: String,
    /// Accept an https node's certificate whoever signed it. The desktop
    /// only.
    pub any_certificate: bool,
    pub theme: Theme,
    /// The whole interface's zoom, 1 being this wallet's own text sizes.
    pub text_scale: f32,
    /// The risk notice along the foot of the window, once read and hidden.
    /// It stays under Settings, About.
    pub hide_notice: bool,
    /// How much to log: 0 to 4, as `--log-level` takes it, or `None` for
    /// nothing.
    pub log_level: Option<u8>,
    /// Write the log to a file as well. The desktop only.
    pub log_to_file: bool,
    /// Show the balance as dots until it is asked for.
    pub hide_balance: bool,
    /// Close an open wallet after this many minutes with nothing done; 0 for
    /// never.
    pub idle_minutes: u32,
    /// Times in the history in UTC rather than as the local clock reads them.
    pub history_utc: bool,
    /// Labels given to subaddresses, by wallet and index. Kept with these
    /// settings, not in the wallet's files.
    pub labels: BTreeMap<String, BTreeMap<u32, String>>,
    /// Wallets whose files have been exported from this browser.
    pub exported: Vec<String>,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            node: nodes::DEFAULT_NODE.to_string(),
            network: Net::Mainnet,
            folder: String::new(),
            accepted_risk: false,
            last_wallet: String::new(),
            any_certificate: false,
            theme: Theme::System,
            text_scale: 1.0,
            hide_notice: false,
            // Warnings and errors, kept in memory for the Logs section.
            log_level: Some(0),
            log_to_file: false,
            hide_balance: false,
            idle_minutes: 0,
            history_utc: false,
            labels: BTreeMap::new(),
            exported: Vec::new(),
        }
    }
}

impl Settings {
    pub fn load(storage: Option<&dyn eframe::Storage>) -> Settings {
        let mut settings: Settings = storage
            .and_then(|s| eframe::get_value(s, SETTINGS_KEY))
            .unwrap_or_default();
        // A wallet with no node chosen yet starts with the default one.
        if settings.node.trim().is_empty() {
            settings.node = nodes::DEFAULT_NODE.to_string();
        }
        if !(MIN_SCALE..=MAX_SCALE).contains(&settings.text_scale) {
            settings.text_scale = 1.0;
        }
        settings
    }
}

pub struct WalletApp {
    host: Box<dyn Host>,
    settings: Settings,
    ready: bool,
    wallets: Vec<String>,
    location: String,
    working: Option<String>,
    messages: Vec<Message>,
    /// egui's clock, in seconds, as of this frame.
    now: f64,
    start: StartForm,
    wallet: Option<WalletView>,
    nodes: NodePicker,
    new_seed: Option<String>,
    seed_written: bool,
    risk_understood: bool,
    /// A wallet waiting for a yes before it is deleted.
    forget: Option<String>,
    settings_tab: SettingsTab,
    /// Whether the saved theme, text size and text styles have been handed
    /// to egui.
    look_applied: bool,
    /// Where the command last sent says why it failed, when that is beside
    /// the form that sent it rather than at the foot of the window.
    awaiting: Option<Place>,
    start_error: Option<String>,
    wallet_error: Option<String>,
    log: LogView,
    /// egui's clock when someone last did something, for closing a wallet
    /// left alone.
    last_activity: f64,
}

struct Message {
    text: String,
    error: bool,
    at: f64,
}

/// The log, as last read from the wallet side.
#[derive(Default)]
struct LogView {
    lines: Vec<String>,
    /// The file it is written to, if any.
    file: Option<String>,
    /// Only lines holding this are shown.
    filter: String,
    /// Whether it has been read since the Logs section was opened.
    read: bool,
}

/// Where a failure is said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// Under the form on the start page.
    Start,
    /// Under the wallet's settings.
    Wallet,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum StartTab {
    #[default]
    Open,
    Create,
    Restore,
    Import,
    Settings,
}

#[derive(Default)]
struct StartForm {
    tab: StartTab,
    selected: String,
    password: String,
    folder: String,
    name: String,
    new_password: String,
    confirm: String,
    language: String,
    seed: String,
    passphrase: String,
    height: String,
    /// The date the restore height is to be found for, as typed.
    date: String,
    keys: Option<(String, Vec<u8>)>,
    cache: Option<(String, Vec<u8>)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Send,
    Receive,
    History,
    Settings,
}

const PAGES: [(Page, &str); 5] = [
    (Page::Overview, "Overview"),
    (Page::Send, "Send"),
    (Page::Receive, "Receive"),
    (Page::History, "History"),
    (Page::Settings, "Settings"),
];

/// The sections of the settings page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SettingsTab {
    /// The open wallet's: only while one is open.
    Wallet,
    #[default]
    Node,
    Appearance,
    Privacy,
    Logs,
    About,
}

/// Which transfers the history shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum HistoryFilter {
    #[default]
    All,
    Received,
    Sent,
    /// Not in a block yet.
    Pending,
}

struct WalletView {
    summary: Summary,
    status: Status,
    history: Vec<Row>,
    page: Page,
    draft: Draft,
    preview: Option<Preview>,
    sent: Option<String>,
    rejected: Option<Vec<String>>,
    seed: Option<String>,
    seed_password: String,
    subaddress_index: u32,
    subaddress: Option<(u32, String)>,
    /// Why the last send could not be prepared, shown beside the form.
    send_error: Option<String>,
    /// The last fee estimate: the amount it sends, and the fee.
    estimate: Option<(u64, u64)>,
    /// Scanning again: from which height, or the height on which date, and
    /// whether that becomes the restore height.
    rescan_height: String,
    rescan_date: String,
    rescan_keep: bool,
    /// Scan again was pressed, and waits for a yes.
    rescan_asked: bool,
    /// The balance, shown for now though the settings hide it.
    balance_shown: bool,
    history_filter: HistoryFilter,
    /// The transfer whose details are open, by transaction ID.
    selected_tx: Option<String>,
    view_key: Option<String>,
    view_key_password: String,
    old_password: String,
    new_password: String,
    new_password_again: String,
    /// A view-only copy: this wallet's password, and the copy's.
    copy_wallet_password: String,
    copy_password: String,
    copy_password_again: String,
}

impl WalletView {
    fn new(summary: Summary) -> WalletView {
        let draft = Draft {
            priority: summary.priority,
            ..Default::default()
        };
        WalletView {
            summary,
            status: Status::default(),
            history: Vec::new(),
            page: Page::Overview,
            draft,
            preview: None,
            sent: None,
            rejected: None,
            seed: None,
            seed_password: String::new(),
            subaddress_index: 1,
            subaddress: None,
            send_error: None,
            estimate: None,
            rescan_height: String::new(),
            rescan_date: String::new(),
            rescan_keep: false,
            rescan_asked: false,
            balance_shown: false,
            history_filter: HistoryFilter::All,
            selected_tx: None,
            view_key: None,
            view_key_password: String::new(),
            old_password: String::new(),
            new_password: String::new(),
            new_password_again: String::new(),
            copy_wallet_password: String::new(),
            copy_password: String::new(),
            copy_password_again: String::new(),
        }
    }
}

#[derive(Default)]
struct Draft {
    address: String,
    amount: String,
    everything: bool,
    priority: u32,
    payment_id: String,
}

#[derive(Default)]
struct NodePicker {
    input: String,
    list: Vec<Node>,
    /// Why the list shown is not a fresh one.
    note: Option<String>,
    fetching: bool,
    /// The network the list was last fetched for.
    fetched: Option<Net>,
    /// By the address as it was sent to be tested.
    tests: HashMap<String, Test>,
}

enum Test {
    Running,
    Done(Result<NodeReport, String>),
}

/// How much is logged, where to, and the lines themselves.
fn logs_settings(
    ui: &mut Ui,
    settings: &mut Settings,
    log: &mut LogView,
    host: &mut dyn Host,
    in_browser: bool,
) {
    let t = tones(ui);
    if !log.read {
        log.read = true;
        host.send(Command::ReadLog);
    }

    let before = (settings.log_level, settings.log_to_file);
    ui.label(RichText::new("How much to log").strong());
    egui::ComboBox::from_id_salt("log-level")
        .selected_text(log_level_label(settings.log_level))
        .show_ui(ui, |ui| {
            for level in [None, Some(0), Some(1), Some(2), Some(3), Some(4)] {
                ui.selectable_value(&mut settings.log_level, level, log_level_label(level));
            }
        });
    // A browser has no files to write to; there the log can be downloaded.
    if !in_browser {
        ui.add_enabled(
            settings.log_level.is_some(),
            egui::Checkbox::new(&mut settings.log_to_file, "Write the log to a file as well"),
        );
    }
    if settings.log_level.is_some_and(|level| level >= 1) {
        ui.colored_label(
            t.warn,
            "The log names the node, heights and transaction IDs. It never holds a seed, a key \
             or a password, but share it with care.",
        );
    }
    if (settings.log_level, settings.log_to_file) != before {
        host.send(Command::SetLog {
            level: settings.log_level,
            to_file: settings.log_to_file,
        });
        host.send(Command::ReadLog);
    }
    if let Some(file) = &log.file {
        ui.label(format!("Written to {file}"));
    }

    ui.add_space(12.0);
    let mut copy = false;
    let mut download = false;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("The log").strong());
        if ui.button("Refresh").clicked() {
            host.send(Command::ReadLog);
        }
        copy = ui.button("Copy").clicked();
        download = ui.button("Save").clicked();
        if ui.button("Clear").clicked() {
            host.send(Command::ClearLog);
        }
        ui.add(
            TextEdit::singleline(&mut log.filter)
                .hint_text("show lines holding…")
                .desired_width(200.0),
        );
    });
    let filter = log.filter.to_lowercase();
    let shown: Vec<&str> = log
        .lines
        .iter()
        .map(String::as_str)
        .filter(|line| filter.is_empty() || line.to_lowercase().contains(&filter))
        .collect();
    if copy {
        ui.ctx().copy_text(shown.join("\n"));
    }
    if download {
        host.download("wownero-wallet.log", shown.join("\n").as_bytes());
    }
    ui.label(format!(
        "{} of the last {} lines",
        shown.len(),
        log.lines.len()
    ));
    // Only the rows in view are laid out: the log keeps two thousand lines.
    let row = ui.text_style_height(&TextStyle::Monospace);
    egui::ScrollArea::both()
        .id_salt("log-lines")
        .max_height(380.0)
        .stick_to_bottom(true)
        .show_rows(ui, row, shown.len(), |ui, rows| {
            for line in &shown[rows] {
                ui.label(RichText::new(*line).monospace());
            }
        });
}

fn log_level_label(level: Option<u8>) -> &'static str {
    match level {
        None => "Nothing",
        Some(0) => "Warnings and errors",
        Some(1) => "What the wallet does",
        Some(2) => "Debugging",
        Some(3) => "Tracing",
        _ => "Everything",
    }
}

impl WalletApp {
    pub fn new(settings: Settings, mut host: Box<dyn Host>) -> WalletApp {
        host.send(Command::AcceptAnyCertificate(settings.any_certificate));
        host.send(Command::SetLog {
            level: settings.log_level,
            to_file: settings.log_to_file,
        });
        let start = StartForm {
            selected: settings.last_wallet.clone(),
            folder: settings.folder.clone(),
            language: "English".into(),
            ..Default::default()
        };
        let nodes = NodePicker {
            input: settings.node.clone(),
            ..Default::default()
        };
        WalletApp {
            host,
            settings,
            ready: false,
            wallets: Vec::new(),
            location: String::new(),
            working: None,
            messages: Vec::new(),
            now: 0.0,
            start,
            wallet: None,
            nodes,
            new_seed: None,
            seed_written: false,
            risk_understood: false,
            forget: None,
            settings_tab: SettingsTab::default(),
            look_applied: false,
            awaiting: None,
            start_error: None,
            wallet_error: None,
            log: LogView::default(),
            last_activity: 0.0,
        }
    }

    fn network(&self) -> Net {
        self.wallet
            .as_ref()
            .map_or(self.settings.network, |w| w.summary.network)
    }

    fn notice(&mut self, text: impl Into<String>) {
        self.push(text.into(), false);
    }

    fn push(&mut self, text: String, error: bool) {
        self.messages.push(Message {
            text,
            error,
            at: self.now,
        });
        if self.messages.len() > 6 {
            self.messages.remove(0);
        }
    }

    /// Send a command whose failure is said beside the form it came from.
    fn send_from(&mut self, place: Place, command: Command) {
        match place {
            Place::Start => self.start_error = None,
            Place::Wallet => self.wallet_error = None,
        }
        self.awaiting = Some(place);
        self.host.send(command);
    }

    /// The saved theme and text size, and this wallet's text styles, on the
    /// first frame; after that, egui's zoom is what is kept.
    fn apply_look(&mut self, ctx: &egui::Context) {
        if self.look_applied {
            // The Appearance buttons change egui's zoom, and so do Ctrl and +
            // or -. Whatever it is now is what is saved.
            self.settings.text_scale = ctx.zoom_factor();
            return;
        }
        self.look_applied = true;
        ctx.all_styles_mut(|style| {
            style.text_styles = [
                (TextStyle::Small, FontId::new(12.0, FontFamily::Proportional)),
                (TextStyle::Body, FontId::new(15.0, FontFamily::Proportional)),
                (TextStyle::Button, FontId::new(15.0, FontFamily::Proportional)),
                (TextStyle::Heading, FontId::new(22.0, FontFamily::Proportional)),
                (TextStyle::Monospace, FontId::new(14.0, FontFamily::Monospace)),
            ]
            .into();
            style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            style.spacing.button_padding = egui::vec2(8.0, 4.0);
        });
        ctx.set_theme(self.settings.theme.preference());
        // In force from the next frame.
        ctx.set_zoom_factor(self.settings.text_scale);
    }

    /// Close an open wallet nobody has touched for as long as the settings
    /// allow.
    fn close_when_idle(&mut self, ctx: &egui::Context) {
        let active = ctx.input(|i| {
            !i.events.is_empty() || i.pointer.is_moving() || i.pointer.any_down()
        });
        if active || self.wallet.is_none() || self.working.is_some() {
            self.last_activity = self.now;
            return;
        }
        let minutes = self.settings.idle_minutes;
        if minutes == 0 {
            return;
        }
        // Frames come only with input or news, so ask for one to notice the
        // time passing.
        ctx.request_repaint_after(Duration::from_secs(20));
        if self.now - self.last_activity < f64::from(minutes) * 60.0 {
            return;
        }
        self.last_activity = self.now;
        let name = self
            .wallet
            .as_ref()
            .map(|w| w.summary.name.clone())
            .unwrap_or_default();
        self.host.send(Command::Close);
        self.notice(format!(
            "Closed {name}, left alone for {minutes} minutes. It opens again with its password."
        ));
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Ready => self.ready = true,
            Event::Wallets { names, location } => {
                if !names.contains(&self.start.selected) {
                    self.start.selected = if names.contains(&self.settings.last_wallet) {
                        self.settings.last_wallet.clone()
                    } else {
                        names.first().cloned().unwrap_or_default()
                    };
                }
                self.wallets = names;
                self.location = location;
            }
            Event::Working(what) => self.working = Some(what),
            Event::Idle => self.working = None,
            Event::Opened(summary) => {
                self.settings.last_wallet = summary.name.clone();
                let form = &mut self.start;
                for field in [
                    &mut form.password,
                    &mut form.new_password,
                    &mut form.confirm,
                    &mut form.seed,
                    &mut form.passphrase,
                    &mut form.name,
                    &mut form.height,
                    &mut form.date,
                ] {
                    field.clear();
                }
                self.awaiting = None;
                self.start_error = None;
                self.wallet_error = None;
                if self.settings_tab == SettingsTab::Node {
                    self.settings_tab = SettingsTab::Wallet;
                }
                self.last_activity = self.now;
                self.wallet = Some(WalletView::new(summary));
            }
            Event::NewSeed(seed) => {
                self.new_seed = Some(seed);
                self.seed_written = false;
            }
            Event::Closed => {
                self.wallet = None;
                self.wallet_error = None;
                self.awaiting = None;
            }
            Event::Status(status) => {
                if let Some(w) = &mut self.wallet {
                    w.status = status;
                }
            }
            Event::History(rows) => {
                if let Some(w) = &mut self.wallet {
                    w.history = rows;
                }
            }
            Event::NodeTested { address, result } => {
                self.nodes.tests.insert(address, Test::Done(result));
            }
            Event::Prepared(preview) => {
                if let Some(w) = &mut self.wallet {
                    w.rejected = None;
                    w.preview = Some(preview);
                }
            }
            Event::Sent { txid } => {
                if let Some(w) = &mut self.wallet {
                    w.preview = None;
                    w.draft = Draft {
                        priority: w.draft.priority,
                        ..Default::default()
                    };
                    w.sent = Some(txid);
                }
                self.notice("Sent.");
            }
            Event::Rejected(reasons) => {
                if let Some(w) = &mut self.wallet {
                    w.preview = None;
                    w.rejected = Some(reasons);
                }
            }
            Event::SendFailed(text) => {
                if let Some(w) = &mut self.wallet {
                    w.preview = None;
                    w.send_error = Some(text);
                }
            }
            Event::FeeEstimate { amount, fee } => {
                if let Some(w) = &mut self.wallet {
                    w.estimate = Some((amount, fee));
                }
            }
            Event::Log { lines, file } => {
                self.log.lines = lines;
                self.log.file = file;
            }
            Event::RestoreHeight(height) => {
                if let Some(w) = &mut self.wallet {
                    w.summary.restore_height = height;
                }
            }
            // For the form that asked: scanning again with a wallet open, or
            // restoring one.
            Event::HeightOn { height, .. } => {
                self.awaiting = None;
                match &mut self.wallet {
                    Some(w) => w.rescan_height = height.to_string(),
                    None => self.start.height = height.to_string(),
                }
            }
            Event::Seed(seed) => {
                self.awaiting = None;
                if let Some(w) = &mut self.wallet {
                    w.seed = Some(seed);
                }
            }
            Event::ViewKey(key) => {
                self.awaiting = None;
                if let Some(w) = &mut self.wallet {
                    w.view_key = Some(key);
                }
            }
            Event::PasswordChanged => {
                self.awaiting = None;
                if let Some(w) = &mut self.wallet {
                    w.new_password.clear();
                    w.new_password_again.clear();
                }
                self.notice("The password is changed: the wallet's files are under the new one.");
            }
            Event::ViewOnlyExported { name, keys } => {
                self.awaiting = None;
                self.host
                    .download(&format!("{name}-view-only.keys"), &keys.0);
                self.notice(format!(
                    "A view-only copy of {name}: it opens with the copy's password, sees what is \
                     paid in, and cannot spend."
                ));
            }
            Event::Subaddress { index, address } => {
                if let Some(w) = &mut self.wallet {
                    w.subaddress = Some((index, address));
                }
            }
            Event::Exported { name, keys, cache } => {
                self.awaiting = None;
                self.host.download(&format!("{name}.keys"), &keys.0);
                if let Some(cache) = cache {
                    self.host.download(&format!("{name}.rscache"), &cache.0);
                }
                if !self.settings.exported.contains(&name) {
                    self.settings.exported.push(name.clone());
                }
                self.notice(format!(
                    "Exported {name}. The keys file is only as safe as its password."
                ));
            }
            Event::Notice(text) => {
                self.awaiting = None;
                self.push(text, false);
            }
            Event::Error(text) => match self.awaiting.take() {
                Some(Place::Start) => self.start_error = Some(text),
                Some(Place::Wallet) => self.wallet_error = Some(text),
                None => self.push(text, true),
            },
            Event::NodeList(result) => {
                self.nodes.fetching = false;
                // The default node first, whether the public list came or not.
                let network = self.network();
                match result {
                    Ok(list) => {
                        self.nodes.list = nodes::with_own_nodes(network, list);
                        self.nodes.note = None;
                    }
                    Err(e) => {
                        self.nodes.list = nodes::with_own_nodes(network, nodes::snapshot(network));
                        self.nodes.note = Some(e);
                    }
                }
            }
            Event::Picked {
                purpose,
                name,
                bytes,
            } => match purpose {
                Pick::Keys => {
                    if self.start.name.trim().is_empty() {
                        self.start.name = name
                            .strip_suffix(".keys")
                            .unwrap_or(name.as_str())
                            .to_string();
                    }
                    self.start.keys = Some((name, bytes.0));
                }
                Pick::Cache => self.start.cache = Some((name, bytes.0)),
            },
        }
    }

    fn top_bar(&mut self, ui: &mut Ui) {
        let t = tones(ui);
        // `Some(None)` opens the settings as they were last left.
        let mut go: Option<Option<SettingsTab>> = None;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Wownero Wallet")
                    .strong()
                    .size(20.0)
                    .color(t.accent),
            );
            ui.label(RichText::new("BETA").small().strong().color(t.warn))
                .on_hover_text(DISCLAIMER);
            if let Some(w) = &self.wallet {
                ui.separator();
                ui.label(RichText::new(w.summary.name.as_str()).strong());
                if w.summary.network != Net::Mainnet {
                    ui.label(RichText::new(w.summary.network.name()).color(t.warn));
                }
                if w.summary.view_only {
                    ui.label(RichText::new("view-only").color(t.warn));
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Settings").clicked() {
                    go = Some(None);
                }
                if let Some(w) = &self.wallet {
                    if node_chip(ui, &w.status).clicked() {
                        go = Some(Some(SettingsTab::Node));
                    }
                }
                if let Some(what) = &self.working {
                    ui.label(what.as_str());
                    ui.spinner();
                }
            });
        });
        if let Some(tab) = go {
            if let Some(tab) = tab {
                self.settings_tab = tab;
            }
            match &mut self.wallet {
                Some(w) => w.page = Page::Settings,
                None => self.start.tab = StartTab::Settings,
            }
        }
    }

    fn message_list(&mut self, ui: &mut Ui) {
        let t = tones(ui);
        let mut dismissed = None;
        for (i, m) in self.messages.iter().enumerate().rev() {
            ui.horizontal(|ui| {
                if ui.small_button("×").clicked() {
                    dismissed = Some(i);
                }
                let color = if m.error {
                    t.bad
                } else {
                    ui.visuals().text_color()
                };
                ui.label(RichText::new(m.text.as_str()).color(color));
            });
        }
        if let Some(i) = dismissed {
            self.messages.remove(i);
        }
    }

    fn page_tabs(&mut self, ui: &mut Ui, narrow: bool) {
        let Some(w) = &mut self.wallet else {
            return;
        };
        let mut close = false;
        let mut tabs = |ui: &mut Ui| {
            for (page, label) in PAGES {
                if ui.selectable_label(w.page == page, label).clicked() {
                    w.page = page;
                }
            }
        };
        if narrow {
            ui.horizontal_wrapped(|ui| {
                tabs(ui);
                if ui.button("Close").clicked() {
                    close = true;
                }
            });
        } else {
            ui.add_space(8.0);
            ui.vertical(|ui| {
                tabs(ui);
                ui.add_space(16.0);
                if ui.button("Close wallet").clicked() {
                    close = true;
                }
            });
        }
        if close {
            self.host.send(Command::Close);
        }
    }

    fn wallet_page(&mut self, ui: &mut Ui) {
        let page = match &self.wallet {
            Some(w) => w.page,
            None => return,
        };
        if page == Page::Settings {
            self.settings_page(ui);
            return;
        }
        let Some(w) = self.wallet.as_mut() else {
            return;
        };
        let host = &mut *self.host;
        match page {
            Page::Overview => overview(ui, w, host, &self.settings, &mut self.settings_tab),
            Page::Send => send_page(ui, w, host),
            Page::Receive => {
                let labels = self
                    .settings
                    .labels
                    .entry(w.summary.name.clone())
                    .or_default();
                receive_page(ui, w, host, labels);
            }
            Page::History => history_page(ui, w, host, &mut self.settings),
            Page::Settings => {}
        }
    }

    /// Settings, with a wallet open or not: that wallet's, the node, how the
    /// interface looks, privacy, the log, and what this is.
    fn settings_page(&mut self, ui: &mut Ui) {
        let in_browser = self.host.in_browser();
        let secure = self.host.secure_page();
        let open = self.wallet.is_some();
        if !open && self.settings_tab == SettingsTab::Wallet {
            self.settings_tab = SettingsTab::Node;
        }
        ui.heading("Settings");
        ui.horizontal_wrapped(|ui| {
            let mut tabs = Vec::new();
            if open {
                tabs.push((SettingsTab::Wallet, "Wallet"));
            }
            tabs.extend([
                (SettingsTab::Node, "Node"),
                (SettingsTab::Appearance, "Appearance"),
                (SettingsTab::Privacy, "Privacy"),
                (SettingsTab::Logs, "Logs"),
                (SettingsTab::About, "About"),
            ]);
            for (tab, label) in tabs {
                ui.selectable_value(&mut self.settings_tab, tab, label);
            }
        });
        ui.separator();
        // The log is read afresh each time its section is opened.
        if self.settings_tab != SettingsTab::Logs {
            self.log.read = false;
        }
        match self.settings_tab {
            SettingsTab::Logs => logs_settings(
                ui,
                &mut self.settings,
                &mut self.log,
                &mut *self.host,
                in_browser,
            ),
            SettingsTab::Wallet => {
                if let Some(w) = self.wallet.as_mut() {
                    wallet_settings(
                        ui,
                        w,
                        &mut *self.host,
                        in_browser,
                        &mut self.wallet_error,
                        &mut self.awaiting,
                    );
                }
            }
            SettingsTab::Node => {
                let t = tones(ui);
                match &self.wallet {
                    Some(w) => {
                        match &w.status.node {
                            Some(n) => ui.label(format!("In use: {n}")),
                            None => ui.label("No node in use."),
                        };
                        if let Some(e) = &w.status.node_error {
                            ui.colored_label(t.bad, e.as_str());
                        }
                    }
                    None => {
                        ui.horizontal(|ui| {
                            ui.label("Network");
                            network_combo(ui, &mut self.settings.network);
                        });
                    }
                }
                let cx = NodeContext {
                    network: self.network(),
                    wallet_open: open,
                    in_browser,
                    secure,
                };
                node_picker(ui, &mut self.nodes, &mut self.settings, &mut *self.host, cx);
            }
            SettingsTab::Appearance => appearance(ui, &mut self.settings, in_browser),
            SettingsTab::Privacy => privacy(ui, &mut self.settings),
            SettingsTab::About => about(ui),
        }
    }

    fn start_page(&mut self, ui: &mut Ui) {
        if !self.ready {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Starting the wallet…");
            });
            return;
        }
        let in_browser = self.host.in_browser();
        ui.add_space(8.0);
        let before = self.start.tab;
        ui.horizontal_wrapped(|ui| {
            let mut tabs = vec![
                (StartTab::Open, "Open"),
                (StartTab::Create, "Create"),
                (StartTab::Restore, "Restore"),
            ];
            if in_browser {
                tabs.push((StartTab::Import, "Import"));
            }
            tabs.push((StartTab::Settings, "Settings"));
            for (tab, label) in tabs {
                ui.selectable_value(&mut self.start.tab, tab, label);
            }
        });
        if self.start.tab != before {
            self.start_error = None;
        }
        ui.separator();
        match self.start.tab {
            StartTab::Open => self.open_tab(ui, in_browser),
            StartTab::Create => self.create_tab(ui),
            StartTab::Restore => self.restore_tab(ui),
            StartTab::Import => self.import_tab(ui),
            StartTab::Settings => {
                self.settings_page(ui);
                return;
            }
        }
        // Why what this form asked for failed, where it was asked.
        if let Some(e) = &self.start_error {
            let t = tones(ui);
            ui.add_space(8.0);
            ui.colored_label(t.bad, e.as_str());
        }
    }

    fn open_tab(&mut self, ui: &mut Ui, in_browser: bool) {
        let mut use_folder = false;
        let mut choose = false;
        let mut show = false;
        if !in_browser {
            ui.horizontal_wrapped(|ui| {
                ui.label("Folder");
                ui.add(
                    TextEdit::singleline(&mut self.start.folder)
                        .hint_text(self.location.as_str())
                        .desired_width(360.0),
                );
                choose = ui.button("Choose…").clicked();
                use_folder = ui.button("Use").clicked();
                show = ui
                    .button("Open")
                    .on_hover_text("Show the folder in the file manager")
                    .clicked();
            });
        }
        let folder_now = match self.start.folder.trim() {
            "" => self.location.clone(),
            typed => typed.to_string(),
        };
        if choose {
            if let Some(path) = self.host.pick_folder(&folder_now) {
                self.start.folder = path;
                use_folder = true;
            }
        }
        if show {
            self.host.open_folder(&folder_now);
        }
        if use_folder {
            self.settings.folder = self.start.folder.trim().to_string();
            let folder = self.settings.folder.clone();
            self.send_from(Place::Start, Command::SetFolder(folder));
        }
        ui.add_space(8.0);
        if self.wallets.is_empty() {
            ui.label("There are no wallets here yet. Create one, or restore one from its seed phrase.");
            if in_browser {
                ui.label("A wallet made elsewhere can be imported from its files.");
            }
            return;
        }

        let mut export = None;
        let mut forget = None;
        for name in &self.wallets {
            ui.horizontal(|ui| {
                ui.radio_value(&mut self.start.selected, name.clone(), name.as_str());
                if in_browser {
                    if ui.small_button("Export").clicked() {
                        export = Some(name.clone());
                    }
                    if ui.small_button("Delete").clicked() {
                        forget = Some(name.clone());
                    }
                }
            });
        }
        ui.add_space(8.0);
        let mut open = false;
        ui.horizontal(|ui| {
            let field = ui.add(
                TextEdit::singleline(&mut self.start.password)
                    .password(true)
                    .hint_text("Password")
                    .desired_width(240.0),
            );
            let entered = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let can_open = !self.start.selected.is_empty();
            if ui.add_enabled(can_open, Button::new("Open")).clicked() || (entered && can_open) {
                open = true;
            }
        });
        if self.settings.node.is_empty() {
            let t = tones(ui);
            ui.colored_label(
                t.warn,
                "No node chosen yet, so the wallet opens offline. Choose one in Settings, under Node.",
            );
        }
        if open {
            let command = Command::Open(OpenWallet {
                name: self.start.selected.clone(),
                password: std::mem::take(&mut self.start.password),
                node: self.settings.node.clone(),
            });
            self.send_from(Place::Start, command);
        }
        if let Some(name) = export {
            self.send_from(Place::Start, Command::Export(name));
        }
        if forget.is_some() {
            self.forget = forget;
        }
    }

    fn create_tab(&mut self, ui: &mut Ui) {
        let f = &mut self.start;
        egui::Grid::new("create")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Name");
                ui.add(TextEdit::singleline(&mut f.name).desired_width(260.0));
                ui.end_row();
                ui.label("Password");
                ui.add(
                    TextEdit::singleline(&mut f.new_password)
                        .password(true)
                        .desired_width(260.0),
                );
                ui.end_row();
                ui.label("Again");
                ui.add(
                    TextEdit::singleline(&mut f.confirm)
                        .password(true)
                        .desired_width(260.0),
                );
                ui.end_row();
                ui.label("Network");
                network_combo(ui, &mut self.settings.network);
                ui.end_row();
                ui.label("Seed language");
                egui::ComboBox::from_id_salt("language")
                    .selected_text(f.language.as_str())
                    .show_ui(ui, |ui| {
                        for list in mnemonic::LANGUAGES
                            .iter()
                            .filter(|l| l.language != Language::EnglishOld)
                        {
                            ui.selectable_value(
                                &mut f.language,
                                list.name.to_string(),
                                language_label(list),
                            );
                        }
                    });
                ui.end_row();
            });

        let f = &self.start;
        let checks = new_wallet_checks(ui, &f.name, &f.new_password, &f.confirm);
        ui.label("Its seed phrase is shown once, next. Write it down: it is the only way to recover the wallet.");
        if ui
            .add_enabled(checks, Button::new("Create wallet"))
            .clicked()
        {
            let command = Command::Create(NewWallet {
                name: f.name.clone(),
                password: f.new_password.clone(),
                network: self.settings.network,
                language: f.language.clone(),
                node: self.settings.node.clone(),
            });
            self.send_from(Place::Start, command);
        }
    }

    fn restore_tab(&mut self, ui: &mut Ui) {
        let t = tones(ui);
        let mut find = false;
        let f = &mut self.start;
        egui::Grid::new("restore")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Seed phrase");
                ui.add(
                    TextEdit::multiline(&mut f.seed)
                        .hint_text("25 words")
                        .desired_rows(3)
                        .desired_width(420.0),
                );
                ui.end_row();
                ui.label("Seed passphrase");
                ui.add(
                    TextEdit::singleline(&mut f.passphrase)
                        .password(true)
                        .hint_text("only if the seed was written with one")
                        .desired_width(260.0),
                );
                ui.end_row();
                ui.label("Restore height");
                ui.add(
                    TextEdit::singleline(&mut f.height)
                        .hint_text("a block height")
                        .desired_width(160.0),
                );
                ui.end_row();
                ui.label("or the date it was made");
                ui.horizontal(|ui| {
                    ui.add(
                        TextEdit::singleline(&mut f.date)
                            .hint_text("2024-05-31")
                            .desired_width(120.0),
                    );
                    find = ui
                        .add_enabled(!f.date.trim().is_empty(), Button::new("Find its height"))
                        .on_hover_text(
                            "Asks the chosen node how long the chain is, and counts back at five \
                             minutes a block, with a day to spare.",
                        )
                        .clicked();
                });
                ui.end_row();
                ui.label("Name");
                ui.add(TextEdit::singleline(&mut f.name).desired_width(260.0));
                ui.end_row();
                ui.label("Password");
                ui.add(
                    TextEdit::singleline(&mut f.new_password)
                        .password(true)
                        .desired_width(260.0),
                );
                ui.end_row();
                ui.label("Again");
                ui.add(
                    TextEdit::singleline(&mut f.confirm)
                        .password(true)
                        .desired_width(260.0),
                );
                ui.end_row();
                ui.label("Network");
                network_combo(ui, &mut self.settings.network);
                ui.end_row();
            });

        if find {
            match format::parse_date(&self.start.date) {
                Ok(date) => {
                    let node = self.settings.node.clone();
                    self.send_from(Place::Start, Command::HeightOn { date, node });
                }
                Err(e) => self.start_error = Some(e),
            }
        }

        let f = &self.start;
        let words = f.seed.split_whitespace().count();
        if words > 0 && words < 24 {
            ui.colored_label(t.warn, format!("{words} words so far; a seed phrase has 25."));
        }
        let height = match f.height.trim().replace([',', '_'], "") {
            h if h.is_empty() => Ok(0),
            h => h
                .parse::<u64>()
                .map_err(|_| "the restore height is a block number".to_string()),
        };
        match &height {
            Err(e) => {
                ui.colored_label(t.bad, e.as_str());
            }
            Ok(0) => {
                ui.label(
                    "With no restore height the wallet reads the whole chain, which takes a long \
                     time. The height the wallet was made at, or a little before, is enough.",
                );
            }
            Ok(_) => {}
        }
        let checks = new_wallet_checks(ui, &f.name, &f.new_password, &f.confirm);
        let ready = checks && words >= 24 && height.is_ok();
        if ui
            .add_enabled(ready, Button::new("Restore wallet"))
            .clicked()
        {
            if let Ok(restore_height) = height {
                let command = Command::Restore(Restore {
                    name: f.name.clone(),
                    password: f.new_password.clone(),
                    network: self.settings.network,
                    seed: f.seed.clone(),
                    passphrase: f.passphrase.clone(),
                    restore_height,
                    node: self.settings.node.clone(),
                });
                self.send_from(Place::Start, command);
            }
        }
    }

    fn import_tab(&mut self, ui: &mut Ui) {
        let t = tones(ui);
        ui.label(
            "Import a wallet from its files: a .keys file, from this wallet or from Wownero's own \
             wallets, and if you have it this wallet's .rscache file. Without the cache the wallet \
             scans again from its restore height.",
        );
        ui.add_space(8.0);
        let mut pick = None;
        egui::Grid::new("import")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Keys file");
                ui.horizontal(|ui| {
                    if ui.button("Choose…").clicked() {
                        pick = Some(Pick::Keys);
                    }
                    if let Some((name, _)) = &self.start.keys {
                        ui.label(name.as_str());
                    }
                });
                ui.end_row();
                ui.label("Cache file");
                ui.horizontal(|ui| {
                    if ui.button("Choose…").clicked() {
                        pick = Some(Pick::Cache);
                    }
                    match &self.start.cache {
                        Some((name, _)) => ui.label(name.as_str()),
                        None => ui.label("none"),
                    };
                });
                ui.end_row();
                ui.label("Name");
                ui.add(TextEdit::singleline(&mut self.start.name).desired_width(260.0));
                ui.end_row();
            });
        if let Some(purpose) = pick {
            self.host.pick_file(purpose);
        }

        let problem = name_problem(&self.start.name);
        if let Some(p) = &problem {
            ui.colored_label(t.bad, p.as_str());
        }
        let ready = self.start.keys.is_some() && !self.start.name.is_empty() && problem.is_none();
        if ui.add_enabled(ready, Button::new("Import")).clicked() {
            if let Some((_, keys)) = self.start.keys.take() {
                let cache = self.start.cache.take().map(|(_, c)| Bytes(c));
                let command = Command::Import {
                    name: std::mem::take(&mut self.start.name),
                    keys: Bytes(keys),
                    cache,
                };
                self.send_from(Place::Start, command);
            }
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        if !self.settings.accepted_risk {
            modal(ctx, "Before you start", |ui| {
                ui.label(DISCLAIMER);
                ui.add_space(8.0);
                ui.label("Keep a written copy of every wallet's seed phrase, and try small amounts first.");
                ui.checkbox(&mut self.risk_understood, "I understand, and I accept the risk");
                if ui
                    .add_enabled(self.risk_understood, Button::new("Continue"))
                    .clicked()
                {
                    self.settings.accepted_risk = true;
                }
            });
            return;
        }

        if let Some(seed) = &self.new_seed {
            let mut done = false;
            modal(ctx, "Write down the seed phrase", |ui| {
                ui.label(
                    "These words are the only way to recover this wallet if its files are lost. \
                     Write them down in order and keep them offline. Anyone who has them can spend \
                     the wallet's money.",
                );
                let mut text = seed.as_str();
                ui.add(
                    TextEdit::multiline(&mut text)
                        .code_editor()
                        .desired_rows(4)
                        .desired_width(f32::INFINITY),
                );
                ui.checkbox(&mut self.seed_written, "I have written it down");
                if ui
                    .add_enabled(self.seed_written, Button::new("Done"))
                    .clicked()
                {
                    done = true;
                }
            });
            if done {
                self.new_seed = None;
            }
            return;
        }

        if let Some(name) = self.forget.clone() {
            let mut answer = None;
            modal(ctx, "Delete a wallet", |ui| {
                ui.label(format!(
                    "Delete {name} from this browser? Without an exported copy of its files or its \
                     seed phrase, its money cannot be recovered."
                ));
                ui.horizontal(|ui| {
                    if ui.button("Delete").clicked() {
                        answer = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        answer = Some(false);
                    }
                });
            });
            match answer {
                Some(true) => {
                    self.forget = None;
                    self.settings.labels.remove(&name);
                    self.settings.exported.retain(|n| n != &name);
                    self.send_from(Place::Start, Command::Forget(name));
                }
                Some(false) => self.forget = None,
                None => {}
            }
        }

        let mut decision = None;
        let unlocked = self.wallet.as_ref().map_or(0, |w| w.status.unlocked);
        if let Some(p) = self.wallet.as_ref().and_then(|w| w.preview.as_ref()) {
            modal(ctx, "Send this transaction?", |ui| {
                ui.label("To");
                let mut address = p.address.as_str();
                ui.add(
                    TextEdit::multiline(&mut address)
                        .code_editor()
                        .desired_rows(2)
                        .desired_width(f32::INFINITY),
                );
                egui::Grid::new("preview")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("Amount");
                        ui.label(RichText::new(format!("{} WOW", format::amount(p.amount))).strong());
                        ui.end_row();
                        ui.label("Fee");
                        ui.label(format!("{} WOW ({})", format::amount(p.fee), p.priority));
                        ui.end_row();
                        ui.label("In all");
                        ui.label(
                            RichText::new(format!(
                                "{} WOW",
                                format::amount(p.amount.saturating_add(p.fee))
                            ))
                            .strong(),
                        );
                        ui.end_row();
                        if p.change > 0 {
                            ui.label("Change");
                            ui.label(format!("{} WOW", format::amount(p.change)));
                            ui.end_row();
                        }
                        // Its inputs leave the unlocked balance now, and the
                        // change comes back locked, as any payment received does.
                        let spent = p.amount.saturating_add(p.fee).saturating_add(p.change);
                        let after = format::amount_short(unlocked.saturating_sub(spent));
                        ui.label("Spendable after");
                        ui.label(if p.change > 0 {
                            format!("{after} WOW, and the change once it unlocks")
                        } else {
                            format!("{after} WOW")
                        });
                        ui.end_row();
                        ui.label("Inputs");
                        ui.label(format!("{}, {} bytes", p.inputs, p.weight));
                        ui.end_row();
                        if let Some(id) = &p.payment_id {
                            ui.label("Payment ID");
                            ui.label(RichText::new(id.as_str()).monospace());
                            ui.end_row();
                        }
                    });
                ui.add_space(8.0);
                ui.label("Check the address. A sent transaction cannot be taken back.");
                ui.horizontal(|ui| {
                    if ui.button("Send").clicked() {
                        decision = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        decision = Some(false);
                    }
                });
            });
        }
        if let Some(send) = decision {
            if let Some(w) = &mut self.wallet {
                w.preview = None;
            }
            self.host.send(if send {
                Command::CommitSend
            } else {
                Command::DiscardSend
            });
        }

        if let Some(what) = &self.working {
            modal(ctx, "Please wait", |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(what.as_str());
                });
            });
        }
    }
}

impl eframe::App for WalletApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_look(ctx);
        self.now = ctx.input(|i| i.time);
        for event in self.host.receive() {
            self.on_event(event);
        }
        self.close_when_idle(ctx);
        let now = self.now;
        self.messages.retain(|m| m.error || now - m.at < NOTICE_SECS);
        let narrow = ctx.screen_rect().width() < NARROW;

        egui::TopBottomPanel::top("top").show(ctx, |ui| self.top_bar(ui));
        if !self.settings.hide_notice {
            egui::TopBottomPanel::bottom("risk").show(ctx, |ui| {
                let t = tones(ui);
                ui.add_space(2.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(DISCLAIMER).color(t.warn));
                    if ui
                        .small_button("Hide")
                        .on_hover_text("It stays under Settings, About.")
                        .clicked()
                    {
                        self.settings.hide_notice = true;
                    }
                });
                ui.add_space(2.0);
            });
        }
        if !self.messages.is_empty() {
            egui::TopBottomPanel::bottom("messages").show(ctx, |ui| self.message_list(ui));
        }
        if self.wallet.is_some() {
            if narrow {
                egui::TopBottomPanel::top("pages").show(ctx, |ui| self.page_tabs(ui, true));
            } else {
                egui::SidePanel::left("pages")
                    .resizable(false)
                    .exact_width(170.0)
                    .show(ctx, |ui| self.page_tabs(ui, false));
            }
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.set_max_width(960.0);
                    if self.wallet.is_some() {
                        self.wallet_page(ui);
                    } else {
                        self.start_page(ui);
                    }
                });
        });
        self.dialogs(ctx);

        if self.working.is_some() || self.nodes.fetching || !self.ready || !self.messages.is_empty()
        {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, SETTINGS_KEY, &self.settings);
    }
}

fn overview(
    ui: &mut Ui,
    w: &mut WalletView,
    host: &mut dyn Host,
    settings: &Settings,
    tab: &mut SettingsTab,
) {
    let t = tones(ui);
    let weak = ui.visuals().weak_text_color();
    // What a browser can lose along with its storage.
    if host.in_browser() {
        if !settings.exported.contains(&w.summary.name) {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    t.warn,
                    "This wallet's files have not been exported from this browser yet. The \
                     browser can clear what a site stores, so keep a copy, and the seed phrase.",
                );
                if ui.small_button("Export now").clicked() {
                    host.send(Command::Export(w.summary.name.clone()));
                }
            });
        }
        if host.storage_persisted() == Some(false) {
            ui.colored_label(
                t.warn,
                "This browser has not promised to keep this site's storage, and may clear it when \
                 space runs low.",
            );
        }
    }

    ui.add_space(8.0);
    ui.label(RichText::new("Balance").color(weak));
    let hidden = settings.hide_balance && !w.balance_shown;
    ui.horizontal(|ui| {
        let text = if hidden {
            "••••• WOW".to_string()
        } else {
            format!("{} WOW", format::amount_short(w.status.balance))
        };
        ui.label(RichText::new(text).size(34.0).strong());
        if settings.hide_balance
            && ui
                .small_button(if w.balance_shown { "Hide" } else { "Show" })
                .clicked()
        {
            w.balance_shown = !w.balance_shown;
        }
    });
    if !hidden && w.status.unlocked != w.status.balance {
        ui.label(format!(
            "{} WOW can be spent now.",
            format::amount_short(w.status.unlocked)
        ));
        if let Some(note) = unlock_note(&w.status) {
            ui.label(RichText::new(note).color(weak));
        }
    }
    ui.add_space(12.0);
    sync_bar(ui, &w.status);
    if let Some(e) = &w.status.node_error {
        ui.colored_label(t.bad, e.as_str());
    }
    ui.horizontal(|ui| {
        let can_refresh = w.status.node.is_some() && !w.status.syncing;
        if ui
            .add_enabled(can_refresh, Button::new("Refresh now"))
            .clicked()
        {
            host.send(Command::Refresh);
        }
        if w.status.node.is_none() && ui.button("Choose a node").clicked() {
            *tab = SettingsTab::Node;
            w.page = Page::Settings;
        }
    });

    ui.add_space(12.0);
    ui.label(RichText::new("Address").color(weak));
    address_box(ui, &w.summary.address);

    ui.add_space(12.0);
    ui.label(RichText::new("Recent").color(weak));
    if w.history.is_empty() {
        ui.label("Nothing yet.");
    } else {
        let recent: Vec<&Row> = w.history.iter().take(5).collect();
        let chosen = history_grid(
            ui,
            &recent,
            "recent",
            &*host,
            settings.history_utc,
            w.status.chain,
        );
        if let Some(txid) = chosen {
            w.selected_tx = Some(txid);
            w.page = Page::History;
        }
    }
}

/// Why money cannot be spent yet, and when the first of it can.
fn unlock_note(status: &Status) -> Option<String> {
    let blocks = status.unlock_blocks?;
    let when = match blocks {
        0 => "with the next block".to_string(),
        1 => format!("in 1 block ({})", format::blocks_as_time(1)),
        n => format!(
            "in {} blocks ({})",
            format::grouped(n),
            format::blocks_as_time(n)
        ),
    };
    Some(format!(
        "{} WOW is locked, and the first of it unlocks {when}. Money received unlocks after 4 \
         blocks, and mined money after 288.",
        format::amount_short(status.locked)
    ))
}

/// What a typed address is, or what is wrong with it.
#[derive(Debug, PartialEq, Eq)]
enum AddressCheck {
    Empty,
    Bad(String),
    Standard,
    Subaddress,
    /// With the payment ID it carries, in hex.
    Integrated(String),
}

fn check_address(text: &str, network: Net) -> AddressCheck {
    use wow_types::address::{Address, AddressError, AddressKind};

    let text = text.trim();
    if text.is_empty() {
        return AddressCheck::Empty;
    }
    match Address::decode_for(text, network.network()) {
        Ok(a) => match (a.kind, a.payment_id) {
            (AddressKind::Integrated, Some(id)) => {
                AddressCheck::Integrated(wow_crypto::hex::encode(&id))
            }
            (AddressKind::Subaddress, _) => AddressCheck::Subaddress,
            _ => AddressCheck::Standard,
        },
        Err(AddressError::WrongNetwork { found, .. }) => AddressCheck::Bad(format!(
            "That is a {} address, and this is a {} wallet.",
            found.name(),
            network.name()
        )),
        Err(_) => AddressCheck::Bad("That is not a Wownero address.".into()),
    }
}

fn send_page(ui: &mut Ui, w: &mut WalletView, host: &mut dyn Host) {
    let t = tones(ui);
    ui.heading("Send");
    if w.summary.view_only {
        ui.label("A view-only wallet cannot send: it has no spend key.");
        return;
    }
    let unlocked = w.status.unlocked;
    let check = check_address(&w.draft.address, w.summary.network);
    let integrated = matches!(check, AddressCheck::Integrated(_));
    let d = &mut w.draft;
    if integrated {
        // The address carries its own, and a second one is refused.
        d.payment_id.clear();
    }
    let before = (
        d.address.clone(),
        d.amount.clone(),
        d.everything,
        d.priority,
        d.payment_id.clone(),
    );
    egui::Grid::new("send")
        .num_columns(2)
        .spacing([12.0, 8.0])
        .show(ui, |ui| {
            ui.label("To");
            ui.add(
                TextEdit::singleline(&mut d.address)
                    .hint_text("a Wownero address")
                    .desired_width(480.0),
            );
            ui.end_row();
            ui.label("");
            match &check {
                AddressCheck::Empty => ui.label(""),
                AddressCheck::Bad(why) => ui.colored_label(t.bad, why.as_str()),
                AddressCheck::Standard => ui.colored_label(t.good, "A standard address."),
                AddressCheck::Subaddress => ui.colored_label(t.good, "A subaddress."),
                AddressCheck::Integrated(id) => ui.colored_label(
                    t.good,
                    format!("An integrated address, carrying the payment ID {id}."),
                ),
            };
            ui.end_row();
            ui.label("Amount");
            ui.horizontal(|ui| {
                ui.add_enabled(
                    !d.everything,
                    TextEdit::singleline(&mut d.amount)
                        .hint_text("0.00")
                        .desired_width(160.0),
                );
                ui.label("WOW");
                ui.toggle_value(&mut d.everything, "Max")
                    .on_hover_text("Send everything that can be spent now, less the fee");
            });
            ui.end_row();
            ui.label("Priority");
            egui::ComboBox::from_id_salt("priority")
                .selected_text(priority_label(d.priority))
                .show_ui(ui, |ui| {
                    for p in 0..=4u32 {
                        ui.selectable_value(&mut d.priority, p, priority_label(p));
                    }
                });
            ui.end_row();
            ui.label("Payment ID");
            ui.add_enabled(
                !integrated,
                TextEdit::singleline(&mut d.payment_id)
                    .hint_text(if integrated {
                        "carried by the address"
                    } else {
                        "optional: 16 hex characters"
                    })
                    .desired_width(220.0),
            );
            ui.end_row();
        });

    ui.label(format!(
        "Can be spent now: {} WOW",
        format::amount_short(unlocked)
    ));
    // Nothing to spend: say so, and why, before anyone fills in the form.
    if unlocked == 0 {
        let why = if w.status.balance == 0 {
            "This wallet has nothing to send yet."
        } else {
            "Nothing in this wallet can be spent yet."
        };
        ui.colored_label(t.warn, why);
        if let Some(note) = unlock_note(&w.status) {
            ui.label(note);
        }
    }

    let amount = if d.everything {
        Ok(None)
    } else {
        format::parse_amount(&d.amount).map(Some)
    };
    if let (false, Err(e)) = (d.everything || d.amount.trim().is_empty(), &amount) {
        ui.colored_label(t.bad, e.as_str());
    }
    let too_much = matches!(amount, Ok(Some(a)) if a > unlocked);
    if too_much && unlocked > 0 {
        ui.colored_label(
            t.bad,
            format!(
                "That is more than can be spent now: {} WOW.",
                format::amount_short(unlocked)
            ),
        );
    }
    let id_to_subaddress = check == AddressCheck::Subaddress && !d.payment_id.trim().is_empty();
    if id_to_subaddress {
        ui.colored_label(
            t.bad,
            "A payment ID cannot go to a subaddress: its payee could not read it.",
        );
    }
    let blocked = if w.status.node.is_none() {
        Some("Choose a node first.")
    } else if w.status.syncing {
        Some("Waiting for the wallet to catch up.")
    } else {
        None
    };
    if let Some(why) = blocked {
        ui.label(why);
    }
    let address_ok = matches!(
        check,
        AddressCheck::Standard | AddressCheck::Subaddress | AddressCheck::Integrated(_)
    );
    let ready = blocked.is_none()
        && address_ok
        && amount.is_ok()
        && unlocked > 0
        && !too_much
        && !id_to_subaddress;

    let after = (
        d.address.clone(),
        d.amount.clone(),
        d.everything,
        d.priority,
        d.payment_id.clone(),
    );
    let form = SendForm {
        address: d.address.trim().to_string(),
        amount: amount.clone().ok().flatten(),
        priority: d.priority,
        payment_id: d.payment_id.trim().to_string(),
    };
    // A changed form makes the last estimate and the last error stale.
    if before != after {
        w.estimate = None;
        w.send_error = None;
    }

    let (mut review, mut estimate) = (false, false);
    ui.horizontal(|ui| {
        review = ui.add_enabled(ready, Button::new("Review")).clicked();
        estimate = ui
            .add_enabled(ready, Button::new("Estimate the fee"))
            .clicked();
    });
    if let Some((sends, fee)) = w.estimate {
        ui.label(format!(
            "The fee comes to about {} WOW, so {} WOW leaves this wallet in all.",
            format::amount_short(fee),
            format::amount_short(sends.saturating_add(fee))
        ));
    }
    if let Some(e) = &w.send_error {
        ui.colored_label(t.bad, e.as_str());
    }
    if review {
        w.send_error = None;
        host.send(Command::PrepareSend(form));
    } else if estimate {
        host.send(Command::EstimateFee(form));
    }

    if let Some(txid) = &w.sent {
        ui.add_space(12.0);
        ui.label("Sent. Its transaction ID:");
        ui.horizontal(|ui| {
            ui.label(RichText::new(txid.as_str()).monospace());
            copy_button(ui, txid);
        });
    }
    let mut dismiss = false;
    if let Some(reasons) = &w.rejected {
        ui.add_space(12.0);
        ui.colored_label(t.bad, "The node refused the transaction:");
        for r in reasons {
            ui.label(format!("• {r}"));
        }
        dismiss = ui.button("Dismiss").clicked();
    }
    if dismiss {
        w.rejected = None;
    }
}

fn receive_page(
    ui: &mut Ui,
    w: &mut WalletView,
    host: &mut dyn Host,
    labels: &mut BTreeMap<u32, String>,
) {
    let t = tones(ui);
    let weak = ui.visuals().weak_text_color();
    ui.heading("Receive");
    ui.label("Primary address");
    address_box(ui, &w.summary.address);
    ui.add_space(16.0);
    ui.label("A subaddress gives each payer an address of their own. All of them pay into this wallet.");

    // The subaddresses already paid, as the history shows them.
    let paid: BTreeSet<u32> = w
        .history
        .iter()
        .filter(|r| r.incoming)
        .flat_map(|r| r.minors.iter().copied())
        .collect();
    let mut show = None;
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(w.subaddress_index > 1, Button::new("<"))
            .clicked()
        {
            w.subaddress_index -= 1;
            show = Some(w.subaddress_index);
        }
        ui.label(format!("Subaddress {}", w.subaddress_index));
        if ui
            .add_enabled(w.subaddress_index < MAX_SUBADDRESS, Button::new(">"))
            .clicked()
        {
            w.subaddress_index += 1;
            show = Some(w.subaddress_index);
        }
        let shown = matches!(&w.subaddress, Some((i, _)) if *i == w.subaddress_index);
        if !shown && ui.button("Show").clicked() {
            show = Some(w.subaddress_index);
        }
        if ui
            .button("Next unused")
            .on_hover_text("The first subaddress nobody has paid yet")
            .clicked()
        {
            let next = (1..=MAX_SUBADDRESS)
                .find(|i| !paid.contains(i))
                .unwrap_or(MAX_SUBADDRESS);
            w.subaddress_index = next;
            show = Some(next);
        }
    });
    if let Some(index) = show {
        host.send(Command::Subaddress(index));
    }
    if let Some((index, address)) = &w.subaddress {
        if *index == w.subaddress_index {
            let index = *index;
            ui.horizontal(|ui| {
                ui.label("Label");
                let mut text = labels.get(&index).cloned().unwrap_or_default();
                let edited = ui
                    .add(
                        TextEdit::singleline(&mut text)
                            .hint_text("who it is for")
                            .desired_width(240.0),
                    )
                    .changed();
                if edited {
                    if text.trim().is_empty() {
                        labels.remove(&index);
                    } else {
                        labels.insert(index, text);
                    }
                }
            });
            if paid.contains(&index) {
                ui.colored_label(
                    t.warn,
                    "This subaddress has been paid before. A fresh one keeps payers apart.",
                );
            } else {
                ui.label(RichText::new("Not paid yet.").color(weak));
            }
            address_box(ui, address);
        }
    }

    // The subaddresses given labels, to find them again.
    if !labels.is_empty() {
        ui.add_space(16.0);
        ui.label(RichText::new("Labelled").strong());
        let mut pick = None;
        egui::Grid::new("labels")
            .striped(true)
            .num_columns(4)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                for (index, label) in labels.iter() {
                    ui.label(format!("#{index}"));
                    ui.label(label.as_str());
                    ui.label(if paid.contains(index) {
                        "paid"
                    } else {
                        "not paid yet"
                    });
                    if ui.small_button("Show").clicked() {
                        pick = Some(*index);
                    }
                    ui.end_row();
                }
            });
        if let Some(index) = pick {
            w.subaddress_index = index;
            host.send(Command::Subaddress(index));
        }
    }
}

fn history_page(ui: &mut Ui, w: &mut WalletView, host: &mut dyn Host, settings: &mut Settings) {
    let weak = ui.visuals().weak_text_color();
    ui.heading("History");
    if w.history.is_empty() {
        ui.label("No transfers yet.");
        return;
    }
    let mut export = false;
    ui.horizontal_wrapped(|ui| {
        for (filter, label) in [
            (HistoryFilter::All, "All"),
            (HistoryFilter::Received, "Received"),
            (HistoryFilter::Sent, "Sent"),
            (HistoryFilter::Pending, "Not in a block yet"),
        ] {
            ui.selectable_value(&mut w.history_filter, filter, label);
        }
        ui.separator();
        ui.checkbox(&mut settings.history_utc, "Times in UTC");
        export = ui.button("Export as CSV").clicked();
    });
    if export {
        let csv = history_csv(&w.history, &*host, settings.history_utc);
        host.download(&format!("{}-history.csv", w.summary.name), csv.as_bytes());
    }
    if w.history.len() >= 1_000 {
        ui.label(RichText::new("The newest 1,000 transfers.").color(weak));
    }

    let filter = w.history_filter;
    let rows: Vec<&Row> = w
        .history
        .iter()
        .filter(|r| match filter {
            HistoryFilter::All => true,
            HistoryFilter::Received => r.incoming,
            HistoryFilter::Sent => !r.incoming,
            HistoryFilter::Pending => r.height.is_none(),
        })
        .collect();
    let chosen = history_grid(
        ui,
        &rows,
        "history",
        &*host,
        settings.history_utc,
        w.status.chain,
    );
    if let Some(txid) = chosen {
        w.selected_tx = if w.selected_tx.as_deref() == Some(txid.as_str()) {
            None
        } else {
            Some(txid)
        };
    }

    // The transfer chosen, in full.
    let mut close = false;
    let selected = w.selected_tx.clone();
    if let Some(row) = selected.and_then(|id| w.history.iter().find(|r| r.txid == id)) {
        ui.add_space(12.0);
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(RichText::new("Details").strong());
            close = ui.small_button("Close").clicked();
        });
        egui::Grid::new("details")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Transaction");
                ui.horizontal(|ui| {
                    ui.label(RichText::new(row.txid.as_str()).monospace());
                    copy_button(ui, &row.txid);
                });
                ui.end_row();
                ui.label("When");
                ui.label(when(&*host, settings.history_utc, row.timestamp));
                ui.end_row();
                ui.label("Kind");
                ui.label(row.kind.as_str());
                ui.end_row();
                ui.label("Amount");
                ui.label(format!(
                    "{}{} WOW",
                    if row.incoming { "+" } else { "-" },
                    format::amount(row.amount)
                ));
                ui.end_row();
                if row.fee > 0 {
                    ui.label("Fee");
                    ui.label(format!("{} WOW", format::amount(row.fee)));
                    ui.end_row();
                }
                ui.label("Height");
                ui.label(
                    row.height
                        .map_or_else(|| "not in a block yet".to_string(), format::grouped),
                );
                ui.end_row();
                ui.label("Confirmations");
                ui.label(confirmations(row, w.status.chain));
                ui.end_row();
                if row.incoming {
                    ui.label("Spendable");
                    ui.label(if row.unlocked { "yes" } else { "not yet" });
                    ui.end_row();
                }
                if let Some(id) = &row.payment_id {
                    ui.label("Payment ID");
                    ui.label(RichText::new(id.as_str()).monospace());
                    ui.end_row();
                }
                if !row.minors.is_empty() {
                    ui.label(if row.incoming {
                        "Paid to"
                    } else {
                        "Spent from"
                    });
                    let names: Vec<String> = row
                        .minors
                        .iter()
                        .map(|m| match m {
                            0 => "the primary address".to_string(),
                            m => format!("subaddress {m}"),
                        })
                        .collect();
                    ui.label(names.join(", "));
                    ui.end_row();
                }
                for (address, amount) in &row.destinations {
                    ui.label("To");
                    ui.label(format!(
                        "{} WOW to {}",
                        format::amount(*amount),
                        format::elide(address, 12)
                    ))
                    .on_hover_text(address.as_str());
                    ui.end_row();
                }
            });
    }
    if close {
        w.selected_tx = None;
    }
}

/// A time as the local clock reads it, or in UTC.
fn when(host: &dyn Host, utc: bool, timestamp: u64) -> String {
    if utc {
        format::timestamp(timestamp)
    } else {
        format::timestamp_in(timestamp, host.utc_offset(timestamp))
    }
}

/// How many blocks carry a transfer: the one it is in, and those after.
fn confirmations(row: &Row, chain: u64) -> String {
    match row.height {
        None => "in the pool".to_string(),
        Some(height) => format::grouped(chain.saturating_sub(height)),
    }
}

/// The history as CSV, newest first, for a spreadsheet.
fn history_csv(rows: &[Row], host: &dyn Host, utc: bool) -> String {
    let mut out = String::from(if utc {
        "date (UTC),kind,amount,fee,height,transaction,payment ID,destinations\n"
    } else {
        "date,kind,amount,fee,height,transaction,payment ID,destinations\n"
    });
    for row in rows {
        let destinations: Vec<String> = row
            .destinations
            .iter()
            .map(|(address, amount)| format!("{address} {}", format::amount(*amount)))
            .collect();
        let fields = [
            when(host, utc, row.timestamp),
            row.kind.clone(),
            format!(
                "{}{}",
                if row.incoming { "" } else { "-" },
                format::amount(row.amount)
            ),
            format::amount(row.fee),
            row.height.map_or_else(String::new, |h| h.to_string()),
            row.txid.clone(),
            row.payment_id.clone().unwrap_or_default(),
            destinations.join("; "),
        ];
        let line: Vec<String> = fields.iter().map(|f| format::csv_field(f)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

/// The open wallet's settings: what it is, its keys, its password, and its
/// files.
fn wallet_settings(
    ui: &mut Ui,
    w: &mut WalletView,
    host: &mut dyn Host,
    in_browser: bool,
    error: &mut Option<String>,
    awaiting: &mut Option<Place>,
) {
    let t = tones(ui);
    let weak = ui.visuals().weak_text_color();
    egui::Grid::new("wallet-facts")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Name");
            ui.label(w.summary.name.as_str());
            ui.end_row();
            ui.label("Kept in");
            ui.label(w.summary.location.as_str());
            ui.end_row();
            ui.label("Network");
            ui.label(w.summary.network.name());
            ui.end_row();
            ui.label("Restore height");
            ui.label(format::grouped(w.summary.restore_height));
            ui.end_row();
            ui.label("Kind");
            ui.label(if w.summary.view_only {
                "view-only"
            } else {
                "full: it can spend"
            });
            ui.end_row();
        });
    if !in_browser && ui.button("Show its folder").clicked() {
        let folder = std::path::Path::new(&w.summary.location)
            .parent()
            .filter(|_| w.summary.location.ends_with(".keys"))
            .map_or_else(|| w.summary.location.clone(), |p| p.display().to_string());
        host.open_folder(&folder);
    }
    // Why what was asked for here failed.
    if let Some(e) = error.as_ref() {
        ui.add_space(8.0);
        ui.colored_label(t.bad, e.as_str());
    }

    ui.add_space(16.0);
    ui.label(RichText::new("Seed phrase").strong());
    let mut hide = false;
    if w.summary.view_only {
        ui.label("A view-only wallet has no seed phrase.");
    } else if let Some(seed) = &w.seed {
        ui.colored_label(t.warn, "Anyone who sees these words can take this wallet's money.");
        let mut text = seed.as_str();
        ui.add(
            TextEdit::multiline(&mut text)
                .code_editor()
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );
        hide = ui.button("Hide").clicked();
    } else {
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut w.seed_password)
                    .password(true)
                    .hint_text("wallet password")
                    .desired_width(200.0),
            );
            if ui.button("Show seed").clicked() {
                *error = None;
                *awaiting = Some(Place::Wallet);
                host.send(Command::ShowSeed {
                    password: std::mem::take(&mut w.seed_password),
                });
            }
        });
    }
    if hide {
        w.seed = None;
    }

    ui.add_space(16.0);
    ui.label(RichText::new("View key").strong());
    ui.label(
        RichText::new(
            "With the address, it lets whoever holds it see every payment to this wallet. It \
             cannot spend.",
        )
        .color(weak),
    );
    let mut hide_view_key = false;
    if let Some(key) = &w.view_key {
        ui.horizontal(|ui| {
            ui.label(RichText::new(key.as_str()).monospace());
            copy_button(ui, key);
            hide_view_key = ui.small_button("Hide").clicked();
        });
    } else {
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut w.view_key_password)
                    .password(true)
                    .hint_text("wallet password")
                    .desired_width(200.0),
            );
            if ui.button("Show view key").clicked() {
                *error = None;
                *awaiting = Some(Place::Wallet);
                host.send(Command::ShowViewKey {
                    password: std::mem::take(&mut w.view_key_password),
                });
            }
        });
    }
    if hide_view_key {
        w.view_key = None;
    }

    ui.add_space(16.0);
    ui.label(RichText::new("Password").strong());
    egui::Grid::new("password")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Now");
            ui.add(
                TextEdit::singleline(&mut w.old_password)
                    .password(true)
                    .desired_width(220.0),
            );
            ui.end_row();
            ui.label("New");
            ui.add(
                TextEdit::singleline(&mut w.new_password)
                    .password(true)
                    .desired_width(220.0),
            );
            ui.end_row();
            ui.label("Again");
            ui.add(
                TextEdit::singleline(&mut w.new_password_again)
                    .password(true)
                    .desired_width(220.0),
            );
            ui.end_row();
        });
    let mismatch = w.new_password != w.new_password_again;
    if mismatch && !w.new_password_again.is_empty() {
        ui.colored_label(t.bad, "The new passwords do not match.");
    }
    let touched = !w.old_password.is_empty() || !w.new_password.is_empty();
    if touched && w.new_password.is_empty() && !mismatch {
        ui.colored_label(
            t.warn,
            "With no password, anyone who copies the wallet's files can spend from it.",
        );
    }
    if ui
        .add_enabled(touched && !mismatch, Button::new("Change password"))
        .clicked()
    {
        *error = None;
        *awaiting = Some(Place::Wallet);
        host.send(Command::ChangePassword {
            old: std::mem::take(&mut w.old_password),
            new: w.new_password.clone(),
        });
    }

    ui.add_space(16.0);
    ui.label(RichText::new("View-only copy").strong());
    ui.label(
        RichText::new(
            "A keys file with the view key and no spend key, to open elsewhere and watch for \
             payments without being able to spend.",
        )
        .color(weak),
    );
    egui::Grid::new("view-only")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("This wallet's password");
            ui.add(
                TextEdit::singleline(&mut w.copy_wallet_password)
                    .password(true)
                    .desired_width(220.0),
            );
            ui.end_row();
            ui.label("The copy's password");
            ui.add(
                TextEdit::singleline(&mut w.copy_password)
                    .password(true)
                    .desired_width(220.0),
            );
            ui.end_row();
            ui.label("Again");
            ui.add(
                TextEdit::singleline(&mut w.copy_password_again)
                    .password(true)
                    .desired_width(220.0),
            );
            ui.end_row();
        });
    let copy_mismatch = w.copy_password != w.copy_password_again;
    if copy_mismatch && !w.copy_password_again.is_empty() {
        ui.colored_label(t.bad, "The copy's passwords do not match.");
    }
    if ui
        .add_enabled(!copy_mismatch, Button::new("Save a view-only copy"))
        .clicked()
    {
        *error = None;
        *awaiting = Some(Place::Wallet);
        host.send(Command::ExportViewOnly {
            password: std::mem::take(&mut w.copy_wallet_password),
            copy_password: std::mem::take(&mut w.copy_password),
        });
        w.copy_password_again.clear();
    }

    // Reading the chain again, from a height or from the height on a date.
    ui.add_space(16.0);
    ui.label(RichText::new("Scan again").strong());
    ui.label(
        "Forget what this wallet has read from the chain and read it again: for payments a scan \
         that started too late missed, or a history that looks wrong. What this wallet sent, and \
         to whom, is kept.",
    );
    let mut find = false;
    egui::Grid::new("rescan")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("From height");
            ui.add(
                TextEdit::singleline(&mut w.rescan_height)
                    .hint_text(format::grouped(w.summary.restore_height))
                    .desired_width(160.0),
            );
            ui.end_row();
            ui.label("or from the date");
            ui.horizontal(|ui| {
                ui.add(
                    TextEdit::singleline(&mut w.rescan_date)
                        .hint_text("2024-05-31")
                        .desired_width(120.0),
                );
                find = ui
                    .add_enabled(
                        !w.rescan_date.trim().is_empty(),
                        Button::new("Find its height"),
                    )
                    .clicked();
            });
            ui.end_row();
        });
    ui.checkbox(&mut w.rescan_keep, "Make it this wallet's restore height too");
    if find {
        match format::parse_date(&w.rescan_date) {
            Ok(date) => {
                *error = None;
                *awaiting = Some(Place::Wallet);
                // The wallet's own node answers.
                host.send(Command::HeightOn {
                    date,
                    node: String::new(),
                });
            }
            Err(e) => *error = Some(e),
        }
    }
    let from = match w.rescan_height.trim().replace([',', '_'], "") {
        h if h.is_empty() => Ok(w.summary.restore_height),
        h => h
            .parse::<u64>()
            .map_err(|_| "the height to scan from is a block number".to_string()),
    };
    match (&from, w.rescan_asked) {
        (Err(e), _) => {
            ui.colored_label(t.bad, e.as_str());
        }
        (Ok(_), false) => {
            if ui.button("Scan again").clicked() {
                w.rescan_asked = true;
            }
        }
        (Ok(height), true) => {
            let height = *height;
            ui.colored_label(
                t.warn,
                format!(
                    "Scan again from height {}? The balance and the history are rebuilt as the \
                     scan goes, which can take a while.",
                    format::grouped(height)
                ),
            );
            ui.horizontal(|ui| {
                if ui.button("Scan again now").clicked() {
                    *error = None;
                    *awaiting = Some(Place::Wallet);
                    host.send(Command::Rescan {
                        height,
                        keep: w.rescan_keep,
                    });
                    w.rescan_asked = false;
                }
                if ui.button("Cancel").clicked() {
                    w.rescan_asked = false;
                }
            });
        }
    }

    if in_browser {
        ui.add_space(16.0);
        ui.label(RichText::new("Backup").strong());
        ui.label(
            "Download this wallet's keys file and its cache. The keys file is encrypted with the \
             wallet's password. The browser can clear what a site stores, so keep a copy.",
        );
        if ui.button("Export files").clicked() {
            *error = None;
            *awaiting = Some(Place::Wallet);
            host.send(Command::Export(w.summary.name.clone()));
        }
    }
    ui.add_space(16.0);
    if ui.button("Close wallet").clicked() {
        host.send(Command::Close);
    }
}

/// How the interface looks: its theme and its size.
fn appearance(ui: &mut Ui, settings: &mut Settings, in_browser: bool) {
    ui.label(RichText::new("Theme").strong());
    ui.horizontal_wrapped(|ui| {
        for (theme, label) in Theme::ALL {
            if ui
                .selectable_value(&mut settings.theme, theme, label)
                .clicked()
            {
                ui.ctx().set_theme(theme.preference());
            }
        }
    });

    ui.add_space(16.0);
    ui.label(RichText::new("Text size").strong());
    let zoom = ui.ctx().zoom_factor();
    let step = |by: f32| {
        ((zoom + by) * 10.0)
            .round()
            .clamp(MIN_SCALE * 10.0, MAX_SCALE * 10.0)
            / 10.0
    };
    ui.horizontal(|ui| {
        if ui
            .add_enabled(zoom > MIN_SCALE + 0.01, Button::new("Smaller"))
            .clicked()
        {
            ui.ctx().set_zoom_factor(step(-SCALE_STEP));
        }
        ui.label(format!("{:.0}%", zoom * 100.0));
        if ui
            .add_enabled(zoom < MAX_SCALE - 0.01, Button::new("Larger"))
            .clicked()
        {
            ui.ctx().set_zoom_factor(step(SCALE_STEP));
        }
        if ui
            .add_enabled((zoom - 1.0).abs() > 0.01, Button::new("Reset"))
            .clicked()
        {
            ui.ctx().set_zoom_factor(1.0);
        }
    });
    if !in_browser {
        ui.label("Ctrl and + or - change it too.");
    }

    ui.add_space(16.0);
    ui.checkbox(
        &mut settings.hide_notice,
        "Hide the risk notice at the foot of the window",
    );
}

/// What is shown to someone looking over a shoulder, and a wallet left open.
fn privacy(ui: &mut Ui, settings: &mut Settings) {
    ui.checkbox(
        &mut settings.hide_balance,
        "Hide the balance until it is asked for",
    );

    ui.add_space(16.0);
    ui.label(RichText::new("Close an open wallet left alone").strong());
    ui.horizontal_wrapped(|ui| {
        for (minutes, label) in [
            (0, "Never"),
            (5, "After 5 minutes"),
            (15, "After 15 minutes"),
            (30, "After 30 minutes"),
            (60, "After an hour"),
        ] {
            ui.selectable_value(&mut settings.idle_minutes, minutes, label);
        }
    });
    ui.label("It is saved as it closes, and opens again with its password.");
}

/// What this is, and the risk of using it.
fn about(ui: &mut Ui) {
    let t = tones(ui);
    ui.label(RichText::new(format!("Wownero Wallet {}", env!("CARGO_PKG_VERSION"))).strong());
    ui.label(
        "A Wownero wallet written in Rust. The desktop wallet and the web wallet share this \
         interface, and the wallet library wownero-wallet-cli uses.",
    );
    ui.add_space(8.0);
    ui.colored_label(t.warn, DISCLAIMER);
    ui.add_space(8.0);
    ui.horizontal_wrapped(|ui| {
        ui.label("Source code:");
        ui.hyperlink_to(
            "github.com/wrkzdev/wow-in-rust",
            "https://github.com/wrkzdev/wow-in-rust",
        );
    });
    ui.label("Licence: BSD-3-Clause.");
}

/// Where the node picker is shown.
struct NodeContext {
    network: Net,
    wallet_open: bool,
    in_browser: bool,
    secure: bool,
}

/// A node typed in or picked from the list, each with a Test button.
fn node_picker(
    ui: &mut Ui,
    picker: &mut NodePicker,
    settings: &mut Settings,
    host: &mut dyn Host,
    cx: NodeContext,
) {
    let t = tones(ui);
    // The public list, fetched the first time it is shown for a network. The
    // default node is listed while it comes.
    if picker.fetched != Some(cx.network) && !picker.fetching {
        picker.fetched = Some(cx.network);
        picker.fetching = true;
        picker.list = nodes::own_nodes(cx.network);
        host.fetch_nodes(&nodes::list_url(cx.network));
    }
    let use_label = if cx.wallet_open { "Use" } else { "Choose" };
    let weak = ui.visuals().weak_text_color();

    let mut test = None;
    let mut chosen = None;
    ui.add_space(8.0);
    ui.label(RichText::new("Node address").strong());
    ui.horizontal_wrapped(|ui| {
        ui.add(
            TextEdit::singleline(&mut picker.input)
                .hint_text("https://host:port")
                .desired_width(320.0),
        );
        let valid = NodeAddress::parse(&picker.input).is_ok();
        if ui.add_enabled(valid, Button::new("Test")).clicked() {
            test = Some(picker.input.trim().to_string());
        }
        if ui.add_enabled(valid, Button::new(use_label)).clicked() {
            chosen = Some(picker.input.trim().to_string());
        }
        if ui
            .button("Default")
            .on_hover_text(nodes::DEFAULT_NODE)
            .clicked()
        {
            picker.input = nodes::DEFAULT_NODE.to_string();
        }
    });
    let input = picker.input.trim().to_string();
    match NodeAddress::parse(&input) {
        Ok(node) => {
            if let Some(why) = node.unreachable_reason(cx.in_browser, cx.secure) {
                ui.colored_label(t.warn, why);
            }
        }
        Err(e) if !input.is_empty() => {
            ui.colored_label(t.bad, e.as_str());
        }
        Err(_) => {}
    }
    test_line(ui, picker.tests.get(&input), true);
    if !cx.wallet_open && !settings.node.is_empty() {
        ui.label(format!(
            "Chosen: {}. A wallet uses it when it opens.",
            settings.node
        ));
    }
    // A browser decides about certificates itself.
    if !cx.in_browser {
        let mut any = settings.any_certificate;
        let changed = ui
            .checkbox(&mut any, "Accept an https node's certificate whoever signed it")
            .on_hover_text(
                "For a node you run yourself, with a self-signed certificate. The connection is \
                 still encrypted, but nothing checks who is at the other end of it.",
            )
            .changed();
        if changed {
            settings.any_certificate = any;
            host.send(Command::AcceptAnyCertificate(any));
        }
        if any {
            ui.colored_label(
                t.warn,
                "Certificates are not checked, so someone between this computer and the node \
                 could pose as it.",
            );
        }
    }

    ui.add_space(16.0);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Nodes").strong());
        ui.label("the default, and public ones");
        ui.hyperlink_to("listed by monero.fail", "https://monero.fail/?crypto=wownero");
        if picker.fetching {
            ui.spinner();
        } else if ui.small_button("Reload").clicked() {
            picker.fetched = None;
        }
    });
    if let Some(note) = &picker.note {
        ui.colored_label(t.warn, note.as_str());
    }
    ui.label(if cx.in_browser {
        "A browser can use a node only if the node allows requests from web pages (CORS), and a \
         page loaded over https can use https nodes only. The Browser column is monero.fail's own \
         check; Test shows what this browser can reach."
    } else {
        "http:// and https:// nodes both work. A node you run yourself is the most private choice."
    });
    if !picker.list.is_empty() {
        let headings: &[&str] = if cx.in_browser {
            &["Node", "Note", "Height", "Browser", "", ""]
        } else {
            &["Node", "Note", "Height", "", ""]
        };
        egui::Grid::new("public-nodes")
            .striped(true)
            .num_columns(headings.len())
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                for heading in headings {
                    ui.label(RichText::new(*heading).strong());
                }
                ui.end_row();
                for node in &picker.list {
                    let unusable = NodeAddress::parse(&node.url)
                        .ok()
                        .and_then(|a| a.unreachable_reason(cx.in_browser, cx.secure));
                    ui.label(RichText::new(node.url.as_str()).monospace())
                        .on_hover_text(node.country_name.as_deref().unwrap_or("location unknown"));
                    ui.label(node.note.as_deref().unwrap_or(""));
                    ui.label(node.last_height.map_or_else(String::new, format::grouped));
                    if cx.in_browser {
                        ui.label(if node.web_compatible { "yes" } else { "no" });
                    }
                    ui.horizontal(|ui| {
                        let usable = unusable.is_none();
                        if ui.add_enabled(usable, Button::new("Test").small()).clicked() {
                            test = Some(node.url.clone());
                        }
                        if ui
                            .add_enabled(usable, Button::new(use_label).small())
                            .clicked()
                        {
                            chosen = Some(node.url.clone());
                        }
                    });
                    match unusable {
                        Some(why) => {
                            ui.label(RichText::new("not usable here").color(weak))
                                .on_hover_text(why);
                        }
                        None => test_line(ui, picker.tests.get(&node.url), false),
                    }
                    ui.end_row();
                }
            });
        // Why a test failed, in full, under the list rather than squeezed into
        // a column.
        for node in &picker.list {
            if let Some(Test::Done(Err(e))) = picker.tests.get(&node.url) {
                ui.colored_label(t.bad, e.as_str());
            }
        }
    }

    if let Some(address) = test {
        picker.tests.insert(address.clone(), Test::Running);
        host.send(Command::TestNode {
            address,
            network: cx.network,
        });
    }
    if let Some(address) = chosen {
        settings.node = address.clone();
        picker.input = address.clone();
        if cx.wallet_open {
            host.send(Command::UseNode(address));
        }
    }
}

/// A test's outcome: in full under the address box, and short in the list.
fn test_line(ui: &mut Ui, test: Option<&Test>, full: bool) {
    let t = tones(ui);
    match test {
        None => {
            if !full {
                ui.label("");
            }
        }
        Some(Test::Running) => {
            ui.spinner();
        }
        Some(Test::Done(Ok(r))) => {
            let mut parts = vec![format!("height {}", format::grouped(r.height))];
            parts.push(if r.network.is_empty() {
                "network not given".to_string()
            } else {
                r.network.clone()
            });
            let syncing = !r.synchronized || r.height < r.target_height;
            if syncing {
                parts.push("still syncing".into());
            }
            parts.push(format!("{} ms", r.millis));
            let (color, lead) = if !r.right_network {
                (t.bad, "wrong network: ")
            } else if syncing {
                (t.warn, "answers, ")
            } else {
                (t.good, "works: ")
            };
            ui.colored_label(color, format!("{lead}{}", parts.join(" · ")));
        }
        Some(Test::Done(Err(e))) => {
            if full {
                ui.colored_label(t.bad, e.as_str());
            } else {
                // Written out in full under the list.
                ui.colored_label(t.bad, "failed: see below")
                    .on_hover_text(e.as_str());
            }
        }
    }
}

/// The node's state in a word or two, which opens the node settings when
/// clicked.
fn node_chip(ui: &mut Ui, status: &Status) -> egui::Response {
    let t = tones(ui);
    let (color, text) = if status.node_error.is_some() {
        (t.bad, "node problem".to_string())
    } else if status.node.is_none() {
        (ui.visuals().weak_text_color(), "no node".to_string())
    } else if status.syncing {
        let percent = if status.chain == 0 {
            String::new()
        } else {
            format!(
                " {:.1}%",
                status.scanned as f64 * 100.0 / status.chain as f64
            )
        };
        (t.warn, format!("syncing{percent}"))
    } else {
        (t.good, format!("synced at {}", format::grouped(status.scanned)))
    };
    let hover = match (&status.node_error, &status.node) {
        (Some(e), _) => e.clone(),
        (None, Some(node)) => node.clone(),
        (None, None) => "No node in use.".to_string(),
    };
    ui.add(
        egui::Label::new(RichText::new(format!("• {text}")).color(color))
            .sense(egui::Sense::click()),
    )
    .on_hover_text(format!("{hover}\nClick for the node settings."))
}

fn sync_bar(ui: &mut Ui, s: &Status) {
    if s.chain == 0 {
        ui.label("Not synced with any node yet.");
        return;
    }
    let fraction = (s.scanned as f64 / s.chain as f64).clamp(0.0, 1.0) as f32;
    let text = if s.scanned >= s.chain {
        format!("Synced at height {}", format::grouped(s.scanned))
    } else {
        format!(
            "Height {} of {}",
            format::grouped(s.scanned),
            format::grouped(s.chain)
        )
    };
    ui.add(egui::ProgressBar::new(fraction).text(text));
}

/// Transfers as a table. Returns the transaction whose Details was pressed.
fn history_grid(
    ui: &mut Ui,
    rows: &[&Row],
    id: &str,
    host: &dyn Host,
    utc: bool,
    chain: u64,
) -> Option<String> {
    let t = tones(ui);
    let mut chosen = None;
    egui::Grid::new(id)
        .striped(true)
        .num_columns(6)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            let date = if utc { "Date (UTC)" } else { "Date" };
            for heading in [date, "", "Amount (WOW)", "Confirmations", "Transaction", ""] {
                ui.label(RichText::new(heading).strong());
            }
            ui.end_row();
            for row in rows {
                ui.label(when(host, utc, row.timestamp));
                let color = match row.kind.as_str() {
                    "failed" => t.bad,
                    "pending" => t.warn,
                    _ if row.incoming => t.good,
                    _ => ui.visuals().text_color(),
                };
                let kind = if row.incoming && !row.unlocked && row.height.is_some() {
                    format!("{}, locked", row.kind)
                } else {
                    row.kind.clone()
                };
                ui.label(RichText::new(kind).color(color));
                let sign = if row.incoming { "+" } else { "-" };
                let amount =
                    ui.label(RichText::new(format!("{sign}{}", format::amount(row.amount))).monospace());
                if row.fee > 0 {
                    amount.on_hover_text(format!("fee {}", format::amount(row.fee)));
                }
                ui.label(confirmations(row, chain));
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format::elide(&row.txid, 6)).monospace())
                        .on_hover_text(row.txid.as_str());
                    copy_button(ui, &row.txid);
                });
                if ui.small_button("Details").clicked() {
                    chosen = Some(row.txid.clone());
                }
                ui.end_row();
            }
        });
    chosen
}

/// A Copy button that says Copied for a moment after.
fn copy_button(ui: &mut Ui, text: &str) {
    let id = egui::Id::new(("copied", text));
    let now = ui.input(|i| i.time);
    let copied = ui
        .ctx()
        .data(|d| d.get_temp::<f64>(id))
        .is_some_and(|at| now - at < COPIED_SECS);
    if ui
        .small_button(if copied { "Copied" } else { "Copy" })
        .clicked()
    {
        ui.ctx().copy_text(text.to_string());
        ui.ctx().data_mut(|d| d.insert_temp(id, now));
        ui.ctx()
            .request_repaint_after(Duration::from_secs_f64(COPIED_SECS));
    }
}

/// An address: selectable text, Copy, and a QR code to scan it from.
fn address_box(ui: &mut Ui, text: &str) {
    let mut shown = text;
    ui.add(
        TextEdit::multiline(&mut shown)
            .code_editor()
            .desired_rows(2)
            .desired_width(f32::INFINITY),
    );
    let qr_id = egui::Id::new(("qr", text));
    let mut qr = ui.ctx().data(|d| d.get_temp::<bool>(qr_id)).unwrap_or(false);
    ui.horizontal(|ui| {
        copy_button(ui, text);
        if ui.selectable_label(qr, "QR code").clicked() {
            qr = !qr;
            ui.ctx().data_mut(|d| d.insert_temp(qr_id, qr));
        }
    });
    if qr {
        crate::qr::show(ui, text, 240.0);
    }
}

fn network_combo(ui: &mut Ui, network: &mut Net) {
    egui::ComboBox::from_id_salt("network")
        .selected_text(network.name())
        .show_ui(ui, |ui| {
            for n in Net::ALL {
                ui.selectable_value(network, n, n.name());
            }
        });
}

/// Shows what is wrong with a new wallet's name and password, and says
/// whether nothing is.
fn new_wallet_checks(ui: &mut Ui, name: &str, password: &str, confirm: &str) -> bool {
    let t = tones(ui);
    let problem = name_problem(name);
    if let Some(p) = &problem {
        ui.colored_label(t.bad, p.as_str());
    }
    let mismatch = password != confirm;
    if mismatch && !confirm.is_empty() {
        ui.colored_label(t.bad, "The passwords do not match.");
    }
    if password.is_empty() {
        ui.colored_label(
            t.warn,
            "With no password, anyone who copies the wallet's files can spend from it.",
        );
    }
    !name.is_empty() && problem.is_none() && !mismatch
}

fn name_problem(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    crate::backend::check_name(name).err()
}

fn language_label(list: &WordList) -> String {
    if list.name == list.english_name {
        list.name.to_string()
    } else {
        format!("{} ({})", list.name, list.english_name)
    }
}

fn priority_label(priority: u32) -> &'static str {
    match priority {
        0 => "automatic",
        1 => "low (unimportant)",
        2 => "normal",
        3 => "elevated",
        _ => "high (priority)",
    }
}

/// A window in the middle of the screen, which cannot be moved or collapsed.
fn modal(ctx: &egui::Context, title: &str, add: impl FnOnce(&mut Ui)) {
    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.set_max_width(520.0);
            add(ui);
        });
}
