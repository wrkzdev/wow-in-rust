//! The interface: one egui app, on the desktop and in a browser.
//!
//! It holds no wallet. It sends [`Command`]s through its [`Host`] and draws
//! what the [`Event`]s that come back say.

use std::collections::HashMap;
use std::time::Duration;

use egui::{Align, Align2, Button, Color32, Layout, RichText, TextEdit, Ui};
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

const ACCENT: Color32 = Color32::from_rgb(0xe0, 0x4f, 0xd8);
const GOOD: Color32 = Color32::from_rgb(0x4c, 0xb8, 0x6a);
const BAD: Color32 = Color32::from_rgb(0xe0, 0x5c, 0x50);
const WARN: Color32 = Color32::from_rgb(0xe0, 0xa0, 0x30);

/// Seconds a notice stays up. Errors stay until dismissed.
const NOTICE_SECS: f64 = 12.0;

/// The wallet watches subaddresses up to its lookahead, 200 by default.
const MAX_SUBADDRESS: u32 = 199;

/// Below this width the pages are tabs across the top, as on a phone.
const NARROW: f32 = 700.0;

/// What the interface needs from where it runs.
pub trait Host {
    fn send(&mut self, command: Command);
    /// What has arrived since the last call.
    fn receive(&mut self) -> Vec<Event>;
    fn in_browser(&self) -> bool;
    /// Whether a browser loaded the wallet over https.
    fn secure_page(&self) -> bool;
    /// Offer bytes as a file to save. The browser only.
    fn download(&mut self, name: &str, bytes: &[u8]);
    /// Ask for a file, which arrives as [`Event::Picked`]. The browser only.
    fn pick_file(&mut self, purpose: Pick);
    /// Fetch the public node list, which arrives as [`Event::NodeList`].
    fn fetch_nodes(&mut self, url: &str);
}

/// What is remembered between runs. Never a password or a seed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub node: String,
    pub network: Net,
    /// Where the desktop keeps wallets; empty for the default.
    pub folder: String,
    pub accepted_risk: bool,
    pub last_wallet: String,
}

impl Settings {
    pub fn load(storage: Option<&dyn eframe::Storage>) -> Settings {
        storage
            .and_then(|s| eframe::get_value(s, SETTINGS_KEY))
            .unwrap_or_default()
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
}

struct Message {
    text: String,
    error: bool,
    at: f64,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum StartTab {
    #[default]
    Open,
    Create,
    Restore,
    Import,
    Node,
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
    keys: Option<(String, Vec<u8>)>,
    cache: Option<(String, Vec<u8>)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Send,
    Receive,
    History,
    Node,
    Wallet,
}

const PAGES: [(Page, &str); 6] = [
    (Page::Overview, "Overview"),
    (Page::Send, "Send"),
    (Page::Receive, "Receive"),
    (Page::History, "History"),
    (Page::Node, "Node"),
    (Page::Wallet, "Wallet"),
];

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

impl WalletApp {
    pub fn new(settings: Settings, host: Box<dyn Host>) -> WalletApp {
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
                ] {
                    field.clear();
                }
                self.wallet = Some(WalletView::new(summary));
            }
            Event::NewSeed(seed) => {
                self.new_seed = Some(seed);
                self.seed_written = false;
            }
            Event::Closed => self.wallet = None,
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
            Event::Seed(seed) => {
                if let Some(w) = &mut self.wallet {
                    w.seed = Some(seed);
                }
            }
            Event::Subaddress { index, address } => {
                if let Some(w) = &mut self.wallet {
                    w.subaddress = Some((index, address));
                }
            }
            Event::Exported { name, keys, cache } => {
                self.host.download(&format!("{name}.keys"), &keys.0);
                if let Some(cache) = cache {
                    self.host.download(&format!("{name}.rscache"), &cache.0);
                }
                self.notice(format!(
                    "Exported {name}. The keys file is only as safe as its password."
                ));
            }
            Event::Notice(text) => self.push(text, false),
            Event::Error(text) => self.push(text, true),
            Event::NodeList(result) => {
                self.nodes.fetching = false;
                match result {
                    Ok(list) => {
                        self.nodes.list = list;
                        self.nodes.note = None;
                    }
                    Err(e) => {
                        self.nodes.list = nodes::snapshot(self.network());
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
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Wownero Wallet")
                    .strong()
                    .size(18.0)
                    .color(ACCENT),
            );
            ui.label(RichText::new("BETA").small().strong().color(WARN))
                .on_hover_text(DISCLAIMER);
            if let Some(w) = &self.wallet {
                ui.separator();
                ui.label(RichText::new(w.summary.name.as_str()).strong());
                if w.summary.network != Net::Mainnet {
                    ui.label(RichText::new(w.summary.network.name()).color(WARN));
                }
                if w.summary.view_only {
                    ui.label(RichText::new("view-only").color(WARN));
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some(w) = &self.wallet {
                    node_chip(ui, &w.status);
                }
                if let Some(what) = &self.working {
                    ui.label(what.as_str());
                    ui.spinner();
                }
            });
        });
    }

    fn message_list(&mut self, ui: &mut Ui) {
        let mut dismissed = None;
        for (i, m) in self.messages.iter().enumerate().rev() {
            ui.horizontal(|ui| {
                if ui.small_button("×").clicked() {
                    dismissed = Some(i);
                }
                let color = if m.error {
                    BAD
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
        let in_browser = self.host.in_browser();
        let secure = self.host.secure_page();
        let Some(w) = self.wallet.as_mut() else {
            return;
        };
        let host = &mut *self.host;
        match w.page {
            Page::Overview => overview(ui, w, host),
            Page::Send => send_page(ui, w, host),
            Page::Receive => receive_page(ui, w, host),
            Page::History => {
                ui.heading("History");
                if w.history.is_empty() {
                    ui.label("No transfers yet.");
                } else {
                    history_grid(ui, &w.history, "history");
                }
            }
            Page::Node => {
                ui.heading("Node");
                match &w.status.node {
                    Some(n) => ui.label(format!("In use: {n}")),
                    None => ui.label("No node in use."),
                };
                if let Some(e) = &w.status.node_error {
                    ui.colored_label(BAD, e.as_str());
                }
                let cx = NodeContext {
                    network: w.summary.network,
                    wallet_open: true,
                    in_browser,
                    secure,
                };
                node_picker(ui, &mut self.nodes, &mut self.settings, host, cx);
            }
            Page::Wallet => wallet_settings(ui, w, host, in_browser),
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
        ui.horizontal_wrapped(|ui| {
            let mut tabs = vec![
                (StartTab::Open, "Open"),
                (StartTab::Create, "Create"),
                (StartTab::Restore, "Restore"),
            ];
            if in_browser {
                tabs.push((StartTab::Import, "Import"));
            }
            tabs.push((StartTab::Node, "Node"));
            for (tab, label) in tabs {
                ui.selectable_value(&mut self.start.tab, tab, label);
            }
        });
        ui.separator();
        match self.start.tab {
            StartTab::Open => self.open_tab(ui, in_browser),
            StartTab::Create => self.create_tab(ui),
            StartTab::Restore => self.restore_tab(ui),
            StartTab::Import => self.import_tab(ui),
            StartTab::Node => {
                ui.horizontal(|ui| {
                    ui.label("Network");
                    network_combo(ui, &mut self.settings.network);
                });
                let cx = NodeContext {
                    network: self.settings.network,
                    wallet_open: false,
                    in_browser,
                    secure: self.host.secure_page(),
                };
                node_picker(ui, &mut self.nodes, &mut self.settings, &mut *self.host, cx);
            }
        }
    }

    fn open_tab(&mut self, ui: &mut Ui, in_browser: bool) {
        if !in_browser {
            ui.horizontal(|ui| {
                ui.label("Folder");
                ui.add(
                    TextEdit::singleline(&mut self.start.folder)
                        .hint_text(self.location.as_str())
                        .desired_width(360.0),
                );
                if ui.button("Use").clicked() {
                    self.settings.folder = self.start.folder.trim().to_string();
                    self.host
                        .send(Command::SetFolder(self.settings.folder.clone()));
                }
            });
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
            ui.colored_label(
                WARN,
                "No node chosen yet, so the wallet opens offline. Choose one on the Node tab.",
            );
        }
        if open {
            self.host.send(Command::Open(OpenWallet {
                name: self.start.selected.clone(),
                password: std::mem::take(&mut self.start.password),
                node: self.settings.node.clone(),
            }));
        }
        if let Some(name) = export {
            self.host.send(Command::Export(name));
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
            self.host.send(Command::Create(NewWallet {
                name: f.name.clone(),
                password: f.new_password.clone(),
                network: self.settings.network,
                language: f.language.clone(),
                node: self.settings.node.clone(),
            }));
        }
    }

    fn restore_tab(&mut self, ui: &mut Ui) {
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

        let f = &self.start;
        let words = f.seed.split_whitespace().count();
        if words > 0 && words < 24 {
            ui.colored_label(WARN, format!("{words} words so far; a seed phrase has 25."));
        }
        let height = match f.height.trim().replace([',', '_'], "") {
            h if h.is_empty() => Ok(0),
            h => h
                .parse::<u64>()
                .map_err(|_| "the restore height is a block number".to_string()),
        };
        match &height {
            Err(e) => {
                ui.colored_label(BAD, e.as_str());
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
                self.host.send(Command::Restore(Restore {
                    name: f.name.clone(),
                    password: f.new_password.clone(),
                    network: self.settings.network,
                    seed: f.seed.clone(),
                    passphrase: f.passphrase.clone(),
                    restore_height,
                    node: self.settings.node.clone(),
                }));
            }
        }
    }

    fn import_tab(&mut self, ui: &mut Ui) {
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
            ui.colored_label(BAD, p.as_str());
        }
        let ready = self.start.keys.is_some() && !self.start.name.is_empty() && problem.is_none();
        if ui.add_enabled(ready, Button::new("Import")).clicked() {
            if let Some((_, keys)) = self.start.keys.take() {
                let cache = self.start.cache.take().map(|(_, c)| Bytes(c));
                self.host.send(Command::Import {
                    name: std::mem::take(&mut self.start.name),
                    keys: Bytes(keys),
                    cache,
                });
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
                    self.host.send(Command::Forget(name));
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
        self.now = ctx.input(|i| i.time);
        for event in self.host.receive() {
            self.on_event(event);
        }
        let now = self.now;
        self.messages.retain(|m| m.error || now - m.at < NOTICE_SECS);
        let narrow = ctx.screen_rect().width() < NARROW;

        egui::TopBottomPanel::top("top").show(ctx, |ui| self.top_bar(ui));
        egui::TopBottomPanel::bottom("risk").show(ctx, |ui| {
            ui.add_space(2.0);
            ui.label(RichText::new(DISCLAIMER).small().color(WARN));
            ui.add_space(2.0);
        });
        if !self.messages.is_empty() {
            egui::TopBottomPanel::bottom("messages").show(ctx, |ui| self.message_list(ui));
        }
        if self.wallet.is_some() {
            if narrow {
                egui::TopBottomPanel::top("pages").show(ctx, |ui| self.page_tabs(ui, true));
            } else {
                egui::SidePanel::left("pages")
                    .resizable(false)
                    .exact_width(160.0)
                    .show(ctx, |ui| self.page_tabs(ui, false));
            }
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.set_max_width(900.0);
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

fn overview(ui: &mut Ui, w: &mut WalletView, host: &mut dyn Host) {
    let weak = ui.visuals().weak_text_color();
    ui.add_space(8.0);
    ui.label(RichText::new("Balance").color(weak));
    ui.label(
        RichText::new(format!("{} WOW", format::amount_short(w.status.balance)))
            .size(32.0)
            .strong(),
    );
    if w.status.unlocked != w.status.balance {
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
        ui.colored_label(BAD, e.as_str());
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
            w.page = Page::Node;
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
        history_grid(ui, &w.history[..w.history.len().min(5)], "recent");
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
                    .desired_width(460.0),
            );
            ui.end_row();
            ui.label("");
            match &check {
                AddressCheck::Empty => ui.label(""),
                AddressCheck::Bad(why) => ui.colored_label(BAD, why.as_str()),
                AddressCheck::Standard => ui.colored_label(GOOD, "A standard address."),
                AddressCheck::Subaddress => ui.colored_label(GOOD, "A subaddress."),
                AddressCheck::Integrated(id) => ui.colored_label(
                    GOOD,
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
        ui.colored_label(WARN, why);
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
        ui.colored_label(BAD, e.as_str());
    }
    let too_much = matches!(amount, Ok(Some(a)) if a > unlocked);
    if too_much && unlocked > 0 {
        ui.colored_label(
            BAD,
            format!(
                "That is more than can be spent now: {} WOW.",
                format::amount_short(unlocked)
            ),
        );
    }
    let id_to_subaddress = check == AddressCheck::Subaddress && !d.payment_id.trim().is_empty();
    if id_to_subaddress {
        ui.colored_label(
            BAD,
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
        ui.colored_label(BAD, e.as_str());
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
        address_box(ui, txid);
    }
    let mut dismiss = false;
    if let Some(reasons) = &w.rejected {
        ui.add_space(12.0);
        ui.colored_label(BAD, "The node refused the transaction:");
        for r in reasons {
            ui.label(format!("• {r}"));
        }
        dismiss = ui.button("Dismiss").clicked();
    }
    if dismiss {
        w.rejected = None;
    }
}

fn receive_page(ui: &mut Ui, w: &mut WalletView, host: &mut dyn Host) {
    ui.heading("Receive");
    ui.label("Primary address");
    address_box(ui, &w.summary.address);
    ui.add_space(16.0);
    ui.label("A subaddress gives each payer an address of their own. All of them pay into this wallet.");
    ui.horizontal(|ui| {
        if ui
            .add_enabled(w.subaddress_index > 1, Button::new("<"))
            .clicked()
        {
            w.subaddress_index -= 1;
            host.send(Command::Subaddress(w.subaddress_index));
        }
        ui.label(format!("Subaddress {}", w.subaddress_index));
        if ui
            .add_enabled(w.subaddress_index < MAX_SUBADDRESS, Button::new(">"))
            .clicked()
        {
            w.subaddress_index += 1;
            host.send(Command::Subaddress(w.subaddress_index));
        }
        let shown = matches!(&w.subaddress, Some((i, _)) if *i == w.subaddress_index);
        if !shown && ui.button("Show").clicked() {
            host.send(Command::Subaddress(w.subaddress_index));
        }
    });
    if let Some((index, address)) = &w.subaddress {
        if *index == w.subaddress_index {
            address_box(ui, address);
        }
    }
}

fn wallet_settings(ui: &mut Ui, w: &mut WalletView, host: &mut dyn Host, in_browser: bool) {
    ui.heading("Wallet");
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

    ui.add_space(16.0);
    ui.label(RichText::new("Seed phrase").strong());
    let mut hide = false;
    if w.summary.view_only {
        ui.label("A view-only wallet has no seed phrase.");
    } else if let Some(seed) = &w.seed {
        ui.colored_label(WARN, "Anyone who sees these words can take this wallet's money.");
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
                host.send(Command::ShowSeed {
                    password: std::mem::take(&mut w.seed_password),
                });
            }
        });
    }
    if hide {
        w.seed = None;
    }

    if in_browser {
        ui.add_space(16.0);
        ui.label(RichText::new("Backup").strong());
        ui.label(
            "Download this wallet's keys file and its cache. The keys file is encrypted with the \
             wallet's password. The browser can clear what a site stores, so keep a copy.",
        );
        if ui.button("Export files").clicked() {
            host.send(Command::Export(w.summary.name.clone()));
        }
    }
    ui.add_space(16.0);
    if ui.button("Close wallet").clicked() {
        host.send(Command::Close);
    }
}

/// Where the node picker is shown.
struct NodeContext {
    network: Net,
    wallet_open: bool,
    in_browser: bool,
    secure: bool,
}

/// A node typed in or picked from the public list, each with a Test button.
fn node_picker(
    ui: &mut Ui,
    picker: &mut NodePicker,
    settings: &mut Settings,
    host: &mut dyn Host,
    cx: NodeContext,
) {
    // The public list, fetched the first time it is shown for a network.
    if picker.fetched != Some(cx.network) && !picker.fetching {
        picker.fetched = Some(cx.network);
        picker.fetching = true;
        picker.list.clear();
        host.fetch_nodes(&nodes::list_url(cx.network));
    }
    let use_label = if cx.wallet_open { "Use" } else { "Choose" };

    let mut test = None;
    let mut chosen = None;
    ui.add_space(8.0);
    ui.label(RichText::new("Node address").strong());
    ui.horizontal(|ui| {
        ui.add(
            TextEdit::singleline(&mut picker.input)
                .hint_text(if cx.in_browser {
                    "https://host:port"
                } else {
                    "host:port"
                })
                .desired_width(300.0),
        );
        let valid = NodeAddress::parse(&picker.input).is_ok();
        if ui.add_enabled(valid, Button::new("Test")).clicked() {
            test = Some(picker.input.trim().to_string());
        }
        if ui.add_enabled(valid, Button::new(use_label)).clicked() {
            chosen = Some(picker.input.trim().to_string());
        }
    });
    let input = picker.input.trim().to_string();
    match NodeAddress::parse(&input) {
        Ok(node) => {
            if let Some(why) = node.unreachable_reason(cx.in_browser, cx.secure) {
                ui.colored_label(WARN, why);
            }
        }
        Err(e) if !input.is_empty() => {
            ui.colored_label(BAD, e.as_str());
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

    ui.add_space(16.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Public nodes").strong());
        ui.hyperlink_to("listed by monero.fail", "https://monero.fail/?crypto=wownero");
        if picker.fetching {
            ui.spinner();
        } else if ui.small_button("Reload").clicked() {
            picker.fetched = None;
        }
    });
    if let Some(note) = &picker.note {
        ui.colored_label(WARN, note.as_str());
    }
    ui.label(
        RichText::new(if cx.in_browser {
            "A browser can use a node only if the node allows requests from web pages (CORS), and \
             a page loaded over https can use https nodes only. The Browser column is monero.fail's \
             own check; Test shows what this browser can reach."
        } else {
            "The desktop wallet reaches http:// nodes only, until it speaks TLS. A node you run \
             yourself is the most private choice."
        })
        .small(),
    );
    if !picker.list.is_empty() {
        egui::Grid::new("public-nodes")
            .striped(true)
            .num_columns(5)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                for heading in ["Node", "Height", "Browser", "", ""] {
                    ui.label(RichText::new(heading).strong());
                }
                ui.end_row();
                for node in &picker.list {
                    ui.label(RichText::new(node.url.as_str()).monospace())
                        .on_hover_text(node.country_name.as_deref().unwrap_or("location unknown"));
                    ui.label(node.last_height.map_or_else(String::new, format::grouped));
                    ui.label(if node.web_compatible { "yes" } else { "no" });
                    ui.horizontal(|ui| {
                        if ui.small_button("Test").clicked() {
                            test = Some(node.url.clone());
                        }
                        if ui.small_button(use_label).clicked() {
                            chosen = Some(node.url.clone());
                        }
                    });
                    test_line(ui, picker.tests.get(&node.url), false);
                    ui.end_row();
                }
            });
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
                (BAD, "wrong network: ")
            } else if syncing {
                (WARN, "answers, ")
            } else {
                (GOOD, "works: ")
            };
            ui.colored_label(color, format!("{lead}{}", parts.join(" · ")));
        }
        Some(Test::Done(Err(e))) => {
            if full {
                ui.colored_label(BAD, e.as_str());
            } else {
                ui.colored_label(BAD, "failed").on_hover_text(e.as_str());
            }
        }
    }
}

fn node_chip(ui: &mut Ui, status: &Status) {
    let (color, text) = if status.node_error.is_some() {
        (BAD, "node problem".to_string())
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
        (WARN, format!("syncing{percent}"))
    } else {
        (GOOD, format!("synced at {}", format::grouped(status.scanned)))
    };
    let hover = match (&status.node_error, &status.node) {
        (Some(e), _) => e.clone(),
        (None, Some(node)) => node.clone(),
        (None, None) => "Choose a node on the Node page.".to_string(),
    };
    ui.label(RichText::new(format!("• {text}")).color(color))
        .on_hover_text(hover);
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

fn history_grid(ui: &mut Ui, rows: &[Row], id: &str) {
    egui::Grid::new(id)
        .striped(true)
        .num_columns(5)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            for heading in ["Date (UTC)", "", "Amount (WOW)", "Height", "Transaction"] {
                ui.label(RichText::new(heading).strong());
            }
            ui.end_row();
            for row in rows {
                ui.label(format::timestamp(row.timestamp));
                let color = match row.kind.as_str() {
                    "failed" => BAD,
                    "pending" => WARN,
                    _ if row.incoming => GOOD,
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
                ui.label(
                    row.height
                        .map_or_else(|| "in the pool".to_string(), format::grouped),
                );
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format::elide(&row.txid, 6)).monospace())
                        .on_hover_text(row.txid.as_str());
                    if ui.small_button("Copy").clicked() {
                        ui.ctx().copy_text(row.txid.clone());
                    }
                });
                ui.end_row();
            }
        });
}

/// Selectable, wrapped, read-only text with a Copy button.
fn address_box(ui: &mut Ui, text: &str) {
    let mut shown = text;
    ui.add(
        TextEdit::multiline(&mut shown)
            .code_editor()
            .desired_rows(2)
            .desired_width(f32::INFINITY),
    );
    if ui.button("Copy").clicked() {
        ui.ctx().copy_text(text.to_string());
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
    let problem = name_problem(name);
    if let Some(p) = &problem {
        ui.colored_label(BAD, p.as_str());
    }
    let mismatch = password != confirm;
    if mismatch && !confirm.is_empty() {
        ui.colored_label(BAD, "The passwords do not match.");
    }
    if password.is_empty() {
        ui.colored_label(
            WARN,
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
            ui.set_max_width(480.0);
            add(ui);
        });
}
