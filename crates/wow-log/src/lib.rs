//! Levelled, categorised logging (`specs/09` §8).
//!
//! The C++ logs through easylogging with per-category levels, configured as
//! `--log-level <0-4>` or a list like `net.p2p:DEBUG,*:WARNING`. `specs/09` §8
//! asks a Rust node to accept that syntax "for operator familiarity", so this
//! does: [`set_level`] takes the five presets and [`set_categories`] the list.
//!
//! It is a crate of its own, with no dependencies, because the node's crates,
//! the wallet's and the binaries all log, and none should depend on another for
//! it.
//!
//! ```
//! wow_log::info!("global", "listening on {}", 34567);
//! ```
//!
//! # Matching
//!
//! A rule's category is a name, a prefix ending in `*` (`net.*`), or `*`.
//! Rules are applied in order and the **last** one that matches a category
//! decides its level, so `*:WARNING,net.p2p:DEBUG` quietens everything except
//! the peer-to-peer layer.
//!
//! # Where lines go
//!
//! To stderr unless told otherwise ([`set_stderr`]), to a rotating file
//! ([`set_file`]), and to memory, for a program that shows its own log
//! ([`set_memory`], [`recent`]).

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fmt;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::Duration;

/// Severity, most severe first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Fatal = 1,
    Error = 2,
    Warning = 3,
    Info = 4,
    Debug = 5,
    Trace = 6,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        Some(match s.trim().to_ascii_uppercase().as_str() {
            "FATAL" => Level::Fatal,
            "ERROR" => Level::Error,
            "WARNING" | "WARN" => Level::Warning,
            "INFO" => Level::Info,
            "DEBUG" => Level::Debug,
            "TRACE" => Level::Trace,
            _ => return None,
        })
    }

    fn tag(self) -> &'static str {
        match self {
            Level::Fatal => "FATAL",
            Level::Error => "ERROR",
            Level::Warning => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }
}

/// The C++ presets for `--log-level 0..4` (`src/common/util.cpp`,
/// `mlog_set_log_level`), trimmed to the categories this implementation uses.
pub const PRESETS: [&str; 5] = [
    "*:WARNING,global:INFO",
    "*:INFO,global:INFO",
    "*:DEBUG",
    "*:TRACE,*.dump:DEBUG",
    "*:TRACE",
];

/// The longest line kept in memory, in bytes; a longer one is cut. A dump
/// category can put a whole block's bytes on one line.
const MAX_KEPT_LINE: usize = 1_000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Rule {
    pattern: String,
    level: Level,
}

impl Rule {
    fn matches(&self, category: &str) -> bool {
        match self.pattern.strip_suffix('*') {
            Some(prefix) => category.starts_with(prefix),
            None => self.pattern == category,
        }
    }
}

/// A log file and its rotation policy (`--log-file`, `--max-log-file-size`,
/// `--max-log-files`).
struct FileSink {
    path: PathBuf,
    file: std::fs::File,
    written: u64,
    max_size: u64,
    max_files: usize,
}

struct Config {
    rules: Vec<Rule>,
    also_stderr: bool,
}

/// The last lines written, for a program to show.
struct Memory {
    lines: VecDeque<String>,
    cap: usize,
}

fn config() -> &'static RwLock<Config> {
    static CONFIG: OnceLock<RwLock<Config>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        RwLock::new(Config {
            rules: parse_rules(PRESETS[0]).expect("the preset parses"),
            also_stderr: true,
        })
    })
}

fn sink() -> &'static Mutex<Option<FileSink>> {
    static SINK: OnceLock<Mutex<Option<FileSink>>> = OnceLock::new();
    SINK.get_or_init(|| Mutex::new(None))
}

fn memory() -> &'static Mutex<Memory> {
    static MEMORY: OnceLock<Mutex<Memory>> = OnceLock::new();
    MEMORY.get_or_init(|| {
        Mutex::new(Memory {
            lines: VecDeque::new(),
            cap: 0,
        })
    })
}

fn parse_rules(spec: &str) -> Result<Vec<Rule>, String> {
    let mut rules = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (pattern, level) = part
            .rsplit_once(':')
            .ok_or_else(|| format!("`{part}` is not category:LEVEL"))?;
        let level = Level::parse(level).ok_or_else(|| format!("`{level}` is not a log level"))?;
        if pattern.trim().is_empty() {
            return Err(format!("`{part}` has no category"));
        }
        rules.push(Rule {
            pattern: pattern.trim().to_string(),
            level,
        });
    }
    Ok(rules)
}

/// `--log-level <0-4>`.
pub fn set_level(level: u8) -> Result<(), String> {
    let preset = PRESETS
        .get(usize::from(level))
        .ok_or_else(|| format!("log level {level} is not 0-4"))?;
    set_categories(preset)
}

/// `--log-level <category:LEVEL,...>`, replacing the current rules.
///
/// A leading `+` adds to the current rules instead, as the C++'s `set_log`
/// console command does.
pub fn set_categories(spec: &str) -> Result<(), String> {
    let (append, spec) = match spec.strip_prefix('+') {
        Some(rest) => (true, rest),
        None => (false, spec),
    };
    let rules = parse_rules(spec)?;
    let mut c = config().write().unwrap_or_else(|e| e.into_inner());
    if append {
        c.rules.extend(rules);
    } else {
        c.rules = rules;
    }
    Ok(())
}

/// Either form `--log-level` accepts: a digit, or a category list.
pub fn configure(spec: &str) -> Result<(), String> {
    match spec.trim().parse::<u8>() {
        Ok(n) => set_level(n),
        Err(_) => set_categories(spec),
    }
}

/// The rules in force, in the `category:LEVEL` form they were given in.
pub fn categories() -> String {
    let c = config().read().unwrap_or_else(|e| e.into_inner());
    c.rules
        .iter()
        .map(|r| format!("{}:{}", r.pattern, r.level.tag()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Send log lines to a file as well, rotating at `max_size` bytes and keeping
/// `max_files` old files. With `quiet`, stop writing to stderr.
pub fn set_file(path: PathBuf, max_size: u64, max_files: usize, quiet: bool) -> Result<(), String> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("cannot open log file {}: {e}", path.display()))?;
    let written = file.metadata().map(|m| m.len()).unwrap_or(0);
    *sink().lock().unwrap_or_else(|e| e.into_inner()) = Some(FileSink {
        path,
        file,
        written,
        max_size,
        max_files,
    });
    config()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .also_stderr = !quiet;
    Ok(())
}

/// Stop writing to the log file [`set_file`] opened, if any.
pub fn close_file() {
    *sink().lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// The file [`set_file`] opened, while it is open.
pub fn file() -> Option<PathBuf> {
    sink()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|s| s.path.clone())
}

/// Stop or start writing lines to stderr. A program whose terminal is its
/// interface, like the wallet's prompt, keeps its log off it.
pub fn set_stderr(on: bool) {
    config()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .also_stderr = on;
}

/// Keep the last `lines` lines in memory as well, for a program that shows its
/// own log: a GUI's log window. Zero keeps none, and forgets those kept.
pub fn set_memory(lines: usize) {
    let mut m = memory().lock().unwrap_or_else(|e| e.into_inner());
    m.cap = lines;
    while m.lines.len() > lines {
        m.lines.pop_front();
    }
}

/// The lines kept in memory, oldest first, without their line breaks.
pub fn recent() -> Vec<String> {
    memory()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .lines
        .iter()
        .cloned()
        .collect()
}

/// Forget the lines kept in memory, and go on keeping new ones.
pub fn clear_recent() {
    memory()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .lines
        .clear();
}

/// `mlog_get_default_log_path`: a log file named `name` in the program's own
/// directory, or in the current one when that cannot be found.
pub fn beside_program(name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(name)))
        .unwrap_or_else(|| PathBuf::from(name))
}

/// Whether a line at `level` in `category` would be written. The macros check
/// this first so a disabled line costs no formatting.
pub fn enabled(category: &str, level: Level) -> bool {
    let c = config().read().unwrap_or_else(|e| e.into_inner());
    let allowed = c
        .rules
        .iter()
        .rev()
        .find(|r| r.matches(category))
        .map(|r| r.level)
        .unwrap_or(Level::Warning);
    level <= allowed
}

/// Write one line. Use the macros instead, which skip disabled lines.
pub fn log(category: &str, level: Level, args: fmt::Arguments<'_>) {
    let line = format!(
        "{}\t{}\t{}\t{}\n",
        timestamp(now()),
        level.tag(),
        category,
        args
    );
    let also_stderr = config().read().map(|c| c.also_stderr).unwrap_or(true);
    if also_stderr {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }

    keep(&line);

    let mut guard = sink().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = guard.as_mut() {
        if s.max_size > 0 && s.written + line.len() as u64 > s.max_size {
            rotate(s);
        }
        if s.file.write_all(line.as_bytes()).is_ok() {
            s.written += line.len() as u64;
        }
    }
}

/// Keep a line in memory, when lines are kept.
fn keep(line: &str) {
    let mut m = memory().lock().unwrap_or_else(|e| e.into_inner());
    if m.cap == 0 {
        return;
    }
    let mut kept = line.trim_end_matches('\n').to_string();
    if kept.len() > MAX_KEPT_LINE {
        let mut cut = MAX_KEPT_LINE;
        while !kept.is_char_boundary(cut) {
            cut -= 1;
        }
        kept.truncate(cut);
        kept.push('…');
    }
    if m.lines.len() >= m.cap {
        m.lines.pop_front();
    }
    m.lines.push_back(kept);
}

/// Rename the current file aside with a timestamp, start a new one, and drop
/// the oldest rotated files past the limit.
fn rotate(s: &mut FileSink) {
    let stamp = timestamp(now()).replace([' ', ':'], "-").replace('.', "-");
    let mut aside = s.path.clone().into_os_string();
    aside.push(format!("-{stamp}"));
    let _ = std::fs::rename(&s.path, &aside);

    if let Ok(f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&s.path)
    {
        s.file = f;
        s.written = 0;
    }

    let (Some(dir), Some(name)) = (s.path.parent(), s.path.file_name()) else {
        return;
    };
    let dir = if dir.as_os_str().is_empty() {
        std::path::Path::new(".")
    } else {
        dir
    };
    let prefix = format!("{}-", name.to_string_lossy());
    let mut old: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .map(|n| n.to_string_lossy().starts_with(&prefix))
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default();
    old.sort();
    while old.len() > s.max_files {
        let _ = std::fs::remove_file(old.remove(0));
    }
}

/// The clock a program gave, for where std has none ([`set_clock`]).
static CLOCK: OnceLock<fn() -> Duration> = OnceLock::new();

/// Give the log a clock, as the time since 1970, where std has none to read:
/// a bare wasm target, in a browser, where every line would otherwise say
/// 1970. The first clock given stays. Everywhere else std's clock is read and
/// this changes nothing.
pub fn set_clock(clock: fn() -> Duration) {
    let _ = CLOCK.set(clock);
}

/// The time a line is stamped with.
///
/// A bare wasm target has no clock std can read -- `SystemTime::now` panics
/// there -- and a wallet built for a browser links this crate, so its lines
/// carry the clock the program gave, or the epoch rather than bring the wallet
/// down.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn now() -> std::time::SystemTime {
    std::time::SystemTime::now()
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn now() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + CLOCK.get().map_or(Duration::ZERO, |clock| clock())
}

/// `YYYY-MM-DD hh:mm:ss.mmm`, UTC.
pub fn timestamp(t: std::time::SystemTime) -> String {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (y, m, day) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{day:02} {:02}:{:02}:{:02}.{:03}",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60,
        d.subsec_millis()
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[macro_export]
macro_rules! log_at {
    ($level:expr, $cat:expr, $($arg:tt)*) => {
        if $crate::enabled($cat, $level) {
            $crate::log($cat, $level, format_args!($($arg)*))
        }
    };
}

#[macro_export]
macro_rules! error {
    ($cat:expr, $($arg:tt)*) => { $crate::log_at!($crate::Level::Error, $cat, $($arg)*) };
}

#[macro_export]
macro_rules! warn {
    ($cat:expr, $($arg:tt)*) => { $crate::log_at!($crate::Level::Warning, $cat, $($arg)*) };
}

#[macro_export]
macro_rules! info {
    ($cat:expr, $($arg:tt)*) => { $crate::log_at!($crate::Level::Info, $cat, $($arg)*) };
}

#[macro_export]
macro_rules! debug {
    ($cat:expr, $($arg:tt)*) => { $crate::log_at!($crate::Level::Debug, $cat, $($arg)*) };
}

#[macro_export]
macro_rules! trace {
    ($cat:expr, $($arg:tt)*) => { $crate::log_at!($crate::Level::Trace, $cat, $($arg)*) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test touches the global configuration, so the assertions that
    /// depend on it cannot race each other.
    #[test]
    fn levels_and_categories_follow_the_cpp_syntax() {
        set_level(0).unwrap();
        assert!(
            enabled("global", Level::Info),
            "level 0 still shows global info"
        );
        assert!(!enabled("net.p2p", Level::Info));
        assert!(enabled("net.p2p", Level::Warning));

        set_categories("*:WARNING,net.*:DEBUG").unwrap();
        assert!(enabled("net.p2p", Level::Debug), "a prefix rule");
        assert!(!enabled("blockchain", Level::Info));

        // The last matching rule wins.
        set_categories("net.p2p:TRACE,net.*:ERROR").unwrap();
        assert!(!enabled("net.p2p", Level::Warning));

        // `+` appends.
        set_categories("+net.p2p:INFO").unwrap();
        assert!(enabled("net.p2p", Level::Info));
        assert!(categories().ends_with("net.p2p:INFO"), "{}", categories());

        configure("4").unwrap();
        assert!(enabled("anything", Level::Trace));

        assert!(set_level(5).is_err());
        assert!(set_categories("net.p2p").is_err());
        assert!(set_categories("net.p2p:LOUD").is_err());
        configure("0").unwrap();
    }

    /// The only test that writes lines, so what memory holds is its own.
    #[test]
    fn the_last_lines_are_kept_in_memory() {
        set_stderr(false);
        set_memory(3);
        clear_recent();
        for i in 0..5 {
            log("test.memory", Level::Info, format_args!("line {i}"));
        }
        let kept = recent();
        assert_eq!(kept.len(), 3, "{kept:?}");
        assert!(kept[0].ends_with("\tINFO\ttest.memory\tline 2"), "{kept:?}");
        assert!(kept[2].ends_with("line 4"), "{kept:?}");

        // A line past the limit is cut on a character, and says so.
        log(
            "test.memory",
            Level::Info,
            format_args!("{}", "é".repeat(800)),
        );
        let long = recent().pop().expect("a line");
        assert!(long.ends_with('…'), "{long}");
        assert!(
            long.len() <= MAX_KEPT_LINE + '…'.len_utf8(),
            "{}",
            long.len()
        );

        clear_recent();
        assert!(recent().is_empty());
        set_memory(0);
        log("test.memory", Level::Info, format_args!("not kept"));
        assert!(recent().is_empty());
        set_stderr(true);
    }

    #[test]
    fn a_default_log_file_sits_beside_the_program() {
        let p = beside_program("wownero-wallet-cli.log");
        assert_eq!(
            p.file_name().and_then(|n| n.to_str()),
            Some("wownero-wallet-cli.log")
        );
        if let Ok(exe) = std::env::current_exe() {
            assert_eq!(p.parent(), exe.parent());
        }
    }

    #[test]
    fn timestamps_are_utc_calendar_dates() {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_757_764_496_789);
        assert_eq!(timestamp(t), "2025-09-13 11:54:56.789");
        assert_eq!(timestamp(std::time::UNIX_EPOCH), "1970-01-01 00:00:00.000");
        // A leap day.
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(951_782_400);
        assert_eq!(timestamp(t), "2000-02-29 00:00:00.000");
    }
}
