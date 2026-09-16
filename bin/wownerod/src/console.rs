//! The interactive console (`specs/09` §4).
//!
//! `specs/09` §4 allows a reduced set of the C++'s commands and asks for the
//! console to be "a thin client over the node's own RPC surface, so there is
//! exactly one implementation of each operation". So it is: every command
//! below calls the handler the RPC server calls, and formats its answer.
//!
//! It runs only when standard input is a terminal and `--non-interactive` was
//! not given, so a node under a service manager never waits on a prompt.
//!
//! A line can be edited as it is typed, and up and down step through the
//! commands typed before. The history is kept in memory only.

use std::io::BufRead;
use std::sync::Arc;

use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use serde_json::{json, Value};
use wow_consensus::constants::DIFFICULTY_TARGET_V2;
use wow_consensus::hardfork::HardFork;
use wow_storage::db::BlockchainDb;

use crate::rpc::{admin, methods, mining, Server};

/// A console command, parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmd {
    Help,
    Status,
    PrintHeight,
    SyncInfo,
    PrintPeerList,
    PrintConnections,
    Diff,
    HardForkInfo,
    PrintPool,
    Bans,
    Ban { host: String, seconds: u64 },
    Unban(String),
    FlushTxpool(Option<String>),
    PopBlocks(u64),
    Save,
    SetLog(String),
    OutPeers(u64),
    InPeers(u64),
    StartMining { address: String, threads: usize },
    StopMining,
    MiningStatus,
    Exit,
}

const HELP: &str = "\
Commands (a subset of the C++ daemon's; see specs/09 §4):
  status                  heights, sync, connections, forks, pool, database
  print_height            the chain height
  sync_info               connections and what each peer reports
  print_pl                the white and gray peer lists
  print_cn                open connections
  diff                    difficulty and network hash rate
  hard_fork_info          the current hard-fork version
  print_pool              transactions in the pool
  bans                    addresses banned
  ban <ip|subnet> [secs]  ban, for a day unless given
  unban <ip|subnet>
  flush_txpool [txid]     drop one transaction, or all of them
  pop_blocks <n>          take n blocks off the tip
  save                    write the pool and flush the database
  set_log <0-4|cat:LEVEL,...>
  out_peers <n>           outgoing connections to keep
  in_peers <n>            incoming connections to allow
  start_mining <address> [threads]
  stop_mining
  mining_status           whether mining, and how fast
  exit                    stop the node";

/// Parse a line. `Ok(None)` for a blank one.
pub fn parse(line: &str) -> Result<Option<Cmd>, String> {
    let mut words = line.split_whitespace();
    let Some(name) = words.next() else {
        return Ok(None);
    };
    let args: Vec<&str> = words.collect();
    let number = |i: usize, what: &str| -> Result<u64, String> {
        args.get(i)
            .ok_or_else(|| format!("{name} needs {what}"))?
            .parse()
            .map_err(|_| format!("{name}: `{}` is not a number", args[i]))
    };
    let cmd = match name {
        "help" => Cmd::Help,
        "status" => Cmd::Status,
        "print_height" => Cmd::PrintHeight,
        "sync_info" => Cmd::SyncInfo,
        "print_pl" => Cmd::PrintPeerList,
        "print_cn" => Cmd::PrintConnections,
        "diff" => Cmd::Diff,
        "hard_fork_info" => Cmd::HardForkInfo,
        "print_pool" | "print_pool_sh" => Cmd::PrintPool,
        "bans" => Cmd::Bans,
        "ban" => Cmd::Ban {
            host: args
                .first()
                .ok_or("ban needs an address or subnet")?
                .to_string(),
            seconds: if args.len() > 1 {
                number(1, "a duration")?
            } else {
                86_400
            },
        },
        "unban" => Cmd::Unban(
            args.first()
                .ok_or("unban needs an address or subnet")?
                .to_string(),
        ),
        "flush_txpool" => Cmd::FlushTxpool(args.first().map(|s| s.to_string())),
        "pop_blocks" => Cmd::PopBlocks(number(0, "a count")?),
        "save" | "save_bc" => Cmd::Save,
        "set_log" => Cmd::SetLog(args.first().ok_or("set_log needs a level")?.to_string()),
        "out_peers" => Cmd::OutPeers(number(0, "a count")?),
        "in_peers" => Cmd::InPeers(number(0, "a count")?),
        "start_mining" => Cmd::StartMining {
            address: args
                .first()
                .ok_or("start_mining needs an address")?
                .to_string(),
            threads: if args.len() > 1 {
                number(1, "a thread count")?.max(1) as usize
            } else {
                1
            },
        },
        "stop_mining" => Cmd::StopMining,
        "mining_status" => Cmd::MiningStatus,
        "exit" | "stop_daemon" => Cmd::Exit,
        other => return Err(format!("unknown command `{other}`; try `help`")),
    };
    Ok(Some(cmd))
}

/// Read commands from standard input on a thread of their own.
///
/// Returns the terminal's mode as the console found it, to be put back when
/// the node stops.
pub fn spawn(server: Arc<Server>) -> crate::signal::TerminalMode {
    let mode = crate::signal::TerminalMode::save();
    let _ = std::thread::Builder::new()
        .name("console".into())
        .spawn(move || match DefaultEditor::new() {
            Ok(editor) => edit(&server, editor),
            Err(e) => {
                wow_log::warn!("global", "the console cannot edit lines: {e}");
                for line in std::io::stdin().lock().lines() {
                    let Ok(line) = line else { break };
                    execute(&server, &line);
                }
            }
        });
    mode
}

/// Commands from the line editor, until input ends.
fn edit(server: &Server, mut editor: DefaultEditor) {
    loop {
        match editor.readline("") {
            Ok(line) => {
                if !line.trim().is_empty() {
                    let _ = editor.add_history_entry(line.as_str());
                }
                execute(server, &line);
            }
            // The editor holds the terminal in raw mode, so Ctrl-C arrives
            // here rather than as the signal that would stop the node.
            Err(ReadlineError::Interrupted) => {
                server.request_stop();
                break;
            }
            Err(_) => break,
        }
    }
}

fn execute(server: &Server, line: &str) {
    match parse(line).and_then(|c| match c {
        Some(cmd) => run(server, cmd),
        None => Ok(String::new()),
    }) {
        Ok(out) if out.is_empty() => {}
        Ok(out) => println!("{out}"),
        Err(e) => eprintln!("{e}"),
    }
}

fn err(e: crate::rpc::methods::RpcError) -> String {
    e.message
}

fn s(v: &Value, key: &str) -> String {
    match &v[key] {
        Value::String(x) => x.clone(),
        Value::Null => "-".into(),
        other => other.to_string(),
    }
}

/// Run a command against the node's RPC handlers.
pub fn run(server: &Server, cmd: Cmd) -> Result<String, String> {
    Ok(match cmd {
        Cmd::Help => HELP.to_string(),
        Cmd::Status => status(server)?,
        Cmd::PrintHeight => server.db().height().to_string(),
        Cmd::SyncInfo => {
            let v = admin::sync_info(server).map_err(err)?;
            let mut out = format!(
                "Height: {}, target: {}",
                s(&v, "height"),
                s(&v, "target_height")
            );
            for p in v["peers"].as_array().into_iter().flatten() {
                let c = &p["info"];
                out.push_str(&format!(
                    "\n{:<22} {:<8} height {:<8} {}",
                    s(c, "address"),
                    if c["incoming"] == true { "in" } else { "out" },
                    s(c, "height"),
                    s(c, "state"),
                ));
            }
            out
        }
        Cmd::PrintPeerList => {
            let v = admin::get_peer_list(server).map_err(err)?;
            let mut out = String::new();
            for (list, name) in [("white_list", "white"), ("gray_list", "gray")] {
                for p in v[list].as_array().into_iter().flatten() {
                    out.push_str(&format!(
                        "{name:<6} {}:{:<6} last seen {}\n",
                        s(p, "host"),
                        s(p, "port"),
                        s(p, "last_seen")
                    ));
                }
            }
            if out.is_empty() {
                "the peer lists are empty".into()
            } else {
                out.trim_end().to_string()
            }
        }
        Cmd::PrintConnections => {
            let v = admin::get_connections(server).map_err(err)?;
            let conns = v["connections"].as_array().cloned().unwrap_or_default();
            if conns.is_empty() {
                return Ok("no connections".into());
            }
            conns
                .iter()
                .map(|c| {
                    format!(
                        "{:<22} {:<4} id {} height {:<8} {} live {}s recv {} sent {}",
                        s(c, "address"),
                        if c["incoming"] == true { "in" } else { "out" },
                        s(c, "peer_id"),
                        s(c, "height"),
                        s(c, "state"),
                        s(c, "live_time"),
                        s(c, "recv_count"),
                        s(c, "send_count"),
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
        Cmd::Diff => {
            let i = methods::get_info(server).map_err(err)?;
            let d = i["difficulty"].as_u64().unwrap_or(0);
            format!(
                "BH: {}, TH: {}, DIFF: {}, CUM_DIFF: {}, HR: {:.2} H/s",
                s(&i, "height"),
                s(&i, "top_block_hash"),
                s(&i, "wide_difficulty"),
                s(&i, "wide_cumulative_difficulty"),
                d as f64 / wow_consensus::constants::DIFFICULTY_TARGET_V2 as f64
            )
        }
        Cmd::HardForkInfo => {
            let v =
                methods::hard_fork_info(server.db(), server.config(), &json!({})).map_err(err)?;
            format!(
                "version {} {}, earliest height {}",
                s(&v, "version"),
                if v["enabled"] == true {
                    "enabled"
                } else {
                    "not enabled"
                },
                s(&v, "earliest_height")
            )
        }
        Cmd::PrintPool => {
            let v = admin::get_transaction_pool(server).map_err(err)?;
            let txs = v["transactions"].as_array().cloned().unwrap_or_default();
            if txs.is_empty() {
                return Ok("the pool is empty".into());
            }
            txs.iter()
                .map(|t| {
                    format!(
                        "{} weight {} fee {} received {}{}",
                        s(t, "id_hash"),
                        s(t, "weight"),
                        s(t, "fee"),
                        s(t, "receive_time"),
                        if t["relayed"] == true {
                            ""
                        } else {
                            " (not relayed)"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
        Cmd::Bans => {
            let v = admin::get_bans(server).map_err(err)?;
            let bans = v["bans"].as_array().cloned().unwrap_or_default();
            if bans.is_empty() {
                return Ok("no bans".into());
            }
            bans.iter()
                .map(|b| format!("{} for {}s more", s(b, "host"), s(b, "seconds")))
                .collect::<Vec<_>>()
                .join("\n")
        }
        Cmd::Ban { host, seconds } => {
            admin::set_bans(
                server,
                &json!({"bans": [{"host": host, "ban": true, "seconds": seconds}]}),
            )
            .map_err(err)?;
            format!("banned {host} for {seconds}s")
        }
        Cmd::Unban(host) => {
            admin::set_bans(
                server,
                &json!({"bans": [{"host": host, "ban": false, "seconds": 0}]}),
            )
            .map_err(err)?;
            format!("unbanned {host}")
        }
        Cmd::FlushTxpool(id) => {
            let params = match &id {
                Some(id) => json!({ "txids": [id] }),
                None => json!({}),
            };
            admin::flush_txpool(server, &params).map_err(err)?;
            "pool flushed".into()
        }
        Cmd::PopBlocks(n) => {
            let body = json!({ "nblocks": n }).to_string();
            let v = admin::pop_blocks(server, body.as_bytes()).map_err(err)?;
            format!("height is now {}", s(&v, "height"))
        }
        Cmd::Save => {
            admin::save_bc(server).map_err(err)?;
            "saved".into()
        }
        Cmd::SetLog(spec) => {
            wow_log::configure(&spec)?;
            format!("log categories: {}", wow_log::categories())
        }
        Cmd::OutPeers(n) => {
            let body = json!({ "out_peers": n }).to_string();
            let v = admin::out_peers(server, body.as_bytes()).map_err(err)?;
            format!("out_peers {}", s(&v, "out_peers"))
        }
        Cmd::InPeers(n) => {
            let body = json!({ "in_peers": n }).to_string();
            let v = admin::in_peers(server, body.as_bytes()).map_err(err)?;
            format!("in_peers {}", s(&v, "in_peers"))
        }
        Cmd::StartMining { address, threads } => {
            mining::start(server, &address, threads).map_err(err)?;
            format!("mining to {address} on {threads} thread(s)")
        }
        Cmd::StopMining => {
            mining::stop_mining(server).map_err(err)?;
            "mining stopped".into()
        }
        Cmd::MiningStatus => {
            let v = mining::mining_status(server).map_err(err)?;
            if v["active"] == true {
                format!(
                    "mining at {} H/s on {} thread(s) to {}",
                    s(&v, "speed"),
                    s(&v, "threads_count"),
                    s(&v, "address")
                )
            } else {
                "not mining".into()
            }
        }
        Cmd::Exit => {
            admin::stop_daemon(server).map_err(err)?;
            "stopping".into()
        }
    })
}

/// `status`: what `get_info` says, and what the node knows beside it, as a
/// table.
fn status(server: &Server) -> Result<String, String> {
    let i = methods::get_info(server).map_err(err)?;
    let height = i["height"].as_u64().unwrap_or(0);
    let target = i["target_height"].as_u64().unwrap_or(0).max(height);
    let difficulty = i["difficulty"].as_u64().unwrap_or(0);
    let (outgoing, incoming) = (
        i["outgoing_connections_count"].as_u64().unwrap_or(0),
        i["incoming_connections_count"].as_u64().unwrap_or(0),
    );
    let hf = HardFork::new(server.config().network);
    let uptime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_sub(server.start_time());
    let mining = match server.miner().as_ref().map(crate::miner::Miner::status) {
        Some(m) if m.active => format!("{} on {} thread(s)", hashrate(m.speed as f64), m.threads),
        _ => "No".into(),
    };

    // The speed and what is left of the wait, while there is a wait. An
    // operator watching a sync wants to know whether to come back in ten
    // minutes or tomorrow, and the height alone does not say.
    let rate = (height < target)
        .then(|| server.core().and_then(crate::node::NodeCore::blocks_per_second))
        .flatten();
    let mut rows: Vec<(&str, String)> = vec![
        ("Local Height", height.to_string()),
        ("Network Height", target.to_string()),
        ("Percentage Synced", percent_synced(height, target)),
    ];
    if let Some(rate) = rate {
        rows.push(("Sync Speed", format!("{rate:.1} blocks/s")));
        let left = ((target - height) as f64 / rate).round() as u64;
        rows.push(("Time Left", uptime_text(left)));
    }
    rows.extend([
        (
            "Sync Status",
            if i["offline"] == true {
                "Offline"
            } else if i["synchronized"] == true {
                "Synchronised"
            } else if outgoing + incoming == 0 {
                "Waiting for peers"
            } else {
                "Syncing"
            }
            .into(),
        ),
        ("Network", s(&i, "nettype")),
        (
            "Network Hashrate",
            hashrate(difficulty as f64 / DIFFICULTY_TARGET_V2 as f64),
        ),
        ("Difficulty", difficulty.to_string()),
        (
            "Block Version",
            format!("v{}", hf.required_version(height.saturating_sub(1))),
        ),
        ("Next Fork", next_fork(&hf, height)),
        ("Incoming Connections", incoming.to_string()),
        ("Outgoing Connections", outgoing.to_string()),
        (
            "Peer List (White/Grey)",
            format!(
                "{} / {}",
                s(&i, "white_peerlist_size"),
                s(&i, "grey_peerlist_size")
            ),
        ),
        ("RPC Connections", s(&i, "rpc_connections_count")),
        ("Uptime", uptime_text(uptime)),
        ("Transaction Pool Size", s(&i, "tx_pool_size")),
        ("Alternative Block Count", s(&i, "alt_blocks_count")),
        ("DB Engine", "LMDB".into()),
        (
            "Database Size",
            bytes(i["database_size"].as_u64().unwrap_or(0)),
        ),
        // `--prune-blockchain` is refused at start (`cli.rs`).
        ("Pruned Node", "No".into()),
        ("Mining", mining),
        ("wownero-rs Version", env!("CARGO_PKG_VERSION").into()),
    ]);
    Ok(table(&rows))
}

/// Rows as a two-column table, each column as wide as its widest cell.
fn table(rows: &[(&str, String)]) -> String {
    let key = rows
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    let value = rows
        .iter()
        .map(|(_, v)| v.chars().count())
        .max()
        .unwrap_or(0);
    let rule = "-".repeat(key + value + 7);
    let mut out = rule.clone();
    for (k, v) in rows {
        out.push_str(&format!("\n| {k:<key$} | {v:<value$} |"));
    }
    out.push('\n');
    out.push_str(&rule);
    out
}

/// Truncated, not rounded, so a node a block behind never reads `100.00%`.
fn percent_synced(height: u64, target: u64) -> String {
    if target == 0 || height >= target {
        return "100.00%".into();
    }
    let hundredths = height as u128 * 10_000 / target as u128;
    format!("{}.{:02}%", hundredths / 100, hundredths % 100)
}

fn hashrate(per_second: f64) -> String {
    const UNITS: [&str; 5] = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s"];
    let (mut v, mut unit) = (per_second, 0);
    while v >= 1000.0 && unit + 1 < UNITS.len() {
        v /= 1000.0;
        unit += 1;
    }
    format!("{v:.2} {}", UNITS[unit])
}

fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let (mut v, mut unit) = (n as f64, 0);
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{v:.2} {}", UNITS[unit])
    }
}

/// `1d 4h 12m 30s`. Used for the uptime and for how much of a sync is left.
fn uptime_text(secs: u64) -> String {
    format!(
        "{}d {}h {}m {}s",
        secs / 86_400,
        secs / 3_600 % 24,
        secs / 60 % 60,
        secs % 60
    )
}

/// The first fork in the node's table that the chain, `height` blocks long,
/// has not reached yet.
fn next_fork(hf: &HardFork, height: u64) -> String {
    let current = hf.required_version(height.saturating_sub(1));
    match hf
        .forks()
        .iter()
        .find(|f| f.version > current && f.height >= height)
    {
        None => "None scheduled".into(),
        Some(f) if f.height == height => format!("v{} with the next block", f.version),
        Some(f) => format!(
            "v{} at {} ({:.2} Days)",
            f.version,
            f.height,
            ((f.height - height) * DIFFICULTY_TARGET_V2) as f64 / 86_400.0
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_rows_line_up_in_a_table() {
        let t = table(&[
            ("Local Height", "4221105".into()),
            ("Uptime", "1d 11h 41m 42s".into()),
        ]);
        assert_eq!(
            t,
            "\
---------------------------------
| Local Height | 4221105        |
| Uptime       | 1d 11h 41m 42s |
---------------------------------"
        );
        assert!(t.lines().all(|l| l.len() == 33), "{t}");
    }

    #[test]
    fn status_values_read_in_sensible_units() {
        assert_eq!(percent_synced(0, 0), "100.00%");
        assert_eq!(percent_synced(10, 5), "100.00%");
        assert_eq!(percent_synced(999_999, 1_000_000), "99.99%");
        assert_eq!(percent_synced(63_300, 873_597), "7.24%");

        assert_eq!(hashrate(0.0), "0.00 H/s");
        assert_eq!(hashrate(990_700.0), "990.70 KH/s");
        assert_eq!(hashrate(2_500_000.0), "2.50 MH/s");

        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(5 * 1024 * 1024 * 1024), "5.00 GiB");

        assert_eq!(uptime_text(128_502), "1d 11h 41m 42s");
    }

    #[test]
    fn the_next_fork_is_the_first_the_chain_has_not_reached() {
        let testnet = HardFork::new(wow_types::Network::Testnet);
        // 41 blocks: the tip is on v15, v16 activates at 45.
        assert_eq!(next_fork(&testnet, 41), "v16 at 45 (0.01 Days)");
        // 45 blocks: block 45, the next one, is v16's first.
        assert_eq!(next_fork(&testnet, 45), "v16 with the next block");
        assert_eq!(next_fork(&testnet, 71), "None scheduled");
        assert_eq!(
            next_fork(&HardFork::new(wow_types::Network::Mainnet), 800_000),
            "None scheduled"
        );
    }

    #[test]
    fn commands_parse_with_their_arguments() {
        assert_eq!(parse("").unwrap(), None);
        assert_eq!(parse("   ").unwrap(), None);
        assert_eq!(parse("status").unwrap(), Some(Cmd::Status));
        assert_eq!(
            parse("ban 1.2.3.4").unwrap(),
            Some(Cmd::Ban {
                host: "1.2.3.4".into(),
                seconds: 86_400
            })
        );
        assert_eq!(
            parse("ban 10.0.0.0/8 60").unwrap(),
            Some(Cmd::Ban {
                host: "10.0.0.0/8".into(),
                seconds: 60
            })
        );
        assert_eq!(parse("pop_blocks 3").unwrap(), Some(Cmd::PopBlocks(3)));
        assert_eq!(parse("flush_txpool").unwrap(), Some(Cmd::FlushTxpool(None)));
        assert_eq!(parse("save_bc").unwrap(), Some(Cmd::Save));
        assert_eq!(parse("exit").unwrap(), Some(Cmd::Exit));
        assert_eq!(
            parse("start_mining WWabc 2").unwrap(),
            Some(Cmd::StartMining {
                address: "WWabc".into(),
                threads: 2
            })
        );
        assert_eq!(
            parse("start_mining WWabc").unwrap(),
            Some(Cmd::StartMining {
                address: "WWabc".into(),
                threads: 1
            })
        );
        assert!(parse("start_mining").unwrap_err().contains("address"));

        assert!(parse("pop_blocks").unwrap_err().contains("needs"));
        assert!(parse("pop_blocks many")
            .unwrap_err()
            .contains("not a number"));
        assert!(parse("frobnicate").unwrap_err().contains("help"));
    }

    /// Every command the help names parses, so the two cannot drift apart.
    #[test]
    fn the_help_lists_only_real_commands() {
        for line in HELP.lines().skip(1) {
            let Some(name) = line.split_whitespace().next() else {
                continue;
            };
            let sample = match name {
                "ban" | "unban" => format!("{name} 1.2.3.4"),
                "pop_blocks" | "out_peers" | "in_peers" => format!("{name} 1"),
                "set_log" => format!("{name} 0"),
                "start_mining" => format!("{name} WWabc"),
                _ => name.to_string(),
            };
            assert!(parse(&sample).is_ok(), "help names `{name}`");
        }
    }
}
