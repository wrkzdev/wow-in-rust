//! The interactive console (`specs/09` §4).
//!
//! `specs/09` §4 allows a reduced set of the C++'s commands and asks for the
//! console to be "a thin client over the node's own RPC surface, so there is
//! exactly one implementation of each operation". So it is: every command
//! below calls the handler the RPC server calls, and formats its answer.
//!
//! It runs only when standard input is a terminal and `--non-interactive` was
//! not given, so a node under a service manager never waits on a prompt.

use std::io::BufRead;
use std::sync::Arc;

use serde_json::{json, Value};
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
  status                  height, sync state, connections
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
pub fn spawn(server: Arc<Server>) {
    let _ = std::thread::Builder::new()
        .name("console".into())
        .spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else { break };
                match parse(&line).and_then(|c| match c {
                    Some(cmd) => run(&server, cmd),
                    None => Ok(String::new()),
                }) {
                    Ok(out) if out.is_empty() => {}
                    Ok(out) => println!("{out}"),
                    Err(e) => eprintln!("{e}"),
                }
            }
        });
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
        Cmd::Status => {
            let i = methods::get_info(server).map_err(err)?;
            let height = i["height"].as_u64().unwrap_or(0);
            let target = i["target_height"].as_u64().unwrap_or(0).max(height);
            let percent = if target == 0 {
                100.0
            } else {
                height as f64 * 100.0 / target as f64
            };
            let difficulty = i["difficulty"].as_u64().unwrap_or(0);
            let uptime = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .saturating_sub(server.start_time());
            format!(
                "Height: {height}/{target} ({percent:.1}%) on {}, {}, net hash {:.2} H/s, \
                 {}(out)+{}(in) connections, uptime {}d {}h {}m {}s",
                s(&i, "nettype"),
                if i["synchronized"] == true {
                    "synchronised"
                } else {
                    "not synchronised"
                },
                difficulty as f64 / wow_consensus::constants::DIFFICULTY_TARGET_V2 as f64,
                i["outgoing_connections_count"],
                i["incoming_connections_count"],
                uptime / 86_400,
                uptime / 3_600 % 24,
                uptime / 60 % 60,
                uptime % 60,
            )
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
