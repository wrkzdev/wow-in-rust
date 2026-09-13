//! `wownerod` — the Wownero node.
//!
//! The binary name is fixed by `specs/00-overview.md` §8 and must stay exactly
//! `wownerod`.
//!
//! # What this build does
//!
//! `specs/10-storage-lmdb.md` §7 calls opening an existing `data.mdb` "the
//! payoff" and asks for it to be "a first-class, documented workflow". That is
//! what this is: it opens a database the C++ node wrote, checks it is the one
//! you meant, and verifies the difficulty chain against it.
//!
//! ```sh
//! # safe against a running C++ node
//! wownerod --data-dir ~/.wownero --db-readonly --check-difficulty-checkpoints
//! ```
//!
//! `--serve` runs the node: peer-to-peer sync, serving peers, relay, the
//! transaction pool and RPC ([`serve`]), and mines ([`miner`]). Options for
//! what is not built are **refused** rather than accepted and ignored (see
//! [`cli::NOT_IMPLEMENTED`]).
//!
//! `deny`, not `forbid`, for `unsafe`: [`signal`] installs the Ctrl-C and
//! `SIGTERM` handlers, which takes a platform call, and is the only module
//! allowed one.

#![deny(unsafe_code)]

mod cli;
mod console;
mod inspect;
mod mempool;
mod miner;
mod netsync;
mod node;
mod rpc;
mod serve;
mod signal;
mod template;
mod zmq;

use std::process::ExitCode;

use cli::{Command, ParseOutcome};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args = match cli::with_config_file(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("wownerod: {e}");
            return ExitCode::FAILURE;
        }
    };
    match cli::parse(args) {
        ParseOutcome::Print(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        ParseOutcome::Error(e) => {
            eprintln!("wownerod: {e}");
            ExitCode::FAILURE
        }
        ParseOutcome::Run(cfg) => match run(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("wownerod: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

fn run(cfg: &cli::Config) -> Result<(), String> {
    // `--genesis` needs no database.
    if cfg.command == Command::Genesis {
        inspect::print_genesis();
        return Ok(());
    }

    if let Some(spec) = &cfg.log_level {
        wow_log::configure(spec).map_err(|e| format!("--log-level: {e}"))?;
    }
    if let Some(path) = &cfg.log_file {
        wow_log::set_file(
            path.clone(),
            cfg.max_log_file_size,
            cfg.max_log_files,
            false,
        )?;
    }

    // Syncing is what may start from nothing: a node with no chain is exactly
    // what a first sync is for. The inspection commands still refuse a missing
    // database, so a mistyped --data-dir stays an error rather than becoming
    // an empty chain reported as height 1. A read-only server has nothing to
    // sync with, so it does not create one either.
    let creates = match cfg.command {
        Command::SyncFrom { .. } => true,
        Command::Serve => !cfg.read_only,
        _ => false,
    };

    // One writer per database, claimed before opening and held until exit.
    // Without it a second read-write process would not be refused; it would
    // sit inside LMDB waiting for the first one's write transaction.
    let _writer = if cfg.read_only {
        None
    } else {
        Some(inspect::claim_writer(cfg, creates)?)
    };

    if creates {
        inspect::bootstrap(cfg)?;
    }

    let db = inspect::open(cfg)?;
    match cfg.command {
        Command::Genesis => unreachable!("handled above"),
        Command::Status => inspect::status(&db, cfg),
        Command::CheckDifficultyCheckpoints => inspect::check_difficulty_checkpoints(&db, cfg),
        Command::VerifyDifficulty { from, to } => inspect::verify_difficulty(&db, cfg, from, to),
        Command::Serve => serve::run(db, cfg),
        Command::SyncFrom {
            ref address,
            max_batches,
        } => netsync::run(db, cfg.network, address, max_batches),
    }
}
