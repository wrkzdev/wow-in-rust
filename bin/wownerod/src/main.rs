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
//! The RPC server, the transaction pool and a one-peer sync over the peer
//! protocol are built; mining, inbound connections and block propagation are
//! not, and the options for them are **refused** rather than accepted and
//! ignored (see [`cli::NOT_IMPLEMENTED`]).

#![forbid(unsafe_code)]

mod cli;
mod inspect;
mod mempool;
mod netsync;
mod rpc;

use std::process::ExitCode;

use cli::{Command, ParseOutcome};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
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

    // `--sync-from` is the one command that may start from nothing: a node
    // with no chain is exactly what a first sync is for. The inspection
    // commands still refuse a missing database, so a mistyped --data-dir stays
    // an error rather than becoming an empty chain reported as height 1.
    if matches!(cfg.command, Command::SyncFrom { .. }) {
        inspect::bootstrap(cfg)?;
    }

    let db = inspect::open(cfg)?;
    match cfg.command {
        Command::Genesis => unreachable!("handled above"),
        Command::Status => inspect::status(&db, cfg),
        Command::CheckDifficultyCheckpoints => inspect::check_difficulty_checkpoints(&db, cfg),
        Command::VerifyDifficulty { from, to } => inspect::verify_difficulty(&db, cfg, from, to),
        Command::Serve => rpc::serve(db, cfg),
        Command::SyncFrom {
            ref address,
            max_batches,
        } => netsync::run(db, cfg.network, address, max_batches),
    }
}
