//! Opening and inspecting an existing `data.mdb`.
//!
//! `specs/10-storage-lmdb.md` §7 lists four requirements for taking over a
//! database the C++ node wrote, and all four are here:
//!
//! * refuse a second writer "as a clear error rather than blocking" -- see
//!   [`claim_writer`], and what it does *not* detect;
//! * check `properties["version"] == 5`;
//! * verify the tip agrees across `blocks` / `block_info` / `block_heights`;
//! * **infer the network from the genesis hash and refuse a mismatch** — the
//!   one that would otherwise be silent, since "a testnet and a mainnet
//!   `data.mdb` are structurally identical".

use wow_consensus::checkpoints::Checkpoints;
use wow_consensus::difficulty::{difficulty_blocks_count, next_difficulty};
use wow_consensus::genesis::network_from_genesis;
use wow_consensus::hardfork::HardFork;
use wow_storage::db::BlockchainDb;
use wow_storage::env::{db_dir, OpenMode, VersionVerdict};
use wow_storage::lmdb::LmdbDb;
use wow_types::Network;

use crate::cli::Config;

/// The file a read-write `wownerod` holds an exclusive lock on, beside
/// `data.mdb`.
///
/// Not `lock.mdb`: that is LMDB's own, and its writer mutex cannot be probed
/// without blocking on it.
pub const WRITER_LOCK_FILENAME: &str = "wownerod-rs.lock";

/// Proof that this process is the database's only writer, held until drop.
pub struct WriterLock {
    _file: std::fs::File,
}

/// Claim the right to write to the database, or say who has it.
///
/// `specs/10` §7 asks for a second writer to be "a clear error rather than
/// blocking". LMDB's own answer is to block: a read-write open starts a write
/// transaction, which waits on the writer mutex for as long as another process
/// holds it -- during a sync, most of the time.
///
/// The lock is an OS advisory lock on [`WRITER_LOCK_FILENAME`], released by the
/// kernel if the holder dies, so a crash never leaves a stale lock behind. It
/// is this implementation's own: **a running C++ node does not take it.** Next
/// to one, open with `--db-readonly`, which LMDB supports alongside a writer.
///
/// With `create`, a missing database directory is made first -- only the
/// syncing path passes it, for the same reason [`bootstrap`] is only called
/// there.
pub fn claim_writer(cfg: &Config, create: bool) -> Result<WriterLock, String> {
    let dir = db_dir(&cfg.data_dir, cfg.network, cfg.regtest);
    if !dir.exists() {
        if !create {
            return Err(no_database(&dir));
        }
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }

    let path = dir.join(WRITER_LOCK_FILENAME);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;

    match file.try_lock() {
        Ok(()) => Ok(WriterLock { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => Err(format!(
            "{} is already open for writing by another wownerod\n\
             Only one process may write to a database. Stop the other one, or \
             pass --db-readonly to inspect or serve it alongside.",
            dir.display()
        )),
        Err(std::fs::TryLockError::Error(e)) => Err(format!("cannot lock {}: {e}", path.display())),
    }
}

fn no_database(dir: &std::path::Path) -> String {
    format!(
        "no database at {}\n\
         Point --data-dir at a directory holding `{}/data.mdb`. \
         `--serve` and `--sync-from` create one there; the inspection \
         commands do not, so a mistyped path is an error and not an \
         empty chain.",
        dir.display(),
        wow_storage::env::DB_DIR
    )
}

/// Create the database and write the genesis block into it.
///
/// Only the syncing path calls this. The inspection commands deliberately do
/// not: `--status` against a mistyped `--data-dir` should say the database is
/// missing, not silently conjure an empty one and report height 1.
///
/// Genesis goes in directly rather than through the validator: it has no parent
/// to check and no proof of work to meet. Its record is not free to make up,
/// though. The C++ adds genesis through the same path as any other block, and
/// the coins that path records are what every later block reward is computed
/// from -- [`wow_consensus::genesis::genesis_record`] has the values.
pub fn bootstrap(cfg: &Config) -> Result<(), String> {
    let dir = db_dir(&cfg.data_dir, cfg.network, cfg.regtest);
    if dir.join(wow_storage::env::DATA_FILENAME).exists() {
        return Ok(());
    }
    if cfg.read_only {
        return Err(format!(
            "there is no database at {} and --db-readonly forbids creating one",
            dir.display()
        ));
    }

    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    let mode = OpenMode {
        sync: cfg.sync_mode,
        read_only: false,
        salvage: false,
    };
    let db = LmdbDb::open(&dir, mode, num_threads())
        .map_err(|e| format!("cannot create a database at {}: {e}", dir.display()))?;

    let blob = wow_consensus::genesis::genesis_blob(cfg.network);
    let blk = wow_types::block::Block::from_blob(&blob)
        .map_err(|e| format!("the genesis block does not parse: {e}"))?;
    let record = wow_consensus::genesis::genesis_record(cfg.network);
    db.add_block(
        &blk,
        &blob,
        record.weight,
        record.long_term_weight,
        record.cumulative_difficulty,
        record.already_generated_coins,
        &[],
    )
    .map_err(|e| format!("cannot write the genesis block: {e}"))?;

    Ok(())
}

/// Open the database, running every check `specs/10` §7 requires.
pub fn open(cfg: &Config) -> Result<LmdbDb, String> {
    let dir = db_dir(&cfg.data_dir, cfg.network, cfg.regtest);
    if !dir.exists() {
        return Err(no_database(&dir));
    }

    let mode = OpenMode {
        sync: cfg.sync_mode,
        read_only: cfg.read_only,
        salvage: cfg.salvage,
    };

    let db = LmdbDb::open(&dir, mode, num_threads()).map_err(|e| {
        // `specs/10` §7: "Refuse to open read-write if `lock.mdb` shows a live
        // writer ... surface it as a clear error rather than blocking."
        if !cfg.read_only {
            format!(
                "cannot open {} read-write: {e}\n\
                 If `wownerod` is running against this directory, stop it first, \
                 or pass --db-readonly to inspect it safely alongside.",
                dir.display()
            )
        } else {
            format!("cannot open {}: {e}", dir.display())
        }
    })?;

    // `properties["version"] == 5`.
    match db.version() {
        VersionVerdict::Current | VersionVerdict::Fresh => {}
        VersionVerdict::NeedsMigration { found } => {
            return Err(format!(
                "database schema version {found} is older than {}\n\
                 Run the C++ wownerod against this directory once to migrate it. \
                 This node will not write version-{} records into an older \
                 database.",
                wow_storage::env::VERSION,
                wow_storage::env::VERSION
            ))
        }
        VersionVerdict::TooNew { found } => {
            return Err(format!(
                "database schema version {found} was made by a later version \
                 than this node understands ({})",
                wow_storage::env::VERSION
            ))
        }
    }

    // The tip must agree across the three tables.
    db.check_tip()
        .map_err(|e| format!("the database tip is inconsistent: {e}"))?;

    // And it must be the network that was asked for.
    check_network(&db, cfg)?;

    // A database this node would sync into must start from the chain's own
    // genesis record. Reading one is harmless, so `--db-readonly` may.
    if !cfg.read_only {
        check_genesis_record(&db, cfg, &dir)?;
    }

    Ok(db)
}

/// Refuse to sync into a database whose genesis record has the wrong coins.
///
/// Earlier builds of this node wrote height 0 with no generated coins (see
/// [`wow_consensus::genesis::genesis_record`]). Every total stored after it is
/// short by the genesis payout, so every reward is computed too large: tolerated
/// until HF 16, which then refuses the real block and bans each peer sending
/// it. The totals are in every block's record, so there is nothing to patch
/// short of syncing again.
fn check_genesis_record(db: &LmdbDb, cfg: &Config, dir: &std::path::Path) -> Result<(), String> {
    if db.height() == 0 {
        return Ok(());
    }
    let expected = wow_consensus::genesis::genesis_record(cfg.network).already_generated_coins;
    let found = db
        .get_block_already_generated_coins(0)
        .map_err(|e| format!("cannot read the genesis block's record: {e}"))?;
    if found == expected {
        return Ok(());
    }
    Err(format!(
        "this database records {found} coins generated by the genesis block, where the \
         chain has {expected}\n\
         It was written by an earlier build of this node that got the genesis record \
         wrong. Every block reward after it is miscomputed, and the block at the HF 16 \
         height is refused, so it cannot finish a sync. Delete {} and sync again.",
        dir.display()
    ))
}

/// `specs/10` §7: infer the network from `blocks[0]` and refuse a mismatch.
fn check_network(db: &LmdbDb, cfg: &Config) -> Result<(), String> {
    let Some(hash) = db
        .genesis_hash()
        .map_err(|e| format!("cannot read the genesis block: {e}"))?
    else {
        // An empty database has no genesis to check against.
        return Ok(());
    };

    match network_from_genesis(&hash) {
        Some(found) if found.config() == cfg.network.config() => Ok(()),
        Some(found) => Err(format!(
            "this database is {found:?}, but {:?} was requested\n\
             Genesis {}\n\
             A testnet and a mainnet data.mdb are structurally identical, so \
             this is checked rather than assumed.",
            cfg.network,
            wow_crypto::hex::encode(&hash)
        )),
        None => Err(format!(
            "this database's genesis block matches no known network\n\
             Genesis {}\n\
             It was not written by a Wownero node, or it is from a fork.",
            wow_crypto::hex::encode(&hash)
        )),
    }
}

fn num_threads() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4)
}

/// `--genesis`.
pub fn print_genesis() {
    println!("Genesis block hashes, which identify a data.mdb's network:\n");
    for n in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
        let id = wow_consensus::genesis::genesis_id(n);
        println!(
            "  {:<10} {}",
            format!("{n:?}"),
            wow_crypto::hex::encode(&id)
        );
    }
}

/// `--status`.
pub fn status(db: &LmdbDb, cfg: &Config) -> Result<(), String> {
    let dir = db_dir(&cfg.data_dir, cfg.network, cfg.regtest);
    let height = db.height();

    println!("database   {}", dir.display());
    println!(
        "mode       {}",
        if db.is_read_only() {
            "read-only"
        } else {
            "read-write"
        }
    );
    println!("network    {:?}", cfg.network);
    println!("schema     version {:?}", db.version());
    println!("height     {height}");

    if height == 0 {
        println!("(empty chain)");
        return Ok(());
    }

    let tip = height - 1;
    let info = db
        .get_block_info(tip)
        .map_err(|e| format!("cannot read the tip: {e}"))?;
    let hf = HardFork::new(cfg.network);

    println!("tip        {}", wow_crypto::hex::encode(&info.hash));
    println!("timestamp  {}", info.timestamp);
    println!("version    {}", hf.required_version(tip));
    println!("cum diff   {}", info.cumulative_difficulty);
    println!("coins      {}", info.coins);
    println!(
        "weight     {} (long-term {})",
        info.weight, info.long_term_block_weight
    );
    println!("rct outs   {}", info.cum_rct);
    println!(
        "outputs    {} under amount 0",
        db.get_num_outputs(0).unwrap_or(0)
    );
    Ok(())
}

/// `--check-difficulty-checkpoints` (`specs/07` §6).
///
/// Walks the checkpoint table and compares the **stored** cumulative difficulty
/// against a recomputation, reporting the last matching height.
///
/// `specs/07` §6 on why this is the check to run first: "it is a cheap and very
/// effective integration test: if your difficulty implementation is wrong
/// anywhere, this fires at the first checkpoint past the error".
pub fn check_difficulty_checkpoints(db: &LmdbDb, cfg: &Config) -> Result<(), String> {
    let checkpoints = Checkpoints::new(cfg.network);
    let height = db.height();

    if checkpoints.is_empty() {
        println!("{:?} has no checkpoints to check.", cfg.network);
        return Ok(());
    }
    if height == 0 {
        return Err("the chain is empty".into());
    }

    println!(
        "Checking {} checkpoints against a chain of {height} blocks.\n",
        checkpoints.all().len()
    );

    let mut checked = 0usize;
    let mut last_match: Option<u64> = None;

    for cp in checkpoints.all() {
        if cp.height >= height {
            break;
        }

        let stored_hash = db
            .get_block_hash(cp.height)
            .map_err(|e| format!("height {}: {e}", cp.height))?;
        if stored_hash != cp.hash {
            return Err(format!(
                "checkpoint {} does not match\n  expected {}\n  stored   {}",
                cp.height,
                wow_crypto::hex::encode(&cp.hash),
                wow_crypto::hex::encode(&stored_hash)
            ));
        }

        let stored_diff = db
            .get_block_cumulative_difficulty(cp.height)
            .map_err(|e| format!("height {}: {e}", cp.height))?;
        if stored_diff != cp.cumulative_difficulty {
            return Err(format!(
                "checkpoint {}: cumulative difficulty differs\n  \
                 expected {}\n  stored   {}\n\
                 The difficulty implementation diverges at or before this height.",
                cp.height, cp.cumulative_difficulty, stored_diff
            ));
        }

        println!(
            "  {:>7}  {}  cum diff {}",
            cp.height,
            &wow_crypto::hex::encode(&cp.hash)[..16],
            cp.cumulative_difficulty
        );
        checked += 1;
        last_match = Some(cp.height);
    }

    match last_match {
        Some(h) => println!("\n{checked} checkpoints match, through height {h}."),
        None => println!("\nThe chain is shorter than the first checkpoint; nothing to check."),
    }
    Ok(())
}

/// `--verify-difficulty` — recompute every block's difficulty over a range.
///
/// Stronger than the checkpoint walk and much slower: it reruns
/// `next_difficulty` at each height and compares against the first difference of
/// the stored cumulative difficulties.
pub fn verify_difficulty(
    db: &LmdbDb,
    cfg: &Config,
    from: u64,
    to: Option<u64>,
) -> Result<(), String> {
    let height = db.height();
    if height < 2 {
        return Err("the chain is too short to verify".into());
    }
    let to = to.unwrap_or(height - 1).min(height - 1);
    let from = from.max(1);
    if from > to {
        return Err(format!("empty range {from}..={to}"));
    }

    let hf = HardFork::new(cfg.network);
    println!("Recomputing difficulty for heights {from}..={to}.\n");

    let mut checked = 0u64;
    let mut reported = 0usize;

    for h in from..=to {
        // The algorithm is chosen by `get_current_hard_fork_version()`, which
        // when validating height `h` is already the version of `h` itself
        // (`specs/07` §3, `specs/06` §9.4).
        let version = hf.required_version(h);
        let count = difficulty_blocks_count(version) as u64;
        let offset = {
            let o = h - h.min(count);
            if o == 0 {
                1
            } else {
                o
            }
        };

        let mut timestamps = Vec::with_capacity((h - offset) as usize);
        let mut cumulative = Vec::with_capacity((h - offset) as usize);
        for i in offset..h {
            let info = db
                .get_block_info(i)
                .map_err(|e| format!("height {i}: {e}"))?;
            timestamps.push(info.timestamp);
            cumulative.push(info.cumulative_difficulty);
        }

        let expected = next_difficulty(version, timestamps, cumulative, h, cfg.network);

        let this = db
            .get_block_cumulative_difficulty(h)
            .map_err(|e| format!("height {h}: {e}"))?;
        let prev = db
            .get_block_cumulative_difficulty(h - 1)
            .map_err(|e| format!("height {}: {e}", h - 1))?;
        let stored = this.wrapping_sub(prev);

        if stored != expected {
            reported += 1;
            eprintln!("  height {h} (v{version}): computed {expected}, chain stored {stored}");
            if reported >= 10 {
                return Err(format!(
                    "stopping after {reported} mismatches; the difficulty \
                     implementation diverges from height {h} or earlier"
                ));
            }
        }
        checked += 1;

        if checked.is_multiple_of(50_000) {
            println!("  ... {checked} heights, at {h}");
        }
    }

    if reported > 0 {
        return Err(format!("{reported} of {checked} heights disagree"));
    }
    println!("\n{checked} heights recomputed, all matching.");
    Ok(())
}
