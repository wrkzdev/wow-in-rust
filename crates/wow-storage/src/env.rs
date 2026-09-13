//! Opening the LMDB environment.
//!
//! `specs/10-storage-lmdb.md` §2, reproducing `BlockchainLMDB::open`
//! (`db_lmdb.cpp:1430`).
//!
//! The parts that decide file compatibility — the path, the flags, the map
//! size, the schema version — are separated from the act of opening so they can
//! be asserted without a database on disk.

use std::path::{Path, PathBuf};

use lmdb_master_sys as ffi;
use wow_types::Network;

use crate::tables::{Table, TABLES};

/// `CRYPTONOTE_BLOCKCHAINDATA_FILENAME`.
pub const DATA_FILENAME: &str = "data.mdb";
/// `CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME`.
pub const LOCK_FILENAME: &str = "lock.mdb";

/// `BlockchainLMDB::get_db_name()` — the directory component this backend adds.
pub const DB_DIR: &str = "lmdb";

/// `mdb_env_set_maxdbs`. Nineteen tables, with room to spare.
pub const MAX_DBS: u32 = 32;

/// LMDB's own default maximum reader slots. `mdb_env_set_maxreaders` is only
/// called when the thread count would exceed it.
pub const DEFAULT_MAX_READERS: u32 = 126;

/// `DEFAULT_MAPSIZE` with `ENABLE_AUTO_RESIZE`, which is the build default:
/// 1 GiB.
pub const DEFAULT_MAPSIZE: usize = 1 << 30;
/// `DEFAULT_MAPSIZE` without `ENABLE_AUTO_RESIZE`: 8 GiB.
pub const DEFAULT_MAPSIZE_NO_AUTO_RESIZE: usize = 1 << 33;
/// `DEFAULT_MAPSIZE` on 32-bit ARM: 2 GiB.
pub const DEFAULT_MAPSIZE_32BIT: usize = 1 << 31;
/// `RESIZE_PERCENT` — resize once 90% of the map is used.
pub const RESIZE_PERCENT: f64 = 0.9;
/// How much `do_resize` adds when it is not given a size: 1 GiB.
pub const RESIZE_ADD_SIZE: usize = 1 << 30;
/// The floor `check_and_resize_for_batch` applies: 512 MiB.
pub const BATCH_MIN_RESIZE: usize = 512 << 20;

/// `properties["version"]` — the schema version this code writes.
pub const VERSION: u32 = 5;

/// `--db-sync-mode` (`specs/10` §2.1, `specs/09` §3.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyncMode {
    /// The absence of `MDB_NOSYNC`.
    #[default]
    Safe,
    /// `DBF_FAST` → `MDB_NOSYNC`.
    Fast,
    /// `DBF_FASTEST` → `MDB_NOSYNC | MDB_WRITEMAP | MDB_MAPASYNC`.
    Fastest,
}

/// Why every open sets `MDB_NOTLS`, which the C++ does not.
///
/// Without it LMDB keeps one reader slot per **thread**: "A thread may use
/// parallel read-only transactions only if `MDB_NOTLS` is used." The C++ lives
/// with that because `m_tinfo` is a `thread_specific_ptr` holding exactly one
/// long-lived read transaction per thread, renewed rather than recreated
/// (`specs/10` §6.1).
///
/// A Rust node cannot: every `BlockchainDb` read method takes `&self` and opens
/// its own snapshot, so a caller holding one and calling another — which
/// `wow-core` does constantly — would be asking for a second reader on the same
/// thread. It is also wrong for async, where a task can resume on a different
/// thread than it started on (`specs/10` §6.2).
///
/// `MDB_NOTLS` only changes how the in-process reader lock table is used. It is
/// not recorded in `data.mdb` and does not affect the format, so it costs
/// nothing in compatibility.
pub const NOTLS_NOTE: () = ();

/// How the environment is being opened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenMode {
    pub sync: SyncMode,
    /// `DBF_RDONLY` → `MDB_RDONLY`, which **replaces** the other flags rather
    /// than being OR'd with them.
    pub read_only: bool,
    /// `DBF_SALVAGE` → `MDB_PREVSNAPSHOT` (`--db-salvage`): open the previous
    /// meta page.
    pub salvage: bool,
}

impl OpenMode {
    /// The `mdb_env_open` flags for this mode (`specs/10` §2.1).
    ///
    /// `read_only` is deliberately not combined with the sync flags: the C++
    /// assigns `MDB_RDONLY` rather than OR-ing it, so a read-only open ignores
    /// `--db-sync-mode` entirely.
    pub fn flags(&self) -> u32 {
        if self.read_only {
            let mut f = ffi::MDB_RDONLY | ffi::MDB_NOTLS;
            if self.salvage {
                f |= ffi::MDB_PREVSNAPSHOT;
            }
            return f;
        }
        let mut f = match self.sync {
            SyncMode::Safe => 0,
            SyncMode::Fast => ffi::MDB_NOSYNC,
            SyncMode::Fastest => ffi::MDB_NOSYNC | ffi::MDB_WRITEMAP | ffi::MDB_MAPASYNC,
        };
        if self.salvage {
            f |= ffi::MDB_PREVSNAPSHOT;
        }
        f | ffi::MDB_NOTLS
    }

    /// The flags the C++ would set, without [`NOTLS_NOTE`]'s addition.
    ///
    /// For comparing against `wownerod`'s own open, and for tests that assert
    /// the `--db-sync-mode` mapping in isolation.
    pub fn sync_flags_only(&self) -> u32 {
        self.flags() & !ffi::MDB_NOTLS
    }
}

/// The directory holding `data.mdb`, given a data directory and a network
/// (`specs/10` §2).
///
/// ```text
/// mainnet   <datadir>/lmdb/
/// testnet   <datadir>/testnet/lmdb/
/// stagenet  <datadir>/stagenet/lmdb/
/// fakechain <datadir>/fake/lmdb/     -- only when NOT reached via --regtest
/// ```
///
/// `--regtest` already appends `fake` to the data-directory argument, so
/// passing `regtest = true` suppresses the extra component rather than adding
/// it twice.
pub fn db_dir(data_dir: &Path, network: Network, regtest: bool) -> PathBuf {
    let mut p = data_dir.to_path_buf();
    match network {
        Network::Mainnet => {}
        Network::Testnet => p.push("testnet"),
        Network::Stagenet => p.push("stagenet"),
        Network::Fakechain => {
            if !regtest {
                p.push("fake");
            }
        }
    }
    p.push(DB_DIR);
    p
}

/// The `data.mdb` path for a database directory.
pub fn data_path(db_dir: &Path) -> PathBuf {
    db_dir.join(DATA_FILENAME)
}

/// The `lock.mdb` path for a database directory.
pub fn lock_path(db_dir: &Path) -> PathBuf {
    db_dir.join(LOCK_FILENAME)
}

/// `mdb_env_set_maxreaders` is called only when the thread count would exceed
/// LMDB's default of 126 — the C++ guards it with `threads > 110`.
///
/// Returns `None` when the default is left alone, which is the normal case.
pub fn max_readers(threads: u32) -> Option<u32> {
    (threads > 110).then_some(threads + 16)
}

/// `need_resize(threshold_size)` (`specs/10` §2.2).
///
/// ```text
/// size_used = psize * last_pgno
/// if threshold > 0 { (mapsize - size_used) < threshold }
/// else             { (size_used / mapsize) > 0.9 }
/// ```
///
/// The two branches are not the same test written two ways: with a threshold it
/// asks "is there less than this much left", and without one it asks "is more
/// than 90% used". The C's second branch divides in floating point.
pub fn need_resize(mapsize: u64, page_size: u64, last_pgno: u64, threshold: u64) -> bool {
    let size_used = page_size.saturating_mul(last_pgno);
    if threshold > 0 {
        return mapsize.saturating_sub(size_used) < threshold;
    }
    if mapsize == 0 {
        return true;
    }
    (size_used as f64 / mapsize as f64) > RESIZE_PERCENT
}

/// `do_resize(increase_size)` — the new map size, before the disk-space check
/// (`specs/10` §2.2).
///
/// ```text
/// new = mapsize + (increase > 0 ? increase : 1 GiB)
/// new += new % page_size
/// ```
///
/// Note the second line **adds** the remainder rather than rounding up to a
/// multiple — `new += new % psize` is not `new = ceil(new / psize) * psize`.
/// Reproduce it: the resulting size is part of what a byte-comparison of two
/// databases would see.
pub fn resized_mapsize(mapsize: u64, page_size: u64, increase_size: u64) -> u64 {
    let add = if increase_size > 0 {
        increase_size
    } else {
        RESIZE_ADD_SIZE as u64
    };
    let mut new = mapsize.saturating_add(add);
    if page_size > 0 {
        new = new.saturating_add(new % page_size);
    }
    new
}

/// `check_and_resize_for_batch` — the size to grow by before a batch write.
pub fn batch_resize_size(estimated_batch_bytes: u64) -> u64 {
    estimated_batch_bytes.max(BATCH_MIN_RESIZE as u64)
}

/// What to do about the schema version found on disk (`specs/10` §2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionVerdict {
    /// No `properties["version"]`: a fresh database. Write [`VERSION`].
    Fresh,
    /// Exactly [`VERSION`].
    Current,
    /// Older. The C++ migrates; `specs/10` §2.3 allows a Rust node to refuse
    /// instead — but **never** to write version-5 records into it.
    NeedsMigration { found: u32 },
    /// Newer: "made by a later version". Mark incompatible and refuse to write.
    TooNew { found: u32 },
}

/// Classify the schema version.
pub fn check_version(found: Option<u32>) -> VersionVerdict {
    match found {
        None => VersionVerdict::Fresh,
        Some(v) if v == VERSION => VersionVerdict::Current,
        Some(v) if v < VERSION => VersionVerdict::NeedsMigration { found: v },
        Some(v) => VersionVerdict::TooNew { found: v },
    }
}

impl VersionVerdict {
    /// May this node write to the database?
    pub fn is_writable(&self) -> bool {
        matches!(self, VersionVerdict::Fresh | VersionVerdict::Current)
    }
}

/// Which tables to open for a given mode.
///
/// `hf_starting_heights` and `txs_prunable_tip` are opened only when writable
/// (`specs/10` §3).
pub fn tables_for(read_only: bool) -> impl Iterator<Item = &'static Table> {
    TABLES.iter().filter(move |t| !(read_only && t.write_only))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filenames_and_limits_match_the_spec() {
        assert_eq!(DATA_FILENAME, "data.mdb");
        assert_eq!(LOCK_FILENAME, "lock.mdb");
        assert_eq!(DB_DIR, "lmdb");
        assert_eq!(MAX_DBS, 32);
        assert!(
            MAX_DBS as usize >= TABLES.len(),
            "maxdbs must cover every table"
        );
        assert_eq!(VERSION, 5);
        assert_eq!(DEFAULT_MAPSIZE, 1 << 30);
        assert_eq!(DEFAULT_MAPSIZE_NO_AUTO_RESIZE, 1 << 33);
        assert_eq!(DEFAULT_MAPSIZE_32BIT, 1 << 31);
        assert_eq!(RESIZE_ADD_SIZE, 1 << 30);
        assert_eq!(BATCH_MIN_RESIZE, 512 * 1024 * 1024);
    }

    /// `specs/10` §2: the per-network path components, and the `--regtest`
    /// double-append that the C++ avoids.
    #[test]
    fn the_database_directory_is_network_specific() {
        let d = Path::new("/data");
        assert_eq!(db_dir(d, Network::Mainnet, false), Path::new("/data/lmdb"));
        assert_eq!(
            db_dir(d, Network::Testnet, false),
            Path::new("/data/testnet/lmdb")
        );
        assert_eq!(
            db_dir(d, Network::Stagenet, false),
            Path::new("/data/stagenet/lmdb")
        );

        // Fakechain without --regtest inserts `fake`.
        assert_eq!(
            db_dir(d, Network::Fakechain, false),
            Path::new("/data/fake/lmdb")
        );
        // With --regtest the data-dir argument already ends in `fake`, so the
        // component must not be added again.
        assert_eq!(
            db_dir(Path::new("/data/fake"), Network::Fakechain, true),
            Path::new("/data/fake/lmdb")
        );
        assert_ne!(
            db_dir(Path::new("/data/fake"), Network::Fakechain, true),
            Path::new("/data/fake/fake/lmdb")
        );
    }

    #[test]
    fn the_data_and_lock_paths_sit_in_the_db_directory() {
        let d = db_dir(Path::new("/data"), Network::Mainnet, false);
        assert_eq!(data_path(&d), Path::new("/data/lmdb/data.mdb"));
        assert_eq!(lock_path(&d), Path::new("/data/lmdb/lock.mdb"));
    }

    /// `specs/10` §2.1. The mapping is small but every flag is part of the
    /// durability contract.
    #[test]
    fn sync_modes_map_to_the_documented_flags() {
        let m = |sync| OpenMode {
            sync,
            read_only: false,
            salvage: false,
        };
        assert_eq!(m(SyncMode::Safe).sync_flags_only(), 0);
        assert_eq!(m(SyncMode::Fast).sync_flags_only(), ffi::MDB_NOSYNC);
        assert_eq!(
            m(SyncMode::Fastest).sync_flags_only(),
            ffi::MDB_NOSYNC | ffi::MDB_WRITEMAP | ffi::MDB_MAPASYNC
        );
        // Every open adds NOTLS so a thread can hold parallel readers.
        assert_ne!(m(SyncMode::Safe).flags() & ffi::MDB_NOTLS, 0);
        // Pin the numbers too: these go to liblmdb, not to a wrapper.
        assert_eq!(ffi::MDB_NOSYNC, 0x10000);
        assert_eq!(ffi::MDB_WRITEMAP, 0x80000);
        assert_eq!(ffi::MDB_MAPASYNC, 0x100000);
        assert_eq!(SyncMode::default(), SyncMode::Safe, "safe is the default");
    }

    /// `MDB_RDONLY` **replaces** the sync flags rather than joining them —
    /// OR-ing `NO_SYNC` into a read-only open would be wrong and LMDB would
    /// reject some combinations outright.
    #[test]
    fn read_only_replaces_the_sync_flags() {
        for sync in [SyncMode::Safe, SyncMode::Fast, SyncMode::Fastest] {
            let f = OpenMode {
                sync,
                read_only: true,
                salvage: false,
            }
            .flags();
            assert_eq!(
                f & !ffi::MDB_NOTLS,
                ffi::MDB_RDONLY,
                "{sync:?} must be ignored"
            );
            assert_eq!(f & ffi::MDB_NOSYNC, 0);
            assert_eq!(f & ffi::MDB_WRITEMAP, 0);
        }
    }

    /// `--db-salvage` adds `MDB_PREVSNAPSHOT` in either mode.
    #[test]
    fn salvage_adds_the_previous_snapshot_flag() {
        let rw = OpenMode {
            sync: SyncMode::Fast,
            read_only: false,
            salvage: true,
        };
        assert_ne!(rw.flags() & ffi::MDB_PREVSNAPSHOT, 0);
        assert_ne!(rw.flags() & ffi::MDB_NOSYNC, 0);

        let ro = OpenMode {
            sync: SyncMode::Safe,
            read_only: true,
            salvage: true,
        };
        assert_eq!(
            ro.flags() & !ffi::MDB_NOTLS,
            ffi::MDB_RDONLY | ffi::MDB_PREVSNAPSHOT
        );
    }

    /// The reader limit is left at LMDB's default unless the thread count would
    /// exceed it. The guard is `threads > 110`, not `threads > 126`.
    #[test]
    fn max_readers_is_only_raised_past_the_guard() {
        assert_eq!(max_readers(1), None);
        assert_eq!(max_readers(110), None);
        assert_eq!(max_readers(111), Some(127));
        assert_eq!(max_readers(200), Some(216));
        assert!(
            max_readers(111).unwrap() > DEFAULT_MAX_READERS,
            "the guard exists so the raise actually raises"
        );
    }

    /// `specs/10` §2.2: the two `need_resize` branches ask different questions.
    #[test]
    fn need_resize_has_two_distinct_branches() {
        let mapsize = 1u64 << 30; // 1 GiB
        let psize = 4096u64;

        // Threshold branch: "is there less than `threshold` left?"
        // Half the map used leaves exactly 512 MiB free.
        let used_pages = (mapsize / 2) / psize;
        let free = mapsize - used_pages * psize;
        assert_eq!(free, 512 << 20);
        assert!(
            !need_resize(mapsize, psize, used_pages, 1 << 20),
            "512 MiB free is more than 1 MiB"
        );
        // The comparison is strict, so exactly the threshold does not trigger.
        assert!(
            !need_resize(mapsize, psize, used_pages, free),
            "free == threshold is not `< threshold`"
        );
        assert!(
            need_resize(mapsize, psize, used_pages, free + 1),
            "one byte more than free does"
        );

        // Percentage branch: "is more than 90% used?"
        let at_80 = ((mapsize as f64 * 0.80) as u64) / psize;
        let at_95 = ((mapsize as f64 * 0.95) as u64) / psize;
        assert!(!need_resize(mapsize, psize, at_80, 0));
        assert!(need_resize(mapsize, psize, at_95, 0));
    }

    /// Exactly 90% used does **not** trigger a resize: the C tests `>`, not
    /// `>=`.
    #[test]
    fn need_resize_is_strictly_greater_than_ninety_percent() {
        let mapsize = 1000u64;
        let psize = 1u64;
        assert!(!need_resize(mapsize, psize, 900, 0), "exactly 90%");
        assert!(need_resize(mapsize, psize, 901, 0));
    }

    #[test]
    fn need_resize_handles_a_degenerate_map() {
        assert!(need_resize(0, 4096, 0, 0), "a zero map always needs one");
        assert!(!need_resize(1 << 30, 4096, 0, 0), "an empty map does not");
    }

    /// `new += new % psize` **adds the remainder**; it does not round up to a
    /// multiple of the page size, and in fact does not align anything. A reader
    /// who assumes the line is an alignment would produce a different map size
    /// whenever the remainder is non-zero.
    #[test]
    fn the_resize_adds_the_remainder_rather_than_rounding_up() {
        let psize = 4096u64;
        // A map size whose post-add value is not page-aligned.
        let mapsize = (1u64 << 30) + 1;
        let got = resized_mapsize(mapsize, psize, 0);

        let after_add = mapsize + RESIZE_ADD_SIZE as u64;
        assert_eq!(after_add % psize, 1, "one byte past a page boundary");
        assert_eq!(got, after_add + 1, "the remainder is added, so +1");

        // What an "align up" reading would give, and why it differs.
        let rounded_up = after_add.div_ceil(psize) * psize;
        assert_eq!(rounded_up, after_add + psize - 1);
        assert_ne!(got, rounded_up, "the two readings must differ here");

        // The C's result is not page-aligned at all -- that is the point.
        assert_ne!(got % psize, 0);
        assert_eq!(rounded_up % psize, 0);
    }

    #[test]
    fn the_resize_uses_the_explicit_increase_when_given_one() {
        let psize = 4096u64;
        let mapsize = 1u64 << 30;
        assert_eq!(
            resized_mapsize(mapsize, psize, 0),
            mapsize + RESIZE_ADD_SIZE as u64,
            "already page-aligned, so the remainder is zero"
        );
        assert_eq!(
            resized_mapsize(mapsize, psize, 1 << 20),
            mapsize + (1 << 20)
        );
    }

    /// A batch grows by at least 512 MiB.
    #[test]
    fn a_batch_resize_has_a_floor() {
        assert_eq!(batch_resize_size(0), BATCH_MIN_RESIZE as u64);
        assert_eq!(batch_resize_size(1), BATCH_MIN_RESIZE as u64);
        assert_eq!(batch_resize_size(1 << 30), 1 << 30);
    }

    /// `specs/10` §2.3: four outcomes, and only two of them permit writing.
    #[test]
    fn the_schema_version_verdicts() {
        assert_eq!(check_version(None), VersionVerdict::Fresh);
        assert_eq!(check_version(Some(5)), VersionVerdict::Current);
        assert_eq!(
            check_version(Some(4)),
            VersionVerdict::NeedsMigration { found: 4 }
        );
        assert_eq!(check_version(Some(6)), VersionVerdict::TooNew { found: 6 });

        assert!(check_version(None).is_writable());
        assert!(check_version(Some(5)).is_writable());
        assert!(
            !check_version(Some(4)).is_writable(),
            "never write v5 records into a v4 database"
        );
        assert!(!check_version(Some(6)).is_writable());
    }

    /// `specs/10` §3: two tables are writable-only, so a read-only open sees 17.
    #[test]
    fn a_read_only_open_skips_the_write_only_tables() {
        assert_eq!(tables_for(false).count(), 19);
        assert_eq!(tables_for(true).count(), 17);

        let ro: Vec<&str> = tables_for(true).map(|t| t.name).collect();
        assert!(!ro.contains(&"hf_starting_heights"));
        assert!(!ro.contains(&"txs_prunable_tip"));
        assert!(ro.contains(&"blocks"));
    }
}
