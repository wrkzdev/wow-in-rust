//! The 19 sub-databases, their flags, and their comparators.
//!
//! `specs/10-storage-lmdb.md` §3, from `db_lmdb.cpp:1485-1535`.
//!
//! Flags and comparators are **part of the file format**. A table opened with
//! the wrong flags or the wrong comparator produces a file the C++ node cannot
//! read, or one it mis-sorts silently — so the table below is a `const` that
//! can be asserted against the spec without opening a database.

use lmdb_master_sys as ffi;

/// Which comparator a table installs, if any.
///
/// The C++ calls `mdb_set_compare` for the key order and `mdb_set_dupsort` for
/// the order of duplicate values under one key. A table may set neither, one,
/// or (in principle) both; none of ours sets both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmp {
    /// LMDB's own ordering: bytewise for normal keys, integer for
    /// `MDB_INTEGERKEY`.
    Default,
    /// `compare_uint64`.
    Uint64,
    /// `compare_hash32`.
    Hash32,
    /// `compare_string`.
    String,
}

/// One sub-database.
#[derive(Clone, Copy, Debug)]
pub struct Table {
    /// The sub-database name, exactly as the C++ passes it to `mdb_dbi_open`.
    pub name: &'static str,
    pub flags: DatabaseFlags,
    /// `mdb_set_compare` — the key order.
    pub key_cmp: Cmp,
    /// `mdb_set_dupsort` — the order of duplicates under one key.
    pub dup_cmp: Cmp,
    /// Opened only when the environment is writable.
    pub write_only: bool,
    /// `mdb_drop(txn, db, 1)` on every open.
    pub drop_on_open: bool,
    /// Present for backwards compatibility and never written.
    pub legacy: bool,
}

const fn t(name: &'static str, flags: DatabaseFlags, key_cmp: Cmp, dup_cmp: Cmp) -> Table {
    Table {
        name,
        flags,
        key_cmp,
        dup_cmp,
        write_only: false,
        drop_on_open: false,
        legacy: false,
    }
}

/// The `mdb_dbi_open` flags a table is opened with.
///
/// A plain `u32` rather than a bitflags type: these go straight to LMDB and are
/// recorded **in the database**, so the wire value is the thing that matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatabaseFlags(pub u32);

impl DatabaseFlags {
    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: DatabaseFlags) -> bool {
        self.0 & other.0 == other.0
    }

    const fn union(self, other: DatabaseFlags) -> DatabaseFlags {
        DatabaseFlags(self.0 | other.0)
    }

    pub const fn empty() -> DatabaseFlags {
        DatabaseFlags(0)
    }
}

/// `MDB_INTEGERKEY` — keys are native-endian integers, compared numerically.
pub const INTEGER_KEY: DatabaseFlags = DatabaseFlags(ffi::MDB_INTEGERKEY);
/// `MDB_DUPSORT`.
pub const DUP_SORT: DatabaseFlags = DatabaseFlags(ffi::MDB_DUPSORT);
/// `MDB_DUPFIXED`.
pub const DUP_FIXED: DatabaseFlags = DatabaseFlags(ffi::MDB_DUPFIXED);

const INT: DatabaseFlags = INTEGER_KEY;
const INT_DUP: DatabaseFlags = INTEGER_KEY.union(DUP_SORT).union(DUP_FIXED);
const PLAIN: DatabaseFlags = DatabaseFlags::empty();

/// All 19 tables, in the order `db_lmdb.cpp` opens them.
///
/// `specs/01` §14 asks for the count to be asserted so an upstream addition is
/// caught rather than silently missed; [`tests::the_table_count_is_nineteen`]
/// is that.
pub const TABLES: &[Table] = &[
    t("blocks", INT, Cmp::Default, Cmp::Default),
    t("block_info", INT_DUP, Cmp::Default, Cmp::Uint64),
    t("block_heights", INT_DUP, Cmp::Default, Cmp::Hash32),
    Table {
        legacy: true,
        ..t("txs", INT, Cmp::Default, Cmp::Default)
    },
    t("txs_pruned", INT, Cmp::Default, Cmp::Default),
    // Note the asymmetry with its neighbours: this one sets a *key* comparator,
    // not a dupsort one, even though the key is already INTEGERKEY.
    t("txs_prunable", INT, Cmp::Uint64, Cmp::Default),
    t("txs_prunable_hash", INT_DUP, Cmp::Default, Cmp::Uint64),
    Table {
        write_only: true,
        ..t("txs_prunable_tip", INT_DUP, Cmp::Default, Cmp::Uint64)
    },
    t("tx_indices", INT_DUP, Cmp::Default, Cmp::Hash32),
    t("tx_outputs", INT, Cmp::Default, Cmp::Default),
    t("output_txs", INT_DUP, Cmp::Default, Cmp::Uint64),
    t("output_amounts", INT_DUP, Cmp::Default, Cmp::Uint64),
    t("spent_keys", INT_DUP, Cmp::Default, Cmp::Hash32),
    t("txpool_meta", PLAIN, Cmp::Hash32, Cmp::Default),
    t("txpool_blob", PLAIN, Cmp::Hash32, Cmp::Default),
    t("alt_blocks", PLAIN, Cmp::Hash32, Cmp::Default),
    Table {
        write_only: true,
        drop_on_open: true,
        ..t("hf_starting_heights", PLAIN, Cmp::Default, Cmp::Default)
    },
    t("hf_versions", INT, Cmp::Default, Cmp::Default),
    t("properties", PLAIN, Cmp::String, Cmp::Default),
];

/// Look a table up by name.
pub fn table(name: &str) -> Option<&'static Table> {
    TABLES.iter().find(|t| t.name == name)
}

/// The five tables that store their logical key as a prefix of the value under
/// a single dummy [`crate::comparator::ZEROKEY`] (`specs/10` §3.2).
///
/// This saves eight bytes per record versus a real key. A lookup positions the
/// cursor at `ZEROKEY` and then uses `MDB_GET_BOTH` with the value prefix.
pub const ZEROKVAL_TABLES: &[&str] = &[
    "block_info",
    "block_heights",
    "tx_indices",
    "output_txs",
    "spent_keys",
];

/// Is this table keyed by the `zerokval` dummy?
pub fn is_zerokval(name: &str) -> bool {
    ZEROKVAL_TABLES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `specs/10` §3: nineteen sub-databases. An upstream addition must be
    /// caught here rather than showing up as a missing table at runtime.
    #[test]
    fn the_table_count_is_nineteen() {
        assert_eq!(TABLES.len(), 19);
    }

    #[test]
    fn table_names_are_unique() {
        let mut names: Vec<&str> = TABLES.iter().map(|t| t.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "a table name is repeated");
    }

    /// The flags are transcribed from `db_lmdb.cpp:1485-1535` and are part of
    /// the file format. This is the table from `specs/10` §3, restated so the
    /// two can be diffed line by line.
    #[test]
    fn the_flags_match_the_spec_table() {
        let expected: &[(&str, DatabaseFlags, Cmp, Cmp)] = &[
            ("blocks", INT, Cmp::Default, Cmp::Default),
            ("block_info", INT_DUP, Cmp::Default, Cmp::Uint64),
            ("block_heights", INT_DUP, Cmp::Default, Cmp::Hash32),
            ("txs", INT, Cmp::Default, Cmp::Default),
            ("txs_pruned", INT, Cmp::Default, Cmp::Default),
            ("txs_prunable", INT, Cmp::Uint64, Cmp::Default),
            ("txs_prunable_hash", INT_DUP, Cmp::Default, Cmp::Uint64),
            ("txs_prunable_tip", INT_DUP, Cmp::Default, Cmp::Uint64),
            ("tx_indices", INT_DUP, Cmp::Default, Cmp::Hash32),
            ("tx_outputs", INT, Cmp::Default, Cmp::Default),
            ("output_txs", INT_DUP, Cmp::Default, Cmp::Uint64),
            ("output_amounts", INT_DUP, Cmp::Default, Cmp::Uint64),
            ("spent_keys", INT_DUP, Cmp::Default, Cmp::Hash32),
            ("txpool_meta", PLAIN, Cmp::Hash32, Cmp::Default),
            ("txpool_blob", PLAIN, Cmp::Hash32, Cmp::Default),
            ("alt_blocks", PLAIN, Cmp::Hash32, Cmp::Default),
            ("hf_starting_heights", PLAIN, Cmp::Default, Cmp::Default),
            ("hf_versions", INT, Cmp::Default, Cmp::Default),
            ("properties", PLAIN, Cmp::String, Cmp::Default),
        ];
        assert_eq!(expected.len(), TABLES.len());
        for (e, got) in expected.iter().zip(TABLES) {
            assert_eq!(e.0, got.name);
            assert_eq!(e.1, got.flags, "{}: flags", got.name);
            assert_eq!(e.2, got.key_cmp, "{}: key comparator", got.name);
            assert_eq!(e.3, got.dup_cmp, "{}: dupsort comparator", got.name);
        }
    }

    /// No table sets both a key comparator and a dupsort comparator, and only
    /// `DUP_SORT` tables set a dupsort one.
    #[test]
    fn comparators_are_assigned_consistently() {
        for t in TABLES {
            assert!(
                t.key_cmp == Cmp::Default || t.dup_cmp == Cmp::Default,
                "{}: sets both a key and a dupsort comparator",
                t.name
            );
            if t.dup_cmp != Cmp::Default {
                assert!(
                    t.flags.contains(DUP_SORT),
                    "{}: has a dupsort comparator but not DUP_SORT",
                    t.name
                );
            }
        }
    }

    /// Every `DUP_SORT` table here is also `DUP_FIXED`, which is what lets LMDB
    /// store the duplicates as a packed array.
    #[test]
    fn dupsort_tables_are_also_dupfixed() {
        for t in TABLES.iter().filter(|t| t.flags.contains(DUP_SORT)) {
            assert!(
                t.flags.contains(DUP_FIXED),
                "{}: DUP_SORT without DUP_FIXED",
                t.name
            );
        }
    }

    /// `txs_prunable` is the odd one out: a *key* comparator on a table whose
    /// key is already `INTEGERKEY`, where its neighbours use dupsort ones.
    /// Easy to normalise away by accident.
    #[test]
    fn txs_prunable_sets_a_key_comparator_not_a_dupsort_one() {
        let t = table("txs_prunable").unwrap();
        assert_eq!(t.key_cmp, Cmp::Uint64);
        assert_eq!(t.dup_cmp, Cmp::Default);
        assert!(!t.flags.contains(DUP_SORT));

        // Its neighbours do the opposite.
        for n in ["txs_prunable_hash", "txs_prunable_tip"] {
            let n = table(n).unwrap();
            assert_eq!(n.key_cmp, Cmp::Default);
            assert_eq!(n.dup_cmp, Cmp::Uint64);
        }
    }

    /// `specs/10` §3: `hf_starting_heights` is dropped on every open and
    /// `txs_prunable_tip` is opened only when writable. Both are opened only in
    /// a writable environment.
    #[test]
    fn the_write_only_tables_are_the_documented_two() {
        let write_only: Vec<&str> = TABLES
            .iter()
            .filter(|t| t.write_only)
            .map(|t| t.name)
            .collect();
        assert_eq!(write_only, vec!["txs_prunable_tip", "hf_starting_heights"]);

        let dropped: Vec<&str> = TABLES
            .iter()
            .filter(|t| t.drop_on_open)
            .map(|t| t.name)
            .collect();
        assert_eq!(dropped, vec!["hf_starting_heights"]);
        assert!(
            table("hf_starting_heights").unwrap().write_only,
            "a table that is dropped on open cannot be opened read-only"
        );
    }

    /// `txs` exists only so old databases open; it is never written.
    #[test]
    fn the_legacy_table_is_txs() {
        let legacy: Vec<&str> = TABLES.iter().filter(|t| t.legacy).map(|t| t.name).collect();
        assert_eq!(legacy, vec!["txs"]);
        assert!(!table("txs_pruned").unwrap().legacy, "this one is current");
    }

    /// `specs/10` §3.2: five tables use the `zerokval` dummy key.
    #[test]
    fn five_tables_use_the_zerokval_dummy() {
        assert_eq!(ZEROKVAL_TABLES.len(), 5);
        for name in ZEROKVAL_TABLES {
            let t = table(name).unwrap_or_else(|| panic!("{name} is not a table"));
            assert!(
                t.flags.contains(DUP_SORT),
                "{name}: a zerokval table must be DUP_SORT"
            );
            assert_ne!(
                t.dup_cmp,
                Cmp::Default,
                "{name}: the logical key is the dupsort prefix, so it needs a \
                 dupsort comparator"
            );
            assert!(is_zerokval(name));
        }
        assert!(!is_zerokval("output_amounts"), "this one has a real key");
        assert!(!is_zerokval("properties"));
    }

    /// `output_amounts` is `DUP_SORT` but **not** a zerokval table — its key is
    /// the real `u64` amount. Lumping it in with the other five would put every
    /// output under one dummy key.
    #[test]
    fn output_amounts_has_a_real_key() {
        let t = table("output_amounts").unwrap();
        assert!(t.flags.contains(DUP_SORT));
        assert!(!is_zerokval(t.name));
    }

    /// The flag *values* are what land in `data.mdb`, so pin the numbers, not
    /// just the names. `wownerod` reads these back and a different bit pattern
    /// means a different table.
    #[test]
    fn the_flag_bits_are_the_lmdb_values() {
        assert_eq!(INTEGER_KEY.bits(), 0x08);
        assert_eq!(DUP_SORT.bits(), 0x04);
        assert_eq!(DUP_FIXED.bits(), 0x10);
        assert_eq!(PLAIN.bits(), 0);
        assert_eq!(INT_DUP.bits(), 0x08 | 0x04 | 0x10);
        assert_eq!(INT_DUP.bits(), 28);
    }

    #[test]
    fn lookup_by_name() {
        assert_eq!(table("blocks").map(|t| t.name), Some("blocks"));
        assert!(table("no_such_table").is_none());
    }
}
