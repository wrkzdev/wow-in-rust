//! `BlockchainDb` over LMDB.
//!
//! `specs/10-storage-lmdb.md` §7 and §9. This is the layer that makes the
//! format in [`crate::records`] into a chain store.
//!
//! # The `zerokval` access pattern
//!
//! Five tables keep their logical key as a prefix of the *value* under one
//! dummy key (`specs/10` §3.2). Every lookup into them is the same two steps —
//! position at [`ZEROKEY`], then `MDB_GET_BOTH` with the prefix — and the
//! dupsort comparator decides the match, so the search value can be just the
//! prefix rather than a whole record. [`LmdbDb::zerokval_get`] is that, once.

use std::collections::BTreeMap;
use std::path::Path;

use wow_crypto::types::{Hash256, KeyImage};
use wow_types::{Block, Transaction};

use crate::comparator::{assert_little_endian, ZEROKEY};
use crate::db::{
    AltBlockData, BlockchainDb, DbError, HistogramEntry, OutputData, Result, TxData, TxPoolVisitor,
};
use crate::env::{check_version, OpenMode, VersionVerdict, DEFAULT_MAPSIZE, VERSION};
use crate::raw::{Db, Env, LmdbError, RoTxn, RwTxn};
use crate::records::{
    property_key, AltBlock, BlockHeight, BlockInfo, OutKey, OutTx, TxIndex, TxPoolMeta,
    PROPERTY_VERSION,
};
use crate::semantics::{next_amount_index, spent_key_images, split_tx_blob, stored_outputs};
use crate::tables::{table, Table, TABLES};

impl From<LmdbError> for DbError {
    fn from(e: LmdbError) -> Self {
        if e.is_not_found() {
            DbError::NotFound
        } else {
            DbError::Backend(Box::new(e))
        }
    }
}

/// The nineteen database handles.
///
/// `Db` is `Copy` and stays valid for the environment's life, so these need no
/// lifetime and can sit beside the [`Env`].
#[derive(Clone, Copy, Debug)]
pub struct Dbs {
    pub blocks: Db,
    pub block_info: Db,
    pub block_heights: Db,
    pub txs: Db,
    pub txs_pruned: Db,
    pub txs_prunable: Db,
    pub txs_prunable_hash: Db,
    /// `None` when read-only (`specs/10` §3).
    pub txs_prunable_tip: Option<Db>,
    pub tx_indices: Db,
    pub tx_outputs: Db,
    pub output_txs: Db,
    pub output_amounts: Db,
    pub spent_keys: Db,
    pub txpool_meta: Db,
    pub txpool_blob: Db,
    pub alt_blocks: Db,
    /// `None` when read-only; dropped on every writable open.
    pub hf_starting_heights: Option<Db>,
    pub hf_versions: Db,
    pub properties: Db,
}

/// An open `data.mdb`.
pub struct LmdbDb {
    env: Env,
    dbs: Dbs,
    version: VersionVerdict,
    read_only: bool,
}

impl LmdbDb {
    /// Open (creating if absent) the database under `db_dir`.
    ///
    /// `db_dir` already includes the `lmdb/` component — use
    /// [`crate::env::db_dir`] to build it.
    pub fn open(db_dir: &Path, mode: OpenMode, threads: u32) -> Result<LmdbDb> {
        Self::open_with_map_size(db_dir, mode, threads, DEFAULT_MAPSIZE)
    }

    /// [`LmdbDb::open`] with an explicit map size.
    pub fn open_with_map_size(
        db_dir: &Path,
        mode: OpenMode,
        threads: u32,
        map_size: usize,
    ) -> Result<LmdbDb> {
        assert_little_endian();
        if !mode.read_only {
            std::fs::create_dir_all(db_dir).map_err(|e| DbError::Backend(Box::new(e)))?;
        }

        let env = Env::open(
            db_dir,
            mode.flags(),
            crate::env::MAX_DBS,
            crate::env::max_readers(threads),
            map_size,
        )?;

        let (dbs, version) = if mode.read_only {
            let rtxn = env.read_txn()?;
            let dbs = open_dbs_ro(&rtxn)?;
            let version = read_version(&rtxn, dbs.properties)?;
            // A read transaction that opened dbi handles must be *committed*,
            // not dropped: the handles only become visible to the environment
            // on commit.
            rtxn.commit()?;
            (dbs, version)
        } else {
            let mut wtxn = env.write_txn()?;
            let dbs = open_dbs_rw(&mut wtxn)?;

            // `hf_starting_heights` is dropped on every open (`specs/10` §3),
            // which keeps the file identical to one the C++ produced.
            if let Some(db) = dbs.hf_starting_heights {
                wtxn.clear_db(db)?;
            }

            let version = read_version(&wtxn, dbs.properties)?;
            if version == VersionVerdict::Fresh {
                wtxn.put(
                    dbs.properties,
                    &property_key(PROPERTY_VERSION),
                    &VERSION.to_ne_bytes(),
                    0,
                )?;
            }
            wtxn.commit()?;
            (dbs, version)
        };

        if !mode.read_only && !version.is_writable() {
            return Err(DbError::Backend(Box::new(VersionError(version))));
        }

        Ok(LmdbDb {
            env,
            dbs,
            version,
            read_only: mode.read_only,
        })
    }

    pub fn env(&self) -> &Env {
        &self.env
    }

    pub fn dbs(&self) -> &Dbs {
        &self.dbs
    }

    pub fn version(&self) -> VersionVerdict {
        self.version
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// A read snapshot. `specs/10` §6.2: do not hold one across a long await —
    /// a pinned snapshot stops the free list being reclaimed and the map grows.
    pub fn read_txn(&self) -> Result<RoTxn<'_>> {
        Ok(self.env.read_txn()?)
    }

    /// `specs/10` §7: the C++ stores nothing identifying the network, so it has
    /// to be inferred from the genesis block and a mismatch refused.
    ///
    /// "This is a real hazard: a testnet and a mainnet `data.mdb` are
    /// structurally identical."
    pub fn genesis_hash(&self) -> Result<Option<Hash256>> {
        let rtxn = self.read_txn()?;
        if rtxn.entries(self.dbs.blocks)? == 0 {
            return Ok(None);
        }
        let info = self.block_info_in(&rtxn, 0)?;
        Ok(Some(info.hash))
    }

    /// `specs/10` §6.3 / §7: verify `blocks`, `block_info` and `block_heights`
    /// agree about the tip.
    ///
    /// With `MDB_NOSYNC` a crash can lose recent *committed* transactions, so
    /// the file stays valid but may come back at an earlier height. This is the
    /// check that catches a disagreement rather than syncing on from a bad tip.
    pub fn check_tip(&self) -> Result<()> {
        let rtxn = self.read_txn()?;
        let height = rtxn.entries(self.dbs.blocks)?;
        if height == 0 {
            return Ok(());
        }
        let tip = height - 1;

        let info_entries = rtxn.entries(self.dbs.block_info)?;
        if info_entries != height {
            return Err(DbError::Backend(Box::new(TipMismatch {
                what: "block_info entry count",
                expected: height,
                found: info_entries,
            })));
        }
        let heights_entries = rtxn.entries(self.dbs.block_heights)?;
        if heights_entries != height {
            return Err(DbError::Backend(Box::new(TipMismatch {
                what: "block_heights entry count",
                expected: height,
                found: heights_entries,
            })));
        }

        // And the tip's own records must round-trip through each other.
        let info = self.block_info_in(&rtxn, tip)?;
        let back = self.block_height_in(&rtxn, &info.hash)?;
        if back != tip {
            return Err(DbError::Backend(Box::new(TipMismatch {
                what: "block_heights disagrees about the tip",
                expected: tip,
                found: back,
            })));
        }
        Ok(())
    }

    // ------------------------------------------------------------ zerokval

    /// The `specs/10` §3.2 lookup: position at [`ZEROKEY`], then
    /// `MDB_GET_BOTH` on the value prefix.
    ///
    /// The dupsort comparator decides the match and only reads the prefix, so
    /// `prefix` can be just the eight-byte height or the 32-byte hash rather
    /// than a whole record.
    fn zerokval_get<'t>(
        &self,
        rtxn: &'t RoTxn<'_>,
        db: Db,
        prefix: &[u8],
    ) -> Result<Option<&'t [u8]>> {
        let mut c = rtxn.cursor(db)?;
        Ok(c.get_both(&ZEROKEY, prefix)?)
    }

    fn block_info_in(&self, rtxn: &RoTxn<'_>, height: u64) -> Result<BlockInfo> {
        let raw = self
            .zerokval_get(rtxn, self.dbs.block_info, &height.to_ne_bytes())?
            .ok_or(DbError::NotFound)?;
        Ok(BlockInfo::decode(raw)?)
    }

    fn block_height_in(&self, rtxn: &RoTxn<'_>, hash: &Hash256) -> Result<u64> {
        let raw = self
            .zerokval_get(rtxn, self.dbs.block_heights, hash)?
            .ok_or(DbError::NotFound)?;
        Ok(BlockHeight::decode(raw)?.height)
    }

    fn tx_index_in(&self, rtxn: &RoTxn<'_>, hash: &Hash256) -> Result<TxIndex> {
        let raw = self
            .zerokval_get(rtxn, self.dbs.tx_indices, hash)?
            .ok_or(DbError::NotFound)?;
        Ok(TxIndex::decode(raw)?)
    }

    /// Begin the write transaction. LMDB allows one at a time environment-wide
    /// and blocks until any previous one finishes (`specs/10` §6.1).
    ///
    /// A batch is simply a writer that lives across several blocks, which is
    /// exactly what `specs/10` §6.2 describes: "The **writer task** owns the
    /// single write transaction. One `RwTxn` per block (or per batch during
    /// bulk sync). Commit is the atomic unit."
    pub fn writer(&self) -> Result<Writer<'_>> {
        if self.read_only {
            return Err(DbError::ReadOnly);
        }
        Ok(Writer {
            txn: self.env.write_txn()?,
            dbs: self.dbs,
        })
    }
}

/// A failed schema-version check, as an error the trait can carry.
#[derive(Debug)]
struct VersionError(VersionVerdict);

impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            VersionVerdict::NeedsMigration { found } => write!(
                f,
                "database schema version {found} predates {VERSION}; run the C++ \
                 wownerod once to migrate it, as this node will not write \
                 version-{VERSION} records into an older database"
            ),
            VersionVerdict::TooNew { found } => write!(
                f,
                "database schema version {found} was made by a later version \
                 than this node understands ({VERSION})"
            ),
            other => write!(f, "incompatible schema version: {other:?}"),
        }
    }
}

impl std::error::Error for VersionError {}

/// `blocks`, `block_info` and `block_heights` disagree (`specs/10` §6.3).
#[derive(Debug)]
struct TipMismatch {
    what: &'static str,
    expected: u64,
    found: u64,
}

impl std::fmt::Display for TipMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: expected {}, found {}",
            self.what, self.expected, self.found
        )
    }
}

impl std::error::Error for TipMismatch {}

fn tbl(name: &str) -> &'static Table {
    table(name).unwrap_or_else(|| panic!("{name} is not in TABLES"))
}

fn open_dbs_rw(w: &mut RwTxn<'_>) -> Result<Dbs> {
    macro_rules! db {
        ($name:literal) => {{
            let t = tbl($name);
            w.create_db($name, t.flags.bits(), t)?
        }};
    }
    Ok(Dbs {
        blocks: db!("blocks"),
        block_info: db!("block_info"),
        block_heights: db!("block_heights"),
        txs: db!("txs"),
        txs_pruned: db!("txs_pruned"),
        txs_prunable: db!("txs_prunable"),
        txs_prunable_hash: db!("txs_prunable_hash"),
        txs_prunable_tip: Some(db!("txs_prunable_tip")),
        tx_indices: db!("tx_indices"),
        tx_outputs: db!("tx_outputs"),
        output_txs: db!("output_txs"),
        output_amounts: db!("output_amounts"),
        spent_keys: db!("spent_keys"),
        txpool_meta: db!("txpool_meta"),
        txpool_blob: db!("txpool_blob"),
        alt_blocks: db!("alt_blocks"),
        hf_starting_heights: Some(db!("hf_starting_heights")),
        hf_versions: db!("hf_versions"),
        properties: db!("properties"),
    })
}

fn open_dbs_ro(r: &RoTxn<'_>) -> Result<Dbs> {
    macro_rules! db {
        ($name:literal) => {{
            let t = tbl($name);
            r.open_db($name, t.flags.bits(), t)?
        }};
    }
    Ok(Dbs {
        blocks: db!("blocks"),
        block_info: db!("block_info"),
        block_heights: db!("block_heights"),
        txs: db!("txs"),
        txs_pruned: db!("txs_pruned"),
        txs_prunable: db!("txs_prunable"),
        txs_prunable_hash: db!("txs_prunable_hash"),
        txs_prunable_tip: None,
        tx_indices: db!("tx_indices"),
        tx_outputs: db!("tx_outputs"),
        output_txs: db!("output_txs"),
        output_amounts: db!("output_amounts"),
        spent_keys: db!("spent_keys"),
        txpool_meta: db!("txpool_meta"),
        txpool_blob: db!("txpool_blob"),
        alt_blocks: db!("alt_blocks"),
        hf_starting_heights: None,
        hf_versions: db!("hf_versions"),
        properties: db!("properties"),
    })
}

fn read_version(rtxn: &RoTxn<'_>, properties: Db) -> Result<VersionVerdict> {
    let key = property_key(PROPERTY_VERSION);
    let found = match rtxn.get(properties, &key)? {
        None => None,
        Some(v) => Some(u32::from_ne_bytes(v.try_into().map_err(|_| {
            DbError::Record(crate::records::RecordError::WrongLength {
                expected: 4,
                found: v.len(),
            })
        })?)),
    };
    Ok(check_version(found))
}

// ---------------------------------------------------------------------------
// reads
// ---------------------------------------------------------------------------

impl BlockchainDb for LmdbDb {
    fn height(&self) -> u64 {
        // `mdb_stat(blocks).ms_entries` (`specs/10` §5.1). A failure here means
        // the environment is gone, which is not something a caller can act on.
        self.read_txn()
            .and_then(|r| Ok(r.entries(self.dbs.blocks)?))
            .unwrap_or(0)
    }

    fn block_exists(&self, h: &Hash256) -> Result<bool> {
        let rtxn = self.read_txn()?;
        Ok(self
            .zerokval_get(&rtxn, self.dbs.block_heights, h)?
            .is_some())
    }

    fn get_block_hash(&self, height: u64) -> Result<Hash256> {
        let rtxn = self.read_txn()?;
        Ok(self.block_info_in(&rtxn, height)?.hash)
    }

    fn get_block_height(&self, h: &Hash256) -> Result<u64> {
        let rtxn = self.read_txn()?;
        self.block_height_in(&rtxn, h)
    }

    fn get_block_blob(&self, height: u64) -> Result<Vec<u8>> {
        let rtxn = self.read_txn()?;
        let raw = rtxn
            .get(self.dbs.blocks, &height.to_ne_bytes())?
            .ok_or(DbError::NotFound)?;
        Ok(raw.to_vec())
    }

    fn get_block_info(&self, height: u64) -> Result<BlockInfo> {
        let rtxn = self.read_txn()?;
        self.block_info_in(&rtxn, height)
    }

    fn get_block_timestamp(&self, height: u64) -> Result<u64> {
        Ok(self.get_block_info(height)?.timestamp)
    }

    fn get_block_weight(&self, height: u64) -> Result<u64> {
        Ok(self.get_block_info(height)?.weight)
    }

    fn get_block_long_term_weight(&self, height: u64) -> Result<u64> {
        Ok(self.get_block_info(height)?.long_term_block_weight)
    }

    fn get_block_cumulative_difficulty(&self, height: u64) -> Result<u128> {
        Ok(self.get_block_info(height)?.cumulative_difficulty)
    }

    fn get_block_already_generated_coins(&self, height: u64) -> Result<u64> {
        Ok(self.get_block_info(height)?.coins)
    }

    fn get_block_cumulative_rct_outputs(&self, heights: &[u64]) -> Result<Vec<u64>> {
        let rtxn = self.read_txn()?;
        heights
            .iter()
            .map(|h| Ok(self.block_info_in(&rtxn, *h)?.cum_rct))
            .collect()
    }

    fn get_long_term_block_weight_median(&self, start: u64, count: u64) -> Result<u64> {
        if count == 0 {
            return Ok(0);
        }
        let rtxn = self.read_txn()?;
        let mut weights = Vec::with_capacity(count as usize);
        for h in start..start + count {
            weights.push(self.block_info_in(&rtxn, h)?.long_term_block_weight);
        }
        Ok(wow_consensus::weight::long_term_median(&mut weights))
    }

    // ---------------------------------------------------------- transactions

    fn tx_exists(&self, h: &Hash256) -> Result<bool> {
        let rtxn = self.read_txn()?;
        Ok(self.zerokval_get(&rtxn, self.dbs.tx_indices, h)?.is_some())
    }

    fn get_tx_data(&self, h: &Hash256) -> Result<TxData> {
        let rtxn = self.read_txn()?;
        let idx = self.tx_index_in(&rtxn, h)?;
        Ok(TxData {
            tx_id: idx.tx_id,
            unlock_time: idx.unlock_time,
            block_height: idx.block_id,
        })
    }

    fn get_tx_blob(&self, h: &Hash256) -> Result<Vec<u8>> {
        let rtxn = self.read_txn()?;
        let idx = self.tx_index_in(&rtxn, h)?;
        let key = idx.tx_id.to_ne_bytes();
        let pruned = rtxn
            .get(self.dbs.txs_pruned, &key)?
            .ok_or(DbError::NotFound)?;
        let prunable = rtxn.get(self.dbs.txs_prunable, &key)?.unwrap_or(&[]);
        let mut out = Vec::with_capacity(pruned.len() + prunable.len());
        out.extend_from_slice(pruned);
        out.extend_from_slice(prunable);
        Ok(out)
    }

    fn get_pruned_tx_blob(&self, h: &Hash256) -> Result<Vec<u8>> {
        let rtxn = self.read_txn()?;
        let idx = self.tx_index_in(&rtxn, h)?;
        let raw = rtxn
            .get(self.dbs.txs_pruned, &idx.tx_id.to_ne_bytes())?
            .ok_or(DbError::NotFound)?;
        Ok(raw.to_vec())
    }

    fn get_prunable_tx_hash(&self, h: &Hash256) -> Result<Hash256> {
        let rtxn = self.read_txn()?;
        let idx = self.tx_index_in(&rtxn, h)?;
        // `txs_prunable_hash` has a real `tx_id` key and holds a single
        // duplicate, so `mdb_get` -- which returns the first data item of a
        // DUPSORT group -- is the whole lookup. No `MDB_GET_BOTH` needed.
        let raw = rtxn
            .get(self.dbs.txs_prunable_hash, &idx.tx_id.to_ne_bytes())?
            .ok_or(DbError::NotFound)?;
        raw.try_into().map_err(|_| {
            DbError::Record(crate::records::RecordError::WrongLength {
                expected: 32,
                found: raw.len(),
            })
        })
    }

    fn get_tx_block_height(&self, h: &Hash256) -> Result<u64> {
        Ok(self.get_tx_data(h)?.block_height)
    }

    fn get_tx_amount_output_indices(&self, tx_id: u64, n: usize) -> Result<Vec<Vec<u64>>> {
        let rtxn = self.read_txn()?;
        let mut out = Vec::with_capacity(n);
        for i in 0..n as u64 {
            let raw = rtxn
                .get(self.dbs.tx_outputs, &(tx_id + i).to_ne_bytes())?
                .ok_or(DbError::NotFound)?;
            out.push(crate::records::decode_tx_outputs(raw)?);
        }
        Ok(out)
    }

    // --------------------------------------------------------------- outputs

    fn get_num_outputs(&self, amount: u64) -> Result<u64> {
        let rtxn = self.read_txn()?;
        let mut c = rtxn.cursor(self.dbs.output_amounts)?;
        if !c.set(&amount.to_ne_bytes())? {
            return Ok(0);
        }
        Ok(c.count()?)
    }

    fn get_output_key(&self, amount: u64, index: u64, with_commitment: bool) -> Result<OutputData> {
        let rtxn = self.read_txn()?;
        let mut c = rtxn.cursor(self.dbs.output_amounts)?;
        let raw = c
            .get_both(&amount.to_ne_bytes(), &index.to_ne_bytes())?
            .ok_or(DbError::NotFound)?;
        Ok(output_data(OutKey::decode(raw)?, amount, with_commitment))
    }

    fn get_output_keys(
        &self,
        amounts: &[u64],
        offsets: &[u64],
        allow_partial: bool,
    ) -> Result<Vec<OutputData>> {
        let rtxn = self.read_txn()?;
        let mut c = rtxn.cursor(self.dbs.output_amounts)?;
        let mut out = Vec::with_capacity(offsets.len());

        for (i, off) in offsets.iter().enumerate() {
            // A single amount broadcasts over every offset, which is the
            // RingCT case (amount 0 for the whole ring).
            let amount = if amounts.len() == 1 {
                amounts[0]
            } else {
                *amounts.get(i).ok_or(DbError::NotFound)?
            };
            match c.get_both(&amount.to_ne_bytes(), &off.to_ne_bytes())? {
                Some(raw) => out.push(output_data(OutKey::decode(raw)?, amount, true)),
                None if allow_partial => {}
                None => return Err(DbError::NotFound),
            }
        }
        Ok(out)
    }

    fn get_output_tx_and_index(&self, amount: u64, index: u64) -> Result<(Hash256, u64)> {
        let rtxn = self.read_txn()?;
        let mut c = rtxn.cursor(self.dbs.output_amounts)?;
        let raw = c
            .get_both(&amount.to_ne_bytes(), &index.to_ne_bytes())?
            .ok_or(DbError::NotFound)?;
        let out = OutKey::decode(raw)?;
        self.get_output_tx_and_index_from_global(out.output_id)
    }

    fn get_output_tx_and_index_from_global(&self, output_id: u64) -> Result<(Hash256, u64)> {
        let rtxn = self.read_txn()?;
        let raw = self
            .zerokval_get(&rtxn, self.dbs.output_txs, &output_id.to_ne_bytes())?
            .ok_or(DbError::NotFound)?;
        let o = OutTx::decode(raw)?;
        Ok((o.tx_hash, o.local_index))
    }

    fn get_output_histogram(
        &self,
        amounts: &[u64],
        _unlocked: bool,
        _recent_cutoff: u64,
        min_count: u64,
    ) -> Result<BTreeMap<u64, HistogramEntry>> {
        // The `unlocked` and `recent` columns need per-output unlock evaluation
        // against the current height; they are computed by the RPC layer, which
        // is where the clock lives. The total is what the chain stores.
        let mut out = BTreeMap::new();
        for a in amounts {
            let total = self.get_num_outputs(*a)?;
            if total >= min_count {
                out.insert(*a, (total, 0, 0));
            }
        }
        Ok(out)
    }

    fn get_output_distribution(&self, amount: u64, from: u64, to: u64) -> Result<Vec<u64>> {
        if amount != 0 {
            // Only amount 0 has a running total to derive from; other amounts
            // would need a scan, and no caller asks for them.
            return Err(DbError::NotFound);
        }
        let heights: Vec<u64> = (from..=to).collect();
        self.get_block_cumulative_rct_outputs(&heights)
    }

    // ------------------------------------------------------------ key images

    fn has_key_image(&self, ki: &KeyImage) -> Result<bool> {
        let rtxn = self.read_txn()?;
        Ok(self
            .zerokval_get(&rtxn, self.dbs.spent_keys, ki.as_bytes())?
            .is_some())
    }

    // ------------------------------------------------------------- hard fork

    fn set_hard_fork_version(&self, height: u64, version: u8) -> Result<()> {
        let mut w = self.writer()?;
        w.txn
            .put(self.dbs.hf_versions, &height.to_ne_bytes(), &[version], 0)?;
        w.commit()
    }

    fn get_hard_fork_version(&self, height: u64) -> Result<u8> {
        let rtxn = self.read_txn()?;
        let raw = rtxn
            .get(self.dbs.hf_versions, &height.to_ne_bytes())?
            .ok_or(DbError::NotFound)?;
        raw.first().copied().ok_or(DbError::NotFound)
    }

    // --------------------------------------------------------------- mempool

    fn add_txpool_tx(&self, h: &Hash256, blob: &[u8], meta: &TxPoolMeta) -> Result<()> {
        let mut w = self.writer()?;
        w.txn.put(self.dbs.txpool_meta, h, &meta.encode(), 0)?;
        w.txn.put(self.dbs.txpool_blob, h, blob, 0)?;
        w.commit()
    }

    fn update_txpool_tx(&self, h: &Hash256, meta: &TxPoolMeta) -> Result<()> {
        let mut w = self.writer()?;
        w.txn.put(self.dbs.txpool_meta, h, &meta.encode(), 0)?;
        w.commit()
    }

    fn remove_txpool_tx(&self, h: &Hash256) -> Result<()> {
        let mut w = self.writer()?;
        w.txn.del(self.dbs.txpool_meta, h, None)?;
        w.txn.del(self.dbs.txpool_blob, h, None)?;
        w.commit()
    }

    fn get_txpool_tx_meta(&self, h: &Hash256) -> Result<TxPoolMeta> {
        let rtxn = self.read_txn()?;
        let raw = rtxn
            .get(self.dbs.txpool_meta, h)?
            .ok_or(DbError::NotFound)?;
        Ok(TxPoolMeta::decode(raw)?)
    }

    fn get_txpool_tx_blob(&self, h: &Hash256) -> Result<Vec<u8>> {
        let rtxn = self.read_txn()?;
        let raw = rtxn
            .get(self.dbs.txpool_blob, h)?
            .ok_or(DbError::NotFound)?;
        Ok(raw.to_vec())
    }

    fn for_all_txpool_txes(&self, f: &mut TxPoolVisitor<'_>) -> Result<()> {
        let rtxn = self.read_txn()?;
        let mut c = rtxn.cursor(self.dbs.txpool_meta)?;
        let mut entry = c.first()?;
        while let Some((k, v)) = entry {
            let hash: Hash256 = k.try_into().map_err(|_| {
                DbError::Record(crate::records::RecordError::WrongLength {
                    expected: 32,
                    found: k.len(),
                })
            })?;
            let meta = TxPoolMeta::decode(v)?;
            let blob = rtxn.get(self.dbs.txpool_blob, k)?;
            if !f(&hash, &meta, blob) {
                break;
            }
            entry = c.next()?;
        }
        Ok(())
    }

    // ------------------------------------------------------------ alt blocks

    fn add_alt_block(&self, h: &Hash256, data: &AltBlockData, blob: &[u8]) -> Result<()> {
        let rec = AltBlock {
            height: data.height,
            cumulative_weight: data.cumulative_weight,
            cumulative_difficulty: data.cumulative_difficulty,
            already_generated_coins: data.already_generated_coins,
            blob: blob.to_vec(),
        };
        let mut w = self.writer()?;
        w.txn.put(self.dbs.alt_blocks, h, &rec.encode(), 0)?;
        w.commit()
    }

    fn get_alt_block(&self, h: &Hash256) -> Result<(AltBlockData, Vec<u8>)> {
        let rtxn = self.read_txn()?;
        let raw = rtxn.get(self.dbs.alt_blocks, h)?.ok_or(DbError::NotFound)?;
        let rec = AltBlock::decode(raw)?;
        Ok((AltBlockData::from(&rec), rec.blob))
    }

    fn remove_alt_block(&self, h: &Hash256) -> Result<()> {
        let mut w = self.writer()?;
        w.txn.del(self.dbs.alt_blocks, h, None)?;
        w.commit()
    }

    fn get_alt_block_count(&self) -> Result<u64> {
        let rtxn = self.read_txn()?;
        Ok(rtxn.entries(self.dbs.alt_blocks)?)
    }

    fn drop_alt_blocks(&self) -> Result<()> {
        let mut w = self.writer()?;
        w.txn.clear_db(self.dbs.alt_blocks)?;
        w.commit()
    }

    // -------------------------------------------------------------- mutation

    fn add_block(
        &self,
        blk: &Block,
        blk_blob: &[u8],
        block_weight: u64,
        long_term_block_weight: u64,
        cumulative_difficulty: u128,
        coins_generated: u64,
        txs: &[(Transaction, Vec<u8>)],
    ) -> Result<u64> {
        let mut w = self.writer()?;
        let h = w.add_block(
            blk,
            blk_blob,
            block_weight,
            long_term_block_weight,
            cumulative_difficulty,
            coins_generated,
            txs,
        )?;
        w.commit()?;
        Ok(h)
    }

    fn pop_block(&self) -> Result<(Block, Vec<Transaction>)> {
        let mut w = self.writer()?;
        let popped = w.pop_block()?;
        w.commit()?;
        Ok(popped)
    }

    fn correct_block_cumulative_difficulties(&self, start: u64, values: &[u128]) -> Result<()> {
        let mut w = self.writer()?;
        for (i, d) in values.iter().enumerate() {
            let height = start + i as u64;
            let mut info = {
                let mut c = w.txn.cursor(self.dbs.block_info)?;
                let raw = c
                    .get_both(&ZEROKEY, &height.to_ne_bytes())?
                    .ok_or(DbError::NotFound)?;
                BlockInfo::decode(raw)?
            };
            w.txn
                .del(self.dbs.block_info, &ZEROKEY, Some(&info.encode()))?;
            info.cumulative_difficulty = *d;
            w.txn
                .put(self.dbs.block_info, &ZEROKEY, &info.encode(), 0)?;
        }
        w.commit()
    }

    // ------------------------------------------------------------- lifecycle

    fn batch_start(&self, _n_blocks: u64, _bytes: u64) -> Result<()> {
        // `specs/10` §6.2 puts the write transaction in the writer task rather
        // than in the database object, and `RwTxn` borrows the environment, so
        // a batch cannot be stashed in `&self`. Use `LmdbDb::writer` and hold
        // the `Writer` across the batch instead — same transaction, same
        // atomicity, with the lifetime checked.
        Err(DbError::Backend(Box::new(BatchShape)))
    }

    fn batch_stop(&self) -> Result<()> {
        Err(DbError::Backend(Box::new(BatchShape)))
    }

    fn resize_barrier(&self) -> Result<()> {
        // Growing the map needs `&mut Env` (`specs/10` §2.2: every outstanding
        // pointer is invalidated), which `&self` cannot provide. The writer
        // task owns the environment and calls `Env::set_map_size` directly.
        Err(DbError::ResizeWhileOpen)
    }

    fn sync(&self) -> Result<()> {
        Ok(self.env.sync(true)?)
    }
}

/// Explains why `batch_start`/`batch_stop` are not the shape to use.
#[derive(Debug)]
struct BatchShape;

impl std::fmt::Display for BatchShape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "use LmdbDb::writer() and hold the Writer across the batch; a write \
             transaction borrows the environment and cannot live in &self"
        )
    }
}

impl std::error::Error for BatchShape {}

/// Turn a stored record into what `get_output_key` returns.
///
/// A pre-RingCT output has no stored commitment, and the C++ synthesises
/// `zero_commit(amount)` when one is asked for (`specs/10` §4.5).
fn output_data(k: OutKey, amount: u64, with_commitment: bool) -> OutputData {
    let commitment = if !with_commitment {
        None
    } else {
        Some(
            k.commitment
                .unwrap_or_else(|| wow_crypto::rct::zero_commit(amount).0),
        )
    };
    OutputData {
        pubkey: k.pubkey,
        unlock_time: k.unlock_time,
        height: k.height,
        commitment,
    }
}

// ---------------------------------------------------------------------------
// writes
// ---------------------------------------------------------------------------

/// The single write transaction (`specs/10` §6.1).
///
/// One `Writer` per block, or one across a whole batch during bulk sync —
/// `specs/10` §6.2 treats those as the same thing, and commit is the atomic
/// unit either way (§6.3).
pub struct Writer<'e> {
    txn: RwTxn<'e>,
    dbs: Dbs,
}

impl Writer<'_> {
    /// Commit. Everything since [`LmdbDb::writer`] lands or none of it does.
    pub fn commit(self) -> Result<()> {
        Ok(self.txn.commit()?)
    }

    /// Abandon the transaction.
    pub fn abort(self) {
        self.txn.abort();
    }

    fn entries(&self, db: Db) -> Result<u64> {
        Ok(self.txn.entries(db)?)
    }

    /// `add_block`, in the order `specs/10` §5.1 fixes.
    ///
    /// The coinbase is added **first**, and every id comes from a table entry
    /// count rather than a stored counter. `specs/10` §5.1: "Any deviation here
    /// renumbers every later output and every ring reference in every later
    /// transaction becomes wrong."
    #[allow(clippy::too_many_arguments, reason = "mirrors the C++ signature")]
    pub fn add_block(
        &mut self,
        blk: &Block,
        blk_blob: &[u8],
        block_weight: u64,
        long_term_block_weight: u64,
        cumulative_difficulty: u128,
        coins_generated: u64,
        txs: &[(Transaction, Vec<u8>)],
    ) -> Result<u64> {
        let height = self.entries(self.dbs.blocks)?;
        let block_hash = blk.block_id().ok_or(DbError::NotFound)?;

        // `bi_cum_rct` continues the previous height's running total
        // (`specs/10` §4.2).
        let previous_cum_rct = if height > 0 {
            let mut c = self.txn.cursor(self.dbs.block_info)?;
            let raw = c
                .get_both(&ZEROKEY, &(height - 1).to_ne_bytes())?
                .ok_or(DbError::NotFound)?;
            BlockInfo::decode(raw)?.cum_rct
        } else {
            0
        };
        let cum_rct = crate::records::cumulative_rct_outputs(
            height,
            blk.header.major_version,
            blk.miner_tx.prefix.version,
            blk.miner_tx.prefix.vout.len(),
            txs.iter()
                .map(|(t, _)| (t.prefix.version, t.prefix.vout.len())),
            previous_cum_rct,
        );

        // THE COINBASE IS FIRST (`specs/10` §5.1).
        let miner_blob = {
            let mut w = wow_serialize::binary::Writer::with_capacity(2048);
            blk.miner_tx.write(&mut w);
            w.into_vec()
        };
        self.add_transaction(height, &blk.miner_tx, &miner_blob)?;
        for (tx, blob) in txs {
            self.add_transaction(height, tx, blob)?;
        }

        self.txn
            .put(self.dbs.blocks, &height.to_ne_bytes(), blk_blob, 0)?;

        let info = BlockInfo {
            height,
            timestamp: blk.header.timestamp,
            coins: coins_generated,
            weight: block_weight,
            cumulative_difficulty,
            hash: block_hash,
            cum_rct,
            long_term_block_weight,
        };
        self.txn
            .put(self.dbs.block_info, &ZEROKEY, &info.encode(), 0)?;

        let bh = BlockHeight {
            hash: block_hash,
            height,
        };
        self.txn
            .put(self.dbs.block_heights, &ZEROKEY, &bh.encode(), 0)?;

        self.txn.put(
            self.dbs.hf_versions,
            &height.to_ne_bytes(),
            &[blk.header.major_version],
            0,
        )?;

        Ok(height)
    }

    /// `add_transaction` (`specs/10` §5.1).
    fn add_transaction(&mut self, height: u64, tx: &Transaction, blob: &[u8]) -> Result<()> {
        // The blob is at hand, so use the form that reads its regions rather
        // than re-serialising three times (`specs/05` §3.2).
        // Fails when `prefix_size` / `unprunable_size` do not describe `blob`,
        // which happens if a parsed transaction was mutated without re-deriving
        // them -- they belong to the blob it came from (`specs/10` §4.8:
        // "record both offsets during parsing and carry them on the
        // transaction"). Say so, rather than returning a bare NotFound that
        // reads like a missing record.
        let tx_hash = wow_types::hashes::transaction_hash_from_blob(tx, blob).ok_or_else(|| {
            DbError::Backend(Box::new(OffsetMismatch {
                blob_len: blob.len(),
                prefix_size: tx.prefix_size,
                unprunable_size: tx.unprunable_size,
            }))
        })?;

        // Key images first. `txin_gen` contributes nothing, which is why a
        // coinbase adds no spent keys despite being added first.
        for ki in spent_key_images(tx) {
            self.txn.put(self.dbs.spent_keys, &ZEROKEY, ki, 0)?;
        }

        // `get_tx_count()` == entries in `txs_pruned`.
        let tx_id = self.entries(self.dbs.txs_pruned)?;
        let key = tx_id.to_ne_bytes();

        let (pruned, prunable) = split_tx_blob(blob, tx.unprunable_size).ok_or_else(|| {
            DbError::Record(crate::records::RecordError::WrongLength {
                expected: tx.unprunable_size,
                found: blob.len(),
            })
        })?;
        self.txn.put(self.dbs.txs_pruned, &key, pruned, 0)?;
        self.txn.put(self.dbs.txs_prunable, &key, prunable, 0)?;

        // `txs_prunable_hash` is written only for v2 (`specs/10` §4.8), and is
        // undefined for `rct.type == Null` (`specs/05` §3.3) -- which is every
        // coinbase, so a v2 coinbase writes nothing here.
        if tx.prefix.version > 1 {
            if let Some(h) = wow_types::hashes::tx_prunable_hash_from_blob(tx, blob) {
                self.txn.put(self.dbs.txs_prunable_hash, &key, &h, 0)?;
            }
        }

        let idx = TxIndex {
            key: tx_hash,
            tx_id,
            unlock_time: tx.prefix.unlock_time,
            block_id: height,
        };
        self.txn
            .put(self.dbs.tx_indices, &ZEROKEY, &idx.encode(), 0)?;

        // Outputs, in order, each taking the next global id.
        let stored = stored_outputs(tx).map_err(|e| DbError::Backend(Box::new(StoreFailed(e))))?;
        let mut amount_output_indices = Vec::with_capacity(stored.len());
        for (i, s) in stored.iter().enumerate() {
            let pubkey = tx.prefix.vout[i]
                .target
                .public_key()
                .ok_or(DbError::NotFound)?;
            let amount_index = self.add_output(
                &tx_hash,
                s.amount,
                pubkey.0,
                i as u64,
                tx.prefix.unlock_time,
                height,
                s.commitment.map(|c| c.0),
            )?;
            amount_output_indices.push(amount_index);
        }
        self.txn.put(
            self.dbs.tx_outputs,
            &key,
            &crate::records::encode_tx_outputs(&amount_output_indices),
            0,
        )?;
        Ok(())
    }

    /// `add_output` (`specs/10` §5.1), returning the `amount_index`.
    #[allow(clippy::too_many_arguments, reason = "mirrors the C++ signature")]
    fn add_output(
        &mut self,
        tx_hash: &Hash256,
        amount: u64,
        pubkey: [u8; 32],
        local_index: u64,
        unlock_time: u64,
        height: u64,
        commitment: Option<[u8; 32]>,
    ) -> Result<u64> {
        // `num_outputs()` == entries in `output_txs`: global and dense.
        let output_id = self.entries(self.dbs.output_txs)?;

        let outtx = OutTx {
            output_id,
            tx_hash: *tx_hash,
            local_index,
        };
        self.txn
            .put(self.dbs.output_txs, &ZEROKEY, &outtx.encode(), 0)?;

        // `amount_index` is `mdb_cursor_count` on the dup group — the call
        // `heed` could not provide (`docs/spec-deltas.md` §16).
        let existing = {
            let mut c = self.txn.cursor(self.dbs.output_amounts)?;
            if c.set(&amount.to_ne_bytes())? {
                c.count()?
            } else {
                0
            }
        };
        let amount_index = next_amount_index(existing);

        let rec = OutKey {
            amount_index,
            output_id,
            pubkey,
            unlock_time,
            height,
            commitment,
        };
        self.txn.put(
            self.dbs.output_amounts,
            &amount.to_ne_bytes(),
            &rec.encode(),
            0,
        )?;

        Ok(amount_index)
    }

    /// `pop_block` — the exact inverse of `add_block`, in reverse order, with
    /// the **coinbase last** (`specs/10` §6.4).
    pub fn pop_block(&mut self) -> Result<(Block, Vec<Transaction>)> {
        let height = self.entries(self.dbs.blocks)?;
        if height == 0 {
            return Err(DbError::NotFound);
        }
        let tip = height - 1;

        let blob = self
            .txn
            .get(self.dbs.blocks, &tip.to_ne_bytes())?
            .ok_or(DbError::NotFound)?
            .to_vec();
        let blk = Block::from_blob(&blob).map_err(|_| {
            DbError::Record(crate::records::RecordError::WrongLength {
                expected: 0,
                found: blob.len(),
            })
        })?;

        // Remove in reverse: block transactions last-to-first, then the
        // coinbase.
        let mut popped = Vec::with_capacity(blk.tx_hashes.len());
        for h in blk.tx_hashes.iter().rev() {
            popped.push(self.remove_transaction(h)?);
        }
        popped.reverse();
        let miner_blob = {
            let mut w = wow_serialize::binary::Writer::with_capacity(2048);
            blk.miner_tx.write(&mut w);
            w.into_vec()
        };
        let miner_hash = wow_types::hashes::transaction_hash_from_blob(&blk.miner_tx, &miner_blob)
            .ok_or(DbError::NotFound)?;
        self.remove_transaction(&miner_hash)?;

        let info = {
            let mut c = self.txn.cursor(self.dbs.block_info)?;
            let raw = c
                .get_both(&ZEROKEY, &tip.to_ne_bytes())?
                .ok_or(DbError::NotFound)?;
            BlockInfo::decode(raw)?
        };
        self.txn
            .del(self.dbs.block_info, &ZEROKEY, Some(&info.encode()))?;

        let bh = BlockHeight {
            hash: info.hash,
            height: tip,
        };
        self.txn
            .del(self.dbs.block_heights, &ZEROKEY, Some(&bh.encode()))?;
        self.txn.del(self.dbs.blocks, &tip.to_ne_bytes(), None)?;
        self.txn
            .del(self.dbs.hf_versions, &tip.to_ne_bytes(), None)?;

        Ok((blk, popped))
    }

    /// Remove one transaction and everything it owns.
    fn remove_transaction(&mut self, tx_hash: &Hash256) -> Result<Transaction> {
        let idx = {
            let mut c = self.txn.cursor(self.dbs.tx_indices)?;
            let raw = c.get_both(&ZEROKEY, tx_hash)?.ok_or(DbError::NotFound)?;
            TxIndex::decode(raw)?
        };
        let key = idx.tx_id.to_ne_bytes();

        // Rebuild the transaction before deleting it, so it can go back to the
        // pool (`specs/06` §7).
        let tx = {
            let pruned = self
                .txn
                .get(self.dbs.txs_pruned, &key)?
                .ok_or(DbError::NotFound)?;
            let prunable = self.txn.get(self.dbs.txs_prunable, &key)?.unwrap_or(&[]);
            let mut blob = Vec::with_capacity(pruned.len() + prunable.len());
            blob.extend_from_slice(pruned);
            blob.extend_from_slice(prunable);
            Transaction::from_blob(&blob).map_err(|_| {
                DbError::Record(crate::records::RecordError::WrongLength {
                    expected: 0,
                    found: blob.len(),
                })
            })?
        };

        // Outputs, in reverse. Each removed `output_id` must be the last one —
        // the self-check `specs/10` §6.4 asks for.
        let indices = {
            let raw = self
                .txn
                .get(self.dbs.tx_outputs, &key)?
                .ok_or(DbError::NotFound)?;
            crate::records::decode_tx_outputs(raw)?
        };
        let stored = stored_outputs(&tx).map_err(|e| DbError::Backend(Box::new(StoreFailed(e))))?;

        for i in (0..stored.len()).rev() {
            let amount = stored[i].amount;
            let amount_index = *indices.get(i).ok_or(DbError::NotFound)?;

            let out = {
                let mut c = self.txn.cursor(self.dbs.output_amounts)?;
                let raw = c
                    .get_both(&amount.to_ne_bytes(), &amount_index.to_ne_bytes())?
                    .ok_or(DbError::NotFound)?;
                OutKey::decode(raw)?
            };

            let total = self.entries(self.dbs.output_txs)?;
            if out.output_id + 1 != total {
                return Err(DbError::Backend(Box::new(TipMismatch {
                    what: "pop_block: output_id is not the last one",
                    expected: total - 1,
                    found: out.output_id,
                })));
            }

            self.txn.del(
                self.dbs.output_amounts,
                &amount.to_ne_bytes(),
                Some(&out.encode()),
            )?;

            let outtx = {
                let mut c = self.txn.cursor(self.dbs.output_txs)?;
                let raw = c
                    .get_both(&ZEROKEY, &out.output_id.to_ne_bytes())?
                    .ok_or(DbError::NotFound)?;
                OutTx::decode(raw)?
            };
            self.txn
                .del(self.dbs.output_txs, &ZEROKEY, Some(&outtx.encode()))?;
        }

        self.txn.del(self.dbs.tx_outputs, &key, None)?;
        self.txn
            .del(self.dbs.tx_indices, &ZEROKEY, Some(&idx.encode()))?;
        self.txn.del(self.dbs.txs_pruned, &key, None)?;
        self.txn.del(self.dbs.txs_prunable, &key, None)?;
        self.txn.del(self.dbs.txs_prunable_hash, &key, None)?;

        for ki in spent_key_images(&tx) {
            self.txn.del(self.dbs.spent_keys, &ZEROKEY, Some(ki))?;
        }

        Ok(tx)
    }
}

/// A transaction's recorded region offsets do not describe the blob it was
/// given.
#[derive(Debug)]
struct OffsetMismatch {
    blob_len: usize,
    prefix_size: usize,
    unprunable_size: usize,
}

impl std::fmt::Display for OffsetMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "transaction offsets do not describe this blob: prefix_size {},              unprunable_size {}, blob {} bytes. The offsets are recorded when a              transaction is parsed and belong to that blob; a transaction built              or mutated in memory must be re-serialised and re-parsed, or have              them recomputed.",
            self.prefix_size, self.unprunable_size, self.blob_len
        )
    }
}

impl std::error::Error for OffsetMismatch {}

/// A `stored_outputs` failure, boxed into the trait's error type.
#[derive(Debug)]
struct StoreFailed(crate::semantics::StoreError);

impl std::fmt::Display for StoreFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot store outputs: {:?}", self.0)
    }
}

impl std::error::Error for StoreFailed {}

/// Every table, for callers that want to enumerate them.
pub fn all_tables() -> &'static [Table] {
    TABLES
}
