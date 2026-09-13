//! A thin safe layer over `lmdb-master-sys`.
//!
//! # Why not `heed`
//!
//! `specs/10` §1 recommends `heed`, and it was tried first. It cannot express
//! this schema:
//!
//! * **No `MDB_GET_BOTH`.** Five tables store their logical key as a *prefix of
//!   the value* under a single dummy key (`specs/10` §3.2), and a lookup is
//!   "position at `ZEROKEY`, then `MDB_GET_BOTH` on the value prefix". `heed`
//!   exposes `MDB_SET` and `MDB_SET_RANGE` on keys only, so the nearest
//!   equivalent is iterating the dup group — O(n) over millions of records for
//!   every `block_info`, `tx_indices` or ring-member read.
//! * **No `mdb_cursor_count`.** `amount_index` is the dup count under
//!   `output_amounts[amount]` (`specs/10` §5.1). `specs/10` anticipates this
//!   exact gap and says to "drop to `lmdb-master-sys` for this one call".
//! * `heed` keeps `MDB_dbi` private and exports no cursor type, so neither can
//!   be reached from outside.
//!
//! Changing the layout to suit the binding was never an option: the M2 gate is
//! that `wownerod` opens a database this node wrote.
//!
//! `lmdb-master-sys` is the crate `heed` itself builds on, so this is not a new
//! dependency — it is the same liblmdb with the wrapper removed.
//!
//! # Safety model
//!
//! LMDB hands out pointers into an mmap that live exactly as long as the
//! transaction. That is expressed with lifetimes here: [`RoTxn`] borrows the
//! [`Env`], a cursor borrows the transaction, and every returned `&[u8]`
//! borrows the transaction. The compiler then enforces what `specs/10` §1.1
//! asks for in prose — "never copy a `&[u8]` out of a transaction and use it
//! after commit/abort".
//!
//! What it cannot enforce is a corrupt file. `specs/10` §1.1 notes a truncated
//! `data.mdb` can segfault inside LMDB rather than return an error; no wrapper
//! shape prevents that, which is why every decoder in [`crate::records`] checks
//! its length instead of casting.

#![allow(
    unsafe_code,
    reason = "this module is the FFI boundary; every block carries a SAFETY note"
)]

use std::ffi::{c_uint, c_void, CString};
use std::marker::PhantomData;
use std::path::Path;
use std::ptr;

use lmdb_master_sys as ffi;

use crate::comparator;

/// An LMDB error code, with the operation that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LmdbError {
    pub code: i32,
    pub op: &'static str,
}

impl LmdbError {
    /// `MDB_NOTFOUND`.
    pub fn is_not_found(&self) -> bool {
        self.code == ffi::MDB_NOTFOUND
    }

    /// `MDB_MAP_FULL` — the map size must grow (`specs/10` §2.2).
    pub fn is_map_full(&self) -> bool {
        self.code == ffi::MDB_MAP_FULL
    }

    /// `MDB_READERS_FULL` — backpressure, not a fatal error (`specs/10` §6.2).
    pub fn is_readers_full(&self) -> bool {
        self.code == ffi::MDB_READERS_FULL
    }
}

impl std::fmt::Display for LmdbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SAFETY: `mdb_strerror` returns a pointer to a static string for every
        // code, including unknown ones (it falls through to `strerror`). It is
        // never null and needs no freeing.
        let msg = unsafe {
            let p = ffi::mdb_strerror(self.code);
            if p.is_null() {
                "unknown".to_string()
            } else {
                std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        write!(f, "{}: {msg} ({})", self.op, self.code)
    }
}

impl std::error::Error for LmdbError {}

pub type Result<T> = std::result::Result<T, LmdbError>;

fn check(code: i32, op: &'static str) -> Result<()> {
    if code == ffi::MDB_SUCCESS {
        Ok(())
    } else {
        Err(LmdbError { code, op })
    }
}

/// An empty `MDB_val`.
fn null_val() -> ffi::MDB_val {
    ffi::MDB_val {
        mv_size: 0,
        mv_data: ptr::null_mut(),
    }
}

/// An `MDB_val` pointing at `s`.
///
/// The caller must keep `s` alive for as long as the value is used; every call
/// site here passes a slice that outlives the FFI call.
fn val(s: &[u8]) -> ffi::MDB_val {
    ffi::MDB_val {
        mv_size: s.len(),
        mv_data: s.as_ptr() as *mut c_void,
    }
}

/// Borrow an `MDB_val` as a slice valid for `'txn`.
///
/// # Safety
///
/// `v` must have been filled by LMDB from a live transaction whose lifetime is
/// at least `'txn`, and the data must not be written to through any other path
/// while the borrow lives.
unsafe fn as_slice<'txn>(v: &ffi::MDB_val) -> &'txn [u8] {
    if v.mv_data.is_null() {
        return &[];
    }
    std::slice::from_raw_parts(v.mv_data as *const u8, v.mv_size)
}

// ---------------------------------------------------------------------------
// comparator callbacks
// ---------------------------------------------------------------------------

/// Build an `extern "C"` comparator from one of ours.
///
/// LMDB stores the function pointer per-dbi for the life of the environment, so
/// these must be plain functions with no captured state.
macro_rules! comparator_fn {
    ($name:ident, $f:path) => {
        /// # Safety
        ///
        /// LMDB calls this with two non-null `MDB_val`s describing keys it is
        /// comparing, both valid for the duration of the call.
        unsafe extern "C" fn $name(
            a: *const ffi::MDB_val,
            b: *const ffi::MDB_val,
        ) -> ::std::ffi::c_int {
            // SAFETY: LMDB never passes null here, and the pointed-to buffers
            // are live for this call.
            let (a, b) = unsafe { (as_slice(&*a), as_slice(&*b)) };
            match $f(a, b) {
                ::std::cmp::Ordering::Less => -1,
                ::std::cmp::Ordering::Equal => 0,
                ::std::cmp::Ordering::Greater => 1,
            }
        }
    };
}

comparator_fn!(cmp_uint64, comparator::compare_uint64);
comparator_fn!(cmp_hash32, comparator::compare_hash32);
comparator_fn!(cmp_string, comparator::compare_string);

/// Which comparator to install.
///
/// `MDB_cmp_func` is itself an `Option<fn>`, so `None` here means "leave LMDB's
/// own ordering alone" and is never passed to `mdb_set_compare`.
fn comparator_ptr(c: crate::tables::Cmp) -> ffi::MDB_cmp_func {
    use crate::tables::Cmp;
    match c {
        Cmp::Default => None,
        Cmp::Uint64 => Some(cmp_uint64),
        Cmp::Hash32 => Some(cmp_hash32),
        Cmp::String => Some(cmp_string),
    }
}

// ---------------------------------------------------------------------------
// Env
// ---------------------------------------------------------------------------

/// An open LMDB environment.
///
/// `Send`/`Sync`: LMDB is thread-safe for concurrent readers and a single
/// writer provided the environment was not opened with `MDB_NOTLS` misuse.
/// Transactions are *not* shared across threads here — each is created and
/// dropped on one thread — and the writer is serialised by LMDB itself.
pub struct Env {
    ptr: *mut ffi::MDB_env,
}

// SAFETY: `MDB_env` is documented as safe to share between threads; LMDB does
// its own locking for the reader table and serialises writers. The only
// requirement this wrapper must uphold is that a transaction does not migrate
// between threads, which the borrow-checked API below prevents (transactions
// are neither `Send` nor `Sync`).
unsafe impl Send for Env {}
unsafe impl Sync for Env {}

impl Env {
    /// `mdb_env_create` + `mdb_env_open`, reproducing `BlockchainLMDB::open`
    /// (`specs/10` §2).
    ///
    /// `flags` comes from [`crate::env::OpenMode::flags_raw`].
    pub fn open(
        path: &Path,
        flags: c_uint,
        max_dbs: u32,
        max_readers: Option<u32>,
        map_size: usize,
    ) -> Result<Env> {
        let mut ptr: *mut ffi::MDB_env = ptr::null_mut();
        // SAFETY: `mdb_env_create` writes a fresh handle through the out
        // pointer and touches nothing else.
        check(unsafe { ffi::mdb_env_create(&mut ptr) }, "mdb_env_create")?;

        let env = Env { ptr };

        // SAFETY: `env.ptr` is a valid handle from `mdb_env_create`, and none
        // of these may be called after `mdb_env_open`, which is why they are
        // here. On any failure `env`'s Drop closes the handle.
        unsafe {
            check(
                ffi::mdb_env_set_maxdbs(env.ptr, max_dbs),
                "mdb_env_set_maxdbs",
            )?;
            if let Some(r) = max_readers {
                check(
                    ffi::mdb_env_set_maxreaders(env.ptr, r),
                    "mdb_env_set_maxreaders",
                )?;
            }
            check(
                ffi::mdb_env_set_mapsize(env.ptr, map_size),
                "mdb_env_set_mapsize",
            )?;
        }

        let c_path = CString::new(path_bytes(path)).map_err(|_| LmdbError {
            code: libc::EINVAL,
            op: "path contains a NUL",
        })?;

        // SAFETY: `c_path` is NUL-terminated and outlives the call. 0o644 is
        // the mode the C++ passes.
        check(
            unsafe { ffi::mdb_env_open(env.ptr, c_path.as_ptr(), flags, 0o644) },
            "mdb_env_open",
        )?;
        Ok(env)
    }

    /// Begin a read transaction.
    pub fn read_txn(&self) -> Result<RoTxn<'_>> {
        let mut txn: *mut ffi::MDB_txn = ptr::null_mut();
        // SAFETY: a null parent and `MDB_RDONLY` start a top-level read txn.
        check(
            unsafe { ffi::mdb_txn_begin(self.ptr, ptr::null_mut(), ffi::MDB_RDONLY, &mut txn) },
            "mdb_txn_begin(read)",
        )?;
        Ok(RoTxn {
            ptr: txn,
            _env: PhantomData,
        })
    }

    /// Begin the write transaction. LMDB permits only one at a time
    /// environment-wide and will block until the previous one finishes
    /// (`specs/10` §6.1).
    pub fn write_txn(&self) -> Result<RwTxn<'_>> {
        let mut txn: *mut ffi::MDB_txn = ptr::null_mut();
        // SAFETY: a null parent and no flags start a top-level write txn.
        check(
            unsafe { ffi::mdb_txn_begin(self.ptr, ptr::null_mut(), 0, &mut txn) },
            "mdb_txn_begin(write)",
        )?;
        Ok(RwTxn {
            inner: RoTxn {
                ptr: txn,
                _env: PhantomData,
            },
        })
    }

    /// `mdb_env_sync(force)`.
    pub fn sync(&self, force: bool) -> Result<()> {
        // SAFETY: valid handle; `force` is a plain int flag.
        check(
            unsafe { ffi::mdb_env_sync(self.ptr, c_uint::from(force) as i32) },
            "mdb_env_sync",
        )
    }

    /// `mdb_env_info().me_mapsize`, and `mdb_stat().ms_psize` /
    /// `me_last_pgno` — the three numbers `need_resize` works from
    /// (`specs/10` §2.2).
    pub fn size_info(&self) -> Result<MapInfo> {
        let mut info = std::mem::MaybeUninit::<ffi::MDB_envinfo>::uninit();
        let mut stat = std::mem::MaybeUninit::<ffi::MDB_stat>::uninit();
        // SAFETY: both calls fully initialise the structs they are given.
        unsafe {
            check(
                ffi::mdb_env_info(self.ptr, info.as_mut_ptr()),
                "mdb_env_info",
            )?;
            check(
                ffi::mdb_env_stat(self.ptr, stat.as_mut_ptr()),
                "mdb_env_stat",
            )?;
            let info = info.assume_init();
            let stat = stat.assume_init();
            Ok(MapInfo {
                map_size: info.me_mapsize as u64,
                last_pgno: info.me_last_pgno as u64,
                page_size: stat.ms_psize as u64,
            })
        }
    }

    /// `mdb_env_set_mapsize`.
    ///
    /// `specs/10` §2.2: this **must not** be called while any transaction is
    /// open, because it invalidates every outstanding pointer. Taking `&mut
    /// self` is what makes that checkable — an open transaction borrows the
    /// environment immutably.
    pub fn set_map_size(&mut self, size: usize) -> Result<()> {
        // SAFETY: `&mut self` proves no transaction borrows this environment,
        // which is the precondition LMDB documents.
        check(
            unsafe { ffi::mdb_env_set_mapsize(self.ptr, size) },
            "mdb_env_set_mapsize",
        )
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: every transaction borrows `self`, so none can be live
            // here. `mdb_env_close` is the documented counterpart to create.
            unsafe { ffi::mdb_env_close(self.ptr) };
        }
    }
}

/// The map-size numbers `specs/10` §2.2 computes with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapInfo {
    pub map_size: u64,
    pub last_pgno: u64,
    pub page_size: u64,
}

#[cfg(unix)]
fn path_bytes(p: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    p.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(p: &Path) -> Vec<u8> {
    p.to_string_lossy().into_owned().into_bytes()
}

// ---------------------------------------------------------------------------
// transactions
// ---------------------------------------------------------------------------

/// A read transaction — a consistent snapshot for its whole life
/// (`specs/10` §6.2).
///
/// Not `Send`: LMDB ties a read transaction to the thread that created it
/// unless `MDB_NOTLS` is set, and this wrapper does not set it.
pub struct RoTxn<'e> {
    ptr: *mut ffi::MDB_txn,
    _env: PhantomData<&'e Env>,
}

impl RoTxn<'_> {
    /// Open a database handle inside this transaction.
    ///
    /// `create` is false here — a read transaction cannot create one.
    pub fn open_db(&self, name: &str, flags: c_uint, table: &crate::tables::Table) -> Result<Db> {
        open_db_in(self.ptr, name, flags, table)
    }

    /// Commit a read transaction.
    ///
    /// Committing a *read* transaction is how the dbi handles opened inside it
    /// become visible to the environment; dropping it instead leaves later
    /// transactions unable to use them.
    pub fn commit(self) -> Result<()> {
        let ptr = self.ptr;
        std::mem::forget(self);
        // SAFETY: the handle is live and is not used again — `forget` skips the
        // Drop that would abort it.
        check(unsafe { ffi::mdb_txn_commit(ptr) }, "mdb_txn_commit(read)")
    }

    /// `mdb_get`.
    pub fn get(&self, db: Db, key: &[u8]) -> Result<Option<&[u8]>> {
        let mut k = val(key);
        let mut v = null_val();
        // SAFETY: `key` outlives the call; `v` is filled with a pointer into
        // the mmap valid for this transaction, which the return type ties to
        // `&self`.
        let rc = unsafe { ffi::mdb_get(self.ptr, db.0, &mut k, &mut v) };
        if rc == ffi::MDB_NOTFOUND {
            return Ok(None);
        }
        check(rc, "mdb_get")?;
        // SAFETY: LMDB filled `v` from this live transaction.
        Ok(Some(unsafe { as_slice(&v) }))
    }

    /// Open a cursor.
    pub fn cursor(&self, db: Db) -> Result<Cursor<'_>> {
        cursor_in(self.ptr, db)
    }

    /// `mdb_stat().ms_entries` — the entry count a table id is derived from
    /// (`specs/10` §5.1).
    pub fn entries(&self, db: Db) -> Result<u64> {
        stat_entries(self.ptr, db)
    }
}

impl Drop for RoTxn<'_> {
    fn drop(&mut self) {
        // SAFETY: aborting a read transaction is always safe and is the
        // cheapest way to end one.
        unsafe { ffi::mdb_txn_abort(self.ptr) };
    }
}

/// The single write transaction (`specs/10` §6.1).
///
/// Derefs to [`RoTxn`], so every read method is available on it.
pub struct RwTxn<'e> {
    inner: RoTxn<'e>,
}

impl<'e> std::ops::Deref for RwTxn<'e> {
    type Target = RoTxn<'e>;
    fn deref(&self) -> &RoTxn<'e> {
        &self.inner
    }
}

impl RwTxn<'_> {
    /// Open a database handle, creating it if absent.
    pub fn create_db(
        &mut self,
        name: &str,
        flags: c_uint,
        table: &crate::tables::Table,
    ) -> Result<Db> {
        open_db_in(self.inner.ptr, name, flags | ffi::MDB_CREATE, table)
    }

    /// `mdb_put`.
    pub fn put(&mut self, db: Db, key: &[u8], value: &[u8], flags: c_uint) -> Result<()> {
        let mut k = val(key);
        let mut v = val(value);
        // SAFETY: both slices outlive the call, and LMDB copies them.
        check(
            unsafe { ffi::mdb_put(self.inner.ptr, db.0, &mut k, &mut v, flags) },
            "mdb_put",
        )
    }

    /// `mdb_del`. With `value`, deletes that one duplicate; without, the key
    /// and all its duplicates.
    ///
    /// Returns false when the entry was not there.
    pub fn del(&mut self, db: Db, key: &[u8], value: Option<&[u8]>) -> Result<bool> {
        let mut k = val(key);
        let mut v = value.map(val);
        let vp = v.as_mut().map_or(ptr::null_mut(), |v| v as *mut _);
        // SAFETY: both slices outlive the call.
        let rc = unsafe { ffi::mdb_del(self.inner.ptr, db.0, &mut k, vp) };
        if rc == ffi::MDB_NOTFOUND {
            return Ok(false);
        }
        check(rc, "mdb_del")?;
        Ok(true)
    }

    /// `mdb_drop(del = 0)` — empty the table but keep the handle.
    ///
    /// This is what `hf_starting_heights` gets on every open (`specs/10` §3).
    pub fn clear_db(&mut self, db: Db) -> Result<()> {
        // SAFETY: `del = 0` empties the database and leaves the dbi valid.
        check(
            unsafe { ffi::mdb_drop(self.inner.ptr, db.0, 0) },
            "mdb_drop",
        )
    }

    /// A writable cursor.
    pub fn cursor_mut(&mut self, db: Db) -> Result<Cursor<'_>> {
        cursor_in(self.inner.ptr, db)
    }

    /// Commit. This is the atomic unit (`specs/10` §6.3).
    pub fn commit(self) -> Result<()> {
        let ptr = self.inner.ptr;
        std::mem::forget(self);
        // SAFETY: the handle is live and not used again; `forget` skips the
        // Drop that would otherwise abort it.
        check(unsafe { ffi::mdb_txn_commit(ptr) }, "mdb_txn_commit")
    }

    /// Abort explicitly. Dropping does the same.
    pub fn abort(self) {
        drop(self);
    }
}

/// A database handle.
///
/// `MDB_dbi` is an index into a per-environment table and stays valid for the
/// life of the environment, so this is `Copy` and outlives the transaction that
/// opened it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Db(ffi::MDB_dbi);

fn open_db_in(
    txn: *mut ffi::MDB_txn,
    name: &str,
    flags: c_uint,
    table: &crate::tables::Table,
) -> Result<Db> {
    let c_name = CString::new(name).map_err(|_| LmdbError {
        code: libc::EINVAL,
        op: "table name contains a NUL",
    })?;
    let mut dbi: ffi::MDB_dbi = 0;
    // SAFETY: `c_name` is NUL-terminated and outlives the call.
    check(
        unsafe { ffi::mdb_dbi_open(txn, c_name.as_ptr(), flags, &mut dbi) },
        "mdb_dbi_open",
    )?;

    // The comparators are part of the file format (`specs/10` §3) and must be
    // set on every open, before any read, because LMDB does not persist them.
    let key_cmp = comparator_ptr(table.key_cmp);
    if key_cmp.is_some() {
        // SAFETY: the callback is a plain `extern "C"` function with no
        // captured state, valid for the whole program, which is what LMDB
        // requires since it stores the pointer per-dbi.
        check(
            unsafe { ffi::mdb_set_compare(txn, dbi, key_cmp) },
            "mdb_set_compare",
        )?;
    }
    let dup_cmp = comparator_ptr(table.dup_cmp);
    if dup_cmp.is_some() {
        // SAFETY: as above.
        check(
            unsafe { ffi::mdb_set_dupsort(txn, dbi, dup_cmp) },
            "mdb_set_dupsort",
        )?;
    }
    Ok(Db(dbi))
}

fn stat_entries(txn: *mut ffi::MDB_txn, db: Db) -> Result<u64> {
    let mut stat = std::mem::MaybeUninit::<ffi::MDB_stat>::uninit();
    // SAFETY: `mdb_stat` fully initialises the struct.
    unsafe {
        check(ffi::mdb_stat(txn, db.0, stat.as_mut_ptr()), "mdb_stat")?;
        Ok(stat.assume_init().ms_entries as u64)
    }
}

fn cursor_in<'t>(txn: *mut ffi::MDB_txn, db: Db) -> Result<Cursor<'t>> {
    let mut ptr: *mut ffi::MDB_cursor = ptr::null_mut();
    // SAFETY: the transaction is live for `'t` by the caller's borrow.
    check(
        unsafe { ffi::mdb_cursor_open(txn, db.0, &mut ptr) },
        "mdb_cursor_open",
    )?;
    Ok(Cursor {
        ptr,
        _txn: PhantomData,
    })
}

// ---------------------------------------------------------------------------
// cursors
// ---------------------------------------------------------------------------

/// A cursor. Borrows its transaction, so every slice it yields is valid for as
/// long as the cursor's borrow.
pub struct Cursor<'t> {
    ptr: *mut ffi::MDB_cursor,
    _txn: PhantomData<&'t ()>,
}

impl<'t> Cursor<'t> {
    fn get(
        &mut self,
        key: Option<&[u8]>,
        value: Option<&[u8]>,
        op: ffi::MDB_cursor_op,
    ) -> Result<Option<(&'t [u8], &'t [u8])>> {
        let mut k = key.map_or_else(null_val, val);
        let mut v = value.map_or_else(null_val, val);
        // SAFETY: any slices passed outlive the call; LMDB fills `k`/`v` with
        // pointers into the mmap valid for the transaction, which `'t` ties to.
        let rc = unsafe { ffi::mdb_cursor_get(self.ptr, &mut k, &mut v, op) };
        if rc == ffi::MDB_NOTFOUND {
            return Ok(None);
        }
        check(rc, "mdb_cursor_get")?;
        // SAFETY: filled by LMDB from the live transaction.
        Ok(Some(unsafe { (as_slice(&k), as_slice(&v)) }))
    }

    /// `MDB_SET` — position exactly at `key`.
    pub fn set(&mut self, key: &[u8]) -> Result<bool> {
        Ok(self.get(Some(key), None, ffi::MDB_SET)?.is_some())
    }

    /// **`MDB_GET_BOTH`** — position at `(key, value)` exactly.
    ///
    /// This is the operation the five `zerokval` tables are read with
    /// (`specs/10` §3.2), and the one `heed` cannot express. The dupsort
    /// comparator decides the match, so for `block_info` the "value" passed
    /// here is just the eight-byte height prefix and the comparator ignores the
    /// rest.
    pub fn get_both(&mut self, key: &[u8], value: &[u8]) -> Result<Option<&'t [u8]>> {
        Ok(self
            .get(Some(key), Some(value), ffi::MDB_GET_BOTH)?
            .map(|(_, v)| v))
    }

    /// `MDB_GET_BOTH_RANGE` — the first duplicate at or after `value`.
    pub fn get_both_range(&mut self, key: &[u8], value: &[u8]) -> Result<Option<&'t [u8]>> {
        Ok(self
            .get(Some(key), Some(value), ffi::MDB_GET_BOTH_RANGE)?
            .map(|(_, v)| v))
    }

    /// `MDB_FIRST`.
    pub fn first(&mut self) -> Result<Option<(&'t [u8], &'t [u8])>> {
        self.get(None, None, ffi::MDB_FIRST)
    }

    /// `MDB_LAST`.
    pub fn last(&mut self) -> Result<Option<(&'t [u8], &'t [u8])>> {
        self.get(None, None, ffi::MDB_LAST)
    }

    /// `MDB_NEXT`.
    ///
    /// Named for the LMDB operation, not for `Iterator::next` — a cursor is
    /// not an iterator here because every move needs a `Result`.
    #[allow(
        clippy::should_implement_trait,
        reason = "mirrors MDB_NEXT; a fallible move cannot be Iterator::next"
    )]
    pub fn next(&mut self) -> Result<Option<(&'t [u8], &'t [u8])>> {
        self.get(None, None, ffi::MDB_NEXT)
    }

    /// `MDB_NEXT_DUP` — the next duplicate under the current key.
    pub fn next_dup(&mut self) -> Result<Option<(&'t [u8], &'t [u8])>> {
        self.get(None, None, ffi::MDB_NEXT_DUP)
    }

    /// `MDB_LAST_DUP` — the last duplicate under the current key.
    pub fn last_dup(&mut self) -> Result<Option<(&'t [u8], &'t [u8])>> {
        self.get(None, None, ffi::MDB_LAST_DUP)
    }

    /// **`mdb_cursor_count`** — how many duplicates share the current key.
    ///
    /// This is `amount_index` (`specs/10` §5.1): the dup count under
    /// `output_amounts[amount]` before the new output is added. The cursor must
    /// already be positioned on the key.
    ///
    /// The other call the spec says `heed` cannot provide.
    pub fn count(&mut self) -> Result<u64> {
        let mut n: ffi::mdb_size_t = 0;
        // SAFETY: the cursor is positioned (the caller established that with
        // `set`), and `n` is a plain out-parameter.
        check(
            unsafe { ffi::mdb_cursor_count(self.ptr, &mut n) },
            "mdb_cursor_count",
        )?;
        Ok(n as u64)
    }

    /// `mdb_cursor_put`.
    pub fn put(&mut self, key: &[u8], value: &[u8], flags: c_uint) -> Result<()> {
        let mut k = val(key);
        let mut v = val(value);
        // SAFETY: both slices outlive the call; LMDB copies them.
        check(
            unsafe { ffi::mdb_cursor_put(self.ptr, &mut k, &mut v, flags) },
            "mdb_cursor_put",
        )
    }

    /// `mdb_cursor_del` at the current position.
    pub fn del(&mut self, flags: c_uint) -> Result<()> {
        // SAFETY: the cursor is positioned by the caller.
        check(
            unsafe { ffi::mdb_cursor_del(self.ptr, flags) },
            "mdb_cursor_del",
        )
    }
}

impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        // SAFETY: closing a cursor is always safe, and it borrows a
        // transaction that is still live.
        unsafe { ffi::mdb_cursor_close(self.ptr) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comparator::ZEROKEY;
    use crate::tables::{table, TABLES};

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let mut p = std::env::temp_dir();
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            p.push(format!("wow-raw-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn env(s: &Scratch) -> Env {
        Env::open(&s.0, 0, 32, None, 16 << 20).expect("open")
    }

    #[test]
    fn an_environment_opens_and_creates_its_files() {
        let s = Scratch::new("open");
        let e = env(&s);
        assert!(s.0.join("data.mdb").exists());
        assert!(s.0.join("lock.mdb").exists());

        let info = e.size_info().unwrap();
        assert!(info.map_size >= 16 << 20);
        assert!(info.page_size > 0);
    }

    #[test]
    fn a_value_round_trips() {
        let s = Scratch::new("roundtrip");
        let e = env(&s);
        let t = table("blocks").unwrap();

        let mut w = e.write_txn().unwrap();
        let db = w.create_db("blocks", t.flags.bits(), t).unwrap();
        w.put(db, &7u64.to_ne_bytes(), b"seven", 0).unwrap();
        w.commit().unwrap();

        let r = e.read_txn().unwrap();
        assert_eq!(r.get(db, &7u64.to_ne_bytes()).unwrap(), Some(&b"seven"[..]));
        assert_eq!(r.get(db, &8u64.to_ne_bytes()).unwrap(), None);
        assert_eq!(r.entries(db).unwrap(), 1);
    }

    /// **The operation `heed` could not express.** `block_info` stores its
    /// height as the value prefix under one dummy key; `MDB_GET_BOTH` finds a
    /// record by that prefix in O(log n).
    #[test]
    fn get_both_finds_a_zerokval_record_by_its_value_prefix() {
        let s = Scratch::new("getboth");
        let e = env(&s);
        let t = table("block_info").unwrap();

        let mut w = e.write_txn().unwrap();
        let db = w.create_db("block_info", t.flags.bits(), t).unwrap();

        // 200 records under the single ZEROKEY, keyed by their height prefix.
        for h in 0..200u64 {
            let rec = crate::records::BlockInfo {
                height: h,
                timestamp: 1_600_000_000 + h,
                weight: 95,
                ..Default::default()
            };
            w.put(db, &ZEROKEY, &rec.encode(), 0).unwrap();
        }
        w.commit().unwrap();

        let r = e.read_txn().unwrap();
        let mut c = r.cursor(db).unwrap();

        // Look one up by height alone -- the dupsort comparator only reads the
        // leading eight bytes, so a bare height is a valid search value.
        let found = c.get_both(&ZEROKEY, &137u64.to_ne_bytes()).unwrap();
        let info = crate::records::BlockInfo::decode(found.expect("height 137")).unwrap();
        assert_eq!(info.height, 137);
        assert_eq!(info.timestamp, 1_600_000_000 + 137);

        // And a height that is not there misses cleanly.
        assert!(c
            .get_both(&ZEROKEY, &500u64.to_ne_bytes())
            .unwrap()
            .is_none());
    }

    /// **The other operation `heed` lacks.** `amount_index` is the dup count
    /// under `output_amounts[amount]` (`specs/10` §5.1).
    #[test]
    fn cursor_count_gives_the_dup_group_size() {
        let s = Scratch::new("count");
        let e = env(&s);
        let t = table("output_amounts").unwrap();

        let mut w = e.write_txn().unwrap();
        let db = w.create_db("output_amounts", t.flags.bits(), t).unwrap();

        // Five outputs of amount 0, two of amount 100.
        for i in 0..5u64 {
            let rec = crate::records::OutKey {
                amount_index: i,
                output_id: i,
                commitment: Some([1; 32]),
                ..Default::default()
            };
            w.put(db, &0u64.to_ne_bytes(), &rec.encode(), 0).unwrap();
        }
        for i in 0..2u64 {
            let rec = crate::records::OutKey {
                amount_index: i,
                output_id: 100 + i,
                ..Default::default()
            };
            w.put(db, &100u64.to_ne_bytes(), &rec.encode(), 0).unwrap();
        }
        w.commit().unwrap();

        let r = e.read_txn().unwrap();
        let mut c = r.cursor(db).unwrap();

        assert!(c.set(&0u64.to_ne_bytes()).unwrap());
        assert_eq!(c.count().unwrap(), 5, "get_num_outputs(0)");

        assert!(c.set(&100u64.to_ne_bytes()).unwrap());
        assert_eq!(c.count().unwrap(), 2, "get_num_outputs(100)");

        // An absent amount is simply not found.
        assert!(!c.set(&999u64.to_ne_bytes()).unwrap());
    }

    /// The dupsort comparator really is installed: records come back in
    /// `compare_hash32` order, not bytewise.
    #[test]
    fn the_dupsort_comparator_is_installed() {
        let s = Scratch::new("cmp");
        let e = env(&s);
        let t = table("block_heights").unwrap();

        let mut a = [0u8; 32];
        a[0] = 0xff; // bytewise largest, compare_hash32 smallest
        let mut b = [0u8; 32];
        b[31] = 0x01;

        let mut w = e.write_txn().unwrap();
        let db = w.create_db("block_heights", t.flags.bits(), t).unwrap();
        for (i, h) in [b, a].iter().enumerate() {
            let rec = crate::records::BlockHeight {
                hash: *h,
                height: i as u64,
            };
            w.put(db, &ZEROKEY, &rec.encode(), 0).unwrap();
        }
        w.commit().unwrap();

        let r = e.read_txn().unwrap();
        let mut c = r.cursor(db).unwrap();
        assert!(c.set(&ZEROKEY).unwrap());
        let (_, first) = c.get(None, None, ffi::MDB_FIRST_DUP).unwrap().unwrap();
        let first = crate::records::BlockHeight::decode(first).unwrap();

        assert_eq!(first.hash, a, "compare_hash32 puts `a` first");
        assert_ne!(first.hash, b, "bytewise would have put `b` first");
    }

    /// Deleting one duplicate leaves the others, which is what `pop_block`
    /// relies on (`specs/10` §6.4).
    #[test]
    fn a_single_duplicate_can_be_deleted() {
        let s = Scratch::new("deldup");
        let e = env(&s);
        let t = table("block_info").unwrap();

        let mut w = e.write_txn().unwrap();
        let db = w.create_db("block_info", t.flags.bits(), t).unwrap();
        for h in 0..3u64 {
            let rec = crate::records::BlockInfo {
                height: h,
                ..Default::default()
            };
            w.put(db, &ZEROKEY, &rec.encode(), 0).unwrap();
        }
        assert_eq!(w.entries(db).unwrap(), 3);

        // Delete the tip only.
        let tip = crate::records::BlockInfo {
            height: 2,
            ..Default::default()
        };
        assert!(w.del(db, &ZEROKEY, Some(&tip.encode())).unwrap());
        assert_eq!(w.entries(db).unwrap(), 2);
        w.commit().unwrap();

        let r = e.read_txn().unwrap();
        let mut c = r.cursor(db).unwrap();
        assert!(c.get_both(&ZEROKEY, &2u64.to_ne_bytes()).unwrap().is_none());
        assert!(c.get_both(&ZEROKEY, &1u64.to_ne_bytes()).unwrap().is_some());
    }

    /// `mdb_drop(del = 0)` empties a table and keeps the handle — what
    /// `hf_starting_heights` gets on every open.
    #[test]
    fn clear_db_empties_but_keeps_the_handle() {
        let s = Scratch::new("clear");
        let e = env(&s);
        let t = table("hf_starting_heights").unwrap();

        let mut w = e.write_txn().unwrap();
        let db = w
            .create_db("hf_starting_heights", t.flags.bits(), t)
            .unwrap();
        w.put(db, b"k", b"v", 0).unwrap();
        assert_eq!(w.entries(db).unwrap(), 1);
        w.clear_db(db).unwrap();
        assert_eq!(w.entries(db).unwrap(), 0);
        w.put(db, b"k2", b"v2", 0).unwrap();
        assert_eq!(w.entries(db).unwrap(), 1, "the handle still works");
        w.commit().unwrap();
    }

    /// A `NotFound` is an ordinary result, not an error to propagate.
    #[test]
    fn not_found_is_distinguishable() {
        let s = Scratch::new("notfound");
        let e = env(&s);
        let t = table("blocks").unwrap();
        let mut w = e.write_txn().unwrap();
        let db = w.create_db("blocks", t.flags.bits(), t).unwrap();
        w.commit().unwrap();

        let r = e.read_txn().unwrap();
        assert_eq!(r.get(db, &1u64.to_ne_bytes()).unwrap(), None);
    }

    /// An aborted write leaves nothing behind — the atomicity `specs/10` §6.3
    /// relies on.
    #[test]
    fn an_aborted_write_leaves_no_trace() {
        let s = Scratch::new("abort");
        let e = env(&s);
        let t = table("blocks").unwrap();

        let mut w = e.write_txn().unwrap();
        let db = w.create_db("blocks", t.flags.bits(), t).unwrap();
        w.put(db, &1u64.to_ne_bytes(), b"one", 0).unwrap();
        w.commit().unwrap();

        let mut w = e.write_txn().unwrap();
        w.put(db, &2u64.to_ne_bytes(), b"two", 0).unwrap();
        w.abort();

        let r = e.read_txn().unwrap();
        assert_eq!(r.get(db, &1u64.to_ne_bytes()).unwrap(), Some(&b"one"[..]));
        assert_eq!(r.get(db, &2u64.to_ne_bytes()).unwrap(), None);
        assert_eq!(r.entries(db).unwrap(), 1);
    }

    /// Every table in the schema opens with its real flags and comparators.
    #[test]
    fn every_table_opens_with_its_flags() {
        let s = Scratch::new("alltables");
        let e = env(&s);
        let mut w = e.write_txn().unwrap();
        for t in TABLES {
            w.create_db(t.name, t.flags.bits(), t)
                .unwrap_or_else(|err| panic!("{}: {err}", t.name));
        }
        w.commit().unwrap();
    }
}
