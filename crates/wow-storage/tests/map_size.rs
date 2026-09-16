//! The map grows rather than filling up (`specs/10` §2.2).
//!
//! LMDB fixes the map size when the environment opens and fails every write
//! past it with `MDB_MAP_FULL`. A node that never grew it stopped syncing for
//! good once its chain filled the default gigabyte, around mainnet height
//! 63,300. `specs/15` §3.3 asks for this test: "force a resize mid-sync (start
//! with a small mapsize)".

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Barrier;

use wow_storage::db::{BlockchainDb, DbError};
use wow_storage::env::{OpenMode, RESIZE_ADD_SIZE};
use wow_storage::lmdb::LmdbDb;
use wow_storage::records::TxPoolMeta;

/// A scratch directory that deletes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("wow-mapsize-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Small enough for a few writes to fill.
const SMALL_MAP: usize = 4 << 20;

fn open(dir: &Path) -> LmdbDb {
    LmdbDb::open_with_map_size(dir, OpenMode::default(), 4, SMALL_MAP).expect("open")
}

/// Growing wants room on disk for a whole increment, as the C++ does. A
/// machine without it cannot run these, and says so.
fn room_to_grow(dir: &Path) -> bool {
    let room = wow_storage::raw::available_space(dir).is_none_or(|n| n >= RESIZE_ADD_SIZE as u64);
    if !room {
        eprintln!(
            "skipped: less than {RESIZE_ADD_SIZE} bytes free under {}",
            dir.display()
        );
    }
    room
}

fn id(i: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..4].copy_from_slice(&i.to_le_bytes());
    h
}

/// Writes adding up to four times the map all land. Reopened, LMDB maps only
/// what is in use -- no room at all -- and the open grows it so writing can go
/// on, which is where a node that filled its map comes back after a restart.
#[test]
fn writes_past_the_map_grow_it_and_survive_a_reopen() {
    let s = Scratch::new("grow");
    if !room_to_grow(&s.0) {
        return;
    }
    let blob = vec![0xa5u8; 256 << 10];
    {
        let db = open(&s.0);
        let before = db.env().size_info().unwrap().map_size;
        for i in 0..64 {
            db.add_txpool_tx(&id(i), &blob, &TxPoolMeta::default())
                .unwrap_or_else(|e| panic!("write {i}: {e}"));
        }
        let after = db.env().size_info().unwrap().map_size;
        assert!(
            after >= before + RESIZE_ADD_SIZE as u64,
            "{before} -> {after}"
        );
    }

    let db = open(&s.0);
    db.add_txpool_tx(&id(64), &blob, &TxPoolMeta::default())
        .expect("a write after reopening");
    let mut seen = 0;
    db.for_all_txpool_txes(&mut |_, _, b| {
        assert_eq!(b.map(<[u8]>::len), Some(blob.len()));
        seen += 1;
        true
    })
    .unwrap();
    assert_eq!(seen, 65);
}

/// One write bigger than all the room left fails inside LMDB with
/// `MDB_MAP_FULL`, and lands on the retry once the map has grown.
#[test]
fn a_write_that_does_not_fit_is_retried_after_growing() {
    let s = Scratch::new("retry");
    if !room_to_grow(&s.0) {
        return;
    }
    let db = open(&s.0);
    let blob = vec![7u8; 2 * SMALL_MAP];
    db.add_txpool_tx(&id(1), &blob, &TxPoolMeta::default())
        .expect("grown and retried");
    assert_eq!(db.get_txpool_tx_blob(&id(1)).unwrap(), blob);
}

/// A thread holding a snapshot cannot have the map grown under it, and is told
/// so rather than left waiting for itself.
#[test]
fn a_resize_from_inside_a_transaction_is_refused() {
    let s = Scratch::new("inside");
    let db = open(&s.0);
    let snapshot = db.read_txn().unwrap();
    assert!(matches!(db.resize_barrier(), Err(DbError::ResizeWhileOpen)));
    drop(snapshot);
    if room_to_grow(&s.0) {
        db.resize_barrier().expect("with nothing open, it grows");
    }
}

/// Readers on other threads go on reading the right bytes while writes grow
/// the map: the gate drains them for each resize and lets them back in.
#[test]
fn readers_on_other_threads_survive_the_map_growing() {
    let s = Scratch::new("readers");
    if !room_to_grow(&s.0) {
        return;
    }
    let db = open(&s.0);
    let blob = vec![0x5au8; 64 << 10];
    db.add_txpool_tx(&id(0), &blob, &TxPoolMeta::default())
        .unwrap();
    let before = db.env().size_info().unwrap().map_size;

    let readers = 4;
    let started = Barrier::new(readers + 1);
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..readers)
            .map(|_| {
                scope.spawn(|| {
                    assert_eq!(db.get_txpool_tx_blob(&id(0)).expect("read"), blob);
                    started.wait();
                    while !done.load(Ordering::Relaxed) {
                        assert_eq!(db.get_txpool_tx_blob(&id(0)).expect("read"), blob);
                    }
                })
            })
            .collect();
        started.wait();
        for i in 1..128 {
            db.add_txpool_tx(&id(i), &blob, &TxPoolMeta::default())
                .unwrap_or_else(|e| panic!("write {i}: {e}"));
        }
        done.store(true, Ordering::Relaxed);
        for h in handles {
            h.join().expect("reader");
        }
    });
    assert!(
        db.env().size_info().unwrap().map_size > before,
        "the writes needed the map to grow"
    );
}
