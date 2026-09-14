//! Where an open wallet's files live.
//!
//! A wallet is a keys file and a cache ([`crate::files`]). On a computer they
//! are files on disk, and the keys file is held while the wallet is open
//! ([`FileStore`]). A browser has no disk to write to: the program keeps the
//! bytes where it keeps wallets, IndexedDB say, and hands them over
//! ([`MemoryStore`]). The wallet reads and writes the same bytes either way.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::files::Paths;
use crate::lock::KeysLock;

/// Where a wallet's keys file and cache are read from and written to.
pub trait Store: Send {
    /// Whether a keys file is already here. A new wallet is not written over
    /// one.
    fn exists(&self) -> bool;

    /// Read the keys file. Where another program could open the same wallet,
    /// the store holds it from here on.
    fn open_keys(&mut self) -> Result<Vec<u8>, String>;

    /// Read this implementation's cache.
    fn read_cache(&mut self) -> Result<CacheRead, String>;

    /// Replace the keys file.
    fn write_keys(&mut self, bytes: &[u8]) -> Result<(), String>;

    /// Replace the cache.
    fn write_cache(&mut self, bytes: &[u8]) -> Result<(), String>;

    /// Keep the primary address beside a new wallet, as `<name>.address.txt`
    /// does.
    fn write_address(&mut self, address: &str) -> Result<(), String>;

    /// Where the wallet is, for messages: its keys file's path, or the name
    /// the program gave it.
    fn location(&self) -> String;
}

/// What [`Store::read_cache`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheRead {
    Found(Vec<u8>),
    /// No cache: the wallet scans from its restore height.
    Missing,
    /// None of ours, but the C++ wallet's is here, in a format this does not
    /// read (`specs/12` §2.2). The wallet rescans, and writes its own at
    /// `ours`.
    WrittenByCpp { ours: String },
}

/// A wallet as files on disk: `<name>.keys`, `<name>.rscache` and
/// `<name>.address.txt` (`specs/12` §2).
pub struct FileStore {
    paths: Paths,
    /// Held from [`Store::open_keys`] on, as the C++ holds it
    /// ([`crate::lock`]).
    lock: Option<KeysLock>,
}

impl FileStore {
    pub fn new(paths: Paths) -> FileStore {
        FileStore { paths, lock: None }
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }
}

impl Store for FileStore {
    fn exists(&self) -> bool {
        self.paths.keys().exists()
    }

    fn open_keys(&mut self) -> Result<Vec<u8>, String> {
        // Held before the keys are read, as the C++ locks before it loads, so a
        // wallet open elsewhere is refused at once. A Windows lock refuses reads
        // through any other handle, so the keys are read through it.
        let path = self.paths.keys();
        let lock = KeysLock::acquire(&path).map_err(|e| e.to_string())?;
        let bytes = lock
            .read()
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        self.lock = Some(lock);
        Ok(bytes)
    }

    fn read_cache(&mut self) -> Result<CacheRead, String> {
        match std::fs::read(self.paths.cache()) {
            Ok(raw) => Ok(CacheRead::Found(raw)),
            Err(_) if self.paths.cpp_cache().exists() => Ok(CacheRead::WrittenByCpp {
                ours: self.paths.cache().display().to_string(),
            }),
            Err(_) => Ok(CacheRead::Missing),
        }
    }

    fn write_keys(&mut self, bytes: &[u8]) -> Result<(), String> {
        // The file is replaced by a rename, and a lock left on the file it
        // replaced would hold nothing. So the lock is let go for the write and
        // taken again on what was written, or on the old file if the write
        // failed.
        let path = self.paths.keys();
        self.lock = None;
        let written = write_atomically(&path, bytes);
        self.lock = Some(KeysLock::acquire(&path).map_err(|e| e.to_string())?);
        written
    }

    fn write_cache(&mut self, bytes: &[u8]) -> Result<(), String> {
        write_atomically(&self.paths.cache(), bytes)
    }

    fn write_address(&mut self, address: &str) -> Result<(), String> {
        let text = format!("{address}\n");
        write_atomically(&self.paths.address_txt(), text.as_bytes())
    }

    fn location(&self) -> String {
        self.paths.keys().display().to_string()
    }
}

/// A wallet held in memory, for a program that keeps the bytes itself: a
/// browser build reads them back after each save and puts them in IndexedDB.
///
/// Clones share what is held, so the program keeps one and the wallet takes
/// the other.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    name: String,
    held: Arc<Mutex<MemoryFiles>>,
}

/// What a [`MemoryStore`] holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryFiles {
    pub keys: Option<Vec<u8>>,
    pub cache: Option<Vec<u8>>,
    pub address: Option<String>,
    /// Counts writes, so the program can tell when there is something new to
    /// keep.
    pub writes: u64,
}

impl MemoryStore {
    /// An empty store, for a wallet about to be created. `name` is how
    /// messages refer to it.
    pub fn new(name: impl Into<String>) -> MemoryStore {
        MemoryStore {
            name: name.into(),
            held: Arc::default(),
        }
    }

    /// A store holding a wallet the program kept: its keys file, and its cache
    /// if it has one.
    pub fn holding(name: impl Into<String>, keys: Vec<u8>, cache: Option<Vec<u8>>) -> Self {
        let store = MemoryStore::new(name);
        {
            let mut held = store.guard();
            held.keys = Some(keys);
            held.cache = cache;
        }
        store
    }

    /// A copy of what is held now.
    pub fn files(&self) -> MemoryFiles {
        self.guard().clone()
    }

    fn guard(&self) -> MutexGuard<'_, MemoryFiles> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Store for MemoryStore {
    fn exists(&self) -> bool {
        self.guard().keys.is_some()
    }

    fn open_keys(&mut self) -> Result<Vec<u8>, String> {
        let keys = self.guard().keys.clone();
        keys.ok_or_else(|| format!("{} holds no wallet", self.name))
    }

    fn read_cache(&mut self) -> Result<CacheRead, String> {
        let cache = self.guard().cache.clone();
        Ok(match cache {
            Some(raw) => CacheRead::Found(raw),
            None => CacheRead::Missing,
        })
    }

    fn write_keys(&mut self, bytes: &[u8]) -> Result<(), String> {
        let mut held = self.guard();
        held.keys = Some(bytes.to_vec());
        held.writes += 1;
        Ok(())
    }

    fn write_cache(&mut self, bytes: &[u8]) -> Result<(), String> {
        let mut held = self.guard();
        held.cache = Some(bytes.to_vec());
        held.writes += 1;
        Ok(())
    }

    fn write_address(&mut self, address: &str) -> Result<(), String> {
        let mut held = self.guard();
        held.address = Some(address.to_string());
        held.writes += 1;
        Ok(())
    }

    fn location(&self) -> String {
        self.name.clone()
    }
}

/// Write to a temporary file and rename over the target.
///
/// A keys file half-written is a wallet lost. The rename is atomic on both
/// platforms this builds for, so a crash leaves either the old file or the new
/// one.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".new");
    let tmp = PathBuf::from(tmp);

    std::fs::write(&tmp, bytes).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot replace {}: {e}", path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clones of a memory store share what it holds, and every write counts.
    #[test]
    fn a_memory_store_shares_what_it_holds() {
        let kept = MemoryStore::new("browser");
        let mut wallet_side = kept.clone();
        assert!(!wallet_side.exists());
        assert!(wallet_side.open_keys().is_err(), "nothing to open yet");

        wallet_side.write_keys(b"keys").expect("keys");
        wallet_side.write_cache(b"cache").expect("cache");

        let files = kept.files();
        assert_eq!(files.keys.as_deref(), Some(&b"keys"[..]));
        assert_eq!(files.cache.as_deref(), Some(&b"cache"[..]));
        assert_eq!(files.writes, 2);
        assert!(kept.exists());
        assert_eq!(wallet_side.location(), "browser");
    }

    /// A store made from kept bytes hands them back.
    #[test]
    fn a_memory_store_holding_a_wallet_reads_it() {
        let mut store = MemoryStore::holding("kept", b"k".to_vec(), None);
        assert_eq!(store.open_keys().expect("keys"), b"k");
        assert_eq!(store.read_cache().expect("cache"), CacheRead::Missing);
    }
}
