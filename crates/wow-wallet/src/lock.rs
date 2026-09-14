//! The `.keys` file, held while a wallet is open: `tools::file_locker`.
//!
//! Two programs with one wallet open would pick the same outputs to spend and
//! write their keys and caches over each other's. `wallet2` locks the keys file
//! for as long as the wallet is open, and this locks it the same way, so this
//! wallet and the C++ one keep each other out as well as themselves.
//!
//! * Unix: `flock(LOCK_EX | LOCK_NB)`, as the reference's `flock_exnb`.
//! * Windows: `LockFileEx` on the first byte, exclusive and failing at once.
//!   The C++ opens the file sharing nothing, so while it holds a wallet this
//!   cannot open the file at all, and while this holds one the C++ cannot.
//!
//! A Windows byte-range lock also refuses reads through any other handle, the
//! holder's own included, which is why the C++ unlocks around loading its
//! keys. Here they are read through the locked handle instead
//! ([`KeysLock::read`]).
//!
//! A save writes `<name>.keys.new` and renames it over the old file, which
//! would leave the lock on the file that was replaced. So a save lets go first
//! and locks the new file after, as `wallet2` does around `store_keys`.
//!
//! Where there are no files to share, as in a browser, there is nothing to
//! lock.

use std::path::Path;

/// A held lock on a keys file. Dropping it lets go.
#[derive(Debug)]
pub struct KeysLock {
    #[cfg(any(unix, windows))]
    file: std::fs::File,
    #[cfg(not(any(unix, windows)))]
    path: std::path::PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Another program, or another open copy of this one, holds it.
    #[error("{0} is open in another wallet program; close it there first")]
    Held(String),
    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

impl KeysLock {
    /// Lock the keys file at `path`, which must exist.
    pub fn acquire(path: &Path) -> Result<KeysLock, LockError> {
        #[cfg(any(unix, windows))]
        {
            let file = std::fs::File::open(path).map_err(|e| failure(e, path))?;
            lock(&file).map_err(|e| failure(e, path))?;
            Ok(KeysLock { file })
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(KeysLock {
                path: path.to_path_buf(),
            })
        }
    }

    /// The whole file, read through the lock.
    pub fn read(&self) -> std::io::Result<Vec<u8>> {
        #[cfg(any(unix, windows))]
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut file = &self.file;
            file.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            Ok(bytes)
        }
        #[cfg(not(any(unix, windows)))]
        {
            std::fs::read(&self.path)
        }
    }
}

#[cfg(any(unix, windows))]
fn failure(e: std::io::Error, path: &Path) -> LockError {
    if is_held(&e) {
        LockError::Held(path.display().to_string())
    } else {
        LockError::Io {
            path: path.display().to_string(),
            source: e,
        }
    }
}

#[cfg(unix)]
fn lock(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: the descriptor is `file`'s and stays open for the call. `flock`
    // takes no pointers and changes nothing but the lock on that descriptor.
    let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn is_held(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::WouldBlock
}

#[cfg(windows)]
fn lock(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    /// `OVERLAPPED`, which names the offset the lock starts at.
    #[repr(C)]
    #[allow(dead_code)] // read by the kernel, not by Rust
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut core::ffi::c_void,
    }

    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;

    #[link(name = "kernel32")]
    extern "system" {
        fn LockFileEx(
            file: *mut core::ffi::c_void,
            flags: u32,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
    }

    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: core::ptr::null_mut(),
    };
    // SAFETY: the handle is `file`'s and stays open for the call, and
    // `overlapped` is a valid OVERLAPPED naming offset 0, zeroed as the
    // reference's is. `LOCKFILE_FAIL_IMMEDIATELY` makes the call answer at once
    // rather than complete later through the structure, so the structure need
    // not outlive it.
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle().cast(),
            LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if ok != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn is_held(e: &std::io::Error) -> bool {
    // The C++ has the file open sharing nothing.
    const ERROR_SHARING_VIOLATION: i32 = 32;
    // Another program holds the byte lock.
    const ERROR_LOCK_VIOLATION: i32 = 33;
    matches!(
        e.raw_os_error(),
        Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
    )
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;

    fn scratch_keys(tag: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!("wow-lock-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("w.keys");
        std::fs::write(&path, b"keys").expect("write");
        path
    }

    /// One holder at a time, and the holder can still read the file.
    #[test]
    fn a_held_keys_file_cannot_be_locked_again() {
        let path = scratch_keys("held");
        let first = KeysLock::acquire(&path).expect("the first lock");

        let err = KeysLock::acquire(&path).expect_err("already held");
        assert!(matches!(err, LockError::Held(_)), "got {err:?}");
        assert!(err.to_string().contains("another wallet program"), "{err}");

        assert_eq!(first.read().expect("read through the lock"), b"keys");
        assert_eq!(first.read().expect("and again, from the start"), b"keys");

        drop(first);
        KeysLock::acquire(&path).expect("free again");

        let _ = std::fs::remove_dir_all(path.parent().expect("a directory"));
    }

    /// A missing file is an I/O error, not a lock someone else holds.
    #[test]
    fn a_missing_keys_file_is_not_held() {
        let path = scratch_keys("missing").with_file_name("absent.keys");
        let err = KeysLock::acquire(&path).expect_err("nothing to lock");
        assert!(matches!(err, LockError::Io { .. }), "got {err:?}");

        let _ = std::fs::remove_dir_all(path.parent().expect("a directory"));
    }
}
