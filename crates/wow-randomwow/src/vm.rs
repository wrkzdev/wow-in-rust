//! Safe wrappers over the RandomWOW cache, dataset and VM.
//!
//! `specs/03-pow.md` §3.4 describes the lifecycle the C node keeps: a **main**
//! seed with a full 2 GiB dataset built in the background, and a **secondary**
//! seed in light mode (cache only). Switching to a seed that is neither costs
//! 200–500 ms, which is why sync requests blocks in epoch-aligned batches.
//!
//! This module provides the pieces; the policy of which seed is main lives in
//! `wow-core` (M2).

use std::sync::{Arc, Mutex};

use crate::ffi;
use crate::Hash256;

/// Allocation or initialisation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RandomWowError {
    /// `randomx_alloc_cache` returned null — usually means the flags asked for
    /// large pages that are not available.
    CacheAllocation,
    /// `randomx_alloc_dataset` returned null. The dataset needs ~2.3 GiB.
    DatasetAllocation,
    /// `randomx_create_vm` returned null.
    VmCreation,
}

impl core::fmt::Display for RandomWowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            RandomWowError::CacheAllocation => "randomx_alloc_cache failed",
            RandomWowError::DatasetAllocation => {
                "randomx_alloc_dataset failed (the dataset needs about 2.3 GiB)"
            }
            RandomWowError::VmCreation => "randomx_create_vm failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for RandomWowError {}

/// Flags for a verifying node: light mode, JIT, and `SECURE` because
/// verification runs on shared worker threads (`specs/03` §3.4).
pub fn verify_flags() -> u32 {
    // SAFETY: a pure CPU-feature query.
    let detected = unsafe { ffi::randomx_get_flags() };
    (detected | ffi::flags::JIT | ffi::flags::SECURE) & !ffi::flags::FULL_MEM
}

/// Flags for a miner: as above plus the full dataset.
pub fn mine_flags() -> u32 {
    // SAFETY: a pure CPU-feature query.
    let detected = unsafe { ffi::randomx_get_flags() };
    detected | ffi::flags::JIT | ffi::flags::FULL_MEM
}

/// An initialised cache for one seed hash.
pub struct Cache {
    ptr: *mut ffi::RandomxCache,
    seed: Hash256,
}

// SAFETY: the cache is immutable once initialised. `randomx_vm_set_cache` and
// `randomx_init_dataset` only read it, and `Cache` hands out `*mut` solely to
// those read-only-in-practice APIs. It is never mutated after `new`.
unsafe impl Send for Cache {}
unsafe impl Sync for Cache {}

impl Cache {
    /// Allocate and initialise a cache for `seed`.
    pub fn new(flags: u32, seed: &Hash256) -> Result<Cache, RandomWowError> {
        // SAFETY: `randomx_alloc_cache` either returns a valid pointer or null,
        // which is checked; `randomx_init_cache` is then called exactly once on
        // that pointer with a 32-byte key.
        unsafe {
            let ptr = ffi::randomx_alloc_cache(flags);
            if ptr.is_null() {
                return Err(RandomWowError::CacheAllocation);
            }
            ffi::randomx_init_cache(ptr, seed.as_ptr() as *const _, seed.len());
            Ok(Cache { ptr, seed: *seed })
        }
    }

    pub fn seed(&self) -> &Hash256 {
        &self.seed
    }

    fn as_ptr(&self) -> *mut ffi::RandomxCache {
        self.ptr
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from `randomx_alloc_cache` and is released once.
        unsafe { ffi::randomx_release_cache(self.ptr) }
    }
}

/// A full dataset, ~2.3 GiB. Only worth building for mining or for bulk
/// historical verification within one epoch.
pub struct Dataset {
    ptr: *mut ffi::RandomxDataset,
}

// SAFETY: as `Cache` — immutable once `init` has returned.
unsafe impl Send for Dataset {}
unsafe impl Sync for Dataset {}

impl Dataset {
    /// Allocate and fill a dataset from `cache`, using `threads` workers.
    ///
    /// This takes tens of seconds. `specs/03` §3.4: the reference builds it in
    /// a background thread and hashes in light mode meanwhile.
    pub fn new(flags: u32, cache: &Cache, threads: usize) -> Result<Dataset, RandomWowError> {
        // SAFETY: checked-null allocation, then `randomx_init_dataset` over a
        // partition of [0, item_count) with no overlapping ranges.
        unsafe {
            let ptr = ffi::randomx_alloc_dataset(flags);
            if ptr.is_null() {
                return Err(RandomWowError::DatasetAllocation);
            }
            let count = ffi::randomx_dataset_item_count();
            let threads = threads.max(1) as u64;
            let per = count as u64 / threads;

            if threads == 1 {
                ffi::randomx_init_dataset(ptr, cache.as_ptr(), 0, count);
            } else {
                // Each worker gets a disjoint half-open range; the last one
                // absorbs the remainder.
                std::thread::scope(|s| {
                    for t in 0..threads {
                        let start = t * per;
                        let n = if t == threads - 1 {
                            count as u64 - start
                        } else {
                            per
                        };
                        let dsp = SendPtr(ptr);
                        let csp = SendPtr(cache.as_ptr());
                        s.spawn(move || {
                            let (d, c) = (dsp, csp);
                            ffi::randomx_init_dataset(d.0, c.0, start as _, n as _);
                        });
                    }
                });
            }
            Ok(Dataset { ptr })
        }
    }

    fn as_ptr(&self) -> *mut ffi::RandomxDataset {
        self.ptr
    }
}

impl Drop for Dataset {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from `randomx_alloc_dataset` and is released once.
        unsafe { ffi::randomx_release_dataset(self.ptr) }
    }
}

/// A pointer wrapper so raw pointers can cross a scoped-thread boundary.
///
/// SAFETY: only used for the dataset and cache pointers inside
/// `Dataset::new`, where each worker writes a **disjoint** range of the dataset
/// and only reads the cache. That is the contract `randomx_init_dataset`
/// documents.
#[derive(Clone, Copy)]
struct SendPtr<T>(*mut T);
unsafe impl<T> Send for SendPtr<T> {}

/// A hashing VM. **Not** thread-safe: give each worker thread its own.
pub struct Vm {
    ptr: *mut ffi::RandomxVm,
    // Keep the inputs alive for as long as the VM references them.
    _cache: Arc<Cache>,
    _dataset: Option<Arc<Dataset>>,
}

// SAFETY: a `Vm` owns its scratchpad and program buffer exclusively, so it can
// move between threads. It is deliberately **not** `Sync`: `randomx_calculate_hash`
// mutates internal state, so concurrent use of one VM is undefined.
unsafe impl Send for Vm {}

impl Vm {
    /// Create a light-mode VM (cache only, ~256 MiB).
    pub fn light(flags: u32, cache: Arc<Cache>) -> Result<Vm, RandomWowError> {
        // SAFETY: `cache` is a live initialised cache held alive by the `Arc`
        // stored in the returned `Vm`; the dataset pointer is null, which the
        // API accepts in light mode.
        unsafe {
            let ptr = ffi::randomx_create_vm(
                flags & !ffi::flags::FULL_MEM,
                cache.as_ptr(),
                core::ptr::null_mut(),
            );
            if ptr.is_null() {
                return Err(RandomWowError::VmCreation);
            }
            Ok(Vm {
                ptr,
                _cache: cache,
                _dataset: None,
            })
        }
    }

    /// Create a full-memory VM backed by `dataset`.
    pub fn full(
        flags: u32,
        cache: Arc<Cache>,
        dataset: Arc<Dataset>,
    ) -> Result<Vm, RandomWowError> {
        // SAFETY: both inputs are live and are kept alive by the `Arc`s stored
        // in the returned `Vm`.
        unsafe {
            let ptr = ffi::randomx_create_vm(
                flags | ffi::flags::FULL_MEM,
                cache.as_ptr(),
                dataset.as_ptr(),
            );
            if ptr.is_null() {
                return Err(RandomWowError::VmCreation);
            }
            Ok(Vm {
                ptr,
                _cache: cache,
                _dataset: Some(dataset),
            })
        }
    }

    /// The seed this VM is currently keyed to.
    pub fn seed(&self) -> &Hash256 {
        self._cache.seed()
    }

    /// Re-key the VM to a different cache, for a seed-epoch change.
    pub fn set_cache(&mut self, cache: Arc<Cache>) {
        // SAFETY: `cache` is live and becomes owned by `self`, so it outlives
        // the VM's use of it.
        unsafe { ffi::randomx_vm_set_cache(self.ptr, cache.as_ptr()) }
        self._cache = cache;
    }

    /// Re-point the VM at a different dataset.
    pub fn set_dataset(&mut self, dataset: Arc<Dataset>) {
        // SAFETY: as `set_cache`.
        unsafe { ffi::randomx_vm_set_dataset(self.ptr, dataset.as_ptr()) }
        self._dataset = Some(dataset);
    }

    /// `randomx_calculate_hash(vm, input, len, out)`.
    ///
    /// `input` is the **block hashing blob** (`specs/03` §1) — the same blob
    /// whose Keccak hash is the block id.
    pub fn hash(&mut self, input: &[u8]) -> Hash256 {
        let mut out = [0u8; ffi::RANDOMX_HASH_SIZE];
        // SAFETY: `ptr` is a live VM; `input` and `out` are valid for their
        // stated lengths, and `out` is exactly RANDOMX_HASH_SIZE bytes.
        unsafe {
            ffi::randomx_calculate_hash(
                self.ptr,
                input.as_ptr() as *const _,
                input.len(),
                out.as_mut_ptr() as *mut _,
            );
        }
        out
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from `randomx_create_vm` and is destroyed once,
        // before the cache and dataset `Arc`s are dropped.
        unsafe { ffi::randomx_destroy_vm(self.ptr) }
    }
}

/// A cache keyed by seed hash, so a re-used seed does not pay the 200–500 ms
/// initialisation again.
///
/// `specs/03` §3.4: the reference keeps a main seed and a secondary seed. This
/// holds the same two slots.
pub struct SeedCache {
    flags: u32,
    slots: Mutex<Vec<Arc<Cache>>>,
    capacity: usize,
}

impl SeedCache {
    pub fn new(flags: u32) -> SeedCache {
        SeedCache {
            flags,
            slots: Mutex::new(Vec::new()),
            // Main plus secondary, as in the reference.
            capacity: 2,
        }
    }

    /// Get (or build) the cache for `seed`.
    ///
    /// Promotes the seed to most-recently-used, so a deep reorg that alternates
    /// between two epochs does not thrash.
    pub fn get(&self, seed: &Hash256) -> Result<Arc<Cache>, RandomWowError> {
        let mut slots = self.slots.lock().expect("seed cache poisoned");
        if let Some(i) = slots.iter().position(|c| c.seed() == seed) {
            let hit = slots.remove(i);
            slots.insert(0, hit.clone());
            return Ok(hit);
        }
        let fresh = Arc::new(Cache::new(self.flags, seed)?);
        slots.insert(0, fresh.clone());
        slots.truncate(self.capacity);
        Ok(fresh)
    }

    /// How many seeds are currently resident.
    pub fn len(&self) -> usize {
        self.slots.lock().expect("seed cache poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
