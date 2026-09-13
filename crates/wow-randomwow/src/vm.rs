//! The RandomWOW Cache, Dataset and VM, in Rust.
//!
//! `specs/03-pow.md` §3.4 describes the lifecycle the C node keeps: a **main**
//! seed with a full 2 GiB dataset built in the background, and a **secondary**
//! seed in light mode (cache only). Switching to a seed that is neither costs
//! the Cache's Argon2 fill, which is why sync requests blocks in epoch-aligned
//! batches.
//!
//! This module provides the pieces; the policy of which seed is main lives in
//! the node.
//!
//! # Flags
//!
//! RandomX's flags are kept so callers read the same, but only three mean
//! anything here: `HARD_AES` uses AES-NI where the CPU has it, `FULL_MEM` is
//! the full Dataset, and `JIT` compiles a Cache's SuperscalarHash programs to
//! machine code on x86-64 -- the VM itself is always interpreted. `SECURE`,
//! `LARGE_PAGES` and the Argon2 SIMD flags are accepted and ignored. None of
//! them changes a hash.

use std::sync::{Arc, Mutex};

use crate::cache::CacheData;
use crate::machine::{Machine, Memory};
use crate::params::{Config, WOWNERO};
use crate::Hash256;

/// `randomx_flags`.
pub mod flags {
    pub const DEFAULT: u32 = 0;
    pub const LARGE_PAGES: u32 = 1;
    pub const HARD_AES: u32 = 2;
    pub const FULL_MEM: u32 = 4;
    pub const JIT: u32 = 8;
    pub const SECURE: u32 = 16;
    pub const ARGON2_SSSE3: u32 = 32;
    pub const ARGON2_AVX2: u32 = 64;
    pub const ARGON2: u32 = 96;
}

/// Allocation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RandomWowError {
    /// The Cache needs 256 MiB.
    CacheAllocation,
    /// The Dataset needs about 2.1 GiB.
    DatasetAllocation,
    /// The VM's scratchpad could not be allocated.
    VmCreation,
}

impl core::fmt::Display for RandomWowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            RandomWowError::CacheAllocation => "cannot allocate the RandomWOW cache (256 MiB)",
            RandomWowError::DatasetAllocation => {
                "cannot allocate the RandomWOW dataset (about 2.1 GiB)"
            }
            RandomWowError::VmCreation => "cannot allocate a RandomWOW scratchpad",
        })
    }
}

impl std::error::Error for RandomWowError {}

/// Flags for a verifying node: light mode, with AES-NI and compiled
/// SuperscalarHash where the machine allows them.
pub fn verify_flags() -> u32 {
    let mut f = flags::DEFAULT;
    if crate::aes::hardware_available() {
        f |= flags::HARD_AES;
    }
    if crate::jit::available() {
        f |= flags::JIT;
    }
    f
}

/// Flags for a miner: as above plus the full Dataset.
pub fn mine_flags() -> u32 {
    verify_flags() | flags::FULL_MEM
}

/// An initialised Cache for one seed.
pub struct Cache {
    data: CacheData,
    seed: Hash256,
}

impl Cache {
    /// Initialise a Cache for `seed`.
    pub fn new(flags: u32, seed: &Hash256) -> Result<Cache, RandomWowError> {
        Cache::with_config(&WOWNERO, flags, seed)
    }

    /// A Cache for any key under any parameters -- upstream RandomX's test
    /// vectors use ASCII keys and upstream's parameters.
    #[doc(hidden)]
    pub fn with_config(
        config: &'static Config,
        flag_bits: u32,
        key: &[u8],
    ) -> Result<Cache, RandomWowError> {
        let jit = flag_bits & flags::JIT != 0;
        let data = CacheData::new(config, key, jit).ok_or(RandomWowError::CacheAllocation)?;
        let mut seed = [0u8; 32];
        let n = key.len().min(32);
        seed[..n].copy_from_slice(&key[..n]);
        Ok(Cache { data, seed })
    }

    pub fn seed(&self) -> &Hash256 {
        &self.seed
    }
}

/// A full Dataset, about 2.1 GiB. Worth building for mining, or for verifying
/// many blocks of one seed epoch.
pub struct Dataset {
    words: Vec<u64>,
    config: &'static Config,
}

impl Dataset {
    /// Compute every item from `cache`, on `threads` threads.
    pub fn new(_flags: u32, cache: &Cache, threads: usize) -> Result<Dataset, RandomWowError> {
        let config = cache.data.config;
        let items = config.dataset_items() as usize;
        let mut words = Vec::new();
        words
            .try_reserve_exact(items * 8)
            .map_err(|_| RandomWowError::DatasetAllocation)?;
        words.resize(items * 8, 0);
        let per_thread = items.div_ceil(threads.max(1));
        std::thread::scope(|s| {
            for (t, chunk) in words.chunks_mut(per_thread * 8).enumerate() {
                let data = &cache.data;
                s.spawn(move || {
                    let first = t * per_thread;
                    for (i, item) in chunk.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                        *item = data.item((first + i) as u64);
                    }
                });
            }
        });
        Ok(Dataset { words, config })
    }
}

/// A hashing VM. **Not** thread-safe: give each worker thread its own.
pub struct Vm {
    machine: Machine,
    cache: Arc<Cache>,
    dataset: Option<Arc<Dataset>>,
}

impl Vm {
    fn machine(flags: u32, config: &'static Config) -> Result<Machine, RandomWowError> {
        let hard_aes = flags & flags::HARD_AES != 0 && crate::aes::hardware_available();
        Machine::new(config, hard_aes).ok_or(RandomWowError::VmCreation)
    }

    /// A light-mode VM: Dataset items are computed from the Cache.
    pub fn light(flags: u32, cache: Arc<Cache>) -> Result<Vm, RandomWowError> {
        Ok(Vm {
            machine: Vm::machine(flags, cache.data.config)?,
            cache,
            dataset: None,
        })
    }

    /// A VM reading the full Dataset.
    pub fn full(
        flags: u32,
        cache: Arc<Cache>,
        dataset: Arc<Dataset>,
    ) -> Result<Vm, RandomWowError> {
        debug_assert!(std::ptr::eq(cache.data.config, dataset.config));
        Ok(Vm {
            machine: Vm::machine(flags, cache.data.config)?,
            cache,
            dataset: Some(dataset),
        })
    }

    /// The seed this VM is keyed to.
    pub fn seed(&self) -> &Hash256 {
        self.cache.seed()
    }

    /// Re-key the VM to another Cache, for a seed-epoch change. A full-mode
    /// VM keeps its Dataset until given a new one.
    pub fn set_cache(&mut self, cache: Arc<Cache>) {
        self.cache = cache;
    }

    pub fn set_dataset(&mut self, dataset: Arc<Dataset>) {
        self.dataset = Some(dataset);
    }

    /// `randomx_calculate_hash` over the block hashing blob (`specs/03` §1).
    pub fn hash(&mut self, input: &[u8]) -> Hash256 {
        let memory = match &self.dataset {
            Some(d) => Memory::Full(&d.words),
            None => Memory::Light(&self.cache.data),
        };
        self.machine.hash(input, &memory)
    }
}

/// A cache keyed by seed hash, so a re-used seed does not pay the Cache's
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
            capacity: 2,
        }
    }

    /// Get (or build) the cache for `seed`, promoting it to most recently
    /// used so a reorg alternating between two epochs does not thrash.
    pub fn get(&self, seed: &Hash256) -> Result<Arc<Cache>, RandomWowError> {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
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

    /// How many seeds are resident.
    pub fn len(&self) -> usize {
        self.slots.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
