//! Raw bindings to the pinned RandomWOW library.
//!
//! `specs/03-pow.md` §3.5 lists the required surface. Written by hand rather
//! than generated: the API is fifteen functions and has been stable for years,
//! and a hand-written binding is one fewer build-time dependency on a build
//! that already needs CMake and a C++ compiler.

use core::ffi::{c_char, c_ulong, c_void};

/// `RANDOMX_HASH_SIZE`.
pub const RANDOMX_HASH_SIZE: usize = 32;
/// `RANDOMX_DATASET_ITEM_SIZE`.
pub const RANDOMX_DATASET_ITEM_SIZE: usize = 64;

/// `randomx_flags`.
///
/// `specs/03` §3.4: "A Rust node MAY choose its own defaults; these flags do
/// not affect the hash output."
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

#[repr(C)]
pub struct RandomxCache {
    _private: [u8; 0],
}

#[repr(C)]
pub struct RandomxDataset {
    _private: [u8; 0],
}

#[repr(C)]
pub struct RandomxVm {
    _private: [u8; 0],
}

extern "C" {
    pub fn randomx_get_flags() -> u32;

    pub fn randomx_alloc_cache(flags: u32) -> *mut RandomxCache;
    pub fn randomx_init_cache(cache: *mut RandomxCache, key: *const c_void, key_size: usize);
    pub fn randomx_release_cache(cache: *mut RandomxCache);

    pub fn randomx_alloc_dataset(flags: u32) -> *mut RandomxDataset;
    pub fn randomx_dataset_item_count() -> c_ulong;
    pub fn randomx_init_dataset(
        dataset: *mut RandomxDataset,
        cache: *mut RandomxCache,
        start_item: c_ulong,
        item_count: c_ulong,
    );
    pub fn randomx_release_dataset(dataset: *mut RandomxDataset);

    pub fn randomx_create_vm(
        flags: u32,
        cache: *mut RandomxCache,
        dataset: *mut RandomxDataset,
    ) -> *mut RandomxVm;
    pub fn randomx_vm_set_cache(machine: *mut RandomxVm, cache: *mut RandomxCache);
    pub fn randomx_vm_set_dataset(machine: *mut RandomxVm, dataset: *mut RandomxDataset);
    pub fn randomx_destroy_vm(machine: *mut RandomxVm);

    pub fn randomx_calculate_hash(
        machine: *mut RandomxVm,
        input: *const c_void,
        input_size: usize,
        output: *mut c_void,
    );
}

// --- the configuration shim (src/shim.c) ---
extern "C" {
    pub fn wow_rx_argon_salt() -> *const c_char;
    pub fn wow_rx_argon_salt_len() -> usize;
    pub fn wow_rx_argon_memory() -> u32;
    pub fn wow_rx_argon_iterations() -> u32;
    pub fn wow_rx_argon_lanes() -> u32;
    pub fn wow_rx_cache_accesses() -> u32;
    pub fn wow_rx_superscalar_latency() -> u32;
    pub fn wow_rx_dataset_base_size() -> u64;
    pub fn wow_rx_dataset_extra_size() -> u64;
    pub fn wow_rx_program_size() -> u32;
    pub fn wow_rx_program_iterations() -> u32;
    pub fn wow_rx_program_count() -> u32;
    pub fn wow_rx_scratchpad_l3() -> u32;
    pub fn wow_rx_scratchpad_l2() -> u32;
    pub fn wow_rx_scratchpad_l1() -> u32;
    pub fn wow_rx_jump_bits() -> u32;
    pub fn wow_rx_jump_offset() -> u32;
    pub fn wow_rx_frequencies(out: *mut u32);
    pub fn wow_rx_frequency_count() -> usize;
}
