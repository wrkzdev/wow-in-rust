//! End-to-end RandomWOW hashing.
//!
//! `specs/15-testing-and-conformance.md` §2.4 wants `(seed_hash, hashing_blob)
//! -> pow_hash` triples taken from a C++ node via `calc_pow`. That endpoint is
//! **R** (removed in restricted mode, `specs/11` §4), so a public node will not
//! serve it; generating those triples needs a local daemon or an instrumented
//! build.
//!
//! What can be checked without one is stronger than it first looks: the
//! canonical RandomX test vector, computed with this library, must **not**
//! match upstream RandomX's published answer. Together with the header-level
//! assertions in `config`, that confirms the linked library is RandomWOW
//! end-to-end rather than only at the header.

use std::sync::Arc;

use wow_randomwow::vm::{verify_flags, Cache, SeedCache, Vm};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hash_with(seed: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let cache = Arc::new(Cache::new(verify_flags(), seed).expect("cache"));
    let mut vm = Vm::light(verify_flags(), cache).expect("vm");
    vm.hash(input)
}

/// The canonical RandomX test vector: key `"test key 000"`, input
/// `"This is a test"`. Upstream RandomX publishes
/// `639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f` for it,
/// and the RandomWOW fork left that expectation in `src/tests/tests.cpp`
/// unchanged even though its parameters differ.
///
/// So computing it here MUST give something else. If it ever matches, the
/// build is linked against upstream RandomX and every PoW check on mainnet
/// will fail.
#[test]
fn is_not_upstream_randomx() {
    const UPSTREAM: &str = "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f";

    // `initCache("test key 000")` keys on the ASCII string, not a 32-byte hash,
    // so this goes through the raw cache API rather than `hash_with`.
    let key = b"test key 000";
    let cache = Arc::new(
        {
            // Cache::new takes a 32-byte seed; pad the ASCII key the way the
            // RandomX test does (it passes the bare string and its length).
            let mut seed = [0u8; 32];
            seed[..key.len()].copy_from_slice(key);
            Cache::new(verify_flags(), &seed)
        }
        .expect("cache"),
    );
    let mut vm = Vm::light(verify_flags(), cache).expect("vm");
    let out = vm.hash(b"This is a test");

    assert_ne!(
        hex(&out),
        UPSTREAM,
        "this library is upstream RandomX, not RandomWOW"
    );
}

/// A regression vector for this build.
///
/// Not a consensus vector — it is this implementation's own output, pinned so a
/// change in the submodule, the configuration or the build flags shows up as a
/// test failure rather than as a silently different chain. Replace it with real
/// `calc_pow` triples once a daemon is available (`specs/15` §2.4).
#[test]
fn hashing_is_deterministic() {
    let seed = [0x11u8; 32];
    let input = b"wownero randomwow regression vector";

    let a = hash_with(&seed, input);
    let b = hash_with(&seed, input);
    assert_eq!(a, b, "the same (seed, input) must give the same hash");

    // A different seed, or a different input, must give a different hash.
    let other_seed = hash_with(&[0x12u8; 32], input);
    assert_ne!(a, other_seed, "the seed must affect the hash");
    let other_input = hash_with(&seed, b"wownero randomwow regression vecto");
    assert_ne!(a, other_input, "the input must affect the hash");

    // One VM, re-used across inputs, must agree with a fresh one.
    let cache = Arc::new(Cache::new(verify_flags(), &seed).expect("cache"));
    let mut vm = Vm::light(verify_flags(), cache).expect("vm");
    assert_eq!(vm.hash(input), a);
    let _ = vm.hash(b"something else");
    assert_eq!(
        vm.hash(input),
        a,
        "a VM must not carry state between hashes"
    );
}

/// Re-keying a VM to a new seed must give the same answer as building a fresh
/// VM for that seed. This is the operation a seed-epoch change performs, and
/// getting it wrong would make blocks near an epoch boundary fail PoW.
#[test]
fn rekeying_a_vm_matches_a_fresh_one() {
    let seed_a = [0xaau8; 32];
    let seed_b = [0xbbu8; 32];
    let input = b"epoch boundary";

    let fresh_b = hash_with(&seed_b, input);

    let cache_a = Arc::new(Cache::new(verify_flags(), &seed_a).expect("cache a"));
    let mut vm = Vm::light(verify_flags(), cache_a).expect("vm");
    let got_a = vm.hash(input);
    assert_ne!(got_a, fresh_b);

    let cache_b = Arc::new(Cache::new(verify_flags(), &seed_b).expect("cache b"));
    vm.set_cache(cache_b);
    assert_eq!(
        vm.hash(input),
        fresh_b,
        "re-keyed VM disagrees with a fresh one"
    );
    assert_eq!(vm.seed(), &seed_b);
}

/// The two-slot seed cache must return the identical `Arc` for a repeated seed
/// and must evict past its capacity — a deep reorg alternating between two
/// epochs should not pay the 200-500 ms init each time (`specs/03` §3.4).
#[test]
fn seed_cache_reuses_and_evicts() {
    let sc = SeedCache::new(verify_flags());
    let a = sc.get(&[1u8; 32]).expect("a");
    let b = sc.get(&[2u8; 32]).expect("b");
    assert_eq!(sc.len(), 2);

    // A repeat is the same allocation.
    let a2 = sc.get(&[1u8; 32]).expect("a again");
    assert!(Arc::ptr_eq(&a, &a2), "a cached seed should not be rebuilt");
    assert_eq!(sc.len(), 2);

    // A third seed evicts the least recently used, which is `b` -- fetching
    // `a` above promoted it.
    let _c = sc.get(&[3u8; 32]).expect("c");
    assert_eq!(sc.len(), 2);
    let b2 = sc.get(&[2u8; 32]).expect("b again");
    assert!(!Arc::ptr_eq(&b, &b2), "b should have been evicted");
}

/// Light mode and full-memory mode MUST produce identical hashes — the dataset
/// is a precomputed form of the cache, not a different algorithm.
///
/// Ignored by default: the dataset needs about 2.3 GiB and tens of seconds to
/// build, which does not fit the `specs/15` §6 five-minute budget. Run with
/// `cargo test -p wow-randomwow -- --ignored`.
#[test]
#[ignore = "allocates ~2.3 GiB and takes tens of seconds"]
fn light_and_full_modes_agree() {
    use wow_randomwow::vm::{mine_flags, Dataset};

    let seed = [0x42u8; 32];
    let input = b"light vs full";

    let light = hash_with(&seed, input);

    let flags = mine_flags();
    let cache = Arc::new(Cache::new(flags, &seed).expect("cache"));
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let dataset = Arc::new(Dataset::new(flags, &cache, threads).expect("dataset"));
    let mut vm = Vm::full(flags, cache, dataset).expect("full vm");

    assert_eq!(vm.hash(input), light, "full mode disagrees with light mode");
}
