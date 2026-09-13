//! RandomWOW against real mainnet blocks.
//!
//! `specs/15-testing-and-conformance.md` §2.4 asks for `(seed_hash,
//! hashing_blob) -> pow_hash` triples "from the C++ node via `calc_pow` (or by
//! instrumenting it)". `calc_pow` is **R** — removed in restricted mode
//! (`specs/11` §4) — so a public node will not serve it, and instrumenting a
//! C++ build is a heavyweight dependency for a unit test.
//!
//! The chain supplies a better oracle anyway. A block's proof-of-work hash must
//! satisfy `check_hash(pow, difficulty)` for that block's own difficulty
//! (`specs/03` §4). Mainnet difficulty in this corpus runs from 1.0e8 to 9.2e9,
//! so a wrong hash passes with probability under 1e-8 — and a hash produced by
//! upstream RandomX rather than RandomWOW, or keyed on the wrong seed, would
//! fail essentially always. Passing 26 blocks across 5 seed epochs
//! is conclusive.
//!
//! This validates, in one go: the seed-height arithmetic, the seed being the
//! block **id** at that height, the hashing blob (and therefore the header
//! serialization and the Merkle root), the library configuration, and the
//! difficulty check.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use wow_crypto::hex;
use wow_randomwow::vm::{verify_flags, Cache, Vm};
use wow_randomwow::{rx_seedheight, select_algorithm, PowAlgorithm, POW_OVERRIDE_HEIGHT};
use wow_types::block::Block;
use wow_types::difficulty::check_hash;

struct Row {
    height: u64,
    seed_height: u64,
    seed_hash: [u8; 32],
    difficulty: u128,
    major_version: u8,
    blob: Vec<u8>,
}

fn corpus() -> Vec<Row> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/pow/index.tsv");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 6, "malformed row: {l}");
            Row {
                height: f[0].parse().expect("height"),
                seed_height: f[1].parse().expect("seed height"),
                seed_hash: hex::decode_array::<32>(f[2]).expect("seed hash"),
                difficulty: f[3].parse().expect("difficulty"),
                major_version: f[4].parse().expect("major version"),
                blob: hex::decode(f[5]).expect("blob hex"),
            }
        })
        .collect()
}

#[test]
fn mainnet_blocks_satisfy_their_own_difficulty() {
    let rows = corpus();
    assert!(rows.len() >= 20, "corpus holds only {} blocks", rows.len());

    // Group by seed so each epoch pays one cache initialisation (200-500 ms).
    // Doing it per block instead is exactly the slow path `specs/03` §3.4 warns
    // about, and is why sync batches are epoch-aligned.
    let mut by_seed: BTreeMap<u64, Vec<&Row>> = BTreeMap::new();
    for r in &rows {
        by_seed.entry(r.seed_height).or_default().push(r);
    }
    assert!(
        by_seed.len() >= 3,
        "want several seed epochs, got {}",
        by_seed.len()
    );

    let mut checked = 0usize;
    let mut overrides = 0usize;
    let mut skipped_cryptonight = 0usize;

    for (seed_height, group) in &by_seed {
        let seed = group[0].seed_hash;
        // Every row in a group must agree on the seed, and it must be the
        // block id at `rx_seedheight(height)` (`specs/03` §3.2).
        for r in group {
            assert_eq!(
                rx_seedheight(r.height),
                *seed_height,
                "height {}: seed height",
                r.height
            );
            assert_eq!(r.seed_hash, seed, "height {}: seed hash", r.height);
        }

        let cache = Arc::new(Cache::new(verify_flags(), &seed).expect("cache"));
        let mut vm = Vm::light(verify_flags(), cache).expect("vm");

        for r in group {
            let b = Block::from_blob(&r.blob)
                .unwrap_or_else(|e| panic!("height {}: parse: {e}", r.height));
            assert_eq!(
                b.header.major_version, r.major_version,
                "height {}",
                r.height
            );
            let blob = b.hashing_blob().expect("hashing blob");

            let pow = match select_algorithm(r.height, r.major_version) {
                PowAlgorithm::Override => {
                    overrides += 1;
                    wow_randomwow::POW_OVERRIDE_HASH
                }
                PowAlgorithm::RandomWow => vm.hash(&blob),
                PowAlgorithm::CryptoNight { .. } => {
                    // Not implemented yet (M2); no such block is in this corpus.
                    skipped_cryptonight += 1;
                    continue;
                }
            };

            assert!(
                check_hash(&pow, r.difficulty),
                "height {}: pow {} does not meet difficulty {}",
                r.height,
                hex::encode(&pow),
                r.difficulty
            );
            checked += 1;
        }
    }

    assert_eq!(skipped_cryptonight, 0, "the corpus should be all HF >= 13");
    assert_eq!(
        overrides, 1,
        "exactly one block is the height-202,612 override"
    );
    assert!(checked >= 20, "only {checked} blocks checked");
    eprintln!(
        "mainnet PoW: {checked} blocks over {} seed epochs, {overrides} override",
        by_seed.len()
    );
}

/// The height-202,612 override, checked against the real chain.
///
/// `specs/03` §5 item 2 warns that the override hash "passes `check_hash` only
/// for difficulty <= 1,297,898,660", and that since "Wownero's average
/// difficulty in the surrounding range (heights 160,777–253,999) is ≈ 3.39 ×
/// 10^9 ... a from-genesis verification with `--fast-block-sync 0` may
/// **reject** the block".
///
/// The corpus says otherwise: the difficulty actually recorded at height
/// 202,612 is 1.2e9, comfortably under that ceiling, so the override passes and
/// a from-genesis verification does **not** reject it. Worth pinning, because
/// the spec's warning would otherwise send someone hunting a non-problem.
#[test]
fn the_202612_override_passes_the_real_difficulty() {
    let rows = corpus();
    let r = rows
        .iter()
        .find(|r| r.height == POW_OVERRIDE_HEIGHT)
        .expect("height 202,612 is in the corpus");

    assert_eq!(
        select_algorithm(r.height, r.major_version),
        PowAlgorithm::Override
    );
    assert!(
        check_hash(&wow_randomwow::POW_OVERRIDE_HASH, r.difficulty),
        "the override hash should pass difficulty {}",
        r.difficulty
    );

    // The documented ceiling, verified by bisection rather than taken on faith.
    let mut lo = 1u128;
    let mut hi = 1u128 << 40;
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if check_hash(&wow_randomwow::POW_OVERRIDE_HASH, mid) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    assert_eq!(lo, 1_297_898_660, "the ceiling specs/03 §5 states");
    assert!(
        r.difficulty < lo,
        "difficulty {} is under the ceiling {lo}, so the override passes",
        r.difficulty
    );

    // The neighbouring blocks are ordinary RandomWOW.
    for h in [r.height - 1, r.height + 1] {
        let n = rows.iter().find(|x| x.height == h).expect("neighbour");
        assert_eq!(
            select_algorithm(n.height, n.major_version),
            PowAlgorithm::RandomWow
        );
    }
}

/// The seed hash is the block **id** at `rx_seedheight(height)` — not the PoW
/// hash, and not the block at `height` itself (`specs/03` §3.2).
#[test]
fn seed_heights_match_the_corpus() {
    for r in corpus() {
        assert_eq!(
            rx_seedheight(r.height),
            r.seed_height,
            "height {}",
            r.height
        );
        assert!(r.seed_height < r.height);
        assert_eq!(r.seed_height % 2048, 0);
        assert_ne!(r.seed_hash, [0u8; 32], "a real seed is not the zero hash");
    }
}
