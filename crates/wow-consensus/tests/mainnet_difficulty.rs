//! All six difficulty algorithms against real mainnet windows.
//!
//! `specs/15-testing-and-conformance.md` §3.2: "**Difficulty.** For each of the
//! six algorithms, feed the exact timestamp and cumulative-difficulty windows
//! from real heights (extracted via RPC) and compare against
//! `get_block_header_by_height(h).difficulty`."
//!
//! This is the test that decides whether M2 can sync. Every algorithm carries
//! quirks that no synthetic input exercises — v2's floating point and its
//! `boost::math::round`, v3's `max(lo, min(x, hi))` where the low bound can
//! exceed the high one, v4's timestamp monotonisation and trailing
//! `min(999, ...)`, v5's `ts[0] - target` seed and its height-307,800 branch
//! switch, and v1's asymmetric lag truncation. Getting any of them wrong makes
//! the chain diverge at the first block of that era.
//!
//! The windows were captured with `scripts/fetch-difficulty.py`. Each row is the
//! exact input `get_difficulty_for_next_block` would assemble at that height:
//! `difficulty_blocks_count(tip_version)` headers ending at `height - 1`.

use std::path::PathBuf;

use wow_consensus::difficulty::{
    difficulty_blocks_count, next_difficulty, select_algorithm, Algorithm,
};
use wow_types::{Difficulty, Network};

struct Window {
    name: String,
    height: u64,
    tip_version: u8,
    expected: Difficulty,
    timestamps: Vec<u64>,
    cumulative_difficulties: Vec<Difficulty>,
}

fn corpus() -> Vec<Window> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/difficulty/index.tsv");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 6, "malformed row: {}", &l[..40.min(l.len())]);
            Window {
                name: f[0].to_string(),
                height: f[1].parse().expect("height"),
                tip_version: f[2].parse().expect("version"),
                expected: f[3].parse().expect("difficulty"),
                timestamps: f[4].split(',').map(|x| x.parse().expect("ts")).collect(),
                cumulative_difficulties: f[5].split(',').map(|x| x.parse().expect("cd")).collect(),
            }
        })
        .collect()
}

/// The gate: every algorithm must reproduce the difficulty the chain recorded.
#[test]
fn every_algorithm_matches_the_chain() {
    let windows = corpus();
    assert!(windows.len() >= 10, "only {} windows", windows.len());

    let mut seen = std::collections::BTreeSet::new();
    let mut failures = Vec::new();

    for w in &windows {
        let algo = select_algorithm(w.tip_version);
        seen.insert(format!("{algo:?}"));

        // The window must be exactly what the C would have collected.
        let count = difficulty_blocks_count(w.tip_version);
        let offset = {
            let o = w.height - w.height.min(count as u64);
            if o == 0 {
                1
            } else {
                o
            }
        };
        assert_eq!(
            w.timestamps.len() as u64,
            w.height - offset,
            "{}: window size",
            w.name
        );
        assert_eq!(
            w.timestamps.len(),
            w.cumulative_difficulties.len(),
            "{}: ragged window",
            w.name
        );

        let got = next_difficulty(
            w.tip_version,
            w.timestamps.clone(),
            w.cumulative_difficulties.clone(),
            w.height,
            Network::Mainnet,
        );
        if got != w.expected {
            failures.push(format!(
                "{} (height {}, v{}, {algo:?}): got {got}, chain says {}",
                w.name, w.height, w.tip_version, w.expected
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} windows failed:\n{}",
        failures.len(),
        windows.len(),
        failures.join("\n")
    );

    // All six algorithms must actually have been exercised.
    for a in [
        Algorithm::V1,
        Algorithm::V2,
        Algorithm::V3,
        Algorithm::V4,
        Algorithm::V5,
        Algorithm::V6,
    ] {
        assert!(
            seen.contains(&format!("{a:?}")),
            "{a:?} was never exercised by the corpus"
        );
    }
    eprintln!(
        "difficulty: {} windows across {} algorithms, all matching",
        windows.len(),
        seen.len()
    );
}

/// Cumulative difficulty must be the running sum the chain recorded, which is
/// what `check_difficulty_checkpoints` verifies (`specs/07` §6).
#[test]
fn windows_have_monotonic_cumulative_difficulty() {
    for w in corpus() {
        for i in 1..w.cumulative_difficulties.len() {
            assert!(
                w.cumulative_difficulties[i] > w.cumulative_difficulties[i - 1],
                "{}: cumulative difficulty fell at index {i}",
                w.name
            );
        }
        // Per-block difficulty is the first difference, and must be positive.
        let first = w.cumulative_difficulties[1] - w.cumulative_difficulties[0];
        assert!(first > 0, "{}: zero difficulty", w.name);
    }
}

/// The tip version, not the block's own version, selects the algorithm
/// (`specs/07` §3). Feeding the same window through the wrong algorithm must
/// give a different answer — otherwise the corpus would not be discriminating.
#[test]
fn the_corpus_discriminates_between_algorithms() {
    for w in corpus() {
        let right = select_algorithm(w.tip_version);
        let mut differed = 0;
        for v in [7u8, 8, 9, 10, 11, 20] {
            if select_algorithm(v) == right {
                continue;
            }
            // A window sized for one algorithm may be too short for another,
            // in which case the guard returns 1 -- also a difference.
            let got = next_difficulty(
                v,
                w.timestamps.clone(),
                w.cumulative_difficulties.clone(),
                w.height,
                Network::Mainnet,
            );
            if got != w.expected {
                differed += 1;
            }
        }
        assert!(
            differed > 0,
            "{}: every other algorithm gave the same answer, so this window \
             proves nothing",
            w.name
        );
    }
}
