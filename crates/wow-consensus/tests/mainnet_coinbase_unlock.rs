//! The HF 16–17 dynamic coinbase unlock rule against real blocks.
//!
//! `specs/15-testing-and-conformance.md` §3.2: "**Coinbase unlock time.** For
//! the HF 16–17 range, assert your `pod_to_hex(...)[..3]` reading matches the
//! C++ for at least 100 real blocks — this is the rule most likely to be
//! implemented as a byte-swap by mistake."
//!
//! The rule (`specs/06` §5.1.1, §9.9):
//!
//! ```text
//! blk_id = get_block_id_by_height(height - 1337)      // mainnet
//! hex3   = pod_to_hex(blk_id)[0..3]                   // storage order
//! unlock = height + 2 * u64::from_str_radix(hex3, 16) + 288
//! ```
//!
//! Two inputs, from two corpora:
//!
//! * the coinbase `unlock_time` comes from the block blobs in
//!   `tests/corpus/blocks/mainnet/`, parsed by `wow-types`;
//! * the referenced block id comes from `tests/corpus/unlock/mainnet.tsv`,
//!   captured by `scripts/fetch-unlock.py`.
//!
//! Neither is committed. The test skips with an explanatory message when either
//! is missing.

use std::collections::BTreeMap;
use std::path::PathBuf;

use wow_consensus::tx_rules::{
    coinbase_unlock_time, dynamic_unlock_lookback, dynamic_unlock_window,
};
use wow_types::{Block, Network};

/// HF 16 activates at 253,999 and HF 18 at 331,170, so the dynamic rule governs
/// `[253_999, 331_170)`.
const HF16_HEIGHT: u64 = 253_999;
const HF18_HEIGHT: u64 = 331_170;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus")
}

/// Whether the fetch that produced the id corpus has finished.
///
/// `scripts/fetch-unlock.py` writes `mainnet.tsv.part` and renames on
/// completion, so a `.part` means the coverage assertions cannot be met yet.
fn ids_are_complete() -> bool {
    corpus_root().join("unlock/mainnet.tsv").exists()
}

/// `height -> referenced block id`, from `scripts/fetch-unlock.py`.
fn referenced_ids() -> BTreeMap<u64, [u8; 32]> {
    let dir = corpus_root().join("unlock");
    let text = std::fs::read_to_string(dir.join("mainnet.tsv"))
        .or_else(|_| std::fs::read_to_string(dir.join("mainnet.tsv.part")))
        .unwrap_or_default();
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 3, "malformed row: {l}");
            let height: u64 = f[0].parse().expect("height");
            let ref_height: u64 = f[1].parse().expect("ref_height");
            assert_eq!(
                ref_height,
                height - dynamic_unlock_lookback(Network::Mainnet),
                "the corpus used a different lookback"
            );
            let mut id = [0u8; 32];
            for (i, b) in id.iter_mut().enumerate() {
                *b = u8::from_str_radix(&f[2][i * 2..i * 2 + 2], 16).expect("hex");
            }
            (height, id)
        })
        .collect()
}

/// `height -> coinbase unlock_time`, parsed out of the block corpus.
fn coinbase_unlock_times() -> BTreeMap<u64, u64> {
    let path = corpus_root().join("blocks/mainnet/index.tsv");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return BTreeMap::new();
    };
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let height: u64 = f[0].parse().ok()?;
            if !(HF16_HEIGHT..HF18_HEIGHT).contains(&height) {
                return None;
            }
            let blob = wow_crypto::hex::decode(f.get(3)?)?;
            let block = Block::from_blob(&blob).ok()?;
            Some((height, block.miner_tx.prefix.unlock_time))
        })
        .collect()
}

/// The gate: the reading must reproduce the recorded `unlock_time` exactly.
#[test]
fn the_dynamic_unlock_matches_real_hf16_and_hf17_blocks() {
    let ids = referenced_ids();
    let unlocks = coinbase_unlock_times();

    if ids.is_empty() || unlocks.is_empty() {
        eprintln!(
            "no unlock corpus; run scripts/fetch-corpus.py then \
             scripts/fetch-unlock.py to enable this gate"
        );
        return;
    }

    let mut checked = 0usize;
    let mut failures = Vec::new();
    let mut distinct_windows = std::collections::BTreeSet::new();

    for (&height, id) in &ids {
        let Some(&recorded) = unlocks.get(&height) else {
            continue;
        };
        let expected = coinbase_unlock_time(16, height, Some(id));
        if expected != recorded && failures.len() < 10 {
            failures.push(format!(
                "  height {height}: computed {expected}, block says {recorded} \
                 (window {} vs {}, ref id starts {:02x}{:02x})",
                expected - height,
                recorded - height,
                id[0],
                id[1]
            ));
        }
        distinct_windows.insert(recorded - height);
        checked += 1;
    }

    assert!(
        failures.is_empty(),
        "{} of {checked} blocks mismatched:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!(
        "coinbase unlock: {checked} HF 16-17 blocks, {} distinct windows, all matching{}",
        distinct_windows.len(),
        if ids_are_complete() {
            ""
        } else {
            " [fetch in progress]"
        }
    );
    if !ids_are_complete() {
        eprintln!("  coverage not enforced while the id corpus is being fetched");
        return;
    }
    assert!(
        checked >= 100,
        "only {checked} blocks checked; §3.2 asks for at least 100"
    );
    // If every block happened to share one window the test would prove nothing
    // about the reading.
    assert!(
        distinct_windows.len() >= 20,
        "only {} distinct unlock windows across {checked} blocks",
        distinct_windows.len()
    );
}

/// The discriminating test: a byte-swapped reading must **disagree** with the
/// chain. Without this, a corpus where every id happened to be symmetric would
/// let the wrong implementation pass.
#[test]
fn a_byte_swapped_reading_disagrees_with_the_chain() {
    let ids = referenced_ids();
    let unlocks = coinbase_unlock_times();
    if ids.is_empty() || unlocks.is_empty() {
        eprintln!("no unlock corpus; skipping");
        return;
    }

    let mut discriminating = 0usize;
    let mut checked = 0usize;

    for (&height, id) in &ids {
        let Some(&recorded) = unlocks.get(&height) else {
            continue;
        };
        checked += 1;

        // The three misreadings worth ruling out.
        let swapped = ((u64::from(id[1]) << 4) | u64::from(id[0] >> 4)) * 2 + 288;
        let le_two_bytes = ((u64::from(id[1]) << 8) | u64::from(id[0])) * 2 + 288;
        let full_first_byte = ((u64::from(id[0]) << 8) | u64::from(id[1])) * 2 + 288;

        let correct = dynamic_unlock_window(id);
        assert_eq!(height + correct, recorded, "height {height}");

        for (name, wrong) in [
            ("byte-swapped", swapped),
            ("little-endian u16", le_two_bytes),
            ("two whole bytes", full_first_byte),
        ] {
            if wrong != correct {
                discriminating += 1;
                assert_ne!(
                    height + wrong,
                    recorded,
                    "height {height}: the {name} reading also matched, so this \
                     block does not discriminate"
                );
            }
        }
    }

    assert!(
        discriminating >= checked,
        "only {discriminating} discriminating comparisons over {checked} blocks; \
         the corpus does not rule out a misreading"
    );
    eprintln!(
        "coinbase unlock: {discriminating} comparisons rule out a misread across \
         {checked} blocks"
    );
}

/// The observed windows must lie in the range the rule allows, 288..=8478 —
/// a cheap check that the corpus is what it claims to be.
#[test]
fn the_observed_windows_are_in_range() {
    let unlocks = coinbase_unlock_times();
    if unlocks.is_empty() {
        eprintln!("no block corpus; skipping");
        return;
    }
    for (&height, &unlock) in &unlocks {
        let window = unlock
            .checked_sub(height)
            .unwrap_or_else(|| panic!("height {height}: unlock {unlock} is in the past"));
        assert!(
            (288..=8478).contains(&window),
            "height {height}: window {window} outside 288..=8478"
        );
    }
    eprintln!(
        "coinbase unlock: {} HF 16-17 windows all within 288..=8478",
        unlocks.len()
    );
}
