//! The long-term block weight model against the chain's own stored column.
//!
//! `specs/15-testing-and-conformance.md` §3.2: "**Weights.** Replay a
//! 100,000-block window and compare `long_term_weight` per block against the
//! C++ values from `get_block_header_by_height`."
//!
//! This is the only way to check the model. `long_term_weight` is a stored
//! database column that **cannot be recomputed from block weights alone**
//! (`specs/06` §3.4) — it is a median over previously *stored* long-term
//! weights, so it is self-referential. Any error is therefore self-propagating:
//! one wrong value poisons the next 100,000 medians, which is exactly why the
//! replay runs two ways.
//!
//! **One-step.** At each height, predict `long_term_weight[h]` from the
//! *chain's own recorded* history. A failure names the first height whose rule
//! is wrong, rather than the first to be poisoned by an earlier one.
//!
//! **Closed-loop.** Seed once, then feed each prediction forward as the input
//! to the next. This is what a syncing node actually does, and it is the only
//! form that catches an error which happens to be invisible for its own block.
//!
//! The rows come from `scripts/fetch-weights.py` and are **not committed**, the
//! way the block corpus is not. Ranges are picked up from
//! `tests/corpus/weights/` as they appear:
//!
//! * nothing there — skip, so a fresh checkout still builds;
//! * a `.part` file — a fetch in progress. Every row in it is checked and a
//!   mismatch still fails, but it cannot satisfy the coverage requirements;
//! * a complete `.tsv` — the full gate, including "this corpus actually reaches
//!   past HF 13" and "it covers at least 100,000 heights".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use wow_consensus::hardfork::HardFork;
use wow_consensus::weight::{next_long_term_block_weight, LongTermWeightWindow};
use wow_types::Network;

struct Range {
    name: String,
    rows: Vec<Row>,
    /// A `.part` file is a fetch in progress: worth checking, not worth
    /// trusting for coverage.
    complete: bool,
}

impl Range {
    fn start(&self) -> u64 {
        self.rows[0].height
    }

    /// How many leading rows are needed just to fill the median window.
    ///
    /// Zero for a from-genesis range: below height 100,000 the window is the
    /// whole chain so far, and below HF 13 every stored weight is the block
    /// weight, so a replay from genesis needs no seed at all.
    fn seed_len(&self) -> usize {
        wow_consensus::weight::long_term_window(self.start()) as usize
    }

    /// Can this range be replayed, or is it only long enough to *probe* a
    /// specific height?
    ///
    /// A short window straddling a fork boundary is still worth having — see
    /// `the_hf20_switch_pins_which_version_applies` — but it cannot seed a
    /// median.
    fn is_replayable(&self) -> bool {
        self.rows.len() > self.seed_len() && self.rows.len() >= 1_000
    }
}

struct Row {
    height: u64,
    major_version: u8,
    block_weight: u64,
    long_term_weight: u64,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/weights")
}

fn load(path: &Path) -> Vec<Row> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let rows: Vec<Row> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 5, "malformed row: {l}");
            Row {
                height: f[0].parse().expect("height"),
                major_version: f[1].parse().expect("major_version"),
                block_weight: f[2].parse().expect("block_weight"),
                long_term_weight: f[3].parse().expect("long_term_weight"),
            }
        })
        .collect();

    for w in rows.windows(2) {
        assert_eq!(
            w[1].height,
            w[0].height + 1,
            "{}: gap in the range, the median window needs every block",
            path.display()
        );
    }
    rows
}

/// Every range in the corpus directory, complete or in progress.
fn ranges() -> Vec<Range> {
    let dir = corpus_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut found: Vec<Range> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter_map(|p| {
            let name = p.file_name().and_then(|s| s.to_str())?.to_string();
            if !name.starts_with("mainnet-") {
                return None;
            }
            let complete = if name.ends_with(".tsv") {
                true
            } else if name.ends_with(".tsv.part") {
                false
            } else {
                return None;
            };
            let rows = load(&p);
            (!rows.is_empty()).then_some(Range {
                name,
                rows,
                complete,
            })
        })
        .collect();
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

/// Nothing on disk means a fresh checkout; say so and skip rather than fail.
fn skip_if_absent(all: &[Range]) -> bool {
    if all.is_empty() {
        eprintln!(
            "no weight corpus in {}; run `python scripts/fetch-weights.py \
             --preset genesis` to enable the weight gate",
            corpus_dir().display()
        );
        return true;
    }
    false
}

/// Say what a partial fetch means for the result, so a weakened gate is never
/// silent.
fn note_partial(all: &[Range]) {
    for r in all.iter().filter(|r| !r.complete) {
        eprintln!(
            "  {} is still being fetched ({} rows, through height {}); checked \
             but not counted towards coverage",
            r.name,
            r.rows.len(),
            r.rows.last().map_or(0, |x| x.height)
        );
    }
}

/// The version of a height, from the hard-fork table — not from the block's own
/// `major_version` field.
///
/// `required_version`, not `ideal_version`: the latter skips table index 0
/// (`specs/06` §9.5) and so reports 1 for every height below 6,969, which is
/// not what `get_current_version()` returns.
fn version_at(hf: &HardFork, height: u64) -> u8 {
    hf.required_version(height)
}

/// The tip's version at the moment `get_next_long_term_block_weight` runs for
/// the block at `height` — which is the version of `height` itself.
///
/// The call happens before `add_block` advances the fork index, but
/// `HardFork::add` votes at `height + 1`, so the two offsets cancel
/// (`docs/spec-deltas.md` §13). This is a named function rather than an inlined
/// call because settling it is part of what this file is for.
fn version_for_stored_weight(hf: &HardFork, height: u64) -> u8 {
    version_at(hf, height)
}

/// The corpus must actually reach past HF 13, or it proves nothing: below it
/// every stored long-term weight is trivially the block weight.
fn spans_the_long_term_gate(rows: &[Row]) -> bool {
    rows.iter().any(|r| r.major_version >= 13)
}

/// `specs/15` §3.2, one-step form.
#[test]
fn stored_long_term_weights_match_the_chain() {
    let all = ranges();
    if skip_if_absent(&all) {
        return;
    }
    note_partial(&all);

    let hf = HardFork::new(Network::Mainnet);
    let mut covered = 0usize;
    let mut summary = Vec::new();

    for range in &all {
        if !range.is_replayable() {
            eprintln!(
                "  {} is a {}-row probe, too short to seed a median; skipped here",
                range.name,
                range.rows.len()
            );
            continue;
        }
        let rows = &range.rows;
        let start = range.start();
        let seed_len = range.seed_len();

        let mut window = LongTermWeightWindow::new();
        let mut checked = 0usize;
        let mut failures = Vec::new();

        for (i, r) in rows.iter().enumerate() {
            if i >= seed_len {
                let version = version_for_stored_weight(&hf, r.height);
                let got = window.next_long_term_block_weight(version, r.block_weight);
                if got != r.long_term_weight && failures.len() < 10 {
                    failures.push(format!(
                        "  height {} (v{version}, block_weight {}): got {got}, \
                         chain stored {}",
                        r.height, r.block_weight, r.long_term_weight
                    ));
                }
                checked += usize::from(got == r.long_term_weight);
            }
            // Always push the *recorded* value, never the prediction.
            window.push(r.long_term_weight);
        }

        assert!(
            failures.is_empty(),
            "{}: {} heights mismatched:\n{}",
            range.name,
            failures.len(),
            failures.join("\n")
        );
        if range.complete {
            covered += checked;
        }
        summary.push(format!(
            "{}: {checked} heights from {start} (seed {seed_len}){}",
            range.name,
            if range.complete { "" } else { " [partial]" }
        ));
    }
    eprintln!("weights (one-step):\n  {}", summary.join("\n  "));

    if all.iter().all(|r| !r.complete) {
        eprintln!("  no complete range yet; coverage not enforced");
        return;
    }
    assert!(
        all.iter()
            .any(|r| r.complete && spans_the_long_term_gate(&r.rows)),
        "no complete range reaches HF 13, where every long-term weight is just \
         the block weight and the model is untested"
    );
    assert!(
        covered >= 100_000,
        "only {covered} heights covered; §3.2 asks for a 100,000-block window"
    );
}

/// The closed-loop form a syncing node actually runs: every median is built
/// from predictions, not from recorded values.
#[test]
fn a_closed_loop_replay_reproduces_the_column() {
    let all = ranges();
    if skip_if_absent(&all) {
        return;
    }
    let hf = HardFork::new(Network::Mainnet);
    let mut ran = 0usize;
    let mut complete_run = false;

    for range in &all {
        // Only a from-genesis range can be replayed closed-loop without
        // trusting recorded values for the seed.
        if range.rows[0].height != 0 {
            continue;
        }
        let mut window = LongTermWeightWindow::new();
        for r in &range.rows {
            let version = version_for_stored_weight(&hf, r.height);
            let got = window.next_long_term_block_weight(version, r.block_weight);
            assert_eq!(
                got, r.long_term_weight,
                "{}: closed-loop replay diverged at height {} (v{version})",
                range.name, r.height
            );
            window.push(got);
            ran += 1;
        }
        complete_run |= range.complete;
        eprintln!(
            "weights (closed-loop): {} heights from genesis in {}{}",
            range.rows.len(),
            range.name,
            if range.complete { "" } else { " [partial]" }
        );
    }

    assert!(
        ran > 0,
        "no from-genesis range; run scripts/fetch-weights.py --preset genesis"
    );
    if !complete_run {
        eprintln!("  no complete from-genesis range yet; coverage not enforced");
        return;
    }
    assert!(
        all.iter()
            .any(|r| r.complete && spans_the_long_term_gate(&r.rows)),
        "no complete range reaches HF 13"
    );
}

/// Which version the stored long-term weight uses, over a from-genesis replay.
///
/// At an HF boundary the two candidate readings — the block's own version, or
/// the previous height's — *can* give different answers, and the C's two
/// offsets cancel out to "its own version" (`docs/spec-deltas.md` §13).
///
/// On Wownero the boundaries below HF 20 cannot show it. The HF 13–19 clamp is
/// an upper bound at `ltem * 1.4`, and with the long-term median pinned at its
/// 300,000 floor that is 420,000 — far above any block in this range, so the
/// clamp never binds and both readings return the raw block weight. This test
/// therefore asserts that they *agree*, and that the reason is the one just
/// given; `the_hf20_switch_pins_which_version_applies` is what actually settles
/// the question.
#[test]
fn the_stored_weight_uses_the_blocks_own_version() {
    let all = ranges();
    if skip_if_absent(&all) {
        return;
    }
    let hf = HardFork::new(Network::Mainnet);
    let mut discriminating = 0usize;
    let mut boundaries = 0usize;

    for range in &all {
        if range.start() != 0 || !range.is_replayable() {
            continue;
        }
        let mut window = LongTermWeightWindow::new();
        for r in &range.rows {
            let own = version_at(&hf, r.height);
            let prev = version_at(&hf, r.height.saturating_sub(1));
            let m = window.median();
            let with_own = next_long_term_block_weight(own, r.block_weight, m);
            let with_prev = next_long_term_block_weight(prev, r.block_weight, m);

            if own != prev {
                boundaries += 1;
                // The clamp is what makes the two readings differ, so if they
                // agree here the block must be inside it.
                if with_own == with_prev {
                    let ltem = 300_000u64.max(m);
                    assert!(
                        r.block_weight <= ltem + ltem * 2 / 5,
                        "{}: height {} is a v{prev}->v{own} boundary whose \
                         weight {} exceeds the clamp, so the two readings \
                         should have differed",
                        range.name,
                        r.height,
                        r.block_weight
                    );
                }
            }
            if with_own != with_prev {
                discriminating += 1;
                assert_eq!(
                    with_own, r.long_term_weight,
                    "{}: height {} distinguishes the two readings, and the \
                     chain agrees with the block's *own* version (v{own}, not \
                     v{prev})",
                    range.name, r.height
                );
            }
            window.push(r.long_term_weight);
        }
    }

    eprintln!(
        "weights: {boundaries} fork boundaries replayed, {discriminating} of \
         them distinguish the two version readings"
    );
}

/// **The test that settles `docs/spec-deltas.md` §13.**
///
/// HF 20 is the one boundary where the two readings must differ on Wownero.
/// The 2021-scaling clamp adds a *lower* bound of `ltem * 10 / 17`, and with
/// the long-term median at its 300,000 floor that is
/// `3_000_000 / 17 = 176_470` — above essentially every Wownero block, which
/// run to a few tens of kilobytes. So at the switch the stored column jumps
/// from the raw block weight to a flat 176,470, and **the height it jumps at
/// names the version that applies**:
///
/// ```text
/// 513_999  v19  block_weight 95   ->  stored 95
/// 514_000  v20  block_weight 96   ->  stored 176_470
/// ```
///
/// Under the block's own version the jump is at 514,000. Under the previous
/// height's it would be at 514,001. The chain says 514,000.
///
/// This needs only a few rows either side, not a replay — `ltem` is pinned to
/// the floor, which the test verifies rather than assumes.
#[test]
fn the_hf20_switch_pins_which_version_applies() {
    const HF20_HEIGHT: u64 = 514_000;
    /// `ltem * 10 / 17` with `ltem` at the 300,000 floor.
    const FLOOR_LOWER_BOUND: u64 = 300_000 * 10 / 17;

    let all = ranges();
    if skip_if_absent(&all) {
        return;
    }
    let hf = HardFork::new(Network::Mainnet);

    let Some(range) = all.iter().find(|r| {
        r.rows.first().is_some_and(|f| f.height < HF20_HEIGHT)
            && r.rows.last().is_some_and(|l| l.height >= HF20_HEIGHT)
    }) else {
        eprintln!(
            "no range straddles the HF 20 switch at {HF20_HEIGHT}; run \
             `python scripts/fetch-weights.py --start 513980 --end 514020` \
             to settle which version the stored weight uses"
        );
        return;
    };

    assert_eq!(FLOOR_LOWER_BOUND, 176_470);
    assert_eq!(version_at(&hf, HF20_HEIGHT), 20);
    assert_eq!(version_at(&hf, HF20_HEIGHT - 1), 19);

    // Verify the premise rather than assuming it: if the long-term median were
    // above its floor, the lower bound would not be 176,470 and the argument
    // below would not hold.
    let first_v20 = range
        .rows
        .iter()
        .find(|r| r.height == HF20_HEIGHT)
        .expect("the range straddles the switch");
    assert_eq!(
        first_v20.long_term_weight, FLOOR_LOWER_BOUND,
        "the long-term median is not at its 300,000 floor here, so this test's \
         premise does not hold and the bound must be recomputed"
    );

    let mut before = 0usize;
    let mut after = 0usize;
    for r in &range.rows {
        let own = version_at(&hf, r.height);
        let prev = version_at(&hf, r.height.saturating_sub(1));

        if r.height < HF20_HEIGHT {
            assert_eq!(
                r.long_term_weight, r.block_weight,
                "{}: height {} is v{own}, below the switch, so the stored \
                 weight should be the raw block weight",
                range.name, r.height
            );
            before += 1;
        } else {
            assert_eq!(
                r.long_term_weight,
                r.block_weight.max(FLOOR_LOWER_BOUND),
                "{}: height {} is v{own}, at or past the switch",
                range.name,
                r.height
            );
            after += 1;
        }

        // The model must agree, with `ltem` at the floor (median 0 floors it).
        let with_own = next_long_term_block_weight(own, r.block_weight, 0);
        let with_prev = next_long_term_block_weight(prev, r.block_weight, 0);
        assert_eq!(
            with_own, r.long_term_weight,
            "{}: height {} disagrees with the model under its own version",
            range.name, r.height
        );

        if r.height == HF20_HEIGHT {
            assert_ne!(
                with_own, with_prev,
                "the switch height must distinguish the two readings"
            );
            assert_eq!(with_prev, r.block_weight, "v19 would store the raw weight");
            assert_ne!(
                with_prev, r.long_term_weight,
                "the previous height's version is the reading the chain rejects"
            );
        }
    }

    assert!(
        before >= 2 && after >= 2,
        "only {before} rows before and {after} after the switch; the transition \
         needs both sides to be visible"
    );
    eprintln!(
        "weights: the HF 20 switch at {HF20_HEIGHT} pins the version reading \
         ({before} rows before, {after} after; stored jumps to {FLOOR_LOWER_BOUND})"
    );
}

/// The header's own `major_version` must match the hard-fork table. If it ever
/// did not, every version-gated rule in the crate would be reading the wrong
/// thing — and this is what caught `docs/spec-deltas.md` §12, the genesis
/// block's version 7.
#[test]
fn the_hard_fork_table_matches_the_block_headers() {
    let all = ranges();
    if skip_if_absent(&all) {
        return;
    }
    let hf = HardFork::new(Network::Mainnet);
    let mut checked = 0usize;

    for range in &all {
        for r in &range.rows {
            assert_eq!(
                version_at(&hf, r.height),
                r.major_version,
                "{}: height {} is v{} in the table but v{} in its header",
                range.name,
                r.height,
                version_at(&hf, r.height),
                r.major_version
            );
            checked += 1;
        }
    }
    eprintln!("weights: {checked} headers agree with the hard-fork table");
}

/// Stored long-term weights must obey the clamp the model claims, independently
/// of the replay — a cheap invariant that would catch a corpus fetched from a
/// forked or pruned node before it produced a confusing replay failure.
#[test]
fn the_stored_column_obeys_its_own_bounds() {
    let all = ranges();
    if skip_if_absent(&all) {
        return;
    }
    for range in &all {
        let mut window = LongTermWeightWindow::new();
        for r in &range.rows {
            if r.major_version >= 13 {
                let ltem = 300_000u64.max(window.median());
                let upper = if r.major_version >= 20 {
                    ltem + ltem * 7 / 10
                } else {
                    ltem + ltem * 2 / 5
                };
                assert!(
                    r.long_term_weight <= upper,
                    "{}: height {} stored {} above the clamp {upper}",
                    range.name,
                    r.height,
                    r.long_term_weight
                );
            } else {
                assert_eq!(
                    r.long_term_weight, r.block_weight,
                    "{}: height {} is pre-HF-13, so the two must coincide",
                    range.name, r.height
                );
            }
            window.push(r.long_term_weight);
        }
    }
}

/// A range being *replayed* must not be all-identical weights, or the median
/// would be trivially right no matter what the window did.
///
/// Short probe ranges are exempt: they exist to pin one specific height, not to
/// exercise the median.
#[test]
fn the_corpus_has_varied_weights() {
    let all = ranges();
    if skip_if_absent(&all) {
        return;
    }
    for range in all.iter().filter(|r| r.is_replayable()) {
        let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
        for r in &range.rows {
            *counts.entry(r.block_weight).or_default() += 1;
        }
        assert!(
            counts.len() >= 20,
            "{}: only {} distinct block weights",
            range.name,
            counts.len()
        );
    }
}
