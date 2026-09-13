//! RandomWOW seed-hash epochs.
//!
//! `specs/03-pow.md` §3.2, from `src/crypto/rx-slow-hash.c`. Pure arithmetic,
//! so it is testable without the library.

/// `SEEDHASH_EPOCH_BLOCKS`.
///
/// Equal to `BLOCKS_SYNCHRONIZING_MAX_COUNT` (`specs/01` §12.1), and that is
/// not a coincidence: sync requests are capped and aligned to this so a batch
/// shares one seed and one dataset (`specs/03` §3.4, `specs/08` §5.4).
pub const SEEDHASH_EPOCH_BLOCKS: u64 = 2048;

/// `SEEDHASH_EPOCH_LAG`.
pub const SEEDHASH_EPOCH_LAG: u64 = 64;

/// `rx_seedheight(height)` — the height whose **block id** is the seed hash.
///
/// Note the seed is the block *id*, not the PoW hash (`specs/03` §3.2).
pub fn rx_seedheight(height: u64) -> u64 {
    if height <= SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG {
        0
    } else {
        (height - SEEDHASH_EPOCH_LAG - 1) & !(SEEDHASH_EPOCH_BLOCKS - 1)
    }
}

/// `rx_seedheights(height)` — the current and next seed heights.
///
/// The "next" one is what `get_block_template` reports as `next_seed_hash` so a
/// miner can pre-build the coming dataset.
pub fn rx_seedheights(height: u64) -> (u64, u64) {
    (
        rx_seedheight(height),
        rx_seedheight(height + SEEDHASH_EPOCH_LAG),
    )
}

/// Is `height` the first block of a new seed epoch?
///
/// Useful for deciding when to start building the next dataset in the
/// background.
pub fn is_seed_epoch_start(height: u64) -> bool {
    height > 0 && rx_seedheight(height) != rx_seedheight(height - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `specs/03` §7: "`rx_seedheight` matches §3.2 including the
    /// `height <= 2112 => 0` case."
    #[test]
    fn early_heights_use_the_zero_seed() {
        for h in 0..=2112u64 {
            assert_eq!(rx_seedheight(h), 0, "height {h}");
        }
        // 2113 is the first height with a non-zero seed.
        assert_eq!(rx_seedheight(2113), 2048);
    }

    /// The boundaries `specs/15` §2.3 lists explicitly.
    #[test]
    fn spec_boundary_heights() {
        assert_eq!(rx_seedheight(2048), 0);
        assert_eq!(rx_seedheight(2112), 0);
        assert_eq!(rx_seedheight(2113), 2048);
        assert_eq!(rx_seedheight(4096), 2048);
        // 4096 + 64 + 1 = 4161 is the first height in the next epoch.
        assert_eq!(rx_seedheight(4160), 2048);
        assert_eq!(rx_seedheight(4161), 4096);
    }

    /// The seed height is always a multiple of the epoch length, and never
    /// ahead of the block it serves.
    #[test]
    fn seed_height_is_aligned_and_behind() {
        for h in 0..40_000u64 {
            let s = rx_seedheight(h);
            assert_eq!(s % SEEDHASH_EPOCH_BLOCKS, 0, "height {h} -> {s} unaligned");
            assert!(s <= h, "height {h} -> seed {s} is ahead");
            if h > SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG {
                // The lag guarantees the seed block is deeply confirmed.
                assert!(h - s > SEEDHASH_EPOCH_LAG, "height {h} -> seed {s}");
            }
        }
    }

    /// The seed changes exactly once per epoch, and at the height the lag
    /// implies.
    #[test]
    fn seed_changes_once_per_epoch() {
        let mut changes = Vec::new();
        for h in 1..20_000u64 {
            if is_seed_epoch_start(h) {
                changes.push(h);
            }
        }
        assert_eq!(
            changes,
            vec![2113, 4161, 6209, 8257, 10305, 12353, 14401, 16449, 18497]
        );
        for w in changes.windows(2) {
            assert_eq!(w[1] - w[0], SEEDHASH_EPOCH_BLOCKS);
        }
    }

    /// `rx_seedheights` returns the current seed and the one `SEEDHASH_EPOCH_LAG`
    /// blocks ahead, which is either the same or exactly one epoch later.
    #[test]
    fn next_seed_is_this_one_or_the_next() {
        for h in 0..20_000u64 {
            let (cur, next) = rx_seedheights(h);
            assert!(
                next == cur || next == cur + SEEDHASH_EPOCH_BLOCKS,
                "height {h}: {cur} -> {next}"
            );
        }
    }

    /// `specs/01` §15: "`BLOCKS_SYNCHRONIZING_MAX_COUNT == SEEDHASH_EPOCH_BLOCKS
    /// == 2048`", and `specs/08` §5.4 says to align block requests to that so
    /// "a batch shares one RandomWOW seed".
    ///
    /// The alignment that actually yields **one** seed is `2048k + 65`, not
    /// `2048k`: the `SEEDHASH_EPOCH_LAG` of 64 shifts each change 65 blocks
    /// past the round boundary. A plainly 2048-aligned batch straddles a change
    /// and needs **two** seeds — still a bounded, cheap number, which is the
    /// point of aligning at all, but not one.
    #[test]
    fn epoch_matches_the_sync_batch_size() {
        assert_eq!(SEEDHASH_EPOCH_BLOCKS, 2048);

        let seeds_over = |start: u64| -> usize {
            (start..start + SEEDHASH_EPOCH_BLOCKS)
                .map(rx_seedheight)
                .collect::<std::collections::HashSet<u64>>()
                .len()
        };

        // Round alignment: two seeds, and only the first 65 blocks use the
        // older one.
        let round = 100_000u64 & !(SEEDHASH_EPOCH_BLOCKS - 1);
        assert_eq!(seeds_over(round), 2);
        let change = (round..round + SEEDHASH_EPOCH_BLOCKS)
            .find(|h| is_seed_epoch_start(*h))
            .unwrap();
        assert_eq!(change - round, SEEDHASH_EPOCH_LAG + 1);

        // Shifting by the lag gives exactly one seed per batch.
        assert_eq!(seeds_over(round + SEEDHASH_EPOCH_LAG + 1), 1);

        // Either way it is bounded at two, which is what keeps a sync batch off
        // the 200-500 ms seed-switch path (`specs/03` §3.4).
        for k in 0..50u64 {
            assert!(seeds_over(k * SEEDHASH_EPOCH_BLOCKS) <= 2);
        }
    }
}
