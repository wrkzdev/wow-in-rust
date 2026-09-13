//! The hard-fork state machine.
//!
//! `specs/06-consensus-rules.md` §1 and the tables in `specs/01` §3.
//!
//! Wownero activates forks **by height** with `threshold = 0`. The C still runs
//! the full voting machinery, but it reduces to a height lookup: with a zero
//! threshold the accumulated-vote condition in `get_voted_fork_index` is
//! satisfied immediately, so the tally never gates anything.
//!
//! Two functions that look interchangeable are not, and confusing them is
//! `specs/06` §9.5:
//!
//! * [`HardFork::ideal_version`] — used for the P2P handshake's `top_version`,
//!   the alt-chain block-template path, and `recalculate_difficulties`. It
//!   **skips table index 0**.
//! * [`HardFork::required_version`] — used for block acceptance. It does not.

use wow_types::Network;

/// One row of the hard-fork table.
///
/// The C's `hardfork_t` also carries `threshold` (always 0 here) and an
/// advisory `time`; neither affects consensus, so neither is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fork {
    pub version: u8,
    pub height: u64,
}

const fn f(version: u8, height: u64) -> Fork {
    Fork { version, height }
}

/// `mainnet_hard_forks` — `src/hardforks/hardforks.cpp`.
pub const MAINNET_HARD_FORKS: &[Fork] = &[
    f(7, 1),        // Awesome Akita
    f(8, 6_969),    // Busty Brazzers
    f(9, 53_666),   // Cool Cage
    f(10, 63_469),  // Dank Doge
    f(11, 81_769),  // Erotic EggplantEmoji
    f(12, 82_069),  // per-byte fee gate
    f(13, 114_969), // F For Fappening -- RandomWOW
    f(14, 115_257), // HF_VERSION_SMALLER_BP + 1 gate
    f(15, 160_777), // Gaping Goatse
    f(16, 253_999), // Illiterate Illuminati -- CLSAG
    f(17, 254_287), // HF_VERSION_CLSAG + 1 gate
    f(18, 331_170), // Junkie Jeff -- BP+, header signing, vote
    f(19, 331_458), // HF_VERSION_BULLETPROOF_PLUS + 1 gate
    f(20, 514_000), // Kunty Karen -- view tags, 2021 scaling
];

/// `testnet_hard_forks`. Version 21 exists **only** here.
pub const TESTNET_HARD_FORKS: &[Fork] = &[
    f(7, 1),
    f(8, 5),
    f(9, 10),
    f(10, 15),
    f(11, 20),
    f(12, 25),
    f(13, 30),
    f(14, 35),
    f(15, 40),
    f(16, 45),
    f(17, 50),
    f(18, 55),
    f(19, 60),
    f(20, 65),
    f(21, 70),
];

/// `stagenet_hard_forks`.
pub const STAGENET_HARD_FORKS: &[Fork] = &[
    f(7, 1),
    f(8, 5),
    f(9, 10),
    f(10, 15),
    f(11, 20),
    f(12, 25),
    f(13, 30),
    f(14, 35),
    f(15, 40),
    f(16, 45),
    f(17, 50),
    f(18, 55),
    f(19, 60),
    f(20, 65),
];

/// `HardFork` is constructed with `original_version = 1`.
pub const ORIGINAL_VERSION: u8 = 1;

/// The table for a network. `Fakechain` uses mainnet's.
pub fn table(network: Network) -> &'static [Fork] {
    match network.config() {
        Network::Mainnet | Network::Fakechain => MAINNET_HARD_FORKS,
        Network::Testnet => TESTNET_HARD_FORKS,
        Network::Stagenet => STAGENET_HARD_FORKS,
    }
}

/// The hard-fork table for one network.
#[derive(Clone, Copy, Debug)]
pub struct HardFork {
    network: Network,
    forks: &'static [Fork],
}

impl HardFork {
    pub fn new(network: Network) -> HardFork {
        HardFork {
            network,
            forks: table(network),
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn forks(&self) -> &'static [Fork] {
        self.forks
    }

    /// `HardFork::get_ideal_version(height)`.
    ///
    /// **Reproduces the index-0 skip** (`specs/06` §9.5). The C's loop is
    /// `for (n = heights.size() - 1; n > 0; --n)`, so index 0 is never
    /// examined and a height below `heights[1].height` returns
    /// `original_version` (**1**), not `heights[0].version` (7).
    ///
    /// On mainnet that means `ideal_version(h) == 1` for every `h < 6969`, even
    /// though those blocks all carry `major_version == 7`.
    ///
    /// This feeds `CORE_SYNC_DATA.top_version` in the handshake
    /// (`specs/08` §3.4), the alt-chain block-template path, and the
    /// `get_ideal_hard_fork_version(height) < 2` target selection in
    /// `recalculate_difficulties` — harmless there, since both targets are 300.
    pub fn ideal_version(&self, height: u64) -> u8 {
        for fork in self.forks.iter().skip(1).rev() {
            if height >= fork.height {
                return fork.version;
            }
        }
        ORIGINAL_VERSION
    }

    /// The highest version in the table — `get_ideal_version()` with no
    /// argument, which is the miner's `minor_version` vote.
    pub fn ideal_version_top(&self) -> u8 {
        self.forks.last().map_or(ORIGINAL_VERSION, |f| f.version)
    }

    /// The version a block at `height` must carry.
    ///
    /// This is `heights[current_fork_index].version` where `current_fork_index`
    /// advances via `get_voted_fork_index(height)`, which with `threshold == 0`
    /// reduces to "the highest index whose `height <= h`". Unlike
    /// [`HardFork::ideal_version`] it does **not** skip index 0, so heights
    /// 1..6968 correctly require version 7.
    ///
    /// # The floor is the table's first entry, not `ORIGINAL_VERSION`
    ///
    /// `get_voted_fork_index` ends in `return current_fork_index`, and
    /// `current_fork_index` starts at **0** — so when no fork height has been
    /// reached the answer is `heights[0].version`, which on Wownero is 7 rather
    /// than `ORIGINAL_VERSION`. The placeholder that `HardFork::init()` would
    /// push at index 0 is never pushed, because `Blockchain::init` calls
    /// `add_fork` for the whole table *before* `init()`, and `init()` only
    /// pushes it `if (heights.empty())`.
    ///
    /// This decides height 0. Wownero's genesis block carries **version 7**,
    /// and `do_check` compares the block version for *equality*
    /// (`block_version == heights[current_fork_index].version`) — so a floor of
    /// `ORIGINAL_VERSION` would reject the genesis block.
    pub fn required_version(&self, height: u64) -> u8 {
        let mut v = self.forks.first().map_or(ORIGINAL_VERSION, |f| f.version);
        for fork in self.forks {
            if height >= fork.height {
                v = fork.version;
            } else {
                break;
            }
        }
        v
    }

    /// `HardFork::check` / `do_check` (`specs/06` §1).
    ///
    /// ```text
    /// accept iff block.major_version == required
    ///       && get_block_vote(block) >= required
    /// ```
    ///
    /// Both checks are consensus even though the vote tally is inert.
    pub fn check(&self, height: u64, major_version: u8, block_vote: u8) -> bool {
        let required = self.required_version(height);
        major_version == required && block_vote >= required
    }

    /// The height at which `version` activates, if it is in the table.
    pub fn earliest_height(&self, version: u8) -> Option<u64> {
        self.forks
            .iter()
            .find(|f| f.version == version)
            .map(|f| f.height)
    }

    /// Is `version` active at `height`?
    pub fn is_active(&self, version: u8, height: u64) -> bool {
        self.earliest_height(version).is_some_and(|h| height >= h)
    }
}

/// Feature gates (`specs/01` §3.4).
///
/// Each maps a feature to the **minimum hard-fork version** at which it
/// applies. The validation code refers to them by name rather than by number.
pub mod gates {
    pub const HF_VERSION_DYNAMIC_FEE: u8 = 4;
    pub const HF_VERSION_ENFORCE_RCT: u8 = 6;
    pub const HF_VERSION_MIN_MIXIN_7: u8 = 7;
    pub const HF_VERSION_MIN_MIXIN_21: u8 = 9;
    pub const HF_VERSION_PER_BYTE_FEE: u8 = 12;
    pub const HF_VERSION_SMALLER_BP: u8 = 13;
    pub const HF_VERSION_LONG_TERM_BLOCK_WEIGHT: u8 = 13;
    /// `RX_BLOCK_VERSION` — RandomWOW takes over from CryptoNight.
    pub const RX_BLOCK_VERSION: u8 = 13;
    pub const HF_VERSION_MIN_2_OUTPUTS: u8 = 15;
    pub const HF_VERSION_MIN_V2_COINBASE_TX: u8 = 15;
    pub const HF_VERSION_SAME_MIXIN: u8 = 15;
    pub const HF_VERSION_REJECT_SIGS_IN_COINBASE: u8 = 15;
    pub const HF_VERSION_ENFORCE_MIN_AGE: u8 = 15;
    pub const HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY: u8 = 15;
    pub const HF_VERSION_EXACT_COINBASE: u8 = 16;
    pub const HF_VERSION_CLSAG: u8 = 16;
    pub const HF_VERSION_DETERMINISTIC_UNLOCK_TIME: u8 = 16;
    pub const HF_VERSION_DYNAMIC_UNLOCK: u8 = 16;
    pub const HF_VERSION_FIXED_UNLOCK: u8 = 18;
    pub const HF_VERSION_BULLETPROOF_PLUS: u8 = 18;
    pub const HF_VERSION_BLOCK_HEADER_MINER_SIG: u8 = 18;
    pub const HF_VERSION_VIEW_TAGS: u8 = 20;
    pub const HF_VERSION_2021_SCALING: u8 = 20;
    pub const HF_VERSION_BP_PLUS_FULL_COMMIT: u8 = 21;
}

#[cfg(test)]
mod tests {
    use super::gates::*;
    use super::*;

    /// `specs/01` §15: the tables must match §3 exactly, "including the 'gate'
    /// forks (12, 14, 17, 19) that exist only to close a feature window".
    #[test]
    fn tables_match_the_spec() {
        assert_eq!(MAINNET_HARD_FORKS.len(), 14);
        assert_eq!(TESTNET_HARD_FORKS.len(), 15, "testnet alone has version 21");
        assert_eq!(STAGENET_HARD_FORKS.len(), 14);

        let expect: &[(u8, u64)] = &[
            (7, 1),
            (8, 6969),
            (9, 53666),
            (10, 63469),
            (11, 81769),
            (12, 82069),
            (13, 114969),
            (14, 115257),
            (15, 160777),
            (16, 253999),
            (17, 254287),
            (18, 331170),
            (19, 331458),
            (20, 514000),
        ];
        for (i, (v, h)) in expect.iter().enumerate() {
            assert_eq!(MAINNET_HARD_FORKS[i], f(*v, *h), "mainnet row {i}");
        }

        // Testnet/stagenet: 7.. at heights 1, 5, 10, 15, ... in steps of 5.
        for (i, fork) in TESTNET_HARD_FORKS.iter().enumerate() {
            assert_eq!(fork.version, 7 + i as u8);
            assert_eq!(fork.height, if i == 0 { 1 } else { 5 * i as u64 });
        }
        assert_eq!(TESTNET_HARD_FORKS.last().unwrap(), &f(21, 70));
        assert_eq!(STAGENET_HARD_FORKS.last().unwrap(), &f(20, 65));

        // Ascending in both columns, which `add_fork` enforces.
        for t in [MAINNET_HARD_FORKS, TESTNET_HARD_FORKS, STAGENET_HARD_FORKS] {
            for w in t.windows(2) {
                assert!(w[1].version > w[0].version);
                assert!(w[1].height > w[0].height);
            }
        }

        // There is no mainnet fork above 20 (`specs/01` §3.1).
        assert_eq!(MAINNET_HARD_FORKS.last().unwrap().version, 20);
    }

    /// `specs/06` §9.5, the quirk that is easiest to "fix" by accident:
    /// `get_ideal_version` never examines index 0, so below the *second* fork's
    /// height it returns `original_version = 1` rather than 7.
    #[test]
    fn ideal_version_skips_table_index_zero() {
        let hf = HardFork::new(Network::Mainnet);

        // Every height below 6969 -- including the genesis and the entire HF 7
        // era -- reports version 1.
        for h in [0u64, 1, 2, 100, 6967, 6968] {
            assert_eq!(hf.ideal_version(h), 1, "height {h}");
        }
        // From the second fork on, it is the real version.
        assert_eq!(hf.ideal_version(6969), 8);
        assert_eq!(hf.ideal_version(53_665), 8);
        assert_eq!(hf.ideal_version(53_666), 9);
        assert_eq!(hf.ideal_version(514_000), 20);
        assert_eq!(hf.ideal_version(u64::MAX), 20);

        // required_version does NOT skip index 0 -- this is the difference.
        assert_eq!(hf.required_version(1), 7);
        assert_eq!(hf.required_version(6968), 7);
        assert_ne!(
            hf.ideal_version(6968),
            hf.required_version(6968),
            "the two must disagree over heights 1..6968"
        );
    }

    /// Height 0 is below every fork height, and the two functions part company
    /// there for a reason the table alone does not show.
    ///
    /// `get_ideal_version` falls through to `original_version` (1). But
    /// `get_voted_fork_index` falls through to `current_fork_index`, which
    /// starts at 0 — so `get_current_version()` is `heights[0].version` (7).
    /// Wownero's genesis block carries version 7 and `do_check` compares for
    /// equality, so a floor of 1 in `required_version` would reject it.
    #[test]
    fn genesis_is_below_every_fork() {
        let hf = HardFork::new(Network::Mainnet);
        assert_eq!(hf.ideal_version(0), ORIGINAL_VERSION, "1: the placeholder");
        assert_eq!(
            hf.required_version(0),
            MAINNET_HARD_FORKS[0].version,
            "7: the first table entry, not the placeholder"
        );
        assert_eq!(hf.required_version(0), 7);
        assert_ne!(hf.required_version(0), ORIGINAL_VERSION);

        // The real genesis block carries 7, and must be accepted.
        assert!(
            hf.check(0, 7, 7),
            "the mainnet genesis block must pass its own check"
        );
    }

    /// `required_version` is the acceptance rule, and it must be exact at every
    /// boundary.
    #[test]
    fn required_version_at_every_boundary() {
        let hf = HardFork::new(Network::Mainnet);
        for w in MAINNET_HARD_FORKS.windows(2) {
            assert_eq!(hf.required_version(w[0].height), w[0].version);
            assert_eq!(hf.required_version(w[1].height - 1), w[0].version);
            assert_eq!(hf.required_version(w[1].height), w[1].version);
        }
        let last = MAINNET_HARD_FORKS.last().unwrap();
        assert_eq!(hf.required_version(last.height), last.version);
        assert_eq!(hf.required_version(last.height + 1_000_000), last.version);
    }

    /// `specs/06` §1: accept iff `major_version == required` **and**
    /// `get_block_vote(b) >= required`, where the vote comes from
    /// `minor_version` with 0 meaning 1.
    #[test]
    fn acceptance_needs_both_the_version_and_the_vote() {
        let hf = HardFork::new(Network::Mainnet);
        let h = 514_000; // requires version 20

        assert!(hf.check(h, 20, 20), "matching version and vote");
        assert!(hf.check(h, 20, 21), "a vote for a later fork is fine");
        assert!(!hf.check(h, 19, 20), "wrong major_version");
        assert!(!hf.check(h, 21, 21), "also wrong: must equal, not exceed");
        assert!(!hf.check(h, 20, 19), "vote below the required version");

        // At HF 7 a minor_version of 0 votes for 1, which is below 7.
        assert!(!hf.check(1, 7, 1), "minor_version 0 -> vote 1 < 7");
        assert!(hf.check(1, 7, 7));
    }

    /// `specs/01` §3.4. The gate versions decide every rule in `specs/06`, so a
    /// typo here is a silent consensus change.
    #[test]
    fn feature_gates() {
        assert_eq!(HF_VERSION_DYNAMIC_FEE, 4);
        assert_eq!(HF_VERSION_ENFORCE_RCT, 6);
        assert_eq!(HF_VERSION_MIN_MIXIN_7, 7);
        assert_eq!(HF_VERSION_MIN_MIXIN_21, 9);
        assert_eq!(HF_VERSION_PER_BYTE_FEE, 12);
        assert_eq!(HF_VERSION_SMALLER_BP, 13);
        assert_eq!(HF_VERSION_LONG_TERM_BLOCK_WEIGHT, 13);
        assert_eq!(RX_BLOCK_VERSION, 13);
        assert_eq!(HF_VERSION_MIN_2_OUTPUTS, 15);
        assert_eq!(HF_VERSION_MIN_V2_COINBASE_TX, 15);
        assert_eq!(HF_VERSION_SAME_MIXIN, 15);
        assert_eq!(HF_VERSION_REJECT_SIGS_IN_COINBASE, 15);
        assert_eq!(HF_VERSION_ENFORCE_MIN_AGE, 15);
        assert_eq!(HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY, 15);
        assert_eq!(HF_VERSION_EXACT_COINBASE, 16);
        assert_eq!(HF_VERSION_CLSAG, 16);
        assert_eq!(HF_VERSION_DETERMINISTIC_UNLOCK_TIME, 16);
        assert_eq!(HF_VERSION_DYNAMIC_UNLOCK, 16);
        assert_eq!(HF_VERSION_FIXED_UNLOCK, 18);
        assert_eq!(HF_VERSION_BULLETPROOF_PLUS, 18);
        assert_eq!(HF_VERSION_BLOCK_HEADER_MINER_SIG, 18);
        assert_eq!(HF_VERSION_VIEW_TAGS, 20);
        assert_eq!(HF_VERSION_2021_SCALING, 20);
        assert_eq!(HF_VERSION_BP_PLUS_FULL_COMMIT, 21);

        // The gate forks exist precisely to close a `>` window one fork later.
        let hf = HardFork::new(Network::Mainnet);
        for (feature, gate) in [
            (HF_VERSION_SMALLER_BP, 14u8),
            (HF_VERSION_CLSAG, 17),
            (HF_VERSION_BULLETPROOF_PLUS, 19),
        ] {
            assert_eq!(gate, feature + 1);
            assert!(
                hf.earliest_height(gate).is_some(),
                "gate {gate} is in the table"
            );
        }

        // 21 is testnet-only.
        assert!(HardFork::new(Network::Mainnet)
            .earliest_height(HF_VERSION_BP_PLUS_FULL_COMMIT)
            .is_none());
        assert_eq!(
            HardFork::new(Network::Testnet).earliest_height(HF_VERSION_BP_PLUS_FULL_COMMIT),
            Some(70)
        );
    }

    /// `Fakechain` uses the mainnet table (`get_config` maps it to mainnet).
    #[test]
    fn fakechain_uses_the_mainnet_table() {
        assert_eq!(table(Network::Fakechain), MAINNET_HARD_FORKS);
        assert_eq!(
            HardFork::new(Network::Fakechain).required_version(514_000),
            20
        );
    }

    #[test]
    fn is_active_and_earliest_height() {
        let hf = HardFork::new(Network::Mainnet);
        assert_eq!(hf.earliest_height(13), Some(114_969));
        assert!(!hf.is_active(13, 114_968));
        assert!(hf.is_active(13, 114_969));
        assert_eq!(hf.earliest_height(6), None, "no fork below 7");
        assert!(!hf.is_active(6, u64::MAX));
        assert_eq!(hf.ideal_version_top(), 20);
        assert_eq!(HardFork::new(Network::Testnet).ideal_version_top(), 21);
    }
}
