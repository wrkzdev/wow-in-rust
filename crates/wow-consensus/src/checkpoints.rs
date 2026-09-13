//! Hard-coded checkpoints.
//!
//! `specs/01-constants.md` §14, from `checkpoints::init_default_checkpoints`.
//!
//! A block at a checkpointed height whose hash differs MUST be rejected, and a
//! block below the last checkpoint can never be reorged out (`specs/06` §7).
//! The cumulative difficulties feed `check_difficulty_checkpoints` /
//! `recalculate_difficulties`, which detect drift — and which `specs/07` §6
//! calls "a cheap and very effective integration test: if your difficulty
//! implementation is wrong anywhere, this fires at the first checkpoint past
//! the error".
//!
//! Two other sources exist and are both **inert on Wownero**, so neither is
//! implemented (`specs/01` §14):
//!
//! * `load_checkpoints_from_json(<datadir>/checkpoints.json)` — a user-supplied
//!   file, independent of DNS;
//! * `load_checkpoints_from_dns` — the DNS TXT URL lists for all three networks
//!   are empty, so it always returns `true` having added nothing.

use wow_types::{Difficulty, Hash256, Network};

/// One `(height, block_hash, cumulative_difficulty)` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub hash: Hash256,
    pub cumulative_difficulty: Difficulty,
}

const fn c(height: u64, hash: &str, cumulative_difficulty: Difficulty) -> Checkpoint {
    Checkpoint {
        height,
        hash: hex32(hash),
        cumulative_difficulty,
    }
}

/// Parse a 64-character hex string at compile time, so a malformed literal is a
/// build error rather than a runtime surprise.
const fn hex32(s: &str) -> Hash256 {
    let b = s.as_bytes();
    assert!(b.len() == 64, "a block hash is 64 hex characters");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[i * 2]) << 4) | nibble(b[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn nibble(ch: u8) -> u8 {
    match ch {
        b'0'..=b'9' => ch - b'0',
        b'a'..=b'f' => ch - b'a' + 10,
        _ => panic!("checkpoint hashes are lowercase hex"),
    }
}

/// The complete mainnet table: **39 entries**.
///
/// `specs/01` §14: "Assert `table.len() == 39` in a unit test so a future
/// upstream addition is caught rather than silently missed."
#[rustfmt::skip] // one checkpoint per line; wrapping makes the table unreadable
pub const MAINNET_CHECKPOINTS: &[Checkpoint] = &[
    c(1, "97f4ce4d7879b3bea54dcec738cd2ebb7952b4e9bb9743262310cd5fec749340", 0x2),
    c(6969, "aa7b66e8c461065139b55c29538a39c33ceda93e587f84d490ed573d80511c87", 0x118eef693fd),
    c(53666, "3f43f56f66ef0c43cf2fd14d0d28fa2aae0ef8f40716773511345750770f1255", 0xb677d6405ae),
    c(63469, "4e33a9343fc5b86661ec0affaeb5b5a065290602c02d817337e4a979fe5747d8", 0xe7cd9819062),
    c(81769, "41db9fef8d0ccfa78b570ee9525d4f55de77b510c3ae4b08a1d51b9aec9ade1d", 0x150066455b88),
    c(82069, "fdea800d23d0b2eea19dec8af31e453e883e8315c97e25c8bb3e88ca164f8369", 0x15079b5fdaa8),
    c(114969, "b48245956b87f243048fd61021f4b3e5443e57eee7ff8ba4762d18926e80b80c", 0x1ca552b3ec68),
    c(115257, "338e056551087fe23d6c4b4280244bc5362b004716d85ec799a775f190f9fea9", 0x1cb25f5d4628),
    c(160777, "9496690579af21f38f00e67e11c2e85a15912fe4f412aad33d1162be1579e755", 0x5376eaa196a8),
    c(253999, "755a289fe8a68e96a0f69069ba4007b676ec87dce2e47dfb9647fe5691f49883", 0x172d026ef7fe8),
    c(254287, "b37cb55abe73965b424f8028bf71bef98d069645077ffa52f0c134907b7734e3", 0x1746622f56668),
    c(256700, "389a8ab95a80e84ec74639c1078bc67b33af208ef00f53bd9609cfc40efa7059", 0x185ace3c1bd68),
    c(271600, "9597cdbdc52ca57d7dbd8f9c0a23a73194ef2ebbcfdc75c21992672706108d43", 0x1e2d2d6a2a9e8),
    c(278300, "b10dcdf7a51651f60fbcc0447409773eef1458d2c706d9a61daf467571ac19c9", 0x20a83a16d3968),
    c(282700, "79c06cafd7cb5f76bcebbf8f1ae16203bb41fd75b284bcd0eb0b457991ab7d4a", 0x22e3baf142de8),
    c(307686, "dfd056b2739c132a07629409a59a028cb7414fac23e3419e79d2f49d66fc3af5", 0x305ba542e3ea8),
    c(307692, "d822cd72037f62824ec87c9dc11768b45dc2632f697fa372e1885789c90f37fc", 0x305e124633878),
    c(307735, "60970378aecdc0a78ccf5154edcc56f23aad8554b49e4716f820461a7588bfdc", 0x3070771b9ba58),
    c(307742, "0ed835bc9fcd949b5a184cf607dcc62ac4268c9e4cf220f8b09bcce58f10916b", 0x30732f1248978),
    c(307750, "7bcafbc757237125b70f569b181eb1b66c530b10d817d7b940f7a73dc827211c", 0x30766666b3d98),
    c(307766, "02fd6c7d6bae710cfa3efb08f50e4bc9a590f6ab61eabd87e5e951338c0c36f6", 0x307d2d47a7918),
    c(307800, "3594894b4231cfdfe911afed6552f9fb4cfe6048bacd0973a3a98623ec8548ce", 0x308b305ca7618),
    c(307880, "659274b698f680c6cae2716cbd4e15ad5def23b5de98e53734c4af2c2e74bb7a", 0x30af6e91e8018),
    c(307883, "9a8c35cd10963a14bba8a9628d1776df92fee5e3153b7249f5d15726efafaaea", 0x30b0965ba5a18),
    c(312130, "e0da085bd273fff9f5f8e604fce0e91908bc62b6b004731a93e16e89cb9b1f54", 0x3cfe7148f2e18),
    c(324600, "b24cd1ed7c192bbcf3d5b15729f2b032566687f96bda6f8cb73a5b16df4c6e6b", 0x69caecbe78718),
    c(327700, "f113c8cbe077aab9296ecbfb41780c147aeb54edfece7e4b9946b8abd0f06de7", 0x732431429c818),
    c(331170, "05243fba853fe375c671a6783eecac28777bca51f5977d5285c235424e52bb69", 0x7c3469310d218),
    c(331458, "f79a664a5e4bc11fa7d804be2c3c72db50c87a27f1f540f337564cbb6314e4cd", 0x7c34d47adf218),
    c(331891, "faceea4b4ab33fc962c24dfa2f98c2aeda4788f67c1e0044c62419912c1a64fe", 0x7c359086aeb58),
    c(332100, "d32c409058c1eceb9a105190c7a5f480b2d6f49f318b18652b49ae971c710124", 0x7c538441cca36),
    c(334000, "17d3b15f8e1a73e1c61335ee7979e9e3d211b9055e8a7fb2481e5f49a51b1c22", 0x7ddd5a79d69c4),
    c(348500, "2d43a157f369e2aa26a329b56456142ecd1361f5808c688d97112a2e3bbd23f4", 0x90889ed877ada),
    c(489400, "b14f49eae77398117ea93435676100d8b655a804689f73a5a4d0d5e71160d603", 0x1123c39bb52f7e),
    c(491200, "cedba73ad35ce7f51aaca2beb36dc32d79ecc716d146eb8211e6a815f3666c4a", 0x11334734abbd17),
    c(497100, "2c4c70ac1ada94151f19d67ccf1aa4e846e6067f49f67c85cc03f78e768ea42b", 0x116906bc97a751),
    c(760300, "50ce41518bb4bea392194c13d0a5ef4cbf01ffb84ba393131e910adb63e2d360", 0x18ef58d8abb8b3),
    c(771100, "03e834788e1e33dbba9bc3431a81189cd655f9da80323a728fa0dae56a95145e", 0x192cdb615ada62),
    c(838800, "85ee72059e12e10a574628cac6f8ebcf8cf6cc1624a274c4ead39ede548777cd", 0x19f2d01d49339c),
];

/// Testnet and stagenet have no hard-coded checkpoints.
pub const TESTNET_CHECKPOINTS: &[Checkpoint] = &[];
pub const STAGENET_CHECKPOINTS: &[Checkpoint] = &[];

/// `HASH_OF_HASHES_STEP` — the fast-sync hash file's group size
/// (`specs/01` §14.1).
pub const HASH_OF_HASHES_STEP: u64 = 512;

/// The checkpoints for a network.
///
/// `FAKECHAIN` bypasses checkpoints entirely (`specs/01` §2), so it gets none —
/// note this differs from the hard-fork table, which it *does* share with
/// mainnet.
pub fn table(network: Network) -> &'static [Checkpoint] {
    match network {
        Network::Mainnet => MAINNET_CHECKPOINTS,
        Network::Testnet => TESTNET_CHECKPOINTS,
        Network::Stagenet => STAGENET_CHECKPOINTS,
        Network::Fakechain => &[],
    }
}

/// The checkpoint table for one network.
#[derive(Clone, Copy, Debug)]
pub struct Checkpoints {
    points: &'static [Checkpoint],
}

impl Checkpoints {
    pub fn new(network: Network) -> Checkpoints {
        Checkpoints {
            points: table(network),
        }
    }

    pub fn all(&self) -> &'static [Checkpoint] {
        self.points
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// The checkpoint at exactly `height`, if there is one.
    pub fn at(&self, height: u64) -> Option<&'static Checkpoint> {
        self.points.iter().find(|c| c.height == height)
    }

    pub fn is_checkpointed(&self, height: u64) -> bool {
        self.at(height).is_some()
    }

    /// `check_block(height, hash)`: a checkpointed height must match exactly;
    /// an unchecked height always passes.
    pub fn check_block(&self, height: u64, hash: &Hash256) -> bool {
        match self.at(height) {
            Some(c) => &c.hash == hash,
            None => true,
        }
    }

    /// The highest checkpointed height. A reorg below this is refused
    /// (`specs/06` §7).
    pub fn last_height(&self) -> Option<u64> {
        self.points.last().map(|c| c.height)
    }

    /// `is_alternative_block_allowed(blockchain_height, block_height)`.
    ///
    /// An alt block at or below the last checkpoint can never be accepted.
    pub fn is_alternative_block_allowed(&self, _chain_height: u64, block_height: u64) -> bool {
        match self.last_height() {
            Some(last) => block_height > last,
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `specs/01` §15: "The checkpoint table has 39 entries and is copied
    /// verbatim from the C++ source."
    #[test]
    fn there_are_exactly_39_checkpoints() {
        assert_eq!(
            MAINNET_CHECKPOINTS.len(),
            39,
            "a fork added or removed a checkpoint upstream"
        );
        assert!(TESTNET_CHECKPOINTS.is_empty());
        assert!(STAGENET_CHECKPOINTS.is_empty());
    }

    #[test]
    fn checkpoints_are_strictly_ascending() {
        for w in MAINNET_CHECKPOINTS.windows(2) {
            assert!(
                w[1].height > w[0].height,
                "heights out of order at {}",
                w[0].height
            );
            assert!(
                w[1].cumulative_difficulty > w[0].cumulative_difficulty,
                "cumulative difficulty must increase, at height {}",
                w[0].height
            );
        }
    }

    /// Spot-check the ends and a few documented rows against `specs/01` §14.
    #[test]
    fn known_rows() {
        let first = MAINNET_CHECKPOINTS[0];
        assert_eq!(first.height, 1);
        assert_eq!(
            wow_crypto::hex::encode(&first.hash),
            "97f4ce4d7879b3bea54dcec738cd2ebb7952b4e9bb9743262310cd5fec749340"
        );
        assert_eq!(first.cumulative_difficulty, 0x2);

        let last = MAINNET_CHECKPOINTS[38];
        assert_eq!(last.height, 838_800);
        assert_eq!(
            wow_crypto::hex::encode(&last.hash),
            "85ee72059e12e10a574628cac6f8ebcf8cf6cc1624a274c4ead39ede548777cd"
        );
        assert_eq!(last.cumulative_difficulty, 0x19f2d01d49339c);

        // The hard-fork boundaries that are also checkpointed.
        let cp = Checkpoints::new(Network::Mainnet);
        for h in [6969u64, 53666, 63469, 81769, 82069, 114969, 115257, 160777] {
            assert!(cp.is_checkpointed(h), "height {h} should be checkpointed");
        }
        // The six hard-coded-difficulty heights of `specs/07` §4.
        for h in [307_686u64, 307_692, 307_735, 307_742, 307_750, 307_766] {
            assert!(cp.is_checkpointed(h), "height {h} should be checkpointed");
        }
        // 331,891 is commented "restart DIFFICULTY_WINDOW" and bounds the
        // HF 18 reset window [331170, 331890].
        assert!(cp.is_checkpointed(331_891));
    }

    #[test]
    fn check_block_enforces_only_checkpointed_heights() {
        let cp = Checkpoints::new(Network::Mainnet);
        let first = MAINNET_CHECKPOINTS[0];

        assert!(cp.check_block(1, &first.hash));
        assert!(
            !cp.check_block(1, &[0u8; 32]),
            "a wrong hash must be rejected"
        );
        // An unchecked height accepts anything.
        assert!(cp.check_block(2, &[0u8; 32]));
        assert!(cp.check_block(u64::MAX, &[0xff; 32]));
    }

    /// `specs/06` §8: an alt block at or below the last checkpoint is refused,
    /// which is what bounds reorg depth.
    #[test]
    fn alt_blocks_below_the_last_checkpoint_are_refused() {
        let cp = Checkpoints::new(Network::Mainnet);
        assert_eq!(cp.last_height(), Some(838_800));
        assert!(!cp.is_alternative_block_allowed(900_000, 838_800));
        assert!(!cp.is_alternative_block_allowed(900_000, 100_000));
        assert!(cp.is_alternative_block_allowed(900_000, 838_801));

        // With no checkpoints -- testnet, stagenet, regtest -- anything goes.
        for n in [Network::Testnet, Network::Stagenet, Network::Fakechain] {
            let cp = Checkpoints::new(n);
            assert!(cp.is_empty());
            assert_eq!(cp.last_height(), None);
            assert!(cp.is_alternative_block_allowed(100, 1));
            assert!(cp.check_block(1, &[0u8; 32]));
        }
    }

    /// `specs/01` §2: regtest bypasses checkpoints, unlike the hard-fork table
    /// which it shares with mainnet.
    #[test]
    fn fakechain_has_no_checkpoints_but_mainnets_forks() {
        assert!(Checkpoints::new(Network::Fakechain).is_empty());
        assert_eq!(
            crate::hardfork::table(Network::Fakechain),
            crate::hardfork::MAINNET_HARD_FORKS
        );
    }

    #[test]
    fn compile_time_hex_matches_runtime_hex() {
        for c in MAINNET_CHECKPOINTS {
            let s = wow_crypto::hex::encode(&c.hash);
            assert_eq!(wow_crypto::hex::decode_array::<32>(&s), Some(c.hash));
        }
    }
}
