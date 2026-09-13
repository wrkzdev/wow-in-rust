//! The Cache and the Dataset items computed from it (`dataset.cpp`; RandomX
//! spec §7).

use crate::argon2::{self, BLOCK_WORDS};
use crate::blake2b::Blake2Generator;
use crate::jit::Compiled;
use crate::params::Config;
use crate::superscalar::{self, Program};

/// `superscalarMul0` and `superscalarAdd1..7`.
const MUL0: u64 = 6364136223846793005;
const ADDS: [u64; 7] = [
    9298411001130361340,
    12065312585734608966,
    9306329213124626780,
    5281919268842080866,
    10536153434571861004,
    3398623926847679864,
    9549104520008361294,
];

/// An initialised Cache: the Argon2d memory and the SuperscalarHash programs.
pub(crate) struct CacheData {
    pub(crate) config: &'static Config,
    /// `argon_memory` blocks of 128 words; item `i` of the Cache is words
    /// `8 * i .. 8 * i + 8`.
    memory: Vec<u64>,
    programs: Vec<Program>,
    /// The same programs as machine code, where they could be compiled.
    jit: Option<Compiled>,
    item_mask: u64,
}

impl CacheData {
    /// `initCache`, compiling the SuperscalarHash programs when `jit` asks and
    /// the target allows. `None` when the memory cannot be allocated.
    pub(crate) fn new(config: &'static Config, key: &[u8], jit: bool) -> Option<CacheData> {
        let words = config.argon_memory as usize * BLOCK_WORDS;
        let mut memory = Vec::new();
        memory.try_reserve_exact(words).ok()?;
        memory.resize(words, 0);
        argon2::fill(&mut memory, key, config);

        let mut gen = Blake2Generator::new(key, 0);
        let programs: Vec<Program> = (0..config.cache_accesses)
            .map(|_| superscalar::generate(&mut gen, config.superscalar_latency))
            .collect();
        let jit = if jit { Compiled::new(&programs) } else { None };
        Some(CacheData {
            config,
            memory,
            programs,
            jit,
            item_mask: u64::from(config.argon_memory) * 1024 / 64 - 1,
        })
    }

    #[cfg(test)]
    pub(crate) fn word(&self, i: usize) -> u64 {
        self.memory[i]
    }

    /// `initDatasetItem`: Dataset item `number`, as eight words.
    pub(crate) fn item(&self, number: u64) -> [u64; 8] {
        let r0 = number.wrapping_add(1).wrapping_mul(MUL0);
        let mut r = [r0, 0, 0, 0, 0, 0, 0, 0];
        for (reg, add) in r[1..].iter_mut().zip(ADDS) {
            *reg = r0 ^ add;
        }
        let mut register_value = number;
        for (i, program) in self.programs.iter().enumerate() {
            let mix = (register_value & self.item_mask) as usize * 8;
            match &self.jit {
                Some(code) => code.execute(i, &mut r),
                None => superscalar::execute(&mut r, program),
            }
            for (reg, word) in r.iter_mut().zip(&self.memory[mix..mix + 8]) {
                *reg ^= word;
            }
            register_value = r[program.address_register];
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::RANDOMX;
    use std::sync::OnceLock;

    fn upstream() -> &'static CacheData {
        static CACHE: OnceLock<CacheData> = OnceLock::new();
        CACHE.get_or_init(|| CacheData::new(&RANDOMX, b"test key 000", true).expect("256 MiB"))
    }

    /// `tests.cpp`, "Cache initialization", with upstream's parameters.
    #[test]
    fn the_cache_matches_the_reference() {
        let c = upstream();
        assert_eq!(c.word(0), 0x191e0e1d23c02186);
        assert_eq!(c.word(1568413), 0xf1b62fe6210bf8b1);
        assert_eq!(c.word(33554431), 0x1f47f056d05cd99b);
    }

    /// `tests.cpp`, "Dataset initialization (interpreter)".
    #[test]
    fn dataset_items_match_the_reference() {
        let c = upstream();
        assert_eq!(c.item(0)[0], 0x680588a85ae222db);
        assert_eq!(c.item(10_000_000)[0], 0x7943a1f6186ffb72);
        assert_eq!(c.item(20_000_000)[0], 0x9035244d718095e1);
        assert_eq!(c.item(30_000_000)[0], 0x145a5091f7853099);
    }
}
