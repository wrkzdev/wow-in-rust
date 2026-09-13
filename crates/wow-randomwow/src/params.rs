//! RandomX parameters.
//!
//! RandomWOW is RandomX with Wownero's parameters (`specs/03-pow.md` §3.1).
//! The implementation takes them as a [`Config`] rather than as constants so
//! the same code also runs upstream RandomX's parameters, which the RandomX
//! test vectors (`src/tests/tests.cpp`) were computed with. Upstream's vectors
//! check the algorithm; Wownero's own blocks check the parameters.

/// How many instruction types a frequency table covers.
pub const INSTRUCTION_COUNT: usize = 30;

/// One parameter set: `configuration.h`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Argon2 blocks of 1 KiB in the Cache.
    pub argon_memory: u32,
    pub argon_iterations: u32,
    pub argon_lanes: u32,
    pub argon_salt: &'static [u8],
    /// Cache reads, and SuperscalarHash programs, per Dataset item.
    pub cache_accesses: u32,
    pub superscalar_latency: u32,
    pub dataset_base_size: u64,
    pub dataset_extra_size: u64,
    pub program_size: u32,
    pub program_iterations: u32,
    pub program_count: u32,
    pub scratchpad_l3: u32,
    pub scratchpad_l2: u32,
    pub scratchpad_l1: u32,
    pub jump_bits: u32,
    pub jump_offset: u32,
    /// `AesGenerator4R`'s round keys, each as four little-endian words: four
    /// for lanes 0 and 1, then four for lanes 2 and 3. The one change RandomWOW
    /// makes outside `configuration.h` is here -- its own keys 0-3, run on all
    /// four lanes, where upstream gives lanes 2 and 3 keys 4-7.
    pub aes_4r_keys: [[u32; 4]; 8],
    /// Out of 256, in the instruction order: IADD_RS, IADD_M, ISUB_R, ISUB_M,
    /// IMUL_R, IMUL_M, IMULH_R, IMULH_M, ISMULH_R, ISMULH_M, IMUL_RCP, INEG_R,
    /// IXOR_R, IXOR_M, IROR_R, IROL_R, ISWAP_R, FSWAP_R, FADD_R, FADD_M,
    /// FSUB_R, FSUB_M, FSCAL_R, FMUL_R, FDIV_M, FSQRT_R, CBRANCH, CFROUND,
    /// ISTORE, NOP.
    pub frequencies: [u32; INSTRUCTION_COUNT],
}

/// RandomWOW, the pinned `configuration.h` (`specs/03` §3.1).
pub const WOWNERO: Config = Config {
    argon_memory: 262_144,
    argon_iterations: 3,
    argon_lanes: 1,
    argon_salt: b"RandomWOW\x01",
    cache_accesses: 8,
    superscalar_latency: 170,
    dataset_base_size: 2_147_483_648,
    dataset_extra_size: 33_554_368,
    program_size: 256,
    program_iterations: 1024,
    program_count: 16,
    scratchpad_l3: 1_048_576,
    scratchpad_l2: 131_072,
    scratchpad_l1: 16_384,
    jump_bits: 8,
    jump_offset: 8,
    aes_4r_keys: crate::aes::GEN4R_KEYS_WOWNERO,
    frequencies: [
        25, 7, 16, 7, 16, 4, 4, 1, 4, 1, 8, 2, 15, 5, 10, 0, 4, 8, 20, 5, 20, 5, 6, 20, 4, 6, 16,
        1, 16, 0,
    ],
};

/// Upstream RandomX's defaults (`doc/configuration.md`), for its test vectors.
pub const RANDOMX: Config = Config {
    argon_memory: 262_144,
    argon_iterations: 3,
    argon_lanes: 1,
    argon_salt: b"RandomX\x03",
    cache_accesses: 8,
    superscalar_latency: 170,
    dataset_base_size: 2_147_483_648,
    dataset_extra_size: 33_554_368,
    program_size: 256,
    program_iterations: 2048,
    program_count: 8,
    scratchpad_l3: 2_097_152,
    scratchpad_l2: 262_144,
    scratchpad_l1: 16_384,
    jump_bits: 8,
    jump_offset: 8,
    aes_4r_keys: crate::aes::GEN4R_KEYS_RANDOMX,
    frequencies: [
        16, 7, 16, 7, 16, 4, 4, 1, 4, 1, 8, 2, 15, 5, 8, 2, 4, 4, 16, 5, 16, 5, 6, 32, 4, 6, 25, 1,
        16, 0,
    ],
};

impl Config {
    /// The constraints `common.hpp` asserts at compile time.
    pub fn check(&self) -> Result<(), String> {
        let pow2 = |x: u64| x != 0 && x & (x - 1) == 0;
        let sum: u32 = self.frequencies.iter().sum();
        let rules: [(bool, &str); 14] = [
            (sum == 256, "the instruction frequencies must sum to 256"),
            (
                self.argon_salt.len() >= 8,
                "the Argon2 salt is shorter than 8 bytes",
            ),
            (
                self.argon_memory >= 8 && pow2(self.argon_memory.into()),
                "the Argon2 memory must be a power of 2 of at least 8",
            ),
            (self.argon_iterations > 0, "Argon2 needs an iteration"),
            (self.argon_lanes > 0, "Argon2 needs a lane"),
            (
                self.cache_accesses > 1,
                "a Dataset item needs two Cache reads",
            ),
            (
                (1..=10_000).contains(&self.superscalar_latency),
                "the superscalar latency is out of range",
            ),
            (
                pow2(self.dataset_base_size) && self.dataset_base_size >= 64,
                "the Dataset base size must be a power of 2 of at least 64",
            ),
            (
                self.dataset_extra_size.is_multiple_of(64),
                "the Dataset extra size must be a multiple of 64",
            ),
            (
                (64..=32_768).contains(&self.program_size),
                "the program size is out of range",
            ),
            (
                self.program_count > 1 && self.program_iterations > 0,
                "a hash needs two programs and an iteration",
            ),
            (
                pow2(self.scratchpad_l3.into())
                    && pow2(self.scratchpad_l2.into())
                    && pow2(self.scratchpad_l1.into()),
                "the scratchpad levels must be powers of 2",
            ),
            (
                self.scratchpad_l3 >= self.scratchpad_l2
                    && self.scratchpad_l2 >= self.scratchpad_l1
                    && self.scratchpad_l1 >= 64,
                "the scratchpad levels must shrink from L3 to L1, down to 64",
            ),
            (
                self.jump_bits > 0 && self.jump_bits + self.jump_offset <= 16,
                "the jump condition does not fit in 16 bits",
            ),
        ];
        match rules.iter().find(|(ok, _)| !ok) {
            Some((_, why)) => Err((*why).to_string()),
            None => Ok(()),
        }
    }

    /// Items in the full Dataset.
    pub(crate) fn dataset_items(&self) -> u64 {
        (self.dataset_base_size + self.dataset_extra_size) / 64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_parameter_sets_are_valid() {
        WOWNERO.check().unwrap();
        RANDOMX.check().unwrap();
        let mut bad = WOWNERO.clone();
        bad.frequencies[0] += 1;
        assert!(bad.check().unwrap_err().contains("256"));
    }

    /// `specs/03` §3.1: the parameters that differ from upstream. Upstream's
    /// on a Wownero chain gives hashes that fail every difficulty check.
    #[test]
    fn wownero_differs_from_upstream_where_the_spec_says() {
        assert_eq!(WOWNERO.argon_salt, b"RandomWOW\x01");
        assert_eq!(
            (
                WOWNERO.program_iterations,
                WOWNERO.program_count,
                WOWNERO.scratchpad_l3
            ),
            (1024, 16, 1 << 20)
        );
        assert_eq!(
            (
                RANDOMX.program_iterations,
                RANDOMX.program_count,
                RANDOMX.scratchpad_l3
            ),
            (2048, 8, 1 << 21)
        );
        assert_ne!(WOWNERO.frequencies, RANDOMX.frequencies);
    }
}
