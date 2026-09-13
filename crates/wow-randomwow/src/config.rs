//! The linked library's compile-time configuration, read back through FFI.
//!
//! `specs/15-testing-and-conformance.md` §2.4 asks for these checks by name,
//! because linking against upstream RandomX instead of RandomWOW is "the single
//! most likely build mistake" — and it produces valid-looking hashes that fail
//! every difficulty check on the real chain, which is a confusing way to find
//! out.

use crate::ffi;

/// The configuration the linked library was compiled with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configuration {
    pub argon_salt: Vec<u8>,
    pub argon_memory: u32,
    pub argon_iterations: u32,
    pub argon_lanes: u32,
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
    /// The 30 `RANDOMX_FREQ_*` values, in the order `specs/03` §3.1 lists them.
    pub frequencies: Vec<u32>,
}

/// Read the linked library's configuration.
pub fn linked_configuration() -> Configuration {
    // SAFETY: every call is a nullary getter over a compile-time constant, and
    // `wow_rx_frequencies` writes exactly 32 `u32`s into the buffer provided.
    unsafe {
        let salt_ptr = ffi::wow_rx_argon_salt();
        let salt_len = ffi::wow_rx_argon_salt_len();
        let argon_salt = core::slice::from_raw_parts(salt_ptr as *const u8, salt_len).to_vec();

        let mut freq = [0u32; 32];
        ffi::wow_rx_frequencies(freq.as_mut_ptr());
        let n = ffi::wow_rx_frequency_count();

        Configuration {
            argon_salt,
            argon_memory: ffi::wow_rx_argon_memory(),
            argon_iterations: ffi::wow_rx_argon_iterations(),
            argon_lanes: ffi::wow_rx_argon_lanes(),
            cache_accesses: ffi::wow_rx_cache_accesses(),
            superscalar_latency: ffi::wow_rx_superscalar_latency(),
            dataset_base_size: ffi::wow_rx_dataset_base_size(),
            dataset_extra_size: ffi::wow_rx_dataset_extra_size(),
            program_size: ffi::wow_rx_program_size(),
            program_iterations: ffi::wow_rx_program_iterations(),
            program_count: ffi::wow_rx_program_count(),
            scratchpad_l3: ffi::wow_rx_scratchpad_l3(),
            scratchpad_l2: ffi::wow_rx_scratchpad_l2(),
            scratchpad_l1: ffi::wow_rx_scratchpad_l1(),
            jump_bits: ffi::wow_rx_jump_bits(),
            jump_offset: ffi::wow_rx_jump_offset(),
            frequencies: freq[..n].to_vec(),
        }
    }
}

/// The RandomWOW Argon2d salt. **Differs from upstream RandomX's
/// `"RandomX\x03"`** — this one byte-string is the whole tell.
pub const WOW_ARGON_SALT: &[u8] = b"RandomWOW\x01";

/// The expected configuration, from `specs/03-pow.md` §3.1.
pub fn expected_configuration() -> Configuration {
    Configuration {
        argon_salt: WOW_ARGON_SALT.to_vec(),
        argon_memory: 262_144,
        argon_iterations: 3,
        argon_lanes: 1,
        cache_accesses: 8,
        superscalar_latency: 170,
        dataset_base_size: 2_147_483_648,
        dataset_extra_size: 33_554_368,
        program_size: 256,
        // The three that differ most visibly from upstream RandomX
        // (2048 / 8 / 2 MiB respectively).
        program_iterations: 1024,
        program_count: 16,
        scratchpad_l3: 1_048_576,
        scratchpad_l2: 131_072,
        scratchpad_l1: 16_384,
        jump_bits: 8,
        jump_offset: 8,
        frequencies: vec![
            25, // IADD_RS  (RandomX: 16)
            7,  // IADD_M
            16, // ISUB_R
            7,  // ISUB_M
            16, // IMUL_R
            4,  // IMUL_M
            4,  // IMULH_R
            1,  // IMULH_M
            4,  // ISMULH_R
            1,  // ISMULH_M
            8,  // IMUL_RCP
            2,  // INEG_R
            15, // IXOR_R
            5,  // IXOR_M
            10, // IROR_R   (RandomX: 8)
            0,  // IROL_R   (RandomX: 2)
            4,  // ISWAP_R
            8,  // FSWAP_R  (RandomX: 4)
            20, // FADD_R   (RandomX: 16)
            5,  // FADD_M
            20, // FSUB_R   (RandomX: 16)
            5,  // FSUB_M
            6,  // FSCAL_R
            20, // FMUL_R   (RandomX: 32)
            4,  // FDIV_M
            6,  // FSQRT_R
            16, // CBRANCH  (RandomX: 25)
            1,  // CFROUND
            16, // ISTORE
            0,  // NOP
        ],
    }
}

/// Check the linked library against `specs/03` §3.1, returning a description of
/// the first mismatch.
///
/// Call this at daemon startup: a wrong library is not something to discover
/// from a stream of rejected blocks.
pub fn verify_linked_configuration() -> Result<(), String> {
    let got = linked_configuration();
    let want = expected_configuration();

    if got.argon_salt != want.argon_salt {
        return Err(format!(
            "RANDOMX_ARGON_SALT is {:?}, expected {:?} -- this is upstream RandomX, not RandomWOW",
            String::from_utf8_lossy(&got.argon_salt),
            String::from_utf8_lossy(&want.argon_salt),
        ));
    }

    macro_rules! check {
        ($field:ident) => {
            if got.$field != want.$field {
                return Err(format!(
                    concat!(stringify!($field), " is {}, expected {}"),
                    got.$field, want.$field
                ));
            }
        };
    }
    check!(argon_memory);
    check!(argon_iterations);
    check!(argon_lanes);
    check!(cache_accesses);
    check!(superscalar_latency);
    check!(dataset_base_size);
    check!(dataset_extra_size);
    check!(program_size);
    check!(program_iterations);
    check!(program_count);
    check!(scratchpad_l3);
    check!(scratchpad_l2);
    check!(scratchpad_l1);
    check!(jump_bits);
    check!(jump_offset);

    if got.frequencies != want.frequencies {
        return Err(format!(
            "instruction frequencies differ:\n  linked:   {:?}\n  expected: {:?}",
            got.frequencies, want.frequencies
        ));
    }
    let sum: u32 = got.frequencies.iter().sum();
    if sum != 256 {
        return Err(format!(
            "instruction frequencies sum to {sum}, expected 256"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `specs/15` §2.4: "a unit test that sums the `RANDOMX_FREQ_*` values and
    /// checks for 256". Read through FFI, so it reflects the header the
    /// **library** was compiled with.
    #[test]
    fn frequencies_sum_to_256() {
        let c = linked_configuration();
        assert_eq!(c.frequencies.len(), 30);
        let sum: u32 = c.frequencies.iter().sum();
        assert_eq!(sum, 256, "linked frequencies: {:?}", c.frequencies);
    }

    /// `specs/15` §2.4: "one that asserts `RANDOMX_ARGON_SALT ==
    /// \"RandomWOW\\x01\"` by reading the compiled constant through FFI. This
    /// catches the single most likely build mistake -- linking against upstream
    /// RandomX."
    #[test]
    fn argon_salt_is_wownero() {
        let c = linked_configuration();
        assert_eq!(c.argon_salt, WOW_ARGON_SALT);
        assert_eq!(c.argon_salt.len(), 10);
        assert_eq!(&c.argon_salt[..9], b"RandomWOW");
        assert_eq!(c.argon_salt[9], 0x01);
        // ...and specifically not upstream's.
        assert_ne!(c.argon_salt.as_slice(), b"RandomX\x03");
    }

    /// The whole parameter set, not just the salt. The three that differ most
    /// from upstream are the ones that change the hash the most.
    #[test]
    fn linked_configuration_matches_the_spec() {
        if let Err(e) = verify_linked_configuration() {
            panic!("{e}");
        }
        let c = linked_configuration();
        assert_eq!(c.program_iterations, 1024, "RandomX uses 2048");
        assert_eq!(c.program_count, 16, "RandomX uses 8");
        assert_eq!(c.scratchpad_l3, 1 << 20, "1 MiB; RandomX uses 2 MiB");
    }
}
