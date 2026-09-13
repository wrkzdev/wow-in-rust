//! RandomWOW hashes computed by the C++ library this crate replaced.
//!
//! Taken from the pinned RandomWOW build, in light mode, before it was removed
//! (`third_party/randomwow` at `27b099b6`). The Rust implementation matched
//! every one of them bit for bit; these keep it matching. `mainnet_pow.rs`
//! checks the same code against real blocks' difficulty.

use std::sync::Arc;

use wow_randomwow::vm::{flags, verify_flags, Cache, Vm};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `(seed byte repeated 32 times, input, hash)`.
const VECTORS: [(u8, &str, &str); 9] = [
    (0x00, "", "1c23821235fcf12c2d4fb25ccd63c15b8cc7c683e658f55660b7072a56121d17"),
    (
        0x00,
        "776f776e65726f2072616e646f6d776f772072656772657373696f6e20766563746f72",
        "dec38fb579bbe763e9179f163331039416f367365f686c23d6fb826972da0fef",
    ),
    (
        0x00,
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "5fa7611d4271a3aef750faff15a9da614f3ec7c9070c7f7d7b273cc5d86e27e1",
    ),
    (0x11, "", "9b44fad19df6d7931ea06cf0d1781921b23d24e065e4ca124cb2c9936bc5e614"),
    (
        0x11,
        "776f776e65726f2072616e646f6d776f772072656772657373696f6e20766563746f72",
        "4abdb523ef41e55ea0d9e7aa416453fcdeb03ea873d6bc8c3f90125ed93d27c5",
    ),
    (
        0x11,
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "fa68e7149a04bd40456bcc9ffa022742cb0680671bea3e47a7d9f2a630a529d0",
    ),
    (0xab, "", "0abe263d4c6684437ec53711355f62615ff33cfadc3235ae9c04c33e63427eab"),
    (
        0xab,
        "776f776e65726f2072616e646f6d776f772072656772657373696f6e20766563746f72",
        "6bf265e7dba4b116f01d4b551fad62257d9ea9d36502ae11fd20b3c94b4db576",
    ),
    (
        0xab,
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "c3d924f03b7c524d364d8424dcc31926c95c656e8d5e452f40e40c4221cb576b",
    ),
];

#[test]
fn hashes_match_the_cpp_library() {
    for seed_byte in [0x00u8, 0x11, 0xab] {
        let cache = Arc::new(Cache::new(verify_flags(), &[seed_byte; 32]).expect("cache"));
        let mut vm = Vm::light(verify_flags(), cache.clone()).expect("vm");
        // The portable AES rounds too, on the first input of each seed.
        let mut soft = Vm::light(flags::DEFAULT, cache).expect("vm");
        for (i, (_, input, want)) in VECTORS.iter().filter(|v| v.0 == seed_byte).enumerate() {
            let input = unhex(input);
            assert_eq!(hex(&vm.hash(&input)), *want, "seed {seed_byte:02x}");
            if i == 0 {
                assert_eq!(hex(&soft.hash(&input)), *want, "portable AES");
            }
        }
    }
}
