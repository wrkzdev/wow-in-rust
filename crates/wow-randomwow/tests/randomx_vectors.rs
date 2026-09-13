//! Upstream RandomX's hash vectors (`src/tests/tests.cpp`), through the same
//! code with upstream's parameters.
//!
//! RandomWOW differs from RandomX only in parameters, so passing these checks
//! the algorithm independently of Wownero's: Argon2d, the AES functions,
//! SuperscalarHash, the VM with every instruction and rounding mode, and the
//! finalisation.

use std::sync::Arc;

use wow_randomwow::params::RANDOMX;
use wow_randomwow::vm::{flags, verify_flags, Cache, Vm};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn vm(key: &[u8], flags: u32) -> Vm {
    let cache = Arc::new(Cache::with_config(&RANDOMX, flags, key).expect("cache"));
    Vm::light(flags, cache).expect("vm")
}

/// Hash tests 1a-1e.
#[test]
fn hashes_match_upstream_randomx() {
    let mut key0 = vm(b"test key 000", verify_flags());
    assert_eq!(
        hex(&key0.hash(b"This is a test")),
        "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"
    );
    assert_eq!(
        hex(&key0.hash(b"Lorem ipsum dolor sit amet")),
        "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969"
    );
    let lorem = b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua";
    assert_eq!(
        hex(&key0.hash(lorem)),
        "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8"
    );

    let mut key1 = vm(b"test key 001", verify_flags());
    assert_eq!(
        hex(&key1.hash(lorem)),
        "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc"
    );
    let blob = unhex(
        "0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d25537f584a9bc9977b\
         00000000666fd8753bf61a8631f12984e3fd44f4014eca629276817b56f32e9b68bd82f416",
    );
    assert_eq!(
        hex(&key1.hash(&blob)),
        "c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1"
    );
}

/// The portable AES rounds give the same hash as AES-NI.
#[test]
fn portable_aes_gives_the_same_hash() {
    let mut soft = vm(b"test key 000", flags::DEFAULT);
    assert_eq!(
        hex(&soft.hash(b"This is a test")),
        "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"
    );
}
