//! The reference tree's own hash vectors.
//!
//! `tests/hash/tests-extra-*.txt` and `tests-slow*.txt`, vendored into
//! `tests/corpus/cryptonight/`. Each line is `<expected> <input-hex>`, with `x`
//! standing for the empty input.
//!
//! These are the vectors the C++ `hash-tests` binary runs, so passing them is
//! the same statement the reference makes about itself.

use std::path::PathBuf;

/// `(expected, input)` pairs from one vector file.
fn vectors(name: &str) -> Vec<([u8; 32], Vec<u8>)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/cryptonight")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut f = l.split_whitespace();
            let expected: [u8; 32] = wow_crypto::hex::decode(f.next().expect("expected"))
                .expect("expected is hex")
                .try_into()
                .expect("expected is 32 bytes");
            // The C++ writes `x` for an empty input.
            let input = match f.next() {
                Some("x") | None => Vec::new(),
                Some(h) => wow_crypto::hex::decode(h).expect("input is hex"),
            };
            (expected, input)
        })
        .collect()
}

fn run(name: &str, f: impl Fn(&[u8]) -> [u8; 32]) {
    // The four `tests-extra-*` files carry the full NIST-style sweep.
    run_at_least(name, 100, f);
}

/// `tests-slow*.txt` are short by design — CryptoNight costs 2 MiB and a
/// million AES rounds per vector, so the reference tree only ships a handful.
fn run_small(name: &str, f: impl Fn(&[u8]) -> [u8; 32]) {
    run_at_least(name, 4, f);
}

fn run_at_least(name: &str, least: usize, f: impl Fn(&[u8]) -> [u8; 32]) {
    let vs = vectors(name);
    assert!(vs.len() >= least, "{name}: only {} vectors", vs.len());

    let mut failures = Vec::new();
    for (i, (expected, input)) in vs.iter().enumerate() {
        let got = f(input);
        if &got != expected && failures.len() < 5 {
            failures.push(format!(
                "  line {}: {} bytes in\n    want {}\n    got  {}",
                i + 1,
                input.len(),
                wow_crypto::hex::encode(expected),
                wow_crypto::hex::encode(&got)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{name}: {} of {} vectors failed:\n{}",
        vs.len() - vs.iter().filter(|(e, i)| &f(i) == e).count(),
        vs.len(),
        failures.join("\n")
    );
    eprintln!("{name}: {} vectors, all matching", vs.len());
}

#[test]
fn blake256_matches_the_reference_vectors() {
    run("tests-extra-blake.txt", wow_crypto::cn::blake256);
}

#[test]
fn groestl256_matches_the_reference_vectors() {
    run("tests-extra-groestl.txt", wow_crypto::cn::groestl256);
}

#[test]
fn jh256_matches_the_reference_vectors() {
    run("tests-extra-jh.txt", wow_crypto::cn::jh256);
}

#[test]
fn skein256_matches_the_reference_vectors() {
    run("tests-extra-skein.txt", wow_crypto::cn::skein256);
}

#[test]
fn cryptonight_v0_matches_the_reference_vectors() {
    run_small("tests-slow.txt", wow_crypto::cn::cn_slow_hash);
}

/// Variant 1 refuses an input under 43 bytes, so the harness has to know that a
/// short vector is not a failure. The reference's own file has none.
#[test]
fn cryptonight_v1_matches_the_reference_vectors() {
    run_small("tests-slow-1.txt", |input| {
        wow_crypto::cn::cn_slow_hash_v1(input).expect("every vector is long enough")
    });
}
