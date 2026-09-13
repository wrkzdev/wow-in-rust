//! The M1 gate for `wow-crypto`: all 5,545 vectors from the reference tree's
//! `tests/crypto/tests.txt`.
//!
//! `specs/15-testing-and-conformance.md` §2.1 — "Making that file pass is the
//! cheapest possible validation of `wow-crypto`."
//!
//! The file format is what `tests/crypto/main.cpp` parses: a command name
//! followed by whitespace-separated hex fields, with `x` meaning the empty byte
//! string. Booleans are the literals `true` / `false`.
//!
//! Four commands draw from the reference's deterministic PRNG. Because the
//! vectors were generated in file order from a single stream, the PRNG must be
//! advanced for every such vector as it is encountered — skipping one desyncs
//! every later one. `crypto::random::Rng::deterministic_test_seed` reproduces
//! the seeding from `tests/crypto/random.c`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use wow_crypto::hex;
use wow_crypto::ops;
use wow_crypto::random::Rng;
use wow_crypto::signature;
use wow_crypto::types::{
    EcPoint, Hash256, KeyDerivation, KeyImage, PublicKey, SecretKey, Signature, ViewTag,
};

fn corpus_path() -> PathBuf {
    // crates/wow-crypto/tests/ -> repository root
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/crypto/tests.txt")
}

/// One vector: the command and its whitespace-separated fields.
struct Fields<'a> {
    items: Vec<&'a str>,
    at: usize,
}

impl<'a> Fields<'a> {
    fn next_str(&mut self) -> Result<&'a str, String> {
        let v = self
            .items
            .get(self.at)
            .copied()
            .ok_or_else(|| "ran out of fields".to_string())?;
        self.at += 1;
        Ok(v)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let s = self.next_str()?;
        // `get(input, vector<char>&)`: "x" denotes the empty buffer.
        if s == "x" {
            return Ok(Vec::new());
        }
        hex::decode(s).ok_or_else(|| format!("bad hex {s:?}"))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let s = self.next_str()?;
        hex::decode_array::<N>(s).ok_or_else(|| format!("bad {N}-byte hex {s:?}"))
    }

    fn bool(&mut self) -> Result<bool, String> {
        match self.next_str()? {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(format!("bad bool {other:?}")),
        }
    }

    fn usize(&mut self) -> Result<usize, String> {
        let s = self.next_str()?;
        s.parse().map_err(|_| format!("bad integer {s:?}"))
    }

    fn signature(&mut self) -> Result<Signature, String> {
        Ok(Signature::from_bytes(&self.array::<64>()?))
    }

    /// A run of `n` signatures written back to back as one hex string, which is
    /// what `getvar(input, n * sizeof(signature), ...)` reads.
    fn signatures(&mut self, n: usize) -> Result<Vec<Signature>, String> {
        let s = self.next_str()?;
        let raw = hex::decode(s).ok_or_else(|| format!("bad hex {s:?}"))?;
        if raw.len() != n * 64 {
            return Err(format!(
                "expected {} bytes of signatures, got {}",
                n * 64,
                raw.len()
            ));
        }
        Ok(raw
            .as_chunks::<64>()
            .0
            .iter()
            .map(Signature::from_bytes)
            .collect())
    }

    fn done(&self) -> bool {
        self.at == self.items.len()
    }
}

/// Run one vector. `Ok(true)` means it passed, `Ok(false)` that the result
/// disagreed with the expectation, `Err` that the line could not be parsed.
///
/// `rng` is threaded through so the PRNG-consuming commands stay in step.
fn run(cmd: &str, f: &mut Fields<'_>, rng: &mut Rng) -> Result<bool, String> {
    Ok(match cmd {
        "check_scalar" => {
            let scalar = f.array::<32>()?;
            let expected = f.bool()?;
            ops::sc_check(&scalar) == expected
        }

        "random_scalar" => {
            let expected = f.array::<32>()?;
            rng.random_scalar() == expected
        }

        "hash_to_scalar" => {
            let data = f.bytes()?;
            let expected = f.array::<32>()?;
            ops::hash_to_scalar(&data).0 == expected
        }

        "generate_keys" => {
            let exp_pub = f.array::<32>()?;
            let exp_sec = f.array::<32>()?;
            let (p, s) = rng.generate_keys();
            p.0 == exp_pub && s.0 == exp_sec
        }

        "check_key" => {
            let key = PublicKey(f.array::<32>()?);
            let expected = f.bool()?;
            ops::check_key(&key) == expected
        }

        "secret_key_to_public_key" => {
            let sec = SecretKey(f.array::<32>()?);
            let expected_ok = f.bool()?;
            let got = ops::secret_key_to_public_key(&sec);
            match (expected_ok, got) {
                (false, None) => true,
                (true, Some(p)) => p.0 == f.array::<32>()?,
                _ => false,
            }
        }

        "generate_key_derivation" => {
            let key1 = PublicKey(f.array::<32>()?);
            let key2 = SecretKey(f.array::<32>()?);
            let expected_ok = f.bool()?;
            let got = wow_crypto::keys::generate_key_derivation(&key1, &key2);
            match (expected_ok, got) {
                (false, None) => true,
                (true, Some(d)) => d.0 == f.array::<32>()?,
                _ => false,
            }
        }

        "derive_public_key" => {
            let d = KeyDerivation(f.array::<32>()?);
            let index = f.usize()? as u64;
            let base = PublicKey(f.array::<32>()?);
            let expected_ok = f.bool()?;
            let got = wow_crypto::keys::derive_public_key(&d, index, &base);
            match (expected_ok, got) {
                (false, None) => true,
                (true, Some(p)) => p.0 == f.array::<32>()?,
                _ => false,
            }
        }

        "derive_secret_key" => {
            let d = KeyDerivation(f.array::<32>()?);
            let index = f.usize()? as u64;
            let base = SecretKey(f.array::<32>()?);
            let expected = f.array::<32>()?;
            wow_crypto::keys::derive_secret_key(&d, index, &base).0 == expected
        }

        "generate_signature" => {
            let prefix: Hash256 = f.array::<32>()?;
            let p = PublicKey(f.array::<32>()?);
            let s = SecretKey(f.array::<32>()?);
            let expected = f.signature()?;
            match signature::generate_signature(rng, &prefix, &p, &s) {
                Some(sig) => sig == expected,
                None => false,
            }
        }

        "check_signature" => {
            let prefix: Hash256 = f.array::<32>()?;
            let p = PublicKey(f.array::<32>()?);
            let sig = f.signature()?;
            let expected = f.bool()?;
            signature::check_signature(&prefix, &p, &sig) == expected
        }

        "hash_to_point" => {
            let h: Hash256 = f.array::<32>()?;
            let expected = f.array::<32>()?;
            ops::hash_to_point(&h) == EcPoint(expected)
        }

        "hash_to_ec" => {
            let key = f.array::<32>()?;
            let expected = f.array::<32>()?;
            ops::hash_to_ec(&key) == Some(EcPoint(expected))
        }

        "generate_key_image" => {
            let p = PublicKey(f.array::<32>()?);
            let s = SecretKey(f.array::<32>()?);
            let expected = f.array::<32>()?;
            ops::generate_key_image(&p, &s) == Some(KeyImage(expected))
        }

        "generate_ring_signature" => {
            let prefix: Hash256 = f.array::<32>()?;
            let image = KeyImage(f.array::<32>()?);
            let n = f.usize()?;
            let mut pubs = Vec::with_capacity(n);
            for _ in 0..n {
                pubs.push(PublicKey(f.array::<32>()?));
            }
            let sec = SecretKey(f.array::<32>()?);
            let sec_index = f.usize()?;
            let expected = f.signatures(n)?;
            match signature::generate_ring_signature(rng, &prefix, &image, &pubs, &sec, sec_index) {
                Some(sigs) => sigs == expected,
                None => false,
            }
        }

        "check_ring_signature" => {
            let prefix: Hash256 = f.array::<32>()?;
            let image = KeyImage(f.array::<32>()?);
            let n = f.usize()?;
            let mut pubs = Vec::with_capacity(n);
            for _ in 0..n {
                pubs.push(PublicKey(f.array::<32>()?));
            }
            let sigs = f.signatures(n)?;
            let expected = f.bool()?;
            signature::check_ring_signature(&prefix, &image, &pubs, &sigs) == expected
        }

        "derive_view_tag" => {
            let d = KeyDerivation(f.array::<32>()?);
            let index = f.usize()? as u64;
            let expected = f.array::<1>()?;
            wow_crypto::keys::derive_view_tag(&d, index) == ViewTag(expected[0])
        }

        // `check_ge_p3_identity` compares a deliberately buggy limb-wise
        // identity test against the fixed one. Both operate on the C's 10-limb
        // `ge_p3` representation, which this implementation does not have and
        // which no consensus rule depends on -- only the fixed function is used
        // (`ge_p3_is_point_at_infinity_vartime`). Counted as skipped rather
        // than silently passed.
        "check_ge_p3_identity" => return Err("__skip__".to_string()),

        other => return Err(format!("unknown command {other:?}")),
    })
}

#[test]
fn reference_crypto_vectors() {
    let path = corpus_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    let mut rng = Rng::deterministic_test_seed();
    let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new(); // (run, failed)
    let mut skipped: BTreeMap<&str, usize> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();
    let mut total = 0usize;

    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        total += 1;
        let items: Vec<&str> = line.split_whitespace().collect();
        let cmd = items[0];
        let mut f = Fields { items, at: 1 };

        match run(cmd, &mut f, &mut rng) {
            Ok(ok) => {
                let e = counts.entry(cmd).or_insert((0, 0));
                e.0 += 1;
                if !ok {
                    e.1 += 1;
                    if failures.len() < 20 {
                        failures.push(format!("line {}: {cmd} FAILED", lineno + 1));
                    }
                } else if !f.done() {
                    // A passing result that did not consume the whole line
                    // means the parser and the file disagree about the shape.
                    e.1 += 1;
                    if failures.len() < 20 {
                        failures.push(format!(
                            "line {}: {cmd} left {} unread fields",
                            lineno + 1,
                            f.items.len() - f.at
                        ));
                    }
                }
            }
            Err(e) if e == "__skip__" => {
                *skipped.entry(cmd).or_insert(0) += 1;
            }
            Err(e) => {
                let c = counts.entry(cmd).or_insert((0, 0));
                c.0 += 1;
                c.1 += 1;
                if failures.len() < 20 {
                    failures.push(format!("line {}: {cmd}: {e}", lineno + 1));
                }
            }
        }
    }

    let mut report = String::new();
    let _ = writeln!(report, "\n{total} vectors in {}", path.display());
    let mut failed_total = 0;
    for (cmd, (run, failed)) in &counts {
        failed_total += failed;
        let _ = writeln!(
            report,
            "  {cmd:<26} {run:>5} run  {failed:>5} failed{}",
            if *failed == 0 { "" } else { "   <-- " }
        );
    }
    for (cmd, n) in &skipped {
        let _ = writeln!(
            report,
            "  {cmd:<26} {n:>5} skipped (C-representation-specific)"
        );
    }
    println!("{report}");

    assert!(
        failed_total == 0,
        "{failed_total} reference vectors failed:\n{}\n{report}",
        failures.join("\n")
    );

    // Guard the corpus itself: if the file is ever truncated or replaced, the
    // gate must fail loudly rather than pass vacuously.
    assert_eq!(total, 5545, "the vendored corpus should hold 5,545 vectors");
    let ran: usize = counts.values().map(|(r, _)| r).sum();
    let skip: usize = skipped.values().sum();
    assert_eq!(ran + skip, total);
    assert_eq!(
        skip, 6,
        "only the 6 check_ge_p3_identity vectors are skipped"
    );
}
