# `tests.txt`

Ported verbatim from the Wownero C++ reference tree at commit `9f4f22c72`:

    tests/crypto/tests.txt        (5,545 vectors, 8.6 MB)

Driven by `crates/wow-crypto/tests/reference_vectors.rs`. The line format is the
one `tests/crypto/main.cpp` parses: a command name followed by whitespace-separated
hex fields. `x` means the empty byte string. See
`specs/15-testing-and-conformance.md` §2.1.

Four commands (`random_scalar`, `generate_keys`, `generate_signature`,
`generate_ring_signature`) consume the reference tree's deterministic PRNG, which
`tests/crypto/random.c` seeds by filling the 200-byte Keccak state with the byte
`0x2a` ("42"). `wow_crypto::random::TestRng` reproduces it, so those vectors are
checked too rather than skipped — the vectors are ordered, so the PRNG must be
advanced for *every* vector that draws from it, in file order.
