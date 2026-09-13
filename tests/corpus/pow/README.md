# RandomWOW proof-of-work vectors

26 real mainnet blocks with their seed hash and their recorded difficulty.

```
height  seed_height  seed_hash  difficulty  major_version  block_blob_hex
```

## Why this shape

`specs/15-testing-and-conformance.md` §2.4 asks for `(seed_hash, hashing_blob)
-> pow_hash` triples taken "from the C++ node via `calc_pow` (or by
instrumenting it)". `calc_pow` is **R** — removed in restricted mode
(`specs/11` §4) — so no public node serves it.

The chain is a better oracle anyway. A block's PoW hash must satisfy
`check_hash(pow, difficulty)` for that block's own difficulty (`specs/03` §4).
The difficulties here run from 1.0e8 to 9.2e9, so a wrong hash passes with
probability under 1e-8; a hash from upstream RandomX, or keyed on the wrong
seed, fails essentially always.

Passing every block validates the seed-height arithmetic, the seed being the
block **id** at that height, the hashing blob (hence the header serialization
and the Merkle root), the linked library's configuration, and the difficulty
check — all at once.

## The heights

Consecutive runs, so each run shares one seed and pays one cache initialisation
(`specs/03` §3.4).

| Run | Why |
|---|---|
| 114,969 – 114,974 | the first RandomWOW blocks; HF 13 activation |
| 202,610 – 202,614 | around the height-202,612 PoW override (`specs/03` §5) |
| 331,170 – 331,174 | HF 18: header signing begins |
| 514,000 – 514,004 | HF 20 |
| 873,000 – 873,004 | near the tip |

Driven by `crates/wow-randomwow/tests/mainnet_pow.rs`.
