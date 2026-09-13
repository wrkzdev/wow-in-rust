# Difficulty windows

Ten real mainnet windows, one or more per algorithm era, covering all six
algorithms of `specs/07-difficulty.md`.

```
name  height  tip_version  expected_difficulty  timestamps_csv  cumulative_difficulties_csv
```

Each row is exactly what `get_difficulty_for_next_block` assembles at `height`:
`difficulty_blocks_count(tip_version)` headers ending at `height - 1`
(`specs/07` §1). `expected_difficulty` is what the chain actually recorded, from
`get_block_header_by_height(height).difficulty`.

| Row | Algorithm | What it pins |
|---|---|---|
| `v1_hf7` | v1 | the 735-collect / 720-window lag truncation, sorting only timestamps |
| `v2_hf8` | v2 | **floating point**, `boost::math::round`, the integer `k` |
| `v3_hf9` | v3 | `max(lo, min(x, hi))` where the low bound can exceed the high one |
| `v4_hf10` | v4 | timestamp monotonisation, digit zeroing, the trailing `min(999, …)` |
| `v5_hf11` / `v5_hf15` / `v5_hf17` | v5 | the `ts[0] - target` seed and the height-307,800 branch switch |
| `v1_hf19` | v1 | versions 18–19 falling back to v1 with a 735-block collection |
| `v6_hf20` / `v6_tip` | v6 | the 144-window / 12-cut and the 3-block lag |

Regenerate with:

```sh
python scripts/fetch-difficulty.py --daemon 127.0.0.1:34568
```

Driven by `crates/wow-consensus/tests/mainnet_difficulty.rs`.
