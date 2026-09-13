# Test corpus

Per `specs/15-testing-and-conformance.md` §7.

```
crypto/tests.txt        5,545 primitive vectors, ported from the reference tree
blocks/                 block blobs
blocks/mainnet/         the ~10k-block M1 corpus (generated; not committed)
txs/                    transaction blobs
foreign/                blobs from OTHER chains that MUST NOT parse as Wownero
```

## Provenance, and why it matters

`blocks/BLOCK1`, `blocks/BLOCK2`, `txs/TX1` and `txs/TX2` come from the
reference tree's `tests/data/fuzz/` seed inputs. Those seeds were inherited from
Monero upstream: `BLOCK1` and `BLOCK2` carry `major_version = 1`, which Wownero
has never had (its first hard fork is version 7). They are structurally valid
and exercise the parser, but they are **not Wownero chain data** and prove
nothing about consensus.

`foreign/bpp_tx_e89415.bin` is a **Monero** mainnet transaction (height
2,777,777, txid `e89415b9…`), inherited as `tests/data/txs/` in the Wownero
tree. It must **fail** to parse as Wownero, because the two chains number their
RingCT types differently:

| Type | Monero | Wownero |
|---|---|---|
| `Bulletproof` | 3 | 5 |
| `Bulletproof2` | 4 | 6 |
| `CLSAG` | 5 | 7 |
| `BulletproofPlus` | **6** | **8** |

Wownero inserted `FullBulletproof = 3` and `SimpleBulletproof = 4`, shifting
everything after it. So this transaction's type byte `0x06` means
`BulletproofPlus` on Monero and `Bulletproof2` on Wownero, and the two layouts
disagree. `crates/wow-types/tests/roundtrip.rs` asserts the rejection.

## The mainnet corpus

`blocks/mainnet/` holds the real M1 gate and is **not committed** — it is a few
hundred MB. Generate it against a synced daemon:

```sh
python scripts/fetch-corpus.py --daemon 127.0.0.1:34568
```

`crates/wow-types/tests/roundtrip.rs::mainnet_block_corpus` skips with an
explanatory message when it is absent, so a fresh checkout still builds and the
rest of the suite still runs.

## The weight ranges

`weights/` holds the input for the `specs/15` §3.2 weight gate and is **not
committed** either. Each row is one block's `block_weight`, `long_term_weight`,
`major_version` and `reward`, straight from `get_block_headers_range`:

```sh
python scripts/fetch-weights.py --daemon 127.0.0.1:34568 --preset genesis
python scripts/fetch-weights.py --daemon 127.0.0.1:34568 --preset hf20
```

`long_term_weight` is a stored database column that cannot be recomputed from
block weights alone (`specs/06` §3.4), so replaying it against the chain's own
recorded values is the only check available.

The `genesis` preset, `[0, 170_000)`, needs no seed: below HF 13 (114,969) the
stored long-term weight is just the block weight, and below height 100,000 the
median window is the whole chain. It covers the HF 13 switch. The `hf20` preset,
`[414_000, 544_000)`, covers the HF 20 switch at 514,000, where the clamp
changes from `[0, 1.4x]` to `[1/1.7x, 1.7x]`; its first 100,000 rows seed the
window that follows.

A third, tiny range settles which hard-fork version the stored weight uses:

```sh
python scripts/fetch-weights.py --daemon 127.0.0.1:34568 --start 513980 --end 514020
```

Forty rows across the HF 20 switch at 514,000 are enough, because the
2021-scaling clamp adds a lower bound of `300_000 * 10 / 17 = 176_470` that is
above any Wownero block — so the stored column jumps at the switch, and the
height it jumps at names the version. The earlier forks cannot show this: their
clamp is an upper bound at 420,000, which no Wownero block reaches.

A fetch in progress leaves a `.tsv.part` file.
`crates/wow-consensus/tests/mainnet_weights.rs` checks every row it finds in one
but will not count it towards coverage, and skips with an explanatory message
when the directory is empty. Ranges too short to seed a 100,000-block median are
treated as probes: used for boundary checks, excluded from the replay.

## The HF 16-17 unlock block ids

`unlock/` holds the input for the `specs/15` §3.2 coinbase-unlock gate, and is
generated too. For a block at height `h` in HF 16-17 the dynamic unlock rule
reads the id of the block `1337` back, so this captures exactly those ids for
the block-corpus heights in that range:

```sh
python scripts/fetch-corpus.py --daemon 127.0.0.1:34568   # first
python scripts/fetch-unlock.py --daemon 127.0.0.1:34568
```

The coinbase `unlock_time` itself comes from the block blobs already in
`blocks/mainnet/`, so nothing else is needed.
`crates/wow-consensus/tests/mainnet_coinbase_unlock.rs` checks not only that the
reading matches but that a byte-swapped, little-endian or two-whole-bytes
reading would **not** — `specs/15` §3.2 calls the byte-swap "the rule most
likely to be implemented [wrongly]", so ruling it out is the point.

A fetch in progress leaves a `.tsv.part` file, and the test relaxes its coverage
assertions while one is present.
