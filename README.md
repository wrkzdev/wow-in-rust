# wownero-rs

A Rust reimplementation of the Wownero suite — daemon, wallet CLI, wallet RPC —
drop-in compatible with the C++ tree at version `0.11.4.0` "Kunty Karen".

> [!WARNING]
> **Unofficial, AI-assisted and experimental. Use it at your own risk.**
>
> * **Not affiliated with Wownero.** This project is not made, endorsed or
>   maintained by the Wownero project or its developers. The official software
>   lives at [codeberg.org/wownero/wownero](https://codeberg.org/wownero/wownero).
>   The Wownero name appears here only to say what this code aims to be
>   compatible with. Please don't take problems with this code to the Wownero
>   developers.
> * **Written largely with AI.** Much of the code, tests and documentation was
>   produced with AI coding tools. It can be wrong in ways that look plausible.
> * **Unaudited, and never used with real funds.** Nothing here has been
>   audited, and the send path has never moved real money — see *Status* below
>   for exactly what has and has not been exercised against the live network.
>   It comes with no warranty. Don't use it with a wallet holding funds you
>   can't afford to lose; for real use, run the official Wownero software.

The normative specification is vendored in [`specs/`](specs/). Start with
[`specs/README.md`](specs/README.md), then
[`specs/00-overview.md`](specs/00-overview.md).

> **The one hard requirement:** the Rust node must join the existing Wownero
> mainnet and reach the same chain tip as the C++ node, byte-for-byte, without a
> fork. Everything else is an implementation choice. Consensus is not.

## Status

| Milestone | Scope | State |
|---|---|---|
| **M1** | Wire parity: crypto primitives, serialization, block/tx types, hashes, RandomWOW | **complete; gate met** |
| **M2** | Verifying sync on mainnet (PoW, difficulty, LMDB store) | **syncs from live C++ peers**; CryptoNight v2/v4 missing |
| **M3** | Serving node (daemon RPC, mempool) | **built**; reorg, propagation and inbound P2P to go |
| **M4** | Wallet (CLI + RPC) | **built and working against public nodes**; sending untested for want of funds |
| M5 | Mining and the long tail | not started |

### Verified against the live network

Against `node2.monerodevs.org:34568` and the mainnet seed nodes, with no local
chain:

* **Wallet** — create, restore from seed (same address reproduced), refresh,
  balance, address, and `transfer` refusing correctly for want of funds. Both
  `wownero-wallet-cli` and `wownero-wallet-rpc`.
* **Ring construction** — the output distribution (2.9 M RingCT outputs) and
  ring members fetched and well formed. This is what a *send* depends on.
* **Relay** — `/send_raw_transaction` answers, and refuses a malformed
  transaction as a structured value rather than a transport error.
* **Node sync** — `wownerod --sync-from <host:port>` handshakes with C++ peers
  and applies blocks continuously. Roughly 11 blocks/s, ~78% of it waiting on
  the peer, so a full sync is many hours; point the wallet at a public node
  instead unless you specifically want your own chain.

Run the live checks yourself:

```sh
WOW_LIVE_NODE=node2.monerodevs.org:34568   cargo test -p wow-daemon-client --test live_node -- --ignored --nocapture
```

**Not verified, and it needs coins:** signing and confirming a real payment,
sweep, and watching a receive land. Everything up to the signature is checked.

**Not built:** mining, inbound P2P connections, block propagation, reorg
handling, transaction proofs, key-image import/export, multiple accounts. The
daemon's `--help` names what is missing rather than accepting options it cannot
honour.

### What M1 has

* **`wow-crypto`** — Keccak-256 (original padding), the CryptoNote
  `ge_fromfe_frombytes_vartime` hash-to-curve, ed25519 with Monero's decoding
  rules, key derivation, view tags, subaddresses, Schnorr and v1 ring
  signatures, base58, and 25-word mnemonics in all 13 languages.
  **All 5,545 vectors from the reference tree's `tests/crypto/tests.txt` pass.**
* **`wow-serialize`** — the consensus binary archive and epee portable storage,
  with both varint encodings kept strictly apart.
* **`wow-types`** — blocks, transactions, RingCT, `tx_extra`, addresses,
  weights, difficulty, and every hash in
  [`specs/05`](specs/05-blocks-and-transactions.md) §3–§4. Validated against
  real mainnet blocks: block ids, coinbase hashes, Merkle roots and blob
  round-trips. **Every HF 18+ block's header signature verifies** against the
  computed `sig_data` and the Schnorr verifier, which is the Wownero-specific
  rule ([`specs/06`](specs/06-consensus-rules.md) §4) and checks most of the
  stack at once.
* **`wow-randomwow`** — FFI to the pinned RandomWOW library, seed-hash epochs,
  and cache/dataset/VM lifecycle. **Hashes 26 real mainnet blocks and every one
  satisfies its own recorded chain difficulty** (1.0e8 – 9.2e9), which validates
  the seed arithmetic, the hashing blob and the linked configuration together.
  The configuration is separately checked three ways
  ([`specs/15`](specs/15-testing-and-conformance.md) §2.4): the build refuses a
  wrong `configuration.h`, the linked library's parameters are read back through
  FFI, and the canonical RandomX test vector is asserted *not* to match
  upstream's published answer.

### What M1 still needs

Nothing. The gate in [`specs/15`](specs/15-testing-and-conformance.md) §2 is
met: **9,189 mainnet blocks** across every hard-fork era round-trip and
hash-match, and the 1,893 of them at HF 18+ have their header signatures
verified.

The corpus itself is generated rather than committed, since it is a few hundred
MB:

```sh
python scripts/fetch-corpus.py --daemon 127.0.0.1:34568   # or a public node
cargo test -p wow-types --test roundtrip
```

`mainnet_block_corpus` skips with an explanatory message when it is absent, so a
fresh checkout still builds. A 21-block HF 18+ fixture **is** committed
(`tests/corpus/blocks/hf18/`) and carries the header-signature check, so the
most Wownero-specific rule is covered without generating anything.

### What M2 has

* **`wow-consensus`** — the whole of
  [`specs/06`](specs/06-consensus-rules.md) and
  [`specs/07`](specs/07-difficulty.md) as pure functions over values the caller
  has already fetched: no storage, no network, no clock.
  * **All six difficulty algorithms** reproduce real mainnet windows exactly,
    including v2's floating point, v3's inverted clamp, v4's timestamp
    monotonisation, v5's `ts[0] - target` seed and the ten hard-coded overrides.
  * Emission and the block-weight penalty, including the two-step division.
  * **The long-term block weight model**, replayed against the chain's own
    stored column over **170,000 blocks from genesis**, both one-step and
    closed-loop. A 40-row probe across the HF 20 switch settles which
    hard-fork version the stored weight uses
    ([`docs/spec-deltas.md`](docs/spec-deltas.md) §13) — the earlier forks
    provably cannot, because their clamp never binds on a Wownero-sized block.
  * Fees: the dynamic base fee in all four regimes, `check_fee` with its 2%
    buffer, and the four 2021-scaling tiers.
  * Hard-fork tables, the 39 checkpoints, timestamp rules and adjusted time.
  * Coinbase and transaction validation — ring sizes, output types, version
    bounds, sorted inputs, minimum age, RingCT type gating, and the HF 16–17
    dynamic coinbase unlock **checked against real blocks**.

### What M2 still needs

* **`wow-storage`** — the LMDB layer, byte-compatible with the C++ `data.mdb`
  ([`specs/10`](specs/10-storage-lmdb.md)). The file format is **done**: all
  nineteen sub-databases open with their exact flags and comparators, every
  record type in §4 encodes and decodes byte-for-byte, and the environment
  reproduces `BlockchainLMDB::open` — paths, `--db-sync-mode` flags, map-size
  arithmetic, the `hf_starting_heights` drop, and the schema-version check.

  Built in the order [`specs/15`](specs/15-testing-and-conformance.md) §3.3
  insists on, comparators first. A wrong `compare_hash32` corrupts nothing and
  fails nothing — it just puts every record where `wownerod` will not look — so
  it is checked twice: as a function, and then against a real LMDB cursor walk
  that proves the ordering differs from bytewise in the direction the C++
  requires.

  The `BlockchainDb` trait (§9) is defined — the seam the spec asks for, kept
  object-safe so `wow-core` can hold an `Arc<dyn BlockchainDb>` and a test
  double can stand in for LMDB. The §5 semantics the format *cannot* enforce
  are implemented and tested: the coinbase-first id assignment order, ids as
  table entry counts rather than stored counters, and the commitment rules —
  including that a v2 coinbase output is filed under **amount zero** with an
  identity-mask commitment, and that an RCT type 8 commitment is multiplied by
  eight on the way in because the wire form is `C/8`.

  What remains is the LMDB implementation of the trait's methods, which lands
  alongside `wow-core` since the two are written against each other.
* **`wow-p2p`** — the Levin codec, peer list and block sync
  ([`specs/08`](specs/08-p2p.md)).
* **`wow-core`** — the `Blockchain` state machine that drives all of the above.
* **CryptoNight v1/v2/v4**, to verify pre-HF-13 proofs of work from genesis.
  [`specs/03`](specs/03-pow.md) §2 allows deferring it this far, and a node that
  syncs from a checkpoint never needs it.

  **v0 is done** — it is a different job from the other three. Wownero's genesis
  is already major version 7, so v0 never mined a block; what it does is derive
  the wallet-file key ([`specs/02`](specs/02-crypto.md) §7), which is the first
  thing standing between a Rust wallet and a `.keys` file the C++ wallet wrote.
  It passes the reference tree's four `tests-slow.txt` vectors, and each of
  BLAKE-256, Grøstl-256, JH-256 and Skein-256 passes its own 321.

The M2 gate is a full mainnet sync from genesis with zero differ mismatches, so
it cannot close until those land.

## Layout

Per [`specs/00-overview.md`](specs/00-overview.md) §4.1. Crates not yet
implemented exist as documented placeholders so the layout is stable.

```
crates/
  wow-crypto/        hashing, ed25519, key derivation, view tags, base58, mnemonics, H/commitments
  wow-serialize/     binary archive (consensus) + epee portable storage + varints
  wow-types/         Block, Transaction, RctSig, addresses, difficulty
  wow-randomwow/     RandomWOW FFI                                    [M1/M2]
  wow-consensus/     emission, weights, fees, difficulty, hard forks
  wow-storage/       BlockchainDb + LMDB, byte-compatible data.mdb
  wow-core/          Blockchain, TxPool, miner                        [M2/M3]
  wow-p2p/           levin, peerlist, sync, Dandelion++               [M2]
  wow-rpc-types/     shared RPC request/response types                [M3]
  wow-rpc-server/    daemon HTTP server                               [M3]
  wow-wallet/        wallet core                                      [M4]
  wow-daemon-client/ wallet-side daemon RPC client                    [M4]
bin/
  wownerod/  wownero-wallet-cli/  wownero-wallet-rpc/
tests/corpus/        test vectors and blobs; see tests/corpus/README.md
scripts/             corpus generation (blocks, difficulty windows, weights, unlock ids)
```

## Building and testing

```sh
git submodule update --init third_party/randomwow
cargo build --workspace
cargo test  --workspace          # ~30 s, dominated by the 5,545 crypto vectors
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check

# Slow checks, excluded from the default run:
cargo test -p wow-randomwow --release -- --ignored   # ~2.3 GiB dataset build
```

Building `wow-randomwow` needs CMake and a C++ toolchain. On Windows it also
needs **Ninja**: CMake's "MinGW Makefiles" generator cannot handle a build path
containing a space, which is easy to end up with. `build.rs` detects Ninja
and says so clearly if it is missing; `WOW_CMAKE_GENERATOR` overrides the
choice.

The workspace pins `opt-level = 3` for dependencies even in the test profile:
an unoptimised `curve25519-dalek` makes the vector suite take minutes rather
than seconds, and [`specs/15`](specs/15-testing-and-conformance.md) §6 budgets
under five minutes for it.

## Working on this

Three rules, in order of importance.

**1. The C++ tree is the specification where the two disagree.** The spec
documents cite `src/...` paths in the reference tree, not this repository. Keep
a checkout to hand. Seventeen places where the spec's summary turned out to be
imprecise are collected in [`docs/spec-deltas.md`](docs/spec-deltas.md) —
twenty-four of them so far — each
with the C++ that settles it; they are also flagged at the code that depends on
them.

Findings in the C++ *itself* — as opposed to in the spec's description of it —
go in [`docs/cpp-findings.md`](docs/cpp-findings.md), each with the C++ test
that would confirm it against a real `wownerod` build.

**2. Reproduce the bugs.** [`specs/06`](specs/06-consensus-rules.md) §9 lists
nine inherited quirks that are now consensus. A "cleaner" implementation is a
chain split. Each one this milestone touches has a test naming it.

**3. A parse failure is a `Result`, never a panic.** The epee parser faces the
network before any authentication; a panic there is a remote crash
([`specs/15`](specs/15-testing-and-conformance.md) §4.4). Every parser here has
a `never_panics` test. `wow-crypto`, `wow-serialize` and `wow-types` set
`#![forbid(unsafe_code)]`; `wow-randomwow` cannot, since it is an FFI binding,
so it sets `#![deny(unsafe_op_in_unsafe_fn)]` and every `unsafe` block carries a
`SAFETY` comment.

## Reference tree

The spec was written against `codeberg.org/wownero/wownero` at commit
`9f4f22c72`. To get one:

```sh
git clone https://codeberg.org/wownero/wownero.git reference/wownero
git -C reference/wownero checkout 9f4f22c72
git -C reference/wownero submodule update --init external/randomwow
```

## Licence

BSD-3-Clause, matching the reference implementation.
