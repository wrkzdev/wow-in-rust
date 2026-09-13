# 00 — Overview & Architecture

## 1. What is being built

A Rust workspace producing three binaries that are drop-in compatible with the
C++ Wownero suite:

| Rust binary | Replaces | Role |
|---|---|---|
| `wownerod` | `wownerod` | Full node: P2P, consensus, blockchain store, mempool, miner, RPC |
| `wownero-wallet-cli` | `wownero-wallet-cli` | Interactive wallet |
| `wownero-wallet-rpc` | `wownero-wallet-rpc` | Wallet as a JSON-RPC service |

Plus supporting crates (consensus, crypto, RandomWOW binding, storage, P2P,
RPC types, wallet core) usable as libraries.

## 2. What Wownero is, in one paragraph

Wownero is a Monero software fork launched 2018-04-01. It differs from Monero in:
**PoW** (RandomWOW — RandomX with a 1 MiB scratchpad, 1024 program iterations,
16 programs, `"RandomWOW\x01"` Argon2d salt); **block time** (300 s, not 120 s);
**emission** (`MONEY_SUPPLY = 2^64-1` atomic units at 11 decimals → 184,467,440.7
WOW total, `EMISSION_SPEED_FACTOR_PER_MINUTE = 24`, **no tail emission**);
**ring size** (fixed 22, not 16); **difficulty** (six different algorithms across
its history, currently Monero's classic algorithm with a 144-block window);
**solo-mining enforcement** (from HF 18 every block header carries an ed25519
signature over the header made with the coinbase output's one-time key, which
requires the miner's wallet spend key — so pool mining via
`get_block_template`/`submit_block` cannot produce a valid block);
**on-chain voting** (a `uint16` `vote` field in the block header); and a
**~1 day coinbase lock** (288 blocks).

Full detail: [01-constants.md](01-constants.md), [06-consensus-rules.md](06-consensus-rules.md).

## 3. Non-goals for the first release

Explicitly out of scope for the initial "daemon working" milestone, and marked
as such throughout:

- Multisig (N-of-M wallets, the MMS messaging system)
- Hardware wallet support (Ledger, Trezor)
- ZMQ RPC (`--zmq-rpc-bind-port`) and the `daemon_handler` interface
- RPC payments (`rpc_access_*` endpoints, `--rpc-payment-address`)
- Blockchain pruning (`--prune-blockchain`)
- Tor/I2P anonymity-network zones
- `blockchain_import` / `blockchain_export` and the other utility binaries

These are all specified as *optional* features so that the data structures they
touch (the `pruning_seed` field in the handshake, the pruned-tx variants of the
P2P block entries, etc.) are still handled correctly on the wire. **A node MUST
parse and relay what it does not implement**; it MUST NOT drop peers for
advertising a feature it lacks.

## 4. Architecture

```
                        +-----------------------------------+
                        |        wownerod (binary)          |
                        |  config, logging, signal handling |
                        +-----------------+-----------------+
                                          |
          +-------------------------------+----------------------------+
          |                               |                            |
  +-------v--------+            +---------v---------+        +---------v--------+
  |  wow-p2p       |            |    wow-core       |        |  wow-rpc-server  |
  | levin codec,   |<---------->| Blockchain,       |<------>| HTTP, JSON-RPC,  |
  | peer manager,  |            | TxPool, HardFork, |        | binary endpoints |
  | dandelion++,   |            | reorg, miner      |        +------------------+
  | sync           |            +----+---------+----+
  +----------------+                 |         |
                          +----------v-+   +---v-------------+
                          | wow-consen |   |  wow-storage    |
                          | sus        |   |  LMDB impl of   |
                          | (pure fns) |   |  BlockchainDb   |
                          +-----+------+   +-----------------+
                                |
          +---------------------+-------------------+
   +------v------+     +--------v-------+   +-------v-------+
   | wow-crypto  |     | wow-serialize  |   | wow-randomwow |
   | ed25519,    |     | binary archive |   | FFI or pure   |
   | keccak,     |     | epee storage   |   | Rust RandomX  |
   | clsag, bp+  |     |                |   | + wow config  |
   +-------------+     +----------------+   +---------------+
```

The wallet side reuses `wow-crypto`, `wow-serialize`, `wow-consensus` (for fee
and weight rules) and `wow-rpc-types`, and talks to a daemon over HTTP.

### 4.1 Crate layout

```
wownero-rs/
|-- Cargo.toml                  # workspace
|-- crates/
|   |-- wow-crypto/             # hashing, ed25519 scalar/point ops, key derivation,
|   |                           #   CLSAG, MLSAG, Bulletproofs, Bulletproofs+, base58,
|   |                           #   mnemonic seeds, chacha20 key-file crypto
|   |-- wow-randomwow/          # RandomWOW: FFI to librandomx built with the WOW
|   |                           #   configuration, plus VM/cache/dataset lifecycle
|   |-- wow-serialize/          # derive-based binary archive (consensus) + epee
|   |                           #   portable storage (P2P) + varint primitives
|   |-- wow-types/              # Block, Transaction, RctSig, addresses, difficulty (u128)
|   |-- wow-consensus/          # pure validation: emission, weights, fees, difficulty,
|   |                           #   hard-fork table, checkpoints, tx & block rules
|   |-- wow-storage/            # BlockchainDb trait + LMDB impl, byte-compatible
|   |                           #   with wownerod's data.mdb
|   |-- wow-core/               # Blockchain (chain state machine), TxPool, miner
|   |-- wow-p2p/                # levin codec, peerlist, connection manager, sync,
|   |                           #   Dandelion++ relay
|   |-- wow-rpc-types/          # request/response types shared by daemon & wallet
|   |-- wow-rpc-server/         # daemon HTTP server
|   |-- wow-wallet/             # wallet core: keys, scanning, selection, tx building,
|   |                           #   keys file + cache file formats
|   `-- wow-daemon-client/      # wallet-side daemon RPC client
|-- bin/
|   |-- wownerod/
|   |-- wownero-wallet-cli/
|   `-- wownero-wallet-rpc/
`-- specs/                      # this directory, vendored into the new repo
```

### 4.2 Dependency guidance

Recommendations, not requirements. The non-negotiable point is **bit-exactness**,
so for every primitive prefer a crate validated against Monero/Wownero test
vectors and add the vectors from
[15-testing-and-conformance.md](15-testing-and-conformance.md) to CI.

| Need | Suggested crate | Notes |
|---|---|---|
| Keccak-256 (original padding) | `tiny-keccak` (`Keccak::v256`) | **Not** SHA-3. See [02-crypto.md §1](02-crypto.md) |
| ed25519 group ops | `curve25519-dalek` | Needs permissive point decoding; see [02-crypto.md §2](02-crypto.md) |
| RandomWOW | FFI to the pinned C++ `RandomWOW` | A pure-Rust RandomX is a large project; FFI first |
| LMDB | `heed` (or `lmdb-master-sys` for raw FFI) | Needs `DUP_SORT` + both comparator hooks; see [10-storage-lmdb.md §1](10-storage-lmdb.md) |
| Async runtime | `tokio` | P2P and RPC are both I/O-bound |
| HTTP server | `hyper` / `axum` | Must support the exact URI set and digest auth |
| Big integers | `primitive-types::U256`, `ethnum` | Difficulty is `u128`; intermediates need 256/512 bits |
| CLSAG / Bulletproofs+ | hand-written on `curve25519-dalek` | No crate matches Monero's exact transcripts |

## 5. Threading & concurrency model

The C++ node is thread-per-connection with a global recursive blockchain mutex.
A Rust implementation SHOULD instead use:

- **One writer task** owning the chain state machine. All block additions, pops
  and reorgs are serialized through it via a command channel. This removes the
  need for the C++ `m_blockchain_lock` recursion.
- **Read snapshots** for RPC and P2P sync responses. An LMDB read transaction
  *is* a consistent snapshot, so this is free — but a read transaction MUST NOT
  be held across a long await, or the free list cannot be reclaimed
  ([10 §6.2](10-storage-lmdb.md)).
- **A rayon pool** for batch verification (CLSAG/BP+ batches, RandomWOW hashing
  of a block batch). Verification is pure and parallelises cleanly.
- **Per-connection tasks** on tokio for P2P and RPC.

Ordering requirement: verification results MUST be applied in height order, and
the difficulty/weight caches MUST be updated inside the same storage transaction
as the block write (see [10-storage-lmdb.md §6](10-storage-lmdb.md)).

## 6. Milestones

Each milestone has an acceptance gate in
[15-testing-and-conformance.md](15-testing-and-conformance.md).

**M1 — Wire parity (no network).**
Binary archive round-trips every block and transaction in the mainnet chain.
All hashes (tx hash, prefix hash, merkle root, block hashing blob, block id,
sig data) match the C++ node for a 10,000-block sample. RandomWOW produces the
correct PoW hash for known `(seed_hash, blob)` pairs.

**M2 — Verifying sync on mainnet.**
Node connects to the seed nodes, syncs from genesis to tip, and its block hashes
and cumulative difficulties match the C++ node at every height. All six
difficulty algorithms, emission, weights and fees reproduce exactly. LMDB store
implemented, byte-compatible with `wownerod`'s `data.mdb` in both directions. No
mining, no wallet. **This is the "basic to have daemon working" target.**

**M3 — Serving node.**
Daemon RPC ([11-daemon-rpc.md](11-daemon-rpc.md)), mempool with Dandelion++
relay, reorg handling, alt-chain tracking, restricted mode. A C++ wallet can
sync against the Rust daemon.

**M4 — Wallet.**
`wownero-wallet-cli` and `wownero-wallet-rpc`: scanning, balance, transfer
construction (CLSAG + Bulletproofs+ under HF 20 rules), key/cache file
compatibility with the C++ wallet.

**M5 — Mining & the long tail.**
Built-in miner with block-header signing (`--spendkey`, `--vote`), plus the
optional features listed in §3.

## 7. Repository bootstrap

The new repository starts empty. Vendor this `specs/` directory into it
unchanged as the normative reference, then create the crates per §4.1 and add
the RandomWOW submodule:

```sh
git submodule add -b 1.2.1-wow \
    https://codeberg.org/wownero/RandomWOW third_party/randomwow
git -C third_party/randomwow checkout 27b099b6dd6fef6e17f58c6dfe00009e9c5df587
```

## 8. Conformance checklist

- [ ] The three binaries are named exactly `wownerod`, `wownero-wallet-cli`,
      `wownero-wallet-rpc`.
- [ ] Unimplemented optional features MUST NOT cause peer drops, handshake
      failures, or parse errors on messages that reference them.
- [ ] Block application MUST be serialized and height-ordered.
- [ ] The RandomWOW submodule MUST be built with the pinned WOW configuration,
      never with upstream RandomX defaults.
