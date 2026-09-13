# 15 — Testing & Conformance

The only acceptance criterion that matters is: **the Rust node agrees with the C++
node about the chain, at every height, on the live network.** Everything here
exists to reach that point and to keep it.

Reference tests live in `tests/` in the C++ tree — `tests/core_tests`,
`tests/unit_tests`, `tests/crypto`, `tests/functional_tests`,
`tests/performance_tests`. Where a vector already exists there, port it rather
than inventing one.

---

## 1. Build a differential-testing harness first

Before writing consensus code, build the thing that tells you whether it is right.

```
+-------------------+          +--------------------+
|  C++ wownerod     |          |  Rust wownerod     |
|  (synced, RPC on) |          |  (under test)      |
+---------+---------+          +---------+----------+
          |                              |
          +---------- differ -----------+
                        |
             for h in 0..tip:
               compare get_block_header_by_height(h)
               compare get_block(h).blob
               compare cumulative_difficulty, reward, weight,
                       long_term_weight, already_generated_coins
```

Run it as a CI job against a locally synced C++ node. The first height where the
two disagree is the bug, and it tells you which rule is wrong with almost no
further debugging.

**This harness is the single highest-leverage thing in the project.** Build it in
M1, even before the P2P layer exists, by feeding the Rust code block blobs
fetched over RPC from the C++ node.

### 1.1 The shortcut the shared schema gives you

Because the storage format is byte-compatible ([10](10-storage-lmdb.md)), there is
a second and much faster differ that needs no RPC and no second running node:

```
        ~/.wownero/lmdb/data.mdb                 (written by C++, or by Rust)
                    |
        open read-only from BOTH implementations
                    |
        for h in 0..tip:  compare block_info records field by field
        for each table:   compare record counts and a sampled record diff
```

Two consequences worth exploiting from day one:

- **Start at the tip, not at genesis.** Copy a synced `data.mdb`, point the Rust
  node at it, and you can test reorg, RPC, mempool and wallet behaviour
  immediately. You do not need M2 to finish before starting M3.
- **Verify a range without syncing it.** Have the Rust node apply blocks
  `[n, n+k)` on top of a copied database and diff the resulting records against
  the C++ node's, which already has them. This turns "did I get the long-term
  weight right?" from a multi-hour question into a seconds-long one.

Keep the RPC differ as well — it is the one that catches RPC-surface bugs, and it
is the only one that works if the schema ever has to diverge.

---

## 2. M1 — Wire parity

### 2.1 Hash vectors

```
cn_fast_hash("")        = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
cn_fast_hash("abc")     = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
```

Port `tests/crypto/tests.txt` — it contains thousands of vectors for
`check_scalar`, `random_scalar`, `hash_to_scalar`, `generate_keys`,
`check_key`, `secret_key_to_public_key`, `generate_key_derivation`,
`derive_public_key`, `derive_secret_key`, `hash_to_ec`, `generate_key_image`,
`generate_signature`, `check_signature`, `generate_ring_signature`,
`check_ring_signature`, `hash_to_point`, `derive_view_tag`. Making that file pass
is the cheapest possible validation of `wow-crypto`.

### 2.2 Round-trip vectors

For a sample of at least 10,000 mainnet blocks spread across all hard-fork eras
(pick ~1000 per era, plus every hard-fork boundary height, plus heights
202,612 and 307,686/307,692/307,735/307,742/307,750/307,766):

```
assert serialize(parse(block_blob)) == block_blob
assert block_id(parsed) == known hash
assert tx_hash(parsed.miner_tx) == known hash
assert merkle_root(parsed) == the value in the hashing blob
assert sig_data(parsed) == the C++ get_sig_data output   (HF >= 18 blocks)
```

The re-serialization check catches non-canonical varints, missed conditional
fields and wrong array-length derivations in one line.

### 2.3 Boundary heights to include explicitly

| Height | Why |
|---|---|
| 0 | genesis construction |
| 1, 6969, 53666, 63469, 81769, 82069 | HF 7–12 boundaries |
| 114968, 114969 | the CryptoNight → RandomWOW switch |
| 115257, 160777 | HF 14, 15 |
| 202612 | the PoW override ([03 §5](03-pow.md)) |
| 253999, 254287 | CLSAG, HF 17 |
| 307686 … 307766 | the six hard-coded difficulties |
| 307800 | the v5 overflow-branch change |
| 331169, 331170, 331171 | the HF 18 switch: BP+, header signing, difficulty reset |
| 331890, 331891 | the end of the difficulty reset window |
| 331458 | HF 19 |
| 513999, 514000, 514001 | HF 20: view tags, 2021 scaling, 144-block window |
| 2048, 2112, 2113, 4096 | RandomWOW seed-epoch boundaries |

### 2.4 RandomWOW vectors

Take `(seed_hash, hashing_blob) -> pow_hash` triples from the C++ node via
`calc_pow` (or by instrumenting it) for blocks in each seed epoch, including at
least one block at a seed-height boundary. Assert your FFI produces the same hash.

Also assert the configuration: a unit test that sums the `RANDOMX_FREQ_*` values
and checks for 256, and one that asserts `RANDOMX_ARGON_SALT == "RandomWOW\x01"`
by reading the compiled constant through FFI. This catches the single most likely
build mistake — linking against upstream RandomX.

### 2.5 Reusable assets in the reference tree

Verified present in the checkout named in [README "Before you start"](README.md).
Port these before writing your own:

| Path | Contents | Use for |
|---|---|---|
| `tests/crypto/tests.txt` | 5,545 vectors | every `wow-crypto` primitive — do this first |
| `tests/hash/tests-extra-blake.txt` | ~380 KB of vectors | Blake-256 |
| `tests/hash/tests-extra-groestl.txt` | ~380 KB | Groestl-256 |
| `tests/hash/tests-extra-jh.txt` | ~380 KB | JH-256 |
| `tests/hash/tests-extra-skein.txt` | ~380 KB | Skein-256 |
| `tests/difficulty/data.txt` | timestamp / difficulty sequences | the difficulty algorithms |
| `tests/block_weight/block_weight.cpp`, `block_weight.py` | long-term weight model | [06 §3.4](06-consensus-rules.md) |
| `tests/fuzz/` | fuzz harnesses | the parsers, [§4.4](#44-adversarial--fuzz-tests) |
| `tests/functional_tests/` | RPC-driven suites | [§4.2](#42-regtest-functional-tests) |
| `tests/core_tests/`, `tests/unit_tests/` | C++ consensus tests | rule-by-rule reference |

The four `tests-extra-*` files are the **CryptoNight finalisation hashes** —
`slow-hash` selects one by `state[0] & 3`, so all four are needed even though the
chain no longer uses CryptoNight for PoW. They are on the critical path for
opening existing wallet files ([02 §7](02-crypto.md)).

`tests/difficulty/data.txt` is Monero-derived, so it exercises the generic
`next_difficulty` shape rather than all six Wownero variants. For the other five,
extract real windows from the chain as described in §3.2.

---

## 3. M2 — Verifying sync

### 3.1 The acceptance gate

```
1. Sync the Rust node from genesis on mainnet, with checkpoints enabled.
2. At the end: for every checkpoint height in [01 §14], assert
   block_hash(h) == expected and cumulative_difficulty(h) == expected.
3. Run the differ (§1) over the full height range: zero mismatches.
4. Re-run with --fast-block-sync 0 up to height 202,611 and assert every PoW
   verifies. (See [03 §5] for why 202,612 is excluded.)
```

Step 2 is the cheap version and should run in CI on a cached data directory.
`check_difficulty_checkpoints` ([07 §6](07-difficulty.md)) does exactly this and
is worth implementing as a `wownerod --check-difficulty-checkpoints` subcommand.

### 3.2 Unit tests worth having

- **Emission.** Iterate `get_block_reward` from genesis with a synthetic chain of
  minimum-weight blocks; assert the running total never exceeds `u64::MAX` and
  that the reward is monotonically non-increasing.
- **The reward penalty.** Property test: for `median_weight` in a range and
  `current_block_weight` in `[median, 2*median]`, compare the two-step division
  against a 256-bit single division and *assert they differ* at some point — this
  proves your implementation is the truncating two-step one, not the "cleaner"
  version ([06 §3.2](06-consensus-rules.md)).
- **Median.** `median([1,2,3,4]) == 2`, `median([1,2]) == 1`,
  `median([u64::MAX, u64::MAX]) == u64::MAX` (the overflow-safe `get_mid`).
- **Difficulty.** For each of the six algorithms, feed the exact timestamp and
  cumulative-difficulty windows from real heights (extracted via RPC) and compare
  against `get_block_header_by_height(h).difficulty`.
- **All ten difficulty overrides** from [07 §4](07-difficulty.md) fire at the
  right heights and only there.
- **Long-term weight.** Replay a 100,000-block window and compare
  `long_term_weight` per block against the C++ values from
  `get_block_header_by_height`.
- **Coinbase unlock time.** For the HF 16–17 range, assert your
  `pod_to_hex(...)[..3]` reading matches the C++ for at least 100 real blocks —
  this is the rule most likely to be implemented as a byte-swap by mistake.
- **Ring size.** Table-driven test over hard-fork versions × actual ring sizes ×
  mixable/unmixable input counts, against the branch table in
  [06 §5.3](06-consensus-rules.md).
- **Output type gating.** Assert `txout_to_key` is accepted at exactly HF 20 —
  the grace-period branch ([06 §5.5](06-consensus-rules.md)) is easy to miss and
  would reject live blocks.

### 3.3 Storage tests

Because the schema is byte-compatible ([10](10-storage-lmdb.md)), the strongest
storage tests are cross-implementation rather than internal.

**The gate for the storage layer:**

- **Rust writes, C++ reads.** Have the Rust node sync N blocks into a fresh
  `data.mdb`, then open it with `wownerod` and run
  `print_height` / `print_block` / `hard_fork_info`. It must agree.
- **C++ writes, Rust reads.** Open a C++-synced `data.mdb` read-only with the Rust
  node and assert the tip, every checkpoint, and a sample of output keys match.
- **Byte-identical output.** Sync the same block range with both nodes from the
  same starting database and compare the two `data.mdb` files **record by record**
  (not byte by byte — LMDB page layout and free lists legitimately differ). A
  per-table record diff that reports the first mismatching key is the single most
  valuable debugging tool in the project.

**Internal tests:**

- Comparator unit tests **first**: `compare_hash32` against a table of known
  orderings (it compares u32 words from index 7 down, not bytewise — see
  [10 §3.1](10-storage-lmdb.md)), plus `compare_uint64` and `compare_string`
  including the shorter-first rule and the NUL-terminated `properties` keys.
- Record round-trip: encode then decode every record type in
  [10 §4](10-storage-lmdb.md) and compare against a record extracted from a real
  `data.mdb`. Assert the two `output_amounts` lengths are exactly 64 and 96.
- `add_block` then `pop_block` restores the exact previous state: compare a hash of
  every table's full contents before and after.
- Randomised add/pop sequences (a small fuzz loop) with invariants after each step:
  `height == mdb_stat(blocks).ms_entries`, `num_outputs` equals the summed output
  count across blocks, and the dup count under `output_amounts[a]` equals the
  number of outputs of amount `a`.
- Output id ordering: for a block with a coinbase and 3 transactions, assert the
  assigned `output_id`s are coinbase-first and dense
  ([10 §5.1](10-storage-lmdb.md)).
- Crash test: write N blocks with `--db-sync-mode fastest`, `SIGKILL`, reopen.
  LMDB's two meta pages mean the file stays structurally valid, so assert the node
  comes back at a *consistent* (possibly earlier) height, and that
  `blocks`/`block_info`/`block_heights` agree on the tip.
- Map-size resize: force a resize mid-sync (start with a small mapsize) and assert
  no transaction is open across it and that no reader observes a stale pointer.
- Reader-leak regression: assert no `RoTxn` outlives a single request, e.g. with a
  test that holds one open and checks the free list does not grow unboundedly —
  or at minimum a lint/review rule, since this failure only shows up in
  production as disk growth ([10 §6.2](10-storage-lmdb.md)).

---

## 4. M3 — Serving node

### 4.1 Interop matrix

Run all four combinations:

| Daemon | Peer / Wallet | Must work |
|---|---|---|
| Rust | C++ daemon | handshake, chain sync both directions, tx relay |
| C++ | Rust daemon | same |
| Rust | C++ wallet | create, sync, balance, transfer, receive |
| C++ | Rust wallet | same |

A Rust daemon that a C++ wallet can transact through, and a Rust wallet that
transacts through a C++ daemon, together prove the RPC surface.

### 4.2 Regtest functional tests

Port `tests/functional_tests/*.py` — they drive a daemon and wallet over RPC and
are directly reusable, since they speak only the RPC surface. Priority:
`blockchain.py`, `transfer.py`, `mining.py`, `txpool.py`, `cold_signing.py`,
`address_book.py`, `proofs.py`.

`--regtest --fixed-difficulty 1` plus `generateblocks` gives a controllable chain.
Note that `generateblocks` cannot work at HF ≥ 18 on a real network
([11 §4.3](11-daemon-rpc.md)) — the fake chain starts at HF 7 and you control the
fork heights, so set up the regtest fork table to exercise both sides of HF 18.

### 4.3 Reorg tests

- Build two competing chains on regtest, switch between them, assert the mempool
  is repopulated and balances are correct after each switch.
- Assert a reorg below the last checkpoint is refused.
- Assert `switch_to_alternative_blockchain` requires *strictly greater* cumulative
  difficulty (an equal-difficulty alt chain must not cause a switch).

### 4.4 Adversarial / fuzz tests

Port `tests/fuzz/*`: block, transaction, `tx_extra`, signature, `bulletproof`,
`levin`, `parse_url`, `http_client`, `base58`, `cold_outputs`, `cold_transaction`.
Then add Rust-native fuzz targets with `cargo-fuzz` for:

- the binary archive parser (blocks, transactions, RCT signatures),
- the epee portable-storage parser (this one faces the network directly and is the
  highest-risk surface),
- the Levin framer, including fragmented and dummy messages,
- base58 and address parsing,
- `tx_extra` parsing.

**Invariant for all of them: never panic.** A parse failure must be a `Result`
error. A panic in a P2P message parser is a remote crash.

---

## 5. M4 — Wallet

- **Keys file compatibility, both directions.** Create a wallet with the C++
  wallet, open it with the Rust wallet, assert the address and the seed match.
  Then create with Rust, open with C++. Cover: deterministic, non-deterministic,
  view-only, `encrypted_secret_keys` on and off, non-default `kdf_rounds`.
- **Mnemonic round-trip** across all supported languages, plus the checksum-word
  computation.
- **Scanning.** On regtest, send to a Rust wallet from a C++ wallet and vice
  versa, across main address / subaddress / integrated address, and assert the
  received amount, payment id and subaddress index all match.
- **View-tag correctness.** Assert the Rust wallet finds exactly the same set of
  owned outputs whether or not the view-tag fast path is enabled.
- **Transfer acceptance.** Every transaction the Rust wallet builds must be
  accepted by a **C++ daemon**. This is the real test of
  [12 §4.6](12-wallet-core.md). Cover 1–16 outputs, 1–many inputs, subaddress
  destinations, integrated addresses, and each of the four priorities.
- **Fee agreement.** For the same inputs and outputs, the Rust and C++ wallets
  should compute the same fee. Small differences are tolerable (the fee only has
  to clear the minimum), but a systematic difference means the weight or the
  estimate is wrong.
- **Proof round-trip.** Generate each proof type with the C++ wallet and verify
  with Rust, and vice versa. Message signing must use the
  `"WowneroMessageSignature"` domain, so cross-verify against the C++ explicitly.

---

## 6. Continuous integration

| Job | Trigger | Duration budget |
|---|---|---|
| `cargo test` (unit + vectors) | every push | < 5 min |
| `cargo clippy -- -D warnings`, `cargo fmt --check` | every push | < 2 min |
| Round-trip over the cached 10k-block corpus | every push | < 10 min |
| Difficulty-checkpoint check against a cached data dir | every push | < 2 min |
| `cargo-fuzz` smoke run (60 s per target) | every push | < 10 min |
| Regtest functional suite | every PR | < 30 min |
| Full mainnet resync + differ | nightly | hours |
| Interop matrix against a pinned C++ build | nightly | < 1 h |

Pin the C++ reference build by commit so a change in *its* behaviour is visible as
a CI failure rather than as mysterious drift.

---

## 7. Test corpus

Vendor a compact corpus into the repo (or an LFS/artifact store):

```
tests/corpus/
  blocks/            # ~10k block blobs + expected (hash, difficulty,
                     #   cum_difficulty, reward, weight, long_term_weight,
                     #   already_generated_coins)
  txs/               # transactions of every RCT type, incl. type 8 and type 9
  pow/               # (seed_hash, blob, pow_hash) triples per epoch
  crypto/tests.txt   # ported from tests/crypto
  addresses/         # valid + invalid addresses for all three networks and
                     #   all three prefixes
  seeds/             # mnemonics in every language with their keys
  levin/             # captured handshake and sync messages, incl. fragments
  keysfiles/         # C++-generated .keys files for each wallet kind
  lmdb/              # a small C++-written data.mdb (a few thousand blocks) plus
                     #   one extracted record of every type from 10 §4, for the
                     #   record-layout and comparator tests
```

Generate it with a script that talks to a synced C++ node over RPC, and commit the
script so the corpus can be regenerated and extended.

---

## 8. Gates summary

A milestone is **not** complete until its gate passes.

| Milestone | Gate |
|---|---|
| M1 | `tests/crypto` vectors pass; 10k-block round-trip and hash comparison pass; RandomWOW vectors pass; the config assertions pass |
| M2 | Full mainnet sync from genesis; all 39 checkpoints match by hash **and** cumulative difficulty; the differ reports zero mismatches over the full range; **a `data.mdb` written by the Rust node opens cleanly in `wownerod` and vice versa** |
| M3 | A C++ wallet completes create → sync → transfer → receive against the Rust daemon; the regtest functional suite passes; fuzz targets run clean |
| M4 | Keys-file compatibility both directions; every Rust-built transaction is accepted by a C++ daemon; proofs cross-verify |
| M5 | A Rust-mined block with `--spendkey` is accepted by a C++ daemon at HF ≥ 18 |

The M5 gate is worth stating precisely because it is the one that proves the
Wownero-specific header-signing rule was implemented correctly, and it cannot be
tested any other way.
