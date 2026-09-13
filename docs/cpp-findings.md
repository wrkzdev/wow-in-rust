# Findings in the C++ reference tree

Things wrong, misleading, or fragile in **upstream C++** — not in this port, and
not in the spec documents. `docs/spec-deltas.md` is the other list: places where
`specs/` describes the C++ inaccurately. This one is about the C++ itself.

Reference tree: `wownero.git` at `9f4f22c72`, version `0.11.4.0` "Kunty Karen".

## How to use this

Each item is a checkbox with a **C++ test to write**. The point is to confirm
each finding against a real `wownerod` build rather than against reading, and
then to decide case by case whether it is worth an upstream patch.

Severity:

- **consensus** — changing it would fork the chain. Report, never "fix".
- **latent** — wrong but currently unreachable, or benign by luck.
- **cosmetic** — a comment or name that misleads a reader; the code is right.

Nothing here is a security report. Anything that looked exploitable would go to
the Wownero maintainers privately first, not into a repo file.

---

## 1. `rctTypes.h`: the `H` generator's stated derivation is false

**Severity:** cosmetic (the constant is correct; the comment is not)

`src/ringct/rctTypes.h:652`:

```cpp
//other basepoint H = toPoint(cn_fast_hash(G)), G the basepoint
static const key H = { {0x8b, 0x65, 0x59, 0x70, ...} };
```

`rctOps.cpp: hash_to_p3` is byte-for-byte `crypto::hash_to_ec`, and applying it
to the basepoint encoding does **not** produce that literal. The same claim
appears in Monero, so it is inherited rather than Wownero's.

Harmless as long as nobody recomputes the constant from the comment — which is
exactly what a reimplementation is tempted to do.

- [ ] **C++ test:** assert
      `hash_to_p3(cn_fast_hash(GetBasepointBytes())) != rct::H`, and add a
      comment correction. Confirms the literal is load-bearing.

**Rust side:** `wow_crypto::rct::h_is_not_the_documented_derivation`,
`docs/spec-deltas.md` §4.

---

## 2. `cryptonote_format_utils.cpp`: `round_money_up`'s comment contradicts its code

**Severity:** cosmetic

`src/cryptonote_basic/cryptonote_format_utils.cpp:1242`:

```cpp
// bump digits by one if the following digits past significant digits were to be 5 or more
if (*ptr != '0')
{
  bump = true;
  *ptr = '0';
}
```

The comment describes round-half-up. The code bumps on **any** non-zero digit,
i.e. it is a ceiling. `round_money_up(101, 2)` is 110, not 100.

The name says "up", so the code is almost certainly what was intended and the
comment is stale. It feeds the four wallet fee tiers, so a reader who trusts the
comment quotes fees that are too low.

- [ ] **C++ test:** `round_money_up(101, 2) == 110` and
      `round_money_up(149, 2) == 150`. Both fail under a half-up reading.

**Rust side:** `wow_consensus::fee::round_money_up_is_a_ceiling_not_a_rounding`.

---

## 3. `db_lmdb.cpp`: `do_resize`'s page alignment does not align

**Severity:** latent (benign — the map ends up slightly larger, never smaller)

`BlockchainLMDB::do_resize`:

```cpp
new_mapsize += new_mapsize % mst.ms_psize;
```

This **adds the remainder**. Rounding up to a page boundary is
`new += psize - (new % psize)`, or `new = ((new + psize - 1) / psize) * psize`.
As written, a map size one byte past a page boundary grows by one byte and is
still unaligned.

LMDB rounds the map size down to a page multiple internally, so the effect is
nil — which is presumably why it has never been noticed.

- [ ] **C++ test:** force a resize from a deliberately unaligned map size and
      assert `mei.me_mapsize % mst.ms_psize` afterwards. Under the intended
      reading it is 0; under the current code it need not be.

**Rust side:**
`wow_storage::env::the_resize_adds_the_remainder_rather_than_rounding_up`.

---

## 4. `blockchain.cpp`: `assert(hi == 0)` is compiled out in release

**Severity:** latent

`Blockchain::get_dynamic_base_fee` calls `div128_64` and then `assert(hi == 0)`
before using `lo`. Release builds define `NDEBUG`, so the assertion vanishes and
an overflow would silently truncate to the low 64 bits instead of aborting.

Unreachable with real inputs — `block_reward * 3000 / median / median` cannot
exceed 64 bits for any median at or above 300,000 — so this is about the guard
being absent, not about a live overflow.

- [ ] **C++ test:** call `get_dynamic_base_fee` with a synthetic `block_reward`
      large enough to overflow and observe a release build returning a truncated
      fee rather than aborting. Consider `CHECK_AND_ASSERT_THROW_MES`.

**Rust side:** `wow_consensus::fee` models the truncation deliberately, since a
release build is the thing to match.

---

## 5. `blockchain.cpp`: a vacuous clause in the ring-size branch table

**Severity:** latent (dead code)

`Blockchain::check_tx_inputs`:

```cpp
|| (hf_version < HF_VERSION_MIN_MIXIN_21 && hf_version >= HF_VERSION_MIN_MIXIN_7+2 && min_actual_mixin > 7)
```

`HF_VERSION_MIN_MIXIN_7 + 2 == 9 == HF_VERSION_MIN_MIXIN_21`, so the condition is
`hf < 9 && hf >= 9`: never true. It presumably dated from when the two constants
differed.

Deleting it changes nothing today, but the constants are the kind of thing that
gets adjusted, and if they ever diverge the clause wakes up.

- [ ] **C++ test:** a static assertion that
      `HF_VERSION_MIN_MIXIN_7 + 2 == HF_VERSION_MIN_MIXIN_21`, so a future
      constant change surfaces the dead clause instead of silently reviving it.

**Rust side:** transcribed as written, with
`wow_consensus::tx_rules::the_vacuous_clause_never_fires` asserting it stays
vacuous. `clippy::impossible_comparisons` flags it, and the allow says why.

---

## 6. `blockchain.cpp`: the last RingCT gate is missing its version guard

**Severity:** latent (inert, but inconsistent)

The eight gates in `check_tx_inputs` that police `rct_signatures.type` are each
wrapped in `if (tx.version >= 2)`. The ninth is not:

```cpp
// from v22, forbid bulletproof plus legacy
if (hf_version > HF_VERSION_BP_PLUS_FULL_COMMIT && rct::is_rct_bp_plus_legacy(tx.rct_signatures.type)) {
```

Inert, because a v1 transaction carries `RCTTypeNull` and
`is_rct_bp_plus_legacy(0)` is false. Still, the asymmetry looks accidental, and a
future gate copied from this one would inherit it.

- [ ] **C++ test:** feed a v1 transaction with a forged `rct_signatures.type` of
      8 at `hf_version = 22` and confirm the rejection comes from this gate.
      Documents the reachability either way.

**Rust side:** `wow_consensus::tx_rules::the_last_gate_applies_to_v1_too`,
`docs/spec-deltas.md` §15.

---

## 7. `hardfork.cpp`: `get_voted_fork_index` depends on call ordering

**Severity:** latent (correct today, fragile)

`HardFork::init()` inserts a placeholder at index 0 only `if (heights.empty())`.
`Blockchain::init` calls `add_fork` for the whole table *before* `init()`, so the
placeholder is never inserted and `heights[0]` is the real first fork.

`get_voted_fork_index` ends in `return current_fork_index` (0 initially), so the
version below every fork height is `heights[0].version` — 7 on Wownero, not
`original_version` (1). Wownero's genesis block carries version 7 and `do_check`
compares for equality, so this is what makes genesis validate.

Swap the two calls and genesis stops validating. Nothing marks the dependency.

- [ ] **C++ test:** construct a `HardFork`, call `init()` **before** `add_fork`,
      and assert `get_current_version()` differs from the normal path — pinning
      the ordering requirement rather than leaving it implicit.

**Rust side:** `wow_consensus::hardfork::genesis_is_below_every_fork`,
`docs/spec-deltas.md` §12.

---

## 8. `varint.h`: a truncated varint is a *successful* read

**Severity:** consensus (reproduce; do not change)

`read_varint` returns the bytes consumed when it runs out of input:

```cpp
if (first == last) return read;   // not an error
```

So a blob ending mid-varint decodes to whatever was accumulated so far, rather
than failing. Any parser that "fixes" this by erroring rejects blobs the
reference accepts.

This is load-bearing, not incidental: dropping a trailing varint from a block
blob reparses to the same object.

- [ ] **C++ test:** `read_varint` over a deliberately truncated buffer, asserting
      it returns the partial value and the short count. Locks the behaviour in
      so nobody tightens it.

**Rust side:** `wow_serialize::varint` reproduces the EOF tolerance;
`docs/spec-deltas.md` §6.

---

## 9. `mnemonics`: the prefix map is last-wins, making `english_old` lossy

**Severity:** latent (affects one wordlist)

`populate_maps` assigns rather than inserts:

```cpp
trimmed_word_map[trimmed] = ii;
```

On a duplicate prefix the **last** word wins, so decoding a seed in a list with
colliding prefixes can yield a different word than was encoded. `english_old`
has such collisions and is flagged `ALLOW_DUPLICATE_PREFIXES` for that reason,
which makes its 25-word round trip lossy in the reference too.

- [ ] **C++ test:** round-trip every `english_old` seed phrase and count the
      words that change. Confirms the loss is inherent rather than a port bug.

**Rust side:** `wow_crypto::mnemonic` reproduces last-wins and excludes
`english_old` from the round-trip assertion; `docs/spec-deltas.md` §9.

---

## 10. `blockchain.cpp`: partial block rewards permanently altered the emission curve

**Severity:** consensus (historical; reproduce exactly)

For hard-fork versions 2–15 a miner could claim **less** than the full block
reward, and `already_generated_coins` accumulated only what was claimed. Every
later reward is computed from that running total, so an under-claim in 2018
changes the subsidy forever.

On Wownero the window is HF 7–15, heights 1 … 253,998. Not a bug to fix — it is
the chain's history — but it is the kind of thing a reimplementation "corrects"
by accident, and the result is a wrong reward at every subsequent height.

- [ ] **C++ test:** replay `validate_miner_transaction` over a height where the
      claimed reward was short and assert `already_generated_coins` advances by
      the claimed amount, not the full one.

**Rust side:** `wow_consensus::emission::validate_miner_reward`.

---

## 11. `rctTypes.cpp`: `is_rct_bulletproof` includes CLSAG

**Severity:** cosmetic (surprising name, correct behaviour)

```cpp
bool is_rct_bulletproof(int type) {
    case RCTTypeSimpleBulletproof: case RCTTypeFullBulletproof:
    case RCTTypeBulletproof: case RCTTypeBulletproof2:
    case RCTTypeCLSAG:                                    // <--
        return true;
```

Correct — CLSAG is a signature scheme that carries Bulletproof *range proofs* —
but the name reads as a type check on the signature scheme. It is why the
`hf > 18` gate labelled "forbid bulletproofs" also forbids CLSAG, which is not
obvious from the call site.

- [ ] **C++ test:** assert `is_rct_bulletproof(RCTTypeCLSAG)` and add a comment
      at the `hf > 18` gate naming CLSAG explicitly.

**Rust side:** `wow_consensus::tx_rules::is_rct_bulletproof` carries the note;
`docs/spec-deltas.md` §15.

---

## 12. `blockchain.cpp`: `check_tx_inputs` judges every transaction by the *tip's* hard-fork version

**Severity:** consensus (report, never "fix")

`src/cryptonote_core/blockchain.cpp:3368`, in the `check_tx_inputs` that does
the work:

```cpp
bool Blockchain::check_tx_inputs(transaction& tx, tx_verification_context &tvc, uint64_t* pmax_used_block_height) const
{
  ...
  const uint8_t hf_version = m_hardfork->get_current_version();
```

`get_current_version()` is the version in force at the **chain tip**, not the
version of the block the transaction is in. Every rule below that line — the
minimum output count, the ring-size table, the version bounds, the
`HF_VERSION_SAME_MIXIN` constant-ring rule — is therefore evaluated against
whatever the chain has since forked to.

For the mempool this is right: a transaction being admitted now must satisfy
today's rules. For a block being added it is only right by accident, because
the tip is the block's own parent while syncing forward. The two cases share
one function and one `hf_version`.

Where it stops being an accident:

- **A reorg past a fork boundary.** Blocks below the fork are re-validated with
  the post-fork rules. Wownero's checkpoints make a reorg that deep
  impossible in practice, which is what keeps this latent.
- **Any re-validation of historical blocks.** It is masked today only by
  finding §13 below: the historical blocks that would fail are never checked.

The `ring size` rules make the exposure concrete. At `hf_version == 7` the
table demands mixin *exactly* 7:

```cpp
|| ((hf_version == HF_VERSION_MIN_MIXIN_7 || hf_version == HF_VERSION_MIN_MIXIN_7+1)
    && min_actual_mixin != 7)
```

Mainnet block 460 carries a transaction with mixin 11. It is on the chain. It
would not pass `check_tx_inputs` at `hf_version` 7, and it would not pass at
`hf_version` 20 either (`hf_version > HF_VERSION_MIN_MIXIN_21 && min_actual_mixin > 21`
is false, but `HF_VERSION_SAME_MIXIN` and the rest now apply to it). It
survives because it is never examined.

- [ ] **C++ test:** call `check_tx_inputs` directly on the transaction in
      mainnet block 460 with the chain synced to the tip, and assert it
      returns false. Then assert that a full sync with `PER_BLOCK_CHECKPOINT`
      disabled fails at that height, which pins the dependency between this
      finding and §13.

**Rust side:** `wow_consensus::tx_rules` takes `hf_version` as a parameter and
`wow_core::chain` passes the *block's* version, which is the stricter reading
and diverges from the C++ only where the C++ is self-inconsistent.
`docs/spec-deltas.md` §23.

---

## 13. `blockchain.cpp`: most of the chain is never verified

**Severity:** consensus (report, never "fix")

With `PER_BLOCK_CHECKPOINT` compiled in — it is, by default — a block whose
height is covered by the embedded `blocks.dat` hash table and whose id matches
skips both proof-of-work and transaction-input validation entirely. The full
mechanism and the three call sites are in `docs/spec-deltas.md` §23.

This is deliberate and is how every Monero-family node achieves a tolerable
initial sync. It is recorded here because of what it implies rather than
because it is wrong:

- The embedded hashes are **the** security boundary for the first ~99% of the
  chain. A node's history is as trustworthy as the binary it came in.
- It cannot be turned off at runtime. There is no
  `--validate-from-genesis`, so "does this chain actually satisfy its own
  rules?" is a question no released build can answer.
- It hides §12 above, and it hides any other rule that historical blocks
  violate. Nobody finds out which rules those are.

The comment above the proof-of-work block is worth reading against this:

```cpp
// Formerly the code below contained an if loop with the following condition
// !m_checkpoints.is_in_checkpoint_zone(get_current_blockchain_height())
// however, this caused the daemon to not bother checking PoW for blocks
// before checkpoints, which is very dangerous behaviour. We moved the PoW
// validation out of the next chunk of code to make sure that we correctly
// check PoW now.
```

The behaviour it calls "very dangerous" was removed from one path and is
present in the next twenty lines, keyed on a different table.

- [ ] **C++ test:** build with `PER_BLOCK_CHECKPOINT` off and sync mainnet from
      genesis; record the first height that fails and the rule it fails. That
      list is the set of rules the chain does not actually satisfy, and it does
      not exist anywhere today.

**Rust side:** `netsync::LocalChain` reproduces the bypass, keyed on the
hard-coded checkpoints rather than an embedded hash file, and reports at
startup which range it is not verifying. `docs/spec-deltas.md` §23.

---

## Not findings

Recorded so they are not re-investigated:

- **The two-step reward division is not a precision trick.**
  `floor(floor(x/m)/m) == floor(x/m²)` for non-negative integers, so the two
  `div128_64` calls lose nothing. It avoids a `u64` overflow in `m * m`, which is
  a real reason, just not the one usually given. `docs/spec-deltas.md` §11.
- **`get_ideal_version` skipping index 0** is deliberate and documented
  upstream, not an oversight.
- **`compare_hash32` comparing u32 words from the top down** is intentional and
  is part of the file format.
