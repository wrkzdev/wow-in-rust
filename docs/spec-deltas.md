# Where `specs/` and the C++ disagree

`specs/README.md` is explicit that the C++ tree is normative and the spec is a
distillation of it. These are the places where, implementing M1, the spec's
summary turned out to be imprecise enough to produce a wrong implementation if
followed literally. Each was settled by reading the reference and is pinned by a
test.

The first is a genuine error: following it produces a wrong block id for every
block on the chain. The rest are mostly summaries that lost a qualifier. They
are recorded so the next person does not have to rediscover them, and so that if
`specs/` is ever revised the list can be folded back in.

Reference tree: `github.com/wownero-project/wownero` at `9f4f22c72`.

---

## 0. The block id hashes a **length-prefixed** blob

The one on this list that is unambiguously consensus-critical: following the
spec literally gives a wrong id for **every block on the chain**.

**Spec:** [`05-blocks-and-transactions.md`](../specs/05-blocks-and-transactions.md)
§4.2 — "`block_id = cn_fast_hash(block_hashing_blob)`". §4.3 and
[`03-pow.md`](../specs/03-pow.md) §1 go further: the block id and the PoW hash
take "the **same** blob" and "differ only in the hash function applied to it".

**Reference:** `calculate_block_hash` is

```cpp
bool hash_result = get_object_hash(get_block_hashing_blob(b), res);
```

and `get_object_hash` is a **template**:

```cpp
template<class t_object>
bool get_object_hash(const t_object& o, crypto::hash& res)
{
  get_blob_hash(t_serializable_object_to_blob(o), res);
  return true;
}
```

Instantiated here with `t_object = blobdata`, i.e. `std::string`. So the
already-serialized blob goes through the binary archive a **second** time, and a
`std::string` serializes as `varint(len) || bytes` ([`04`](../specs/04-serialization.md)
§1.2). The actual rule is:

```text
block_id = cn_fast_hash( varint(hashing_blob.len()) || hashing_blob )
```

The other two consumers of the same blob do **not** do this:

* `get_block_longhash` passes `bd` to the PoW function untouched, so the PoW
  input is the bare blob;
* `get_sig_data` calls `crypto::cn_fast_hash(blob.data(), blob.size(), …)`
  directly, so the HF 18 miner signature covers the bare blob too.

So §4.3's "differ only in the hash function" is false in both directions: the
preimages differ as well.

The prefix is not always one byte. An HF 18+ header is 66 bytes longer
(signature plus vote), which pushes the blob past 127 bytes and the varint to
two.

**How it was found:** the first 2,160 blocks of the generated mainnet corpus
failed on block id while their coinbase hashes, Merkle roots and blob
round-trips all matched — which localised it to the last step.

**Pinned by:** `Block::block_id`,
`block_id_prefixes_the_hashing_blob_with_its_length`,
`the_length_prefix_can_be_two_bytes`, `sig_data_has_no_length_prefix`, and the
mainnet corpus.

---

## 1. Point decoding is *not* fully permissive

**Spec:** [`02-crypto.md`](../specs/02-crypto.md) §2 item 1 — "`ge_frombytes_vartime`
accepts any 32-byte value that decodes to a curve point, including
**small-order and non-canonical points**. It does **not** reject non-canonical
`y` encodings the way a strict ed25519 library does."

**Reference:** `src/crypto/crypto-ops.c: ge_frombytes_vartime` has two
rejections the spec's summary omits:

```c
/* Validate the number to be canonical */
if (h9 == 33554428 && h8 == 268435440 && ... && h0 >= 4294967277) {
  return -1;
}
...
if (fe_isnegative(h->X) != (s[31] >> 7)) {
  /* If x = 0, the sign must be positive */
  if (!fe_isnonzero(h->X)) {
    return -1;
  }
  fe_neg(h->X, h->X);
}
```

The limb literals spell out exactly `y >= p` after bit 255 is masked. And since
the curve forces `x == 0` precisely when `y^2 == 1`, the second check is
`y in {1, p-1}` with the sign bit set.

Small-order and torsioned points *are* accepted — that part of the spec holds,
and it is the part that matters for not forking. The permissive loader the spec
is describing is the one inlined into `ge_fromfe_frombytes_vartime`, which is a
different function.

**Cost of getting it wrong:** 26 of the 372 `check_key` reference vectors fail.

**Pinned by:** `wow_crypto::ops::decode_point` and the `check_key` vectors.

---

## 2. `ge_fromfe_frombytes_vartime` does *not* mask bit 255

Not stated either way in the spec, and it is the opposite of §1's function.

**Reference:** compare the two inlined `fe_frombytes` bodies —

```c
/* ge_frombytes_vartime */          int64_t h9 = (load_3(s + 29) & 8388607) << 2;
/* ge_fromfe_frombytes_vartime */   int64_t h9 = load_3(s + 29) << 2;
```

So the hash-to-point map reduces the whole 256-bit little-endian value mod `p`
(`2^255 === 19`), rather than truncating to 255 bits. Half of all Keccak outputs
have bit 255 set, so using the masking loader breaks half the vectors.

**Pinned by:** `wow_crypto::field::Fe::from_bytes_unmasked`, and
`masked_and_unmasked_loaders`.

---

## 3. `random_scalar` rejection-samples

**Spec:** [`02-crypto.md`](../specs/02-crypto.md) §3.1 — "`random_scalar()` =
`sc_reduce32(random 32 bytes)`, rejecting zero."

**Reference:** `src/crypto/crypto.cpp: random32_unbiased` first rejects any draw
that is **not below `15 * l`**, the largest multiple of `l` that fits in 32
bytes, and only then reduces:

```c
while(1) {
  generate_random_bytes_thread_safe(32, bytes);
  if (!less32(bytes, limit)) continue;   /* limit = 15 * l */
  sc_reduce32(bytes);
  if (sc_isnonzero(bytes)) break;
}
```

Without the rejection the reduction is biased — and, more immediately, the
number of draws differs, so every vector generated from the deterministic test
PRNG desynchronises.

**Pinned by:** `wow_crypto::random::Rng::random32_unbiased` and the 245
`random_scalar` vectors.

---

## 4. The `H` generator's documented derivation does not reproduce it

**Spec:** [`02-crypto.md`](../specs/02-crypto.md) §2 item 4 — "`H` is the second
generator: `H = 8 * to_point(cn_fast_hash(G))`, hard-coded in `rctOps.cpp` as
`8b655970...`".

`rctOps.cpp: hash_to_p3` is byte-for-byte the same function as
`crypto::hash_to_ec`, and applying it to the basepoint encoding does **not**
produce the literal. The comment in `rctTypes.h` says the same thing the spec
does, so the folklore is upstream, not introduced here.

`H` is only needed for commitments and Bulletproofs+ (M2/M4). **Take the literal
from `rctTypes.h`; do not derive it.**

**Pinned by:** `hash_to_ec_lands_in_the_prime_order_subgroup`, which asserts what
*is* true and documents the rest.

---

## 5. Consensus varint reading is bit-width dependent

**Spec:** [`04-serialization.md`](../specs/04-serialization.md) §1.1 — "the reader
MUST reject a varint longer than `ceil(bits/7)` bytes for the target type"
mentions `bits`, but the worked rules are all `u64`.

**Reference:** `src/common/varint.h` templates on
`std::numeric_limits<T>::digits`, and the overflow test is
`byte >= 1 << (bits - shift)`. `block_header.major_version` is a `uint8_t`, so
its varint overflows at a completely different point than a `u64` field's. Using
64 everywhere accepts blobs the reference rejects.

**Pinned by:** `wow_serialize::varint::read_varint_bits` and
`width_changes_the_overflow_point`.

---

## 6. A truncated varint is a *successful* read

Not mentioned in the spec.

**Reference:** `tools::read_varint` returns the byte count on running out of
input, and `binary_archive::serialize_uvarint` tests `0 <= read_varint(...)` —
so EOF mid-varint is success with the partially accumulated value, and reading a
varint from an empty buffer yields `0`. Fixed-size reads are *not* tolerant;
only varints are.

Reachable when a varint is the final field of a blob, where it decodes an
alternative encoding of an otherwise well-formed structure. Rejecting it would
make a peer that sends such a blob be treated differently than the reference
treats it.

A concrete instance: a block ends with the `tx_hashes` length varint. Drop that
one byte from the genesis blob and it still parses — as the same block. Every
shorter truncation lands inside a fixed-size field and fails.

A concrete instance: a block ends with . Drop that one
byte from the genesis blob and it still parses — as the same block. Every
shorter truncation lands inside a fixed-size field and fails.

**Pinned by:** `truncation_is_success_in_the_reference` and
`varint_eof_tolerance_is_limited_to_varints`.

---

## 7. `bulletproofs_plus.len() != 1` is not a parse limit

**Spec:** [`04-serialization.md`](../specs/04-serialization.md) §1.6 lists
"`bulletproofs_plus.len() != 1` (for BP+ types) or `L.len() < 6`" among the
things to "reject at parse time".

**Reference:** `serialize_rctsig_prunable` checks only `nbp > outputs` and
`n_bulletproof_plus_max_amounts < outputs`. The `!= 1` and `L.len() < 6` checks
live in `expand_transaction_1`
(`cryptonote_format_utils.cpp:173`), a separate step that
`parse_and_validate_tx_from_blob` runs afterwards and that the `base_only` path
— used for pruned transactions — skips entirely.

The distinction matters: a pruned entry legitimately has no proofs at all.

Also note `nbp` is a `uint32_t`, so its `VARINT_FIELD` reads with `bits = 32`
(see §5), and for RCT type 5 specifically it is a raw `u32` LE rather than a
varint.

**Pinned by:** `Transaction::expand` versus `Transaction::from_blob_base_only`.

---

## 8. An epoch-aligned sync batch spans *two* seeds, not one

**Spec:** [`08-p2p.md`](../specs/08-p2p.md) §5.4 — "**Align requests to
`SEEDHASH_EPOCH_BLOCKS` (2048) boundaries** so that a batch shares one RandomWOW
seed."

**Reference:** `rx_seedheight(h) = (h - 64 - 1) & ~2047`, so the seed changes at
heights `2048k + 65`, not at `2048k`. A batch starting at a round multiple of
2048 straddles a change: its first 65 blocks use the previous seed.

The *point* of aligning still stands — it bounds a batch at two seeds instead of
many, keeping sync off the 200–500 ms seed-switch path. Aligning to `2048k + 65`
would give exactly one.

**Pinned by:** `epoch_matches_the_sync_batch_size`.

---

## 9. Mnemonic details the spec's summary compresses

**Spec:** [`02-crypto.md`](../specs/02-crypto.md) §6.

Three things from `src/mnemonics/language_base.h: populate_maps`:

* **Duplicate prefixes resolve last-wins.** `trimmed_word_map[trimmed] = ii` is
  a plain assignment. Only `english_old` has duplicates (292 of them) and it is
  the only list passing `ALLOW_DUPLICATE_PREFIXES`. Keeping the *first* index
  instead silently decodes some English-old seeds to the wrong key.
* **The short-word check is on byte length**, `(*it).size()`, not character
  count. `spanish` passes `ALLOW_SHORT_WORDS` for its 31 words under 4 bytes;
  counting characters would find 36.
* **Word trimming is on characters**, `utf8prefix`. Chinese (prefix length 1)
  and Japanese (3) make the distinction load-bearing.

A consequence worth knowing: a 25-word English-old seed is **lossy** on the
prefix-matching path, in the reference too. The 24-word (no-checksum) path
matches full words and round-trips exactly.

**Pinned by:** `english_old_prefixes_collide`,
`short_word_flags_match_the_reference`, `utf8_prefix_counts_characters`.

---

## 10. The height-202,612 override is not actually a problem on Wownero

**Spec:** [`03-pow.md`](../specs/03-pow.md) §5 item 2 — the override hash
"passes `check_hash` only for difficulty <= **1,297,898,660**. Wownero's average
difficulty in the surrounding range (heights 160,777–253,999) is ≈ 3.39 × 10^9,
so depending on the actual difficulty at that height, a from-genesis
verification with `--fast-block-sync 0` may **reject** the block."

§3 of the same document repeats the concern, and [`15`](../specs/15-testing-and-conformance.md)
§3.1 tells you to exclude 202,612 from a from-genesis PoW run because of it.

**The chain:** the difficulty actually recorded at height 202,612 is
**1,200,000,000** — under the ceiling. The override passes, and a from-genesis
verification does not reject the block.

The ceiling itself is right: bisecting `check_hash` against the override hash
gives exactly 1,297,898,660. It is the "average difficulty in the surrounding
range" that misleads — the average over 160,777–253,999 is indeed billions, but
difficulty at that particular height had dipped.

Not a correctness issue either way, since reproducing the override is what
matters. Recorded so nobody spends time engineering around a rejection that does
not happen.

**Pinned by:** `the_202612_override_passes_the_real_difficulty`, which asserts
both the ceiling and the real difficulty.

---

## 11. The two-step reward division is *not* different from the one-step one

**Spec:** [`06-consensus-rules.md`](../specs/06-consensus-rules.md) §3.2 — "The
two successive `div128_64` calls are **not** the same as one division by
`median_weight^2` — each truncates. Reproduce the two-step division." Repeated
as quirk §9.8, and [`15`](../specs/15-testing-and-conformance.md) §3.2 turns it
into a test:

> **The reward penalty.** Property test: for `median_weight` in a range and
> `current_block_weight` in `[median, 2*median]`, compare the two-step division
> against a 256-bit single division and *assert they differ* at some point —
> this proves your implementation is the truncating two-step one, not the
> "cleaner" version.

**That test can never pass.** For non-negative integers

```text
floor(floor(x / m) / m)  ==  floor(x / m²)
```

is a theorem (Concrete Mathematics eq. 3.11), and the C loses no precision
between the steps: `div128_64` produces a full 128-bit quotient
(`reward_hi`, `reward_lo`), which the second call then divides. Checked here
against a 256-bit single division across the realistic input range, and
separately against arbitrary precision over two million random `(x, m)` pairs
plus an exhaustive small range — zero counterexamples, as the theorem requires.

The hazard is real but inverted: someone following §3.2 writes a test that
cannot pass, and may then "fix" a *correct* implementation to make it fail.

Reproducing the two-step form is still the right thing to write, for a reason
the spec does not give: `median * median` overflows `u64` once the median
exceeds 2^32, where the two-step form never forms that product.

**Pinned by:** `two_step_division_equals_one_step` and
`one_step_in_u64_would_overflow_where_two_step_does_not`.

---

## 12. `required_version` below the first fork is 7, not 1 — and genesis depends on it

**Spec:** `06-consensus-rules.md` §1 gives block acceptance as

> `required = heights[current_fork_index].version` … `current_fork_index`
> advances via `get_voted_fork_index(height)`, which with `threshold == 0`
> reduces to "the highest index whose `height <= h`" — so for acceptance
> purposes `required` is the correct height-based version, including 7 for
> heights 1..6968.

**Reality:** at **height 0 no index qualifies**, and the spec does not say what
happens then. The C does:

```cpp
int HardFork::get_voted_fork_index(uint64_t height) const
{
  for (int n = heights.size() - 1; n >= 0; --n) {
    ...
    if (height >= heights[n].height && accumulated_votes >= threshold) return n;
  }
  return current_fork_index;            // <-- falls through to 0
}
```

`current_fork_index` is initialised to 0 and `heights[0]` is `{version 7,
height 1}` — **not** an `original_version` placeholder. `HardFork::init()` does
push such a placeholder, but only `if (heights.empty())`, and `Blockchain::init`
calls `add_fork` for the whole table *before* `init()`. So the placeholder is
never inserted and the floor is 7.

This is not cosmetic. Wownero's genesis block carries `major_version == 7` (the
blob begins `07 07 …`), and `do_check` compares the block version for
**equality**:

```cpp
return block_version == heights[current_fork_index].version
    && voting_version >= heights[current_fork_index].version;
```

An implementation that floors `required_version` at `original_version` (1), as
the surrounding text in §1 suggests, rejects its own genesis block.

Note this is the *opposite* of `get_ideal_version`, whose loop bound is `n > 0`
and which therefore really does return 1 below the first fork — that asymmetry
is §9.5, and it is correctly described. The two functions disagree at every
height in `0..6969`, for two different reasons.

**Found by:** the block headers in the weight corpus. `major_version` is 7 at
height 0, which `required_version` predicted as 1.

**Pinned by:** `genesis_is_below_every_fork` and
`the_hard_fork_table_matches_the_block_headers`.

---

## 13. Which hard-fork version the stored long-term weight uses

**Spec:** `06-consensus-rules.md` §3.4 writes `get_next_long_term_block_weight`
as `if hf < 13 { … }` without saying which height `hf` belongs to. §1's caveat
box flags the general hazard — "several places call
`get_current_hard_fork_version()` … where a reader would expect the version at
the block being validated" — but names only `get_difficulty_for_next_block` and
`check_fee`, not this.

**Reality:** for the block at height `h` it is the version of **`h` itself**,
and arriving at that takes two cancelling offsets.

1. `get_next_long_term_block_weight(block_weight)` is called *before*
   `m_db->add_block`, and `HardFork::add` — which advances the fork index — runs
   *inside* `add_block`. So the hard-fork state is one block behind: it last saw
   block `h - 1`.
2. But `HardFork::add(blk, height)` ends with
   `get_voted_fork_index(height + 1)`. Having last processed `h - 1`, the index
   already points at the fork covering `h`.

Neither offset is visible from §3.4, and taking either one alone gives the wrong
answer for exactly the blocks at a fork boundary — which is where a chain split
would start.

`update_next_cumulative_weight_limit` is the mirror image and is *consistent*
once the above is understood: it runs *after* `add_block` (the C comments "do
this after updating the hard fork state since the weight limit may change due to
fork"), so it sees the version of `h + 1` with a `db_height` of `h + 1` — the
next block's version, for the limit the next block must satisfy.

### What settles it

Only one hard fork on Wownero can tell the two readings apart, and it is not the
one you would reach for. HF 13 looks like the obvious test, but the HF 13-19
clamp is an *upper* bound at `ltem * 1.4`, and with the long-term median pinned
at its 300,000 floor that is 420,000 -- far above any Wownero block, which run
to a few tens of kilobytes. The clamp never binds, so both readings return the
raw block weight and the boundary is invisible. Replaying 170,000 blocks from
genesis crosses eight fork boundaries and **none of them discriminates**.

HF 20 does, because the 2021-scaling clamp adds a *lower* bound of
`ltem * 10 / 17 = 3_000_000 / 17 = 176_470`, which is above essentially every
Wownero block. The stored column therefore jumps, and the height it jumps at
names the version:

```text
513_999  v19  block_weight    95  ->  stored     95
514_000  v20  block_weight    96  ->  stored 176_470
514_001  v20  block_weight    96  ->  stored 176_470
```

Under the block's own version the jump is at 514,000. Under the previous
height's version it would be at 514,001. The chain says 514,000.

**Pinned by:** `the_hf20_switch_pins_which_version_applies`, which verifies that
`ltem` really is at its floor rather than assuming it, and
`the_stored_weight_uses_the_blocks_own_version`, which asserts that the earlier
boundaries agree *and* that the reason is the clamp not binding.

---

## 14. HF 20 also forbids *mixing* the two output types

**Spec:** `06-consensus-rules.md` §5.5 gives `check_output_types` as three
branches and calls the middle one out as "easy to miss":

```rust
} else {                                        // hf == 20 -- GRACE PERIOD
    require!(o.target is txout_to_key || o.target is txout_to_tagged_key);
}
```

**Reality:** the grace-period branch has a **second** assertion, which the spec's
pseudocode drops:

```cpp
else  //(hf_version == HF_VERSION_VIEW_TAGS)
{
  CHECK_AND_ASSERT_MES(o.target.type() == typeid(txout_to_key) || o.target.type() == typeid(txout_to_tagged_key), ...);

  // require all outputs in a tx be of the same type
  CHECK_AND_ASSERT_MES(o.target.type() == tx.vout[0].target.type(), false, "non-matching variant types: " ...);
}
```

Either type is legal at HF 20, but **not both inside one transaction**. An
implementation following §5.5 as written accepts a transaction the C++ rejects.

Mainnet is at HF 20, so this branch is the live one — the spec's own warning
("a node that requires view tags at HF 20 will reject valid blocks") applies in
the other direction too.

The clause exists only in the `hf == 20` branch. Above and below it the single
permitted type makes uniformity automatic, so there is nothing to check.

**Pinned by:** `hf20_forbids_mixing_the_two_output_types`.

---

## 15. The RingCT type gating is nine sequential gates, not a table

**Spec:** `06-consensus-rules.md` §5.10 presents the rule as eight lines of the
form "`hf < X`: type Y forbidden", which reads as an exhaustive table.

**Reality:** the C++ is a sequence of independent `if` blocks, and two of them
are missing from that table:

* **`hf > 11` forbids the old bulletproof types.**

  ```cpp
  // from v12, forbid old bulletproofs
  if (hf_version > 11) {
    if (tx.version >= 2) {
      const bool old_bulletproof = rct::is_rct_old_bulletproof(tx.rct_signatures.type);
  ```

  `is_rct_old_bulletproof` is types **3 and 4** — the two Wownero inserted into
  the numbering. §5.10's table forbids them only from `hf > 16` (via
  "types other than CLSAG-or-later"), leaving HF 12–16 open. No such
  transaction was ever made, so this cannot split a live chain, but the two
  implementations do differ.

* **`hf < 18` rejects on BP+ *proofs*, not only on the type.**

  ```cpp
  if (bulletproof_plus_legacy || !tx.rct_signatures.p.bulletproofs_plus.empty())
  ```

  A transaction claiming an older type while carrying BP+ proofs is caught by
  the second disjunct. A type-only table misses it.

Two further details the table form loses:

* gates 1–8 are each guarded by `tx.version >= 2`, so a v1 transaction skips
  them entirely; **the ninth is not guarded**, though it is inert for v1 because
  such a transaction carries `RCTTypeNull`;
* `rct::is_rct_bulletproof` **includes CLSAG**. The `hf > 18` gate forbids
  "Bulletproof range proofs", and CLSAG (7) carries them, so CLSAG is forbidden
  from HF 19 — not merely superseded. §5.10's summary line ("Current mainnet
  (HF 20): only `BulletproofPlus` (8)") is correct, but only the predicate's
  membership explains why.

**Pinned by:** `the_two_inserted_types_are_forbidden_only_from_hf12`,
`bulletproof_plus_proofs_are_gated_independently_of_the_type`,
`the_last_gate_applies_to_v1_too` and `hf20_permits_only_bulletproof_plus`.

---

## 16. `heed` cannot express this schema; the storage layer uses raw FFI

**Spec:** `10-storage-lmdb.md` §1 recommends `heed` 0.22 and lists the three
features the schema needs, with the `heed` API for each:

> | Need | `heed` API |
> |---|---|
> | `MDB_DUPSORT` / `MDB_DUPFIXED` | `DatabaseFlags::DUP_SORT` / `DUP_FIXED` |
> | `mdb_set_compare` | `.key_comparator::<C>()` |
> | `mdb_set_dupsort` | `.dup_sort_comparator::<C>()` |

**Reality:** all three are true, and they are not enough. Two operations the
schema depends on have no `heed` equivalent at all:

* **`MDB_GET_BOTH`.** Five tables store their logical key as a *prefix of the
  value* under one dummy key (§3.2), and §3.2 itself describes the lookup as
  "position the cursor at key `ZEROKEY`, then `MDB_GET_BOTH` with the
  value-prefix you are searching for". `heed`'s cursor exposes `MDB_SET` and
  `MDB_SET_RANGE` — both key operations. There is no value-positioning call, so
  the only way to find a record is to iterate the dup group: **O(n) over
  millions of records** for every `block_info`, `block_heights`, `tx_indices`,
  `output_txs` and `spent_keys` read. That is the hot path for ring
  verification.

* **`mdb_cursor_count`.** §5.1 defines `amount_index` as
  `mdb_cursor_count(output_amounts @ amount)`. §5.1 already anticipates the gap
  — "if it does not expose `mdb_cursor_count` directly, either drop to
  `lmdb-master-sys` for this one call or maintain the count in memory" — and the
  gap is real.

Neither can be worked around from outside the crate: `heed` keeps `MDB_dbi`
private (`pub(crate) dbi`) and exports no cursor type, so the raw handles needed
to call either function are unreachable.

Changing the layout to suit the binding is not an option — the M2 gate is that
`wownerod` opens a database this node wrote.

**Resolution:** the storage layer is built directly on **`lmdb-master-sys`**,
which §1 explicitly permits ("available if a raw-FFI port of `db_lmdb.cpp` turns
out to be easier for a specific table"). It is the crate `heed` itself builds
on, so this removes a dependency rather than adding one.

The cost is real and worth stating: `crates/wow-storage/src/raw.rs` is the only
`unsafe` code in the workspace outside the RandomWOW FFI (since replaced by Rust;
see §25). It is confined to one
module, every block carries a `SAFETY` note, and the borrow checker enforces
what §1.1 asks for in prose — a transaction borrows the environment, a cursor
borrows the transaction, and every returned `&[u8]` borrows the transaction, so
"never use a slice after commit" is a compile error rather than a convention.

`comparator.rs`, `records.rs`, `tables.rs` and `env.rs` were written
binding-agnostic and did not change.

**Pinned by:** `raw::tests::get_both_finds_a_zerokval_record_by_its_value_prefix`
and `raw::tests::cursor_count_gives_the_dup_group_size` — the two operations that
forced the decision — plus
`raw::tests::the_dupsort_comparator_is_installed`, which proves the callbacks
reach LMDB through the FFI boundary.

---

## 17. `key_data` is epee portable storage, not a binary archive

**Spec:** `12-wallet-core.md` §2.1.1 calls `key_data` "the binary-archive
serialization of `account_base`" and gives a flat layout:

> ```
> account_keys:
>     account_public_address  { [32] spend_public, [32] view_public }
>     [32] spend_secret_key
>     [32] view_secret_key
>     (multisig_keys: varint count + count * [32])   # only if multisig
> uint64 creation_timestamp
> ```

**Reality:** the writer is
`epee::serialization::store_t_to_binary(account, account_data)`
(`wallet2::get_keys_file_data`), so `key_data` is an **epee portable-storage**
blob driven by the `BEGIN_KV_SERIALIZE_MAP` in `account.h` — a nine-byte
signature, named entries, and a nested section for the address. Not the
consensus binary archive of `specs/04` §1, which is what the outer
`keys_file_data` container uses. Both formats appear in the same file, one
inside the other.

Two further differences in the same paragraph:

* **`m_encryption_iv` is missing from the spec's layout.** It is a member of
  `account_keys`, it is serialized (`KV_SERIALIZE_VAL_POD_AS_BLOB_OPT` with an
  all-zero default), and it is the IV the secret keys are encrypted under. A
  reader that does not pick it up decrypts the keys under the wrong IV.

* **`device_derivation_path` is not in `account_keys`.** §1.1 lists it on the
  struct. In this tree it is a `wallet2` member written to the keys file's JSON
  as `device_derivation_path`, and `account_keys` has no such field.

The actual member names, all of which the C++ reader looks up by name:

```
m_keys: {
  m_account_address: { m_spend_public_key, m_view_public_key },   # STRINGs
  m_spend_secret_key, m_view_secret_key,                          # STRINGs
  m_multisig_keys,        # one STRING, all keys concatenated, not an array
  m_encryption_iv,        # STRING, 8 bytes
}
m_creation_timestamp      # UINT64
```

**Pinned by:** `account::golden::the_key_data_layout`, which asserts the bytes
for a fixed account and decodes them in its own doc comment.

---

## 18. The keys file's JSON is not valid UTF-8

**Spec:** `12-wallet-core.md` §2.1 says `account_data` "decrypts to a **JSON
object**" and lists its members.

**Reality:** it decrypts to something that is JSON only in the sense rapidjson
means. `key_data` is a binary blob written into a JSON **string** with
`value.SetString(account_data.data(), account_data.size())`, and rapidjson's
writer escapes only the control characters, `"` and `\` — bytes `0x80`–`0xff`
pass through raw. So the plaintext contains byte sequences that are not valid
UTF-8, and any reader that requires UTF-8 either fails or, worse, substitutes
replacement characters and corrupts the key material.

The reference reads it back with rapidjson, which does not validate encoding
either, so the bytes survive the round trip.

**Resolution:** `keys_file.rs` transcodes Latin-1 in both directions — byte `n`
is character `n`. Every escape either writer produces is ASCII and every
character in the document is below `U+0100` by construction, so the round trip
is exact.

The same paragraph's advice to tolerate missing members is right and is
followed; this implementation goes further and keeps every member it does not
model, so rewriting a wallet written by the C++ does not reset settings it has
no opinion about.

**Pinned by:** `keys_file::tests::the_decrypted_json_is_not_utf8`, which asserts
that `String::from_utf8` on a file this code wrote fails, and that the transcode
round-trips; and `keys_file::tests::unknown_settings_survive_a_rewrite`.

---

## 19. The secret keys are encrypted under a *second* CryptoNight-derived key

**Spec:** `12-wallet-core.md` §2.1.1 says the secret keys inside `key_data` are
"themselves ChaCha20-encrypted with the same key (`account_base::encrypt_keys`)"
and tells the reader to "reproduce `encrypt_keys` / `decrypt_viewkey` exactly or
existing wallets will not open".

**Reality:** not the same key. `account.cpp`'s `get_key_stream` calls a static
`derive_key` first:

```cpp
static void derive_key(const crypto::chacha_key &base_key, crypto::chacha_key &key)
{
  ...
  data[sizeof(base_key)] = config::HASH_KEY_MEMORY;   // 'k'
  crypto::generate_chacha_key(data.data(), sizeof(data), key, 1);
}
```

`generate_chacha_key` is **CryptoNight v0**, so opening a wallet runs CryptoNight
twice: once over the password, once over the resulting key plus `'k'`. A reader
that uses the password key directly gets a key stream that is wrong but
well-formed, so the failure surfaces as keys that do not match their public keys
rather than as a decryption error.

Nearby and easy to confuse with it: `wallet2.cpp`'s `derive_cache_key` has the
same shape — 32 bytes plus one domain byte, 32 bytes out — but uses
`cn_fast_hash`, i.e. **Keccak**. `specs/02` §7 documents that one and not the
other. Three derivations, two hashes.

The stream layout is: spend key, then view key, then each multisig key, 32 bytes
apiece. `encrypt_viewkey` takes the **second** 32-byte slot and leaves the spend
key alone, which is how a wallet with `ask_password == AskPasswordToDecrypt`
keeps scanning while the spend key stays encrypted.

**Pinned by:** `chacha::tests::the_two_derivations_are_different_functions`,
`account::tests::the_viewkey_slot_is_the_second_one` and
`account::tests::encrypt_is_its_own_inverse`.

---

## 20. CLSAG's domain separators are 32-byte blocks, not strings

**Spec:** `02-crypto.md` §4.3 gives the hashes as

> ```
> mu_P  = hash_to_scalar("CLSAG_agg_0" || P_0..P_{n-1} || C_0..C_{n-1}
>                        || I || D_8 || C_offset)
> ```

with a note that the separators are "all without trailing NUL". That reads as
an 11-byte prefix followed by the keys.

**Reality:** the C hashes a vector of **32-byte keys** and writes the string
into the first element over zeros:

```cpp
keyV mu_P_to_hash(2*n+4);                       // domain, P, C, I, D, C_offset
sc_0(mu_P_to_hash[0].bytes);                    // 32 zero bytes
memcpy(mu_P_to_hash[0].bytes, config::HASH_KEY_CLSAG_AGG_0,
       sizeof(config::HASH_KEY_CLSAG_AGG_0) - 1);
```

So the hashed prefix is `"CLSAG_agg_0"` followed by **21 zero bytes** — 32 in
all — and the same for `CLSAG_agg_1` (11 bytes) and `CLSAG_round` (11 bytes).
The spec's "without trailing NUL" is accurate as far as it goes: the `- 1`
drops the NUL, so the string is not NUL-terminated *within* the block. What it
does not say is that there is a block.

The vector sizes in the C are the tell, and they are worth reading as an
independent check on the layout: `2*n+4` for the aggregation hashes (domain,
`n` dests, `n` masks, `I`, `D/8`, `C_offset`) and `2*n+5` for the round hash
(domain, `n` dests, `n` masks, `C_offset`, message, `L`, `R`). Both only add up
if the domain occupies a full key.

This is the failure mode where nothing looks wrong: an 11-byte prefix produces
signatures that verify against themselves and are rejected by every other
implementation, so a round-trip test passes and the chain does not.

`hash_to_scalar(keyV)` itself is plain concatenation — no length prefixes, no
separators between elements — so the block is the only framing there is.

**Pinned by:** `clsag::tests::the_domain_blocks_are_padded`, which asserts the
padding and that the three blocks differ, and
`clsag::tests::the_two_aggregation_scalars_differ`, which is what the domain
separation buys: if `mu_P` and `mu_C` were equal the key and commitment terms
would collapse into one and the signature would stop binding the amount.

---

## 21. The real spend is not placed at a random position in the ring

**Spec:** `12-wallet-core.md` §4.3 closes with:

> The real spend is placed at a uniformly random position in the sorted ring,
> and `key_offsets` are then converted to relative form.

Read literally that describes two steps: sort the ring, then move the real
output to a randomly chosen slot.

**Reality:** there is one step. `wallet2::get_outs` sorts the ring members by
global output index and stops:

```cpp
// sort the subsection, to ensure the daemon doesn't know which output is ours
std::sort(outs.back().begin(), outs.back().end(),
          [](const get_outs_entry &a, const get_outs_entry &b) {
            return std::get<0>(a) < std::get<0>(b);
          });
```

The real output lands wherever its index sorts to. No shuffle follows, and one
could not: the ring has to be ascending for the relative-offset encoding
(`specs/05` §2.1), so moving a member would either break the ordering or change
which outputs the ring names.

The spec's sentence is a fair description of the *effect* — the decoys come
from the gamma distribution, so the real output's rank among them is not
predictable — but a reader implementing it as written would either produce
rings that are not ascending, or "shuffle" and then re-sort, which is a no-op
that looks like a safeguard.

Worth stating plainly because a wrong guess here is invisible: a ring that is
sorted is correct, and a ring that has been shuffled and re-sorted is the same
ring. Neither fails. Only a ring that is *not* sorted fails, and it fails at
the daemon rather than in the wallet.

**Pinned by:** `decoys::tests::a_ring_is_well_formed`, which asserts the ring is
ascending, distinct, the right size, and reports the real member's position
correctly.


---

## 22. `NOTIFY_REQUEST_GET_OBJECTS` may ask for at most 100 blocks

**Spec:** `specs/08` §5.4 describes the block request and gives
`BLOCKS_SYNCHRONIZING_MAX_COUNT = 2,048` as the maximum, alongside a note to
align requests to the seed-hash epoch. `specs/01` §12.1 lists the same
constant. Nothing says how many blocks one request may name.

**Reality:** the responder caps a single request at a *different* constant,
which is not in `specs/01` at all:

```cpp
// src/cryptonote_protocol/cryptonote_protocol_handler.h
#define CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT 100

// src/cryptonote_protocol/cryptonote_protocol_handler.inl
if (arg.blocks.size() > CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT)
{
  LOG_ERROR_CCONTEXT("Requested objects count is too big ...");
  drop_connection(context, false, false);
  return 1;
}
```

`BLOCKS_SYNCHRONIZING_MAX_COUNT` bounds a *span* — how many blocks one peer is
assigned in the span queue — not how many one message may name. A span of 2,048
is fetched as at least 21 requests.

**Why it matters more than the number:** `drop_connection` closes the socket.
There is no Levin error code, no response, nothing on the wire. The 101st block
asked for produces an end-of-file on the next read, tens of seconds later,
after several batches have already succeeded. An implementation that grows its
batch size — 20, 40, 80, 160 — appears to work perfectly and then dies, and the
error it reports is `failed to fill whole buffer`, which names neither the
cause nor the message that caused it.

**Pinned by:** `wow_p2p::messages::MAX_OBJECT_REQUEST_COUNT`, used as the growth
ceiling in `sync::BatchSize::grow` and as the guard in `Peer::request_blocks`;
`sync::tests::the_batch_size_stays_within_its_bounds`.

---

## 23. The reference does not verify transactions below its embedded block hashes

**Spec:** `specs/06` §9 gives the transaction rules as unconditional, and
`specs/07` §6 treats the checkpoints as a cross-check on difficulty. Neither
says that the reference *skips* validation for most of the chain.

**Reality:** `PER_BLOCK_CHECKPOINT` is compiled in, and
`Blockchain::handle_block_to_main_chain` sets `fast_check` when the block's
height is covered by `m_blocks_hash_check` — the per-block hash table built
from the embedded `blocks.dat` — and the block's id matches the stored one:

```cpp
// src/cryptonote_core/blockchain.cpp
if (blockchain_height < m_blocks_hash_check.size())
{
  const auto &expected_hash = m_blocks_hash_check[blockchain_height].first;
  if (expected_hash != crypto::null_hash)
  {
    if (memcmp(&id, &expected_hash, sizeof(hash)) != 0) { /* reject */ }
    fast_check = true;
  }
}
```

`fast_check` then suppresses **both** remaining checks:

```cpp
if (!fast_check)
{
  ... proof_of_work = get_block_longhash(...);
  if (!check_hash(proof_of_work, current_diffic)) { /* reject */ }
}
...
#if defined(PER_BLOCK_CHECKPOINT)
if (!fast_check)
#endif
{
  tx_verification_context tvc;
  if (!check_tx_inputs(tx, tvc)) { /* reject */ }
}
```

and `check_tx_inputs` has its own earlier exit for the same reason:

```cpp
if (m_db->height() < m_blocks_hash_check.size() && kept_by_block)
{
  max_used_block_id = null_hash;
  max_used_block_height = 0;
  return true;
}
```

**This is load-bearing, not an optimisation.** Wownero mainnet contains blocks
that today's rules reject. Block 460 carries a transaction with ring size 12
(mixin 11) while `check_tx_inputs` requires mixin *exactly* 7 at hard-fork
version 7:

```cpp
|| ((hf_version == HF_VERSION_MIN_MIXIN_7 || hf_version == HF_VERSION_MIN_MIXIN_7+1)
    && min_actual_mixin != 7)
```

A node that validated every block from genesis would stop there. The reference
never does, because height 460 is inside `blocks.dat`. An implementation that
reads `specs/06` §9 as written and applies it to a from-genesis sync is not
being stricter than the reference — it is unable to sync the chain at all, and
the rule it trips over is one it copied correctly.

See `docs/cpp-findings.md` §14 for the related defect: the version those rules
are evaluated *at* is the chain tip's, not the block's.

**Pinned by:** `netsync::LocalChain`, which reproduces the bypass against the
hard-coded checkpoint list rather than an embedded hash file, and states the
difference at the point of use.

---

## 24. `/get_output_distribution.bin` requires `binary: true` in the *request*

**Spec:** `specs/11` §5.4 and `specs/12` §4.3 describe the call decoy selection
is built on, and list `amounts`, `from_height`, `to_height` and `cumulative`.
The `binary` field is documented as an output-format flag on the *response*.

**Reality:** it is a required input, and the binary endpoint refuses without
it:

```cpp
// src/rpc/core_rpc_server.cpp
bool core_rpc_server::on_get_output_distribution_bin(...)
{
  ...
  if (!req.binary)
  {
    res.status = "Binary only call";
    return false;
  }
```

It also changes the shape of the answer. With `binary: true`, `distribution`
is serialised `CONTAINER_POD_AS_BLOB` — one string of little-endian `u64`s —
rather than as an epee array:

```cpp
if (this_ref.binary)
{
  if (is_store)
  {
    if (this_ref.compress)
    {
      const_cast<std::string&>(this_ref.compressed_data) = compress_integer_array(this_ref.data.distribution);
      KV_SERIALIZE(compressed_data)
    }
    else
      KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(data.distribution, "distribution")
  }
  ...
}
else
  KV_SERIALIZE_N(data.distribution, "distribution")
```

**Why it is worth its own section:** this is the call that turns a wallet's
"I want to spend" into a ring. Without it there are no decoys, so there is no
transaction. And the failure is silent until the moment of sending — a wallet
syncs, shows a balance, and only fails when someone tries to move money.

It is also a case where being lenient was actively harmful. This node's own
`/get_output_distribution.bin` did not check the flag, so
`wow-daemon-client` sent `binary: false` and every test passed; the first real
daemon it met answered `Binary only call`. The handler now refuses the same
way, with the same wording, so the test suite can tell.

**Pinned by:** `wallet_sync::the_output_distribution_needs_the_binary_flag` and
`wallet_sync::the_client_gets_a_distribution_from_this_daemon`, plus
`wow-daemon-client`'s `tests/live_node.rs`, which runs against a real node on
demand.

---

## 25. RandomWOW changes more than `configuration.h` — and is now Rust

A RandomX whose `configuration.h` values are all parameterised, and set to
Wownero's, still gives a wrong hash for every block.

**Spec:** [`03-pow.md`](../specs/03-pow.md) §3 — "RandomWOW is RandomX compiled
with a Wownero-specific `configuration.h`. The algorithm structure (…) is
unmodified RandomX; only the parameters differ." §3.5 recommends FFI to the
pinned C++ library and accepts a pure-Rust RandomX "only if it is parameterised
… and passes the RandomWOW test vectors", as a later optimisation;
[`00-overview.md`](../specs/00-overview.md) §8 requires the submodule.

**Reference:** the fork (`codeberg.org/wownero/RandomWOW`, branch `1.2.1-wow`)
is upstream RandomX 1.2.1 plus one commit, `27b099b6` "RandomWOW parameters".
Besides `configuration.h`, its assembler copy, and `common.hpp`'s frequency sum
(which drops `IROL_R`, now 0), that commit changes `aes_hash.cpp`:

```cpp
-#define AES_GEN_4R_KEY0 0x99e5d23f, 0x2f546d2b, 0xd1833ddb, 0x6421aadd
+#define AES_GEN_4R_KEY0 0xcf359e95, 0x141f82b7, 0x7ffbe4a6, 0xf890465d
 ...                                     /* KEY1..3 likewise; KEY4..7 kept */
 	while (outptr < outputEnd) {
 		state0 = aesdec<softAes>(state0, key0);
 		state1 = aesenc<softAes>(state1, key0);
-		state2 = aesdec<softAes>(state2, key4);
-		state3 = aesenc<softAes>(state3, key4);
+		state2 = aesdec<softAes>(state2, key0);
+		state3 = aesenc<softAes>(state3, key0);
 		...                              /* rounds 2-4 likewise */
```

`AesGenerator4R` turns each program's seed into the program, so this changes
every program. RandomWOW uses its own keys 0-3, on all four lanes, where
upstream gives lanes 2 and 3 keys 4-7. The comment above the keys still derives
them as BLAKE2b-512 of `"RandomX AesGenerator4R keys 0-3"`; that is true of
upstream's values, not these, and the fork does not say where they come from.
The fork's `tests.cpp` also still expects upstream's hashes.

**Resolution:** `wow-randomwow` implements RandomX in Rust with every parameter
as data, the 4R keys included (`params::Config::aes_4r_keys`), and no longer
links the C++. The parameters and the algorithm are checked separately:

* under upstream's parameters it reproduces upstream RandomX's published hashes
  (`tests.cpp`, tests 1a-1e), which checks the algorithm;
* under Wownero's it reproduces nine hashes the C++ library computed before it
  was removed, which checks the parameters;
* real mainnet blocks satisfy their own difficulty, as before;
* the pieces are held to `tests.cpp`'s own vectors: the Argon2d Cache, the
  SuperscalarHash generator, Dataset items, `AesGenerator1R`,
  `randomx_reciprocal`, instruction decoding, and rounding in every mode.

Two things the C++ does cannot be copied directly:

* **Rounding modes.** `CFROUND` sets the CPU's rounding mode. Rust code assumes
  round-to-nearest throughout, so each operation is computed that way and then
  moved one step where the mode needs it. Which side the exact result lies on
  is found exactly: TwoSum for addition, a 128-bit mantissa comparison for
  multiplication, division and square root.
* **The JIT.** SuperscalarHash is compiled to x86-64 machine code, as the C++
  does. The VM is interpreted. A light-mode hash measured about 75 ms on a
  16-thread desktop, where the C++ took 19 ms with its JIT and 389 ms without
  it. To make up the difference, sync hashes each batch of blocks on every core
  before verifying them.

With the C++ gone, the builds, CI and release images need no CMake, Ninja or
C++ runtime.

**Pinned by:** `tests/randomx_vectors.rs`, `tests/wownero_vectors.rs` and
`tests/mainnet_pow.rs` in `wow-randomwow`;
`aes::tests::upstream_4r_keys_come_from_blake2b`; and
`jit::tests::running::*`, which holds the compiled SuperscalarHash to the
interpreter over generated programs and over every instruction with every
register pair.

---

## 26. `get_blocks.bin` answers from the block both sides have, and a start height beats the history

**Spec:** `specs/11` §5.1 lists `block_ids` and `start_height` in the request
without saying how they combine, and `specs/12` §3.1 has the daemon answer
from the short chain history. Neither says which block the answer starts at.

**Reality:** `Blockchain::find_blockchain_supplement` does two things a wallet
has to know:

```cpp
// src/cryptonote_core/blockchain.cpp
if(req_start_block > 0)
{
  if (req_start_block >= m_db->height())
    return false;
  start_height = req_start_block;
}
else
{
  if(!find_blockchain_supplement(qblock_ids, start_height))
    return false;
}
...
//we start to put block ids INCLUDING last known id, just to make other side be sure
starter_offset = split_height;
```

* A start height above zero wins, and the history is not read at all.
* Otherwise the history must end at genesis, and the answer starts **at** the
  newest block in it the daemon has: a block the wallet already holds.
  `wallet2::process_parsed_blocks` compares that block's hash and passes over
  it.

`on_get_blocks` answers a history whose newest hash is the top block with no
blocks at all, and `get_hashes.bin` uses the same split.

**Why it matters:** this node's `get_blocks.bin` answered one block past the
split and ignored `start_height` when there was a history, and `wow-wallet` was
written against it. Pointed at a C++ node, the wallet read the repeated block
as a reorg on every batch, detaching it and scanning it again. A wallet
restored above zero kept naming its restore height, so every call was answered
from there: the same blocks, forever. Neither showed against this node, which
agreed with the wallet.

**Pinned by:** `refresh::tests::the_block_a_daemon_repeats_is_not_a_reorg`,
`refresh::tests::a_restored_wallet_names_its_height_only_until_it_has_a_history`,
`wallet_sync::the_daemon_answers_from_the_short_chain_history`,
`wallet_sync::a_start_height_above_zero_is_taken_as_given`,
`wallet_sync::a_wallet_restored_above_zero_syncs_and_stays_synced`, and
`wow-daemon-client`'s
`live_node::a_second_batch_starts_at_the_last_block_of_the_first`.

---

## 27. The crate layout grew three crates and left two empty

`specs/00-overview.md` §4.1 lists twelve crates under `crates/`. The tree has
fifteen, and two of the twelve are empty.

**Added, each one replacing what would otherwise be a dependency:**

| crate | instead of |
|---|---|
| `wow-log` | `tracing`, for the C++'s `0`–`4` levels and `category:LEVEL` syntax |
| `wow-zmq` | `libzmq`, which is C++ and the thing this project exists not to link |
| `wow-tls` | `ring` or `aws-lc-rs` under `rustls`, both of which are C and assembly ([§25](#25-randomwow-changes-more-than-configurationh--and-is-now-rust) is the same story for RandomWOW) |

**Empty, and the work went elsewhere:**

`wow-rpc-types` and `wow-rpc-server` are still the placeholders §4.1 asks for.
The daemon's RPC is `bin/wownerod/src/rpc/`, because nothing but that one
binary serves it and a crate with a single caller buys nothing. The wallet
side's request and response types live with the client that parses them, in
`wow-daemon-client`, for the same reason: they are only ever constructed by it.

They are kept rather than deleted so the difference from the spec is visible
instead of silent. Deleting them would make the layout *look* like §4.1 with
none of §4.1's separation.

**Why it matters:** §4.1 opens the part of the spec people read before writing
anything, and a reader who takes it literally will go looking for the daemon's
RPC in an empty crate. It is also the section that quietly stopped being true
first: three of the four departures — `wow-log`, `wow-zmq`, `wow-tls` — came
from decisions about *dependencies*, not about layout, and nobody revisits a
layout section when choosing a crate.

**Pinned by:** nothing, and it cannot be — a layout is not a behaviour. The
README's layout listing names all fifteen and says which two are empty, which
is the nearest thing to a check there is.

---

## 28. `/get_transaction_pool_hashes.bin` is JSON, despite the suffix

**Spec:** `specs/11` §5 lists every path ending in `.bin` as epee portable
storage — "Body and response are **epee portable storage**" — and
`/get_transaction_pool_hashes.bin` is in that table.

**Reality:** it is the one exception. Of the nine `.bin` paths in the
reference's URI map, eight are `MAP_URI_AUTO_BIN2` and this one is not:

```cpp
// src/rpc/core_rpc_server.h
MAP_URI_AUTO_BIN2("/get_outs.bin",                   on_get_outs_bin,  ...)
MAP_URI_AUTO_BIN2("/get_output_distribution.bin",    on_get_output_distribution_bin, ...)
MAP_URI_AUTO_JON2("/get_transaction_pool_hashes.bin", on_get_transaction_pool_hashes_bin, ...)
```

`MAP_URI_AUTO_JON2` parses the request with `load_t_from_json` and renders the
answer with `store_t_to_json`, so a node answers this path in JSON and refuses
an epee request outright — `MAP_URI_AUTO_BIN2`'s sibling returns `400 Bad
Request` on a parse failure, and this one never sees epee as anything but
malformed JSON. `wallet2` matches it:

```cpp
// src/wallet/wallet2.cpp, update_pool_state_by_pool_query
bool r = epee::net_utils::invoke_http_json("/get_transaction_pool_hashes.bin", req, res, *m_http_client, rpc_timeout);
```

`invoke_http_json`, where every other `.bin` call in that file is
`invoke_http_bin`.

The answer is JSON with one field that is not: `tx_hashes` is a
`KV_SERIALIZE_CONTAINER_POD_AS_BLOB`, so the packed 32-byte hashes go inside a
JSON string as **raw bytes**, escaped only for `\b \f \n \r \t \v " \ /`
(`transform_to_escape_sequence`). The result is not valid UTF-8 and not valid
JSON, and only epee's own reader can read it back — a `\uXXXX` escape would not
do, because `match_string2` decodes one into UTF-8 and any byte above `0x7f`
would come back as two.

**Why it matters:** it cost this node a wallet. Routing by the `.bin` suffix
sent epee to a JSON caller, `wallet2` could not parse the reply, and it reports
a reply it cannot parse as `no_connection_to_daemon` — so a node that was
answering every other call correctly looked like a node that was not running,
on every refresh. It cost the wallet side too: `wow-daemon-client` asked for
this path in epee, which no C++ node would ever have answered.

**Pinned by:** `wow_daemon_client::DaemonClient::get_pool_hashes`, which now
asks `/get_transaction_pool_hashes` — the plain JSON endpoint beside it, which
sends hex strings an ordinary parser can read — and, on the node's side,
`wownerod::rpc::admin::pool_hashes_as_json` with
`methods::a_blob_field_is_escaped_the_way_epee_escapes_one`.
