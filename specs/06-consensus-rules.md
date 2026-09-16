# 06 — Consensus Rules

Source: `src/cryptonote_core/blockchain.cpp`,
`src/cryptonote_core/cryptonote_tx_utils.cpp`,
`src/cryptonote_basic/cryptonote_basic_impl.cpp`,
`src/cryptonote_basic/hardfork.cpp`, `src/cryptonote_core/tx_pool.cpp`.

This is the normative rule set. Every rule is gated on a **hard-fork version**,
obtained from the hard-fork table in [01 §3](01-constants.md) by height, never
from the block's own `major_version` alone (except where stated).

---

## 1. Hard-fork state machine

`src/cryptonote_basic/hardfork.cpp`.

Wownero activates forks **by height** with `threshold = 0`. The C++ still runs the
full voting machinery, but it reduces to a height lookup.

`HardFork` is constructed with `original_version = 1` and the table is appended in
ascending order by `add_fork`, which rejects out-of-order or duplicate entries.

```rust
/// HardFork::get_ideal_version(height). NOTE the `n > 0` bound: index 0 is
/// never examined, so a height below heights[1].height returns
/// original_version (= 1), NOT heights[0].version (= 7).
fn get_ideal_version(&self, height: u64) -> u8 {
    for n in (1..self.heights.len()).rev() {
        if height >= self.heights[n].height { return self.heights[n].version; }
    }
    self.original_version                     // 1
}
```

On mainnet that means `get_ideal_version(h) == 1` for every `h < 6969`, even
though those blocks all carry `major_version == 7`. Reproduce the off-by-one: the
function feeds `CORE_SYNC_DATA.top_version` in the P2P handshake
([08 §3.4](08-p2p.md)), the alt-chain block-template path, and the
`get_ideal_hard_fork_version(height) < 2` target selection in
`recalculate_difficulties` (harmless there, since both targets are 300).

Block acceptance is a **different** function — `HardFork::check` / `do_check`,
which uses `current_fork_index` (the index tracking the chain tip), *not*
`get_ideal_version`:

```
required = heights[current_fork_index].version
accept iff block.major_version == required
      && get_block_vote(block) >= required

where get_block_vote(b) = if b.minor_version == 0 { 1 } else { b.minor_version }
```

`current_fork_index` advances via `get_voted_fork_index(height)`, which with
`threshold == 0` reduces to "the highest index whose `height <= h`" — so for
acceptance purposes `required` is the correct height-based version, including 7 for
heights 1..6968.

Because `threshold == 0` the accumulated-vote condition in
`get_voted_fork_index` is satisfied immediately, so the vote tally never gates
anything and activation is purely height-based. Implement the height rule plus the
two checks above; a full vote-window implementation is not needed, but the two
checks **are** consensus.

The DB stores the applied version per height (`hf_versions`) so that a restart or
a reorg reproduces the same versions; see [10 §4.11](10-storage-lmdb.md).

> **Caveat that matters for validation order.** Several places in the C++ call
> `get_current_hard_fork_version()`, which reads as "the version at the current
> tip" but is not. `HardFork::add` advances it to the version of the *next*
> height as each block is stored, so while the block at height `H` is validated
> it returns the version at `H`. This affects `get_difficulty_for_next_block`
> (which picks the difficulty algorithm by it, see [07 §3](07-difficulty.md)),
> `check_fee` and `check_block_timestamp`. Reading the tip block's version
> instead picks the wrong difficulty algorithm on the first block of six
> mainnet forks (6969, 53,666, 63,469, 81,769, 331,170, 514,000).

---

## 2. Block validation order

`Blockchain::handle_block_to_main_chain`, with prechecks in `add_new_block`.
Order matters because some checks feed later ones.

1. **Have it already?** `have_block(id)` → reject as `already_exists`.
2. **Parent is the tip?** If `bl.prev_id != top_hash`, this is an alternative
   block → `handle_alternative_block` (§8).
3. **Hard fork check** — `HardFork::check(bl)` (§1).
4. **Timestamp** — `check_block_timestamp` (§2.1).
5. **Difficulty** — compute `next_difficulty` for this height (§[07](07-difficulty.md)).
6. **Proof of work** — unless a precomputed hash covers this height
   ([01 §14.1](01-constants.md#141-fast-sync-hash-file)), compute `pow_hash` and
   require `check_hash(pow, difficulty)`.
7. **Checkpoint** — if the height is checkpointed, the block hash MUST match.
8. **Coinbase prevalidation** — `prevalidate_miner_transaction` (§4).
9. **Transactions** — for each tx hash in `tx_hashes`, in order: fetch from the
   mempool or the pool supplement, then `check_tx_inputs` (§5) and the
   semantic checks. Any failure → reject the whole block and return the
   already-taken transactions to the pool.
   - A tx hash appearing twice in one block → reject.
   - A tx already in the chain → reject.
   - Key-image double spends **within the block** → reject. The C++ keeps a
     per-block `key_images_container keys` set, populated by `check_for_double_spend`
     as each transaction is accepted, so a key image may appear at most once
     across the whole block (and must not already be in `spent_keys`).
10. **Coinbase amount** — `validate_miner_transaction` (§3.3).
11. **Cumulative weight limit** — `cumulative_block_weight` MUST be
    `<= 2 * m_current_block_cumul_weight_median`; enforced indirectly through
    `get_block_reward` returning false when
    `current_block_weight > 2 * median_weight`.
12. **Commit** — write block, txs, outputs, key images, update
    `already_generated_coins`, cumulative difficulty, long-term weight, and the
    next weight limit — all atomically (§[10 §6](10-storage-lmdb.md)).

### 2.1 Timestamp rules

```
ftl    = if version >= 8 { 600 }  else { 7200 }         # seconds
window = if version >= 10 { 11 }  else { 60 }           # blocks
```

- `block.timestamp <= now + ftl` (uses wall-clock `time(NULL)`).
- If `chain_height >= window`: `block.timestamp >= median(last `window`
  timestamps)`.

`version` here is `get_current_hard_fork_version()` — the version at the height
being validated (§1).

### 2.2 Adjusted time

`get_adjusted_time(height)` — used for time-based unlock evaluation from HF 16:

```
if height < window: return now
ts = timestamps of blocks [height-window, height)
median_ts = median(ts) + (window + 1) * 300 / 2
adjusted  = ts.last() + 300
return min(adjusted, median_ts)
```

`window` is the same 11/60 value as §2.1. Note the hard-coded
`DIFFICULTY_TARGET_V2` (300), not a version-dependent target.

---

## 3. Emission and the coinbase amount

### 3.1 Base reward

`get_block_reward(median_weight, current_block_weight, already_generated_coins,
&reward, version)`:

```rust
let target = if version < 2 { 300 } else { 300 };   // both 300 on Wownero
let target_minutes = target / 60;                   // 5
let esf = EMISSION_SPEED_FACTOR_PER_MINUTE - (target_minutes - 1);   // 24 - 4 = 20

let mut base_reward = (MONEY_SUPPLY - already_generated_coins) >> esf;
if base_reward < FINAL_SUBSIDY_PER_MINUTE * target_minutes {          // 0
    base_reward = FINAL_SUBSIDY_PER_MINUTE * target_minutes;          // 0
}
```

`MONEY_SUPPLY = u64::MAX`, `FINAL_SUBSIDY_PER_MINUTE = 0` → **no tail emission**.
The subsidy decays geometrically by a factor of `1 - 2^-20` per block forever.

### 3.2 The block-weight penalty

```rust
let full_reward_zone = get_min_block_weight(version);        // 300_000 for v >= 5
let median_weight = max(median_weight, full_reward_zone);

if current_block_weight <= median_weight { return base_reward; }
if current_block_weight > 2 * median_weight { return Err(BlockTooBig); }

// 128-bit arithmetic, truncating division, applied TWICE
let multiplicand = (2 * median_weight - current_block_weight) * current_block_weight;
let product = (base_reward as u128) * (multiplicand as u128);
let reward = (product / median_weight as u128) / median_weight as u128;
```

The two successive `div128_64` calls are **not** the same as one division by
`median_weight^2` — each truncates. Reproduce the two-step division.

`multiplicand` is computed in 64-bit (`uint64_t multiplicand = 2*median - cur;
multiplicand *= cur;`) — a deliberate bug-fix comment in the C++ notes this was
once 32-bit-truncated on ARM. Use `u64` for `multiplicand`, then widen.

### 3.3 Coinbase amount validation

`validate_miner_transaction`:

```
money_in_use = sum(miner_tx.vout[*].amount)

if version == 3:                        # dead on Wownero (no v3 fork) but specified
    every output amount MUST be a "valid decomposed amount"

median_weight = if version >= 15 { m_current_block_cumul_weight_median }
                else { median(last 100 block weights) }

base_reward = get_block_reward(median_weight, cumulative_block_weight,
                              already_generated_coins, version)   # must succeed

reject if base_reward + fee < money_in_use              # overspend

if version < 2 || version >= HF_VERSION_EXACT_COINBASE (16):
    reject if base_reward + fee != money_in_use         # must claim exactly
else:                                                   # versions 2..15
    require money_in_use - fee <= base_reward
    if base_reward + fee != money_in_use { partial_block_reward = true }
    base_reward = money_in_use - fee                    # <-- affects emission!
```

The `else` branch matters historically: for HF versions 2–15 a miner could claim
*less* than the full reward, and the accounting then recorded only what was
claimed, permanently changing the emission curve. On Wownero this window is HF
7–15 (heights 1 … 253,998). `already_generated_coins` MUST accumulate the
**adjusted** `base_reward`, not the theoretical one:

```
already_generated_coins[h] = already_generated_coins[h-1] + base_reward_adjusted
```

(`Blockchain::handle_block_to_main_chain` passes `base_reward` — as mutated above —
into `m_db->add_block`.) Getting this wrong makes every subsequent reward wrong.

### 3.4 Block weight limits and long-term weight

`update_next_cumulative_weight_limit`, run after each block:

```rust
let hf = get_current_hard_fork_version();
let full_reward_zone = get_min_block_weight(hf);              // 300_000

if hf < HF_VERSION_LONG_TERM_BLOCK_WEIGHT (13) {
    m_current_block_cumul_weight_median = median(last 100 block weights);
} else {
    let nblocks = min(CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE /*100_000*/,
                      db_height);
    let ltm = long_term_block_weight_median(db_height - nblocks, nblocks);
    m_long_term_effective_median_block_weight =
        max(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 /*300_000*/, ltm);

    let stm = median(last 100 block weights);
    let effective = if hf >= HF_VERSION_2021_SCALING (20) {
        min(max(m_long_term_effective_median_block_weight, stm),
            50 * m_long_term_effective_median_block_weight)
    } else {
        min(max(300_000, stm), 50 * m_long_term_effective_median_block_weight)
    };
    m_current_block_cumul_weight_median = effective;
}

if m_current_block_cumul_weight_median <= full_reward_zone {
    m_current_block_cumul_weight_median = full_reward_zone;
}
m_current_block_cumul_weight_limit = m_current_block_cumul_weight_median * 2;
```

The long-term weight *stored for a block* (`get_next_long_term_block_weight`):

```rust
if hf < 13 { return block_weight; }
let ltm = long_term_block_weight_median(db_height - nblocks, nblocks);
let ltem = max(300_000, ltm);
let (block_weight, short_term_constraint) = if hf >= 20 {
    // clamp into [ltem/1.7, ltem*1.7]
    (max(block_weight, ltem * 10 / 17), ltem + ltem * 7 / 10)
} else {
    // clamp into [0, ltem*1.4]
    (block_weight, ltem + ltem * 2 / 5)
};
min(block_weight, short_term_constraint)
```

`long_term_block_weight_median(start, count)` is the median of the
**stored long-term weights** over that window — a separate DB column from the
block weight. It is *not* recomputable from block weights alone, so the column
must be persisted ([10 §4.2](10-storage-lmdb.md)).

**Median definition** (`epee::misc_utils::median`, `contrib/epee/include/misc_language.h`):

```rust
fn median(v: &mut Vec<u64>) -> u64 {
    if v.is_empty() { return 0; }
    if v.len() == 1 { return v[0]; }
    v.sort();                                  // full sort, not nth_element
    let n = v.len() / 2;
    if v.len() % 2 == 1 { v[n] }
    else { get_mid(v[n - 1], v[n]) }           // overflow-safe floor((a+b)/2)
}
// get_mid(a,b) = a/2 + b/2 + ((a % 2) + (b % 2)) / 2  ==  floor((a+b)/2)
```

Match this exactly; an off-by-one median shifts every reward.

---

## 4. Miner block-header signing (HF 18+) — Wownero-specific

`Blockchain::prevalidate_miner_transaction`, first block of the function. For
`hf_version >= HF_VERSION_BLOCK_HEADER_MINER_SIG (18)`:

1. `miner_tx.vout.len() == 1` — **exactly one** coinbase output.
2. `check_output_types(miner_tx, hf_version)` passes (§5.5).
3. `block.vote <= 2`.
4. Compute `sig_data` ([05 §4.4](05-blocks-and-transactions.md)).
5. Extract `P = output_public_key(miner_tx.vout[0])`.
6. `check_signature(sig_data, P, block.signature)` MUST pass
   ([02 §3.9](02-crypto.md)).

### 4.1 Why this enforces solo mining

The signing key is the **one-time secret key** of the coinbase output:

```
derivation = generate_key_derivation(tx_pub_key, view_secret_key)
x          = derive_secret_key(derivation, 0, spend_secret_key)
signature  = sign(sig_data, P, x)         # P = x*G = the coinbase output key
```

Producing it requires the miner's **private spend key**. A pool cannot sign on a
miner's behalf, and a miner cannot delegate hashing without handing over the
spend key. Consequently:

- `get_block_template` returns a template whose `signature` is zero, and
  `submit_block` on such a block **fails** `prevalidate_miner_transaction` at HF
  18+. RPC/stratum mining is dead on Wownero mainnet.
- `generateblocks` (regtest) explicitly sets `signature = {}` and `vote = 0`,
  which is only viable on `FAKECHAIN`.
- The built-in daemon miner takes `--spendkey <hex>` and derives the view key as
  `sc_reduce32(keccak(spendkey))` ([02 §3.2](02-crypto.md)).

### 4.2 Mining loop ordering

Because `signature` is inside the hashing blob, the loop is:

```
for nonce in start.. {
    block.nonce = nonce;
    if major_version >= 18 {
        block.signature = sign(get_sig_data(&block), P, x);
        block.vote = configured_vote;
    }
    if check_hash(pow_hash(&block), difficulty) { found!() }
}
```

Each attempt needs a fresh signature. (`src/cryptonote_basic/miner.cpp`, worker
loop.) A Rust miner MUST NOT hoist the signature out of the loop.

### 4.3 The vote field

`--vote yes` → 1, `--vote no` → 2, absent → 0. Any other string is a startup
error. `vote > 2` is rejected by consensus. The daemon RPC reports
`block_header.vote`; tallying is done off-chain by block explorers.

---

## 5. Coinbase and transaction validation

### 5.1 Coinbase prevalidation (all versions)

After the HF-18 signature block:

- `miner_tx.vin.len() == 1` and `vin[0]` is `txin_gen`.
- `miner_tx.version > 1 || hf_version < HF_VERSION_MIN_V2_COINBASE_TX (15)` —
  i.e. from HF 15 the coinbase MUST be v2.
- From HF 15 (`HF_VERSION_REJECT_SIGS_IN_COINBASE`): if `miner_tx.version >= 2`
  then `rct_signatures.type == Null`.
- `txin_gen.height == block height`.
- **Unlock time** (§5.1.1).
- `check_outs_overflow(miner_tx)` — the sum of output amounts must not overflow
  `u64`.
- `check_output_types(miner_tx, hf_version)` (§5.5).

#### 5.1.1 Coinbase unlock time

Three regimes:

```rust
if hf >= HF_VERSION_FIXED_UNLOCK (18) {
    require unlock_time == height + 288;              // CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_V2
} else if hf >= HF_VERSION_DYNAMIC_UNLOCK (16) {      // HF 16, 17
    let n = if mainnet { 1337 } else { 5 };
    let blk_id = get_block_id_by_height(height - n);
    // FIRST THREE hex characters of the block id, as printed by pod_to_hex
    let hex3 = &hex_lower(blk_id)[..3];
    let blk_num = u64::from_str_radix(hex3, 16).unwrap() * 2;   // 0 ..= 8190
    require unlock_time == height + blk_num + 288;    // 288 ..= 8478 blocks
} else {
    require unlock_time == height + 60;               // CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
}
```

`pod_to_hex` prints the 32 bytes in **storage order**, lowercase, so `hex3` is
the first one and a half bytes of `blk_id`. Reproduce that, not a byte-swapped
reading.

At 300 s/block, the HF 16–17 dynamic window ranged from 1 day to ~29 days; HF 18
fixed it at 288 blocks = 1 day.

### 5.2 Transaction semantic checks (`check_tx_semantic`, pre-input)

- At least one input.
- No duplicate key images inside the tx.
- `check_inputs_types_supported` — every input is `txin_to_key`.
- `check_outs_valid` — every output amount and target is well-formed; for v2,
  amounts MUST be 0.
- `check_money_overflow` — input and output sums do not overflow.
- For v1: `sum(inputs) >= sum(outputs)`; `fee = difference`.
- v1 only: the correct number of ring signatures.

### 5.3 Ring size rules (`check_tx_inputs`)

```rust
let min_mixin = if hf >= HF_VERSION_MIN_MIXIN_21 (9) { 21 } else { 7 };
```

For each `txin_to_key`, classify the referenced amount as *mixable* or
*unmixable*: amount 0 (RingCT) is always mixable; a non-zero amount is unmixable
iff `get_num_outputs(amount) <= min_mixin`.

Let `min_actual_mixin` / `max_actual_mixin` be the min/max of
`key_offsets.len() - 1` over all `txin_to_key` inputs.

```rust
// 1. constant ring size, from HF 15
if hf >= HF_VERSION_SAME_MIXIN (15) && min_actual_mixin != max_actual_mixin {
    reject;   // "varying ring size"
}

// 2. below-minimum is only allowed to spend unmixable pre-RingCT dust
if min_actual_mixin < min_mixin
   && !(hf == HF_VERSION_MIN_MIXIN_21 (9) && min_actual_mixin == 7)
{
    if n_unmixable == 0 { reject; }
    if n_mixable > 1   { reject; }
} else if (hf >  9 && min_actual_mixin > 21)
       || (hf == 9 && min_actual_mixin != 21 && min_actual_mixin != 7)  // grace
       || (hf <  9 && hf >= HF_VERSION_MIN_MIXIN_7 + 2 /*9*/ && min_actual_mixin > 7)
       || ((hf == 7 || hf == 8) && min_actual_mixin != 7)
{
    reject;   // "invalid ring size"
}
```

Net effect on current mainnet (HF 20): ring size is **exactly 22** for every
input, with no exceptions, since there are no unmixable outputs left in practice.

The third clause (`hf < 9 && hf >= 9`) is vacuous — it can never fire. Keep it as
written; it is harmless and copying it avoids introducing a difference.

### 5.4 Transaction version bounds

```
max_tx_version = if hf <= 3 { 1 } else { 2 }
min_tx_version = if n_unmixable > 0 { 1 }
                 else if hf >= HF_VERSION_ENFORCE_RCT (6) { 2 }
                 else { 1 }
reject if tx.version > max_tx_version || tx.version < min_tx_version
```

### 5.5 Output types

`check_output_types(tx, hf_version)` — `cryptonote_format_utils.cpp:1003`. Three
branches, and the middle one is easy to miss:

```rust
for o in &tx.vout {
    if hf_version > HF_VERSION_VIEW_TAGS {          // hf > 20
        require!(o.target is txout_to_tagged_key);  // 0x03 only
    } else if hf_version < HF_VERSION_VIEW_TAGS {   // hf < 20
        require!(o.target is txout_to_key);         // 0x02 only
    } else {                                        // hf == 20 -- GRACE PERIOD
        require!(o.target is txout_to_key || o.target is txout_to_tagged_key);
    }
}
```

**Mainnet is currently at HF 20, so both output types are legal on the tip right
now.** A node that requires view tags at HF 20 will reject valid blocks. The
wallet *produces* tagged keys from HF 20 (`construct_miner_tx` and
`construct_tx_with_tx_key` use `use_view_tags = hf >= HF_VERSION_VIEW_TAGS`), but
validation accepts either until HF 21.

### 5.6 Minimum outputs

From `HF_VERSION_MIN_2_OUTPUTS (15)`, a v2 transaction MUST have
`vout.len() >= 2`. (Coinbase is exempt; it is validated separately and from HF 18
must have exactly 1.)

### 5.7 Sorted inputs

From HF 7 (i.e. always), key images MUST be **strictly decreasing** when compared
as raw bytes with `memcmp`:

```
for consecutive txin_to_key inputs a, b:  memcmp(b.k_image, a.k_image) < 0
```

(The C++ rejects when `memcmp(current, last) >= 0`.)

### 5.8 Minimum output age

From `HF_VERSION_ENFORCE_MIN_AGE (15)`:

```
max_used_block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE (4) <= chain_height
```

where `max_used_block_height` is the greatest height among all referenced ring
members.

### 5.9 Unlock-time evaluation for referenced outputs

Each referenced output carries an `unlock_time` (from its own transaction);
`is_tx_spendtime_unlocked`:

```rust
if unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER (500_000_000) {
    // height-based
    (db_height - 1) + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS (1) >= unlock_time
} else {
    // time-based
    let now = if hf >= HF_VERSION_DETERMINISTIC_UNLOCK_TIME (16) {
        get_adjusted_time(db_height)      // §2.2
    } else {
        wall_clock_now()
    };
    now + (if hf < 2 { 300 } else { 300 }) >= unlock_time
}
```

Switching from wall-clock to `get_adjusted_time` at HF 16 is what makes unlock
evaluation deterministic across nodes — before that, two nodes could disagree.

### 5.10 RingCT type gating

`check_tx_inputs` (around the type checks):

```
hf <  HF_VERSION_SMALLER_BP (13):        Bulletproof2 (6) forbidden
hf >  HF_VERSION_SMALLER_BP (13):        Bulletproof (5)  forbidden
hf <  HF_VERSION_CLSAG (16):             Clsag (7) forbidden
hf >  HF_VERSION_CLSAG (16):             types other than CLSAG-or-later forbidden
hf <  HF_VERSION_BULLETPROOF_PLUS (18):  BulletproofPlus (8) forbidden
hf >  HF_VERSION_BULLETPROOF_PLUS (18):  Bulletproof range proofs forbidden
hf <  HF_VERSION_BP_PLUS_FULL_COMMIT (21): BulletproofPlusFullCommit (9) forbidden
hf >  HF_VERSION_BP_PLUS_FULL_COMMIT (21): BulletproofPlus (8) legacy forbidden
```

Note the `>` (strictly greater) comparisons: HF 13 permits both 5 and 6, HF 16
permits both 6 and 7, HF 18 permits both 7 and 8, HF 21 permits both 8 and 9.
That is exactly why the "gate" forks 14, 17, 19 exist — they close the window one
block-height range later.

**Current mainnet (HF 20): only `BulletproofPlus` (8).**

### 5.11 Signature verification

- v1: `check_ring_signature(tx_prefix_hash, k_image, ring_pubkeys, sigs)` per
  input.
- v2 with CLSAG or BP+: `verRctNonSemanticsSimple` (the CLSAGs) plus
  `verRctSemanticsSimple` (range proofs, commitment sum, fee).
- Commitment sum: `sum(pseudoOuts) == sum(outPk masks) + txnFee * H`, with the
  `scalarmult8` convention from [02 §4.4](02-crypto.md).
- The result cache (`m_rct_ver_cache`) is a performance optimisation only; the
  `rct_cache_type` warning at `HF_VERSION_BP_PLUS_FULL_COMMIT` is cosmetic.

### 5.12 Double spends

- A key image already in the chain (`spent_keys`) → reject.
- A key image twice within one block → reject.
- A key image twice within one tx → reject (§5.2).

---

## 6. Fees

### 6.1 `get_dynamic_base_fee(block_reward, median_block_weight, version)`

```rust
let min_block_weight = get_min_block_weight(version);       // 300_000
let median_block_weight = max(median_block_weight, min_block_weight);

if version >= HF_VERSION_PER_BYTE_FEE (12) {
    // 128-bit: lo = block_reward * 3000
    let mut v = (block_reward as u128) * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT as u128;
    v /= median_block_weight as u128;
    if version >= HF_VERSION_2021_SCALING (20) {
        v /= median_block_weight as u128;
        let mut lo = v as u64;            // asserts hi == 0
        lo -= lo / 20;                    // * 0.95
        return if lo == 0 { 1 } else { lo };
    } else {
        v /= min_block_weight as u128;
        let lo = v as u64;
        return lo / 5;                    // * 0.2
    }
}

// pre-HF-12, per-kB
let fee_base = if version >= 5 { DYNAMIC_FEE_PER_KB_BASE_FEE_V5 /*400_000_000*/ }
               else { DYNAMIC_FEE_PER_KB_BASE_FEE /*2_000_000_000*/ };
let unscaled = fee_base * min_block_weight / median_block_weight;
let lo = ((unscaled as u128 * block_reward as u128)
          / DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD as u128) as u64;
let mask = 1000;                             // get_fee_quantization_mask()
(lo + mask - 1) / mask * mask                // round up
```

Every division truncates; the order of divisions is load-bearing.

### 6.2 `check_fee(tx_weight, fee)`

```rust
let version = get_current_hard_fork_version();
let mut median = 0; let mut base_reward = 0;
if version >= HF_VERSION_DYNAMIC_FEE (4) {
    median = m_current_block_cumul_weight_limit / 2;
    let agc = if h > 0 { already_generated_coins(h - 1) } else { 0 };
    base_reward = get_block_reward(median, 1, agc, version)?;   // note: weight = 1
}

let needed_fee = if version >= HF_VERSION_PER_BYTE_FEE (12) {
    let m = if version >= HF_VERSION_LONG_TERM_BLOCK_WEIGHT (13) {
        min(median, m_long_term_effective_median_block_weight)
    } else { median };
    let fee_per_byte = get_dynamic_base_fee(base_reward, m, version);
    let raw = tx_weight * fee_per_byte;
    (raw + 999) / 1000 * 1000                    // quantize up to 8 decimals
} else {
    let fee_per_kb = if version < HF_VERSION_DYNAMIC_FEE (4) { FEE_PER_KB }
                     else { get_dynamic_base_fee(base_reward, median, version) };
    let mut kb = tx_weight / 1024;
    if tx_weight % 1024 != 0 { kb += 1; }
    kb * fee_per_kb
};

// 2% acceptance buffer
fee >= needed_fee - needed_fee / 50
```

`check_fee` is a **mempool/block-acceptance** rule and uses the *tip's* hard-fork
version and the *current* medians. It is therefore not a pure function of the
block being validated; reproduce the call sites.

### 6.3 Relay-only policy (not consensus)

Enforced in `tx_pool::add_tx` only when `!kept_by_block` — i.e. for transactions
arriving from the network or RPC, never for transactions inside a block:

- `tx.extra.len() <= MAX_TX_EXTRA_SIZE (1060)` → else `tx_extra_too_big`.
- `tx.unlock_time == 0` → else `nonzero_unlock_time`. **Wownero refuses to relay
  any transaction with a non-zero unlock time**, but such a transaction is still
  valid inside a block.
- Key images not already spent → else `double_spend`.
- `check_fee` → else `fee_too_low`.
- `tx_weight <= CRYPTONOTE_MAX_TX_SIZE (1_000_000)` → else `too_big`.

All of these set `no_drop_offense`, meaning the sending peer is not penalised.

### 6.4 Fee estimate for wallets

`get_dynamic_base_fee_estimate(grace_blocks)` returns a per-byte fee; from HF 20
it returns **four** values (the 2021 scaling tiers) via
`get_dynamic_base_fee_estimate_2021_scaling`:

```rust
let Mfw = min(Mnw, Mlw);          // Mnw = next weight median, Mlw = long-term median
let Fl = base_reward * 3000 / (Mfw * Mfw);
let Fn = 4 * base_reward * 3000 / (Mfw * Mfw);
let Fm = 16 * base_reward * 3000 / (300_000 * Mfw);
let Fh = max(4 * Fm, 4 * Fm * Mfw / (32 * 3000 * Mnw / 300_000));
fees = [round_money_up(Fl, 2), round_money_up(Fn, 2),
        round_money_up(Fm, 2), round_money_up(Fh, 2)];
```

`round_money_up(v, places)` keeps the `places` most significant decimal digits and
rounds up. These map to wallet priorities 1..4 (low/normal/medium/high).

---

## 7. Reorganisation

`Blockchain::switch_to_alternative_blockchain`:

1. Compute the alt chain's cumulative difficulty. Switch only if it **strictly
   exceeds** the main chain's.
2. Pop main-chain blocks down to the split point, collecting their transactions.
3. Add the alt-chain blocks in order. If any fails, roll back: re-add the
   original main chain blocks and mark the offending alt block invalid.
4. Return the popped main-chain transactions to the mempool with
   `kept_by_block = true` (so policy rules from §6.3 do not reject them).
5. Re-add the now-orphaned blocks to the alternative-blocks store.
6. Recompute the difficulty and weight caches, and reset
   `m_timestamps_and_difficulties_height` so the cached difficulty window is
   rebuilt.
7. Update the RandomWOW main seed hash for the new tip
   ([03 §3.4](03-pow.md)).

Reorg depth is bounded by the checkpoint rule: a block below the last hard
checkpoint can never be reorged out.

---

## 8. Alternative blocks

`Blockchain::handle_alternative_block`:

- Reject if the block's height is at or below the last checkpoint and its hash
  does not match.
- Build the alt chain by walking `prev_id` through `m_alt_blocks` and then into
  the main chain to find the split point.
- Timestamp check against the alt chain's own median window.
- Difficulty: `get_next_difficulty_for_alternative_chain` — the same algorithms,
  fed with the alt chain's timestamps and cumulative difficulties.
- PoW: for `major_version >= RX_BLOCK_VERSION` use `get_altblock_longhash` with
  the seed hash resolved along the alt chain; otherwise `get_block_longhash`.
- Store in `alt_blocks` with `alt_block_data_t { height, cumulative_weight,
  cumulative_difficulty_low/high, already_generated_coins }`.
- If the alt chain's cumulative difficulty exceeds the main chain's, reorg (§7).

---

## 9. Inherited quirks that are now consensus

**Reproduce all of these.** Each one is a potential chain split.

### 9.1 Hard-coded difficulty overrides

`next_difficulty_v5` returns fixed values at six specific mainnet heights
(307,686 / 307,692 / 307,735 / 307,742 / 307,750 / 307,766), and several
algorithms have "reset" windows. Full list: [07 §4](07-difficulty.md).

### 9.2 The height 202,612 proof-of-work override

`get_block_longhash` returns a hard-coded hash at `height == 202612`
regardless of block content (a Monero artifact for a 514-tx block that broke the
original `tree_hash_cnt`). Full analysis and its interaction with fast-sync:
[03 §5](03-pow.md#5-the-height-202612-override).

### 9.3 Partial block rewards changed the emission curve

HF 7–15 allowed under-claiming the coinbase; `already_generated_coins` recorded
the claimed amount. §3.3.

### 9.4 `get_current_hard_fork_version()` is the next block's version, not the tip's

`BlockchainDB::add_block` ends with `m_hardfork->add(blk, height)`, and
`HardFork::add` moves to `get_voted_fork_index(height + 1)`. So while the block
at height `H` is validated, the "current" version is the one at `H`. It selects
the difficulty algorithm and window, the timestamp window and future limit, and
`check_fee`. Reading the tip block's version (`H - 1`) instead picks the wrong
difficulty algorithm on the first block of six mainnet forks: 6969, 53,666,
63,469, 81,769, 331,170 and 514,000. `tests/corpus/difficulty` pins all six.
§1.

### 9.5 `get_ideal_version` skips table index 0

Returns `original_version = 1` for heights below the *second* fork's height, not
`heights[0].version = 7`. §1.

### 9.6 The vacuous ring-size clause

`hf < 9 && hf >= 9` in §5.3 can never be true. Keep it.

### 9.7 `RCTTypeBulletproofPlus` stores commitments divided by 8

And `RCTTypeBulletproofPlus_FullCommit` (HF 21, testnet only) does not.
[02 §4.4](02-crypto.md#44-bulletproofs).

### 9.8 Two-step division in the reward penalty

`(x / m) / m`, not `x / (m*m)`. §3.2.

### 9.9 `pod_to_hex(...).substr(0,3)` for the dynamic coinbase unlock

Reads 1.5 bytes of hex text, not an integer. §5.1.1.

---

## 10. Conformance checklist

- [ ] Hard-fork version comes from the height table; `major_version` MUST equal
      the required version and `get_block_vote(b) >= required`.
- [ ] `already_generated_coins` accumulates the **adjusted** base reward.
- [ ] The reward penalty uses two successive truncating divisions.
- [ ] `median()` on even-length input is `(v[n/2-1] + v[n/2]) / 2`, integer.
- [ ] Long-term block weights are persisted, not recomputed.
- [ ] HF 18+: exactly one coinbase output, `vote <= 2`, valid header signature
      over `sig_data`.
- [ ] The miner re-signs the header for every nonce.
- [ ] Coinbase unlock time matches the three-regime rule, including the
      `pod_to_hex().substr(0,3)` reading at HF 16–17.
- [ ] Ring size is exactly 22 at HF ≥ 9 (with the documented exceptions).
- [ ] Output type: `txout_to_key` only below HF 20, **either** at exactly HF 20,
      `txout_to_tagged_key` only above HF 20.
- [ ] Key images strictly decreasing by `memcmp`.
- [ ] Unlock evaluation uses `get_adjusted_time` from HF 16.
- [ ] RCT type gating uses the `<` / `>` comparisons of §5.10 verbatim.
- [ ] Relay-only rules (tx_extra size, non-zero unlock time) are **not** applied
      to transactions inside blocks.
- [ ] Reorg requires strictly greater cumulative difficulty and returns popped
      txs to the pool with `kept_by_block = true`.
- [ ] Every quirk in §9 is reproduced.
