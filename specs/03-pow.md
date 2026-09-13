# 03 — Proof of Work

Source of truth: `src/cryptonote_core/cryptonote_tx_utils.cpp`
(`get_block_longhash`, `get_altblock_longhash`), `src/crypto/rx-slow-hash.c`,
`src/crypto/hash-ops.h`, `src/cryptonote_basic/difficulty.cpp`, and the
`RandomWOW` submodule at commit `27b099b6dd6fef6e17f58c6dfe00009e9c5df587`
(branch `1.2.1-wow`).

## 1. The PoW input

The hashed input is always the **block hashing blob**
(see [05 §4.3](05-blocks-and-transactions.md)):

```
blob = serialize(block_header)           # includes signature+vote from HF 18
     || tx_tree_root_hash                # 32 bytes
     || varint(tx_hashes.len() + 1)
```

Note this is the **same blob** used to compute the block id. The block id and the
PoW hash differ only in the hash function applied to it.

## 2. Algorithm selection by block major version

From `get_block_longhash`:

```rust
fn pow_hash(blob: &[u8], height: u64, major_version: u8, seed_hash: &Hash256)
    -> Hash256
{
    // MUST come first: see §5
    if height == 202_612 {
        return hex!("84f64766475d51837ac9efbef1926486e58563c95a19fef4aec3254f03000000");
    }
    if major_version >= RX_BLOCK_VERSION /* 13 */ {
        randomwow(seed_hash, blob)
    } else {
        let variant = if major_version >= 11 { 4 }
                      else if major_version >= 9 { 2 }
                      else { 1 };
        cn_slow_hash(blob, variant, height)
    }
}
```

| Block major version | Heights (mainnet) | Algorithm |
|---|---|---|
| 7, 8 | 1 – 53,665 | CryptoNight **variant 1** |
| 9, 10 | 53,666 – 81,768 | CryptoNight **variant 2** |
| 11, 12 | 81,769 – 114,968 | CryptoNight **variant 4** (a.k.a. CryptoNightR / "cn/wow") |
| ≥ 13 | 114,969 – tip | **RandomWOW** |

A node that only ever syncs from a checkpointed snapshot can stub the
CryptoNight branches, but a node that verifies from genesis
(`--fast-block-sync 0`) needs all of them. See
[06 §9.2](06-consensus-rules.md#92-the-height-202612-proof-of-work-override).

`cn_slow_hash` variant 4 takes `height` as an input (it derives a per-block
random program from `height`), so the signature must carry it.

## 3. RandomWOW

RandomWOW is RandomX compiled with a Wownero-specific `configuration.h`. The
algorithm structure (Argon2d cache fill, superscalar dataset generation, VM
execution, Blake2b/AES finalisation) is unmodified RandomX; only the parameters
differ.

### 3.1 Parameters — MUST match exactly

```c
RANDOMX_ARGON_MEMORY        262144        /* KiB -> 256 MiB cache */
RANDOMX_ARGON_ITERATIONS    3
RANDOMX_ARGON_LANES         1
RANDOMX_ARGON_SALT          "RandomWOW\x01"     /* <-- differs from RandomX */
RANDOMX_CACHE_ACCESSES      8
RANDOMX_SUPERSCALAR_LATENCY 170
RANDOMX_DATASET_BASE_SIZE   2147483648
RANDOMX_DATASET_EXTRA_SIZE  33554368
RANDOMX_PROGRAM_SIZE        256
RANDOMX_PROGRAM_ITERATIONS  1024          /* RandomX: 2048 */
RANDOMX_PROGRAM_COUNT       16            /* RandomX: 8    */
RANDOMX_SCRATCHPAD_L3       1048576       /* 1 MiB; RandomX: 2 MiB */
RANDOMX_SCRATCHPAD_L2       131072
RANDOMX_SCRATCHPAD_L1       16384
RANDOMX_JUMP_BITS           8
RANDOMX_JUMP_OFFSET         8
```

Instruction frequencies (out of 256 per slot):

```c
RANDOMX_FREQ_IADD_RS   25   /* RandomX: 16 */
RANDOMX_FREQ_IADD_M     7
RANDOMX_FREQ_ISUB_R    16
RANDOMX_FREQ_ISUB_M     7
RANDOMX_FREQ_IMUL_R    16
RANDOMX_FREQ_IMUL_M     4
RANDOMX_FREQ_IMULH_R    4
RANDOMX_FREQ_IMULH_M    1
RANDOMX_FREQ_ISMULH_R   4
RANDOMX_FREQ_ISMULH_M   1
RANDOMX_FREQ_IMUL_RCP   8
RANDOMX_FREQ_INEG_R     2
RANDOMX_FREQ_IXOR_R    15
RANDOMX_FREQ_IXOR_M     5
RANDOMX_FREQ_IROR_R    10   /* RandomX: 8 */
RANDOMX_FREQ_IROL_R     0   /* RandomX: 2 */
RANDOMX_FREQ_ISWAP_R    4
RANDOMX_FREQ_FSWAP_R    8   /* RandomX: 4  */
RANDOMX_FREQ_FADD_R    20   /* RandomX: 16 */
RANDOMX_FREQ_FADD_M     5
RANDOMX_FREQ_FSUB_R    20   /* RandomX: 16 */
RANDOMX_FREQ_FSUB_M     5
RANDOMX_FREQ_FSCAL_R    6
RANDOMX_FREQ_FMUL_R    20   /* RandomX: 32 */
RANDOMX_FREQ_FDIV_M     4
RANDOMX_FREQ_FSQRT_R    6
RANDOMX_FREQ_CBRANCH   16   /* RandomX: 25 */
RANDOMX_FREQ_CFROUND    1
RANDOMX_FREQ_ISTORE    16
RANDOMX_FREQ_NOP        0
```

The frequencies MUST sum to 256. **Using upstream RandomX defaults produces
valid-looking hashes that fail every difficulty check on the real chain.**

### 3.2 Seed hash epochs

`src/crypto/rx-slow-hash.c`:

```c
#define SEEDHASH_EPOCH_BLOCKS  2048    /* == BLOCKS_SYNCHRONIZING_MAX_COUNT */
#define SEEDHASH_EPOCH_LAG       64
```

```rust
pub fn rx_seedheight(height: u64) -> u64 {
    if height <= (SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG) as u64 {  // <= 2112
        0
    } else {
        (height - SEEDHASH_EPOCH_LAG as u64 - 1) & !((SEEDHASH_EPOCH_BLOCKS - 1) as u64)
    }
}

/// (current seed height, next seed height)
pub fn rx_seedheights(height: u64) -> (u64, u64) {
    (rx_seedheight(height),
     rx_seedheight(height + SEEDHASH_EPOCH_LAG as u64))
}
```

The **seed hash** for a block at `height` is the **block id at
`rx_seedheight(height)`** — i.e. the block hash, not the PoW hash.

Both env-var overrides in the C++ (`SEEDHASH_EPOCH_LAG`,
`SEEDHASH_EPOCH_BLOCKS`, constrained to powers of two ≤ the defaults) exist for
testing only and MAY be omitted; if implemented they MUST NOT be settable on
mainnet.

For the **genesis block** the C++ passes `pbc == NULL`, in which case the seed
hash is all zeros.

### 3.3 Alternative-chain blocks

`get_altblock_longhash(block, seed_hash)` hashes the same blob with an explicitly
supplied seed hash, because an alt block's seed height may resolve to a block
that is not on the main chain. When validating an alt block the node computes the
seed hash by walking the **alt chain** back to `rx_seedheight(alt_height)`,
falling back to the main chain when the alt chain is shorter than that
(`Blockchain::handle_alternative_block`, around the `RX_BLOCK_VERSION` check).

### 3.4 VM/dataset lifecycle

The C++ keeps two seeds live: a **main** seed (with a full 2 GiB dataset, built in
a background thread) and a **secondary** seed (light mode, cache only). A Rust
implementation SHOULD do the same:

- `rx_set_main_seedhash(seed, threads)` is called on every chain tip change with
  `get_block_id_by_height(rx_seedheight(height))`. If the seed is unchanged it is
  a no-op. Otherwise: allocate/initialise the cache immediately (so hashing can
  continue in light mode) and rebuild the dataset in the background.
- Hashing with a seed that is neither main nor secondary promotes it to
  secondary, serialised under a mutex (200–500 ms per switch). During deep reorgs
  or historical verification this is the slow path; batching blocks by seed epoch
  turns it back into the fast path. **Sync SHOULD request blocks in
  `SEEDHASH_EPOCH_BLOCKS`-aligned batches for exactly this reason** — that is why
  `BLOCKS_SYNCHRONIZING_MAX_COUNT == 2048`.
- Flags: full-memory (dataset) mode is opt-in via `MONERO_RANDOMX_FULL_MEM`;
  large pages are attempted and silently fall back. JIT is enabled with
  `RANDOMX_FLAG_SECURE` for non-miner threads. A Rust node MAY choose its own
  defaults; these flags do not affect the hash output.

### 3.5 Implementation route

Recommended: FFI to the pinned `RandomWOW` C++ library.

```
third_party/randomwow/         # submodule, branch 1.2.1-wow, pinned commit
crates/wow-randomwow/build.rs  # cmake -> librandomx.a, bindgen or hand-written extern "C"
```

Required surface:

```rust
extern "C" {
    fn randomx_alloc_cache(flags: u32) -> *mut RandomxCache;
    fn randomx_init_cache(cache: *mut RandomxCache, key: *const u8, keysize: usize);
    fn randomx_alloc_dataset(flags: u32) -> *mut RandomxDataset;
    fn randomx_init_dataset(ds: *mut RandomxDataset, cache: *mut RandomxCache,
                            start: c_ulong, count: c_ulong);
    fn randomx_dataset_item_count() -> c_ulong;
    fn randomx_create_vm(flags: u32, cache: *mut RandomxCache,
                         dataset: *mut RandomxDataset) -> *mut RandomxVm;
    fn randomx_vm_set_cache(vm: *mut RandomxVm, cache: *mut RandomxCache);
    fn randomx_vm_set_dataset(vm: *mut RandomxVm, ds: *mut RandomxDataset);
    fn randomx_calculate_hash(vm: *mut RandomxVm, input: *const u8, len: usize,
                              out: *mut u8);
    fn randomx_destroy_vm(vm: *mut RandomxVm);
    fn randomx_release_cache(cache: *mut RandomxCache);
    fn randomx_release_dataset(ds: *mut RandomxDataset);
}
```

A pure-Rust RandomX is acceptable **only** if it is parameterised (the existing
Rust RandomX crates hard-code upstream constants) and passes the RandomWOW test
vectors. Treat it as a later optimisation, not a milestone-2 dependency.

## 4. The difficulty check

`src/cryptonote_basic/difficulty.cpp`. Difficulty is a **128-bit** unsigned
integer (`boost::multiprecision::uint128_t` → Rust `u128`).

A hash passes iff, treating the 32-byte hash as a **little-endian 256-bit
integer**:

```
hash_as_u256 * difficulty  <  2^256
```

equivalently `hash_as_u256 <= (2^256 - 1) / difficulty`.

The C++ has two implementations and picks between them:

```rust
pub fn check_hash(hash: &Hash256, difficulty: u128) -> bool {
    if difficulty <= u64::MAX as u128 {
        check_hash_64(hash, difficulty as u64)
    } else {
        check_hash_128(hash, difficulty)
    }
}
```

`check_hash_64` is a hand-rolled 64x64→128 multiply-with-carry chain;
`check_hash_128` promotes to 512 bits and tests
`hash_val * difficulty <= u256::MAX`. Both are equivalent to the single
statement above. In Rust:

```rust
pub fn check_hash(hash: &[u8; 32], difficulty: u128) -> bool {
    if difficulty == 0 { return false; }             // guard; see note
    let h = U256::from_little_endian(hash);
    let (prod, overflow) = h.overflowing_mul(U256::from(difficulty));
    // pass iff the 320-bit product fits in 256 bits
    !overflow && prod <= U256::MAX
}
```

Use a checked/widening multiply — `overflowing_mul` on `U256` is exactly the
"fits without overflow into the least significant 256 bits" condition the C++
comment describes.

> **Difficulty 0.** `next_difficulty*` can return 0 on overflow; the C++
> blockchain then errors with "difficulty overhead". Treat a computed difficulty
> of 0 as a validation failure for the block, not as "any hash passes".

## 5. The height 202,612 override

```c
if (height == 202612) {
  static const std::string longhash_202612 =
    "84f64766475d51837ac9efbef1926486e58563c95a19fef4aec3254f03000000";
  epee::string_tools::hex_to_pod(longhash_202612, res);
  return true;
}
```

This is a Monero artifact: Monero's block 202,612 contained 514 transactions and
triggered a bug in the original CryptoNote `tree_hash_cnt`. Wownero inherited the
workaround verbatim, **and it executes on Wownero's own height 202,612**, where
the block is a RandomWOW block (HF 15).

Consequences you must handle:

1. `pow_hash` MUST return this constant at height 202,612 regardless of the real
   block contents. Reproduce it.
2. As a 256-bit little-endian integer this hash is
   `0x34f2_5c3a...`, which passes `check_hash` only for difficulty ≤
   **1,297,898,660**. Wownero's average difficulty in the surrounding range
   (heights 160,777–253,999) is ≈ 3.39 × 10^9, so depending on the actual
   difficulty at that height, a from-genesis verification with
   `--fast-block-sync 0` may **reject** the block. The default fast-sync path
   covers height 202,612 via `checkpoints.dat`
   ([01 §14.1](01-constants.md#141-fast-sync-hash-file)) and never evaluates the
   PoW, which is why the reference node syncs fine.
3. Therefore: implement fast-block-sync (skip PoW where a precomputed hash
   exists) **before** attempting a full from-genesis verification, and treat
   "verify every PoW from genesis" as a diagnostic mode that is known to be
   unable to guarantee success at this one height.

Do not "fix" this by removing the override — a node that computes the real
RandomWOW hash at height 202,612 will disagree with the reference node about
whether that block is valid whenever PoW is actually checked.

## 6. Mining

See [09 §6](09-daemon.md). The essential PoW-side points:

- The miner varies `block.nonce` (a raw little-endian `u32` in the header).
- From HF 18 the miner MUST re-sign the header **after** setting the nonce and
  **before** hashing, because the signature is part of the hashing blob
  ([06 §4](06-consensus-rules.md)). This means each nonce attempt requires a
  fresh ed25519 signature — the miner cannot simply increment the nonce over a
  fixed blob. Reproduce that ordering.
- `find_nonce_for_given_block(gbh, block, difficulty, height, seed_hash)`
  increments `nonce` until `check_hash(pow, difficulty)`.

## 7. Conformance checklist

- [ ] The PoW input is the block **hashing blob**, including `signature` and
      `vote` from HF 18.
- [ ] `pow_hash` checks `height == 202612` **first**, before any version
      dispatch.
- [ ] RandomWOW is built with the §3.1 configuration; the instruction
      frequencies sum to 256 and match §3.1 exactly.
- [ ] `rx_seedheight` matches §3.2 including the `height <= 2112 => 0` case.
- [ ] The seed hash is the **block id** at the seed height.
- [ ] Genesis uses an all-zero seed hash.
- [ ] `check_hash` treats the hash as little-endian u256 and tests for a
      320-bit product that fits in 256 bits.
- [ ] A computed difficulty of 0 fails the block.
- [ ] CryptoNight variants 1, 2 and 4 are available for historical verification;
      variant 4 receives `height`.
