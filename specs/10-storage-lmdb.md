# 10 — Storage: LMDB blockchain database (byte-compatible)

Source: `src/blockchain_db/blockchain_db.h` (the abstract interface),
`src/blockchain_db/blockchain_db.cpp` (shared logic),
`src/blockchain_db/lmdb/db_lmdb.cpp` + `db_lmdb.h` (the schema — this document is
essentially a specification of that file).

## 0. The goal, and why it is this one

The Rust node uses **LMDB with the exact same on-disk schema as `wownerod`**, so
that it can open an existing `data.mdb` in place, and `wownerod` can open a
database the Rust node wrote.

This is a stronger requirement than "use LMDB". It buys three specific things:

1. **Bring-up without resyncing.** Point the Rust node at an existing synced data
   directory and it starts at the tip. You do not wait for 840,000 blocks before
   you can test anything.
2. **Differential testing becomes trivial.** The harness in
   [15 §1](15-testing-and-conformance.md#1-build-a-differential-testing-harness-first)
   collapses from "sync both nodes for hours, compare over RPC" to "open both
   databases read-only, iterate, compare records". You can also diff the database
   the Rust node produced against the one the C++ node produced from the same
   blocks — which catches derived-value bugs at the exact height they occur.
3. **A whole bug class disappears by construction.** `output_id` ordering,
   `amount_index` assignment, `long_term_block_weight`,
   `already_generated_coins`, `cumulative_rct_outputs` — if these were wrong, the
   C++ node could not read the result. The format is the test.

The cost, stated plainly: **no compression** (LMDB has none), and we are bound to
this schema's quirks permanently. The chain is a few GB, so the first is
acceptable; the second is the same constraint the consensus rules already impose.

> Changed from an earlier draft of this spec, which specified RocksDB with zstd
> level 6. If compression ever becomes the priority, a second backend can be added
> behind the `BlockchainDb` trait in §9 — that trait is the seam which keeps the
> option open — but it would give up everything in the list above, so it should be
> a deliberate decision backed by a measurement, not a default.

---

## 1. Bindings

**`heed`** (v0.22.x, actively maintained) is the recommended wrapper. It exposes
the three LMDB features this schema cannot do without:

| Need | `heed` API |
|---|---|
| `MDB_DUPSORT` / `MDB_DUPFIXED` | `DatabaseFlags::DUP_SORT` / `DUP_FIXED` |
| `mdb_set_compare` | `.key_comparator::<C>()` on the database options builder |
| `mdb_set_dupsort` | `.dup_sort_comparator::<C>()` |

`lmdb-master-sys` is available if a raw-FFI port of `db_lmdb.cpp` turns out to be
easier for a specific table. Do **not** use `libmdbx-rs`: MDBX is an LMDB fork
with its own file format, which forfeits the entire point of this chapter.

Avoid the stale crates (`lmdb-rkv`, `lmdb-zero`, `danburkert/lmdb-rs`,
`mozilla/lmdb-rs` — the last is explicitly marked inactive).

Prior art: [Cuprate](https://github.com/Cuprate/cuprate), the Rust Monero node,
uses `heed` as its default backend (with `redb` as a swappable alternative), so
the binding choice is well-trodden.

### 1.1 The `unsafe` reality

LMDB hands out pointers into an mmap'd region that are valid only for the lifetime
of the transaction. `heed` models this with lifetimes, but:

- Never copy a `&[u8]` out of a transaction and use it after commit/abort.
- A corrupt or truncated `data.mdb` can **segfault** rather than return an error.
  Validate record lengths before transmuting: every decoder in §4 MUST check the
  slice length first and return an error, never index blindly.
- `#[repr(C, packed)]` structs are **not** a safe way to read these records. Write
  explicit field-by-field decoders from byte slices (§4).

---

## 2. Environment setup

Reproduce `BlockchainLMDB::open` (`db_lmdb.cpp:1430`).

```
files:            <datadir>/lmdb/data.mdb, <datadir>/lmdb/lock.mdb
mdb_env_set_maxdbs(env, 32)
mdb_env_set_maxreaders(env, threads + 16)   // only if threads > 110; LMDB's
                                            // default max is 126
mdb_env_open(env, path, flags, 0644)
```

`CRYPTONOTE_BLOCKCHAINDATA_FILENAME = "data.mdb"`,
`CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME = "lock.mdb"`
([01 §1](01-constants.md)).

The `lmdb` component comes from `BlockchainLMDB::get_db_name()`, so the full path
is `<datadir>/lmdb/`. Per-network data directories add their own component first
(`<datadir>/testnet/lmdb/`, `<datadir>/stagenet/lmdb/`), and `FAKECHAIN` reached
*without* `--regtest` inserts `fake/` as well (`<datadir>/fake/lmdb/`) —
`--regtest` already appends `fake` via the data-dir argument, so it is not added
twice.

The C++ also refuses to start if a legacy `blockchain.bin` exists in the data
directory. Reproducing that check is optional.

### 2.1 Environment flags — mapping `--db-sync-mode`

```
DBF_FAST     -> MDB_NOSYNC
DBF_FASTEST  -> MDB_NOSYNC | MDB_WRITEMAP | MDB_MAPASYNC
DBF_RDONLY   -> MDB_RDONLY          (replaces the flags, not OR'd)
DBF_SALVAGE  -> MDB_PREVSNAPSHOT    (--db-salvage: open the previous meta page)
```

`safe` mode is the absence of `MDB_NOSYNC`. See
[09 §3.3](09-daemon.md#33---db-sync-mode) for the option syntax.

### 2.2 Map size

LMDB requires the map size up front and cannot grow it implicitly.

```
DEFAULT_MAPSIZE = 1 << 30   (1 GiB)   with ENABLE_AUTO_RESIZE   <-- the build default
DEFAULT_MAPSIZE = 1 << 33   (8 GiB)   without ENABLE_AUTO_RESIZE
DEFAULT_MAPSIZE = 1 << 31   (2 GiB)   on 32-bit ARM
RESIZE_PERCENT  = 0.9
```

On open: if the existing map size is below `DEFAULT_MAPSIZE`, raise it to
`DEFAULT_MAPSIZE`. Then check `need_resize()` and resize if required.

`need_resize(threshold_size)`:

```
size_used = mst.ms_psize * mei.me_last_pgno
if threshold_size > 0:
    return (mei.me_mapsize - size_used) < threshold_size
return (size_used / mei.me_mapsize) > RESIZE_PERCENT      // 90%
```

`do_resize(increase_size)`:

```
add_size = 1 << 30                      // 1 GiB per resize
warn and return if free disk space < add_size
new_mapsize = me_mapsize + (increase_size > 0 ? increase_size : add_size)
new_mapsize += new_mapsize % mst.ms_psize
prevent new transactions; wait for all active transactions to drain
mdb_env_set_mapsize(env, new_mapsize)
allow new transactions
```

Two hard constraints, both of which the C++ enforces by throwing:

- **A resize MUST NOT happen while a write transaction is open**, and MUST NOT
  happen at all while a batch transaction is active.
- All read transactions must be drained first, because changing the map size
  invalidates every existing pointer.

This is the part of LMDB that most resembles a footgun. In Rust, model it as an
explicit `resize_barrier()` on the writer task that takes a write lock excluding
all snapshot readers — do not try to resize opportunistically from a reader.

For batch writes, `check_and_resize_for_batch(batch_num_blocks, batch_bytes)`
pre-computes an estimated batch size and resizes by
`max(estimated, 512 MiB)` before starting.

### 2.3 Schema version

`properties["version"]` is a `u32`. **Current value: `VERSION = 5`.**

On open:

- `db_version > 5` → warn "made by a later version", mark incompatible, refuse to
  write (the C++ reopens read-only).
- `db_version < 5` → the C++ runs `migrate()`. A Rust node MAY instead refuse and
  tell the operator to run the C++ node once to migrate. Do **not** silently
  write version-5 records into a version-4 database.
- Missing → a fresh database; write `5`.

---

## 3. Tables

19 sub-databases. Flags and comparators are from `db_lmdb.cpp:1485-1535` and are
**part of the file format** — a table opened with the wrong flags or comparator
produces a file the C++ node cannot read, or silently mis-sorts.

| Table | LMDB flags | `set_compare` | `set_dupsort` |
|---|---|---|---|
| `blocks` | `INTEGERKEY` | — | — |
| `block_info` | `INTEGERKEY｜DUPSORT｜DUPFIXED` | — | `compare_uint64` |
| `block_heights` | `INTEGERKEY｜DUPSORT｜DUPFIXED` | — | `compare_hash32` |
| `txs` | `INTEGERKEY` | — | — |
| `txs_pruned` | `INTEGERKEY` | — | — |
| `txs_prunable` | `INTEGERKEY` | `compare_uint64` | — |
| `txs_prunable_hash` | `INTEGERKEY｜DUPSORT｜DUPFIXED` | — | `compare_uint64` |
| `txs_prunable_tip` | `INTEGERKEY｜DUPSORT｜DUPFIXED` | — | `compare_uint64` |
| `tx_indices` | `INTEGERKEY｜DUPSORT｜DUPFIXED` | — | `compare_hash32` |
| `tx_outputs` | `INTEGERKEY` | — | — |
| `output_txs` | `INTEGERKEY｜DUPSORT｜DUPFIXED` | — | `compare_uint64` |
| `output_amounts` | `INTEGERKEY｜DUPSORT｜DUPFIXED` | — | `compare_uint64` |
| `spent_keys` | `INTEGERKEY｜DUPSORT｜DUPFIXED` | — | `compare_hash32` |
| `txpool_meta` | — | `compare_hash32` | — |
| `txpool_blob` | — | `compare_hash32` | — |
| `alt_blocks` | — | `compare_hash32` | — |
| `hf_starting_heights` | — | — | — |
| `hf_versions` | `INTEGERKEY` | — | — |
| `properties` | — | `compare_string` | — |

Notes:

- `txs` is **legacy and unused** — it exists only so old databases open. Open it,
  never write to it.
- `hf_starting_heights` is **dropped on every open** (`mdb_drop(txn, db, 1)`).
  It is opened only when not read-only, and is not used elsewhere. Reproduce the
  drop; it keeps the file identical.
- `txs_prunable_tip` is opened only when not read-only.
- `MDB_INTEGERKEY` means keys are native-endian `u64` (or `u32`) **in host byte
  order**, compared as integers. On little-endian hosts — the only ones that
  matter here — that is `u64::to_le_bytes()`. See §3.3.

### 3.1 The comparators

```rust
// compare_uint64 — memcpy both sides to u64 (host order), compare numerically
fn compare_uint64(a: &[u8], b: &[u8]) -> Ordering {
    u64::from_ne_bytes(a[..8].try_into().unwrap())
        .cmp(&u64::from_ne_bytes(b[..8].try_into().unwrap()))
}

// compare_hash32 — 32 bytes viewed as 8 u32s (host order), compared from the
// MOST SIGNIFICANT WORD DOWN, i.e. word index 7 first, then 6, ... then 0.
fn compare_hash32(a: &[u8], b: &[u8]) -> Ordering {
    for n in (0..8).rev() {
        let va = u32::from_ne_bytes(a[n*4..n*4+4].try_into().unwrap());
        let vb = u32::from_ne_bytes(b[n*4..n*4+4].try_into().unwrap());
        if va != vb { return va.cmp(&vb); }
    }
    Ordering::Equal
}

// compare_string — strncmp over min(len) then shorter-first
fn compare_string(a: &[u8], b: &[u8]) -> Ordering {
    let sz = a.len().min(b.len());
    match a[..sz].cmp(&b[..sz]) {
        Ordering::Equal => a.len().cmp(&b.len()),
        other => other,
    }
}
```

`compare_hash32` is **not** bytewise ordering. Getting it wrong does not corrupt
data but does break `MDB_GET_BOTH` lookups, so every hash-keyed read silently
misses. This is the single most likely subtle mistake in this chapter — unit-test
it against a table of known orderings before anything else.

### 3.2 The `zerokval` trick

**Five** tables use `DUPSORT | DUPFIXED` with a single dummy key of 8 zero bytes:

```rust
const ZEROKEY: [u8; 8] = [0; 8];
```

For these, the logical key is stored as a **prefix of the value** and the
`dupsort` comparator sorts on that prefix. This saves 8 bytes per record versus a
real key. A lookup is: position the cursor at key `ZEROKEY`, then `MDB_GET_BOTH`
with the value-prefix you are searching for.

| Table | Value (logical key first) | Dupsort compares |
|---|---|---|
| `block_info` | `mdb_block_info` (§4.2), starts with `u64 bi_height` | `compare_uint64` over bytes 0..8 |
| `block_heights` | `blk_height` (§4.3), starts with `[32] bh_hash` | `compare_hash32` over bytes 0..32 |
| `tx_indices` | `txindex` (§4.4), starts with `[32] key` | `compare_hash32` over bytes 0..32 |
| `output_txs` | `outtx` (§4.6), starts with `u64 output_id` | `compare_uint64` over bytes 0..8 |
| `spent_keys` | `[32]` key image | `compare_hash32` |

The other dupsort tables use real keys:

- `output_amounts` — key is the `u64 amount`; the dup value is
  `outkey` / `pre_rct_outkey` (§4.5), sorted by `compare_uint64` over the leading
  `amount_index`.
- `txs_prunable_hash`, `txs_prunable_tip` — `INTEGERKEY` on `tx_id`, with dupsort
  on the value.

> When porting, treat the cursor usage in each accessor as authoritative rather
> than this table: grep `zerokval` in `db_lmdb.cpp` (about 40 call sites, all
> unambiguous) and mirror each one. Ignore the hits inside the `migrate_*`
> functions unless you also implement migration.

### 3.3 Endianness and the packed-struct ABI

Every record is the raw memory image of a `#pragma pack(push, 1)` C++ struct, in
**host byte order**. Consequences:

- These files are little-endian in practice. A big-endian build of the C++ node
  would produce an incompatible file too, so this is not a regression — but it
  does mean the Rust code should assert `cfg!(target_endian = "little")` at open,
  or explicitly encode/decode with `from_le_bytes` and document that big-endian
  hosts get a *different* (self-consistent) file.
- `MDB_INTEGERKEY` keys must be written as `u64::to_ne_bytes()`.
- **Never** `transmute` a slice into a struct. Decode field by field with length
  checks (§1.1).

---

## 4. Record layouts

Byte-exact. Offsets are decimal; all integers little-endian (host order, §3.3).

### 4.1 Keys

```
blocks, block_info(*), txs_pruned, txs_prunable, txs_prunable_hash,
txs_prunable_tip, tx_outputs, hf_versions   ->  u64 native-endian
output_amounts                              ->  u64 amount, native-endian
txpool_meta, txpool_blob, alt_blocks        ->  [32] hash
properties                                  ->  NUL-TERMINATED ASCII string,
                                                 length INCLUDES the NUL
(*) via the ZEROKEY dummy, see §3.2
```

`properties` keys include the terminating NUL because the C++ uses
`MDB_val_copy<const char*>` with `strlen(s)+1`. `properties["version"]` is
therefore an 8-byte key `"version\0"`. Getting this wrong means you write a new
key rather than reading the existing one.

Known `properties` keys: `"version"` (`u32`), `"pruning_seed"` (`u32`),
`"max_block_size"` (`u64`).

### 4.2 `mdb_block_info` (= `mdb_block_info_4`), 96 bytes

```
  0  u64  bi_height
  8  u64  bi_timestamp
 16  u64  bi_coins                  // already_generated_coins
 24  u64  bi_weight                 // block weight (size_t widened to u64)
 32  u64  bi_diff_lo                // cumulative difficulty, low  64 bits
 40  u64  bi_diff_hi                // cumulative difficulty, high 64 bits
 48  [32] bi_hash
 80  u64  bi_cum_rct                // running total, see below
 88  u64  bi_long_term_block_weight
```

Older versions of this record exist (`_1` without `bi_cum_rct`, `_2` without
`bi_long_term_block_weight`, `_3` with a single `bi_diff`). A version-5 database
only contains `_4`. If you support reading older databases, dispatch on the record
length; otherwise require `version == 5`.

`bi_cum_rct` is computed in `add_block`:

```
num_rct_outs = (if miner_tx.version == 2 { miner_tx.vout.len() } else { 0 })
             + sum over txs of (if tx.version == 2 { tx.vout.len() } else { 0 })
if height > 0 && block.major_version >= 4 {
    num_rct_outs += block_info[height - 1].bi_cum_rct
}
```

Note the `major_version >= 4` guard — always true on Wownero, but reproduce it.

`bi_long_term_block_weight` **cannot be recomputed** from block weights
([06 §3.4](06-consensus-rules.md)); it is authoritative here.

### 4.3 `blk_height` (value of `block_heights`), 40 bytes

```
  0  [32] bh_hash
 32  u64  bh_height
```

Dupsort-compared by `compare_hash32` over bytes 0..32.

### 4.4 `txindex` (value of `tx_indices`), 56 bytes

```
  0  [32] key                       // tx hash
 32  u64  tx_id                     // tx_data_t begins here
 40  u64  unlock_time
 48  u64  block_id                  // the HEIGHT of the containing block
```

Dupsort-compared by `compare_hash32` over bytes 0..32.

### 4.5 `outkey` / `pre_rct_outkey` (values of `output_amounts`)

**The record length varies by output type.** This is not optional — `add_output`
fills one `outkey` buffer and then sets `data.mv_size` to one of two values.

Both payload structs are `#pragma pack(push, 1)` and differ only by the trailing
commitment (`blockchain_db.h:124` and `db_lmdb.cpp:68`):

```
pre_rct_output_data_t, 48 bytes:      output_data_t, 80 bytes:
  0  [32] pubkey                        0  [32] pubkey
 32  u64  unlock_time                  32  u64  unlock_time
 40  u64  height                       40  u64  height
                                       48  [32] commitment
```

giving the two record forms:

```
pre_rct_outkey  (amount != 0), 64 bytes:
  0  u64  amount_index
  8  u64  output_id
 16  [32] pubkey
 48  u64  unlock_time
 56  u64  height

outkey  (amount == 0, RingCT), 96 bytes:
  0  u64  amount_index
  8  u64  output_id
 16  [32] pubkey
 48  u64  unlock_time
 56  u64  height
 64  [32] commitment
```

Every field is naturally 8-aligned or a byte array, so packed and unpacked layouts
coincide and these sizes are stable across compilers. Still assert them in a test
against a record read from a real `data.mdb`.

`add_output` writes 96 bytes when `tx_output.amount == 0` and 64 bytes otherwise —
i.e. it truncates the same buffer, dropping the commitment. Readers dispatch on
the record length, and `get_output_key(..., include_commitment)` synthesises
`commitment = zeroCommit(amount)` for the short form.

Dupsort-compared by `compare_uint64` over the leading `amount_index`.

### 4.6 `outtx` (value of `output_txs`), 48 bytes

```
  0  u64  output_id
  8  [32] tx_hash
 40  u64  local_index               // the output's index within its transaction
```

Dupsort-compared by `compare_uint64` over bytes 0..8.

### 4.7 `tx_outputs`

Key `u64 tx_id`, value = the raw array `u64[num_outputs]` of **amount output
indices**, i.e. `sizeof(u64) * n` bytes with no count prefix. An empty vector is
stored as a zero-length value.

### 4.8 `txs_pruned` / `txs_prunable`

Key `u64 tx_id`. Values are the two halves of the tx blob split at
`unprunable_size` ([05 §2.2](05-blocks-and-transactions.md)):

```
txs_pruned[tx_id]   = blob[0 .. unprunable_size]
txs_prunable[tx_id] = blob[unprunable_size ..]
```

If `tx.unprunable_size` is not already known, the C++ recomputes it by serializing
`serialize_base`. In Rust, record both offsets during parsing and carry them on the
transaction — never re-serialize.

`txs_prunable_hash[tx_id]` = the 32-byte prunable hash; written only for
`tx.version > 1`.

### 4.9 `txpool_meta`

Key `[32] tx hash`, value = `txpool_tx_meta_t`, **192 bytes**
(`blockchain_db.h:154`):

```
  0  [32] max_used_block_id
 32  [32] last_failed_id
 64  u64  weight
 72  u64  fee
 80  u64  max_used_block_height
 88  u64  last_failed_height
 96  u64  receive_time
104  u64  last_relayed_time
                              // <-- the C++ marks "112 bytes" here
112  u8   kept_by_block
113  u8   relayed
114  u8   do_not_relay
115  u8   bitfield (see below)
116  [76] padding             // "till 192 bytes"
```

The struct is **not** inside a `#pragma pack` block, but every field is naturally
aligned, so `sizeof` is 192 with no compiler-inserted padding. The 76-byte tail
exists so the struct can grow without a schema migration; write it as zeros and
preserve it on read-modify-write.

Byte 115 is a bitfield. With the x86-64/AArch64 Itanium ABI (GCC and Clang),
`uint8_t` bitfields are allocated from the **least significant bit up**:

```
bit 0  double_spend_seen
bit 1  pruned
bit 2  is_local
bit 3  dandelionpp_stem
bit 4  is_forwarding
bits 5-7  bf_padding
```

`relay_method` is not stored directly; it is reconstructed from five separate
flags (`blockchain_db.cpp:78`):

```rust
// set_relay_method clears kept_by_block, do_not_relay, is_local,
// is_forwarding, dandelionpp_stem, then sets exactly one (or none):
none    -> do_not_relay = 1
local   -> is_local = 1
forward -> is_forwarding = 1
stem    -> dandelionpp_stem = 1
block   -> kept_by_block = 1
fluff   -> (all zero)

// get_relay_method rebuilds a state word and switches on it:
state = kept_by_block
      | (do_not_relay     << 1)
      | (is_local         << 2)
      | (is_forwarding    << 3)
      | (dandelionpp_stem << 4)
```

Note `kept_by_block` and `do_not_relay` are full `u8` fields (bytes 112 and 114)
while `is_local`, `is_forwarding` and `dandelionpp_stem` are bits in byte 115 — so
the state word mixes two storage locations. `relayed` (byte 113) is independent of
the relay method.

`last_relayed_time` is overloaded ([09 §2.2](09-daemon.md#22-txpool)).

### 4.10 `alt_blocks`

Key `[32] block hash`, value = `alt_block_data_t` followed immediately by the
block blob in the same value:

```
  0  u64  height
  8  u64  cumulative_weight
 16  u64  cumulative_difficulty_low
 24  u64  cumulative_difficulty_high
 32  u64  already_generated_coins
 40  ...  block blob
```

### 4.11 `hf_versions`

Key `u64 height`, value `u8` version.

---

## 5. Semantics that must be preserved

The format enforces most invariants, but these are the ones the format cannot
check.

### 5.1 Id assignment order

```
add_block:
    add_transaction(miner_tx)          # THE COINBASE IS FIRST
    for tx in txs (in block.tx_hashes order): add_transaction(tx)

add_transaction:
    for each input: add_spent_key(k_image)     # txin_gen contributes nothing
    tx_id = get_tx_count()                     # == entries in txs_pruned
    write txs_pruned / txs_prunable / txs_prunable_hash / tx_indices
    for i in 0..vout.len():
        amount_output_indices[i] = add_output(tx_hash, vout[i], i, tx.unlock_time, commitment)
    add_tx_amount_output_indices(tx_id, amount_output_indices)

add_output:
    output_id    = num_outputs()               # global, dense
    amount_index = mdb_cursor_count(output_amounts @ amount)   # current dup count
```

`output_id` and `tx_id` are derived from **table entry counts**
(`mdb_stat().ms_entries`), not from a stored counter — so they cannot drift out of
sync with the data. `height` likewise is `mdb_stat(m_blocks).ms_entries`.
Keep that property: do not cache these in `properties`.

`amount_index` comes from `mdb_cursor_count` on the dup group. `heed` exposes the
dup count via cursor iteration; if it does not expose `mdb_cursor_count` directly,
either drop to `lmdb-master-sys` for this one call or maintain the count in memory
for the current write transaction and verify it against a count-on-open.

Any deviation here renumbers every later output and every ring reference in every
later transaction becomes wrong.

### 5.2 Commitments stored for outputs

`BlockchainDB::add_transaction` (`blockchain_db.cpp:206`):

```rust
if is_miner_tx && tx.version == 2 {
    // v2 coinbase outputs are stored as RingCT outputs with an identity mask
    let commitment = zero_commit(vout.amount);   // amount*H + 1*G
    let stored_amount = 0;                        // <-- amount ZEROED
    add_output(tx_hash, stored_amount, target, i, tx.unlock_time, Some(commitment));
} else if tx.version > 1 {
    let mut commitment = tx.rct.out_pk[i].mask;
    if is_rct_bp_plus_legacy(tx.rct.ty) {         // RCT type 8
        commitment = scalarmult8(commitment);     // store the FULL commitment
    }
    add_output(tx_hash, vout[i].amount, target, i, tx.unlock_time, Some(commitment));
} else {
    add_output(tx_hash, vout[i].amount, target, i, tx.unlock_time, None);
}
```

Three things to get right:

1. **v2 coinbase outputs are stored with `amount = 0`** and an identity-mask
   commitment, so they land in the RingCT output set and can serve as decoys. This
   is why the dup count under `output_amounts[0]` includes coinbase outputs.
2. The stored commitment is always the **full** `C`, never `C/8`. RCT type 8
   serializes `outPk.mask` as `C/8`, so multiply by 8 before storing; type 9
   already holds `C` ([02 §4.4](02-crypto.md)).
3. `zero_commit(a) = a*H + 1*G` (`rct::zeroCommit`). Port it exactly.

### 5.3 `get_num_outputs(amount)`

The dup count under `output_amounts[amount]`. Consensus-relevant: it decides
whether a pre-RingCT amount is "mixable" ([06 §5.3](06-consensus-rules.md)).

### 5.4 `get_output_distribution`

Derived from `bi_cum_rct` differences for amount 0. Wallets use it for decoy
selection ([12 §4.3](12-wallet-core.md)), so the values must match.

### 5.5 `get_indexing_base`

Returns 0 for LMDB. Keep 0.

---

## 6. Transactions and concurrency

### 6.1 The C++ model

- **One write transaction at a time**, environment-wide (LMDB guarantees this).
- Read transactions are per-thread and cached: `m_tinfo` is a
  `thread_specific_ptr<mdb_threadinfo>` holding a long-lived read txn plus a full
  set of cursors, renewed with `mdb_txn_renew` rather than recreated.
- `batch_start(n_blocks, bytes)` / `batch_stop()` wrap many blocks in one write
  txn during bulk sync, with `check_and_resize_for_batch` first.
- `block_wtxn_start` / `block_wtxn_stop` wrap a single block.

### 6.2 The Rust model

Map it onto the architecture in [00 §5](00-overview.md):

- The **writer task** owns the single write transaction. One `RwTxn` per block
  (or per batch during bulk sync). Commit is the atomic unit.
- **Readers** take a `RoTxn` per request. `heed`'s `RoTxn` is a real LMDB read
  transaction, so it is a consistent snapshot for free — this is strictly nicer
  than RocksDB snapshots and needs no extra machinery.
- **Do not hold a `RoTxn` across an `await` that could last arbitrarily long.** A
  long-lived reader pins an old snapshot, so the free list cannot be reclaimed and
  the map grows. This is the classic LMDB operational failure. Bound reader
  lifetime to a single request, and set a hard cap.
- Reader slots are finite (`maxreaders`, default 126). Raise it per §2 and treat
  `MDB_READERS_FULL` as backpressure on the RPC layer, not a fatal error.
- A resize needs all transactions drained (§2.2) — the writer task must be able to
  ask readers to yield.

### 6.3 Atomicity

A whole block — `blocks`, `block_info`, `block_heights`, the per-tx tables, the
output tables, `spent_keys`, `hf_versions` — commits in **one** write transaction.
LMDB gives all-or-nothing across sub-databases, which satisfies the requirement
directly. There is no WAL and no torn-write recovery to write: LMDB's two meta
pages mean a crash leaves the last committed transaction intact.

With `MDB_NOSYNC` / `MDB_MAPASYNC` (`fast` / `fastest`) a crash can lose recent
*committed* transactions, but the database remains structurally valid — you come
back at an earlier height, not a corrupt file. That is a meaningfully better
failure mode than the RocksDB alternative, and it is why no
`verify_and_repair_tip()` equivalent is needed. Still verify on open that
`blocks`, `block_info` and `block_heights` agree about the tip, and pop if not.

### 6.4 `pop_block`

Exact inverse of §5.1, in reverse order:

```
for tx in [txs..., miner_tx]:          # reverse; COINBASE LAST
    for i in (0..vout.len()).rev():
        remove output_amounts dup (amount, amount_index)
        remove output_txs dup (output_id)
    remove tx_outputs[tx_id], tx_indices dup, txs_pruned[tx_id],
           txs_prunable[tx_id], txs_prunable_hash dup
    for each input: remove spent_keys dup (k_image)
remove block_info dup (height), block_heights dup (hash), blocks[height],
       hf_versions[height]
```

One write transaction. Because the ids are dense and derived from entry counts,
assert that the removed `output_id` equals `num_outputs() - 1` as a self-check.

Popped transactions go back to the mempool with `kept_by_block = true`
([06 §7](06-consensus-rules.md)).

---

## 7. Using an existing `data.mdb`

This is the payoff; make it a first-class, documented workflow.

```sh
# read-only inspection against a running C++ node's database is safe
wownerod-rs --data-dir ~/.wownero --db-readonly --check-difficulty-checkpoints

# take over an existing datadir (stop wownerod first)
wownerod-rs --data-dir ~/.wownero
```

Requirements:

- Refuse to open read-write if `lock.mdb` shows a live writer. LMDB's own locking
  handles the mutual exclusion; surface it as a clear error rather than blocking.
- Check `properties["version"] == 5` (§2.3).
- Verify the tip agrees across `blocks` / `block_info` / `block_heights`.
- Check the network: the C++ stores nothing identifying the network in
  `properties`, so infer it from the **genesis block hash** in `blocks[0]` and
  refuse a mismatch. (This is a real hazard: a testnet and a mainnet `data.mdb`
  are structurally identical.)

Because the format is shared, the M2 gate in
[15 §3.1](15-testing-and-conformance.md) can be run as a direct database diff
rather than an RPC comparison, and it can start from a snapshot at the tip.

---

## 8. Performance notes

LMDB's characteristics differ from RocksDB's in ways that affect the node:

- **Reads are zero-copy** out of the mmap, so `get_output_key` batches are very
  fast — this is the hot path for ring verification and it gets faster, not
  slower, than the RocksDB design.
- **Writes are more expensive** (copy-on-write B-tree, no write buffer), and bulk
  sync therefore wants large batch transactions. This is exactly what
  `batch_start(n_blocks, bytes)` is for; implement it before benchmarking sync.
- **No compression**, so expect the store to be somewhat larger than the RocksDB
  design would have been. `output_amounts` dominates (a 96-byte record per RingCT
  output), then `txs_prunable` (CLSAG at ring size 22 is ~2.2 KB per input).
- **No background compaction**, so no write stalls and no CPU spikes — steadier
  latency than RocksDB under load.
- Free pages are reused, but only once no reader holds an older snapshot (§6.2).
  A leaked long-lived reader looks exactly like a disk-space leak.

---

## 9. The `BlockchainDb` trait

Keep the trait as the seam, both to allow a test double (the equivalent of
`testdb.h`) and to keep an alternative backend possible later.

```rust
pub trait BlockchainDb: Send + Sync {
    // --- chain ---
    fn height(&self) -> u64;                          // mdb_stat(blocks).ms_entries
    fn block_exists(&self, h: &Hash256) -> Result<bool>;
    fn get_block_hash(&self, height: u64) -> Result<Hash256>;
    fn get_block_height(&self, h: &Hash256) -> Result<u64>;
    fn get_block_blob(&self, height: u64) -> Result<Vec<u8>>;
    fn get_block_info(&self, height: u64) -> Result<BlockInfo>;
    fn get_block_timestamp(&self, height: u64) -> Result<u64>;
    fn get_block_weight(&self, height: u64) -> Result<u64>;
    fn get_block_long_term_weight(&self, height: u64) -> Result<u64>;
    fn get_block_cumulative_difficulty(&self, height: u64) -> Result<u128>;
    fn get_block_already_generated_coins(&self, height: u64) -> Result<u64>;
    fn get_block_cumulative_rct_outputs(&self, heights: &[u64]) -> Result<Vec<u64>>;
    fn get_long_term_block_weight_median(&self, start: u64, count: u64) -> Result<u64>;

    // --- transactions ---
    fn tx_exists(&self, h: &Hash256) -> Result<bool>;
    fn get_tx_data(&self, h: &Hash256) -> Result<TxData>;
    fn get_tx_blob(&self, h: &Hash256) -> Result<Vec<u8>>;
    fn get_pruned_tx_blob(&self, h: &Hash256) -> Result<Vec<u8>>;
    fn get_prunable_tx_hash(&self, h: &Hash256) -> Result<Hash256>;
    fn get_tx_block_height(&self, h: &Hash256) -> Result<u64>;
    fn get_tx_amount_output_indices(&self, tx_id: u64, n: usize) -> Result<Vec<Vec<u64>>>;

    // --- outputs ---
    fn get_num_outputs(&self, amount: u64) -> Result<u64>;
    fn get_output_key(&self, amount: u64, index: u64, with_commitment: bool)
        -> Result<OutputData>;
    fn get_output_keys(&self, amounts: &[u64], offsets: &[u64], allow_partial: bool)
        -> Result<Vec<OutputData>>;
    fn get_output_tx_and_index(&self, amount: u64, index: u64) -> Result<(Hash256, u64)>;
    fn get_output_tx_and_index_from_global(&self, output_id: u64) -> Result<(Hash256, u64)>;
    fn get_output_histogram(&self, amounts: &[u64], unlocked: bool,
                            recent_cutoff: u64, min_count: u64)
        -> Result<BTreeMap<u64, (u64, u64, u64)>>;
    fn get_output_distribution(&self, amount: u64, from: u64, to: u64) -> Result<Vec<u64>>;

    // --- key images ---
    fn has_key_image(&self, ki: &KeyImage) -> Result<bool>;

    // --- hard fork ---
    fn set_hard_fork_version(&self, height: u64, version: u8) -> Result<()>;
    fn get_hard_fork_version(&self, height: u64) -> Result<u8>;

    // --- mempool ---
    fn add_txpool_tx(&self, h: &Hash256, blob: &[u8], meta: &TxPoolMeta) -> Result<()>;
    fn update_txpool_tx(&self, h: &Hash256, meta: &TxPoolMeta) -> Result<()>;
    fn remove_txpool_tx(&self, h: &Hash256) -> Result<()>;
    fn get_txpool_tx_meta(&self, h: &Hash256) -> Result<TxPoolMeta>;
    fn get_txpool_tx_blob(&self, h: &Hash256) -> Result<Vec<u8>>;
    fn for_all_txpool_txes(
        &self, f: &mut dyn FnMut(&Hash256, &TxPoolMeta, Option<&[u8]>) -> bool) -> Result<()>;

    // --- alt blocks ---
    fn add_alt_block(&self, h: &Hash256, data: &AltBlockData, blob: &[u8]) -> Result<()>;
    fn get_alt_block(&self, h: &Hash256) -> Result<(AltBlockData, Vec<u8>)>;
    fn remove_alt_block(&self, h: &Hash256) -> Result<()>;
    fn get_alt_block_count(&self) -> Result<u64>;
    fn drop_alt_blocks(&self) -> Result<()>;

    // --- mutation ---
    fn add_block(&self, blk: &Block, blk_blob: &[u8], block_weight: u64,
                 long_term_block_weight: u64, cumulative_difficulty: u128,
                 coins_generated: u64, txs: &[(Transaction, Vec<u8>)]) -> Result<u64>;
    fn pop_block(&self) -> Result<(Block, Vec<Transaction>)>;
    fn correct_block_cumulative_difficulties(&self, start: u64, values: &[u128]) -> Result<()>;

    // --- lifecycle ---
    fn batch_start(&self, n_blocks: u64, bytes: u64) -> Result<()>;
    fn batch_stop(&self) -> Result<()>;
    fn resize_barrier(&self) -> Result<()>;          // §2.2
    fn sync(&self) -> Result<()>;                    // mdb_env_sync
}
```

Note the differences from a RocksDB-shaped trait: no `snapshot()` (a `RoTxn` *is*
the snapshot), no `verify_and_repair_tip()` (§6.3), and explicit
`batch_start`/`batch_stop`/`resize_barrier` because LMDB's transaction and map-size
model is part of the interface rather than hidden behind it.

---

## 10. Conformance checklist

- [ ] Table names, LMDB flags, and `set_compare` / `set_dupsort` assignments match
      §3 exactly.
- [ ] `compare_hash32` compares u32 words from **index 7 down to 0**, not
      bytewise — unit-tested against known orderings.
- [ ] `compare_string` is strncmp-then-shorter-first; `properties` keys include
      their terminating NUL.
- [ ] The `ZEROKEY` dummy-key tables use a value-prefix logical key with the right
      dupsort comparator; `output_amounts` uses the real amount as its key.
- [ ] `MDB_INTEGERKEY` keys are written in native byte order.
- [ ] Records are decoded field-by-field with length checks; no `transmute`, no
      `repr(packed)` reads.
- [ ] `output_amounts` values are written at the **short** length for
      `amount != 0` and the long length for RingCT, and readers dispatch on length.
- [ ] `output_id` / `tx_id` / `height` are derived from table entry counts, not
      cached counters.
- [ ] Id assignment order matches §5.1, **coinbase first**.
- [ ] v2 coinbase outputs stored with `amount = 0` and
      `commitment = zero_commit(amount)`.
- [ ] Stored commitments are the full `C`; RCT type 8 masks multiplied by 8.
- [ ] `bi_long_term_block_weight` and `bi_cum_rct` are persisted, with the
      `major_version >= 4` guard on the running total.
- [ ] `cumulative_difficulty` split across `bi_diff_lo` / `bi_diff_hi` and
      reassembled as `u128`.
- [ ] One write transaction per block; `pop_block` is the exact inverse and
      asserts the highest ids were removed.
- [ ] `hf_starting_heights` is dropped on open; `txs` is opened but never written.
- [ ] `properties["version"]` is checked; `> 5` refuses to write, `< 5` refuses
      rather than half-migrating.
- [ ] Map-size resize drains all transactions and never runs inside a write or
      batch transaction.
- [ ] Read transactions are bounded to one request and never held across a long
      await.
- [ ] The network is inferred from the genesis hash in `blocks[0]` and a mismatch
      is refused.
- [ ] A `data.mdb` written by the Rust node opens cleanly in `wownerod`, and vice
      versa. **This is the gate for this chapter.**
