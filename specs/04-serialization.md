# 04 — Serialization

Wownero uses **three** distinct encodings. Mixing them up is the most common
source of interop failure.

| Encoding | Where | Consensus? |
|---|---|---|
| **Binary archive** | block/tx blobs, everything that gets hashed, the blockchain DB | **Yes** — byte-exact |
| **Epee portable storage** | Levin P2P payloads, `*.bin` RPC endpoints, `p2pstate.bin` | Wire-exact |
| **JSON** | JSON-RPC and plain-HTTP RPC | Field-name exact |

Source: `src/serialization/*`, `contrib/epee/include/storages/portable_storage*`,
`contrib/epee/include/serialization/keyvalue_serialization.h`,
`docs/PORTABLE_STORAGE.md`.

---

## 1. Binary archive (consensus serialization)

### 1.1 Varint

CryptoNote/protobuf-style base-128, **not** the epee varint of §2.1.

```
while value >= 0x80 { emit((value & 0x7f) | 0x80); value >>= 7 }
emit(value)
```

Little-endian groups of 7 bits, high bit = continuation. Max 10 bytes for u64.

**Strictness on read:** the reader MUST reject
- a varint longer than `ceil(bits/7)` bytes for the target type,
- a value that overflows the target type.

The C++ `read_varint` returns an error for both. Overly-long encodings of small
values (e.g. `0x80 0x00` for zero) are **rejected** — this matters because block
and tx blobs are hashed, so a non-canonical encoding would produce a different
hash for semantically identical data.

### 1.2 Field kinds

The C++ macros map to these wire forms:

| Macro | Wire form |
|---|---|
| `VARINT_FIELD(x)` | varint |
| `FIELD(x)` for a POD (`crypto::hash`, `public_key`, `signature`, `u32` nonce) | raw little-endian bytes, **no length prefix** |
| `FIELD(x)` for `std::vector<T>` / `std::list<T>` | `varint(len)` then each element |
| `FIELD(x)` for `std::string` / `blobdata` / `std::vector<u8>` | `varint(len)` then raw bytes |
| `FIELD(x)` for a struct | that struct's fields in declaration order, no framing |
| `FIELD(x)` for a `boost::variant` | `u8` tag byte, then the selected type's fields |
| `FIELDS(x)` | inline the fields of `x` with no framing |

There is **no** field-name, no field-tag, no length framing around structs. The
layout is entirely positional, so declaration order is part of the format.

Notable: `block_header.nonce` is `FIELD`, i.e. a raw 4-byte LE integer, **not** a
varint. `block_header.vote` is `FIELD` on a `u16`, i.e. raw 2 bytes LE.

### 1.3 Variant tags

```
txin_gen              0xff
txin_to_script        0x00
txin_to_scripthash    0x01
txin_to_key           0x02

txout_to_script       0x00
txout_to_scripthash   0x01
txout_to_key          0x02
txout_to_tagged_key   0x03      # HF 20+

transaction           0xcc      # only used by the KV/JSON archives
block                 0xbb
```

`tx_extra` field tags (a variant inside the `extra` byte blob — see
[05 §3.4](05-blocks-and-transactions.md)):

```
TX_EXTRA_TAG_PADDING              0x00
TX_EXTRA_TAG_PUBKEY               0x01
TX_EXTRA_NONCE                    0x02
TX_EXTRA_MERGE_MINING_TAG         0x03
TX_EXTRA_TAG_ADDITIONAL_PUBKEYS   0x04
TX_EXTRA_MYSTERIOUS_MINERGATE_TAG 0xDE
```

### 1.4 Conditional fields

Several structures serialize different fields depending on a value already read.
The reader MUST use the *just-decoded* value, not an out-of-band expectation:

- `block_header`: `signature` (64 B) and `vote` (2 B LE) are present **iff**
  `major_version >= 18`.
- `transaction`: `signatures` iff `version == 1`, else `rct_signatures`.
- `rctSigBase` / `rctSigPrunable`: field set depends on `type`, and array lengths
  come from `inputs`/`outputs`/`mixin`, which are derived from the already-parsed
  prefix (see [05 §2.3](05-blocks-and-transactions.md)).

This "length from context" property means **a transaction blob cannot be parsed
without parsing its prefix first**, and `rctsig_prunable` cannot be parsed without
knowing `vin[0].key_offsets.len() - 1` as the mixin.

### 1.5 Recommended Rust shape

```rust
pub trait BinSerialize { fn write(&self, w: &mut impl Write) -> Result<()>; }
pub trait BinDeserialize: Sized {
    type Ctx;                                 // e.g. (inputs, outputs, mixin, type)
    fn read(r: &mut impl Read, ctx: Self::Ctx) -> Result<Self>;
}
```

Do not try to make this a plain `serde` format: the context-dependent lengths and
the "no framing" struct rule do not fit serde's model. A small derive macro over
an explicit field list is a better fit.

### 1.6 Limits enforced during parsing

Reject at parse time (the C++ does):

- `tx.version == 0` or `> CURRENT_TRANSACTION_VERSION (2)`.
- `block.tx_hashes.len() > CRYPTONOTE_MAX_TX_PER_BLOCK (0x10000000)`.
- RCT `inputs`, `outputs`, `mixin` each `>= 0xffffffff`.
- `rctSigPrunable`: `nbp > outputs`;
  `n_bulletproof_plus_max_amounts(bpp) < outputs`.
- `bulletproofs_plus.len() != 1` (for BP+ types) or `L.len() < 6`.
- `outPk.len() != vout.len()`.
- Unknown RCT `type` values.

A parse failure is a validation failure, never a panic.

---

## 2. Epee portable storage (P2P and `.bin` RPC)

A self-describing name/value tree. Used for every Levin payload and for the
binary RPC endpoints.

### 2.1 Epee varint

**Different from §1.1.** Little-endian, with the low 2 bits encoding the width:

| Low 2 bits | Total size | Value range |
|---|---|---|
| `00` | 1 byte | 0 – 63 |
| `01` | 2 bytes | 64 – 16,383 |
| `10` | 4 bytes | 16,384 – 1,073,741,823 |
| `11` | 8 bytes | 1,073,741,824 – 4,611,686,018,427,387,903 |

Encode: `(value << 2) | width_code`, written as a LE integer of that width.

Examples: `0 -> 00`, `7 -> 1c`, `101 -> 95 01`,
`17000 -> A2 09 01 00`, `7942319744 -> 03 BA 98 65 07 00 00 00`.

### 2.2 Header

Every portable-storage blob begins with 9 bytes:

```
01 11 01 01   # signature A: u32 LE 0x01011101
01 01 02 01   # signature B: u32 LE 0x01020101
01            # version
```

### 2.3 Section

```
varint  entry_count
entry_count x Entry
```

### 2.4 Entry

```
u8      name_len            (<= 255)
[n]     name bytes          (no NUL)
u8      type                (optionally | 0x80)
[varint count]              (present only if type & 0x80)
value(s)
```

### 2.5 Types

```
1  INT64    2  INT32    3  INT16   4  INT8
5  UINT64   6  UINT32   7  UINT16  8  UINT8
9  DOUBLE  10  STRING  11  BOOL   12  OBJECT  13  ARRAY
0x80 = ARRAY flag
```

- Integers: fixed-width little-endian.
- `BOOL`: 1 byte, 0 / 1.
- `DOUBLE`: 8 bytes, IEEE-754 little-endian.
- `STRING`: `varint(len)` + raw bytes. **Hashes, keys, and arbitrary binary
  blobs are all carried as `STRING`.**
- `OBJECT`: a nested Section.
- Arrays: `type | 0x80`, then `varint(count)`, then `count` values with no
  per-element type byte and no padding. Nested arrays are impossible directly;
  the code wraps inner arrays in objects (`OBJECT | ARRAY`).
- `ARRAY` (13) as a standalone type is not used by Monero/Wownero.

### 2.6 The KV_SERIALIZE macro family

The structure definitions in `src/p2p/p2p_protocol_defs.h` and
`src/cryptonote_protocol/cryptonote_protocol_defs.h` use these; each maps to a
specific encoding. A Rust implementation must reproduce them per field:

| Macro | Encoding |
|---|---|
| `KV_SERIALIZE(x)` | natural mapping (int → int type, `std::string` → STRING, struct → OBJECT, vector → ARRAY of the element type) |
| `KV_SERIALIZE_OPT(x, default)` | same, but **absent on read means `default`**; always written |
| `KV_SERIALIZE_VAL_POD_AS_BLOB(x)` | a POD (e.g. `crypto::hash`, `uuid`) as a **STRING** of exactly `sizeof(T)` bytes |
| `KV_SERIALIZE_CONTAINER_POD_AS_BLOB(x)` | a container of PODs as **one STRING** containing the concatenated elements; length MUST be a multiple of `sizeof(T)` |
| `KV_SERIALIZE_PARENT(T)` | the parent struct's entries inlined into this section |
| `KV_SERIALIZE_N(x, "name")` | as `KV_SERIALIZE` but with an explicit entry name |

`KV_SERIALIZE_OPT` is what makes the protocol forward-compatible: a peer that
omits `pruning_seed` or `rpc_port` is fine, and a reader MUST supply the default
rather than erroring.

`KV_SERIALIZE_CONTAINER_POD_AS_BLOB` is why `NOTIFY_REQUEST_CHAIN.block_ids`
arrives as a single string of `32 * n` bytes, not as an array of 32-byte strings.

### 2.7 Reader strictness

- Unknown entry names MUST be **skipped**, not rejected. This is how the protocol
  evolves.
- Missing non-`OPT` fields are an error.
- A type mismatch on a known field is an error.
- Enforce a maximum nesting depth (the C++ uses `EPEE_DEFAULT_MAX_RECURSION_DEPTH`)
  and a maximum entry/element count, or a hostile peer can exhaust memory with a
  tiny message.

---

## 3. JSON

Used by JSON-RPC (`POST /json_rpc`) and the plain-HTTP endpoints
(`/get_info`, `/send_raw_transaction`, ...).

- The C++ derives JSON field names from the same `KV_SERIALIZE` macros, so
  **JSON field names equal the portable-storage entry names**. This is convenient:
  one struct definition can serve both.
- `KV_SERIALIZE_VAL_POD_AS_BLOB` in JSON becomes a **hex string**, not a binary
  string. Amounts and heights are JSON numbers (u64 — beware of clients that
  parse into f64; the reference server emits them as numbers anyway).
- Optional fields (`KV_SERIALIZE_OPT`) may be omitted by clients.
- 128-bit difficulties are emitted **three** ways for compatibility:
  `difficulty` (low 64 bits), `difficulty_top64` (high 64 bits), and
  `wide_difficulty` (a `0x`-prefixed hex string). `store_difficulty()` in
  `core_rpc_server.cpp` fills all three; a Rust server MUST too.
- JSON-RPC envelope: `{"jsonrpc":"2.0","id":"0","method":"...","params":{...}}`
  and `{"jsonrpc":"2.0","id":"0","result":{...}}` or
  `{"jsonrpc":"2.0","id":"0","error":{"code":N,"message":"..."}}`.

---

## 4. Levin framing

See [08 §1](08-p2p.md). Briefly: a 33-byte header followed by a
portable-storage body.

---

## 5. Conformance checklist

- [ ] Two different varint encodings are implemented and never confused: base-128
      for consensus blobs, `(value << 2) | width` for epee.
- [ ] Consensus varint reading rejects over-long and overflowing encodings.
- [ ] `block_header.nonce` is a raw `u32` LE; `vote` is a raw `u16` LE.
- [ ] `signature` + `vote` are serialized iff `major_version >= 18`.
- [ ] Variant tags match §1.3 exactly, including `txin_gen = 0xff`.
- [ ] Portable-storage readers skip unknown entry names and apply `OPT`
      defaults.
- [ ] `*_POD_AS_BLOB` fields are STRINGs in binary and hex in JSON.
- [ ] `CONTAINER_POD_AS_BLOB` fields are one concatenated STRING.
- [ ] Difficulty is reported as `difficulty` + `difficulty_top64` +
      `wide_difficulty`.
- [ ] Parse limits from §1.6 are enforced and produce errors, not panics.
