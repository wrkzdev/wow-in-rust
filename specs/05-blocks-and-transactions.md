# 05 — Blocks & Transactions

Source: `src/cryptonote_basic/cryptonote_basic.h`,
`src/cryptonote_basic/cryptonote_format_utils.cpp`,
`src/cryptonote_basic/tx_extra.h`, `src/ringct/rctTypes.h`.

All layouts below are the **binary archive** ([04 §1](04-serialization.md)).
Field order is the wire order.

---

## 1. Block

### 1.1 `block_header`

```
varint   major_version         u8
varint   minor_version         u8      # vote for the next fork, not a build tag
varint   timestamp             u64     # unix seconds
[32]     prev_id                       # raw
[4]      nonce                 u32 LE  # raw, NOT varint
--- only if major_version >= 18 (HF_VERSION_BLOCK_HEADER_MINER_SIG) ---
[64]     signature                     # (c, r) Schnorr, see 02 §3.9
[2]      vote                  u16 LE  # raw; MUST be 0, 1 or 2
```

`minor_version` doubles as the legacy hard-fork vote:
`get_block_vote(b) = if b.minor_version == 0 { 1 } else { b.minor_version }`.

`vote` is Wownero's separate on-chain proposal vote:
`0 = abstain, 1 = yes, 2 = no`. `vote > 2` is a **consensus failure** from HF 18.

### 1.2 `block`

```
block_header                          # as above
transaction   miner_tx                # the coinbase
varint        n_tx_hashes
[32] * n      tx_hashes
```

`n_tx_hashes > CRYPTONOTE_MAX_TX_PER_BLOCK (0x10000000)` → parse error.

---

## 2. Transaction

### 2.1 `transaction_prefix`

```
varint   version                      # 1 or 2; 0 or >2 -> parse error
varint   unlock_time                  # height if < 500_000_000, else unix time
varint   n_vin
n_vin  x txin_v                       # tagged variant
varint   n_vout
n_vout x tx_out
varint   extra_len
[extra_len] extra                     # opaque byte blob, parsed separately
```

#### Inputs

```
txin_gen            tag 0xff:  varint height
txin_to_key         tag 0x02:  varint amount
                               varint n_key_offsets
                               n x varint key_offsets    # RELATIVE offsets
                               [32]  k_image
txin_to_script      tag 0x00:  [32] prev, varint prevout, vec<u8> sigset
txin_to_scripthash  tag 0x01:  [32] prev, varint prevout, txout_to_script script,
                               vec<u8> sigset
```

`txin_to_script` / `txin_to_scripthash` have never appeared on chain and are
rejected by `check_tx_inputs`; they must still **parse** for blob round-tripping.

`key_offsets` are relative: `absolute[0] = relative[0]`,
`absolute[i] = absolute[i-1] + relative[i]`. Ring size = `key_offsets.len()`;
"mixin" = `key_offsets.len() - 1`.

#### Outputs

```
tx_out:
  varint  amount
  u8      target tag
    0x02 txout_to_key         : [32] key
    0x03 txout_to_tagged_key  : [32] key, [1] view_tag      # HF 20+
    0x00 txout_to_script      : vec<public_key> keys, vec<u8> script
    0x01 txout_to_scripthash  : [32] hash
```

### 2.2 `transaction`

```
transaction_prefix
if version == 1:
    signatures: for each vin, `get_signature_size(vin)` signatures of 64 bytes,
                written back-to-back with NO length prefixes.
                get_signature_size(txin_gen) = 0
                get_signature_size(txin_to_key) = key_offsets.len()
                (an empty top-level `signatures` vector is allowed only if every
                 input's signature size is 0)
else:               # version 2
    if !vin.is_empty():
        rctSigBase       (serialize_rctsig_base, see 2.3)
        if type != Null:
            rctSigPrunable   (serialize_rctsig_prunable, see 2.4)
```

Three byte offsets in the blob are recorded during parsing and are needed for
hashing (§3):

- `prefix_size`   — bytes consumed by `transaction_prefix`
- `unprunable_size` — bytes consumed by prefix + `rctSigBase`
  (for v1: prefix only)
- the remainder is the prunable part

### 2.3 `rctSigBase`

```
u8      type                                 # RctType
if type == Null: stop
varint  txnFee
if type == Simple (2):                       # only type 2 keeps pseudoOuts here
    inputs x [32] pseudoOuts
ecdhInfo: outputs x
    if type >= Bulletproof2 (6):   [8]  amount           # truncated, mask omitted
    else:                          [32] mask, [32] amount
outPk:    outputs x [32] mask                # only `mask`; `dest` is derived
```

`message` and `mixRing` are **not** serialized — `message` is the tx prefix hash
and `mixRing` is fetched from the chain.

`inputs` = `vin.len()`, `outputs` = `vout.len()`, both from the prefix.

### 2.4 `rctSigPrunable`

Parameterised by `(type, inputs, outputs, mixin)` where
`mixin = vin[0].key_offsets.len() - 1` when `vin[0]` is a `txin_to_key`, else 0.

```
# --- range proofs ---
if type in {SimpleBulletproof(4), FullBulletproof(3)}:
    outputs x Bulletproof                      # one per output, no count prefix
elif type in {BulletproofPlus(8), BulletproofPlusFullCommit(9)}:
    varint nbp                                 # MUST be <= outputs
    nbp x BulletproofPlus
    require n_bulletproof_plus_max_amounts(bpp) >= outputs
elif type in {Bulletproof(5), Bulletproof2(6), Clsag(7)}:
    if type in {Bulletproof2, Clsag}: varint nbp
    else:                             u32 LE nbp          # note: raw u32 for type 5
    nbp x Bulletproof
    require n_bulletproof_max_amounts(bp) >= outputs
else:                                          # Full(1) / Simple(2)
    outputs x rangeSig                         # Borromean: 64 s0, 64 s1, ee, 64 Ci

# --- ring signatures ---
if type in {Clsag(7), BulletproofPlus(8), BulletproofPlusFullCommit(9)}:
    inputs x {
        (mixin+1) x [32] s
        [32] c1
        [32] D                                 # I is NOT serialized
    }
else:
    mg_elements = if type in {Simple, Bulletproof, Bulletproof2, SimpleBulletproof}
                  { inputs } else { 1 }
    mg_elements x {
        (mixin+1) x {
            ss2 = (if type in {Simple, Bulletproof, Bulletproof2, SimpleBulletproof}
                   { 1 } else { inputs }) + 1
            ss2 x [32]
        }
        [32] cc                                # II is NOT serialized
    }

# --- pseudo outputs ---
if type in {Bulletproof(5), Bulletproof2(6), SimpleBulletproof(4), Clsag(7),
            BulletproofPlus(8), BulletproofPlusFullCommit(9)}:
    inputs x [32] pseudoOuts
```

`Bulletproof` on the wire: `A, S, T1, T2, taux, mu, vec<L>, vec<R>, a, b, t`
(`V` omitted). `BulletproofPlus`: `A, A1, B, r1, s1, d1, vec<L>, vec<R>`
(`V` omitted). Inside `rctSigPrunable` the `L`/`R` vectors **do** carry their own
varint length prefixes (they are ordinary `FIELD(vector)`s).

`n_bulletproof_plus_max_amounts(p) = 1 << (p.L.len() - 6)`, summed over proofs.

### 2.5 Pruned transactions

A "pruned" tx is prefix + `rctSigBase` with the prunable part replaced by its
hash. Used by `NOTIFY_RESPONSE_GET_OBJECTS` when `prune = true` and by the
pruning feature. A non-pruning node MUST still be able to **receive** pruned
entries (`tx_blob_entry { blob, prunable_hash }`) and MUST request unpruned data
for blocks it intends to verify.

`get_pruned_transaction_weight` is only defined for types 6, 7, 8, 9.

---

## 3. Hashes

### 3.1 Transaction prefix hash

```
tx_prefix_hash = cn_fast_hash( serialize(transaction_prefix) )
```

This is the `message` for RingCT and the message for v1 ring signatures.

### 3.2 Transaction hash

**v1:** `tx_hash = cn_fast_hash(entire tx blob)`.

**v2:** a hash of three hashes:

```
h0 = tx_prefix_hash
h1 = cn_fast_hash( blob[prefix_size .. unprunable_size] )      # the rctSigBase bytes
h2 = if rct.type == Null { 0u8 * 32 }
     else { tx_prunable_hash }                                  # see 3.3
tx_hash = cn_fast_hash(h0 || h1 || h2)
```

Note `h1` covers exactly the `rctSigBase` region — i.e. the blob slice between
the end of the prefix and the start of the prunable data. Compute those offsets
during parsing; do not re-serialize.

Coinbase transactions from HF 15 are v2 with `rct.type == Null`, so their `h2` is
the null hash and their `h1` covers the single `type` byte (`0x00`).

### 3.3 Transaction prunable hash

`cn_fast_hash` over `blob[unprunable_size ..]` — the serialized
`rctSigPrunable`. Undefined (and unused) for `rct.type == Null`.

### 3.4 `tx_extra` parsing

`extra` is an opaque `Vec<u8>` for serialization purposes; it is parsed as a
sequence of tagged fields:

```
loop until end of buffer:
  u8 tag
  0x00 PADDING:  read zero bytes until EOF or a non-zero byte; total padding
                 length (including the tag) must be <= 255; a non-zero byte
                 inside padding is an error
  0x01 PUBKEY:   [32] tx public key
  0x02 NONCE:    varint len (<= 255), [len] bytes
                 nonce[0] == 0x00 -> 32-byte plain payment id follows (len 33)
                 nonce[0] == 0x01 -> 8-byte encrypted payment id follows (len 9)
  0x03 MERGE_MINING_TAG: varint depth, [32] merkle_root   (length-prefixed blob)
  0x04 ADDITIONAL_PUBKEYS: varint count, count x [32]
  0xDE MYSTERIOUS_MINERGATE: varint len, [len] bytes
  unknown tag -> stop parsing (the remainder is ignored)
```

**Important:** `parse_tx_extra` failing does **not** invalidate the transaction —
`extra` is consensus-opaque. Only its *size* is constrained
(`MAX_TX_EXTRA_SIZE = 1060`, and only as a relay rule, see
[06 §6.3](06-consensus-rules.md)). A wallet that cannot parse `extra` simply
cannot find its outputs in that tx.

`sort_tx_extra` is used when *building* a coinbase: fields are emitted in
ascending tag order. Not required on validation.

### 3.5 Merkle root

```
get_tx_tree_hash(block) = tree_hash([ get_transaction_hash(block.miner_tx) ]
                                    ++ block.tx_hashes)
```

`tree_hash` is [02 §1.4](02-crypto.md#14-tree_hash--the-transaction-merkle-root).

---

## 4. Block hashing

### 4.1 Block hashing blob

```
blob = serialize(block_header)                 # signature+vote included from HF 18
     || get_tx_tree_hash(block)                # 32 bytes, raw
     || varint(block.tx_hashes.len() + 1)      # +1 for the coinbase
```

### 4.2 Block id

```
block_id = cn_fast_hash(block_hashing_blob)
```

The block id is **not** the hash of the full block blob. `calculate_block_hash`
serializes the full block (for the size) but hashes only the hashing blob.

### 4.3 Proof-of-work input

The **same** blob as §4.1, fed to the PoW function
([03 §1](03-pow.md)). Block id and PoW hash differ only in the hash function.

### 4.4 Miner-signature data (HF 18+)

```
tmp = block_header with signature zeroed (vote left intact)
sig_data_blob = serialize(tmp)
              || get_tx_tree_hash(block)
              || varint(tx_hashes.len() + 1)
sig_data = cn_fast_hash(sig_data_blob)
```

`sig_data` is the message for the header signature. Because `vote` is *inside*
`sig_data` but `signature` is zeroed, the signature commits to the vote (so the
vote cannot be tampered with) while remaining computable.

`get_sig_data` / `get_block_hashing_blob_sig_data` in
`cryptonote_format_utils.cpp`.

---

## 5. Weights and sizes

Distinguish carefully:

| Term | Meaning |
|---|---|
| **blob size** | `serialize(tx).len()` |
| **tx weight** | blob size + Bulletproof clawback (below) |
| **block weight** | `get_transaction_weight(miner_tx) + sum(tx weights)`. The coinbase has no range proof, so its weight equals its blob size. This is what the reward penalty and the weight limit use. When syncing *pruned* blocks the weight is instead taken from `checkpoints.dat`'s weight table, since it cannot be recomputed. |
| **long-term block weight** | a clamped function of the block weight, [06 §3.4](06-consensus-rules.md) |

### 5.1 Transaction weight

```rust
fn get_transaction_weight(tx: &Transaction, blob_size: usize) -> u64 {
    if tx.version < 2 { return blob_size as u64; }
    let bp  = is_rct_bulletproof(tx.rct.ty);           // types 3,4,5,6,7
    let bpp = is_rct_bulletproof_plus_any(tx.rct.ty);  // types 8,9
    if !bp && !bpp { return blob_size as u64; }
    if tx.vout.len() <= 2 { return blob_size as u64; }
    if is_rct_old_bulletproof(tx.rct.ty) { return blob_size as u64; }  // types 3,4
    let n_padded = if bpp { n_bulletproof_plus_max_amounts(&tx.rct.p.bpp) }
                   else   { n_bulletproof_max_amounts(&tx.rct.p.bp) };
    blob_size as u64 + clawback(tx, n_padded)
}

fn clawback(tx: &Transaction, n_padded_outputs: usize) -> u64 {
    let plus = matches!(tx.rct.ty, BulletproofPlus | BulletproofPlusFullCommit);
    let bp_base = (32 * ((if plus {6} else {9}) + 7 * 2)) / 2;   // plus: 320, else 368
    if n_padded_outputs <= 2 { return 0; }
    let mut nlr = 0;
    while (1usize << nlr) < n_padded_outputs { nlr += 1; }
    nlr += 6;
    let bp_size = 32 * ((if plus {6} else {9}) + 2 * nlr);
    assert!(tx.vout.len() <= BULLETPROOF_MAX_OUTPUTS);           // 16
    assert!(bp_base * n_padded_outputs >= bp_size);
    (bp_base as u64 * n_padded_outputs as u64 - bp_size as u64) * 4 / 5
}
```

The clawback makes a batched range proof pay roughly what individual proofs would
have cost, so that batching does not under-pay fees.

### 5.2 Fee extraction

```
fee = if tx.version == 1 { sum(input amounts) - sum(output amounts) }
      else                { tx.rct.txnFee }
```

v1 requires the amounts to be non-overflowing and inputs ≥ outputs; see
[06 §5.2](06-consensus-rules.md).

---

## 6. Address formats

```rust
pub struct AccountPublicAddress { spend_public_key: [u8;32], view_public_key: [u8;32] }
```

Serialized (binary archive) as the two keys back-to-back, 64 bytes. Base58
encoding and prefixes: [02 §5](02-crypto.md) and [01 §2](01-constants.md).

Integrated address adds an 8-byte payment id after the two keys (72 bytes).

There is also a legacy non-base58 form: `get_account_address_from_str` treats an
input whose length is exactly `2 * sizeof(public_address_outer_blob)` as raw hex
of `{prefix_u8, address, checksum_u8}` where the checksum is the sum of all
preceding bytes mod 256. Supporting it is optional.

---

## 7. Conformance checklist

- [ ] `nonce` is a raw LE u32; `vote` a raw LE u16; both inside the header.
- [ ] `signature` + `vote` present iff `major_version >= 18`.
- [ ] `vote > 2` fails validation from HF 18.
- [ ] Ring member offsets are relative and converted correctly.
- [ ] v1 `signatures` are written with no length prefixes, sized per input.
- [ ] `rctSigPrunable` array lengths are derived from
      `(type, inputs, outputs, mixin)` as in §2.4, including the raw-`u32` `nbp`
      for RCT type 5.
- [ ] `tx_hash` for v2 is the hash of three hashes using blob offsets, not a
      re-serialization.
- [ ] Coinbase txs from HF 15 hash with `h2 = null_hash`.
- [ ] Block id = `cn_fast_hash(hashing blob)`, not of the full block blob.
- [ ] The hashing blob ends with `varint(tx_count + 1)`.
- [ ] `sig_data` zeroes only `signature`, keeps `vote`.
- [ ] Block weight uses coinbase **blob size** plus tx **weights**.
- [ ] The Bulletproof clawback matches §5.1 including the `4/5` factor and the
      `bp_base` difference between BP and BP+.
- [ ] `tx_extra` parse failures do not invalidate a transaction.
