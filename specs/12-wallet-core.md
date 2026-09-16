# 12 — Wallet Core

Source: `src/wallet/wallet2.h`, `src/wallet/wallet2.cpp` (~16 kLOC — the single
largest file in the tree), `src/cryptonote_core/cryptonote_tx_utils.cpp`
(`construct_tx_and_get_tx_key`), `src/device/device_default.cpp`.

This is the library both `wownero-wallet-cli` and `wownero-wallet-rpc` sit on top
of. It is not consensus code, but **it must produce transactions that the
consensus rules in [06](06-consensus-rules.md) accept**, and it must read the
existing C++ wallet files.

---

## 1. Keys and accounts

### 1.1 Key material

```rust
pub struct AccountKeys {
    pub account_address: AccountPublicAddress,   // (spend_public, view_public)
    pub spend_secret_key: SecretKey,             // zero for view-only wallets
    pub view_secret_key: SecretKey,
    pub multisig_keys: Vec<SecretKey>,           // optional
    pub device_derivation_path: String,
}
```

Wallet kinds:

| Kind | `spend_secret_key` | `view_secret_key` | Can spend |
|---|---|---|---|
| Normal | set | set | yes |
| View-only ("watch-only") | zero | set | no (can sign nothing) |
| Multisig | partial | set | with cosigners |
| Background-sync | zero while backgrounded | set | no |

### 1.2 Deterministic wallets

A **deterministic** wallet is one where `view_secret_key == sc_reduce32(keccak(spend_secret_key))`
([02 §3.2](02-crypto.md)). Only deterministic wallets have a 25-word mnemonic
seed. `is_deterministic()` tests exactly that relation, so a wallet restored from
separate keys is non-deterministic and `seed` fails.

### 1.3 Subaddresses

Accounts (`major`) and addresses (`minor`) as in [02 §3.8](02-crypto.md). The
wallet precomputes a table from subaddress spend public key → `(major, minor)` so
scanning is a hash-map lookup. Lookahead defaults:
`subaddress_lookahead_major = 50`, `subaddress_lookahead_minor = 200`. Both are
persisted in the keys file and settable.

Index `(0, 0)` is the main address.

---

## 2. File formats

A wallet is three files:

```
<name>.keys          encrypted keys + settings
<name>               the cache (transfers, subaddresses, tx history)
<name>.address.txt   the primary address as plain text (convenience)
```

plus, when background sync is configured, `<name>.background.keys` and
`<name>.background` (the same formats, keyed differently).

### 2.1 Keys file

Outer container, **binary archive** ([04 §1](04-serialization.md)):

```
keys_file_data:
    [8]      iv                      # chacha_iv, FIELD (raw)
    varint   len
    [len]    account_data            # ChaCha20 ciphertext
```

`account_data` decrypts to a **JSON object**. Key derivation:
`generate_chacha_key(password, kdf_rounds)` = CryptoNight v0 of the password,
re-hashed `kdf_rounds - 1` more times ([02 §7](02-crypto.md)).

JSON members (all present in the reference writer; readers MUST tolerate missing
members by using defaults):

```
key_data                      # binary blob: the serialized account (see 2.1.1)
seed_language
key_on_device, watch_only, multisig, multisig_threshold,
multisig_signers, multisig_derivations, multisig_rounds_passed,
always_confirm_transfers, print_ring_members, store_tx_info,
default_mixin, default_priority, auto_refresh, refresh_type,
refresh_height, skip_to_height, confirm_non_default_ring_size,
ask_password, max_reorg_depth, min_output_count, min_output_value,
default_decimal_point, merge_destinations, confirm_backlog,
confirm_backlog_threshold, confirm_export_overwrite, auto_low_priority,
nettype, segregate_pre_fork_outputs, key_reuse_mitigation2,
segregation_height, ignore_fractional_outputs, ignore_outputs_above,
ignore_outputs_below, track_uses, background_sync_type,
show_wallet_name_when_locked, inactivity_lock_timeout,
setup_background_mining, subaddress_lookahead_major,
subaddress_lookahead_minor, original_keys_available, export_format,
load_deprecated_formats, encrypted_secret_keys,
device_name, device_derivation_path,
original_address, original_view_secret_key,      # multisig only
persistent_rpc_client_id, auto_mine_for_rpc_payment,
credits_target, enable_multisig, custom_background_key
```

Booleans are stored as `0`/`1` **integers**, not JSON `true`/`false`.

#### 2.1.1 `key_data`

The binary-archive serialization of `account_base`:

```
account_keys:
    account_public_address  { [32] spend_public, [32] view_public }
    [32] spend_secret_key
    [32] view_secret_key
    (multisig_keys: varint count + count * [32])   # only if multisig
uint64 creation_timestamp
```

If `encrypted_secret_keys` is set, the two secret keys inside `key_data` are
themselves ChaCha20-encrypted with the same key (`account_base::encrypt_keys`),
except that the **view key is left decrypted** when
`ask_password == AskPasswordToDecrypt` so the wallet can scan without the
password. Reproduce `encrypt_keys` / `decrypt_viewkey` exactly or existing
wallets will not open.

### 2.2 Cache file

Same outer container (`cache_file_data { iv, cache_data }`), but the key is

```
cache_key = derive_cache_key(chacha_key, HASH_KEY_WALLET_CACHE /* 0x8d */)
```

and the plaintext is a **Boost portable binary archive** of `wallet2`'s member
data (transfers, key images, payments, subaddress maps, tx notes, attributes,
address book, …).

**Do not attempt to reimplement the Boost archive format.** Instead:

- Define your own cache format (whatever is convenient — bincode, CBOR, or a small
  SQLite or LMDB store), and
- Detect a C++ cache and **rebuild from the chain**: the keys file alone is
  sufficient to reconstruct everything by rescanning from `refresh_height`, which
  takes minutes, not hours, because the wallet only needs `get_blocks.bin`.

State this clearly in the CLI: "this wallet's cache was written by the C++ wallet;
rescanning". Then write your own cache under a different name (e.g.
`<name>.rscache`) so both implementations can coexist.

The keys file **is** shared and MUST be read and written compatibly — that is
where the money is.

### 2.3 Locking

The C++ takes an exclusive file lock on `<name>.keys` for the wallet's lifetime.
Do the same, so two processes cannot corrupt a wallet.

---

## 3. Scanning (refresh)

### 3.1 The loop

```
1. short_chain_history = [ last 10 block hashes, then exponential gaps,
                           genesis last ]   (same shape as the P2P sync history)
2. GET /get_blocks.bin { block_ids: short_chain_history, start_height, prune }
3. for each returned block:
     if block hash != our stored hash at that height -> REORG: detach and retry
     process_new_blockchain_entry(block, output_indices)
4. repeat until current_height reached
5. process the pool (get_transaction_pool_hashes.bin + get_transactions)
```

`refresh_height` is where a new wallet starts. `--restore-height` /
`set restore-height` sets it. A wallet created now should default to
`current_height - <a safety margin>`; the C++ estimates a height from the
creation timestamp using a 300 s block time.

### 3.2 Per-output scan

For each transaction in each block, for each output index `i`:

```
R  = tx public key from tx_extra (TX_EXTRA_TAG_PUBKEY), plus any
     TX_EXTRA_TAG_ADDITIONAL_PUBKEYS entry i for subaddress sends
D  = generate_key_derivation(R, view_secret_key)

if output is txout_to_tagged_key:
    if derive_view_tag(D, i) != output.view_tag { skip }      # 1/256 survive
P' = derive_subaddress_public_key(output.key, D, i)
if P' is in the subaddress table:
    this output is ours, at subaddress index = table[P']
    amount = if tx.version == 1 { output.amount }
             else { decode_rct(tx.rct, D_scalar, i) }         # [02 §4.5]
    key_image = generate_key_image(output.key, x)
        where x = derive_secret_key(D, i, spend_secret_key)
               (+ subaddress secret key m if the index is not (0,0))
```

The **view tag** check is the whole point of HF 20: it removes 255/256 of the
expensive `derive_subaddress_public_key` work. Implement it as the first filter.

For a view-only wallet, `x` cannot be computed, so key images come from an
`import_key_images` file produced by a full wallet.

### 3.3 Reorg handling

If a returned block's hash differs from the stored hash at that height, detach:
drop all transfers, payments and key images at or above the split height, then
re-request. `max_reorg_depth` (default 0 = unlimited) bounds how far back the
wallet will accept a reorg.

### 3.4 Background sync

`setup_background_sync <off|reuse-wallet-password|custom-background-password>`
stores a **view-only** copy of the keys in `<name>.background.keys` (domain byte
`HASH_KEY_BACKGROUND_KEYS_FILE = 0x8f`, cache domain
`HASH_KEY_BACKGROUND_CACHE = 0x8e`) so a daemon-side process can keep the wallet
synced without the spend key in memory. Optional for the first release; if
omitted, the CLI commands `setup_background_sync`, `start_background_sync` and
`stop_background_sync` MUST report "not supported" rather than silently
succeeding.

---

## 4. Transfer construction

### 4.1 Inputs

```rust
pub struct TransferDetails {
    pub block_height: u64,
    pub tx: TransactionPrefix,
    pub txid: Hash256,
    pub internal_output_index: u64,
    pub global_output_index: u64,      // the amount output index
    pub spent: bool,
    pub frozen: bool,
    pub spent_height: u64,
    pub key_image: KeyImage,
    pub mask: Key,                    // the amount blinding factor
    pub amount: u64,
    pub rct: bool,
    pub key_image_known: bool,
    pub key_image_request: bool,
    pub pk_index: u64,
    pub subaddr_index: SubaddressIndex,
    pub uses: Vec<(u64, Hash256)>,    // if track_uses
}
```

A transfer is spendable iff: not `spent`, not `frozen`, `key_image_known`,
and unlocked (`is_transfer_unlocked`, §4.2).

### 4.2 Unlock check (wallet side)

```
unlocked = is_tx_spendtime_unlocked(td.tx.unlock_time, td.block_height)
        && td.block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE (4) <= chain_height
```

Coinbase outputs carry `unlock_time = height + 288` at HF ≥ 18, so mined coins
take ~1 day to become spendable. The wallet MUST report the locked balance
separately (`balance` vs `unlocked_balance`).

### 4.3 Decoy (ring member) selection

Ring size is **22** at HF ≥ 9 — `min_mixin = 21`, and the *exact* ring size is
enforced from HF 15, so the wallet MUST use exactly 22 members and the same count
for every input.

Selection uses the **gamma distribution** picker from Miller et al.
(`gamma_picker` in `wallet2.cpp`):

```
GAMMA_SHAPE = 19.28
GAMMA_SCALE = 1 / 1.61
DEFAULT_UNLOCK_TIME  = CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE * DIFFICULTY_TARGET_V2
                     = 4 * 300 = 1200 seconds
RECENT_SPEND_WINDOW  = 15 * DIFFICULTY_TARGET_V2 = 4500 seconds
```

(Both derived constants differ from Monero's because `DIFFICULTY_TARGET_V2` is
300, not 120.)

Setup, given `rct_offsets` = the cumulative RingCT output count per block from
`get_output_distribution`:

```
blocks_in_a_year    = 86400 * 365 / 300                 # = 105_120 on Wownero
blocks_to_consider  = min(rct_offsets.len(), blocks_in_a_year)
outputs_to_consider = rct_offsets.last()
                      - (if blocks_to_consider < len { rct_offsets[len - blocks_to_consider - 1] } else { 0 })
end                 = rct_offsets.len() - (max(1, 4) - 1)     # drop the 3 youngest blocks
num_rct_outputs     = rct_offsets[end - 1]
average_output_time = 300 * blocks_to_consider / outputs_to_consider as f64
```

Pick:

```
x = exp(gamma_sample(19.28, 1/1.61))
if x > 1200 { x -= 1200 } else { x = rand_idx(RECENT_SPEND_WINDOW) as f64 }
output_index = (x / average_output_time) as u64
if output_index >= num_rct_outputs { return BAD_PICK }
output_index = num_rct_outputs - 1 - output_index
block = lower_bound(rct_offsets[..end], output_index)
then pick uniformly among the outputs in that block
```

Note `blocks_in_a_year` uses `DIFFICULTY_TARGET_V2 = 300`, so the constant is
105,120 on Wownero versus 262,800 on Monero. Using Monero's value would make the
wallet's decoy distribution distinguishable — a privacy bug, not a consensus bug,
but a real one.

The real spend is placed at a uniformly random position in the sorted ring, and
`key_offsets` are then converted to relative form
([05 §2.1](05-blocks-and-transactions.md)).

### 4.4 Input selection

`transfer_selected_rct` / `create_transactions_2`:

- Prefer outputs from the same subaddress account.
- Honour `min_output_count`, `min_output_value`, `ignore_fractional_outputs`,
  `ignore_outputs_above`, `ignore_outputs_below`.
- Split into multiple transactions when a single one would exceed the weight that
  the current `block_weight_limit` allows, or exceed
  `BULLETPROOF_PLUS_MAX_OUTPUTS (16)` outputs.
- Always produce **at least 2 outputs** (HF 15 rule) — add a zero-amount dummy
  change output to the sender's own address if necessary.

### 4.5 Fee

```
fee_per_byte = the estimate from get_fee_estimate for the chosen priority
               (4 tiers at HF >= 20, see [06 §6.4])
weight       = get_transaction_weight(tx, blob_size)     # includes the BP+ clawback
fee          = round_up(weight * fee_per_byte, quantization_mask = 1000)
```

The wallet must iterate: adding the fee changes the change amount, which can
change the number of outputs, which changes the weight. `FEE_CALCULATION_MAX_RETRIES = 10`.

The fee a transaction pays is its **built** weight's, not the estimate's.
`create_transactions_2` estimates, builds, recomputes the fee from the blob, and
builds again at that fee (the difference moves the change, or a sweep's amount),
repeating while the blob needs more than it pays. The estimate only chooses
inputs; the estimator runs a few bytes over, so a fee charged on it is a little
too high.

Priorities map to the four tiers returned by `get_fee_estimate`
(1 = low … 4 = high), asked for with `grace_blocks = FEE_ESTIMATE_GRACE_BLOCKS (10)`.

**Priority 0 is not normal.** `adjust_priority(0)`, with `default_priority == 0`
and `auto_low_priority` on (the default), returns **1** unless the pool holds at
least a full reward zone (`block_weight_limit / 2`) of transactions paying the low
rate or more, or the ten blocks below the wallet's height fill more than 80% of
ten zones; then **2**. When it cannot tell (a failed call, fewer than ten blocks)
it returns 0, and `get_base_fee` maps a 0 that reaches it to the low tier too.
`simple_wallet::transfer` starts from `default_priority`; `sweep_all` and the
wallet RPC start from 0, so a default priority set there leaves them at the low
tier. `default_priority` and `auto_low_priority` are persisted settings.

### 4.6 Building the transaction

`construct_tx_with_tx_key`:

```
tx.version = 2
tx.unlock_time = 0                     # MUST be 0: a non-zero unlock time is not
                                       #   relayed ([06 §6.3])
rct_config = { range_proof_type: RangeProofPaddedBulletproof,
               bp_version: if bulletproof_plus { 4 } else { 3 } }
rct_type   = BulletproofPlus (8)       # the only legal type at HF 20

tx_key = random keypair
tx.extra:
    TX_EXTRA_TAG_PUBKEY(tx_key.pub)
    TX_EXTRA_TAG_ADDITIONAL_PUBKEYS(...)  # one per output, if any destination
                                          #   is a subaddress
    TX_EXTRA_NONCE(encrypted payment id)  # if an integrated address was used
    then sort_tx_extra()

for each output j with destination (spend D, view C):
    r = if destination is a subaddress { tx_key.sec * D-derived }
        else { tx_key.sec }
    derivation = generate_key_derivation(C, r)
    P_j        = derive_public_key(derivation, j, D)
    view_tag   = derive_view_tag(derivation, j)        # HF >= 20
    target     = txout_to_tagged_key(P_j, view_tag)    # HF >= 20
    amount_key = derivation_to_scalar(derivation, j)
    ecdh       = encode(amount, amount_key)            # [02 §4.5]

inputs: sorted by DESCENDING key image (memcmp), per [06 §5.7]
CLSAG over the pre_mlsag_hash                          # [02 §4.2, §4.3]
Bulletproofs+ over the output amounts, padded to a power of two
outPk[i].mask = C_i / 8                                # RCT type 8 convention
txnFee = fee
```

> **The reference wallet never builds RCT type 9.** `genRctSimple` derives the
> type from `rct_config.bp_version`, and `bp_version` 4 maps to
> `RCTTypeBulletproofPlus` unless the caller pre-set `rv.type` to
> `RCTTypeBulletproofPlus_FullCommit` — which `wallet2` does not do. The
> `bulletproof_plus_full_commit` flag in `wallet2.cpp` only feeds the size/weight
> *estimators*. So for the Rust wallet, **type 9 needs no construction path**;
> the daemon needs only to *validate* it (for the testnet HF 21).

Order of operations that trips people up:

1. Build the prefix **completely** (including `extra`, sorted) before computing
   `tx_prefix_hash`.
2. `tx_prefix_hash` is the RingCT `message`.
3. Build the range proof, then set `outPk[i].mask` from the proof's commitments
   (`scalarmult8(C[i])` for the non-legacy types, per
   [02 §4.4](02-crypto.md)).
4. Compute `pre_mlsag_hash` **after** the range proof exists, since it hashes the
   proof elements.
5. Sign the CLSAGs last.

### 4.7 Sweeping

- `sweep_all` — send every unlocked output to one destination, splitting into as
  many transactions as needed.
- `sweep_single <key_image>` — spend exactly one output.
- `sweep_below <amount>` — only outputs under a threshold.
- `sweep_dust` / `sweep_unmixable` — spend outputs whose amount has too few
  same-amount outputs on chain to form a ring. On Wownero today there are no
  unmixable outputs, so these are effectively no-ops; they MUST still exist and
  report "no unmixable outputs found".

---

## 5. Proofs

All use the Schnorr scheme from [02 §3.9](02-crypto.md) with domain separation.

| Proof | Command | What it proves |
|---|---|---|
| Tx key | `get_tx_key` / `check_tx_key` | reveals the tx secret key to a third party |
| Tx proof (OutProofV2 / InProofV2) | `get_tx_proof` / `check_tx_proof` | a tx paid a given address, without revealing the tx key. Domain `"TXPROOF_V2"` |
| Spend proof | `get_spend_proof` / `check_spend_proof` | the prover spent a given tx |
| Reserve proof | `get_reserve_proof` / `check_reserve_proof` | the prover controls at least N coins |
| Message signature | `sign` / `verify` | domain `"WowneroMessageSignature"` — **Wownero-specific**, so Monero tooling cannot verify Wownero signatures and vice versa |

The V1 (`"OutProofV1"` / no domain) variants must still *verify* for old proofs;
new proofs are V2.

---

## 6. Payment URIs

```
wownero:<address>[?tx_amount=<amount>][&tx_payment_id=<id>]
        [&recipient_name=<name>][&tx_description=<desc>]
```

`make_uri` / `parse_uri` in `wallet2.cpp`. Amounts are decimal WOW strings with up
to 11 decimals. The scheme string is exactly `wownero:` — check for it
case-sensitively, as the C++ does (`uri.substr(0,8) != "wownero:"`).

---

## 7. Multisig, hardware wallets, MMS — optional

Deferred. If not implemented:

- `is_multisig` returns `false`.
- `prepare_multisig`, `make_multisig`, `exchange_multisig_keys`,
  `finalize_multisig`, `export/import_multisig_info`, `sign_multisig`,
  `submit_multisig`, `mms` MUST return a clear "not supported in this build"
  error.
- A keys file with `multisig: 1` MUST be **refused** to open, not opened
  incorrectly.
- The `HASH_KEY_MULTISIG*` domain separators are documented in
  [01 §10](01-constants.md) for when this is picked up.

---

## 8. Cold signing / offline flows

| File | Produced by | Consumed by |
|---|---|---|
| unsigned tx set | `transfer` on a view-only wallet | `sign_transfer` on the cold wallet |
| signed tx set | `sign_transfer` | `submit_transfer` on the hot wallet |
| key image export | `export_key_images` on the cold wallet | `import_key_images` on the view-only wallet |
| output export | `export_outputs` | `import_outputs` |

All are the binary archive of a versioned struct, optionally base64-wrapped
depending on `export_format` (`Binary` or `Ascii`). If not implemented in the
first release, the CLI commands MUST fail loudly.

---

## 9. Conformance checklist

- [ ] The `.keys` file is read and written byte-compatibly with the C++ wallet,
      including `encrypted_secret_keys` and the decrypted-view-key case.
- [ ] Booleans in the keys JSON are `0`/`1` integers.
- [ ] A C++ cache file is detected and the wallet rescans rather than
      misinterpreting it.
- [ ] The keys file is exclusively locked while the wallet is open.
- [ ] Scanning checks the **view tag first** for tagged-key outputs.
- [ ] `is_deterministic` tests `view == sc_reduce32(keccak(spend))`; a
      non-deterministic wallet has no seed.
- [ ] Ring size is exactly 22 and identical across all inputs.
- [ ] `blocks_in_a_year` uses the 300 s target (105,120), not Monero's value.
- [ ] Every transaction has at least 2 outputs.
- [ ] `tx.unlock_time` is 0 on every wallet-built transaction.
- [ ] Inputs are sorted by descending key image.
- [ ] `outPk[i].mask` is `C/8` for RCT type 8.
- [ ] `pre_mlsag_hash` is computed after the range proof exists.
- [ ] Fee iteration converges within 10 retries and uses the tx **weight**.
- [ ] Message signatures use the `"WowneroMessageSignature"` domain.
- [ ] URIs use the `wownero:` scheme.
- [ ] Unimplemented features fail loudly; a multisig keys file is refused.
