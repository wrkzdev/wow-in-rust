# 14 — Wallet RPC (`wownero-wallet-rpc`)

Source: `src/wallet/wallet_rpc_server.h` (the method map),
`src/wallet/wallet_rpc_server.cpp`,
`src/wallet/wallet_rpc_server_commands_defs.h`,
`src/wallet/wallet_rpc_server_error_codes.h`.

`WALLET_RPC_VERSION` = major 1, minor 30 → `(1 << 16) | 30` = `65_566`.

This is the wallet's programmatic surface. Exchanges, payment processors and
`wownero-wallet-cli` alternatives depend on it, so **method names, parameter names
and error codes are a compatibility surface** and MUST match.

---

## 1. Transport

Single endpoint: `POST /json_rpc`, JSON-RPC 2.0, same envelope as
[11 §1](11-daemon-rpc.md). There are no `.bin` endpoints and no direct-path
endpoints on the wallet RPC.

```
wownero-wallet-rpc --rpc-bind-port <port>
                   (--wallet-file <f> --password <p> | --wallet-dir <dir>)
                   [--rpc-login user:pass | --disable-rpc-login]
                   [--daemon-address <host:port>] [--trusted-daemon]
                   [--confirm-external-bind]
                   [--testnet|--stagenet]
                   [--prompt-for-password]
                   [--no-initial-sync]
                   [--log-file <path>] [--log-level <0-4|categories>]
```

`--wallet-dir` mode starts with **no wallet open**; the client then calls
`open_wallet` / `create_wallet` / `restore_deterministic_wallet` /
`generate_from_keys`. Every other method returns
`-13 NOT_OPEN` until one succeeds.

Authentication: HTTP **digest** via `--rpc-login`. The reference *requires* either
`--rpc-login` or the explicit `--disable-rpc-login`; a Rust implementation MUST
keep that requirement — an unauthenticated wallet RPC on a reachable interface is
a wallet-draining hole.

---

## 2. Methods

All 114 methods from the reference map. **Bold** = the minimum set for M4.

### 2.1 Wallet management

```
open_wallet        close_wallet        create_wallet
restore_deterministic_wallet          generate_from_keys
change_wallet_password                store
stop_wallet        auto_refresh       refresh
rescan_blockchain  rescan_spent       scan_tx
get_version        get_languages      set_log_level  set_log_categories
set_daemon         estimate_tx_size_and_weight
get_default_fee_priority
setup_background_sync  start_background_sync  stop_background_sync
```

**`open_wallet`, `close_wallet`, `create_wallet`, `store`, `refresh`,
`get_version`, `rescan_blockchain`, `set_daemon`.**

### 2.2 Addresses and accounts

```
get_address        get_address_index   create_address    label_address
validate_address   get_accounts        create_account    label_account
get_account_tags   tag_accounts        untag_accounts    set_account_tag_description
make_integrated_address  split_integrated_address
set_subaddress_lookahead
getaddress                            # legacy alias of get_address
```

**`get_address`, `get_address_index`, `create_address`, `validate_address`,
`get_accounts`, `create_account`, `make_integrated_address`,
`split_integrated_address`.**

### 2.3 Balance and history

```
get_balance        getbalance          # legacy alias
get_height         getheight           # legacy alias
get_transfers      get_transfer_by_txid
get_payments       get_bulk_payments
incoming_transfers
export_outputs     import_outputs
export_key_images  import_key_images
freeze  thaw  frozen
get_attribute  set_attribute
get_tx_notes   set_tx_notes
get_address_book  add_address_book  edit_address_book  delete_address_book
```

**`get_balance`, `get_height`, `get_transfers`, `get_transfer_by_txid`,
`get_payments`, `get_bulk_payments`, `incoming_transfers`.**

### 2.4 Sending

```
transfer           transfer_split
sweep_all          sweep_single       sweep_dust        sweep_unmixable
relay_tx           describe_transfer
sign_transfer      submit_transfer
make_uri           parse_uri
```

**`transfer`, `transfer_split`, `sweep_all`, `sweep_single`, `relay_tx`.**

### 2.5 Keys and proofs

```
query_key          # "mnemonic" | "view_key" | "spend_key"
get_tx_key         check_tx_key
get_tx_proof       check_tx_proof
get_spend_proof    check_spend_proof
get_reserve_proof  check_reserve_proof
sign               verify
is_multisig
```

**`query_key`, `get_tx_key`, `check_tx_key`.**

### 2.6 Mining

```
start_mining       stop_mining
```

Both proxy to the daemon. `start_mining` at HF ≥ 18 will mine invalid blocks
unless the daemon has `--spendkey`; the response SHOULD carry a warning field or
the server SHOULD log one.

### 2.7 Multisig (optional)

```
prepare_multisig   make_multisig     finalize_multisig
exchange_multisig_keys
export_multisig_info  import_multisig_info
sign_multisig      submit_multisig
```

If unimplemented, return `-31 NOT_MULTISIG` / `-48 DISABLED` rather than
succeeding vacuously.

---

## 3. Key method shapes

Only the ones where the shape is easy to get wrong.

### 3.1 `transfer`

Request:

```
destinations       : [ { amount: u64, address: string } ]
account_index      : u32  OPT default 0
subaddr_indices    : [u32] OPT
priority           : u32  OPT       # 0..4
ring_size          : u32  OPT       # MUST be 22
unlock_time        : u64  OPT       # MUST be 0, see below
payment_id         : string OPT     # deprecated; use an integrated address
get_tx_key         : bool OPT
do_not_relay       : bool OPT
get_tx_hex         : bool OPT
get_tx_metadata    : bool OPT
```

Response:

```
tx_hash, tx_key, amount, fee, weight, multisig_txset, unsigned_txset,
tx_blob (if get_tx_hex), tx_metadata (if get_tx_metadata),
spent_key_images : { key_images: [string] }
```

**`unlock_time` must be 0.** A non-zero value produces a transaction the network
will not relay ([06 §6.3](06-consensus-rules.md)); the server returns
`-50 NONZERO_UNLOCK_TIME`. This error code exists in the reference specifically
because of Wownero's relay rule — reproduce it rather than letting the transfer
fail opaquely at `send_raw_transaction`.

`ring_size` other than 22 (at HF ≥ 15) MUST be rejected.

### 3.2 `transfer_split`

Same request plus no `get_tx_key` semantics change; response has arrays:

```
tx_hash_list, tx_key_list, amount_list, fee_list, weight_list,
tx_blob_list, tx_metadata_list, multisig_txset, unsigned_txset,
spent_key_images_list
```

### 3.3 `get_balance`

```
Request : { account_index, address_indices (OPT), all_accounts (OPT),
            strict (OPT) }
Response: { balance, unlocked_balance, multisig_import_needed,
            time_to_unlock, blocks_to_unlock,
            per_subaddress: [ { account_index, address_index, address,
                                balance, unlocked_balance, label,
                                num_unspent_outputs, time_to_unlock,
                                blocks_to_unlock } ] }
```

`blocks_to_unlock` matters much more on Wownero than on Monero because mined
coins lock for 288 blocks (~1 day) — make sure it is computed and returned.

### 3.4 `get_transfers`

```
Request : { in, out, pending, failed, pool, filter_by_height,
            min_height, max_height, account_index, subaddr_indices,
            all_accounts, verbose }
Response: { in: [...], out: [...], pending: [...], failed: [...], pool: [...] }
```

Each entry: `txid, payment_id, height, timestamp, amount, amounts, fee, note,
destinations, type, unlock_time, locked, subaddr_index, subaddr_indices,
address, double_spend_seen, confirmations, suggested_confirmations_threshold`.

`suggested_confirmations_threshold` is computed from the amount and the block
reward; on Wownero the block time is 300 s, so the same threshold means 2.5× the
wall-clock wait compared to Monero. Compute it from the actual target, not a
hard-coded number.

### 3.5 `query_key`

`{ key_type: "mnemonic" | "view_key" | "spend_key" }` →
`{ key: string }`. `"mnemonic"` returns `-43 NON_DETERMINISTIC` for a wallet whose
view key is not `keccak(spend key)` ([12 §1.2](12-wallet-core.md)).

### 3.6 `validate_address`

```
Request : { address, any_net_type (OPT), allow_openalias (OPT) }
Response: { valid, integrated, subaddress, nettype, openalias_address }
```

Must accept all three Wownero prefixes ([01 §2](01-constants.md)) and correctly
classify integrated (108 chars) versus standard/sub (97 chars) mainnet addresses.

### 3.7 `make_uri` / `parse_uri`

Scheme `wownero:` ([12 §6](12-wallet-core.md)).

---

## 4. Error codes

```
 -1 UNKNOWN_ERROR             -2 WRONG_ADDRESS          -3 DAEMON_IS_BUSY
 -4 GENERIC_TRANSFER_ERROR    -5 WRONG_PAYMENT_ID       -6 TRANSFER_TYPE
 -7 DENIED                    -8 WRONG_TXID             -9 WRONG_SIGNATURE
-10 WRONG_KEY_IMAGE          -11 WRONG_URI             -12 WRONG_INDEX
-13 NOT_OPEN                 -14 ACCOUNT_INDEX_OUT_OF_BOUNDS
-15 ADDRESS_INDEX_OUT_OF_BOUNDS                        -16 TX_NOT_POSSIBLE
-17 NOT_ENOUGH_MONEY         -18 TX_TOO_LARGE          -19 NOT_ENOUGH_OUTS_TO_MIX
-20 ZERO_DESTINATION         -21 WALLET_ALREADY_EXISTS -22 INVALID_PASSWORD
-23 NO_WALLET_DIR            -24 NO_TXKEY              -25 WRONG_KEY
-26 BAD_HEX                  -27 BAD_TX_METADATA       -28 ALREADY_MULTISIG
-29 WATCH_ONLY               -30 BAD_MULTISIG_INFO     -31 NOT_MULTISIG
-32 WRONG_LR                 -33 THRESHOLD_NOT_REACHED -34 BAD_MULTISIG_TX_DATA
-35 MULTISIG_SIGNATURE       -36 MULTISIG_SUBMISSION   -37 NOT_ENOUGH_UNLOCKED_MONEY
-38 NO_DAEMON_CONNECTION     -39 BAD_UNSIGNED_TX_DATA  -40 BAD_SIGNED_TX_DATA
-41 SIGNED_SUBMISSION        -42 SIGN_UNSIGNED         -43 NON_DETERMINISTIC
-44 INVALID_LOG_LEVEL        -45 ATTRIBUTE_NOT_FOUND   -46 ZERO_AMOUNT
-47 INVALID_SIGNATURE_TYPE   -48 DISABLED              -49 PROXY_ALREADY_DEFINED
-50 NONZERO_UNLOCK_TIME      -51 IS_BACKGROUND_WALLET  -52 IS_BACKGROUND_SYNCING
```

Notes:

- `-37 NOT_ENOUGH_UNLOCKED_MONEY` vs `-17 NOT_ENOUGH_MONEY` is the distinction
  clients use to decide whether to retry later. With a 288-block coinbase lock,
  `-37` is common for mining pools and solo miners; return the right one.
- `-3 DAEMON_IS_BUSY` maps from the daemon's `CORE_BUSY`; clients retry on it.
- `-50 NONZERO_UNLOCK_TIME` is Wownero-specific in practice (§3.1).

---

## 5. Operational requirements

- The wallet RPC holds the wallet open and refreshes on a timer when
  `auto_refresh` is on. `refresh` forces one; `auto_refresh` toggles it.
- `store` persists the cache. The server SHOULD also store periodically and on
  shutdown — an unflushed cache means a long rescan next start.
- Concurrent requests: the reference serialises everything under one wallet lock.
  Do the same; a wallet is not a concurrent data structure.
- `--prompt-for-password` asks on stdin at startup instead of taking `--password`.
- Long operations (`rescan_blockchain`, `refresh` on a fresh wallet) block the
  request. Clients expect that; do not add an async job API that existing clients
  cannot use.

---

## 6. Conformance checklist

- [ ] Single `POST /json_rpc` endpoint, JSON-RPC 2.0.
- [ ] Either `--rpc-login` or an explicit `--disable-rpc-login` is required.
- [ ] `--wallet-dir` mode returns `-13 NOT_OPEN` until a wallet is opened.
- [ ] All method names from §2 exist, including the legacy aliases
      `getbalance`, `getaddress`, `getheight`.
- [ ] `transfer` rejects non-zero `unlock_time` with `-50` and ring sizes other
      than 22.
- [ ] `get_balance` returns `blocks_to_unlock` / `time_to_unlock`.
- [ ] `query_key "mnemonic"` returns `-43` for a non-deterministic wallet.
- [ ] `-17` vs `-37` are distinguished correctly.
- [ ] Error codes match §4 exactly.
- [ ] `WALLET_RPC_VERSION` reports major 1, minor 30.
- [ ] Unimplemented optional methods return `-48 DISABLED` or `-31 NOT_MULTISIG`,
      never a fake success.
