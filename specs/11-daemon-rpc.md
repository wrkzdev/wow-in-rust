# 11 — Daemon RPC

Source: `src/rpc/core_rpc_server.h` (the URI map), `src/rpc/core_rpc_server.cpp`,
`src/rpc/core_rpc_server_commands_defs.h`,
`src/rpc/core_rpc_server_error_codes.h`, `src/rpc/rpc_args.cpp`.

Default mainnet port **34568**. Field names in this document are exactly the JSON
keys.

---

## 1. Transports

| Path | Body | Notes |
|---|---|---|
| `POST /json_rpc` | JSON-RPC 2.0 | the `method` dispatch table, §4 |
| `POST /<name>` | plain JSON | the direct endpoints, §3 |
| `POST /<name>.bin` | epee portable storage | the binary endpoints, §5 |

Envelope for `/json_rpc`:

```json
{"jsonrpc":"2.0","id":"0","method":"get_info","params":{}}
{"jsonrpc":"2.0","id":"0","result":{ ... }}
{"jsonrpc":"2.0","id":"0","error":{"code":-1,"message":"..."}}
```

Direct endpoints return the result object at the top level, always with a
`status` field (`"OK"`, `"BUSY"`, `"NOT MINING"`, `"PAYMENT REQUIRED"`, or an
error string) and an `untrusted` boolean.

### 1.1 Content limits

`MAX_RPC_CONTENT_LENGTH = 1_048_576` bytes for requests.
`DEFAULT_RPC_SOFT_LIMIT_SIZE = 25 MiB` soft cap on responses; over it, the server
truncates the result and returns an error rather than allocating unboundedly.

### 1.2 Authentication and TLS

- `--rpc-login user[:pass]` enables **HTTP digest** auth (not basic). If the
  password is omitted, a random one is generated and printed.
- `--rpc-ssl <enabled|disabled|autodetect>` with the `--rpc-ssl-*` options. A
  Rust implementation MAY defer TLS to a reverse proxy, but MUST then refuse to
  bind a non-loopback address without `--confirm-external-bind`.
- `--rpc-access-control-origins` sets CORS headers.
- Rate limiting: `DEFAULT_RPC_MAX_CONNECTIONS (100)`,
  `DEFAULT_RPC_MAX_CONNECTIONS_PER_PUBLIC_IP (3)`,
  `_PER_PRIVATE_IP (25)`, and an IP ban after
  `RPC_IP_FAILS_BEFORE_BLOCK (3)` failures unless `--disable-rpc-ban`.

### 1.3 Restricted mode

Two ways to get it:

- `--restricted-rpc` — the whole server is restricted.
- `--rpc-restricted-bind-port` — a *second* listener that is restricted while the
  primary one is not.

In restricted mode the endpoints marked **R** in §3–§4 are **not routed at all**
(the URI map omits them) and return the server's standard 404/`UNSUPPORTED_RPC`
path. In addition, several permitted endpoints behave differently:

- `get_info` omits or zeroes operationally sensitive fields.
- `get_blocks.bin` and `get_transactions` cap the number of items returned
  (`COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT = 1000`,
  `..._MAX_TX_COUNT = 20000`).
- `get_output_distribution` refuses requests for the full history.
- Fields exposing peer addresses are suppressed.

`--public-node` advertises the node's RPC port in the P2P peer list; it implies
the operator intends the restricted listener to be reachable.

---

## 2. Common response fields

Every response carries:

```
status    : string   # "OK" on success
untrusted : bool     # true if the answer came from a bootstrap daemon or the
                     #   node is not yet synced
```

`rpc_access_response_base` adds `credits : u64` and `top_hash : string` when RPC
payments are enabled. If payments are not implemented, emit `credits: 0` and
`top_hash: ""` so clients that read the fields do not break.

### 2.1 128-bit difficulty encoding

Wherever a difficulty appears, **three** fields are emitted
(`store_difficulty()`):

```
difficulty        : u64      # low 64 bits
difficulty_top64  : u64      # high 64 bits
wide_difficulty   : string   # "0x"-prefixed hex of the full u128
```

Same for cumulative difficulty:
`cumulative_difficulty`, `cumulative_difficulty_top64`,
`wide_cumulative_difficulty`.

---

## 3. Direct endpoints

**R** = removed in restricted mode.

| Path(s) | Purpose |
|---|---|
| `/get_height`, `/getheight` | `{height, hash}` |
| `/get_transactions`, `/gettransactions` | fetch txs by hash, as hex/JSON, with pool lookup |
| `/get_alt_blocks_hashes` | hashes of known alternative blocks |
| `/is_key_image_spent` | per key image: 0 unspent, 1 spent in chain, 2 spent in pool |
| `/send_raw_transaction`, `/sendrawtransaction` | submit a tx; §3.1 |
| `/start_mining` **R** | start the built-in miner |
| `/stop_mining` **R** | |
| `/mining_status` **R** | |
| `/save_bc` **R** | flush the store |
| `/get_peer_list` **R** | white + gray lists |
| `/get_public_nodes` | peers that advertised an RPC port |
| `/set_log_hash_rate` **R** | |
| `/set_log_level` **R** | |
| `/set_log_categories` **R** | |
| `/get_transaction_pool` | full pool with metadata |
| `/get_transaction_pool_hashes` | pool tx hashes (hex) |
| `/get_transaction_pool_hashes.bin` | pool tx hashes (binary) |
| `/get_transaction_pool_stats` | histogram of the pool |
| `/set_bootstrap_daemon` **R** | |
| `/stop_daemon` **R** | |
| `/get_info`, `/getinfo` | the main status endpoint; §3.2 |
| `/get_net_stats` **R** | byte counters |
| `/get_limit` | current rate limits |
| `/set_limit` **R** | |
| `/out_peers` **R** | get/set the outgoing connection target |
| `/in_peers` **R** | get/set the incoming connection limit |
| `/get_outs` | output keys by `(amount, index)`, JSON |
| `/update` **R** | check for / download an update |
| `/pop_blocks` **R** | pop N blocks |

### 3.1 `send_raw_transaction`

Request:

```
tx_as_hex        : string
do_not_relay     : bool  OPT default false
do_sanity_checks : bool  OPT default true
```

Response adds one boolean per rejection reason, all of which MUST be present:

```
reason              : string
not_relayed         : bool
low_mixin           : bool
double_spend        : bool
invalid_input       : bool
invalid_output      : bool
too_big             : bool
overspend           : bool
fee_too_low         : bool
too_few_outputs     : bool
sanity_check_failed : bool
tx_extra_too_big    : bool
nonzero_unlock_time : bool
```

`tx_extra_too_big` and `nonzero_unlock_time` correspond to the Wownero relay
policies in [06 §6.3](06-consensus-rules.md) and are the two rejections a wallet
author is most likely to hit.

`do_sanity_checks` runs `tx_sanity_check` — a heuristic that rejects transactions
whose ring members are implausibly clustered. It is policy, not consensus.

### 3.2 `get_info`

The fields clients depend on:

```
height, target_height, difficulty(+top64+wide), target,
tx_count, tx_pool_size, alt_blocks_count,
outgoing_connections_count, incoming_connections_count,
rpc_connections_count, white_peerlist_size, grey_peerlist_size,
mainnet, testnet, stagenet, nettype,
top_block_hash, cumulative_difficulty(+top64+wide),
block_size_limit, block_weight_limit,
block_size_median, block_weight_median,
adjusted_time, start_time, free_space,
offline, untrusted, bootstrap_daemon_address,
height_without_bootstrap, was_bootstrap_ever_used,
database_size, update_available, version,
synchronized, busy_syncing,
restricted, credits, top_hash
```

`block_size_limit` / `block_size_median` are legacy aliases for the weight
fields; emit both with the same values.

`nettype` is one of `"mainnet"`, `"testnet"`, `"stagenet"`, `"fakechain"`.

---

## 4. JSON-RPC methods

| Method (and alias) | Purpose |
|---|---|
| `get_block_hash` / `on_get_block_hash` / `on_getblockhash` | height → hash |
| `get_block_template` / `getblocktemplate` | mining template; §4.1 |
| `get_miner_data` | a compact template for pools |
| `calc_pow` **R** | compute a PoW hash for given inputs |
| `add_aux_pow` | merge-mining aux PoW insertion |
| `submit_block` / `submitblock` | submit a mined block; §4.2 |
| `generateblocks` **R** | regtest only; §4.3 |
| `get_last_block_header` / `getlastblockheader` | |
| `get_block_header_by_hash` / `getblockheaderbyhash` | |
| `get_block_header_by_height` / `getblockheaderbyheight` | |
| `get_block_headers_range` / `getblockheadersrange` | |
| `get_block` / `getblock` | header + blob + tx hashes + JSON |
| `get_connections` **R** | |
| `get_info` | same payload as `/get_info` |
| `hard_fork_info` | §4.4 |
| `set_bans` **R** / `get_bans` **R** / `banned` **R** | |
| `flush_txpool` **R** | |
| `get_output_histogram` | |
| `get_version` | `{version, release, current_height, target_height, hard_forks}` |
| `get_coinbase_tx_sum` **R** | |
| `get_fee_estimate` | §4.5 |
| `get_alternate_chains` **R** | |
| `relay_tx` **R** | |
| `sync_info` **R** | per-peer sync state and the span queue |
| `get_txpool_backlog` | |
| `get_output_distribution` | |
| `prune_blockchain` **R** | optional |
| `flush_cache` **R** | |
| `rpc_access_info` / `rpc_access_submit_nonce` / `rpc_access_pay` | RPC payments (optional) |
| `rpc_access_tracking` **R** / `rpc_access_data` **R** / `rpc_access_account` **R** | RPC payments (optional) |

### 4.1 `get_block_template`

Request: `{wallet_address, reserve_size, prev_block (optional, hex)}`.

Response:

```
blocktemplate_blob : string (hex)   # the full serialized block
blockhashing_blob  : string (hex)   # the PoW input, per [05 §4.1]
difficulty(+top64+wide)
height             : u64
expected_reward    : u64
prev_hash          : string (hex)
reserved_offset    : u64            # where to write the extra nonce
seed_height        : u64            # RandomWOW, if major_version >= 13
seed_hash          : string (hex)
next_seed_hash     : string (hex)   # only if it differs from seed_hash
vote               : u16            # ALWAYS 0 -- see below
status, untrusted
```

`wallet_address` MUST be a main address, not a subaddress
(`CORE_RPC_ERROR_CODE_MINING_TO_SUBADDRESS`).

**The template's `signature` is zero and `vote` is 0.** At HF ≥ 18 a block built
from this template is rejected by `prevalidate_miner_transaction` unless the
submitter signs the header with the spend key of `wallet_address`
([06 §4.1](06-consensus-rules.md)). The endpoint MUST still be implemented —
explorers and monitoring use it — but a Rust daemon SHOULD log a warning when it
is called at HF ≥ 18 so operators are not mystified by rejected blocks.

### 4.2 `submit_block`

Params: an array of hex block blobs. For each, parse, then
`handle_incoming_block`. Errors:

```
-6  WRONG_BLOCKBLOB        # unparseable
-10 WRONG_BLOCKBLOB_SIZE
-7  BLOCK_NOT_ACCEPTED     # failed validation (this is what an unsigned
                           #   HF-18+ block gets)
```

Response: `{status, untrusted, block_id}`.

### 4.3 `generateblocks`

Regtest only (`CORE_RPC_ERROR_CODE_REGTEST_REQUIRED` otherwise). Builds
templates, mines them at the fixed difficulty, and submits them. Note that it
explicitly sets `signature = {}` and `vote = 0`, so it only works on
`FAKECHAIN`.

### 4.4 `hard_fork_info`

Request `{version}` (0 = current). Response:

```
version         : u8     # the version in effect
enabled         : bool
window          : u32
votes           : u32
threshold       : u32
voting          : u8
state           : u32
earliest_height : u64
credits, top_hash, status, untrusted
```

With `threshold = 0` in the Wownero table, `enabled` is purely height-driven.

### 4.5 `get_fee_estimate`

Request `{grace_blocks}`. Response:

```
fee         : u64          # per-byte
fees        : [u64; 4]     # the 2021 scaling tiers, HF >= 20
quantization_mask : u64    # 1000
status, untrusted, credits, top_hash
```

See [06 §6.4](06-consensus-rules.md) for the four-tier computation.

### 4.6 Block header response

`fill_block_header_response` — the shape shared by all the header endpoints:

```
major_version, minor_version, timestamp, prev_hash, nonce,
vote,                               # <-- Wownero-specific
orphan_status, height, depth, hash,
difficulty(+top64+wide), cumulative_difficulty(+top64+wide),
reward, block_size, block_weight, num_txes,
pow_hash (only if fill_pow_hash and not restricted),
long_term_weight, miner_tx_hash
```

`reward` is `sum(miner_tx.vout[*].amount)`.

A Rust implementation MUST include `vote`; explorers read it for the on-chain
vote tally.

---

## 5. Binary endpoints

Body and response are **epee portable storage** ([04 §2](04-serialization.md)).
These are the wallet sync path and the performance-critical ones.

| Path(s) | Purpose |
|---|---|
| `/get_blocks.bin`, `/getblocks.bin` | the wallet refresh workhorse; §5.1 |
| `/get_blocks_by_height.bin`, `/getblocks_by_height.bin` | blocks at explicit heights |
| `/get_hashes.bin`, `/gethashes.bin` | block hashes from a short history |
| `/get_o_indexes.bin` | global output indices for a tx |
| `/get_outs.bin` | output keys by `(amount, index)` |
| `/get_output_distribution.bin` | output distribution, compressed form |
| `/get_transaction_pool_hashes.bin` | pool hashes |

### 5.1 `get_blocks.bin`

Request:

```
block_ids  : string   # CONTAINER_POD_AS_BLOB, the wallet's short chain history
start_height : u64
prune      : bool
no_miner_tx : bool  OPT default false
pool_info_since : u64 OPT
```

Response:

```
blocks       : array of block_complete_entry
start_height : u64
current_height : u64
output_indices : array of { indices: array of { indices: u64[] } }
daemon_time    : u64
pool_info_extent, added_pool_txs, remaining_added_pool_txids, removed_pool_txids
status, untrusted, credits, top_hash
```

Capped at `COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT (1000)` blocks and
`..._MAX_TX_COUNT (20000)` transactions per call.

`output_indices` gives, per block, per transaction, the list of **global amount
output indices** for that transaction's outputs — this is how a wallet learns
where its outputs sit in the ring-member table without a second round trip. The
order is coinbase first, then transactions in `tx_hashes` order
([10 §5.1](10-storage-lmdb.md)).

### 5.2 `get_o_indexes.bin`

Request `{txid}` → response `{o_indexes: u64[]}`. Same values as one entry of
`output_indices` above.

---

## 6. Error codes

```
-1  WRONG_PARAM            -2  TOO_BIG_HEIGHT        -3  TOO_BIG_RESERVE_SIZE
-4  WRONG_WALLET_ADDRESS   -5  INTERNAL_ERROR        -6  WRONG_BLOCKBLOB
-7  BLOCK_NOT_ACCEPTED     -9  CORE_BUSY            -10 WRONG_BLOCKBLOB_SIZE
-11 UNSUPPORTED_RPC       -12 MINING_TO_SUBADDRESS  -13 REGTEST_REQUIRED
-14 PAYMENT_REQUIRED      -15 INVALID_CLIENT        -16 PAYMENT_TOO_LOW
-17 DUPLICATE_PAYMENT     -18 STALE_PAYMENT         -19 RESTRICTED
-20 UNSUPPORTED_BOOTSTRAP -21 PAYMENTS_NOT_ENABLED
```

Note there is no `-8`.

Status strings: `"OK"`, `"BUSY"`, `"NOT MINING"`, `"PAYMENT REQUIRED"`.

`CORE_BUSY` is returned whenever `check_core_ready()` fails — i.e. the node is
still syncing or the core is not ready. Wallets retry on it, so it MUST be used
rather than a generic internal error.

---

## 7. Implementation priority

For M3 (a node a C++ wallet can sync against), the minimum set is:

```
/get_height  /get_info  /get_blocks.bin  /get_hashes.bin  /get_outs.bin
/get_o_indexes.bin  /get_output_distribution.bin
/send_raw_transaction  /get_transactions  /is_key_image_spent
/get_transaction_pool_hashes.bin
json_rpc: get_info, get_version, hard_fork_info, get_fee_estimate,
          get_block_header_by_height, get_last_block_header,
          get_output_histogram, get_output_distribution
```

Then the mining and administrative endpoints, then the optional RPC-payment set.

---

## 8. Conformance checklist

- [ ] Both the plain-JSON and `.bin` transports are implemented with the exact
      URI names, including the no-underscore aliases (`/getheight`,
      `/getblocks.bin`, …).
- [ ] Every response includes `status` and `untrusted`.
- [ ] Difficulty is always emitted as the three-field triple.
- [ ] `send_raw_transaction` returns all twelve rejection booleans, including
      `tx_extra_too_big` and `nonzero_unlock_time`.
- [ ] Block header responses include `vote`.
- [ ] `get_block_template` returns `reserved_offset`, `seed_hash`,
      `next_seed_hash` and `vote: 0`.
- [ ] `get_blocks.bin` returns `output_indices` in coinbase-first order.
- [ ] Restricted mode removes the **R** endpoints from routing and caps result
      sizes.
- [ ] Error codes match §6 exactly; `CORE_BUSY` is used while syncing.
- [ ] `MAX_RPC_CONTENT_LENGTH` is enforced on requests.
- [ ] Mining to a subaddress returns `-12`.
- [ ] Non-loopback binds require `--confirm-external-bind`.
