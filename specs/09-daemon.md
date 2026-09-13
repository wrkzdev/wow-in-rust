# 09 — Daemon (`wownerod`)

Source: `src/daemon/*`, `src/cryptonote_core/cryptonote_core.cpp`,
`src/cryptonote_core/tx_pool.cpp`, `src/cryptonote_basic/miner.cpp`,
`src/p2p/net_node.cpp`, `src/rpc/rpc_args.cpp`.

---

## 1. Process structure

```
main()
 ├─ parse CLI + config file (§3)
 ├─ init logging (§8)
 ├─ open blockchain store (LMDB)            -> wow-storage
 ├─ construct core:
 │    Blockchain  (chain state machine)
 │    TxPool      (mempool)
 │    HardFork    (version state)
 │    Checkpoints
 │    Miner       (optional)
 ├─ start P2P server                        -> wow-p2p
 ├─ start RPC server(s) (unrestricted + optional restricted) -> wow-rpc-server
 ├─ start the interactive console (unless --detach)
 └─ run until SIGINT/SIGTERM or `exit`, then: stop RPC, stop P2P, flush DB, close
```

The C++ layers this as `daemonizer -> t_daemon -> t_core / t_p2p / t_rpc`. A Rust
implementation SHOULD instead use one supervisor task with a shutdown
`CancellationToken`, and MUST ensure the store is flushed and closed last.

### 1.1 Startup order requirements

1. The store must be opened and its height known before the P2P server starts
   advertising `CORE_SYNC_DATA`.
2. `HardFork::init` replays `hf_versions` from the store and reconciles it with
   the compiled-in table; a mismatch (e.g. the binary now knows about a new fork
   whose height is already in the chain) triggers a **rescan of the hard-fork
   state** and possibly a chain rollback to the fork height.
3. `update_next_cumulative_weight_limit()` must run before any block is accepted,
   so the weight median and limit are correct.
4. `rx_set_main_seedhash(block_id_at(rx_seedheight(height)))` must be called for
   the loaded tip before hashing anything.
5. Checkpoints and (if enabled) the fast-sync hash table load before sync starts.

---

## 2. The core

### 2.1 `Blockchain`

Owns the canonical chain. Key public operations:

| Operation | Notes |
|---|---|
| `add_new_block(block, &bvc)` | the main entry point; see [06 §2](06-consensus-rules.md) |
| `handle_block_to_main_chain` | extend the tip |
| `handle_alternative_block` | alt chains, [06 §8](06-consensus-rules.md) |
| `switch_to_alternative_blockchain` | reorg, [06 §7](06-consensus-rules.md) |
| `pop_blocks(n)` | used by `pop_blocks` RPC and by reorg |
| `get_difficulty_for_next_block` | [07](07-difficulty.md) |
| `create_block_template` | mining, §6 |
| `get_blocks / get_transactions / get_outs` | RPC service |
| `check_tx_inputs / check_fee` | mempool admission |
| `prune_blockchain / update_pruning` | optional |
| `recalculate_difficulties` | diagnostic, [07 §6](07-difficulty.md) |

`block_verification_context` (`bvc`) flags that MUST be reported back to the P2P
layer so it can decide whether to ban:

```
m_added_to_main_chain, m_verifivation_failed (sic), m_marked_as_orphaned,
m_already_exists, m_partial_block_reward, m_bad_pow
```

Only `m_verifivation_failed` and `m_bad_pow` justify banning.

### 2.2 `TxPool`

In-memory index plus two persisted tables (`txpool_meta`, `txpool_blob`) so the
pool survives a restart.

Per-transaction metadata (`txpool_tx_meta_t`, **192 bytes** — full byte layout and
the relay-method bit encoding in [10 §4.9](10-storage-lmdb.md)):

```
max_used_block_id   : [32]
last_failed_id      : [32]
weight              : u64
fee                 : u64
max_used_block_height : u64
last_failed_height  : u64
receive_time        : u64
last_relayed_time   : u64
kept_by_block       : u8
relayed             : u8
do_not_relay        : u8
bitfield            : double_spend_seen:1, pruned:1, is_local:1,
                      dandelionpp_stem:1, is_forwarding:1, bf_padding:3
padding             : [76]
```

`last_relayed_time` is overloaded: for i2p/tor arrivals it is a randomised
forward time; for Dandelion++ stem transactions it is the randomised embargo
deadline; otherwise it is the actual last relay timestamp.

Admission (`add_tx`) applies, in order:

1. Size: `tx_weight <= CRYPTONOTE_MAX_TX_SIZE (1_000_000)` unless `kept_by_block`.
2. `check_fee` ([06 §6.2](06-consensus-rules.md)) unless `kept_by_block`.
3. `tx.extra.len() <= 1060` unless `kept_by_block`.
4. `tx.unlock_time == 0` unless `kept_by_block`.
5. Key images not already spent on chain, unless `kept_by_block`.
6. Not already in the pool.
7. `check_tx_inputs` — full verification (ring signatures, range proofs).

All the `!kept_by_block` rejections set `no_drop_offense`.

Eviction: when the pool exceeds `--max-txpool-weight` (default
`DEFAULT_TXPOOL_MAX_WEIGHT = 648_000_000`), drop the lowest
`fee / weight` transactions first. Transactions older than
`CRYPTONOTE_MEMPOOL_TX_LIVETIME (3 days)` expire; those that came from a popped
alt block get `CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME (1 week)`.

Ordering for block templates: descending `fee / weight`, then by receive time.

### 2.3 Notifiers

`--block-notify`, `--reorg-notify`, `--block-rate-notify`, `--tx-notify` spawn a
shell command with `%s`-style substitutions. Optional; if implemented, MUST NOT
block the writer task.

---

## 3. Command line and configuration

The config file is `<datadir>/wownero.conf`, INI-style `key=value`, one per line,
with the same names as the long CLI options (no leading `--`). CLI wins over the
file.

### 3.1 Network selection

`--testnet`, `--stagenet`, `--regtest` (`FAKECHAIN`). Mutually exclusive. These
change the data subdirectory, ports, address prefixes, `NETWORK_ID`, genesis and
the hard-fork table.

### 3.2 Options that MUST be supported

Grouped by owner.

**General**

```
--help --version
--data-dir <path>                  default: ~/.wownero (+ /testnet, /stagenet)
--config-file <path>
--log-file <path> --log-level <0-4> --max-log-file-size --max-log-files
--max-concurrency <n>
--detach --pidfile <path>          (non-Windows)
--non-interactive
--offline
--os-version
```

**Blockchain / core**

```
--db-sync-mode <safe|fast|fastest>[:sync|async][:<n>[blocks|bytes]]
                                   default: fast:async:250000000bytes
--db-salvage
--block-sync-size <n>              0 = adaptive (default)
--block-download-max-size <bytes>
--fast-block-sync <0|1>            default 1
--prep-blocks-threads <n>
--show-time-stats <0|1>
--max-txpool-weight <bytes>
--keep-alt-blocks
--enforce-dns-checkpointing
--disable-dns-checkpoints
--check-updates <disabled|notify|download|update>
--fixed-difficulty <n>             regtest only
--keep-fakechain
--sync-pruned-blocks
--prune-blockchain
--no-sync
--test-drop-download --test-drop-download-height   (test only)
```

**P2P**

```
--p2p-bind-ip <ip> --p2p-bind-port <port>
--p2p-bind-ipv6-address --p2p-bind-port-ipv6 --p2p-use-ipv6 --p2p-ignore-ipv4
--p2p-external-port <port>
--add-peer <addr>                  repeatable
--add-priority-node <addr>         repeatable
--add-exclusive-node <addr>        repeatable; disables all other peers
--seed-node <addr>                 repeatable
--ban-list <file>
--enable-dns-blocklist
--hide-my-port
--no-igd / --igd <disabled|enabled|delayed>
--out-peers <n> --in-peers <n>
--max-connections-per-ip <n>
--limit-rate-up <kB/s> --limit-rate-down <kB/s> --limit-rate <kB/s>
--tos-flag <n>
--allow-local-ip
--pad-transactions
--anonymous-inbound <...>          optional (i2p/tor)
--tx-proxy <...>                   optional (i2p/tor)
--proxy <ip:port> --proxy-allow-dns-leaks
```

**RPC**

```
--rpc-bind-ip <ip> --rpc-bind-port <port>
--rpc-bind-ipv6-address --rpc-use-ipv6 --rpc-ignore-ipv4
--rpc-restricted-bind-ip <ip> --rpc-restricted-bind-port <port>
--restricted-rpc
--public-node
--confirm-external-bind
--rpc-login <user[:pass]>
--rpc-access-control-origins <origins>
--disable-rpc-ban
--rpc-ssl <enabled|disabled|autodetect> --rpc-ssl-private-key --rpc-ssl-certificate
--rpc-ssl-ca-certificates --rpc-ssl-allowed-fingerprints
--rpc-ssl-allow-chained --rpc-ssl-allow-any-cert
--bootstrap-daemon-address <...> --bootstrap-daemon-login <...>
--bootstrap-daemon-proxy <...>
--rpc-payment-address --rpc-payment-difficulty --rpc-payment-credits  (optional)
```

**Mining** (Wownero-specific pair in bold)

```
--start-mining <address>
--mining-threads <n>
--extra-messages-file <path>
--bg-mining-enable --bg-mining-ignore-battery
--bg-mining-min-idle-interval --bg-mining-idle-threshold --bg-mining-miner-target
--spendkey <hex>                   ** REQUIRED to mine at HF >= 18 **
--vote <yes|no>                    ** Wownero-specific; anything else is an error **
```

**ZMQ** (optional, out of scope for the first release)

```
--zmq-rpc-bind-ip --zmq-rpc-bind-port --zmq-pub --no-zmq
--restricted-zmq-rpc --confirm-zmq-rpc-external-bind
```

### 3.3 `--db-sync-mode`

Parsed as up to three colon-separated components in any order:

- `safe` — synchronous, fully durable writes, no batching.
- `fast` (default) — batched writes, `sync` only at batch boundaries.
- `fastest` — no explicit sync; a crash can lose recent blocks.
- `sync` / `async` — whether the sync itself is on the write path.
- `<n>blocks` or `<n>bytes` — batch size; default `250000000bytes`.

LMDB environment-flag mapping in [10 §2.1](10-storage-lmdb.md).

### 3.4 Regtest

`--regtest` selects `FAKECHAIN`, which uses the mainnet config values but
disables checkpoints and allows `--fixed-difficulty` and the `generateblocks`
RPC. `--keep-fakechain` preserves the fake chain across restarts (otherwise the
data is wiped on startup). MUST be impossible to enable on mainnet.

---

## 4. Interactive console

The C++ daemon runs a readline-style console when not detached. Commands
(`src/daemon/command_parser_executor.cpp`):

```
help  version  status  print_height  print_pl  print_pl_stats  print_cn
print_bc <start> [end]  print_block <hash|height>  print_tx <hash> [+hex|+json]
is_key_image_spent <ki>  print_pool  print_pool_sh  print_pool_stats
start_mining <addr> [<threads>] [do_background_mining] [ignore_battery]
stop_mining  mining_status
save  save_bc  set_log <level|categories>  diff
out_peers <n>  in_peers <n>  limit <n>  limit_up <n>  limit_down <n>
hard_fork_info  bans  ban <ip> [seconds]  unban <ip>  banned <ip>
flush_txpool [txid]  output_histogram [amount ...]
print_coinbase_tx_sum <height> <count>  alt_chain_info  bc_dyn_stats <n>
update <check|download>  relay_tx <txid>  sync_info  pop_blocks <n>
prune_blockchain  check_blockchain_pruning  set_bootstrap_daemon <...>
rpc_payments  flush_cache <bad-txs|bad-blocks>  print_net_stats
start_save_graph  stop_save_graph  set_log_level  exit
```

Every one of these maps 1:1 onto an RPC call ([11](11-daemon-rpc.md)). Implement
the console as a thin client over the node's own RPC surface, so there is exactly
one implementation of each operation.

The console is a convenience, not a compatibility surface; a Rust daemon MAY
offer a reduced set, but SHOULD keep `status`, `print_height`, `sync_info`,
`print_pl`, `diff`, `hard_fork_info`, `start_mining`, `stop_mining` and `exit`.

---

## 5. Sync driver

State machine per connection (`cryptonote_protocol_handler`):

```
before_handshake -> synchronizing -> standby -> normal
```

Driver loop:

1. On learning a peer is ahead, send `NOTIFY_REQUEST_CHAIN` with the sparse
   history ([08 §5.2](08-p2p.md)).
2. On `NOTIFY_RESPONSE_CHAIN_ENTRY`, verify the split point, then queue spans of
   block hashes.
3. Request spans with `NOTIFY_REQUEST_GET_OBJECTS`, at most 2048 blocks, aligned
   to 2048-block boundaries.
4. On `NOTIFY_RESPONSE_GET_OBJECTS`, verify the response matches the request,
   then hand the batch to the writer task.
5. The writer verifies and applies blocks strictly in height order.
6. When no peer is ahead, transition to `normal` and rely on
   `NOTIFY_NEW_FLUFFY_BLOCK` / timed sync.

### 5.1 Batch verification

Before applying a batch, precompute in parallel (this is what
`--prep-blocks-threads` controls):

- block hashes,
- PoW hashes (one RandomWOW VM per thread, all sharing the batch's dataset),
- transaction hashes and signature/range-proof verification.

Then apply sequentially. **The parallel phase MUST NOT make consensus decisions
that depend on chain state** (difficulty, medians, unlock times) — those are only
correct in the sequential phase.

### 5.2 Stalls and drops

- A peer that does not answer within `P2P_DEFAULT_INVOKE_TIMEOUT` is dropped and
  its span reassigned.
- `--block-download-max-size` bounds the in-flight queue.
- If a span fails verification the peer is banned and the span reassigned.

---

## 6. Built-in miner

`src/cryptonote_basic/miner.cpp`.

### 6.1 Block template

`Blockchain::create_block_template(b, miner_address, diffic, height,
expected_reward, extra_nonce)`:

1. For a tip-extending template:
   `b.major_version = get_current_version()` (the tip's applied version),
   `b.minor_version = get_ideal_version()` (the highest known version — this is
   the legacy fork vote), `b.prev_id = tip`,
   `median_weight = m_current_block_cumul_weight_limit / 2`,
   `diffic = get_difficulty_for_next_block()`,
   `already_generated_coins = get_block_already_generated_coins(height - 1)`.
   For a template on top of a specified `prev_block` (the `prev_block` parameter
   of `get_block_template`), `major_version = get_ideal_version(height)` and the
   medians come from the alt chain.
2. `b.timestamp = time(NULL)`; then run `check_block_timestamp(b, &median_ts)` and
   if it fails, set `b.timestamp = median_ts`.
3. Fill transactions from the pool by descending `fee/weight` while
   `cumulative_weight <= median_weight * 2`
   (`tx_pool::fill_block_template`).
4. Build the coinbase twice: once to estimate its weight, then up to **10** more
   times in a loop, because the coinbase weight depends on the reward, which
   depends on the block weight, which includes the coinbase. The loop grows or
   pads `extra` until the weight is stable.
   `max_outs = if hf_version >= 4 { 1 } else { 11 }` — on Wownero this is
   **always 1**, since the chain starts at HF 7.
   `CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE = 600` bytes are reserved for the
   caller's extra nonce.
5. Return `reserved_offset` — the byte offset inside the template blob where a
   pool would write its extra nonce.

### 6.2 `construct_miner_tx`

```rust
tx.vin  = [ txin_gen { height } ]
tx.extra = [ TX_EXTRA_TAG_PUBKEY(txkey.pub) ] (+ extra_nonce) then sort_tx_extra
reward = get_block_reward(median_weight, current_block_weight,
                          already_generated_coins, hf)? + fee

if hf in 2..4     { reward -= reward % BASE_REWARD_CLAMP_THRESHOLD }   // dead on Wownero
out_amounts = decompose_amount_into_digits(reward,
                  dust_threshold = if hf >= 2 { 0 } else { DEFAULT_DUST_THRESHOLD })
if height == 0 || hf >= 4 {
    // fold the smallest amounts together until out_amounts.len() <= max_outs
    while max_outs < out_amounts.len() {
        out_amounts[1] += out_amounts[0];
        out_amounts.rotate_left(1);      // shift everything down one slot
        out_amounts.pop();
    }
}
for (i, amount) in out_amounts.iter().enumerate() {
    D = generate_key_derivation(miner_address.view_public_key, txkey.sec)
    P = derive_public_key(D, i, miner_address.spend_public_key)
    target = if hf >= HF_VERSION_VIEW_TAGS { txout_to_tagged_key(P, derive_view_tag(D,i)) }
             else                          { txout_to_key(P) }
    tx.vout.push(tx_out { amount, target })
}
assert!(sum(out_amounts) == reward)
tx.version = if hf >= 4 { 2 } else { 1 }
tx.unlock_time = per [06 §5.1.1]
```

`max_outs` is 1 for every hard fork Wownero has ever had, so the fold loop always
collapses the decomposition into a **single output** whose amount is the entire
reward. From HF 18 this is also a consensus requirement
(`prevalidate_miner_transaction` demands `vout.len() == 1`).

### 6.3 Mining loop

Per [06 §4.2](06-consensus-rules.md) and [03 §6](03-pow.md):

```
loop {
    if template changed { refresh b, diff, height }
    b.nonce = nonce;
    if b.major_version >= 18 {
        b.signature = sign(get_sig_data(&b), P, eph_secret_key);
        b.vote = configured_vote;
    }
    let h = pow_hash(&b, height, b.major_version, &seed_hash);
    if check_hash(h, diff) { submit(b); }
    nonce += n_threads;
}
```

`eph_secret_key` is derived once per template:

```
D = generate_key_derivation(get_tx_pub_key_from_extra(b.miner_tx), view_secret_key)
x = derive_secret_key(D, 0, spend_secret_key)
P = output_public_key(b.miner_tx.vout[0])
```

Without `--spendkey`, `spend_secret_key` is zero and every signature is invalid,
so the daemon will mine blocks that the network rejects. **A Rust daemon SHOULD
refuse to start mining at HF ≥ 18 without `--spendkey`**, which the C++ does not
do — this is an allowed improvement because it changes no consensus behaviour.

### 6.4 Background mining

`--bg-mining-enable` throttles mining based on system idleness
(`--bg-mining-min-idle-interval`, `--bg-mining-idle-threshold`) and a target CPU
share (`--bg-mining-miner-target`), pausing on battery unless
`--bg-mining-ignore-battery`. Optional.

---

## 7. Bootstrap daemon (optional)

`--bootstrap-daemon-address` makes the node proxy RPC calls it cannot answer yet
(because it is still syncing) to a remote daemon. If implemented, it MUST:

- only proxy while `!is_synchronized()`,
- never proxy `submit_block` or the mining endpoints,
- report `untrusted: true` in responses that came from the bootstrap daemon.

---

## 8. Logging

Categories with per-category levels, e.g.
`net:INFO,blockchain:DEBUG,*:WARNING`. Levels 0–4 map to preset category strings.
`--log-level` and the `set_log` console command / `set_log_level` and
`set_log_categories` RPCs change it at runtime.

A Rust node SHOULD use `tracing` with an `EnvFilter`, and MUST accept the C++
level syntax (`0`–`4` and `category:LEVEL` lists) for operator familiarity.

Log rotation: `--max-log-file-size` (default 104,850,000 bytes) and
`--max-log-files` (default 50).

---

## 9. Shutdown

On `SIGINT` / `SIGTERM` / console `exit`:

1. Stop accepting new P2P connections and RPC requests.
2. Stop the miner.
3. Signal the writer task to finish the current block and stop.
4. Flush and commit the store (including the txpool tables).
5. Save `p2pstate.bin`.
6. Close the store.

A crash between 3 and 6 with `--db-sync-mode fast` can lose recent blocks; the
node must detect a torn write on the next start and roll back to the last
consistent height ([10 §6](10-storage-lmdb.md)).

---

## 10. Conformance checklist

- [ ] Hard-fork state is replayed from the store on startup and reconciled with
      the compiled table.
- [ ] `update_next_cumulative_weight_limit` runs before the first block is
      accepted.
- [ ] The RandomWOW main seed is set for the loaded tip before any hashing.
- [ ] Mempool admission applies the `!kept_by_block` rules in the order of §2.2
      and sets `no_drop_offense`.
- [ ] Mempool is persisted across restarts.
- [ ] Blocks are verified in parallel but applied sequentially in height order;
      no chain-state-dependent rule is evaluated in the parallel phase.
- [ ] `create_block_template` stabilises the coinbase weight and reports
      `reserved_offset`.
- [ ] The coinbase has exactly one output at HF ≥ 18.
- [ ] The miner re-signs per nonce and derives the ephemeral key from the
      coinbase tx public key.
- [ ] `--vote` accepts only `yes` / `no` and errors otherwise.
- [ ] `--regtest` / `--fixed-difficulty` cannot be enabled on mainnet.
- [ ] Shutdown flushes the store last.
