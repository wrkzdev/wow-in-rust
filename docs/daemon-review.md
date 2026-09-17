# Daemon review: tracking

The review of `wownerod` started when `--serve` would not start on an empty
data directory. This file tracks what became of each item it raised, in the
review's own order.

Last updated 2026-09-16.

Statuses:

* **Done**: built and covered by tests.
* **Partly**: some of the item is built; the rest is noted.
* **Different**: done another way than the review suggested.
* **Open**: not built. Options for it are refused with a reason, not accepted
  and ignored.

> [!NOTE]
> **Done means built and covered by tests, not proven on mainnet.** Since this
> note was first written the node has run against live C++ peers and held the
> network's tip for over a day with twelve outgoing connections, so the
> outbound half — syncing from several peers, fluffy blocks, the peer store,
> alternative blocks — has now been exercised for real. The rest has not:
> inbound peers, IPv6, Dandelion++ relay, a real reorg, the admin and mining
> RPC, HTTP Digest login, RPC over TLS, the ZMQ RPC and publisher, and the
> miner have all only run between local daemons, mostly on regtest. The README's
> Status table says the same thing and is the one to trust if these two ever
> drift again.

## The failure that started it

| Item | Status | What changed |
|---|---|---|
| `--serve` on an empty `--data-dir` fails with "no database" | Done | `--serve` creates the database when it is not `--db-readonly`, so the two-process workaround is no longer needed ([`main.rs`](../bin/wownerod/src/main.rs)) |

## Bugs in what existed

| # | Item | Status | What changed |
|---|---|---|---|
| 1 | Two commands given: the last one wins silently | Done | A second command is an error (`COMMANDS` in [`cli.rs`](../bin/wownerod/src/cli.rs); tests `two_commands_are_refused` and `two_commands_are_refused_by_the_binary`) |
| 2 | `--serve` opens read-write with no check for another writer | Partly | A read-write open first takes the `wownerod-rs.lock` file lock, and a second Rust writer is refused rather than left waiting ([`inspect.rs`](../bin/wownerod/src/inspect.rs), test `a_second_writer_is_refused`). **Open:** the lock cannot see a C++ `wownerod` using the same directory; keep `--db-readonly` next to one |
| 3 | `send_raw_transaction` says `not_relayed: false` but sends nothing | Done | `not_relayed` is false only when the transaction goes to a connected peer (`Server::relays`) |
| 4 | Every response sends `Access-Control-Allow-Origin: *` | Partly | No CORS header unless `--rpc-access-control-origins` lists the origin, which requires `--rpc-login`. A request with any other `Origin` gets 403. **Open:** the `Host` header is still not checked (the C++ does not check it either) |
| 5 | Binding to IPv6 builds `::1:34568`, which does not parse | Done | The address is bracketed before the port (`bind_address`, test `the_bind_address_brackets_ipv6`). The IPv6 listener options were a separate item, now Done (see B and D) |
| 6 | Reorgs not handled: a node stays stuck behind an orphaned block | Done | Alternative blocks are kept. The node switches to a chain with strictly more cumulative difficulty, and puts the old chain back if the switch fails ([`chain.rs`](../crates/wow-core/src/chain.rs), [`pipeline.rs`](../crates/wow-core/tests/pipeline.rs)). Alternative blocks' transactions are held in memory only, so after a restart a switch to such a chain is refused |
| 7a | The 1000-batch cap of `--sync-from` is hard-coded | Open | Unchanged. `--serve` syncs continuously and has no cap |
| 7b | The Windows default data directory differs from the C++ | Done | `%ProgramData%\wownero`, as the C++ uses |

## A. One long-running process

| Item | Status | Notes |
|---|---|---|
| Sync inside `--serve`, with one writer | Done | The chain sits behind a single lock in `NodeCore`, and locks are always taken chain first, then pool ([`node.rs`](../bin/wownerod/src/node.rs)) |
| Bootstrap from seeds; `--add-peer`, `--seed-node`, `--add-priority-node`, `--add-exclusive-node` | Done | Six mainnet seeds. Testnet and stagenet have none, so they need `--add-peer` |
| Move to another peer on disconnect | Done | |
| Stay connected: timed sync every 60 s, `NEW_BLOCK` and `NEW_FLUFFY_BLOCK` | Done | Timed syncs go out on one clock for all connections, as the C++ sends them from its idle loop |
| Alternative blocks and reorgs | Done | See bug 6 |
| Keep the pool in step with the chain | Done | Mined transactions leave the pool. After a reorg or `pop_blocks`, transactions from the replaced blocks go back in |
| Real `synchronized`, `target_height` and connection counts in `get_info`; `sync_info` | Done | `untrusted` also follows the sync state |
| `--no-sync`, `--offline`, clean Ctrl-C/SIGTERM | Done | Shutdown order: miner, peers, pool saved, database synced last |
| *(found along the way)* proof of work for a sync batch on every core | Done | Before taking the chain lock, `apply_blocks` computes the RandomWOW hash of each block in the batch in parallel; the chain then takes each hash instead of computing it. A hash depends only on its seed and hashing blob, so a stored one is exactly what the chain would compute, and unused ones are dropped after the batch (`ChainPow::prehash` in [`netsync.rs`](../bin/wownerod/src/netsync.rs)) |
| *(found along the way)* a block's transactions verified, not trusted | Done | `check_tx_inputs`' cryptographic half (`specs/06` §5.11, §5.4) ran only for the pool; the block path checked shapes and double spends and took the ring signatures, the range proof and the commitment sum on the sending peer's word. `wow_core::txcheck::TxVerifier` is the seam, `netsync::ChainTxs` the implementation, and the work is the same `mempool::verify` — a transaction in a block and the same transaction in the pool are now judged by one function. A batch is verified on every core before the chain lock is taken, as its proofs of work already were. A shape this node cannot verify is refused **and does not ban the peer**, the distinction `PowError::CryptoNightNotImplemented` already made |
| *(found along the way)* syncing from several peers at once | Done | Spans of block ids are reserved per connection and filled by different peers, as in the C++ `block_queue` ([`queue.rs`](../crates/wow-p2p/src/queue.rs), [`node.rs`](../crates/wow-p2p/src/node.rs)). One `p2p-apply` thread applies filled spans in height order. The C++ thresholds hold: at most 10 filled spans and 100 MB queued, with download forced within 1000 blocks of the tip. A stale next span is re-requested from another peer after 30 s (5 s in standby). A peer that disconnects has its unfilled spans flushed; a peer whose blocks are rejected loses its spans and is banned, or has its connection closed when the rejection does not warrant a ban. `sync_info` now reports `spans` and `overview` ([`tests/node.rs`](../crates/wow-p2p/tests/node.rs)) |

## B. P2P listener

| Item | Status | Notes |
|---|---|---|
| `--p2p-bind-ip`, `--p2p-bind-port`, `--p2p-external-port`, `--hide-my-port`, `--no-igd` | Done | `--igd disabled` is accepted too; any other `--igd` value is refused |
| Answer incoming handshakes with the peer list, real port and support flags | Done | The list is a random pick of the white list with `last_seen` zeroed, and a timed sync gives a peer only addresses it has not had yet, as `get_peerlist_head` and `sent_addresses` do in the C++ |
| Serve `REQUEST_CHAIN` and `REQUEST_GET_OBJECTS` | Done | At most 100 objects per request ([spec-deltas §22](spec-deltas.md)) |
| White, gray and anchor lists; ping back before white-listing; state file | Done | Saved to `p2pstate-rs.bin`, so a C++ node's `p2pstate.bin` is left alone. Outgoing peers are chosen as the C++ chooses them: one port per host, one peer per /24, the white list favouring its most recently seen, and a host that failed skipped for an hour. A peer list's `last_seen` values are zeroed on arrival, and one gray address a minute is handshaken and promoted or dropped |
| `--out-peers`, `--in-peers`, `--max-connections-per-ip`; drop idle connections after 300 s | Done | |
| Bans for bad proof of work and protocol violations; `--ban-list`; `get_bans`, `set_bans` | Done | `banned` added too. Only a failed verification bans a peer; this node's own gaps (such as an unimplemented CryptoNight variant) do not |
| IPv6: `--p2p-use-ipv6`, `--p2p-bind-ipv6-address`, `--p2p-bind-port-ipv6`, `--p2p-ignore-ipv4` | Done | The IPv6 listener sets `IPV6_V6ONLY`, so it and the IPv4 listener can share a port ([`net.rs`](../crates/wow-p2p/src/net.rs)). `--p2p-bind-ipv6-address` defaults to `::`. IPv6 peers are dialled whether or not `--p2p-use-ipv6` is given, as in the C++ ([`tests/ipv6.rs`](../bin/wownerod/tests/ipv6.rs), [`tests/node.rs`](../crates/wow-p2p/tests/node.rs)) |
| `--limit-rate-*`, `--proxy` | Open | Refused |
| Blocking threads rather than an async runtime | Done as suggested | A reader and a writer thread per connection, with a bounded outbox |

## C. Relay and propagation

| Item | Status | Notes |
|---|---|---|
| Relay transactions from `send_raw_transaction` and from peers | Done | Dandelion++ from the start rather than broadcast-first: 2 stems, 20% fluff, 39 s embargo, 10-minute epochs. The pool keeps each transaction's relay method as the C++ does (saved in its `txpool_meta` flags), and only fluffed or mined ones reach the restricted RPC, the ZMQ RPC, a peer's complement request, block templates, miner data and ZMQ `txpool_add` |
| Fluffy block announcements; requests for missing transactions | Done | |
| Keep the pool across restarts | Done | Saved on shutdown and by `save_bc`, loaded at start |

## D. Operator options

| Item | Status | Notes |
|---|---|---|
| `--config-file` and `<data dir>/wownero.conf` | Done | The command line wins, lists included |
| `--log-level` and `--log-file` using `tracing` | Different | Uses a small [`wow-log`](../crates/wow-log) crate instead, with the C++'s `0`–`4` and `category:LEVEL` syntax plus file rotation (`--max-log-file-size`, `--max-log-files`). **Open:** `WOW_P2P_TRACE` remains in the single-peer `--sync-from` code ([`peer.rs`](../crates/wow-p2p/src/peer.rs)) |
| `--rpc-restricted-bind-port`, a second restricted listener | Done | `--rpc-restricted-bind-ip` too, 127.0.0.1 unless given. As in the C++, a restricted listener's `get_info` zeroes the node's own counters and rounds the database size up to 5 GiB, `get_transactions` takes at most 100 hashes, `is_key_image_spent` 5,000 key images, and `get_output_distribution.bin` amount 0 only. A non-loopback `--rpc-bind-ip` or `--rpc-bind-ipv6-address` needs `--confirm-external-bind` even with `--restricted-rpc` or `--rpc-login` |
| IPv6 on the RPC port: `--rpc-use-ipv6`, `--rpc-bind-ipv6-address`, `--rpc-restricted-bind-ipv6-address`, `--rpc-ignore-ipv4` | Done | Both bind addresses default to `::1` ([`tests/ipv6.rs`](../bin/wownerod/tests/ipv6.rs)) |
| TLS on the RPC port | Done | rustls, on a provider of pure-Rust RustCrypto crates ([`tls.rs`](../bin/wownerod/src/rpc/tls.rs), [`provider.rs`](../crates/wow-tls/src/provider.rs)) that replaced ring. It negotiates what the C++ does: TLS 1.3, and TLS 1.2 with ECDHE, ECDSA or RSA certificates, AES-GCM or ChaCha20-Poly1305, and X25519, P-256 or P-384. `--rpc-ssl enabled\|disabled\|autodetect`; the default, autodetect, takes plain and TLS connections on the same port. A self-signed ECDSA P-256 certificate is generated once and kept as `rpc_ssl.crt` and `rpc_ssl.key` in the data directory, unless `--rpc-ssl-certificate` and `--rpc-ssl-private-key` supply one. RSA pairs, which the C++ generates (RSA-4096) and `wownero-gen-ssl-cert` makes, are served as they are, with the same fingerprint. They are signed with `rsa` 0.9, blinded but not constant-time (RUSTSEC-2023-0071), and the node warns at startup when it serves one. Client certificates are checked against `--rpc-ssl-allowed-fingerprints` (SHA-256) or `--rpc-ssl-ca-certificates`, with `--rpc-ssl-allow-chained`; `--rpc-ssl-allow-any-cert` turns the check off ([`tests/tls.rs`](../bin/wownerod/tests/tls.rs)) |
| `--rpc-login` (HTTP Digest) and `--rpc-access-control-origins` | Done | RFC 2617, MD5, `qop=auth`. A password left out is generated and printed. An address is blocked for 24 h after 3 failed logins unless `--disable-rpc-ban`; loopback is exempt |
| Per-IP connection caps: 3 public, 25 private | Done | Plus 100 in total; all three are options |
| `--public-node` | Done | Advertises the restricted port, and is refused without one |
| `--max-txpool-weight` | Done | |
| `--block-sync-size`, `--prep-blocks-threads` | Open | Refused |
| The `:sync\|async:<n>` part of `--db-sync-mode` | Open | Still accepted and ignored; only the mode sets the LMDB flags |
| `--pidfile`, `--non-interactive`, a console that calls the RPC | Done | `help` lists the commands, including the mining ones |
| Admin RPCs: `get_connections`, `get_peer_list`, `stop_daemon`, `pop_blocks`, `flush_txpool`, `get_transaction_pool`, `is_key_image_spent` | Done | Also `sync_info`, `get_bans`, `set_bans`, `banned`, `relay_tx`, `get_public_nodes`, `in_peers`, `out_peers`, `save_bc`, `get_net_stats`, `set_log_level`, `set_log_categories` and the pool hash and stats endpoints. On a restricted listener, the ones marked **R** are not routed |

## E. Mining

| Item | Status | Notes |
|---|---|---|
| `get_block_template`, `submit_block` | Done | Returns `reserved_offset`, the seed hashes and `extra_nonce`, with errors −3, −4, −9 and −12. From HF 18 a warning is logged, because a block built from a template is rejected unless its header is signed with the address's spend key ([`mining.rs`](../bin/wownerod/src/rpc/mining.rs), [`template.rs`](../bin/wownerod/src/template.rs)) |
| `--start-mining`, `--spendkey`, `--vote` | Done | Also `--mining-threads`, `/start_mining`, `/stop_mining`, `/mining_status` and console commands. From HF 18 the miner signs every attempt, refuses to start without `--spendkey`, and refuses a key that is not the address's ([`miner.rs`](../bin/wownerod/src/miner.rs)) |
| *(beyond the review)* `generateblocks` and `--fixed-difficulty`, both regtest only | Done | `generateblocks` signs its blocks when the daemon has the address's `--spendkey`; the C++ leaves them unsigned |
| Background mining (`--bg-mining-*`), `--extra-messages-file` | Open | Refused |
| Tested on | Regtest only | At the CryptoNight v1 heights, between two local daemons ([`tests/mining.rs`](../bin/wownerod/tests/mining.rs)). No RandomWOW block mined here has been checked by a C++ node yet (`specs/15` M5) |

## F. ZMQ

| Item | Status | Notes |
|---|---|---|
| ZMTP without libzmq | Done | A new crate, [`wow-zmq`](../crates/wow-zmq): ZMTP 3.1 with NULL security, in Rust. REP and PUB servers, REQ and SUB clients, a 10 MiB message limit, and subscriptions in both the ZMTP 3.0 and 3.1 forms ([`tests/sockets.rs`](../crates/wow-zmq/tests/sockets.rs)) |
| The ZMQ RPC | Done | [`zmq/`](../bin/wownerod/src/zmq) (`json`, `handler`, `publish`). The JSON-RPC 2.0 envelope has the C++ error forms: `error_str` is `Failed`, `Invalid request type` or `Malformed json`, with the C++ messages. All 27 C++ methods are routed; `get_peer_list` answers "RPC method not yet implemented.", as the C++ does. `--restricted-zmq-rpc` blocks methods by name and applies the C++ restricted limits |
| Publishing with `--zmq-pub tcp://ip:port` (repeatable) | Done | Topics `json-full-chain_main`, `json-minimal-chain_main`, `json-full-miner_data`, `json-full-txpool_add` and `json-minimal-txpool_add`, sent per block in the C++ order: txpool, then miner_data, then chain_main. A reorg announces each replacing block |
| `--zmq-rpc-bind-ip`, `--zmq-rpc-bind-port`, `--confirm-zmq-rpc-external-bind`, `--no-zmq` | Done | Defaults `127.0.0.1` and 34569 (28082 on testnet, 38082 on stagenet). ZMQ is on by default, as in the C++, and a bind to anything but loopback needs `--confirm-zmq-rpc-external-bind` ([`tests/zmq.rs`](../bin/wownerod/tests/zmq.rs)) |
| `ipc://` pub endpoints; CURVE and PLAIN security | Open | Not supported |
| `get_output_distribution` for amounts other than 0 | Open | Only amount 0 (RingCT) is served |

## G. Code that is not Rust

| Item | Status | Notes |
|---|---|---|
| RandomWOW, from the pinned C++ library | Done | Rewritten in Rust ([`wow-randomwow`](../crates/wow-randomwow)). The submodule, `build.rs`, and CMake, Ninja and the C++ runtime are gone from the builds, CI and Docker images. The fork changes `AesGenerator4R`'s keys as well as `configuration.h` ([spec-deltas §25](spec-deltas.md)). Checked against upstream RandomX's published hashes, hashes from the C++ library, and 26 mainnet blocks. SuperscalarHash is compiled to machine code on x86-64; the VM is interpreted. A light-mode hash takes about 75 ms on a 16-thread desktop; the C++ took 19 ms with its JIT and 389 ms without |
| ring, under the RPC TLS | Done | Replaced by the RustCrypto provider (see D). Tested with every suite, group and key type, with record vectors computed by OpenSSL, and against OpenSSL's `s_client` with an RSA-4096 pair laid out as the C++ leaves it. No ring, aws-lc-rs or OpenSSL is in either workspace's dependency graph |
| LMDB | Kept | The one C dependency of the node and the command-line wallets, by design: `data.mdb` must stay byte-compatible with the C++ node |
| Wayland, under the desktop GUI | Kept | Found by [`scripts/check-no-c.sh`](../scripts/check-no-c.sh), which was written to pin the two rows above and immediately turned up a third. `wayland-backend` compiles a small C shim on Linux, reached from eframe's default features through winit and smithay-client-toolkit. Distinct from *linking* libwayland, which still happens at run time through `wayland-sys`, so a Linux build needs no system development packages — but it is C, and "LMDB is the only C" was wrong without this asterisk. Dropping it would mean dropping Wayland support |
| Anything else | Checked | [`scripts/check-no-c.sh`](../scripts/check-no-c.sh) resolves both workspaces for every target that is actually shipped — Linux, Windows, macOS, Android, wasm — and fails on any crate that compiles C and is not on its list. A CI job runs it. Per target rather than `--target all`, which drags in Haiku and Android dependencies for platforms nothing here ships |

## Still open, in one place

**Daemon**

* `--proxy`, `--tx-proxy` and `--anonymous-inbound` (i2p/Tor).
* Rate limits (`--limit-rate*`).
* Pruning, bootstrap daemons, RPC payments.
* Background mining and extra messages in mined blocks.
* ZMQ: no `ipc://` pub endpoints or CURVE/PLAIN security, and
  `get_output_distribution` serves amount 0 (RingCT) only.
* ZMQ `get_blocks_fast` starts at the split block, inclusive, as the C++ does,
  while the HTTP `get_blocks.bin` here starts one past it. That may differ from
  the C++ HTTP endpoint; it is left unchanged until that is checked.
* The HTTP `get_info` still reports `tx_count` 0; the ZMQ `get_info` computes
  it.
* ZMQ `send_raw_tx` reports `relayed` as "handed to the peer-to-peer layer".
* `--block-sync-size`, `--prep-blocks-threads`, and the sync and batch parts of
  `--db-sync-mode`.
* The hard-coded 1000-batch cap and `WOW_P2P_TRACE` in `--sync-from`.
* The RPC does not check the `Host` header.
* The writer lock cannot detect a C++ node using the same data directory.
* A RingCT shape with no verifier here — anything but Bulletproofs+ — is
  refused rather than waved through, so a chain replayed from genesis stops at
  the first pre-HF-18 transaction, as it already does at the first CryptoNight
  v2 block. Mainnet above the last checkpoint is all Bulletproofs+.
* CryptoNight variants 2 and 4 (versions 9–12). A mainnet sync does not need
  them, because checkpoints cover those heights. A chain replayed without
  checkpoints still stops at the version 9 fork, and the miner cannot mine
  those versions.
* RandomWOW's VM is interpreted, and SuperscalarHash is compiled only on
  x86-64. A JIT for the VM, and for aarch64, would bring verification and
  mining closer to the C++ speed. This is the only lever that helps
  verification: the 2 GiB dataset, which is the other way to make a hash
  faster, has to be rebuilt every 2,048 blocks when the seed changes, and at
  one hash per block that costs three to twelve times what light mode does
  — the arithmetic is written out at `ChainPow::pow_hash`. `monerod`
  reaches the same conclusion and builds a dataset only for mining.
* The Docker release builds have not been run since the C++ toolchain was
  removed from their images.
* An RSA key on the RPC TLS port is signed by `rsa` 0.9, which is not
  constant-time (RUSTSEC-2023-0071, no fixed release). Until one exists, an
  ECDSA key avoids it, at the cost of a new fingerprint.

**Wallets**

* The web wallet cannot send daemon login credentials. Requests go through
  the browser's `fetch`, which does not do HTTP Digest, so a node started
  with `--rpc-login` is out of reach from a browser. `wownero-wallet-cli`,
  `wownero-wallet-rpc` and the desktop GUI all can — `--daemon-login
  <user>:<password>`, `set_daemon <address> <user>:<password>`, or Settings,
  Node in the GUI.

**Verification**

* Run `--serve` for a long time against live mainnet peers, covering inbound
  peers, relay and a real reorg.
* Have a C++ node accept a block this miner produced (`specs/15` M5).
