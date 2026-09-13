# 01 — Constants & Network Parameters

Source of truth: `src/cryptonote_config.h`, `src/hardforks/hardforks.cpp`,
`src/checkpoints/checkpoints.cpp`, `src/p2p/net_node.inl`, `src/crypto/hash-ops.h`.

Every value in this document is consensus- or wire-critical unless marked
*(policy)* or *(local)*. Implement them as `const` in `wow-consensus`; do not
re-derive them.

## 1. Identity

| Constant | Value |
|---|---|
| `CRYPTONOTE_NAME` | `"wownero"` |
| Display decimal point | `11` |
| `COIN` (atomic units per WOW) | `100_000_000_000` (10^11) |
| Version | `0.11.4.0`, release name `Kunty Karen` |
| `CORE_RPC_VERSION` | major `3`, minor `15` → `(3 << 16) | 15` = `196_623` |
| `WALLET_RPC_VERSION` | major `1`, minor `30` → `65_566` |
| Payment URI scheme | `wownero:` |
| Message-signing domain | `"WowneroMessageSignature"` |
| Default data dir (Unix) | `$HOME/.wownero` |
| Default data dir (Windows) | `%ALLUSERSPROFILE%\wownero` (`CSIDL_COMMON_APPDATA`) |
| Testnet / stagenet subdir | `<datadir>/testnet`, `<datadir>/stagenet` |
| Config file | `<datadir>/wownero.conf` *(local)* |
| Log file | `<datadir>/wownero.log` *(local)* |
| P2P state file | `p2pstate.bin` *(local)* |

## 2. Per-network parameters

```rust
pub enum Network { Mainnet, Testnet, Stagenet, Fakechain }
```

`Fakechain` uses the **mainnet** config block (`get_config` maps
`FAKECHAIN => mainnet`) but bypasses difficulty and checkpoints.

| Parameter | Mainnet | Testnet | Stagenet |
|---|---|---|---|
| Address prefix | `4146` | `53` | `24` |
| Integrated address prefix | `6810` | `54` | `25` |
| Subaddress prefix | `12208` | `63` | `36` |
| P2P port | `34567` | `28080` | `38080` |
| RPC port | `34568` | `28081` | `38081` |
| ZMQ RPC port | `34569` | `28082` | `38082` |
| Genesis nonce | `70` | `10001` | `10002` |

### 2.1 NETWORK_ID

A 16-byte value sent verbatim in the Levin handshake `network_id` field. A peer
with a different value MUST be dropped.

```
mainnet:  11 33 FF 77 61 04 41 61 17 31 00 82 16 A1 A1 10
testnet:  12 30 F1 71 61 04 41 61 17 31 00 82 16 A1 A1 11
stagenet: 12 30 F1 71 61 04 41 61 17 31 00 82 16 A1 A1 12
```

### 2.2 Genesis

Genesis is not stored as a block blob; it is *constructed*:

1. Parse `GENESIS_TX` (hex) as a transaction — this is the genesis coinbase.
2. `major_version = 7`, `minor_version = 7` (`CURRENT_BLOCK_MAJOR_VERSION` /
   `CURRENT_BLOCK_MINOR_VERSION`).
3. `timestamp = 0`, `prev_id = 0`, `nonce = GENESIS_NONCE`, `tx_hashes = []`.
4. `signature` and `vote` are **absent** from the serialization because
   `major_version (7) < HF_VERSION_BLOCK_HEADER_MINER_SIG (18)`.

The C++ code then calls `find_nonce_for_given_block(..., difficulty = 1, ...)`,
which at difficulty 1 always succeeds on the first try, so the nonce stays at
`GENESIS_NONCE`. A Rust implementation MAY skip that step entirely.

Mainnet `GENESIS_TX`:

```
013c01ff0001ffffffffff1f029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121012a1a936be5d91c01ee876e38c13fab0ee11cbe86011a2bf7740fb5ebd39d267d
```

Testnet:

```
013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a28e9d0bc890d1
```

Stagenet:

```
013c01ff0001ffffffffffff0302df5d56da0c7d643ddd1ce61901c7bdc5fb1738bfe39fbe69c28a3a7032729c0f2101168d0c4ca86fb55a4cf6a36d31431be1c53a3bd7411bb24e8832410289fa6f3b
```

Genesis PoW: `get_block_longhash` is called with `pbc == NULL`, so the RandomWOW
seed hash is all-zero. Since `major_version = 7 < RX_BLOCK_VERSION (13)`, the
genesis PoW is in fact CryptoNight variant 1 — but nothing validates genesis PoW,
so this only matters if you reproduce `generate_genesis_block` literally.

## 3. Hard forks

`(version, height)` pairs. The C++ `hardfork_t` also carries `threshold` (always
0 here → height-based activation, no voting threshold) and an advisory `time`.

### 3.1 Mainnet — `src/hardforks/hardforks.cpp`

| Version | Height | Release name | Introduced |
|---|---|---|---|
| 7 | 1 | Awesome Akita | CryptoNight v1, ring ≥ 8, sorted inputs |
| 8 | 6,969 | Busty Brazzers | Bulletproofs, LWMA, ring ≥ 10, unlock 4 |
| 9 | 53,666 | Cool Cage | CryptoNight v2, LWMA v2, ring = 22 |
| 10 | 63,469 | Dank Doge | LWMA v4 |
| 11 | 81,769 | Erotic EggplantEmoji | CryptoNight/wow (variant 4), LWMA-1 N=144, BP v2, per-byte fee |
| 12 | 82,069 | " | per-byte fee gate (`HF_VERSION_PER_BYTE_FEE`) |
| 13 | 114,969 | F For Fappening | **RandomWOW**, new block weight algorithm, smaller BP |
| 14 | 115,257 | " | (`HF_VERSION_SMALLER_BP + 1` gate) |
| 15 | 160,777 | Gaping Goatse | ≥ 2 outputs, same ring size, no sigs in coinbase, min age, effective short-term median |
| 16 | 253,999 | Illiterate Illuminati | CLSAG, dynamic coinbase unlock, deterministic unlock time, exact coinbase |
| 17 | 254,287 | " | (`HF_VERSION_CLSAG + 1` gate) |
| 18 | 331,170 | Junkie Jeff | **Bulletproofs+**, **block-header miner signing**, **vote field**, fixed 288-block unlock, difficulty reset |
| 19 | 331,458 | " | (`HF_VERSION_BULLETPROOF_PLUS + 1` gate) |
| 20 | 514,000 | Kunty Karen | **View tags**, 2021 fee/weight scaling, 144-block difficulty window, tx_extra limit |

**Note the gap:** there is no mainnet hard fork above 20. The current tip runs
version 20.

### 3.2 Testnet

Versions 7..21 at heights 1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70.
Version **21** (height 70) exists only on testnet and only enables
`RCTTypeBulletproofPlus_FullCommit` (see [06 §5.6](06-consensus-rules.md)).

### 3.3 Stagenet

Versions 7..20 at heights 1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65.

### 3.4 Feature gates

These map a feature to the **minimum hard-fork version** at which it applies.
Implement them as named constants; the validation code in
[06-consensus-rules.md](06-consensus-rules.md) refers to them by name.

| Constant | Value |
|---|---|
| `HF_VERSION_DYNAMIC_FEE` | 4 |
| `HF_VERSION_ENFORCE_RCT` | 6 |
| `HF_VERSION_MIN_MIXIN_7` | 7 |
| `HF_VERSION_MIN_MIXIN_21` | 9 |
| `HF_VERSION_PER_BYTE_FEE` | 12 |
| `HF_VERSION_SMALLER_BP` | 13 |
| `HF_VERSION_LONG_TERM_BLOCK_WEIGHT` | 13 |
| `RX_BLOCK_VERSION` (RandomWOW) | 13 |
| `HF_VERSION_MIN_2_OUTPUTS` | 15 |
| `HF_VERSION_MIN_V2_COINBASE_TX` | 15 |
| `HF_VERSION_SAME_MIXIN` | 15 |
| `HF_VERSION_REJECT_SIGS_IN_COINBASE` | 15 |
| `HF_VERSION_ENFORCE_MIN_AGE` | 15 |
| `HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY` | 15 |
| `HF_VERSION_EXACT_COINBASE` | 16 |
| `HF_VERSION_CLSAG` | 16 |
| `HF_VERSION_DETERMINISTIC_UNLOCK_TIME` | 16 |
| `HF_VERSION_DYNAMIC_UNLOCK` | 16 |
| `HF_VERSION_FIXED_UNLOCK` | 18 |
| `HF_VERSION_BULLETPROOF_PLUS` | 18 |
| `HF_VERSION_BLOCK_HEADER_MINER_SIG` | 18 |
| `HF_VERSION_VIEW_TAGS` | 20 |
| `HF_VERSION_2021_SCALING` | 20 |
| `HF_VERSION_BP_PLUS_FULL_COMMIT` | 21 |

## 4. Block & chain constants

| Constant | Value | Notes |
|---|---|---|
| `DIFFICULTY_TARGET_V1` | 300 s | Wownero has always targeted 5 minutes |
| `DIFFICULTY_TARGET_V2` | 300 s | |
| `CURRENT_BLOCK_MAJOR_VERSION` | 7 | genesis only |
| `CURRENT_BLOCK_MINOR_VERSION` | 7 | genesis only |
| `CURRENT_TRANSACTION_VERSION` | 2 | max parseable tx version |
| `CRYPTONOTE_MAX_BLOCK_NUMBER` | 500,000,000 | unlock_time height/time discriminator |
| `CRYPTONOTE_MAX_TX_SIZE` | 1,000,000 | |
| `CRYPTONOTE_MAX_TX_PER_BLOCK` | `0x10000000` | |
| `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT` | 7200 s | version < 8 |
| `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2` | 600 s | version ≥ 8 |
| `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` | 60 | version < 10 |
| `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2` | 11 | version ≥ 10 |
| `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` | 4 | min output age from HF 15 |
| `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` | 60 | coinbase lock before HF 16 |
| `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_V2` | 288 | coinbase lock from HF 18 (~1 day) |
| `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS` | 1 | |
| `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2` | 300 | `= TARGET_V2 * 1` |
| `ORPHANED_BLOCKS_MAX_COUNT` | 100 | *(policy)* |

## 5. Emission

| Constant | Value |
|---|---|
| `MONEY_SUPPLY` | `u64::MAX` = `18_446_744_073_709_551_615` |
| `EMISSION_SPEED_FACTOR_PER_MINUTE` | 24 |
| `FINAL_SUBSIDY_PER_MINUTE` | **0** — no tail emission |
| `CRYPTONOTE_REWARD_BLOCKS_WINDOW` | 100 |
| `config::BASE_REWARD_CLAMP_THRESHOLD` | `100_000_000` (10^8) |
| `config::DEFAULT_DUST_THRESHOLD` | `2_000_000_000` |

Effective emission-speed factor: `24 - (300/60 - 1)` = **20**, so
`base_reward = (MONEY_SUPPLY - already_generated_coins) >> 20`.
Total supply = `u64::MAX` atomic units = **184,467,440.73709551615 WOW**.
See [06 §3](06-consensus-rules.md).

## 6. Block weight

| Constant | Value |
|---|---|
| `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1` | 20,000 (version < 2) |
| `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2` | 60,000 (2 ≤ version < 5) |
| `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5` | **300,000** (version ≥ 5 — i.e. always, on Wownero) |
| `CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE` | 100,000 |
| `CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR` | 50 |
| `CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE` | 600 |

Because Wownero's first hard fork is version 7, `get_min_block_weight()` always
returns **300,000** on all live networks. The V1/V2 branches are dead code but
are specified for completeness.

## 7. Fees

| Constant | Value |
|---|---|
| `FEE_PER_KB_OLD` | `10_000_000_000` |
| `FEE_PER_KB` | `2_000_000_000` |
| `FEE_PER_BYTE` | `300_000` |
| `DYNAMIC_FEE_PER_KB_BASE_FEE` | `2_000_000_000` |
| `DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD` | `10_000_000_000_000` |
| `DYNAMIC_FEE_PER_KB_BASE_FEE_V5` | `2_000_000_000 * 60_000 / 300_000` = `400_000_000` |
| `DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT` | 3,000 |
| `PER_KB_FEE_QUANTIZATION_DECIMALS` | 8 |
| `CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES` | 2 |
| `config::DEFAULT_FEE_ATOMIC_XMR_PER_KB` | 500 *(placeholder, unused)* |
| `config::FEE_CALCULATION_MAX_RETRIES` | 10 *(wallet)* |

Fee quantization mask = `10^(11 - 8)` = **1000**
(`get_fee_quantization_mask()` = `10^(CRYPTONOTE_DISPLAY_DECIMAL_POINT - PER_KB_FEE_QUANTIZATION_DECIMALS)`).

## 8. Difficulty windows

| Constant | Value |
|---|---|
| `DIFFICULTY_WINDOW` | 720 |
| `DIFFICULTY_WINDOW_V2` | 60 |
| `DIFFICULTY_WINDOW_V3` | 144 |
| `DIFFICULTY_LAG` | 15 |
| `DIFFICULTY_LAG_V2` | 3 |
| `DIFFICULTY_CUT` | 60 |
| `DIFFICULTY_CUT_V2` | 12 |
| `DIFFICULTY_BLOCKS_COUNT` | `720 + 15` = 735 |
| `DIFFICULTY_BLOCKS_COUNT_V2` | `60 + 1` = 61 |
| `DIFFICULTY_BLOCKS_COUNT_V3` | `144 + 1` = 145 |
| `DIFFICULTY_BLOCKS_COUNT_V4` | `144 + 3` = 147 |

Selection logic and the hard-coded per-height overrides are in
[07-difficulty.md](07-difficulty.md).

## 9. Ring signatures & proofs

| Constant | Value |
|---|---|
| Minimum ring size, HF 7–8 | 8 (`min_mixin = 7`) |
| Minimum ring size, HF ≥ 9 | **22** (`min_mixin = 21`) |
| `BULLETPROOF_MAX_OUTPUTS` | 16 |
| `BULLETPROOF_PLUS_MAX_OUTPUTS` | 16 |
| `config::MULTISIG_MAX_SIGNERS` | 16 |
| `MAX_TX_EXTRA_SIZE` | 1,060 *(relay policy, not consensus)* |
| `TX_EXTRA_PADDING_MAX_COUNT` | 255 |
| `TX_EXTRA_NONCE_MAX_COUNT` | 255 |

## 10. Hash domain separators

Byte-exact strings from `src/cryptonote_config.h`. Where the C++ passes
`sizeof(literal)` the **trailing NUL is included**; this is called out per entry.

| Name | Value | NUL included |
|---|---|---|
| `HASH_KEY_BULLETPROOF_EXPONENT` | `"bulletproof"` | no (uses `strlen`) |
| `HASH_KEY_BULLETPROOF_PLUS_EXPONENT` | `"bulletproof_plus"` | no |
| `HASH_KEY_BULLETPROOF_PLUS_TRANSCRIPT` | `"bulletproof_plus_transcript"` | no |
| `HASH_KEY_RINGDB` | `"ringdsb"` (sic) | wallet-local |
| `HASH_KEY_SUBADDRESS` | `"SubAddr"` | **yes** — 8 bytes incl. NUL |
| `HASH_KEY_ENCRYPTED_PAYMENT_ID` | `0x8d` | n/a |
| `HASH_KEY_WALLET` | `0x8c` | n/a |
| `HASH_KEY_WALLET_CACHE` | `0x8d` | n/a |
| `HASH_KEY_BACKGROUND_CACHE` | `0x8e` | n/a |
| `HASH_KEY_BACKGROUND_KEYS_FILE` | `0x8f` | n/a |
| `HASH_KEY_RPC_PAYMENT_NONCE` | `0x58` | n/a |
| `HASH_KEY_MEMORY` | `'k'` | n/a |
| `HASH_KEY_MULTISIG` | `"Multisig"` + 24 zero bytes (32 total) | n/a |
| `HASH_KEY_MULTISIG_KEY_AGGREGATION` | `"Multisig_key_agg"` | no |
| `HASH_KEY_CLSAG_ROUND_MULTISIG` | `"CLSAG_round_ms_merge_factor"` | no |
| `HASH_KEY_TXPROOF_V2` | `"TXPROOF_V2"` | no |
| `HASH_KEY_CLSAG_ROUND` | `"CLSAG_round"` | no |
| `HASH_KEY_CLSAG_AGG_0` | `"CLSAG_agg_0"` | no |
| `HASH_KEY_CLSAG_AGG_1` | `"CLSAG_agg_1"` | no |
| `HASH_KEY_MESSAGE_SIGNING` | `"WowneroMessageSignature"` | **Wownero-specific** |
| `HASH_KEY_MM_SLOT` | `'m'` | n/a |
| `HASH_KEY_MULTISIG_TX_PRIVKEYS_SEED` | `"multisig_tx_privkeys_seed"` | no |
| `HASH_KEY_MULTISIG_TX_PRIVKEYS` | `"multisig_tx_privkeys"` | no |
| `HASH_KEY_TXHASH_AND_MIXRING` | `"txhash_and_mixring"` | no |
| View tag salt | `"view_tag"` (8 bytes, no NUL) | no |

Exact usage per separator is in [02-crypto.md](02-crypto.md).

## 11. Mempool & relay *(policy)*

| Constant | Value |
|---|---|
| `CRYPTONOTE_MEMPOOL_TX_LIVETIME` | 259,200 s (3 days) |
| `CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME` | 604,800 s (1 week) |
| `DEFAULT_TXPOOL_MAX_WEIGHT` | `648_000_000` bytes |
| `CRYPTONOTE_DANDELIONPP_STEMS` | 2 |
| `CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY` | 20 (percent) |
| `CRYPTONOTE_DANDELIONPP_MIN_EPOCH` | 10 min |
| `CRYPTONOTE_DANDELIONPP_EPOCH_RANGE` | 30 s |
| `CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE` | 5 s (Poisson) |
| `CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE` | 39 s |
| `CRYPTONOTE_NOISE_MIN_EPOCH` | 5 min |
| `CRYPTONOTE_NOISE_EPOCH_RANGE` | 30 s |
| `CRYPTONOTE_NOISE_MIN_DELAY` | 10 s |
| `CRYPTONOTE_NOISE_DELAY_RANGE` | 5 s |
| `CRYPTONOTE_NOISE_BYTES` | 3,072 |
| `CRYPTONOTE_NOISE_CHANNELS` | 2 |
| `CRYPTONOTE_MAX_FRAGMENTS` | 20 |
| `CRYPTONOTE_FORWARD_DELAY_BASE` | 15 s |
| `CRYPTONOTE_FORWARD_DELAY_AVERAGE` | 22 s |

## 12. P2P *(policy / local)*

| Constant | Value |
|---|---|
| `P2P_LOCAL_WHITE_PEERLIST_LIMIT` | 1,000 |
| `P2P_LOCAL_GRAY_PEERLIST_LIMIT` | 5,000 |
| `P2P_DEFAULT_CONNECTIONS_COUNT` | 12 |
| `P2P_DEFAULT_HANDSHAKE_INTERVAL` | 60 s |
| `P2P_DEFAULT_PACKET_MAX_SIZE` | 50,000,000 |
| `P2P_DEFAULT_PEERS_IN_HANDSHAKE` / `P2P_MAX_PEERS_IN_HANDSHAKE` | 250 |
| `P2P_DEFAULT_CONNECTION_TIMEOUT` | 5,000 ms |
| `P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT` | 45 s |
| `P2P_DEFAULT_PING_CONNECTION_TIMEOUT` | 2,000 ms |
| `P2P_DEFAULT_INVOKE_TIMEOUT` | 120,000 ms |
| `P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT` | 5,000 ms |
| `P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT` | 70 |
| `P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT` | 2 |
| `P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT` | 2 |
| `P2P_DEFAULT_LIMIT_RATE_UP` | 8,192 kB/s |
| `P2P_DEFAULT_LIMIT_RATE_DOWN` | 32,768 kB/s |
| `P2P_FAILED_ADDR_FORGET_SECONDS` | 3,600 |
| `P2P_IP_BLOCKTIME` | 86,400 |
| `P2P_IP_FAILS_BEFORE_BLOCK` | 10 |
| `P2P_IDLE_CONNECTION_KILL_INTERVAL` | 300 s |
| `P2P_SUPPORT_FLAG_FLUFFY_BLOCKS` | `0x01` |
| `P2P_SUPPORT_FLAGS` | `0x01` |
| `RPC_IP_FAILS_BEFORE_BLOCK` | 3 |
| `DNS_BLOCKLIST_LIFETIME` | 691,200 s (8 days) |

### 12.1 Sync sizing

| Constant | Value |
|---|---|
| `BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT` | 10,000 |
| `BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT` | 25,000 |
| `BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4` | 100 |
| `BLOCKS_SYNCHRONIZING_DEFAULT_COUNT` | 20 |
| `BLOCKS_SYNCHRONIZING_MAX_COUNT` | **2,048** — must equal `SEEDHASH_EPOCH_BLOCKS` |

### 12.2 Seed nodes (mainnet)

Hard-coded IPs; **Wownero has no DNS seeds** (`m_seed_nodes_list` is empty, and
`load_checkpoints_from_dns` has empty URL lists). Testnet/stagenet fall back to
the mainnet list — which means they effectively have no working seeds.

```
192.99.8.110:34567      # node.monerodevs.org
37.187.74.171:34567     # node2.monerodevs.org
88.99.195.15:34567      # node3.monerodevs.org
158.69.60.225:34567     # explore.wownero.com
195.94.188.201:34567    # spippolatori.it
45.237.33.156:34567     # wow.cypher.tec.br
```

## 13. RPC limits *(policy)*

| Constant | Value |
|---|---|
| `COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT` | 1,000 |
| `COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT` | 20,000 |
| `DEFAULT_RPC_MAX_CONNECTIONS_PER_PUBLIC_IP` | 3 |
| `DEFAULT_RPC_MAX_CONNECTIONS_PER_PRIVATE_IP` | 25 |
| `DEFAULT_RPC_MAX_CONNECTIONS` | 100 |
| `DEFAULT_RPC_SOFT_LIMIT_SIZE` | 26,214,400 (25 MiB) |
| `MAX_RPC_CONTENT_LENGTH` | 1,048,576 |
| `RPC_CREDITS_PER_HASH_SCALE` | `(f32) 1 << 24` |

## 14. Hard-coded checkpoints

39 entries, `(height, block_hash, cumulative_difficulty)`, from
`checkpoints::init_default_checkpoints`. A block at a checkpointed height whose
hash differs MUST be rejected. Cumulative difficulties are used by
`check_difficulty_checkpoints` / `recalculate_difficulties` to detect drift.

| Height | Block hash | Cumulative difficulty |
|---|---|---|
| 1 | `97f4ce4d7879b3bea54dcec738cd2ebb7952b4e9bb9743262310cd5fec749340` | `0x2` |
| 6969 | `aa7b66e8c461065139b55c29538a39c33ceda93e587f84d490ed573d80511c87` | `0x118eef693fd` |
| 53666 | `3f43f56f66ef0c43cf2fd14d0d28fa2aae0ef8f40716773511345750770f1255` | `0xb677d6405ae` |
| 63469 | `4e33a9343fc5b86661ec0affaeb5b5a065290602c02d817337e4a979fe5747d8` | `0xe7cd9819062` |
| 81769 | `41db9fef8d0ccfa78b570ee9525d4f55de77b510c3ae4b08a1d51b9aec9ade1d` | `0x150066455b88` |
| 82069 | `fdea800d23d0b2eea19dec8af31e453e883e8315c97e25c8bb3e88ca164f8369` | `0x15079b5fdaa8` |
| 114969 | `b48245956b87f243048fd61021f4b3e5443e57eee7ff8ba4762d18926e80b80c` | `0x1ca552b3ec68` |
| 115257 | `338e056551087fe23d6c4b4280244bc5362b004716d85ec799a775f190f9fea9` | `0x1cb25f5d4628` |
| 160777 | `9496690579af21f38f00e67e11c2e85a15912fe4f412aad33d1162be1579e755` | `0x5376eaa196a8` |
| 253999 | `755a289fe8a68e96a0f69069ba4007b676ec87dce2e47dfb9647fe5691f49883` | `0x172d026ef7fe8` |
| 254287 | `b37cb55abe73965b424f8028bf71bef98d069645077ffa52f0c134907b7734e3` | `0x1746622f56668` |
| 256700 | `389a8ab95a80e84ec74639c1078bc67b33af208ef00f53bd9609cfc40efa7059` | `0x185ace3c1bd68` |
| 271600 | `9597cdbdc52ca57d7dbd8f9c0a23a73194ef2ebbcfdc75c21992672706108d43` | `0x1e2d2d6a2a9e8` |
| 278300 | `b10dcdf7a51651f60fbcc0447409773eef1458d2c706d9a61daf467571ac19c9` | `0x20a83a16d3968` |
| 282700 | `79c06cafd7cb5f76bcebbf8f1ae16203bb41fd75b284bcd0eb0b457991ab7d4a` | `0x22e3baf142de8` |
| 307686 | `dfd056b2739c132a07629409a59a028cb7414fac23e3419e79d2f49d66fc3af5` | `0x305ba542e3ea8` |
| 307692 | `d822cd72037f62824ec87c9dc11768b45dc2632f697fa372e1885789c90f37fc` | `0x305e124633878` |
| 307735 | `60970378aecdc0a78ccf5154edcc56f23aad8554b49e4716f820461a7588bfdc` | `0x3070771b9ba58` |
| 307742 | `0ed835bc9fcd949b5a184cf607dcc62ac4268c9e4cf220f8b09bcce58f10916b` | `0x30732f1248978` |
| 307750 | `7bcafbc757237125b70f569b181eb1b66c530b10d817d7b940f7a73dc827211c` | `0x30766666b3d98` |
| 307766 | `02fd6c7d6bae710cfa3efb08f50e4bc9a590f6ab61eabd87e5e951338c0c36f6` | `0x307d2d47a7918` |
| 307800 | `3594894b4231cfdfe911afed6552f9fb4cfe6048bacd0973a3a98623ec8548ce` | `0x308b305ca7618` |
| 307880 | `659274b698f680c6cae2716cbd4e15ad5def23b5de98e53734c4af2c2e74bb7a` | `0x30af6e91e8018` |
| 307883 | `9a8c35cd10963a14bba8a9628d1776df92fee5e3153b7249f5d15726efafaaea` | `0x30b0965ba5a18` |
| 312130 | `e0da085bd273fff9f5f8e604fce0e91908bc62b6b004731a93e16e89cb9b1f54` | `0x3cfe7148f2e18` |
| 324600 | `b24cd1ed7c192bbcf3d5b15729f2b032566687f96bda6f8cb73a5b16df4c6e6b` | `0x69caecbe78718` |
| 327700 | `f113c8cbe077aab9296ecbfb41780c147aeb54edfece7e4b9946b8abd0f06de7` | `0x732431429c818` |
| 331170 | `05243fba853fe375c671a6783eecac28777bca51f5977d5285c235424e52bb69` | `0x7c3469310d218` |
| 331458 | `f79a664a5e4bc11fa7d804be2c3c72db50c87a27f1f540f337564cbb6314e4cd` | `0x7c34d47adf218` |
| 331891 | `faceea4b4ab33fc962c24dfa2f98c2aeda4788f67c1e0044c62419912c1a64fe` | `0x7c359086aeb58` |
| 332100 | `d32c409058c1eceb9a105190c7a5f480b2d6f49f318b18652b49ae971c710124` | `0x7c538441cca36` |
| 334000 | `17d3b15f8e1a73e1c61335ee7979e9e3d211b9055e8a7fb2481e5f49a51b1c22` | `0x7ddd5a79d69c4` |
| 348500 | `2d43a157f369e2aa26a329b56456142ecd1361f5808c688d97112a2e3bbd23f4` | `0x90889ed877ada` |
| 489400 | `b14f49eae77398117ea93435676100d8b655a804689f73a5a4d0d5e71160d603` | `0x1123c39bb52f7e` |
| 491200 | `cedba73ad35ce7f51aaca2beb36dc32d79ecc716d146eb8211e6a815f3666c4a` | `0x11334734abbd17` |
| 497100 | `2c4c70ac1ada94151f19d67ccf1aa4e846e6067f49f67c85cc03f78e768ea42b` | `0x116906bc97a751` |
| 760300 | `50ce41518bb4bea392194c13d0a5ef4cbf01ffb84ba393131e910adb63e2d360` | `0x18ef58d8abb8b3` |
| 771100 | `03e834788e1e33dbba9bc3431a81189cd655f9da80323a728fa0dae56a95145e` | `0x192cdb615ada62` |
| 838800 | `85ee72059e12e10a574628cac6f8ebcf8cf6cc1624a274c4ead39ede548777cd` | `0x19f2d01d49339c` |

That is the complete list: **39 entries**. Assert `table.len() == 39` in a unit
test so a future upstream addition is caught rather than silently missed.

Checkpoints also come from two other sources, both of which are **inert on
Wownero** and MAY be omitted:

- `load_checkpoints_from_json(<datadir>/checkpoints.json)` — a user-supplied
  `{"hashlines":[{"height":N,"hash":"..."}]}` file, enabled by
  `--enforce-dns-checkpointing` bookkeeping but independent of DNS.
- `load_checkpoints_from_dns` — the DNS TXT URL lists for all three networks are
  **empty**, so this always returns `true` having added nothing.

### 14.1 Fast-sync hash file

`src/blocks/checkpoints.dat` (104,836 bytes) holds precomputed block hashes for
the first 1,638 groups of `HASH_OF_HASHES_STEP = 512` blocks (838,656 blocks).
Format:

```
u32 LE  nblocks                 # number of 512-block groups = 1638
repeat nblocks times:
    [32] hash_of_hashes         # keccak(512 consecutive block hashes, 16384 bytes)
    [32] hash_of_weights        # keccak(512 consecutive u64 LE block weights, 4096 bytes)
```

Total size MUST equal `4 + nblocks * 64`. On mainnet the file's SHA-256 is
compared against a hard-coded `expected_block_hashes_hash` before use.

Semantics: when a block's height is covered by this table and the expected hash
is known, the node **skips PoW verification** and only checks that the block hash
matches. This is `--fast-block-sync 1` (default on). With
`--fast-block-sync 0` the node verifies every PoW from genesis. See
[06 §9.2](06-consensus-rules.md#92-the-height-202612-proof-of-work-override) for
why that distinction matters on Wownero.

## 15. Conformance checklist

- [ ] All address prefixes, ports and `NETWORK_ID` values match §2 exactly.
- [ ] Hard-fork tables for all three networks match §3 exactly, including the
      "gate" forks (12, 14, 17, 19) that exist only to close a feature window.
- [ ] `get_min_block_weight` returns 300,000 for every version ≥ 5.
- [ ] `FINAL_SUBSIDY_PER_MINUTE` is 0 — there MUST be no tail emission.
- [ ] The fee quantization mask is 1000.
- [ ] The checkpoint table has 39 entries and is copied verbatim from the C++
      source.
- [ ] `BLOCKS_SYNCHRONIZING_MAX_COUNT == SEEDHASH_EPOCH_BLOCKS == 2048`.
