# 13 — Wallet CLI (`wownero-wallet-cli`)

Source: `src/simplewallet/simplewallet.cpp` (114 registered commands),
`src/simplewallet/simplewallet.h`.

The CLI is a thin interactive shell over [12 — Wallet Core](12-wallet-core.md).
It is not a compatibility surface in the protocol sense, but scripts and users
depend on the command names and on the output being parseable by eye, so keep the
names and the general output shape.

---

## 1. Startup

```
wownero-wallet-cli [options] [--wallet-file <name> | --generate-new-wallet <name>
                              | --restore-deterministic-wallet
                              | --restore-from-keys
                              | --generate-from-view-key
                              | --generate-from-spend-key
                              | --generate-from-keys
                              | --generate-from-json <file>]
```

Key options:

```
--daemon-address <host:port>        default 127.0.0.1:34568
--daemon-host <host> --daemon-port <port>
--daemon-login <user[:pass]>
--trusted-daemon / --untrusted-daemon
--proxy <ip:port>
--password <pass> --password-file <file>
--testnet --stagenet
--restore-height <n>
--restore-date <YYYY-MM-DD>
--electrum-seed "<25 words>"
--mnemonic-language <lang>
--command <cmd ...>                 run one command and exit
--log-file <path> --log-level <n>
--max-concurrency <n>
--kdf-rounds <n>                    default 1
--no-initial-sync
--offline
--create-address-file
--use-english-language-names
--rpc-bind-port ...                 (wallet-rpc only; see 14)
```

`--trusted-daemon` unlocks commands that leak information to the daemon
(`get_output_distribution` over the full chain, `is_output_spent`, ring
lookups) and enables importing key images. A remote daemon is untrusted by
default.

On first run without a wallet file, the CLI offers to generate, restore or open,
and asks for a mnemonic language.

---

## 2. Commands

Grouped by purpose. Every name below is a registered handler in
`simplewallet.cpp` and MUST be present (or explicitly reject as unsupported).

### 2.1 Wallet lifecycle

```
help  apropos <keyword>  version  wallet_info  welcome  status  clear  exit
save  save_bc  save_watch_only  password  encrypted_seed  seed  spendkey  viewkey
set <option> <value>        # persists to the keys file
set_log <level|categories>
```

`set` options (all persisted in the keys JSON, [12 §2.1](12-wallet-core.md)):

```
seed language | always-confirm-transfers | print-ring-members | store-tx-info
default-ring-size | auto-refresh | refresh-type | priority | confirm-missing-payment-id
ask-password | unit | min-outputs-count | min-outputs-value | merge-destinations
confirm-backlog | confirm-backlog-threshold | refresh-from-block-height
auto-low-priority | segregate-pre-fork-outputs | key-reuse-mitigation2
subaddress-lookahead | segregation-height | ignore-fractional-outputs
ignore-outputs-above | ignore-outputs-below | track-uses | setup-background-mining
device-name | export-format | load-deprecated-formats | persistent-rpc-client-id
auto-mine-for-rpc-payment-threshold | credits-target | inactivity-lock-timeout
show-wallet-name-when-locked | enable-multisig-experimental
```

### 2.2 Addresses & accounts

```
address [new [<label>] | all | <index> | label <index> <label>]
integrated_address [<payment_id>|<address>]
address_book [add <address> [<description>] | delete <index>]
account [new <label> | switch <index> | label <index> <label>
         | tag <tag> <index...> | untag <index...> | tag_description <tag> <desc>]
payment_id
set_description <text>  get_description
show_qr_code [<subaddress_index>]     # Wownero keeps this; renders the address
                                      #   as a terminal QR code
```

### 2.3 Balance & history

```
balance [detail]
incoming_transfers [available|unavailable] [verbose] [uses] [index=<N1>[,<N2>...]]
payments <payment_id> [<payment_id> ...]
bc_height
show_transfers [in|out|all|pending|failed|pool|coinbase] [index=<N>]
               [<min_height> [<max_height>]]
export_transfers [in|out|all|pending|failed|pool|coinbase] [index=<N>]
               [<min_height> [<max_height>]] [output=<filepath>] [option=<with_keys>]
show_transfer <txid>
unspent_outputs [index=<N>] [<min_amount> [<max_amount>]]
net_stats  rpc_payment_info  public_nodes
restore_height
```

### 2.4 Sending

```
transfer [index=<N1>[,<N2>...]] [<priority>] [<ring_size>]
         (<URI> | <address> <amount>) [<payment_id>]
sweep_all [index=<N>|index=all] [<priority>] [<ring_size>] [outputs=<N>]
          <address> [<payment_id>]
sweep_account <account> [index=<N>] [<priority>] [<ring_size>] [outputs=<N>]
          <address> [<payment_id>]
sweep_below <amount_threshold> [index=<N>] [<priority>] [<ring_size>] <address>
sweep_single [<priority>] [<ring_size>] [outputs=<N>] <key_image> <address>
sweep_unmixable
donate [index=<N>] [<priority>] [<ring_size>] <amount> [<payment_id>]
fee
```

`<ring_size>` MUST be rejected unless it is **22** at HF ≥ 15 (the same-ring-size
rule means any other value produces an invalid transaction). Print a clear error
rather than building a doomed transaction.

`<priority>` is `default|unimportant|normal|elevated|priority` or `0..4`.

`donate` sends to the hard-coded donation address in `simplewallet.h`; on
non-mainnet it re-encodes that address for the current network.

### 2.5 Proofs & signing

```
get_tx_key <txid>   set_tx_key <txid> <tx_key> [<subaddress>]
check_tx_key <txid> <tx_key> <address>
get_tx_proof <txid> <address> [<message>]
check_tx_proof <txid> <address> <signature_file> [<message>]
get_spend_proof <txid> [<message>]
check_spend_proof <txid> <signature_file> [<message>]
get_reserve_proof (all | <amount>) [<message>]
check_reserve_proof <address> <signature_file> [<message>]
sign <filename> [--spend-key] [--signature-file <file>]
verify <filename> <address> <signature_file>
get_tx_note <txid>  set_tx_note <txid> [free text]
```

### 2.6 Refresh & maintenance

```
refresh  rescan_bc [hard|soft|keep_ki]  rescan_spent  scan_tx <txid> [<txid> ...]
set_daemon <host>[:<port>] [trusted|untrusted]
freeze <key_image>  thaw <key_image>  frozen <key_image>
mark_output_spent / mark_output_unspent / is_output_spent
lock
```

`rescan_bc hard` wipes the cache and rescans from `refresh_height`;
`soft` keeps known key images; `keep_ki` keeps the key images only.

### 2.7 Ring management (`--trusted-daemon`)

```
print_ring <key_image>|<txid>
set_ring <filename> | ( <key_image> absolute|relative <index> [<index>...] )
unset_ring <txid>|<key_image> [<key_image>...]
save_known_rings
```

Used to make re-spends of the same output reuse the same ring, which avoids the
"key reuse" heuristic. Stored in a local `ringdb` LMDB keyed with
`HASH_KEY_RINGDB`. Optional; if omitted, these commands MUST report
unsupported rather than silently doing nothing.

### 2.8 Mining

```
start_mining [<threads>] [bg_mining] [ignore_battery]
stop_mining
start_mining_for_rpc  stop_mining_for_rpc
```

`start_mining` calls the daemon's `/start_mining`. **At HF ≥ 18 that produces
invalid blocks unless the daemon was started with `--spendkey`**
([06 §4.1](06-consensus-rules.md)). The CLI SHOULD print a warning explaining
this, since it is the single most confusing thing about mining Wownero.

### 2.9 Cold/offline signing

```
export_outputs <filename> [all]   import_outputs <filename>
export_key_images <filename> [all]  import_key_images <filename>
sign_transfer [export_raw] [<filename>]  submit_transfer <filename>
hw_key_images_sync  hw_reconnect
```

### 2.10 Multisig (optional — see [12 §7](12-wallet-core.md))

```
prepare_multisig  make_multisig <threshold> <string...>
exchange_multisig_keys <string...>  export_multisig_info <filename>
import_multisig_info <filename...>  sign_multisig <filename>
submit_multisig <filename>  export_raw_multisig_tx <filename>
mms <subcommand...>
```

### 2.11 Background sync (optional)

```
setup_background_sync <off|reuse-wallet-password|custom-background-password>
start_background_sync  stop_background_sync
```

---

## 3. Interaction requirements

- **Password prompts** must not echo, and the password buffer should be wiped
  after use (the C++ uses `epee::wipeable_string`).
- **`inactivity_lock_timeout`** (default on) locks the wallet after N seconds of
  no input; `lock` locks immediately. Unlocking re-prompts for the password.
- **Confirmation prompts** before every transfer, showing amount, fee, ring size,
  destinations and (if `print-ring-members`) the ring members.
  `always-confirm-transfers` can be turned off.
- **Refresh runs in the background** when `auto-refresh` is on, printing "Height
  N / M" progress and announcing received transactions.
- **`--command`** runs a single command non-interactively and exits with a status
  code, which is how scripts drive the wallet. Support it.
- Output amounts are printed with 11 decimals (`default_decimal_point`), e.g.
  `1.00000000000`.

---

## 4. Implementation priority

M4 minimum viable CLI:

```
open/create/restore, seed, viewkey, spendkey, address, balance, refresh,
show_transfers, incoming_transfers, transfer, sweep_all, sweep_single,
fee, bc_height, status, save, set_daemon, rescan_bc, set, help, exit
```

Then proofs, then export/import, then rings, then multisig.

---

## 5. Conformance checklist

- [ ] All command names from §2 are registered; unimplemented ones report
      "not supported" with a non-zero exit under `--command`.
- [ ] `set` options persist to the keys file and are re-read on open.
- [ ] Ring sizes other than 22 are rejected with an explanation.
- [ ] Amounts are parsed and printed with exactly 11 decimals.
- [ ] Passwords are never echoed and are wiped after use.
- [ ] `--command` supports non-interactive scripted use.
- [ ] `start_mining` warns about the `--spendkey` requirement at HF ≥ 18.
- [ ] The wallet refuses to open a multisig keys file when multisig is not
      implemented.
