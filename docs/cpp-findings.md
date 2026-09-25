# Findings in the C++ reference tree

Things wrong, misleading, or fragile in **upstream C++** — not in this port, and
not in the spec documents. `docs/spec-deltas.md` is the other list: places where
`specs/` describes the C++ inaccurately. This one is about the C++ itself.

Reference tree: `wownero.git` at `9f4f22c72`, version `0.11.4.0` "Kunty Karen".

## How to use this

Each item is a checkbox with a **C++ test to write**. The point is to confirm
each finding against a real `wownerod` build rather than against reading, and
then to decide case by case whether it is worth an upstream patch.

Severity:

- **consensus** — changing it would fork the chain. Report, never "fix".
- **latent** — wrong but currently unreachable, or benign by luck.
- **cosmetic** — a comment or name that misleads a reader; the code is right.

Nothing here is a security report. Anything that looked exploitable would go to
the Wownero maintainers privately first, not into a repo file.

---

## 1. `rctTypes.h`: the `H` generator's stated derivation is false

**Severity:** cosmetic (the constant is correct; the comment is not)

`src/ringct/rctTypes.h:652`:

```cpp
//other basepoint H = toPoint(cn_fast_hash(G)), G the basepoint
static const key H = { {0x8b, 0x65, 0x59, 0x70, ...} };
```

`rctOps.cpp: hash_to_p3` is byte-for-byte `crypto::hash_to_ec`, and applying it
to the basepoint encoding does **not** produce that literal. The same claim
appears in Monero, so it is inherited rather than Wownero's.

Harmless as long as nobody recomputes the constant from the comment — which is
exactly what a reimplementation is tempted to do.

- [ ] **C++ test:** assert
      `hash_to_p3(cn_fast_hash(GetBasepointBytes())) != rct::H`, and add a
      comment correction. Confirms the literal is load-bearing.

**Rust side:** `wow_crypto::rct::h_is_not_the_documented_derivation`,
`docs/spec-deltas.md` §4.

---

## 2. `cryptonote_format_utils.cpp`: `round_money_up`'s comment contradicts its code

**Severity:** cosmetic

`src/cryptonote_basic/cryptonote_format_utils.cpp:1242`:

```cpp
// bump digits by one if the following digits past significant digits were to be 5 or more
if (*ptr != '0')
{
  bump = true;
  *ptr = '0';
}
```

The comment describes round-half-up. The code bumps on **any** non-zero digit,
i.e. it is a ceiling. `round_money_up(101, 2)` is 110, not 100.

The name says "up", so the code is almost certainly what was intended and the
comment is stale. It feeds the four wallet fee tiers, so a reader who trusts the
comment quotes fees that are too low.

- [ ] **C++ test:** `round_money_up(101, 2) == 110` and
      `round_money_up(149, 2) == 150`. Both fail under a half-up reading.

**Rust side:** `wow_consensus::fee::round_money_up_is_a_ceiling_not_a_rounding`.

---

## 3. `db_lmdb.cpp`: `do_resize`'s page alignment does not align

**Severity:** latent (benign — the map ends up slightly larger, never smaller)

`BlockchainLMDB::do_resize`:

```cpp
new_mapsize += new_mapsize % mst.ms_psize;
```

This **adds the remainder**. Rounding up to a page boundary is
`new += psize - (new % psize)`, or `new = ((new + psize - 1) / psize) * psize`.
As written, a map size one byte past a page boundary grows by one byte and is
still unaligned.

LMDB rounds the map size down to a page multiple internally, so the effect is
nil — which is presumably why it has never been noticed.

- [ ] **C++ test:** force a resize from a deliberately unaligned map size and
      assert `mei.me_mapsize % mst.ms_psize` afterwards. Under the intended
      reading it is 0; under the current code it need not be.

**Rust side:**
`wow_storage::env::the_resize_adds_the_remainder_rather_than_rounding_up`.

---

## 4. `blockchain.cpp`: `assert(hi == 0)` is compiled out in release

**Severity:** latent

`Blockchain::get_dynamic_base_fee` calls `div128_64` and then `assert(hi == 0)`
before using `lo`. Release builds define `NDEBUG`, so the assertion vanishes and
an overflow would silently truncate to the low 64 bits instead of aborting.

Unreachable with real inputs — `block_reward * 3000 / median / median` cannot
exceed 64 bits for any median at or above 300,000 — so this is about the guard
being absent, not about a live overflow.

- [ ] **C++ test:** call `get_dynamic_base_fee` with a synthetic `block_reward`
      large enough to overflow and observe a release build returning a truncated
      fee rather than aborting. Consider `CHECK_AND_ASSERT_THROW_MES`.

**Rust side:** `wow_consensus::fee` models the truncation deliberately, since a
release build is the thing to match.

---

## 5. `blockchain.cpp`: a vacuous clause in the ring-size branch table

**Severity:** latent (dead code)

`Blockchain::check_tx_inputs`:

```cpp
|| (hf_version < HF_VERSION_MIN_MIXIN_21 && hf_version >= HF_VERSION_MIN_MIXIN_7+2 && min_actual_mixin > 7)
```

`HF_VERSION_MIN_MIXIN_7 + 2 == 9 == HF_VERSION_MIN_MIXIN_21`, so the condition is
`hf < 9 && hf >= 9`: never true. It presumably dated from when the two constants
differed.

Deleting it changes nothing today, but the constants are the kind of thing that
gets adjusted, and if they ever diverge the clause wakes up.

- [ ] **C++ test:** a static assertion that
      `HF_VERSION_MIN_MIXIN_7 + 2 == HF_VERSION_MIN_MIXIN_21`, so a future
      constant change surfaces the dead clause instead of silently reviving it.

**Rust side:** transcribed as written, with
`wow_consensus::tx_rules::the_vacuous_clause_never_fires` asserting it stays
vacuous. `clippy::impossible_comparisons` flags it, and the allow says why.

---

## 6. `blockchain.cpp`: the last RingCT gate is missing its version guard

**Severity:** latent (inert, but inconsistent)

The eight gates in `check_tx_inputs` that police `rct_signatures.type` are each
wrapped in `if (tx.version >= 2)`. The ninth is not:

```cpp
// from v22, forbid bulletproof plus legacy
if (hf_version > HF_VERSION_BP_PLUS_FULL_COMMIT && rct::is_rct_bp_plus_legacy(tx.rct_signatures.type)) {
```

Inert, because a v1 transaction carries `RCTTypeNull` and
`is_rct_bp_plus_legacy(0)` is false. Still, the asymmetry looks accidental, and a
future gate copied from this one would inherit it.

- [ ] **C++ test:** feed a v1 transaction with a forged `rct_signatures.type` of
      8 at `hf_version = 22` and confirm the rejection comes from this gate.
      Documents the reachability either way.

**Rust side:** `wow_consensus::tx_rules::the_last_gate_applies_to_v1_too`,
`docs/spec-deltas.md` §15.

---

## 7. `hardfork.cpp`: `get_voted_fork_index` depends on call ordering

**Severity:** latent (correct today, fragile)

`HardFork::init()` inserts a placeholder at index 0 only `if (heights.empty())`.
`Blockchain::init` calls `add_fork` for the whole table *before* `init()`, so the
placeholder is never inserted and `heights[0]` is the real first fork.

`get_voted_fork_index` ends in `return current_fork_index` (0 initially), so the
version below every fork height is `heights[0].version` — 7 on Wownero, not
`original_version` (1). Wownero's genesis block carries version 7 and `do_check`
compares for equality, so this is what makes genesis validate.

Swap the two calls and genesis stops validating. Nothing marks the dependency.

- [ ] **C++ test:** construct a `HardFork`, call `init()` **before** `add_fork`,
      and assert `get_current_version()` differs from the normal path — pinning
      the ordering requirement rather than leaving it implicit.

**Rust side:** `wow_consensus::hardfork::genesis_is_below_every_fork`,
`docs/spec-deltas.md` §12.

---

## 8. `varint.h`: a truncated varint is a *successful* read

**Severity:** consensus (reproduce; do not change)

`read_varint` returns the bytes consumed when it runs out of input:

```cpp
if (first == last) return read;   // not an error
```

So a blob ending mid-varint decodes to whatever was accumulated so far, rather
than failing. Any parser that "fixes" this by erroring rejects blobs the
reference accepts.

This is load-bearing, not incidental: dropping a trailing varint from a block
blob reparses to the same object.

- [ ] **C++ test:** `read_varint` over a deliberately truncated buffer, asserting
      it returns the partial value and the short count. Locks the behaviour in
      so nobody tightens it.

**Rust side:** `wow_serialize::varint` reproduces the EOF tolerance;
`docs/spec-deltas.md` §6.

---

## 9. `mnemonics`: the prefix map is last-wins, making `english_old` lossy

**Severity:** latent (affects one wordlist)

`populate_maps` assigns rather than inserts:

```cpp
trimmed_word_map[trimmed] = ii;
```

On a duplicate prefix the **last** word wins, so decoding a seed in a list with
colliding prefixes can yield a different word than was encoded. `english_old`
has such collisions and is flagged `ALLOW_DUPLICATE_PREFIXES` for that reason,
which makes its 25-word round trip lossy in the reference too.

- [ ] **C++ test:** round-trip every `english_old` seed phrase and count the
      words that change. Confirms the loss is inherent rather than a port bug.

**Rust side:** `wow_crypto::mnemonic` reproduces last-wins and excludes
`english_old` from the round-trip assertion; `docs/spec-deltas.md` §9.

---

## 10. `blockchain.cpp`: partial block rewards permanently altered the emission curve

**Severity:** consensus (historical; reproduce exactly)

For hard-fork versions 2–15 a miner could claim **less** than the full block
reward, and `already_generated_coins` accumulated only what was claimed. Every
later reward is computed from that running total, so an under-claim in 2018
changes the subsidy forever.

On Wownero the window is HF 7–15, heights 1 … 253,998. Not a bug to fix — it is
the chain's history — but it is the kind of thing a reimplementation "corrects"
by accident, and the result is a wrong reward at every subsequent height.

- [ ] **C++ test:** replay `validate_miner_transaction` over a height where the
      claimed reward was short and assert `already_generated_coins` advances by
      the claimed amount, not the full one.

**Rust side:** `wow_consensus::emission::validate_miner_reward`.

---

## 11. `rctTypes.cpp`: `is_rct_bulletproof` includes CLSAG

**Severity:** cosmetic (surprising name, correct behaviour)

```cpp
bool is_rct_bulletproof(int type) {
    case RCTTypeSimpleBulletproof: case RCTTypeFullBulletproof:
    case RCTTypeBulletproof: case RCTTypeBulletproof2:
    case RCTTypeCLSAG:                                    // <--
        return true;
```

Correct — CLSAG is a signature scheme that carries Bulletproof *range proofs* —
but the name reads as a type check on the signature scheme. It is why the
`hf > 18` gate labelled "forbid bulletproofs" also forbids CLSAG, which is not
obvious from the call site.

- [ ] **C++ test:** assert `is_rct_bulletproof(RCTTypeCLSAG)` and add a comment
      at the `hf > 18` gate naming CLSAG explicitly.

**Rust side:** `wow_consensus::tx_rules::is_rct_bulletproof` carries the note;
`docs/spec-deltas.md` §15.

---

## 12. `blockchain.cpp`: `check_tx_inputs` judges every transaction by the *tip's* hard-fork version

**Severity:** consensus (report, never "fix")

> **Correction: the premise of this finding is wrong.** `get_current_version()`
> is not the tip block's version. `BlockchainDB::add_block` calls
> `m_hardfork->add(blk, height)`, and `HardFork::add` advances to
> `get_voted_fork_index(height + 1)`, so while the block at height `H` is
> validated it returns the version at `H` — the block's own. Forward sync and a
> reorg (which pops first) both see the right version; nothing depends on an
> accident. Taking the premise at face value, the Rust node read the version at
> `H - 1` for the difficulty and timestamp rules and picked the wrong
> difficulty algorithm on the first block of six mainnet forks; see
> `wow_core::Blockchain::current_version`. The block-460 observation below still
> holds, but it is §13's.

`src/cryptonote_core/blockchain.cpp:3368`, in the `check_tx_inputs` that does
the work:

```cpp
bool Blockchain::check_tx_inputs(transaction& tx, tx_verification_context &tvc, uint64_t* pmax_used_block_height) const
{
  ...
  const uint8_t hf_version = m_hardfork->get_current_version();
```

`get_current_version()` is the version in force at the **chain tip**, not the
version of the block the transaction is in. Every rule below that line — the
minimum output count, the ring-size table, the version bounds, the
`HF_VERSION_SAME_MIXIN` constant-ring rule — is therefore evaluated against
whatever the chain has since forked to.

For the mempool this is right: a transaction being admitted now must satisfy
today's rules. For a block being added it is only right by accident, because
the tip is the block's own parent while syncing forward. The two cases share
one function and one `hf_version`.

Where it stops being an accident:

- **A reorg past a fork boundary.** Blocks below the fork are re-validated with
  the post-fork rules. Wownero's checkpoints make a reorg that deep
  impossible in practice, which is what keeps this latent.
- **Any re-validation of historical blocks.** It is masked today only by
  finding §13 below: the historical blocks that would fail are never checked.

The `ring size` rules make the exposure concrete. At `hf_version == 7` the
table demands mixin *exactly* 7:

```cpp
|| ((hf_version == HF_VERSION_MIN_MIXIN_7 || hf_version == HF_VERSION_MIN_MIXIN_7+1)
    && min_actual_mixin != 7)
```

Mainnet block 460 carries a transaction with mixin 11. It is on the chain. It
would not pass `check_tx_inputs` at `hf_version` 7, and it would not pass at
`hf_version` 20 either (`hf_version > HF_VERSION_MIN_MIXIN_21 && min_actual_mixin > 21`
is false, but `HF_VERSION_SAME_MIXIN` and the rest now apply to it). It
survives because it is never examined.

- [ ] **C++ test:** call `check_tx_inputs` directly on the transaction in
      mainnet block 460 with the chain synced to the tip, and assert it
      returns false. Then assert that a full sync with `PER_BLOCK_CHECKPOINT`
      disabled fails at that height, which pins the dependency between this
      finding and §13.

**Rust side:** `wow_consensus::tx_rules` takes `hf_version` as a parameter and
`wow_core::chain` passes the *block's* version, which is the stricter reading
and diverges from the C++ only where the C++ is self-inconsistent.
`docs/spec-deltas.md` §23.

---

## 13. `blockchain.cpp`: most of the chain is never verified

**Severity:** consensus (report, never "fix")

With `PER_BLOCK_CHECKPOINT` compiled in — it is, by default — a block whose
height is covered by the embedded `blocks.dat` hash table and whose id matches
skips both proof-of-work and transaction-input validation entirely. The full
mechanism and the three call sites are in `docs/spec-deltas.md` §23.

This is deliberate and is how every Monero-family node achieves a tolerable
initial sync. It is recorded here because of what it implies rather than
because it is wrong:

- The embedded hashes are **the** security boundary for the first ~99% of the
  chain. A node's history is as trustworthy as the binary it came in.
- It cannot be turned off at runtime. There is no
  `--validate-from-genesis`, so "does this chain actually satisfy its own
  rules?" is a question no released build can answer.
- It hides §12 above, and it hides any other rule that historical blocks
  violate. Nobody finds out which rules those are.

The comment above the proof-of-work block is worth reading against this:

```cpp
// Formerly the code below contained an if loop with the following condition
// !m_checkpoints.is_in_checkpoint_zone(get_current_blockchain_height())
// however, this caused the daemon to not bother checking PoW for blocks
// before checkpoints, which is very dangerous behaviour. We moved the PoW
// validation out of the next chunk of code to make sure that we correctly
// check PoW now.
```

The behaviour it calls "very dangerous" was removed from one path and is
present in the next twenty lines, keyed on a different table.

- [ ] **C++ test:** build with `PER_BLOCK_CHECKPOINT` off and sync mainnet from
      genesis; record the first height that fails and the rule it fails. That
      list is the set of rules the chain does not actually satisfy, and it does
      not exist anywhere today.

**Rust side:** `netsync::LocalChain` reproduces the bypass, keyed on the
hard-coded checkpoints rather than an embedded hash file, and reports at
startup which range it is not verifying. `docs/spec-deltas.md` §23.

---

## 14. `miner.cpp`: the vote is set after the header is signed

**Severity:** latent (costs a found block now and then)

`src/cryptonote_basic/miner.cpp`, in `worker_thread`:

```cpp
crypto::hash sig_data = get_sig_data(b);
...
crypto::generate_signature(sig_data, output_public_key, eph_secret_key, signature);
b.signature = signature;
b.vote = m_int_vote;           // after the signature it should be under
```

`vote` is serialized into the header that `get_sig_data` hashes; only
`signature` is zeroed. `b` is copied from the template, whose vote is 0, each
time the template changes, so with `--vote yes` or `--vote no` the first nonce
tried after every refresh carries a signature over vote 0 and a header saying 1
or 2. Later nonces are fine, because `b` keeps the vote from the one before.
If that first nonce meets the target, the node rejects its own block ("Miner
signature is invalid").

- [ ] **C++ test:** set a template, run one iteration of the worker loop with
      `m_int_vote = 1`, and check the signature against the resulting header.
      The fix is to move `b.vote = m_int_vote` above `get_sig_data`.

**Rust side:** `wownerod::miner::sign_header` sets the vote first;
`a_signed_header_verifies_as_consensus_checks_it` signs with votes 0, 1 and 2.

---

## 15. `miner.cpp`: the signing key is never checked against the address

**Severity:** latent (a miner that can never win)

`miner::init` reads `--spendkey` with `hex_to_pod` and ignores its result,
derives the view key as `keccak(spend)`, and never compares either with the
address passed to `start_mining`. Without `--spendkey` the keys stay zero. In
every one of those cases each block found carries a signature that does not
verify against `vout[0]`'s key, the node rejects it, and the log still says a
block was found. In a debug build `generate_signature`'s `assert(pub == t2)`
aborts the daemon instead.

- [ ] **C++ test:** `start_mining` at HF 18 with no `--spendkey`, and with the
      key of a different address; both should be refused at start.

**Rust side:** `wownerod::miner::Keys::new` refuses a key that is not the
address's, and mining past HF 18 without one is refused
(`a_spend_key_is_checked_against_the_address`,
`mining_past_hf18_without_keys_is_refused`).

---

## 16. `core_rpc_server.cpp`: `generateblocks` cannot produce a valid block

**Severity:** latent (regtest tooling)

```cpp
if (b.major_version >= HF_VERSION_BLOCK_HEADER_MINER_SIG)
{
    b.signature = {};
    b.vote = 0;
}
```

Regtest runs the newest fork from height 1, so every block needs a header
signature, and `check_signature` rejects an all-zero one. Every
`generateblocks` call finds a nonce and then fails in `submitblock`, which also
means the Python functional tests that call it cannot pass.

- [ ] **C++ test:** `generateblocks` on a fresh regtest daemon, expecting the
      height to advance.

**Rust side:** `rpc::mining::generateblocks` signs every attempt when the
daemon has the address's `--spendkey` (`docs/daemon-review.md` E).

---

## 17. `blockchain.cpp`: `recalculate_difficulties` uses the tip's algorithm for every height

**Severity:** latent on mainnet; live on testnet and stagenet

```cpp
uint8_t version = get_current_hard_fork_version();   // once, before the loop
...
for (uint64_t height = start_height; height <= top_height; ++height)
{
  uint64_t HEIGHT = m_db->height();                   // the tip, not `height`
  if (version >= 20) recalculated_diff = next_difficulty_v6(..., HEIGHT, m_nettype);
```

`core::on_idle` runs it every seven days from the last matching difficulty
checkpoint. Monero has one algorithm, so hoisting the version out of the loop
cost nothing there; Wownero has six.

- **Testnet and stagenet** have no difficulty checkpoints, so the run starts at
  0. Blocks 1-720 were validated at difficulty 100 (the
  `HEIGHT <= DIFFICULTY_WINDOW` branch); the rerun passes the tip height and
  gets 1. The drift is "found" at height 1 and every cumulative difficulty is
  rewritten about 100 times too low, after which the node asks for a
  hundredth of the network's work.
- **Mainnet** is safe only because everything after the last difficulty
  checkpoint (838,800) is HF 20.

- [ ] **C++ test:** run `recalculate_difficulties(0)` on a testnet chain past
      height 720 and compare the stored cumulative difficulties before and
      after.

**Rust side:** not reproduced. Nothing calls
`correct_block_cumulative_difficulties`, so the Rust node never rewrites
stored difficulties.

---

## 18. `blockchain.cpp`: alternative-chain difficulty uses the main chain's version and height

**Severity:** consensus (report, never "fix")

`get_next_difficulty_for_alternative_chain` picks the algorithm and window with
`get_current_hard_fork_version()` and passes `HEIGHT = m_db->height()`: both
the main chain's, not the alternative block's. The main path uses the block
being validated. So near a fork that changes the algorithm, or on testnet
while the tip is past 720 and the alternative block is not, an alternative
block is judged by different rules than the same block would be on the main
path. All of mainnet's algorithm changes are behind checkpoints.

- [ ] **C++ test:** on testnet, submit an alternative block at height 700 with
      the tip at 800 and compare the difficulty it is checked against with the
      one the main path used at 700.

**Rust side:** reproduced, so a Rust node accepts the alternative blocks a C++
node does. `wow_core::chain::Blockchain::alt_difficulty` used to pass the
alternative block's height as `HEIGHT`; it now passes the main chain's,
`specs/07` §7.

---

## 19. `abstract_tcp_server2.inl`: an RPC reply is cut while it is still being written

**Severity:** latent (large replies to remote clients)

The connection has one timer. `start_write` sets `wait_write = true` and never
touches it; only `on_write` re-arms it, and that runs after the whole buffer
has gone. An RPC reply is always one unchunked `async_write` (`send()`,
`m_connection_type == e_connection_type_RPC ||`). So:

- the first request on a new remote connection has 10 s
  (`NEW_CONNECTION_TIMEOUT_REMOTE`) from accept for the handler and the whole
  write together;
- a reused keep-alive connection has whatever is left of its 5 minutes.

When the timer fires, `interrupt()` closes the socket mid-body. A client sees
a truncated reply, typically a big `get_blocks.bin`. Monero fixed it on
2026-08-17 (`4979a1c57e28`, re-arming the timer in `start_write`; take it
without the `NEW_CONNECTION_TIMEOUT_LOCAL` change that `b7d4144e` reverts).
Even then the budget is capped at the default timeout, so a 100 MB reply to a
client slower than about 330 KB/s is still cut; writing in pieces and
re-arming after each would remove that.

- [ ] **C++ test:** Monero's `slow_reader_is_not_dropped_mid_response`.

**Rust side:** not reproduced. `rpc::http::WRITE_TIMEOUT` is `SO_SNDTIMEO`,
which bounds each write call, so a client that keeps reading is never cut off.

---

## 20. `abstract_tcp_server2.inl`: the per-host connection map never shrinks

**Severity:** latent (slow memory growth)

```cpp
static std::map<std::string, unsigned int> hosts;
unsigned int &val = hosts[m_host];
```

Entries are never erased, and `get_default_timeout()`'s `host_count(0)` call
inserts one too. Every distinct remote address ever seen, P2P or RPC, stays
for the life of the process. Monero fixed it in `0bf3e67`.

- [ ] **C++ test:** connect from many loopback addresses and check the map's
      size after they close.

**Rust side:** connections per address are counted from the live connection
list, with no map. The same leak did exist in two failure-count maps, which
only reset an address's stale count when that address failed again:
`AddressBook::record_failure` (bad handshakes) and
`rpc::auth::Login::record_failure` (failed RPC logins). Both now drop every
count older than their window (`stale_failure_counts_are_removed`).

---

## 21. `http_protocol_handler.inl`: a pipelined request after a body waits for more bytes

**Severity:** latent (no client here pipelines)

```cpp
case http_state_retriving_body:
    return handle_retriving_query_body();
```

After the body is consumed and answered, this returns instead of going round
the loop again, so a second request already sitting in `m_cache` is not
parsed until another read arrives, which a client waiting for its answer
never sends. The connection sits until the idle timeout. The no-body path also
keeps answering pipelined requests after one that said `Connection: close`.

- [ ] **C++ test:** send two POSTs with bodies in one segment and expect two
      replies.

**Rust side:** not reproduced: one buffered reader per connection, a body read
by its `Content-Length` and no further, and nothing read after a
`Connection: close` request (`rpc::http::pipelined_requests_are_read_in_turn`).

---

## 22. `core_rpc_server.cpp`: `add_aux_pow` writes merge-mining depth 0

**Severity:** latent (merge mining with two or more chains)

```cpp
size_t merkle_tree_depth = 0;                                   // never updated
res.merkle_tree_depth = cryptonote::encode_mm_depth(aux_pow.size(), nonce);
if (!add_mm_merkle_root_to_tx_extra(b.miner_tx.extra, merkle_root, merkle_tree_depth))
```

The response reports the real depth and the coinbase carries 0, so aux chains
that check the tag reject the proof. With one chain the encoded depth is 0 and
it happens to work. Monero PR #9073 fixed it, together with widening the depth
in `add_mm_merkle_root_to_tx_extra` to a varint. From HF 18 any template it
returns also has to be re-signed by whoever mines it.

- [ ] **C++ test:** `add_aux_pow` with two chains, then parse the returned
      template's extra and compare the depth with the response's.

**Rust side:** `add_aux_pow` is not implemented.

---

## 23. `core_rpc_server.cpp`: the restricted `get_info` gives out the exact build

**Severity:** cosmetic (a scanning aid, and a console escape)

Wownero removed Monero's `restricted ? "" :` from `on_get_info`, so a public
node tells anyone its exact version and commit, while the restricted ZMQ
`get_info` still blanks it. The same change removed the
`is_version_string_valid` filter from the console's `version` command, which
then prints whatever a remote daemon returns, terminal escape sequences
included.

- [ ] **C++ test:** `get_info` on a restricted port over HTTP and ZMQ, expecting
      the same `version`.

**Rust side:** `get_info` on a restricted listener returns an empty `version`
over HTTP, as it already did over ZMQ (`the_restricted_port_leaves_out_what_is_restricted`).
No wallet here reads it. The wallets print daemon-supplied text through
`wow_daemon_client::printable`, which replaces control characters: RPC error
messages, `status`, a rejected transaction's `reason`, and `nettype`.

---

## 24. `daemon_handler.cpp`: the restricted ZMQ histogram refuses `recent_cutoff = 0`

**Severity:** cosmetic

```cpp
const clock::time_point cutoff{std::chrono::seconds{req.recent_cutoff}};
if (now - cutoff > 3 days) ...  // refuse
```

HTTP (`on_get_output_histogram`) refuses only
`recent_cutoff > 0 && recent_cutoff < now - 3 days`, so 0, "no cutoff", is
served there and refused over ZMQ. A `recent_cutoff` above about 9.2e9 also
overflows the seconds-to-nanoseconds conversion.

- [ ] **C++ test:** restricted ZMQ `get_output_histogram` with
      `recent_cutoff = 0`.

**Rust side:** the ZMQ handler used to copy the ZMQ test; it now uses the HTTP
one (`zmq::handler::recent_cutoff_too_old`,
`restricted_mode_and_refused_configurations`).

---

## 25. `cryptonote_core.cpp`, `updates.cpp`: the update check is half rebranded

**Severity:** latent (dormant: the domain list is empty)

`core::check_updates` looks up `software = "monero"` while the RPC `update`
handler uses `"wownero"`; `get_update_url`'s host is `""`, so a URL comes out
relative; and the hash test `fields[3].size() != 64 && !alnum` (inherited, and
still in Monero) accepts any 64-character non-hex string. Nothing runs today
because `dns_urls` is empty, but all three fail the moment update domains are
added back.

- [ ] **C++ test:** `check_updates` against a stub resolver serving a Wownero
      record.

**Rust side:** `--check-updates` is refused as not implemented.

---

## 26. `tx_pool.cpp`: `prune` can leave the pool and its database out of step

**Severity:** latent (needs a database error)

```cpp
LockedTXN lock(m_blockchain.get_db());
while (...) { try {
    if (!parse_and_validate_tx_prefix_from_blob(txblob, tx)) { MERROR(...); return; }
    m_blockchain.remove_txpool_tx(txid);
    reduce_txpool_weight(meta.weight);
    remove_transaction_keyimages(tx, txid);
    ...
  } catch (const std::exception &e) { MERROR(...); return; } }
lock.commit();
```

A `return` from the middle of the loop skips `commit()`, so `~LockedTXN`
aborts the batch and puts back the transactions already pruned, whose weight
and key images have already left memory. Those transactions are in the
database but no longer guard their key images, and at the next start
`insert_key_images` can find two transactions for one key image and refuse to
start. `LockedTXN::commit()` swallowing a `batch_stop` failure after memory
has changed has the same effect. `break` instead of `return` would commit what
was done.

- [ ] **C++ test:** make `get_txpool_tx_blob` throw on the second transaction
      `prune` visits and compare the pool's key images with its database.

**Rust side:** not reproduced: the pool lives in memory and is written only by
`TxPool::save`, and every eviction goes through `TxPool::remove`. Eviction
used to take `kept_by_block` transactions too, which `prune` skips; it no
longer does (`eviction_frees_key_images_and_spares_kept_by_block`).

---

## 27. `db_lmdb.cpp`: a failed `do_resize` leaves new transactions blocked

**Severity:** latent

`do_resize` calls `mdb_txn_safe::prevent_new_txns()` first, and the
`throw0`s on `m_write_txn != nullptr` or a failed `mdb_env_set_mapsize` leave
before `allow_new_txns()`. Every later `mdb_txn_safe` then spins on
`creation_gate`: the node hangs at full CPU instead of reporting the error.
Separate from §3.

- [ ] **C++ test:** make `mdb_env_set_mapsize` fail inside `do_resize` and
      check that a read transaction can still be opened afterwards.

**Rust side:** not reproduced: `raw::Env::resize` runs inside the gate's
`exclusive` closure, and the gate is released whatever
`mdb_env_set_mapsize` returns: an error comes back as the closure's value.

---

## Not findings

Recorded so they are not re-investigated:

- **The two-step reward division is not a precision trick.**
  `floor(floor(x/m)/m) == floor(x/m²)` for non-negative integers, so the two
  `div128_64` calls lose nothing. It avoids a `u64` overflow in `m * m`, which is
  a real reason, just not the one usually given. `docs/spec-deltas.md` §11.
- **`get_ideal_version` skipping index 0** is deliberate and documented
  upstream, not an oversight.
- **`compare_hash32` comparing u32 words from the top down** is intentional and
  is part of the file format.
