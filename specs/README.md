# Wownero Rust Suite — Specification

This directory is a complete, implementation-ready specification for a **Rust
reimplementation of the Wownero coin suite**: consensus protocol, daemon, and
wallet (CLI + RPC service).

The reference implementation is the Wownero C++ tree (version `0.11.4.0`
"Kunty Karen", a fork of Monero). Every consensus-relevant statement in these
documents was extracted from that tree, and each document cites the C++ file and
symbol it was derived from.

## Before you start

These documents cite paths like `src/cryptonote_core/blockchain.cpp`. Those refer
to the **C++ reference tree, not to this repository.**

This spec was written against the reference tree at commit **`9f4f22c72`**
(version `0.11.4.0`, "Kunty Karen"). Clone it and check that commit out before
following any citation — line numbers move:

```sh
git clone https://codeberg.org/wownero/wownero
git -C wownero checkout 9f4f22c72
```

Point `WOW_REF` at wherever you put it. Every command below uses it, so nothing
here depends on where your checkout lives:

```sh
WOW_REF="$PWD/wownero"
grep -n "next_difficulty_v5" "$WOW_REF/src/cryptonote_basic/difficulty.cpp"
```

One thing is **not** checked out there: the RandomWOW submodule
(`external/randomwow` is empty). Populate it before touching PoW —

```sh
git -C "$WOW_REF" submodule update --init external/randomwow
```

— or fetch the pinned config directly:

```sh
curl -sL https://codeberg.org/wownero/RandomWOW/raw/commit/27b099b6dd6fef6e17f58c6dfe00009e9c5df587/src/configuration.h
```

If the spec is ever moved to a machine without that checkout, clone it instead:

```sh
git clone https://codeberg.org/wownero/wownero.git reference/wownero
git -C reference/wownero checkout 9f4f22c72
git -C reference/wownero submodule update --init external/randomwow
```

You need the reference tree for three reasons:

1. **Three algorithm-level gaps.** This spec is complete as a *consensus*
   specification and deliberately incomplete as a *cryptography* one. For these,
   the C++ is the spec and this document only gives you the wire format, the
   domain separators and the conventions:
   - **CLSAG** prove/verify — `src/ringct/rctSigs.cpp` (`CLSAG_Gen`, `CLSAG_Ver`).
     Needed for M2.
   - **Bulletproofs+** prove/verify — `src/ringct/bulletproofs_plus.cc`. The
     inner-product argument, generator derivation and transcript are not written
     out here; the `C` vs `C/8` commitment conventions in
     [02 §4.4](02-crypto.md) are, and those are the part people get wrong.
     Needed for M2.
   - **CryptoNight** v0/v1/v2/v4 — `src/crypto/slow-hash.c`. v0 is needed to
     decrypt existing wallet files; v1/v2/v4 only for from-genesis PoW
     verification of pre-HF-13 blocks.

   Also `ge_fromfe_frombytes_vartime` in `src/crypto/crypto-ops.c`, which
   `hash_to_ec` depends on — small, but not a standard hash-to-curve.

2. **Test vectors.** `tests/crypto/tests.txt` (**5,545 vectors**) covers the
   primitives and is the cheapest possible validation of `wow-crypto`. Also
   reusable: `tests/difficulty/`, `tests/block_weight/`, `tests/hash/`, the fuzz
   corpora in `tests/fuzz/`, and the RPC-driven suites in
   `tests/functional_tests/`. See [15](15-testing-and-conformance.md).

3. **Differential testing.** A built and synced C++ node is the oracle for every
   acceptance gate. Because the storage schema is shared
   ([10](10-storage-lmdb.md)), you can also diff its `data.mdb` directly, which is
   far faster than comparing over RPC — [15 §1.1](15-testing-and-conformance.md).

### First task

Milestone **M1** ([00 §6](00-overview.md#6-milestones)) is gap-free and
independently testable — start there, not at the daemon:

```
Read specs/ in full (17 documents, start with README.md). We're building the
Rust Wownero suite it specifies.

The C++ reference implementation is a clone of
https://codeberg.org/wownero/wownero checked out at 9f4f22c72; put its path in
$WOW_REF. The spec cites files in that tree, and it is the normative source for
the three algorithm gaps listed in specs/README.md "Before you start": CLSAG,
Bulletproofs+, CryptoNight.

Begin milestone M1 per specs/00-overview.md §6: scaffold the workspace, then
implement wow-crypto (hashing, ed25519 ops, key derivation, view tags, base58,
mnemonics), wow-serialize (binary archive + epee portable storage), and
wow-types. Gate: specs/15-testing-and-conformance.md §2 -- port
tests/crypto/tests.txt from the reference tree first, it is the cheapest
validation of wow-crypto.

Consensus rules are normative. Reproduce the quirks in specs/06 §9 exactly,
including the ones that look like bugs.
```

## The one hard requirement

> **The Rust node must join the existing Wownero mainnet and reach the same
> chain tip as the C++ node, byte-for-byte, without a fork.**

Everything else — the crate layout, the async runtime, the CLI ergonomics — is an
implementation choice. Consensus is not.
Where this specification describes behaviour that looks like a bug (and several
places do; see [quirks](06-consensus-rules.md#9-inherited-quirks-that-are-now-consensus)),
**reproduce the bug**. A "cleaner" implementation is a chain split.

## Reading order

| # | Document | What it covers |
|---|----------|----------------|
| 00 | [Overview & architecture](00-overview.md) | Scope, deliverables, crate layout, milestones |
| 01 | [Constants & network parameters](01-constants.md) | Every consensus constant, hard-fork table, checkpoints, seed nodes |
| 02 | [Cryptography](02-crypto.md) | Keccak, ed25519, key derivation, view tags, CLSAG, Bulletproofs(+), base58, mnemonics |
| 03 | [Proof of work](03-pow.md) | RandomWOW parameters, seed-hash epochs, CryptoNight history, difficulty check |
| 04 | [Serialization](04-serialization.md) | Binary archive (consensus), epee portable storage (P2P), JSON conventions |
| 05 | [Blocks & transactions](05-blocks-and-transactions.md) | Wire structures and all hash definitions |
| 06 | [Consensus rules](06-consensus-rules.md) | Block/tx validation by hard fork, emission, weights, fees, miner signing |
| 07 | [Difficulty](07-difficulty.md) | All six difficulty algorithms, selection, hard-coded overrides |
| 08 | [P2P network](08-p2p.md) | Levin, command set, handshake, sync, Dandelion++, peer management |
| 09 | [Daemon](09-daemon.md) | Process architecture, mempool, reorg, miner, CLI, config |
| 10 | [Storage (LMDB)](10-storage-lmdb.md) | The exact `data.mdb` schema: tables, flags, comparators, record layouts |
| 11 | [Daemon RPC](11-daemon-rpc.md) | Every endpoint, restricted mode, binary endpoints |
| 12 | [Wallet core](12-wallet-core.md) | Keys, scanning, selection, tx construction, file formats |
| 13 | [Wallet CLI](13-wallet-cli.md) | `wownero-wallet-cli` command surface |
| 14 | [Wallet RPC](14-wallet-rpc.md) | `wownero-wallet-rpc` method surface |
| 15 | [Testing & conformance](15-testing-and-conformance.md) | Test vectors, differential testing, acceptance gates |

## Conformance language

- **MUST** / **MUST NOT** — consensus-critical or wire-critical. Deviation
  causes a chain split, a failed handshake, or an unparseable message.
- **SHOULD** — relay/policy behaviour. Deviation degrades interoperability or
  privacy but does not split the chain.
- **MAY** — free implementation choice.

Each document ends with a **Conformance checklist** enumerating its MUSTs.

## Status of the source material

- Reference tree: Wownero `master` at commit `9f4f22c72`, version `0.11.4.0`.
- Mainnet hard forks defined up to **v20** (height 514,000). **v21** exists in
  the testnet table only (height 70) and introduces one new RCT type; it is
  specified here so the Rust node is ready, but it is not yet mainnet consensus.
- RandomWOW is pinned to `codeberg.org/wownero/RandomWOW` branch `1.2.1-wow`,
  commit `27b099b6dd6fef6e17f58c6dfe00009e9c5df587`. Its parameters are
  reproduced in [03-pow.md](03-pow.md) and were read from that exact commit.
