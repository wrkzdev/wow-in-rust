# 02 — Cryptography

Source of truth: `src/crypto/*`, `src/ringct/*`, `src/device/device_default.cpp`,
`src/common/base58.cpp`, `src/mnemonics/*`.

Everything in this document is consensus-critical. A one-bit difference in any
primitive produces a node that cannot validate the chain.

## 1. Hashing

### 1.1 `cn_fast_hash` = Keccak-256 (original padding)

The pervasive hash. **This is Keccak-f[1600] with rate 1088 and the original
Keccak padding (`0x01` domain byte), NOT SHA3-256 (`0x06`).** Output 32 bytes.

```rust
pub fn cn_fast_hash(data: &[u8]) -> Hash256 {
    let mut k = tiny_keccak::Keccak::v256();   // v256 == original padding
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}
```

Test vector: `cn_fast_hash(b"")` =
`c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.
If you get `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`
you have SHA3, which is wrong.

`get_blob_hash(blob)` and `get_object_hash(obj)` are `cn_fast_hash` over the
blob / over the binary serialization of the object.

### 1.2 `hash_to_scalar`

```
hash_to_scalar(data) = sc_reduce32(cn_fast_hash(data))
```
i.e. keccak then reduce the 32-byte little-endian value mod
`l = 2^252 + 27742317777372353535851937790883648493`.

### 1.3 `hash_to_ec` / `hash_to_p3`

`cn_fast_hash` then Monero's `ge_fromfe_frombytes_vartime` (the Shallue–van de
Woestijne-ish map used by CryptoNote), then multiply by 8. Used for key images
and CLSAG. This map is **not** any standard hash-to-curve; port
`ge_fromfe_frombytes_vartime` from `src/crypto/crypto-ops.c` literally.

### 1.4 `tree_hash` — the transaction Merkle root

From `src/crypto/tree-hash.c`. Not a standard binary Merkle tree.

```rust
fn tree_hash_cnt(count: usize) -> usize {   // 1 << floor(log2(count)), for count >= 3
    let mut pow = 2;
    while pow < count { pow <<= 1; }
    pow >> 1
}

fn tree_hash(hashes: &[Hash256]) -> Hash256 {
    match hashes.len() {
        0 => unreachable!(),
        1 => hashes[0],
        2 => cn_fast_hash(&concat(hashes[0], hashes[1])),
        count => {
            let cnt = tree_hash_cnt(count);
            // ints has `cnt` slots, zero-initialised
            let mut ints = vec![[0u8; 32]; cnt];
            // first (2*cnt - count) hashes are copied verbatim
            let k = 2 * cnt - count;
            ints[..k].copy_from_slice(&hashes[..k]);
            // the remaining are paired and hashed
            let mut i = k;
            for j in k..cnt {
                ints[j] = cn_fast_hash(&concat(hashes[i], hashes[i + 1]));
                i += 2;
            }
            debug_assert_eq!(i, count);
            // then standard pairwise reduction
            let mut cnt = cnt;
            while cnt > 2 {
                cnt >>= 1;
                for j in 0..cnt { ints[j] = cn_fast_hash(&concat(ints[2*j], ints[2*j + 1])); }
            }
            cn_fast_hash(&concat(ints[0], ints[1]))
        }
    }
}
```

`get_tx_tree_hash(block)` builds the input list as
`[miner_tx_hash] ++ block.tx_hashes` and calls `tree_hash` on it.

`count <= 0x10000000` (2^28) is asserted upstream; reject larger.

## 2. ed25519 / Curve25519 conventions

Monero/Wownero uses the ed25519 group with its own encoding conventions. Key
points where a standard ed25519 library will not match:

1. **Point decoding is permissive.** `ge_frombytes_vartime` accepts any 32-byte
   value that decodes to a curve point, including **small-order and non-canonical
   points**. It does **not** reject non-canonical `y` encodings the way a strict
   ed25519 library does. With `curve25519-dalek` use
   `CompressedEdwardsY::decompose`/`decompress` and do **not** add torsion or
   canonicality checks unless the C++ does.
2. **`sc_check`** requires the scalar to be canonical (`< l`). `sc_reduce32`
   reduces in place.
3. **`sc_isnonzero`** is a constant-time nonzero test on 32 bytes.
4. `G` is the standard ed25519 basepoint. `H` is the second generator:
   `H = 8 * to_point(cn_fast_hash(G))`, hard-coded in `rctOps.cpp` as
   `8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94`.
5. `INV_EIGHT` = the scalar `1/8 mod l` =
   `0x06...` — hard-coded in `rctTypes.h`; port the literal.
6. `scalarmult8(P)` = `8 * P` (used to clear torsion in Bulletproofs+
   commitments).

### 2.1 Keys

| Type | Size | Notes |
|---|---|---|
| `secret_key` / `ec_scalar` | 32 | little-endian scalar `< l` |
| `public_key` / `ec_point` | 32 | compressed ed25519 point |
| `key_derivation` | 32 | compressed point (`8 * a * R`) |
| `key_image` | 32 | compressed point |
| `signature` | 64 | `(c, r)`, both scalars |
| `hash` | 32 | |
| `hash8` | 8 | encrypted payment ID |
| `view_tag` | **1** | |

## 3. Core key operations

### 3.1 Key pair

```
secret_key_to_public_key(a) -> A = a*G
generate_keys() -> (a = random_scalar(), A = a*G)
```

`random_scalar()` = `sc_reduce32(random 32 bytes)`, rejecting zero.

### 3.2 Deterministic view key

Wownero (like Monero) derives the private view key from the private spend key:

```
b  = private spend key
a  = sc_reduce32(keccak256(b))      # private view key
```

This exact derivation is used by the daemon miner when given `--spendkey`
(`src/cryptonote_basic/miner.cpp: miner::init`) and by the wallet for
deterministic wallets.

### 3.3 `generate_key_derivation`

```
generate_key_derivation(P, s) -> D = 8 * (s * P)
```
Fails if `P` does not decode. The multiply-by-8 clears the cofactor.

### 3.4 `derivation_to_scalar`

```
derivation_to_scalar(D, output_index) = hash_to_scalar(D || varint(output_index))
```
The buffer is `32 + varint_len` bytes — **exactly** the written varint length, no
padding, even though the C++ struct reserves 10 bytes.

### 3.5 Output key derivation

```
derive_public_key(D, i, B)  -> B + derivation_to_scalar(D, i) * G
derive_secret_key(D, i, b)  -> b + derivation_to_scalar(D, i)        (mod l)
derive_subaddress_public_key(out_key, D, i) -> out_key - derivation_to_scalar(D,i)*G
```

### 3.6 Key image

```
generate_key_image(P, x) -> x * hash_to_ec(P)
```
where `P` is the one-time output public key and `x` the corresponding one-time
secret key. `hash_to_ec` is §1.3.

### 3.7 View tags (HF 20+)

From `crypto_ops::derive_view_tag`:

```
buf = "view_tag"                 # 8 bytes, NO trailing NUL
    || derivation                # 32 bytes
    || varint(output_index)      # exactly the written bytes
view_tag = cn_fast_hash(buf)[0]  # FIRST byte only
```

### 3.8 Subaddresses

From `device_default::get_subaddress*`:

```
m = hash_to_scalar( "SubAddr\0"              # 8 bytes, NUL INCLUDED
                  || a                        # 32-byte private view key
                  || u32_le(major)
                  || u32_le(minor) )
D = B + m*G                      # subaddress spend public key
C = a * D                        # subaddress view public key
subaddress = (C as view, D as spend)
```

`index == (0,0)` returns the main address unchanged — do **not** run the
derivation for it.

### 3.9 Schnorr signature (`generate_signature` / `check_signature`)

Used for message signing, tx proofs, reserve proofs, **and the HF 18 block
header miner signature**. It is *not* standard ed25519.

```
struct s_comm { h: [u8;32], key: [u8;32], comm: [u8;32] }   // 96 bytes, packed

sign(m, A, a):
    loop {
        k = random_scalar()
        comm = k*G
        c = hash_to_scalar(s_comm{ h: m, key: A, comm })
        if c == 0 { continue }
        r = k - c*a           (mod l)     // sc_mulsub(r, c, a, k)
        if r == 0 { continue }
        return (c, r)
    }

verify(m, A, (c, r)):
    if A does not decode -> false
    if !sc_check(c) || !sc_check(r) || c == 0 -> false
    comm = c*A + r*G                       // ge_double_scalarmult_base_vartime
    if comm == encode(identity) -> false    // the literal 32-byte {1,0,...,0}
    c2 = hash_to_scalar(s_comm{ h: m, key: A, comm })
    return c2 == c
```

Note the explicit rejection of the identity commitment and the `c != 0` check;
both are required.

## 4. RingCT

### 4.1 Types

```rust
#[repr(u8)]
pub enum RctType {
    Null = 0,
    Full = 1,
    Simple = 2,
    FullBulletproof = 3,
    SimpleBulletproof = 4,
    Bulletproof = 5,
    Bulletproof2 = 6,
    Clsag = 7,
    BulletproofPlus = 8,
    BulletproofPlusFullCommit = 9,   // Wownero-only, HF 21 (testnet)
}
```

Which types are legal at which hard fork: [06 §5.6](06-consensus-rules.md).
On mainnet today (HF 20) the only legal non-coinbase type is
**`BulletproofPlus` (8)**.

### 4.2 The `pre_mlsag_hash` (message being signed)

From `rctSigs.cpp: get_pre_mlsag_hash`. Three hashes are concatenated and hashed:

```
hashes[0] = rv.message                      # = tx prefix hash
hashes[1] = cn_fast_hash( serialize(rctSigBase) )   # the "base" blob
hashes[2] = cn_fast_hash( kv )              # all proof elements, concatenated

pre_mlsag_hash = cn_fast_hash(hashes[0] || hashes[1] || hashes[2])
```

For `BulletproofPlus` / `BulletproofPlusFullCommit`, `kv` is, for each proof in
`bulletproofs_plus`, in order:

```
A, A1, B, r1, s1, d1, L[0..], R[0..]
```

`V` is **not** included — it is reconstructed from `outPk.mask`, which is already
covered by `hashes[1]`.

For `Bulletproof`/`Bulletproof2`/`Clsag`/`SimpleBulletproof`/`FullBulletproof`,
`kv` is per proof: `A, S, T1, T2, taux, mu, L[0..], R[0..], a, b, t`.

For Borromean types, `kv` is per range sig: `asig.s0[0..64]`, `asig.s1[0..64]`,
`asig.ee`, `Ci[0..64]`.

### 4.3 CLSAG

Domain separators (all without trailing NUL):
`"CLSAG_round"`, `"CLSAG_agg_0"`, `"CLSAG_agg_1"`.

```
Given ring of n members, each (P_i, C_i), the pseudo-output commitment C_offset,
message m (= pre_mlsag_hash), key image I, auxiliary image D:

D_8   = D * INV_EIGHT              # serialized form
mu_P  = hash_to_scalar("CLSAG_agg_0" || P_0..P_{n-1} || C_0..C_{n-1}
                       || I || D_8 || C_offset)
mu_C  = hash_to_scalar("CLSAG_agg_1" || <same tail>)

c_{i+1} = hash_to_scalar("CLSAG_round" || P_0..P_{n-1} || C_0..C_{n-1}
                         || C_offset || m || L_i || R_i)
  where, for the non-signing indices,
    L_i = s_i*G + c_i*mu_P*P_i + c_i*mu_C*(C_i - C_offset)
    R_i = s_i*Hp(P_i) + c_i*mu_P*I + c_i*mu_C*D
```

Verification succeeds iff the recomputed `c_0` equals the stored `c1`.
`I` is not serialized (it comes from the input's `k_image`); `D` is serialized;
`s` has `ring_size` entries.

Port `CLSAG_Gen`/`CLSAG_Ver` from `src/ringct/rctSigs.cpp` element by element and
validate against the vectors in
[15-testing-and-conformance.md](15-testing-and-conformance.md).

### 4.4 Bulletproofs+

`src/ringct/bulletproofs_plus.cc`. Domain separators:
`"bulletproof_plus"` (generator derivation) and
`"bulletproof_plus_transcript"` (transcript initialisation).

Proof structure on the wire:

```
BulletproofPlus { A, A1, B, r1, s1, d1, L: Vec<Key>, R: Vec<Key> }   # V is not serialized
```

`n_bulletproof_plus_max_amounts(proof) = 1 << (proof.L.len() - 6)`.
`L.len() >= 6` is required. `BULLETPROOF_PLUS_MAX_OUTPUTS = 16`.

**The commitment convention differs by RCT type** — this is the entire content of
`BulletproofPlusFullCommit`:

| | `BulletproofPlus` (8) | `BulletproofPlusFullCommit` (9) |
|---|---|---|
| `outPk[i].mask` holds | `C_i / 8` | `C_i` (the full commitment) |
| `V[i]` for verification | `outPk[i].mask` as-is | `outPk[i].mask * INV_EIGHT` |
| Commitment-sum check uses | `8 * outPk[i].mask` | `outPk[i].mask` |
| Amount decode compares against | `8 * outPk[i].mask` | `outPk[i].mask` |

(`expand_transaction_1` in `cryptonote_format_utils.cpp`, plus the
`is_rct_bp_plus_legacy` branches in `rctSigs.cpp`.)

For legacy `Bulletproof`/`Bulletproof2`/`Clsag`, `outPk[i].mask` holds the full
`C_i` and `V[i] = outPk[i].mask * INV_EIGHT`.

### 4.5 Amount encoding (`ecdhEncode`/`ecdhDecode`)

For `Bulletproof2` and later (i.e. types 6, 7, 8, 9) the **short form** is used:

```
shared_sec    = derivation_to_scalar(derivation, output_index)   # the amount key
mask          = hash_to_scalar( "commitment_mask"     # 15 bytes, no NUL
                              || shared_sec )          # 32 bytes -> 47 total
amount_pad    = cn_fast_hash( "amount"                 # 6 bytes, no NUL
                            || shared_sec )            # 32 bytes -> 38 total
amount_8bytes = amount_le_u64 XOR amount_pad[0..8]
```

Only 8 bytes of `ecdhInfo[i].amount` are serialized and the blinding factor is
not serialized at all (it is recomputed as `mask` above). For types ≤ 5 the
legacy form is used instead — both 32-byte fields serialized, and

```
s1 = hash_to_scalar(shared_sec); s2 = hash_to_scalar(s1)
encode: mask += s1; amount += s2       decode: mask -= s1; amount -= s2
```

Bodies: `src/ringct/rctOps.cpp: ecdhHash, genCommitmentMask, ecdhEncode,
ecdhDecode`.

## 5. Base58 (CryptoNote block variant)

`src/common/base58.cpp`. **Not** Bitcoin base58.

- Alphabet: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
- Data is processed in **8-byte blocks**, each encoded as exactly **11
  characters**. A trailing partial block of `n` bytes encodes to
  `encoded_block_sizes[n]` characters: `[0, 2, 3, 5, 6, 7, 9, 10, 11]`.
- Each block is interpreted as a **big-endian** unsigned integer.

Address encoding (`encode_addr`):

```
body = varint(prefix) || data
checksum = cn_fast_hash(body)[0..4]
address = base58_encode(body || checksum)
```

`data` for a standard/sub address is `spend_public_key || view_public_key`
(64 bytes); for an integrated address it is
`spend_public_key || view_public_key || payment_id8` (72 bytes).

Resulting mainnet lengths: prefix 4146 is a 2-byte varint, so a standard address
is `varint(2) + 64 + 4 = 70` bytes → **97 characters**. Integrated addresses are
`2 + 72 + 4 = 78` bytes → **108 characters**.

There is also a legacy raw-hex path: if the input string length is exactly
`2 * sizeof(public_address_outer_blob)` the C++ parses it as hex. Supporting it
is optional.

## 6. Mnemonic seeds

`src/mnemonics/electrum-words.cpp`. 25 words = 24 data words + 1 checksum word.

- `seed_length = 24`; a valid seed has **25** words.
- Each word list has **1626** words.
- Encoding: for each 4 bytes of the 32-byte key, taken as a **little-endian
  u32** `x`:
  ```
  w1 = x % 1626
  w2 = (x / 1626 + w1) % 1626
  w3 = (x / 1626 / 1626 + w2) % 1626
  ```
- Decoding inverts this; the reconstructed key MUST be 32 bytes.
- Checksum: take the first `unique_prefix_length` UTF-8 characters of each of
  the 24 words, concatenate, CRC32 the result, and index
  `word_index = crc32 % 24`; the 25th word MUST equal word `word_index`
  (compared on its trimmed prefix).
- Supported languages (with their `unique_prefix_length`, read from each header):
  English (3), English-old, Chinese-simplified (1), Dutch, Esperanto, French,
  German, Italian, Japanese, Lojban, Portuguese, Russian, Spanish.

The 25-word seed encodes the **private spend key**; the view key is derived per
§3.2 for deterministic wallets.

## 7. Wallet file encryption

`src/crypto/chacha.h`, `src/wallet/wallet2.cpp`.

- Key derivation from password: `generate_chacha_key(password)` =
  `cn_slow_hash(password, variant 0, height 0)` — i.e. **CryptoNight v0**, not a
  modern KDF. With `kdf_rounds > 1` the result is re-hashed with
  `cn_slow_hash(..., prehashed=0)` `kdf_rounds - 1` more times.
- Cipher: ChaCha20 (8-byte IV prepended to the ciphertext), 20 rounds.
- Keys-file and cache-file domain bytes: `HASH_KEY_WALLET = 0x8c`,
  `HASH_KEY_WALLET_CACHE = 0x8d` (appended to the key material before hashing).

This means a Rust wallet **must implement CryptoNight v0** even though the chain
no longer uses it, purely to open existing wallet files. `cn_slow_hash` variant 0
needs: AES round keys derived from keccak, a 2 MiB scratchpad, 524,288 iterations
of the memory-hard loop, then one of Blake-256 / Groestl-256 / JH-256 / Skein-256
selected by `state[0] & 3`. Port `src/crypto/slow-hash.c`.

## 8. Encrypted payment IDs

```
derivation = 8 * r * A                      # tx secret key * recipient view pubkey
key = hash_to_scalar( derivation || 0x8d )  # HASH_KEY_ENCRYPTED_PAYMENT_ID
encrypted_pid[i] = pid[i] XOR key[i]        # for i in 0..8
```

## 9. Conformance checklist

- [ ] `cn_fast_hash(b"")` = `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.
- [ ] `tree_hash` reproduces the `tree_hash_cnt` copy-then-pair structure exactly,
      including the zero-initialised `ints` buffer.
- [ ] Point decoding MUST be as permissive as `ge_frombytes_vartime`.
- [ ] `derivation_to_scalar` hashes exactly `32 + varint_len` bytes.
- [ ] `"SubAddr"` includes its trailing NUL; `"view_tag"` does not.
- [ ] `view_tag` is the **first** byte of the hash, 1 byte total.
- [ ] The Schnorr verifier rejects `c == 0`, non-canonical scalars, and an
      identity commitment.
- [ ] Bulletproofs+ commitment handling differs between RCT type 8 and type 9
      exactly as tabulated in §4.4.
- [ ] `ecdhInfo.amount` is truncated to 8 bytes and the mask omitted for RCT
      types ≥ 6.
- [ ] Base58 uses 8-byte blocks → 11 chars, big-endian, with the
      `[0,2,3,5,6,7,9,10,11]` partial-block table.
- [ ] CryptoNight v0 is implemented for wallet-file decryption.
