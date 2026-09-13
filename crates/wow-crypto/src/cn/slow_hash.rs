//! `cn_slow_hash` variant 0 — CryptoNight.
//!
//! `src/crypto/slow-hash.c`, the portable (`#else`) path. Variants 0 and 1.
//!
//! # What each variant is for
//!
//! It is for **wallet files**: `generate_chacha_key(password)` is
//! `cn_slow_hash(password, variant 0)` (`specs/02` §7). Without this a Rust
//! wallet cannot open a `.keys` file written by the C++ wallet, whatever else
//! it implements.
//!
//! Variant **1** is the chain's. Wownero's genesis block is already major
//! version 7, so `specs/03` §2 maps versions 7–8 to variant 1, 9–10 to variant
//! 2, and 11–12 to variant 4, with RandomWOW from 13. Variant 1 is what a
//! regtest chain built from genesis mines with, and the first stretch of
//! mainnet. Variants 2 and 4 are still missing; a node syncing from a
//! checkpoint needs none of them.
//!
//! # What variant 1 adds
//!
//! Three small changes, and not one of them is a different shape — which is
//! why they are easy to get subtly wrong and hard to notice:
//!
//! * a **tweak** derived from the input at offset 35 and the last word of the
//!   Keccak state, which is why variant 1 refuses an input under 43 bytes,
//! * a table-driven patch of byte 11 of the block written in the first half,
//!   and
//! * the tweak xored into the high half of the block written in the second
//!   half — into the *stored* value only, not into the running `a`.
//!
//! # Shape
//!
//! 1. Keccak-1600 over the input, keeping the whole 200-byte state.
//! 2. Fill a 2 MiB scratchpad by running ten AES rounds over a 128-byte block
//!    taken from that state, 16,384 times.
//! 3. 524,288 iterations of a read-modify-write loop over the scratchpad, each
//!    doing one AES round and one 64×64→128 multiply.
//! 4. Fold the scratchpad back into the 128-byte block, permute the Keccak
//!    state once more, and finish with whichever of Blake-256, Grøstl-256,
//!    JH-256 or Skein-256 `state[0] & 3` selects.
//!
//! Step 3 is the memory-hard part and is where a mistake shows up as a wrong
//! digest with no other symptom, so the reference vectors in
//! `tests/corpus/cryptonight/tests-slow.txt` are the check that matters.

use super::aes;
use crate::keccak;

/// `MEMORY` — the scratchpad, 2 MiB.
const MEMORY: usize = 1 << 21;
/// `ITER`. The loop runs `ITER / 2` times, each pass touching two blocks.
const ITER: usize = 1 << 20;
/// `INIT_SIZE_BLK` — AES blocks per scratchpad-fill step.
const INIT_SIZE_BLK: usize = 8;
/// `INIT_SIZE_BYTE`.
const INIT_SIZE_BYTE: usize = INIT_SIZE_BLK * aes::BLOCK;
/// Scratchpad blocks, and so the index mask.
const BLOCKS: usize = MEMORY / aes::BLOCK;

/// `e2i`: the low 64 bits of `a`, as a block index.
///
/// The division by the block size before masking is not the same as masking
/// first — it discards the low four bits rather than using them.
#[inline]
fn e2i(a: &[u8; aes::BLOCK]) -> usize {
    let lo = u64::from_le_bytes(a[..8].try_into().expect("8 bytes"));
    ((lo / aes::BLOCK as u64) & (BLOCKS as u64 - 1)) as usize
}

/// `mul`: the low halves of `a` and `b` multiplied to 128 bits, stored **high
/// word first**. The order is not a detail; swapping it still produces a
/// plausible hash.
#[inline]
fn mul(a: &[u8; aes::BLOCK], b: &[u8; aes::BLOCK]) -> [u8; aes::BLOCK] {
    let x = u64::from_le_bytes(a[..8].try_into().expect("8 bytes")) as u128;
    let y = u64::from_le_bytes(b[..8].try_into().expect("8 bytes")) as u128;
    let p = x * y;
    let mut out = [0u8; aes::BLOCK];
    out[..8].copy_from_slice(&((p >> 64) as u64).to_le_bytes());
    out[8..].copy_from_slice(&(p as u64).to_le_bytes());
    out
}

/// `sum_half_blocks`: two independent wrapping 64-bit additions, not a 128-bit
/// one — there is no carry between the halves.
#[inline]
fn sum_half_blocks(a: &mut [u8; aes::BLOCK], b: &[u8; aes::BLOCK]) {
    for (ha, hb) in a.chunks_exact_mut(8).zip(b.chunks_exact(8)) {
        let x = u64::from_le_bytes(ha.try_into().expect("8 bytes"));
        let y = u64::from_le_bytes(hb.try_into().expect("8 bytes"));
        ha.copy_from_slice(&x.wrapping_add(y).to_le_bytes());
    }
}

#[inline]
fn xor_blocks(a: &mut [u8; aes::BLOCK], b: &[u8; aes::BLOCK]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= y;
    }
}

#[inline]
fn block_at(pad: &[u8], j: usize) -> [u8; aes::BLOCK] {
    pad[j * aes::BLOCK..(j + 1) * aes::BLOCK]
        .try_into()
        .expect("16 bytes")
}

#[inline]
fn put_block(pad: &mut [u8], j: usize, v: &[u8; aes::BLOCK]) {
    pad[j * aes::BLOCK..(j + 1) * aes::BLOCK].copy_from_slice(v);
}

/// Which variant to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// The wallet's, for the keys-file KDF (`specs/02` §7).
    V0,
    /// The chain's at major versions 7 and 8 (`specs/03` §2).
    V1,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CnError {
    /// `VARIANT1_INIT64` reads eight bytes at offset 35, so there have to be
    /// 43. The reference calls `_exit(1)` here; returning an error is the same
    /// refusal without taking the process with it.
    #[error("CryptoNight variant 1 needs at least 43 bytes of input, got {0}")]
    TooShortForV1(usize),
}

/// CryptoNight variant 0 of `input`.
///
/// The 2 MiB scratchpad is heap-allocated; it does not fit on a thread stack,
/// and the C only gets away with a stack array because it compiles with a
/// large one.
pub fn cn_slow_hash(input: &[u8]) -> [u8; 32] {
    hash(input, Variant::V0).expect("variant 0 has no length requirement")
}

/// CryptoNight variant 1 of `input`.
pub fn cn_slow_hash_v1(input: &[u8]) -> Result<[u8; 32], CnError> {
    hash(input, Variant::V1)
}

/// The body, for either variant.
pub fn hash(input: &[u8], variant: Variant) -> Result<[u8; 32], CnError> {
    if variant == Variant::V1 && input.len() < 43 {
        return Err(CnError::TooShortForV1(input.len()));
    }
    let mut state = keccak::keccak1600(input);

    // `VARIANT1_INIT64`: the last word of the Keccak state, xored with eight
    // bytes of the *input* at offset 35 -- which is the nonce's position in a
    // block hashing blob, and the reason for the length requirement above.
    let tweak = match variant {
        Variant::V0 => 0u64,
        Variant::V1 => {
            let last = u64::from_le_bytes(state[192..200].try_into().expect("8 bytes"));
            let nonce = u64::from_le_bytes(input[35..43].try_into().expect("8 bytes"));
            last ^ nonce
        }
    };

    // `state.init` is the 128 bytes at offset 64; `state.k` the 64 before it.
    let mut text = [0u8; INIT_SIZE_BYTE];
    text.copy_from_slice(&state[64..64 + INIT_SIZE_BYTE]);

    // Pass one: expand the scratchpad from the first half of `state.k`.
    let key: [u8; aes::KEY] = state[..aes::KEY].try_into().expect("32 bytes");
    let round_keys = aes::expand_key(&key);

    let mut pad = vec![0u8; MEMORY];
    for i in 0..MEMORY / INIT_SIZE_BYTE {
        for j in 0..INIT_SIZE_BLK {
            let block: &mut [u8; aes::BLOCK] = (&mut text[j * aes::BLOCK..(j + 1) * aes::BLOCK])
                .try_into()
                .expect("16 bytes");
            aes::pseudo_round(block, &round_keys);
        }
        pad[i * INIT_SIZE_BYTE..(i + 1) * INIT_SIZE_BYTE].copy_from_slice(&text);
    }

    // The two working blocks, from the four quarters of `state.k`.
    let mut a = [0u8; aes::BLOCK];
    let mut b = [0u8; aes::BLOCK];
    for i in 0..aes::BLOCK {
        a[i] = state[i] ^ state[aes::KEY + i];
        b[i] = state[aes::BLOCK + i] ^ state[aes::KEY + aes::BLOCK + i];
    }

    // Pass two: the memory-hard loop.
    for _ in 0..ITER / 2 {
        // First half: one AES round keyed by `a`, written back xored with `b`.
        let j = e2i(&a);
        let mut c1 = block_at(&pad, j);
        aes::round(&mut c1, &a);
        let mut written = c1;
        xor_blocks(&mut written, &b);
        if variant == Variant::V1 {
            variant1_patch(&mut written);
        }
        put_block(&mut pad, j, &written);

        // Second half: multiply, add, and write back. The sequence below is
        // the reference's swap-heavy one unrolled into its meaning:
        //   sp[j2] = a + hi:lo(c1 * sp[j2]);  a = sp[j2] ^ that;  b = c1
        let j2 = e2i(&c1);
        let c2 = block_at(&pad, j2);
        let d = mul(&c1, &c2);

        let mut sum = a;
        sum_half_blocks(&mut sum, &d);

        // The new `a` is taken *before* the tweak, so `VARIANT1_2` changes what
        // is stored and not what the loop carries forward.
        a = c2;
        xor_blocks(&mut a, &sum);

        if variant == Variant::V1 {
            let x = u64::from_le_bytes(sum[8..].try_into().expect("8 bytes"));
            sum[8..].copy_from_slice(&(x ^ tweak).to_le_bytes());
        }
        put_block(&mut pad, j2, &sum);

        b = c1;
    }

    // Pass three: fold the scratchpad back in, keyed by the second half of
    // `state.k`.
    text.copy_from_slice(&state[64..64 + INIT_SIZE_BYTE]);
    let key: [u8; aes::KEY] = state[aes::KEY..2 * aes::KEY].try_into().expect("32 bytes");
    let round_keys = aes::expand_key(&key);

    for i in 0..MEMORY / INIT_SIZE_BYTE {
        for j in 0..INIT_SIZE_BLK {
            let off = i * INIT_SIZE_BYTE + j * aes::BLOCK;
            let block: &mut [u8; aes::BLOCK] = (&mut text[j * aes::BLOCK..(j + 1) * aes::BLOCK])
                .try_into()
                .expect("16 bytes");
            for (x, y) in block.iter_mut().zip(pad[off..off + aes::BLOCK].iter()) {
                *x ^= y;
            }
            aes::pseudo_round(block, &round_keys);
        }
    }
    state[64..64 + INIT_SIZE_BYTE].copy_from_slice(&text);

    // One more permutation, then the selected final hash over all 200 bytes.
    let mut words = [0u64; 25];
    for (w, chunk) in words.iter_mut().zip(state.chunks_exact(8)) {
        *w = u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
    }
    keccak::keccakf(&mut words);
    for (w, chunk) in words.iter().zip(state.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&w.to_le_bytes());
    }

    Ok(match state[0] & 3 {
        0 => super::blake256(&state),
        1 => super::groestl256(&state),
        2 => super::jh256(&state),
        _ => super::skein256(&state),
    })
}

/// `VARIANT1_1`: patch byte 11 of a block on its way into the scratchpad.
///
/// The table is four two-bit values packed into a `u32`; the index is built
/// from bits 4, 3 and 0 of the byte itself. Written out, it maps the top nibble
/// of the byte's low bits to one of `0x00`, `0x10`, `0x20`, `0x30`.
#[inline]
fn variant1_patch(block: &mut [u8; aes::BLOCK]) {
    const TABLE: u32 = 0x0007_5310;
    let tmp = block[11];
    let index = (((tmp >> 3) & 6) | (tmp & 1)) << 1;
    block[11] = tmp ^ ((TABLE >> index) as u8 & 0x30);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `e2i` drops the low four bits rather than masking them in.
    #[test]
    fn the_scratchpad_index() {
        let mut a = [0u8; aes::BLOCK];
        a[..8].copy_from_slice(&0x1fu64.to_le_bytes());
        assert_eq!(e2i(&a), 1, "31 / 16 == 1");
        a[..8].copy_from_slice(&(MEMORY as u64).to_le_bytes());
        assert_eq!(e2i(&a), 0, "one past the end wraps to the start");
        a[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(e2i(&a) < BLOCKS);
    }

    /// The product is stored high word first.
    #[test]
    fn the_multiply_stores_high_first() {
        let mut a = [0u8; aes::BLOCK];
        let mut b = [0u8; aes::BLOCK];
        a[..8].copy_from_slice(&(1u64 << 32).to_le_bytes());
        b[..8].copy_from_slice(&(1u64 << 32).to_le_bytes());
        let d = mul(&a, &b);
        assert_eq!(
            u64::from_le_bytes(d[..8].try_into().expect("8")),
            1,
            "the high word leads"
        );
        assert_eq!(u64::from_le_bytes(d[8..].try_into().expect("8")), 0);
    }

    /// The halves add independently — no carry crosses the middle.
    #[test]
    fn the_addition_does_not_carry_across_halves() {
        let mut a = [0u8; aes::BLOCK];
        a[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        let mut b = [0u8; aes::BLOCK];
        b[..8].copy_from_slice(&1u64.to_le_bytes());
        sum_half_blocks(&mut a, &b);
        assert_eq!(
            a,
            [0u8; aes::BLOCK],
            "wraps, and the high half is untouched"
        );
    }

    /// Variant 1 refuses a short input rather than reading past the end.
    ///
    /// The reference calls `_exit(1)` here, which is a refusal with the process
    /// attached to it. 43 bytes is where the eight-byte read at offset 35 ends.
    #[test]
    fn variant_one_needs_forty_three_bytes() {
        for n in [0usize, 1, 34, 42] {
            assert_eq!(
                cn_slow_hash_v1(&vec![0u8; n]),
                Err(CnError::TooShortForV1(n)),
                "{n} bytes"
            );
        }
        assert!(cn_slow_hash_v1(&[0u8; 43]).is_ok());
    }

    /// The two variants are different functions on the same input.
    #[test]
    fn the_variants_differ() {
        let input = [7u8; 64];
        assert_ne!(
            cn_slow_hash(&input),
            cn_slow_hash_v1(&input).expect("long enough")
        );
    }

    /// The tweak comes from the input at offset 35, so a change there alters
    /// the answer even though the scratchpad seed is the same length.
    #[test]
    fn the_tweak_reads_the_nonce_position() {
        let mut a = [3u8; 64];
        let mut b = a;
        b[35] ^= 0xff;
        assert_ne!(
            cn_slow_hash_v1(&a).expect("ok"),
            cn_slow_hash_v1(&b).expect("ok")
        );
        // And a byte outside 35..43 also matters, because everything feeds the
        // Keccak state -- this is a sanity check on the test above, not a
        // separate property.
        a[50] ^= 0xff;
        assert_ne!(
            cn_slow_hash_v1(&a).expect("ok"),
            cn_slow_hash_v1(&[3u8; 64]).expect("ok")
        );
    }

    /// `VARIANT1_1` only ever sets bits 4 and 5 of byte 11, and leaves every
    /// other byte alone.
    #[test]
    fn the_variant_one_patch_touches_one_byte() {
        for v in 0u8..=255 {
            let mut block = [0xaau8; aes::BLOCK];
            block[11] = v;
            let before = block;
            variant1_patch(&mut block);

            for i in 0..aes::BLOCK {
                if i != 11 {
                    assert_eq!(block[i], before[i], "byte {i} changed for {v:#x}");
                }
            }
            assert_eq!(
                block[11] & !0x30,
                v & !0x30,
                "only bits 4 and 5 move, for {v:#x}"
            );
        }
    }

    /// The reference's own first vector, so a failure here is unambiguous.
    #[test]
    fn the_first_reference_vector() {
        let input = b"de omnibus dubitandum";
        assert_eq!(
            crate::hex::encode(&cn_slow_hash(input)),
            "2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5"
        );
    }
}
