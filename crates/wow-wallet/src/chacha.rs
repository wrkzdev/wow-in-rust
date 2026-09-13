//! ChaCha, and the three key derivations the wallet builds on it.
//!
//! `src/crypto/chacha.c` and `chacha.h`.
//!
//! # This is not RFC 7539
//!
//! The reference is Bernstein's original `chacha-merged.c`: a **64-bit counter**
//! in words 12–13 and a **64-bit nonce** in words 14–15. RFC 7539 splits those
//! differently — a 32-bit counter in word 12 and a 96-bit nonce in 13–15 — so
//! an off-the-shelf ChaCha20 takes a twelve-byte nonce and puts the wallet's
//! eight bytes in the wrong words. Do not substitute one.
//!
//! # Three derivations that look alike and are not
//!
//! | What | From | Hash |
//! |---|---|---|
//! | [`generate_chacha_key`] | the password | **CryptoNight** v0 |
//! | [`derive_key_stream_key`] | the keys-file key + `'k'` | **CryptoNight** v0 |
//! | [`derive_cache_key`] | the keys-file key + `0x8c`/`0x8d` | **Keccak** |
//!
//! Two of the three are CryptoNight and one is not; all three take 32 or 33
//! bytes in and give 32 out. `specs/02` §7 describes the first and the third
//! and does not mention the second, which is why opening a wallet costs two
//! CryptoNight evaluations rather than one.

use wow_crypto::cn::cn_slow_hash;
use wow_crypto::cn_fast_hash;

/// `CHACHA_KEY_SIZE`.
pub const KEY_SIZE: usize = 32;
/// `CHACHA_IV_SIZE`. Eight bytes, not twelve.
pub const IV_SIZE: usize = 8;

/// `config::HASH_KEY_MEMORY`, the domain byte for the in-memory key stream.
pub const HASH_KEY_MEMORY: u8 = b'k';
/// `config::HASH_KEY_WALLET`.
pub const HASH_KEY_WALLET: u8 = 0x8c;
/// `config::HASH_KEY_WALLET_CACHE`.
pub const HASH_KEY_WALLET_CACHE: u8 = 0x8d;
/// `config::HASH_KEY_BACKGROUND_CACHE`.
pub const HASH_KEY_BACKGROUND_CACHE: u8 = 0x8e;
/// `config::HASH_KEY_BACKGROUND_KEYS_FILE`.
pub const HASH_KEY_BACKGROUND_KEYS_FILE: u8 = 0x8f;

pub type Key = [u8; KEY_SIZE];
pub type Iv = [u8; IV_SIZE];

const SIGMA: &[u8; 16] = b"expand 32-byte k";

#[inline]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// ChaCha with `rounds` rounds, xored over `data`.
fn chacha(rounds: u32, data: &[u8], key: &Key, iv: &Iv) -> Vec<u8> {
    debug_assert_eq!(rounds % 2, 0, "ChaCha runs double rounds");

    let mut j = [0u32; 16];
    for (i, w) in j[..4].iter_mut().enumerate() {
        *w = u32::from_le_bytes(SIGMA[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
    }
    for (i, w) in j[4..12].iter_mut().enumerate() {
        *w = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
    }
    // Words 12 and 13 are the counter, 14 and 15 the nonce.
    j[14] = u32::from_le_bytes(iv[0..4].try_into().expect("4 bytes"));
    j[15] = u32::from_le_bytes(iv[4..8].try_into().expect("4 bytes"));

    let mut out = Vec::with_capacity(data.len());
    for block in data.chunks(64) {
        let mut x = j;
        for _ in 0..rounds / 2 {
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 1, 5, 9, 13);
            quarter_round(&mut x, 2, 6, 10, 14);
            quarter_round(&mut x, 3, 7, 11, 15);
            quarter_round(&mut x, 0, 5, 10, 15);
            quarter_round(&mut x, 1, 6, 11, 12);
            quarter_round(&mut x, 2, 7, 8, 13);
            quarter_round(&mut x, 3, 4, 9, 14);
        }

        let mut stream = [0u8; 64];
        for (i, w) in x.iter().enumerate() {
            let v = w.wrapping_add(j[i]);
            stream[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        out.extend(block.iter().zip(stream.iter()).map(|(b, s)| b ^ s));

        // 64-bit counter, low word first.
        j[12] = j[12].wrapping_add(1);
        if j[12] == 0 {
            j[13] = j[13].wrapping_add(1);
        }
    }
    out
}

/// ChaCha20. The keys file and the key stream both use this.
pub fn chacha20(data: &[u8], key: &Key, iv: &Iv) -> Vec<u8> {
    chacha(20, data, key, iv)
}

/// ChaCha8 — only ever used when reading a pre-2017 keys file, which the
/// reference falls back to when the ChaCha20 plaintext is not valid JSON.
pub fn chacha8(data: &[u8], key: &Key, iv: &Iv) -> Vec<u8> {
    chacha(8, data, key, iv)
}

/// `generate_chacha_key`: CryptoNight v0 of the password, re-hashed
/// `kdf_rounds - 1` more times.
///
/// `kdf_rounds` is 1 for every wallet the CLI writes; the option exists for
/// callers that want a slower KDF, and both ends must agree or the file will
/// not open.
pub fn generate_chacha_key(password: &[u8], kdf_rounds: u64) -> Key {
    let mut h = cn_slow_hash(password);
    for _ in 1..kdf_rounds {
        h = cn_slow_hash(&h);
    }
    h
}

/// `account.cpp`'s `derive_key`: the key that encrypts the secret keys inside
/// `key_data`.
///
/// This is **not** [`derive_cache_key`] with a different byte — it runs
/// CryptoNight, not Keccak.
pub fn derive_key_stream_key(base: &Key) -> Key {
    let mut data = [0u8; KEY_SIZE + 1];
    data[..KEY_SIZE].copy_from_slice(base);
    data[KEY_SIZE] = HASH_KEY_MEMORY;
    generate_chacha_key(&data, 1)
}

/// `wallet2.cpp`'s `derive_cache_key`: Keccak over the key and one domain byte.
///
/// This is **not** [`derive_key_stream_key`] with a different byte — it runs
/// Keccak, not CryptoNight, so it is cheap where the other is not.
pub fn derive_cache_key(base: &Key, domain: u8) -> Key {
    let mut data = [0u8; KEY_SIZE + 1];
    data[..KEY_SIZE].copy_from_slice(base);
    data[KEY_SIZE] = domain;
    cn_fast_hash(&data)
}

/// The key stream `account_keys::xor_with_key_stream` xors over the secret
/// keys: ChaCha20 of `bytes` zeros, under a key derived from `base`.
pub fn key_stream(base: &Key, iv: &Iv, bytes: usize) -> Vec<u8> {
    let key = derive_key_stream_key(base);
    chacha20(&vec![0u8; bytes], &key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wow_crypto::hex;

    /// The published ChaCha20 keystream for an all-zero key and nonce.
    #[test]
    fn the_zero_key_vector() {
        let out = chacha20(&[0u8; 64], &[0u8; 32], &[0u8; 8]);
        assert_eq!(
            hex::encode(&out),
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
             da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
        );
    }

    /// The counter is word 12 and advances once per block. The published
    /// second block pins that; it does not, on its own, distinguish word 13
    /// being the counter's high half from it being part of a nonce, because
    /// both are zero here.
    #[test]
    fn the_counter_advances_per_block() {
        let out = chacha20(&[0u8; 128], &[0u8; 32], &[0u8; 8]);
        assert_eq!(
            hex::encode(&out[64..]),
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed\
             29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"
        );
    }

    /// Both halves of the eight-byte IV reach the state. A layout that fed the
    /// IV into words 13–14 instead of 14–15 would still pass the vector above,
    /// but would make these two IVs collide with a shifted pair.
    #[test]
    fn both_halves_of_the_iv_matter() {
        let key = [0u8; 32];
        let base = chacha20(&[0u8; 64], &key, &[0u8; 8]);
        let low = chacha20(&[0u8; 64], &key, &[1, 0, 0, 0, 0, 0, 0, 0]);
        let high = chacha20(&[0u8; 64], &key, &[0, 0, 0, 0, 1, 0, 0, 0]);
        assert_ne!(low, base);
        assert_ne!(high, base);
        assert_ne!(low, high);
    }

    /// Encryption is its own inverse, since it is a stream xor.
    #[test]
    fn it_round_trips() {
        let key = [7u8; 32];
        let iv = [3u8; 8];
        let msg = b"the keys file is where the money is".to_vec();
        let ct = chacha20(&msg, &key, &iv);
        assert_ne!(ct, msg);
        assert_eq!(chacha20(&ct, &key, &iv), msg);
    }

    /// Eight rounds and twenty rounds are different functions, and the wallet
    /// picks between them by whether the plaintext parses.
    #[test]
    fn eight_rounds_is_not_twenty() {
        let key = [1u8; 32];
        let iv = [2u8; 8];
        assert_ne!(
            chacha8(&[0u8; 64], &key, &iv),
            chacha20(&[0u8; 64], &key, &iv)
        );
    }

    /// A partial final block must not be padded out.
    #[test]
    fn a_short_input_keeps_its_length() {
        for n in [0usize, 1, 63, 64, 65, 127, 128, 129] {
            assert_eq!(chacha20(&vec![0u8; n], &[9u8; 32], &[4u8; 8]).len(), n);
        }
        // And a prefix of a long encryption equals the short encryption.
        let long = chacha20(&[0u8; 200], &[9u8; 32], &[4u8; 8]);
        let short = chacha20(&[0u8; 65], &[9u8; 32], &[4u8; 8]);
        assert_eq!(&long[..65], &short[..]);
    }

    /// The two 33-byte derivations use different hashes. If they ever agree,
    /// one of them has been written in terms of the other.
    #[test]
    fn the_two_derivations_are_different_functions() {
        let base = [0x11u8; 32];
        assert_ne!(
            derive_key_stream_key(&base),
            derive_cache_key(&base, HASH_KEY_MEMORY)
        );

        // derive_cache_key is plain Keccak over 33 bytes; check it directly so
        // a future refactor cannot quietly make it CryptoNight.
        let mut data = [0u8; 33];
        data[..32].copy_from_slice(&base);
        data[32] = HASH_KEY_WALLET_CACHE;
        assert_eq!(
            derive_cache_key(&base, HASH_KEY_WALLET_CACHE),
            cn_fast_hash(&data)
        );
    }

    /// The domain byte changes the answer, which is the point of having one.
    #[test]
    fn the_domain_byte_separates() {
        let base = [0x22u8; 32];
        assert_ne!(
            derive_cache_key(&base, HASH_KEY_WALLET_CACHE),
            derive_cache_key(&base, HASH_KEY_BACKGROUND_CACHE)
        );
    }

    /// `kdf_rounds` iterates, so 1 and 2 differ and 2 is one more hash.
    #[test]
    fn the_kdf_rounds_iterate() {
        let one = generate_chacha_key(b"hunter2", 1);
        let two = generate_chacha_key(b"hunter2", 2);
        assert_ne!(one, two);
        assert_eq!(two, wow_crypto::cn::cn_slow_hash(&one));
    }
}
