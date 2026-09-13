//! 25-word mnemonic seeds.
//!
//! `specs/02-crypto.md` §6, from `src/mnemonics/electrum-words.cpp`.
//!
//! 25 words = 24 data words + 1 checksum word. Each 4-byte little-endian `u32`
//! of the 32-byte key becomes three words in base 1626, with the running-sum
//! obfuscation the CryptoNote scheme uses.
//!
//! The 25-word seed encodes the **private spend key**; the view key is derived
//! from it per `specs/02` §3.2, so only deterministic wallets have a seed
//! (`specs/12-wallet-core.md` §1.2).

mod crc32;
mod wordlist;

pub use wordlist::{by_language, by_name, english, Language, WordList, LANGUAGES};

use crate::types::SecretKey;

/// Words of key material in a seed. `seed_length` in the C.
pub const SEED_DATA_WORDS: usize = 24;
/// Total words in a valid seed: 24 data words plus the checksum word.
pub const SEED_WORDS: usize = SEED_DATA_WORDS + 1;
/// `NWORDS` — every language's list is exactly this long.
pub const WORDLIST_LEN: u32 = 1626;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MnemonicError {
    /// Not 24 or 25 words.
    WrongWordCount(usize),
    /// No language's list contains every word.
    UnknownLanguage,
    /// The 25th word does not match the computed checksum word.
    BadChecksum,
    /// A word is not in the chosen language's list.
    UnknownWord(String),
    /// The three words of a group do not satisfy `w[0] % 1626 == w[1]`.
    ///
    /// The C's "mumble mumble" check: it catches a seed whose words are
    /// individually valid but whose grouping is corrupt.
    Inconsistent,
    /// A key that is not 32 bytes.
    BadKeyLength(usize),
}

impl core::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MnemonicError::WrongWordCount(n) => {
                write!(f, "expected {SEED_WORDS} words (or {SEED_DATA_WORDS} without a checksum), got {n}")
            }
            MnemonicError::UnknownLanguage => write!(f, "seed language not recognised"),
            MnemonicError::BadChecksum => write!(f, "invalid checksum word"),
            MnemonicError::UnknownWord(w) => write!(f, "word {w:?} is not in the word list"),
            MnemonicError::Inconsistent => write!(f, "inconsistent word group"),
            MnemonicError::BadKeyLength(n) => write!(f, "key must be 32 bytes, got {n}"),
        }
    }
}

impl std::error::Error for MnemonicError {}

/// Split a seed phrase on whitespace.
fn split(words: &str) -> Vec<&str> {
    words.split_whitespace().collect()
}

/// `Language::utf8prefix(s, count)`: the first `count` UTF-8 *characters*.
///
/// Not the first `count` bytes — for Chinese (prefix length 1) and Japanese
/// (3) that distinction decides whether a word matches at all.
pub(crate) fn utf8_prefix(s: &str, count: usize) -> &str {
    match s.char_indices().nth(count) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// `create_checksum_index(word_list, language)`.
///
/// Concatenates the **trimmed** form of each of the 24 data words (the trimmed
/// word as stored in the map, not the word as supplied), CRC-32s the result,
/// and takes it modulo the word count. The 25th word is the data word at that
/// index.
pub fn checksum_index(words: &[&str], lang: &'static WordList) -> Result<usize, MnemonicError> {
    let mut trimmed = String::new();
    for w in words {
        let key = lang
            .trimmed_key(w)
            .ok_or_else(|| MnemonicError::UnknownWord((*w).to_string()))?;
        trimmed.push_str(key);
    }
    Ok((crc32::crc32(trimmed.as_bytes()) as usize) % words.len())
}

/// `bytes_to_words(src, len, words, language_name)` for a 32-byte key.
///
/// ```text
/// for each little-endian u32 x of the key:
///     w1 = x % 1626
///     w2 = (x / 1626 + w1) % 1626
///     w3 = (x / 1626 / 1626 + w2) % 1626
/// ```
pub fn key_to_words(key: &SecretKey, lang: &'static WordList) -> String {
    let n = WORDLIST_LEN;
    let mut out: Vec<&str> = Vec::with_capacity(SEED_WORDS);
    for chunk in key.0.as_chunks::<4>().0 {
        let x = u32::from_le_bytes(*chunk);
        let w1 = x % n;
        let w2 = (x / n + w1) % n;
        let w3 = (x / n / n + w2) % n;
        out.push(lang.word(w1 as usize));
        out.push(lang.word(w2 as usize));
        out.push(lang.word(w3 as usize));
    }
    debug_assert_eq!(out.len(), SEED_DATA_WORDS);
    let idx = checksum_index(&out, lang).expect("our own words are in the list");
    out.push(out[idx]);
    out.join(" ")
}

/// `words_to_bytes(words, dst, 32, ...)`.
///
/// Accepts 24 words (no checksum) or 25 (with one, which is verified). Returns
/// the key and the language it was found in.
pub fn words_to_key(phrase: &str) -> Result<(SecretKey, &'static WordList), MnemonicError> {
    let mut seed = split(phrase);
    let has_checksum = match seed.len() {
        SEED_WORDS => true,
        SEED_DATA_WORDS => false,
        n => return Err(MnemonicError::WrongWordCount(n)),
    };

    let lang = find_language(&seed, has_checksum).ok_or(MnemonicError::UnknownLanguage)?;

    if has_checksum {
        if !checksum_ok(&seed, lang) {
            return Err(MnemonicError::BadChecksum);
        }
        seed.pop();
    }

    let n = WORDLIST_LEN;
    let mut key = [0u8; 32];
    for (g, group) in seed.as_chunks::<3>().0.iter().enumerate() {
        let w1 = lang
            .index_of(group[0], has_checksum)
            .ok_or_else(|| MnemonicError::UnknownWord(group[0].to_string()))?
            as u32;
        let w2 = lang
            .index_of(group[1], has_checksum)
            .ok_or_else(|| MnemonicError::UnknownWord(group[1].to_string()))?
            as u32;
        let w3 = lang
            .index_of(group[2], has_checksum)
            .ok_or_else(|| MnemonicError::UnknownWord(group[2].to_string()))?
            as u32;

        let x = w1
            .wrapping_add(n.wrapping_mul((n - w1 + w2) % n))
            .wrapping_add(n.wrapping_mul(n).wrapping_mul((n - w2 + w3) % n));

        // The C's "mumble mumble" consistency check.
        if x % n != w1 {
            return Err(MnemonicError::Inconsistent);
        }
        key[g * 4..g * 4 + 4].copy_from_slice(&x.to_le_bytes());
    }

    Ok((SecretKey(key), lang))
}

/// `checksum_test(seed, language)`.
fn checksum_ok(seed: &[&str], lang: &'static WordList) -> bool {
    let Some((last, data)) = seed.split_last() else {
        return false;
    };
    let Ok(idx) = checksum_index(data, lang) else {
        return false;
    };
    let expect = data[idx];
    // Both sides are trimmed to the prefix length before comparing, and the
    // comparison is case-insensitive (`Language::WordEqual`).
    let n = lang.unique_prefix_length as usize;
    let a = utf8_prefix(expect, n).to_lowercase();
    let b = utf8_prefix(last, n).to_lowercase();
    a == b
}

/// `find_seed_language(seed, has_checksum, matched_indices, language)`.
///
/// Tries the languages in the reference's order and returns the first full
/// match whose checksum also passes; failing that, the first full match whose
/// checksum did not (the C's `fallback`, for a mistyped seed in a known
/// language).
pub fn find_language(seed: &[&str], has_checksum: bool) -> Option<&'static WordList> {
    let mut fallback: Option<&'static WordList> = None;
    for lang in LANGUAGES {
        if !seed
            .iter()
            .all(|w| lang.index_of(w, has_checksum).is_some())
        {
            continue;
        }
        if has_checksum && !checksum_ok(seed, lang) {
            // A prefix-only match can collide across languages, so an failed
            // checksum demotes this to a fallback rather than accepting it.
            if fallback.is_none() {
                fallback = Some(lang);
            }
            continue;
        }
        return Some(lang);
    }
    fallback
}

#[cfg(test)]
mod tests;
