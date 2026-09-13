//! The 13 word lists, each 1626 words.
//!
//! Extracted verbatim from `src/mnemonics/*.h` in the reference tree. The
//! `unique_prefix_length` values come from each language's `Base(...)`
//! constructor call and are load-bearing: they decide how many leading
//! characters a word is matched on, and therefore both language detection and
//! the checksum.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::utf8_prefix;

/// A supported seed language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    English,
    EnglishOld,
    ChineseSimplified,
    Dutch,
    Esperanto,
    French,
    German,
    Italian,
    Japanese,
    Lojban,
    Portuguese,
    Russian,
    Spanish,
}

/// One language's word list and its matching rules.
pub struct WordList {
    pub language: Language,
    /// `get_language_name()` — the endonym, e.g. `"Nederlands"`.
    pub name: &'static str,
    /// `get_english_language_name()`, e.g. `"Dutch"`.
    pub english_name: &'static str,
    /// How many leading UTF-8 characters a word is matched on.
    pub unique_prefix_length: u32,
    /// `ALLOW_DUPLICATE_PREFIXES`: set only by `english_old`, whose
    /// 4-character prefixes are not unique (292 collide). For any other list a
    /// duplicate makes `populate_maps` throw.
    pub allows_duplicate_prefixes: bool,
    /// `ALLOW_SHORT_WORDS`: set by `english_old` and `spanish`, which contain
    /// words shorter than `unique_prefix_length` **bytes**. The C tests
    /// `(*it).size()`, the byte length, not the character count — so an
    /// accented three-letter Spanish word is 4 bytes and not "short".
    pub allows_short_words: bool,
    raw: &'static str,
    words: OnceLock<Vec<&'static str>>,
    /// Lowercased full word -> index.
    by_word: OnceLock<HashMap<String, usize>>,
    /// Lowercased trimmed prefix -> index, plus the canonical trimmed key.
    by_prefix: OnceLock<HashMap<String, (usize, &'static str)>>,
}

impl WordList {
    /// The 1626 words, in index order.
    pub fn words(&'static self) -> &'static [&'static str] {
        self.words
            .get_or_init(|| self.raw.lines().filter(|l| !l.is_empty()).collect())
    }

    pub fn word(&'static self, index: usize) -> &'static str {
        self.words()[index]
    }

    fn word_map(&'static self) -> &'static HashMap<String, usize> {
        self.by_word.get_or_init(|| {
            self.words()
                .iter()
                .enumerate()
                .map(|(i, w)| (w.to_lowercase(), i))
                .collect()
        })
    }

    fn prefix_map(&'static self) -> &'static HashMap<String, (usize, &'static str)> {
        self.by_prefix.get_or_init(|| {
            let n = self.unique_prefix_length as usize;
            let mut m = HashMap::new();
            for (i, w) in self.words().iter().enumerate() {
                let key = utf8_prefix(w, n);
                // `populate_maps` does `trimmed_word_map[trimmed] = ii`, a plain
                // assignment -- so on a duplicate prefix the **last** word wins.
                // Only the `english_old` list has duplicates (292 of them), and
                // it is the one list that passes `ALLOW_DUPLICATE_PREFIXES`.
                // Keeping the first index instead silently decodes some
                // English-old seeds to the wrong key.
                m.insert(key.to_lowercase(), (i, key));
            }
            m
        })
    }

    /// Look a word up. With `trimmed`, match on the prefix (which is what the
    /// reference does whenever a checksum word is present); otherwise match the
    /// whole word.
    pub fn index_of(&'static self, word: &str, trimmed: bool) -> Option<usize> {
        if trimmed {
            let n = self.unique_prefix_length as usize;
            self.prefix_map()
                .get(&utf8_prefix(word, n).to_lowercase())
                .map(|(i, _)| *i)
        } else {
            self.word_map().get(&word.to_lowercase()).copied()
        }
    }

    /// The canonical trimmed key for a word, as `create_checksum_index`
    /// concatenates it (`it2->first`, the map key — not the supplied word).
    pub fn trimmed_key(&'static self, word: &str) -> Option<&'static str> {
        let n = self.unique_prefix_length as usize;
        self.prefix_map()
            .get(&utf8_prefix(word, n).to_lowercase())
            .map(|(_, k)| *k)
    }
}

macro_rules! wordlists {
    ($( $konst:ident : $variant:ident, $name:expr, $english:expr, $prefix:expr,
        $file:expr, dup = $dup:expr, short = $short:expr; )*) => {
        $(
            static $konst: WordList = WordList {
                language: Language::$variant,
                name: $name,
                english_name: $english,
                unique_prefix_length: $prefix,
                allows_duplicate_prefixes: $dup,
                allows_short_words: $short,
                raw: include_str!(concat!("../../wordlists/", $file, ".txt")),
                words: OnceLock::new(),
                by_word: OnceLock::new(),
                by_prefix: OnceLock::new(),
            };
        )*

        /// All word lists, in the order `find_seed_language` tries them.
        ///
        /// The order is part of the behaviour: prefix matching can make a seed
        /// match more than one language, and the first full match wins.
        pub static LANGUAGES: &[&WordList] = &[ $( &$konst ),* ];
    };
}

// The order below is `find_seed_language`'s `language_instances` vector from
// `src/mnemonics/electrum-words.cpp`, verbatim. The `dup` / `short` flags are
// the arguments each language's `populate_maps(...)` call passes.
wordlists! {
    CHINESE_SIMPLIFIED: ChineseSimplified, "简体中文 (中国)", "Chinese (simplified)", 1,
        "chinese_simplified", dup = false, short = false;
    ENGLISH:    English,    "English",      "English",    3, "english",    dup = false, short = false;
    DUTCH:      Dutch,      "Nederlands",   "Dutch",      4, "dutch",      dup = false, short = false;
    FRENCH:     French,     "Français",     "French",     4, "french",     dup = false, short = false;
    // populate_maps(ALLOW_SHORT_WORDS): 31 Spanish words are under 4 bytes.
    SPANISH:    Spanish,    "Español",      "Spanish",    4, "spanish",    dup = false, short = true;
    GERMAN:     German,     "Deutsch",      "German",     4, "german",     dup = false, short = false;
    ITALIAN:    Italian,    "Italiano",     "Italian",    4, "italian",    dup = false, short = false;
    PORTUGUESE: Portuguese, "Português",    "Portuguese", 4, "portuguese", dup = false, short = false;
    JAPANESE:   Japanese,   "日本語",        "Japanese",   3, "japanese",   dup = false, short = false;
    RUSSIAN:    Russian,    "русский язык", "Russian",    4, "russian",    dup = false, short = false;
    ESPERANTO:  Esperanto,  "Esperanto",    "Esperanto",  4, "esperanto",  dup = false, short = false;
    LOJBAN:     Lojban,     "Lojban",       "Lojban",     4, "lojban",     dup = false, short = false;
    // populate_maps(ALLOW_DUPLICATE_PREFIXES | ALLOW_SHORT_WORDS): the legacy
    // list, with 292 colliding prefixes and 108 short words.
    ENGLISH_OLD: EnglishOld, "EnglishOld", "English (old)", 4, "english_old",
        dup = true, short = true;
}

/// Look a language up by either of its names, as `bytes_to_words` does.
pub fn by_name(name: &str) -> Option<&'static WordList> {
    LANGUAGES
        .iter()
        .copied()
        .find(|l| l.name == name || l.english_name == name)
}

/// Look a language up by its enum tag.
pub fn by_language(lang: Language) -> &'static WordList {
    LANGUAGES
        .iter()
        .copied()
        .find(|l| l.language == lang)
        .expect("every Language variant has a list")
}

/// The default language for a new wallet.
pub fn english() -> &'static WordList {
    &ENGLISH
}
