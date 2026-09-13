use super::*;
use crate::ops::sc_reduce32;

fn key(b: u8) -> SecretKey {
    SecretKey(sc_reduce32(&[b; 32]))
}

#[test]
fn every_list_has_1626_unique_words() {
    assert_eq!(LANGUAGES.len(), 13);
    for lang in LANGUAGES {
        let w = lang.words();
        assert_eq!(
            w.len(),
            WORDLIST_LEN as usize,
            "{} has {} words",
            lang.english_name,
            w.len()
        );
        let uniq: std::collections::HashSet<_> = w.iter().collect();
        assert_eq!(uniq.len(), w.len(), "{} has duplicates", lang.english_name);
        assert!(
            w.iter().all(|x| !x.is_empty() && x.trim() == *x),
            "{} has a blank or padded word",
            lang.english_name
        );
    }
}

/// The prefix lengths come from each `Base(...)` constructor. English and
/// Japanese are 3, Chinese is 1, everything else is 4.
#[test]
fn prefix_lengths_match_the_reference() {
    let expect: &[(&str, u32)] = &[
        ("English", 3),
        ("English (old)", 4),
        ("Chinese (simplified)", 1),
        ("Dutch", 4),
        ("Esperanto", 4),
        ("French", 4),
        ("German", 4),
        ("Italian", 4),
        ("Japanese", 3),
        ("Lojban", 4),
        ("Portuguese", 4),
        ("Russian", 4),
        ("Spanish", 4),
    ];
    for (name, n) in expect {
        let l = wordlist::by_name(name).unwrap_or_else(|| panic!("no list named {name}"));
        assert_eq!(l.unique_prefix_length, *n, "{name}");
    }
}

/// `utf8prefix` counts **characters**, not bytes. For Chinese (prefix 1) and
/// Russian (4) a byte-wise implementation would slice mid-codepoint.
#[test]
fn utf8_prefix_counts_characters() {
    assert_eq!(utf8_prefix("abbey", 3), "abb");
    assert_eq!(utf8_prefix("ab", 3), "ab");
    assert_eq!(utf8_prefix("", 3), "");
    assert_eq!(utf8_prefix("的", 1), "的");
    assert_eq!(utf8_prefix("абажур", 4), "абаж");
    assert_eq!(utf8_prefix("あいこくしん", 3), "あいこ");
    // A byte-wise prefix of length 4 would be invalid UTF-8 here.
    assert!(utf8_prefix("абажур", 4).chars().count() == 4);
}

#[test]
fn roundtrip_in_every_language() {
    for lang in LANGUAGES {
        // `english_old` is excluded: its 4-character prefixes are not unique,
        // so the 25-word path is lossy there in the reference too. See
        // `english_old_prefixes_collide`.
        if lang.allows_duplicate_prefixes {
            continue;
        }
        // Non-degenerate keys only: an all-zero key encodes as 25 copies of
        // word 0, which is genuinely ambiguous across languages (see
        // `an_all_identical_seed_is_ambiguous_across_languages`).
        for seed in [1u8, 0x42, 0xfe] {
            let k = key(seed);
            let phrase = key_to_words(&k, lang);
            assert_eq!(
                phrase.split_whitespace().count(),
                SEED_WORDS,
                "{} produced the wrong word count",
                lang.english_name
            );
            let (back, found) = words_to_key(&phrase).unwrap_or_else(|e| {
                panic!("{}: {phrase}: {e}", lang.english_name);
            });
            assert_eq!(back, k, "{} did not round-trip", lang.english_name);
            // Prefix matching can make a phrase match several languages; what
            // matters is that the key is right.
            let _ = found;
        }
    }
}

/// Exactly one list has colliding prefixes, and `populate_maps` resolves a
/// collision by **last-wins** (`trimmed_word_map[trimmed] = ii`). Keeping the
/// first index instead would silently decode some English-old seeds to the
/// wrong key, which is a lost-funds bug rather than a test failure.
#[test]
fn english_old_prefixes_collide() {
    for lang in LANGUAGES {
        let n = lang.unique_prefix_length as usize;
        let mut seen: std::collections::HashMap<String, usize> = Default::default();
        let mut dups = 0usize;
        let mut last_for: std::collections::HashMap<String, usize> = Default::default();
        for (i, w) in lang.words().iter().enumerate() {
            let t = utf8_prefix(w, n).to_lowercase();
            if seen.insert(t.clone(), i).is_some() {
                dups += 1;
            }
            last_for.insert(t, i);
        }
        if lang.allows_duplicate_prefixes {
            assert!(
                dups > 0,
                "{} was expected to have duplicates",
                lang.english_name
            );
            assert_eq!(lang.english_name, "English (old)");
        } else {
            assert_eq!(
                dups, 0,
                "{} has {dups} duplicate prefixes",
                lang.english_name
            );
        }
        // Whatever the list, the lookup must return the LAST index.
        for (t, i) in &last_for {
            assert_eq!(
                lang.index_of(t, true),
                Some(*i),
                "{}: prefix {t:?} should map to the last matching word",
                lang.english_name
            );
        }
    }
}

/// English-old is still usable on the 24-word (no-checksum) path, where words
/// are matched in full rather than by prefix.
#[test]
fn english_old_roundtrips_without_a_checksum_word() {
    let lang = wordlist::by_name("English (old)").unwrap();
    for seed in [1u8, 0x42, 0xfe] {
        let k = key(seed);
        let phrase = key_to_words(&k, lang);
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let short = words[..SEED_DATA_WORDS].join(" ");
        assert_eq!(words_to_key(&short).unwrap().0, k);
    }
}

/// `populate_maps` throws on a word shorter than the prefix length unless
/// `ALLOW_SHORT_WORDS` is set, which only `spanish` and `english_old` pass.
///
/// The C tests `(*it).size()`, the **byte** length, so an accented three-letter
/// Spanish word such as "año" (4 bytes) is not short while "asa" (3 bytes) is.
/// Counting characters instead would flag 36 words rather than the correct 31 —
/// harmless here, but the same byte-vs-character distinction decides how words
/// are trimmed, where it is not harmless.
#[test]
fn short_word_flags_match_the_reference() {
    for lang in LANGUAGES {
        let n = lang.unique_prefix_length as usize;
        let short = lang.words().iter().filter(|w| w.len() < n).count();
        if lang.allows_short_words {
            assert!(
                short > 0,
                "{} claims ALLOW_SHORT_WORDS but has none",
                lang.english_name
            );
        } else {
            assert_eq!(
                short, 0,
                "{} has {short} words under {n} bytes but does not pass ALLOW_SHORT_WORDS",
                lang.english_name
            );
        }
    }
    // Exactly the two lists the reference flags, and only those.
    let flagged: Vec<&str> = LANGUAGES
        .iter()
        .filter(|l| l.allows_short_words)
        .map(|l| l.english_name)
        .collect();
    assert_eq!(flagged, vec!["Spanish", "English (old)"]);

    let dup: Vec<&str> = LANGUAGES
        .iter()
        .filter(|l| l.allows_duplicate_prefixes)
        .map(|l| l.english_name)
        .collect();
    assert_eq!(dup, vec!["English (old)"]);
}

#[test]
fn roundtrip_over_many_keys() {
    let lang = wordlist::english();
    let mut rng = crate::random::Rng::deterministic_test_seed();
    for _ in 0..64 {
        let k = SecretKey(rng.random_scalar());
        let phrase = key_to_words(&k, lang);
        assert_eq!(words_to_key(&phrase).unwrap().0, k);
    }
}

/// A 24-word phrase (no checksum) is accepted, and matches the 25-word form.
#[test]
fn accepts_a_seed_without_a_checksum_word() {
    let lang = wordlist::english();
    let k = key(0x11);
    let full = key_to_words(&k, lang);
    let words: Vec<&str> = full.split_whitespace().collect();
    let short = words[..SEED_DATA_WORDS].join(" ");
    assert_eq!(words_to_key(&short).unwrap().0, k);
}

#[test]
fn rejects_a_wrong_checksum_word() {
    let lang = wordlist::english();
    let k = key(0x22);
    let full = key_to_words(&k, lang);
    let mut words: Vec<&str> = full.split_whitespace().collect();

    // Replace the checksum word with a different one from the list.
    let last = words.len() - 1;
    let replacement = lang
        .words()
        .iter()
        .find(|w| {
            utf8_prefix(w, 3) != utf8_prefix(words[last], 3)
                && !words[..SEED_DATA_WORDS].contains(w)
        })
        .unwrap();
    words[last] = replacement;
    let tampered = words.join(" ");

    // Either the checksum fails outright, or no language accepts the phrase.
    assert!(matches!(
        words_to_key(&tampered),
        Err(MnemonicError::BadChecksum) | Err(MnemonicError::UnknownLanguage)
    ));
}

#[test]
fn rejects_wrong_word_counts() {
    assert!(matches!(
        words_to_key("one two three"),
        Err(MnemonicError::WrongWordCount(3))
    ));
    assert!(matches!(
        words_to_key(""),
        Err(MnemonicError::WrongWordCount(0))
    ));
    let lang = wordlist::english();
    let full = key_to_words(&key(1), lang);
    let too_many = format!("{full} abbey");
    assert!(matches!(
        words_to_key(&too_many),
        Err(MnemonicError::WrongWordCount(26))
    ));
}

#[test]
fn rejects_words_from_no_language() {
    let phrase = (0..25)
        .map(|i| format!("zzqqxx{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(matches!(
        words_to_key(&phrase),
        Err(MnemonicError::UnknownLanguage)
    ));
}

/// `specs/02` §6: the checksum word is the data word at
/// `crc32(trimmed words) % 24`, compared on its trimmed prefix.
#[test]
fn checksum_word_is_the_indexed_data_word() {
    let lang = wordlist::english();
    let k = key(0x33);
    let phrase = key_to_words(&k, lang);
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let data = &words[..SEED_DATA_WORDS];
    let idx = checksum_index(data, lang).unwrap();
    assert!(idx < SEED_DATA_WORDS);
    assert_eq!(words[SEED_DATA_WORDS], data[idx]);
}

/// The checksum concatenates the **trimmed** words, not the full ones. With
/// English's prefix length of 3, using full words gives a different CRC and so
/// a different checksum word in most cases.
#[test]
fn checksum_uses_trimmed_words() {
    let lang = wordlist::english();
    let k = key(0x44);
    let phrase = key_to_words(&k, lang);
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let data = &words[..SEED_DATA_WORDS];

    let trimmed: String = data.iter().map(|w| utf8_prefix(w, 3)).collect();
    let full: String = data.concat();
    assert_ne!(trimmed, full, "test needs words longer than the prefix");
    assert_eq!(
        checksum_index(data, lang).unwrap(),
        (crate::mnemonic::crc32::crc32(trimmed.as_bytes()) as usize) % SEED_DATA_WORDS
    );
}

/// Matching is case-insensitive, as `Language::WordEqual` lowercases both
/// sides. German capitalises its nouns, so this is not hypothetical.
#[test]
fn matching_is_case_insensitive() {
    let lang = wordlist::by_name("German").unwrap();
    let k = key(0x55);
    let phrase = key_to_words(&k, lang);
    assert!(
        phrase.chars().any(|c| c.is_uppercase()),
        "German words should be capitalised"
    );
    assert_eq!(words_to_key(&phrase.to_lowercase()).unwrap().0, k);
}

#[test]
fn extra_whitespace_is_tolerated() {
    let lang = wordlist::english();
    let k = key(0x66);
    let phrase = key_to_words(&k, lang);
    let messy = format!("  {}  ", phrase.replace(' ', "   \t "));
    assert_eq!(words_to_key(&messy).unwrap().0, k);
}

/// The "mumble mumble" check: a group whose three words do not satisfy
/// `w[0] % 1626 == w[1]` is corrupt even if every word is in the list.
#[test]
fn detects_an_inconsistent_group() {
    let lang = wordlist::english();
    let k = key(0x77);
    let phrase = key_to_words(&k, lang);
    let mut words: Vec<&str> = phrase.split_whitespace().collect();
    // Swap two words within a group without touching the checksum word.
    words.swap(0, 1);
    // Recompute a checksum word so we test the group check, not the checksum.
    let data: Vec<&str> = words[..SEED_DATA_WORDS].to_vec();
    let idx = checksum_index(&data, lang).unwrap();
    let fixed = format!("{} {}", data.join(" "), data[idx]);
    match words_to_key(&fixed) {
        Err(MnemonicError::Inconsistent) => {}
        // A swap can occasionally still be consistent; in that case the key
        // must at least differ from the original.
        Ok((k2, _)) => assert_ne!(k2, k),
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
fn language_lookup_accepts_both_names() {
    assert_eq!(
        wordlist::by_name("Nederlands").unwrap().english_name,
        "Dutch"
    );
    assert_eq!(wordlist::by_name("Dutch").unwrap().name, "Nederlands");
    assert_eq!(
        wordlist::by_name("日本語").unwrap().english_name,
        "Japanese"
    );
    assert!(wordlist::by_name("Klingon").is_none());
    assert_eq!(
        wordlist::by_language(Language::Spanish).english_name,
        "Spanish"
    );
}

/// `specs/15` §4.4 again: never panic on hostile input.
#[test]
fn never_panics() {
    let junk = [
        "",
        " ",
        "\t\n",
        "abbey",
        "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的",
        "a b c d e f g h i j k l m n o p q r s t u v w x y",
        "\u{0}\u{0}\u{0}",
    ];
    for j in junk {
        let _ = words_to_key(j);
    }
    // 25 copies of the same word, in each language.
    for lang in LANGUAGES {
        let w = lang.word(0);
        let phrase = vec![w; 25].join(" ");
        let _ = words_to_key(&phrase);
    }
}

/// A seed whose words are all identical carries almost no information, and the
/// prefix matching makes it match several languages. The reference resolves
/// this by taking the first language in `find_seed_language`'s fixed order, and
/// so does this implementation -- but the recovered key is then *not* the one
/// that produced the phrase.
///
/// This is a property of the scheme, not a defect to fix: 24 identical words
/// encode 24 identical `u32`s, and the checksum passes trivially because every
/// candidate checksum word is the same word. Pinned here so the ordering in
/// `LANGUAGES` is not changed casually.
#[test]
fn an_all_identical_seed_is_ambiguous_across_languages() {
    let lojban = wordlist::by_name("Lojban").unwrap();
    let zero = SecretKey([0u8; 32]);
    let phrase = key_to_words(&zero, lojban);
    assert_eq!(phrase.split_whitespace().count(), SEED_WORDS);
    assert!(
        phrase.split_whitespace().all(|w| w == lojban.word(0)),
        "an all-zero key should encode as 25 copies of word 0"
    );

    let (recovered, found) = words_to_key(&phrase).unwrap();
    // Some language accepts it; which one is decided by the fixed order.
    assert!(LANGUAGES.iter().any(|l| std::ptr::eq(*l, found)));
    if !std::ptr::eq(found, lojban) {
        assert_ne!(
            recovered, zero,
            "a cross-language prefix collision should change the key"
        );
    }

    // Round-tripping within one language is still exact when the language is
    // pinned rather than detected.
    for lang in LANGUAGES {
        let p = key_to_words(&zero, lang);
        let idx: Vec<usize> = p
            .split_whitespace()
            .take(SEED_DATA_WORDS)
            .map(|w| lang.index_of(w, true).unwrap())
            .collect();
        assert!(idx.iter().all(|i| *i == idx[0]));
    }
}
