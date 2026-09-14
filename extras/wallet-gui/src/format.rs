//! Amounts, heights and times, as the interface shows them.
//!
//! The amount rules are wallet-cli's (`bin/wownero-wallet-cli/src/fmt.rs`):
//! **11 decimals**, not Monero's 12, and a typed amount with more places than
//! that is refused rather than rounded.

/// `CRYPTONOTE_DISPLAY_DECIMAL_POINT`.
pub const DECIMALS: u32 = 11;

/// Atomic units in one WOW.
pub const ATOMIC_PER_COIN: u64 = 100_000_000_000;

/// Every decimal place, none trimmed, as `print_money` prints it.
pub fn amount(atomic: u64) -> String {
    let whole = atomic / ATOMIC_PER_COIN;
    let frac = atomic % ATOMIC_PER_COIN;
    format!("{whole}.{frac:0width$}", width = DECIMALS as usize)
}

/// Trailing zeros dropped, keeping at least two decimals: for headings, where
/// eleven places are noise.
pub fn amount_short(atomic: u64) -> String {
    let full = amount(atomic);
    let (whole, frac) = full.split_once('.').unwrap_or((full.as_str(), "00"));
    let trimmed = frac.trim_end_matches('0');
    let frac = if trimmed.len() < 2 { &frac[..2] } else { trimmed };
    format!("{whole}.{frac}")
}

/// Parse an amount as typed: `5`, `5.25`, `.25`, `1_000`.
pub fn parse_amount(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("an amount is required".into());
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_digit() || b == b'.' || b == b'_')
    {
        return Err(format!("`{s}` is not an amount"));
    }
    let s: String = s.chars().filter(|c| *c != '_').collect();

    let (whole, frac) = match s.split_once('.') {
        None => (s.as_str(), ""),
        Some((_, f)) if f.contains('.') => return Err(format!("`{s}` has two decimal points")),
        Some((w, f)) => (w, f),
    };
    if frac.len() > DECIMALS as usize {
        return Err(format!(
            "`{s}` has {} decimal places; the smallest unit is {} ({DECIMALS} places)",
            frac.len(),
            amount(1)
        ));
    }

    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| format!("`{whole}` is not a whole number"))?
    };
    let mut padded = frac.to_string();
    while padded.len() < DECIMALS as usize {
        padded.push('0');
    }
    let frac: u64 = padded
        .parse()
        .map_err(|_| format!("`{frac}` is not a fraction"))?;

    whole
        .checked_mul(ATOMIC_PER_COIN)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| format!("`{s}` is larger than the money supply"))
}

/// `873,901`.
pub fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `YYYY-MM-DD HH:MM` in UTC, or an empty string for no time.
pub fn timestamp(ts: u64) -> String {
    if ts < 1_234_567_890 {
        return String::new();
    }
    let secs = ts % 86_400;
    // `civil_from_days`, from Howard Hinnant's date algorithms.
    let z = (ts / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}",
        secs / 3_600,
        secs / 60 % 60
    )
}

/// The first and last few characters of something long: `Wo3fq…x9Tz`.
pub fn elide(text: &str, keep: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= keep * 2 + 1 {
        return text.to_string();
    }
    let head: String = chars[..keep].iter().collect();
    let tail: String = chars[chars.len() - keep..].iter().collect();
    format!("{head}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CASES: &[(u64, &str)] = &[
        (0, "0.00000000000"),
        (1, "0.00000000001"),
        (ATOMIC_PER_COIN, "1.00000000000"),
        (150_000_000_000, "1.50000000000"),
        (123_456_789_012_345, "1234.56789012345"),
        (u64::MAX, "184467440.73709551615"),
    ];

    #[test]
    fn amounts_round_trip_with_eleven_decimals() {
        for (atomic, text) in CASES {
            assert_eq!(&amount(*atomic), text);
            assert_eq!(parse_amount(text).expect("re-parses"), *atomic);
        }
    }

    #[test]
    fn short_amounts_keep_two_decimals() {
        assert_eq!(amount_short(0), "0.00");
        assert_eq!(amount_short(150_000_000_000), "1.50");
        assert_eq!(amount_short(123_456_789_012_345), "1234.56789012345");
        assert_eq!(amount_short(1), "0.00000000001");
    }

    #[test]
    fn typed_amounts_are_read_exactly_or_refused() {
        assert_eq!(parse_amount(".5").expect("ok"), 50_000_000_000);
        assert_eq!(parse_amount("1_000").expect("ok"), 1_000 * ATOMIC_PER_COIN);
        for bad in ["", "abc", "1.2.3", "-1", "1e9", "1,5", "0.000000000001"] {
            assert!(parse_amount(bad).is_err(), "`{bad}` should not parse");
        }
        assert!(parse_amount("184467441").is_err());
    }

    #[test]
    fn numbers_and_times_read_at_a_glance() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(873_901), "873,901");
        assert_eq!(grouped(1_000_000), "1,000,000");
        assert_eq!(timestamp(1_600_000_000), "2020-09-13 12:26");
        assert_eq!(timestamp(0), "");
        assert_eq!(elide("abcdefghij", 3), "abc…hij");
        assert_eq!(elide("abcdefg", 3), "abcdefg");
    }
}
