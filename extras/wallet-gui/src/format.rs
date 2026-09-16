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

/// Blocks as a wait, at Wownero's five minutes a block: "about 20 minutes",
/// "about 3 hours", "about 2 days".
pub fn blocks_as_time(blocks: u64) -> String {
    let minutes = blocks.saturating_mul(5);
    if minutes < 90 {
        format!("about {minutes} minutes")
    } else if minutes < 36 * 60 {
        format!("about {} hours", (minutes + 30) / 60)
    } else {
        format!("about {} days", (minutes + 12 * 60) / (24 * 60))
    }
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

/// A date as typed, `YYYY-MM-DD`, as the start of that day in UTC, in seconds
/// since 1970.
pub fn parse_date(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let bad = || format!("`{text}` is not a date written as 2024-05-31");
    let mut parts = text.splitn(3, '-');
    let (Some(y), Some(m), Some(d)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(bad());
    };
    let year: i64 = y.parse().map_err(|_| bad())?;
    let month: i64 = m.parse().map_err(|_| bad())?;
    let day: i64 = d.parse().map_err(|_| bad())?;
    if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(bad());
    }
    // `days_from_civil`, from Howard Hinnant's date algorithms: the inverse of
    // what `timestamp` does.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok(days as u64 * 86_400)
}

/// The height the chain had reached by `date`, reckoned back from `chain`
/// blocks at `now`, at five minutes a block.
///
/// Blocks do not come evenly, so it is kept a day early: a restore height a
/// little low costs a longer scan, where one too high hides payments.
pub fn height_on(date: u64, chain: u64, now: u64) -> u64 {
    const BLOCK_SECS: u64 = 300;
    const A_DAY: u64 = 288;
    let back = now.saturating_sub(date) / BLOCK_SECS;
    chain.saturating_sub(back).saturating_sub(A_DAY)
}

/// `YYYY-MM-DD HH:MM` in a time zone `offset` seconds east of UTC, or an
/// empty string for no time.
pub fn timestamp_in(ts: u64, offset: i64) -> String {
    if ts < 1_234_567_890 {
        return String::new();
    }
    timestamp(ts.saturating_add_signed(offset))
}

/// A field of a CSV file: quoted when it holds a comma, a quote or a line
/// break, with its quotes doubled.
pub fn csv_field(text: &str) -> String {
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_times_and_csv_fields() {
        let ts = 1_789_000_000;
        assert_eq!(timestamp_in(ts, 0), timestamp(ts));
        assert_eq!(timestamp_in(ts, 3_600), timestamp(ts + 3_600));
        assert_eq!(timestamp_in(ts, -3_600), timestamp(ts - 3_600));
        assert_eq!(timestamp_in(0, 3_600), "");

        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn dates_are_read_as_days_in_utc() {
        assert_eq!(parse_date("1970-01-01").expect("a date"), 0);
        assert_eq!(parse_date(" 2000-02-29 ").expect("a leap day"), 951_782_400);
        assert_eq!(
            timestamp(parse_date("2026-09-15").expect("a date")),
            "2026-09-15 00:00"
        );
        for bad in ["", "2026", "2026-13-01", "2026-00-10", "2026-09-32", "15/09/2026", "1969-12-31"] {
            assert!(parse_date(bad).is_err(), "`{bad}`");
        }
    }

    #[test]
    fn a_height_on_a_date_is_reckoned_back_and_kept_early() {
        let now = 1_800_000_000;
        // A day back is 288 blocks, and a day's margin 288 more.
        assert_eq!(height_on(now - 86_400, 10_000, now), 9_424);
        // Before the chain began, and in the future, it stays in range.
        assert_eq!(height_on(0, 10_000, now), 0);
        assert_eq!(height_on(now + 86_400, 10_000, now), 9_712);
    }

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
