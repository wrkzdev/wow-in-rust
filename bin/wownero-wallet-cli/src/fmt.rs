//! Printing and parsing amounts.
//!
//! `specs/13` §3: amounts are shown with **11 decimals**, not Monero's 12.
//! `CRYPTONOTE_DISPLAY_DECIMAL_POINT` is 11 because `MONEY_SUPPLY` is
//! `u64::MAX` rather than a round number (`specs/01`).
//!
//! Getting this wrong is not cosmetic. A user who types `1.5` and gets ten
//! times that sent has been failed by the parser, so both directions are here
//! together and both are tested against the same table.

/// `CRYPTONOTE_DISPLAY_DECIMAL_POINT`.
pub const DECIMALS: u32 = 11;

/// Atomic units in one WOW.
pub const ATOMIC_PER_COIN: u64 = 100_000_000_000; // 10^11

/// Format an amount the way the reference prints it: every decimal place,
/// none trimmed.
///
/// `print_money` pads to the full width rather than shortening, so columns of
/// amounts line up and `0.00000000001` is visibly different from `0.0000000001`.
pub fn amount(atomic: u64) -> String {
    let whole = atomic / ATOMIC_PER_COIN;
    let frac = atomic % ATOMIC_PER_COIN;
    format!("{whole}.{frac:0width$}", width = DECIMALS as usize)
}

/// Parse an amount as a user types it.
///
/// Accepts a bare integer (`5`), a decimal (`5.25`), and a leading point
/// (`.25`). Rejects anything with more than [`DECIMALS`] decimal places rather
/// than rounding: silently dropping a digit off the end of an amount is not
/// something a wallet should do.
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

    // Right-pad the fraction to the full width, so `.5` is half a coin.
    let mut padded = frac.to_string();
    while padded.len() < DECIMALS as usize {
        padded.push('0');
    }
    let frac: u64 = if padded.is_empty() {
        0
    } else {
        padded
            .parse()
            .map_err(|_| format!("`{frac}` is not a fraction"))?
    };

    whole
        .checked_mul(ATOMIC_PER_COIN)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| format!("`{s}` is larger than the money supply"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table both directions are checked against.
    const CASES: &[(u64, &str)] = &[
        (0, "0.00000000000"),
        (1, "0.00000000001"),
        (10, "0.00000000010"),
        (ATOMIC_PER_COIN, "1.00000000000"),
        (ATOMIC_PER_COIN / 2, "0.50000000000"),
        (150_000_000_000, "1.50000000000"),
        (123_456_789_012_345, "1234.56789012345"),
        (u64::MAX, "184467440.73709551615"),
    ];

    #[test]
    fn amounts_print_with_eleven_decimals() {
        for (atomic, text) in CASES {
            assert_eq!(&amount(*atomic), text, "{atomic}");
            assert_eq!(
                amount(*atomic).split('.').nth(1).expect("a fraction").len(),
                DECIMALS as usize
            );
        }
    }

    #[test]
    fn amounts_round_trip() {
        for (atomic, _) in CASES {
            let printed = amount(*atomic);
            assert_eq!(
                parse_amount(&printed).expect("re-parses"),
                *atomic,
                "{printed}"
            );
        }
    }

    #[test]
    fn the_decimal_point_is_eleven_not_twelve() {
        // Monero prints 1.000000000000 for one coin; this must not.
        assert_eq!(amount(ATOMIC_PER_COIN), "1.00000000000");
        assert_eq!(amount(ATOMIC_PER_COIN).len(), "1.".len() + 11);
        assert_eq!(ATOMIC_PER_COIN, 10u64.pow(DECIMALS));
    }

    #[test]
    fn parsing_accepts_what_a_user_types() {
        assert_eq!(parse_amount("1").expect("ok"), ATOMIC_PER_COIN);
        assert_eq!(parse_amount("1.5").expect("ok"), 150_000_000_000);
        assert_eq!(parse_amount(".5").expect("ok"), 50_000_000_000);
        assert_eq!(parse_amount("0.00000000001").expect("ok"), 1);
        assert_eq!(parse_amount("  2  ").expect("ok"), 2 * ATOMIC_PER_COIN);
        assert_eq!(parse_amount("1_000").expect("ok"), 1_000 * ATOMIC_PER_COIN);
    }

    /// More precision than exists is an error, not a silent truncation. A
    /// wallet that quietly drops a digit is sending a different amount than
    /// the one it was told to.
    #[test]
    fn too_much_precision_is_refused() {
        let e = parse_amount("0.000000000001").expect_err("twelve places");
        assert!(e.contains("decimal places"), "{e}");
        assert!(parse_amount("1.5").is_ok());
    }

    #[test]
    fn nonsense_is_refused() {
        for bad in ["", "  ", "abc", "1.2.3", "-1", "1e9", "1,5"] {
            assert!(parse_amount(bad).is_err(), "`{bad}` should not parse");
        }
    }

    /// Past the money supply is an error rather than a wrap.
    ///
    /// `MONEY_SUPPLY` is `u64::MAX` atomic units, which at eleven decimals is
    /// 184,467,440 whole coins -- not the 184 billion a reader might get by
    /// mis-splitting the digits.
    #[test]
    fn an_amount_past_the_supply_is_refused() {
        assert_eq!(amount(u64::MAX), "184467440.73709551615");

        assert!(parse_amount("184467440").is_ok(), "just under the supply");
        assert!(parse_amount("184467441").is_err(), "just over it");
        assert!(parse_amount("999999999999").is_err());
        // And the exact supply round-trips.
        assert_eq!(parse_amount("184467440.73709551615").expect("ok"), u64::MAX);
    }
}
