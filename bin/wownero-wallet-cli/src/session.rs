//! The CLI's view of an open wallet.
//!
//! The substance lives in [`wow_wallet::files`], because the RPC server needs
//! the same thing. What stays here is display.

pub use wow_wallet::files::{now, Paths, Session};

use crate::fmt;

/// Format a balance line the way `balance` prints it.
pub fn balance_line(balance: u64, unlocked: u64) -> String {
    if balance == unlocked {
        format!("Balance: {}, all unlocked", fmt::amount(balance))
    } else {
        format!(
            "Balance: {}, unlocked: {} ({} still locked)",
            fmt::amount(balance),
            fmt::amount(unlocked),
            fmt::amount(balance - unlocked)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_balance_line_separates_locked_funds() {
        assert_eq!(
            balance_line(100_000_000_000, 100_000_000_000),
            "Balance: 1.00000000000, all unlocked"
        );
        let line = balance_line(100_000_000_000, 40_000_000_000);
        assert!(line.contains("unlocked: 0.40000000000"), "{line}");
        assert!(line.contains("0.60000000000 still locked"), "{line}");
    }
}
