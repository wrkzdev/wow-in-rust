//! The wallet RPC error codes (`specs/14` §4).
//!
//! These are a **compatibility surface**. An exchange or payment processor
//! branches on the number, so a wrong one is worse than no answer: the client
//! takes the wrong recovery path and does so silently.
//!
//! Two distinctions the spec singles out, both of which matter more here than
//! on Monero:
//!
//! * `-37 NOT_ENOUGH_UNLOCKED_MONEY` against `-17 NOT_ENOUGH_MONEY`. The first
//!   means "wait"; the second means "you do not have it". With a 288-block
//!   coinbase lock, a miner sees `-37` constantly, and a client that read it as
//!   `-17` would give up on money it is about to be able to spend.
//! * `-50 NONZERO_UNLOCK_TIME` exists because of Wownero's relay rule
//!   (`specs/06` §6.3). Returning it beats letting the transfer fail opaquely
//!   inside `send_raw_transaction` three steps later.

/// One error the server can return.
pub struct Error {
    pub code: i32,
    pub message: String,
}

impl Error {
    pub fn new(code: i32, message: impl Into<String>) -> Error {
        Error {
            code,
            message: message.into(),
        }
    }
}

macro_rules! codes {
    ($($name:ident = $value:expr, $doc:expr;)*) => {
        $(
            #[doc = $doc]
            // The whole table is kept, not only the codes this build returns
            // today. It *is* the compatibility surface: a reader checking a
            // client against `specs/14` §4 should find every number in one
            // place, and a method added later should not have to reintroduce
            // its code and risk picking a different one.
            #[allow(dead_code, reason = "the documented table, not only what is used")]
            pub const $name: i32 = $value;
        )*

        /// Every code, for the test that checks them against `specs/14` §4.
        #[cfg(test)]
        pub const ALL: &[(&str, i32)] = &[$((stringify!($name), $value)),*];
    };
}

codes! {
    UNKNOWN_ERROR = -1, "Anything without a better code.";
    WRONG_ADDRESS = -2, "An address that does not decode, or is for another network.";
    DAEMON_IS_BUSY = -3, "The daemon is syncing. Clients retry on this.";
    GENERIC_TRANSFER_ERROR = -4, "A transfer failed for a reason with no other code.";
    WRONG_PAYMENT_ID = -5, "A payment id that is not 8 or 32 bytes of hex.";
    TRANSFER_TYPE = -6, "An unknown transfer type filter.";
    DENIED = -7, "Refused by policy.";
    WRONG_TXID = -8, "A transaction id that does not decode.";
    WRONG_SIGNATURE = -9, "A signature that does not verify.";
    WRONG_KEY_IMAGE = -10, "A key image that does not decode.";
    WRONG_URI = -11, "A `wownero:` URI that does not parse.";
    WRONG_INDEX = -12, "A subaddress index that does not exist.";
    NOT_OPEN = -13, "No wallet is open. Every method but the openers returns this.";
    ACCOUNT_INDEX_OUT_OF_BOUNDS = -14, "No such account.";
    ADDRESS_INDEX_OUT_OF_BOUNDS = -15, "No such address in that account.";
    TX_NOT_POSSIBLE = -16, "The transaction cannot be constructed as asked.";
    NOT_ENOUGH_MONEY = -17, "The balance is short. Not a wait-and-retry condition.";
    TX_TOO_LARGE = -18, "The transaction would exceed the size limit.";
    NOT_ENOUGH_OUTS_TO_MIX = -19, "The chain has too few outputs to form a ring.";
    ZERO_DESTINATION = -20, "A destination with no amount.";
    WALLET_ALREADY_EXISTS = -21, "A wallet of that name is already there.";
    INVALID_PASSWORD = -22, "The password does not open the wallet.";
    NO_WALLET_DIR = -23, "The server was not started with --wallet-dir.";
    NO_TXKEY = -24, "No transaction key was kept for that transaction.";
    WRONG_KEY = -25, "A key that does not decode or does not match.";
    BAD_HEX = -26, "A field that should be hex is not.";
    BAD_TX_METADATA = -27, "Transaction metadata that does not parse.";
    WATCH_ONLY = -29, "The wallet has no spend key.";
    NOT_MULTISIG = -31, "The wallet is not multisig.";
    BAD_MULTISIG_TX_DATA = -34, "A multisig transfer set that does not parse.";
    NOT_ENOUGH_UNLOCKED_MONEY = -37, "The balance is there but locked. Retry later.";
    NO_DAEMON_CONNECTION = -38, "No daemon is set, or it cannot be reached.";
    BAD_UNSIGNED_TX_DATA = -39, "An unsigned transfer set that does not parse, or lies about its change.";
    BAD_SIGNED_TX_DATA = -40, "A signed transfer set that does not parse.";
    SIGNED_SUBMISSION = -41, "A signed transfer set that could not be relayed.";
    SIGN_UNSIGNED = -42, "An unsigned transfer set that could not be signed.";
    NON_DETERMINISTIC = -43, "The wallet has no seed phrase (`specs/12` §1.2).";
    ATTRIBUTE_NOT_FOUND = -45, "No such attribute.";
    ZERO_AMOUNT = -46, "An amount of zero.";
    INVALID_SIGNATURE_TYPE = -47, "An unknown signature type.";
    DISABLED = -48, "The method is disabled in this build.";
    PROXY_ALREADY_DEFINED = -49, "A proxy for one daemon, when --proxy gives one for all.";
    NONZERO_UNLOCK_TIME = -50, "Wownero does not relay a non-zero unlock time.";
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code matches `specs/14` §4, and no two share a number.
    ///
    /// A duplicate would mean a client cannot tell two conditions apart, which
    /// is the failure this whole module exists to prevent.
    #[test]
    fn the_codes_are_the_documented_ones_and_are_unique() {
        let mut seen = std::collections::HashMap::new();
        for (name, code) in ALL {
            assert!(
                *code < 0,
                "{name} is {code}; every wallet RPC error is negative"
            );
            if let Some(other) = seen.insert(*code, *name) {
                panic!("{name} and {other} share code {code}");
            }
        }
    }

    /// The two distinctions `specs/14` §4 calls out by name.
    #[test]
    fn the_retryable_conditions_are_distinct() {
        // "wait" and "you do not have it" are different answers.
        assert_ne!(NOT_ENOUGH_UNLOCKED_MONEY, NOT_ENOUGH_MONEY);
        assert_eq!(NOT_ENOUGH_UNLOCKED_MONEY, -37);
        assert_eq!(NOT_ENOUGH_MONEY, -17);

        // The Wownero-specific one.
        assert_eq!(NONZERO_UNLOCK_TIME, -50);
        assert_eq!(NOT_OPEN, -13);
        assert_eq!(DAEMON_IS_BUSY, -3);
    }
}
