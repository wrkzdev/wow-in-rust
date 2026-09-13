//! Transaction weight and the Bulletproof clawback.
//!
//! `specs/05-blocks-and-transactions.md` §5.1. The clawback makes a batched
//! range proof pay roughly what individual proofs would have cost, so that
//! batching does not under-pay fees.
//!
//! Distinguish carefully (`specs/05` §5):
//!
//! | Term | Meaning |
//! |---|---|
//! | blob size | `serialize(tx).len()` |
//! | tx weight | blob size + the clawback below |
//! | block weight | coinbase **blob size** + sum of tx **weights** |

use crate::limits::BULLETPROOF_MAX_OUTPUTS;
use crate::rct::RctType;
use crate::tx::Transaction;

/// `get_transaction_weight(tx, blob_size)`.
///
/// Returns the blob size unchanged for everything that does not carry a batched
/// range proof: v1 transactions, non-Bulletproof RCT, `vout.len() <= 2`, and
/// the old Bulletproof types 3 and 4.
pub fn get_transaction_weight(tx: &Transaction, blob_size: usize) -> u64 {
    let blob = blob_size as u64;
    if tx.prefix.version < 2 {
        return blob;
    }
    let ty = tx.rct_signatures.ty;
    let bp = ty.is_bulletproof();
    let bpp = ty.is_bulletproof_plus();
    if !bp && !bpp {
        return blob;
    }
    if tx.prefix.vout.len() <= 2 {
        return blob;
    }
    if ty.is_old_bulletproof() {
        return blob;
    }
    let Some(n_padded) = tx.rct_signatures.n_padded_outputs() else {
        return blob;
    };
    blob + clawback(ty, tx.prefix.vout.len(), n_padded)
}

/// The Bulletproof(+) clawback (`specs/05` §5.1).
///
/// ```text
/// bp_base = (32 * ((plus ? 6 : 9) + 7 * 2)) / 2     // plus: 320, else 368
/// nlr     = ceil(log2(n_padded_outputs)) + 6
/// bp_size = 32 * ((plus ? 6 : 9) + 2 * nlr)
/// clawback = (bp_base * n_padded_outputs - bp_size) * 4 / 5
/// ```
///
/// The `4/5` factor and the `bp_base` difference between BP and BP+ are both
/// consensus.
pub fn clawback(ty: RctType, n_outputs: usize, n_padded_outputs: usize) -> u64 {
    let plus = ty.is_bulletproof_plus();
    let fields: usize = if plus { 6 } else { 9 };
    let bp_base = (32 * (fields + 7 * 2)) / 2;
    debug_assert_eq!(bp_base, if plus { 320 } else { 368 });

    if n_padded_outputs <= 2 {
        return 0;
    }
    let mut nlr = 0usize;
    while (1usize << nlr) < n_padded_outputs {
        nlr += 1;
    }
    nlr += 6;
    let bp_size = 32 * (fields + 2 * nlr);

    // The C asserts both of these. A blob that violates them is malformed
    // rather than merely expensive, so saturate instead of panicking.
    debug_assert!(n_outputs <= BULLETPROOF_MAX_OUTPUTS);
    debug_assert!(bp_base * n_padded_outputs >= bp_size);
    let _ = n_outputs;

    let lhs = (bp_base as u64).saturating_mul(n_padded_outputs as u64);
    lhs.saturating_sub(bp_size as u64) * 4 / 5
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two `bp_base` values the formula produces. Getting either wrong
    /// changes every batched transaction's fee.
    #[test]
    fn bp_base_values() {
        // BP+: (32 * (6 + 14)) / 2 = 320.  BP: (32 * (9 + 14)) / 2 = 368.
        assert_eq!((32 * (6 + 7 * 2)) / 2, 320);
        assert_eq!((32 * (9 + 7 * 2)) / 2, 368);
    }

    #[test]
    fn no_clawback_for_two_or_fewer_padded_outputs() {
        for ty in [RctType::BulletproofPlus, RctType::Clsag] {
            assert_eq!(clawback(ty, 1, 1), 0);
            assert_eq!(clawback(ty, 2, 2), 0);
        }
    }

    /// Worked values for BP+, the only type on mainnet today.
    #[test]
    fn bulletproof_plus_clawback_values() {
        let t = RctType::BulletproofPlus;
        // n_padded = 4: nlr = 2 + 6 = 8, bp_size = 32 * (6 + 16) = 704.
        // (320*4 - 704) * 4 / 5 = (1280 - 704) * 4 / 5 = 576 * 4 / 5 = 460.
        assert_eq!(clawback(t, 3, 4), 460);
        // n_padded = 8: nlr = 3 + 6 = 9, bp_size = 32 * (6 + 18) = 768.
        // (2560 - 768) * 4 / 5 = 1792 * 4 / 5 = 1433 (truncating).
        assert_eq!(clawback(t, 5, 8), 1433);
        // n_padded = 16: nlr = 4 + 6 = 10, bp_size = 32 * (6 + 20) = 832.
        // (5120 - 832) * 4 / 5 = 4288 * 4 / 5 = 3430 (truncating).
        assert_eq!(clawback(t, 16, 16), 3430);
    }

    #[test]
    fn bulletproof_clawback_differs_from_plus() {
        // Same padding, different bp_base -> a different clawback.
        assert_ne!(
            clawback(RctType::Clsag, 3, 4),
            clawback(RctType::BulletproofPlus, 3, 4)
        );
        // BP: n_padded = 4, nlr = 8, bp_size = 32 * (9 + 16) = 800.
        // (368*4 - 800) * 4 / 5 = (1472 - 800) * 4 / 5 = 672 * 4 / 5 = 537.
        assert_eq!(clawback(RctType::Clsag, 3, 4), 537);
    }

    /// The division truncates, so the result is not `(x * 4) / 5` rounded.
    #[test]
    fn the_four_fifths_factor_truncates() {
        // 1792 * 4 = 7168; 7168 / 5 = 1433.6 -> 1433.
        assert_eq!(1792u64 * 4 / 5, 1433);
        assert_eq!(clawback(RctType::BulletproofPlus, 5, 8), 1433);
    }

    #[test]
    fn weight_equals_blob_size_for_the_exempt_cases() {
        use crate::tx::{TransactionPrefix, TxIn, TxOut, TxOutTarget};
        use wow_crypto::types::{KeyImage, PublicKey};

        let out = || TxOut {
            amount: 0,
            target: TxOutTarget::ToKey {
                key: PublicKey([1; 32]),
            },
        };
        let mk = |version: u64, ty: RctType, n_out: usize| Transaction {
            prefix: TransactionPrefix {
                version,
                unlock_time: 0,
                vin: vec![TxIn::ToKey {
                    amount: 0,
                    key_offsets: vec![1; 22],
                    k_image: KeyImage([2; 32]),
                }],
                vout: (0..n_out).map(|_| out()).collect(),
                extra: vec![],
            },
            rct_signatures: crate::rct::RctSignatures {
                ty,
                ..Default::default()
            },
            ..Default::default()
        };

        // v1: always the blob size.
        assert_eq!(get_transaction_weight(&mk(1, RctType::Null, 5), 1000), 1000);
        // Non-bulletproof RCT.
        assert_eq!(
            get_transaction_weight(&mk(2, RctType::Simple, 5), 1000),
            1000
        );
        // <= 2 outputs.
        assert_eq!(
            get_transaction_weight(&mk(2, RctType::BulletproofPlus, 2), 1000),
            1000
        );
        // The old bulletproof types are exempt whatever the output count.
        assert_eq!(
            get_transaction_weight(&mk(2, RctType::SimpleBulletproof, 5), 1000),
            1000
        );
    }
}
