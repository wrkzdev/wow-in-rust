//! Choosing inputs and working out the fee.
//!
//! `specs/12` §4.4 and §4.5. `wallet2::create_transactions_2`,
//! `estimate_tx_weight`, `estimate_fee`.
//!
//! # The fee is circular
//!
//! The fee depends on the transaction's weight; the weight depends on how many
//! outputs there are; the number of outputs depends on whether there is any
//! change left after the fee. `specs/12` §4.5 resolves it by iterating, up to
//! `FEE_CALCULATION_MAX_RETRIES`, and so does this.
//!
//! The loop converges because each pass can only raise the fee, and raising the
//! fee can only remove the change output — it cannot add one. Two passes settle
//! nearly every transaction.
//!
//! # The weight is estimated, not measured
//!
//! The fee has to be known before the transaction is built, because it is one
//! of the transaction's own fields. So the weight comes from a formula over the
//! input, output and ring counts rather than from a blob. The formula is the
//! reference's, term for term, and it deliberately **over**-estimates in places
//! — a transaction that comes out lighter than estimated pays slightly over the
//! odds, which is fine, where one that comes out heavier would be rejected.

use wow_consensus::fee::{quantize_up, FEE_QUANTIZATION_MASK};
use wow_crypto::types::SubaddressIndex;

use crate::refresh::Transfer;

/// `FEE_CALCULATION_MAX_RETRIES`.
pub const FEE_CALCULATION_MAX_RETRIES: usize = 10;

/// `BULLETPROOF_PLUS_MAX_OUTPUTS`.
pub const MAX_OUTPUTS: usize = 16;

/// The smallest transaction the rules allow: one destination plus change, or a
/// dummy if there is no change (`specs/12` §4.4, the HF 15 rule).
pub const MIN_OUTPUTS: usize = 2;

/// `estimate_rct_tx_size` for the only shape this wallet builds: RCT type 8,
/// CLSAG, Bulletproof+, tagged keys.
///
/// `ring_size` is the whole ring, so the reference's `mixin` is one less.
pub fn estimate_tx_size(
    n_inputs: usize,
    ring_size: usize,
    n_outputs: usize,
    extra_size: usize,
) -> usize {
    let mixin = ring_size.saturating_sub(1);
    let mut size = 0usize;

    // The prefix: a version and an unlock time, then the inputs and outputs.
    size += 1 + 6;
    size += n_inputs * (1 + 6 + (mixin + 1) * 2 + 32);
    size += n_outputs * (6 + 32);
    size += extra_size;

    // The RCT type byte.
    size += 1;

    // The range proof. Note this counts from zero, unlike the clawback below.
    let mut log_padded_outputs = 0usize;
    while (1usize << log_padded_outputs) < n_outputs {
        log_padded_outputs += 1;
    }
    size += (2 * (6 + log_padded_outputs) + 6) * 32 + 3;

    // One CLSAG per input.
    size += n_inputs * (32 * (mixin + 1) + 64);

    // View tags, one byte each.
    size += n_outputs;

    // pseudoOuts, ecdhInfo, outPk, txnFee. `mixRing` is not serialized — it is
    // reconstructed from the key offsets, which is most of what RingCT saves.
    size += 32 * n_inputs;
    size += 8 * n_outputs;
    size += 32 * n_outputs;
    size += 4;

    size
}

/// `estimate_tx_weight`: the size, plus the Bulletproof+ clawback
/// (`specs/05` §5.1).
///
/// The clawback exists so a batched proof does not get its size saving for
/// free. Note `log_padded_outputs` starts at **2** here and at **0** in
/// [`estimate_tx_size`] — a difference in the reference that looks like a bug
/// and is not, because the clawback only applies above two outputs anyway, so
/// the first two iterations would be skipped regardless.
pub fn estimate_tx_weight(
    n_inputs: usize,
    ring_size: usize,
    n_outputs: usize,
    extra_size: usize,
) -> u64 {
    let mut size = estimate_tx_size(n_inputs, ring_size, n_outputs, extra_size) as u64;

    if n_outputs > 2 {
        // A two-output proof's notional size, halved to normalise to one proof.
        let bp_base = (32 * (6 + 7 * 2)) / 2u64;
        let mut log_padded_outputs = 2usize;
        while (1usize << log_padded_outputs) < n_outputs {
            log_padded_outputs += 1;
        }
        let nlr = 2 * (6 + log_padded_outputs) as u64;
        let bp_size = 32 * (6 + nlr);
        size += (bp_base * (1u64 << log_padded_outputs) - bp_size) * 4 / 5;
    }
    size
}

/// `calculate_fee_from_weight`.
pub fn fee_from_weight(base_fee_per_byte: u64, weight: u64) -> u64 {
    quantize_up(weight.saturating_mul(base_fee_per_byte))
}

/// Bytes of `tx_extra` in a transaction [`crate::transfer::construct`] builds.
///
/// The public key is 33. A payment id, real or the dummy that a two-output
/// transaction carries in its place, is 11: the nonce tag, its length, the
/// encrypted-id tag and eight bytes. Paying a subaddress adds a tag, a count
/// and a key per output, and no dummy.
pub fn extra_size(n_outputs: usize, payment_id: bool, any_subaddress: bool) -> usize {
    let mut size = 1 + 32;
    if payment_id || (n_outputs == MIN_OUTPUTS && !any_subaddress) {
        size += 2 + 1 + 8;
    }
    if any_subaddress {
        size += 2 + 32 * n_outputs;
    }
    size
}

/// What a caller is willing to spend and how.
#[derive(Clone, Debug)]
pub struct SpendOptions {
    pub ring_size: usize,
    /// Per-byte fee for the chosen priority, from `get_fee_estimate`.
    pub fee_per_byte: u64,
    /// Bytes `tx_extra` will take. A transaction with a payment id is larger.
    pub extra_size: usize,
    /// Prefer outputs from this account, as `wallet2` does. `None` spends from
    /// anywhere.
    pub from_account: Option<u32>,
    /// `ignore_outputs_above` / `ignore_outputs_below`.
    pub ignore_above: u64,
    pub ignore_below: u64,
    /// The chain height, for the unlock check.
    pub chain_height: u64,
    pub now: u64,
}

impl Default for SpendOptions {
    fn default() -> Self {
        SpendOptions {
            ring_size: crate::decoys::RING_SIZE,
            fee_per_byte: 0,
            extra_size: 44, // the tx public key and an encrypted payment id
            from_account: None,
            ignore_above: u64::MAX,
            ignore_below: 0,
            chain_height: 0,
            now: 0,
        }
    }
}

/// What to build, once the arithmetic has settled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendPlan {
    /// Indices into the transfer list.
    pub inputs: Vec<usize>,
    /// The amount going to each destination, in the order given.
    pub amounts: Vec<u64>,
    /// The change, which the caller sends back to itself. Zero means a dummy
    /// output is still needed to reach two.
    pub change: u64,
    pub fee: u64,
    /// The weight the fee was computed from: the estimate while planning, the
    /// built transaction's own once [`crate::transfer::construct_settled`] has
    /// run.
    pub estimated_weight: u64,
    /// A sweep pays its fee out of the amount sent rather than out of change.
    pub sweep: bool,
}

impl SpendPlan {
    /// Total outputs, including change or the dummy that stands in for it.
    pub fn output_count(&self) -> usize {
        (self.amounts.len() + 1).max(MIN_OUTPUTS)
    }

    /// The same inputs and destinations at another fee.
    ///
    /// The difference comes out of the change or, for a sweep, out of the
    /// amount sent. A fee the inputs cannot cover is [`SpendError::NotEnough`];
    /// the C++ would go back for another input, which this does not, because
    /// the fee only moves by the few bytes the estimate was off by.
    pub fn with_fee(&self, fee: u64) -> Result<SpendPlan, SpendError> {
        let sending: u64 = self.amounts.iter().sum();
        let in_total = sending + self.change + self.fee;
        let mut next = self.clone();
        next.fee = fee;
        if self.sweep {
            if fee >= in_total {
                return Err(SpendError::NotEnough {
                    available: in_total,
                    needed: fee,
                    fee,
                });
            }
            next.amounts = vec![in_total - fee];
        } else {
            let needed = sending.saturating_add(fee);
            if needed > in_total {
                return Err(SpendError::NotEnough {
                    available: in_total,
                    needed,
                    fee,
                });
            }
            next.change = in_total - needed;
        }
        Ok(next)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpendError {
    #[error("nothing to send")]
    NoDestinations,
    #[error("{0} destinations plus change is past the limit of {MAX_OUTPUTS} outputs")]
    TooManyDestinations(usize),
    #[error("a destination amount is zero")]
    ZeroAmount,
    #[error(
        "not enough unlocked funds: {available} available, {needed} needed including a fee of {fee}"
    )]
    NotEnough {
        available: u64,
        needed: u64,
        fee: u64,
    },
    #[error("the fee did not settle after {0} attempts")]
    FeeDidNotSettle(usize),
}

/// Which transfers are eligible to spend.
///
/// Unspent, unlocked, with a key image known — a view-only wallet has none, so
/// it can select nothing, which is the correct answer rather than an error the
/// caller has to special-case.
pub fn spendable<'a>(
    transfers: &'a [Transfer],
    options: &SpendOptions,
) -> Vec<(usize, &'a Transfer)> {
    transfers
        .iter()
        .enumerate()
        .filter(|(_, t)| !t.spent && t.key_image.is_some())
        .filter(|(_, t)| t.unlocked(options.chain_height, options.now))
        .filter(|(_, t)| t.amount >= options.ignore_below && t.amount <= options.ignore_above)
        .filter(|(_, t)| match options.from_account {
            Some(a) => t.subaddress.major == a,
            None => true,
        })
        .collect()
}

/// Plan a transaction: pick inputs, settle the fee.
///
/// `destinations` are the amounts going out, not counting change. The caller
/// supplies the addresses; this only does arithmetic, because which address
/// change goes to is a policy question and the amounts are not.
pub fn plan(
    transfers: &[Transfer],
    destinations: &[u64],
    options: &SpendOptions,
) -> Result<SpendPlan, SpendError> {
    if destinations.is_empty() {
        return Err(SpendError::NoDestinations);
    }
    if destinations.contains(&0) {
        return Err(SpendError::ZeroAmount);
    }
    // Plus one for change, and at least two outputs in total.
    if destinations.len() + 1 > MAX_OUTPUTS {
        return Err(SpendError::TooManyDestinations(destinations.len()));
    }

    let sending: u64 = destinations.iter().copied().sum();

    // Largest first. `wallet2` has a more careful policy — it prefers dust and
    // avoids leaving unspendable remainders — but largest-first uses the fewest
    // inputs, and each input costs both weight and a ring to fetch.
    let mut candidates = spendable(transfers, options);
    candidates.sort_by_key(|(_, t)| std::cmp::Reverse(t.amount));
    let available: u64 = candidates.iter().map(|(_, t)| t.amount).sum();

    let mut chosen: Vec<usize> = Vec::new();
    let mut in_total = 0u64;
    let mut fee = 0u64;
    let mut weight = 0u64;

    for _ in 0..FEE_CALCULATION_MAX_RETRIES {
        // Take inputs until they cover the send plus the fee we currently
        // believe in.
        let target = sending.saturating_add(fee);
        while in_total < target {
            let Some((i, t)) = candidates.get(chosen.len()) else {
                return Err(SpendError::NotEnough {
                    available,
                    needed: target,
                    fee,
                });
            };
            chosen.push(*i);
            in_total += t.amount;
        }

        // The change output exists unless it would be zero — and even then an
        // output is needed to reach two, so the count is the same either way.
        let outputs = (destinations.len() + 1).max(MIN_OUTPUTS);
        let next_weight =
            estimate_tx_weight(chosen.len(), options.ring_size, outputs, options.extra_size);
        let next_fee = fee_from_weight(options.fee_per_byte, next_weight);

        if next_fee == fee && in_total >= sending + fee {
            weight = next_weight;
            let change = in_total - sending - fee;
            return Ok(SpendPlan {
                inputs: chosen,
                amounts: destinations.to_vec(),
                change,
                fee,
                estimated_weight: weight,
                sweep: false,
            });
        }
        fee = next_fee;
        weight = next_weight;
    }

    // The loop only ever raises the fee, so failing to settle means the inputs
    // could not keep up with it.
    Err(if in_total < sending.saturating_add(fee) {
        SpendError::NotEnough {
            available,
            needed: sending.saturating_add(fee),
            fee,
        }
    } else {
        let _ = weight;
        SpendError::FeeDidNotSettle(FEE_CALCULATION_MAX_RETRIES)
    })
}

/// Plan a sweep: send **everything** eligible to one destination.
///
/// The difference from [`plan`] is that the amount is an output of the
/// calculation rather than an input — the fee comes out of what is being sent,
/// so there is no change and the destination gets whatever is left.
pub fn plan_sweep(transfers: &[Transfer], options: &SpendOptions) -> Result<SpendPlan, SpendError> {
    let candidates = spendable(transfers, options);
    if candidates.is_empty() {
        return Err(SpendError::NotEnough {
            available: 0,
            needed: 0,
            fee: 0,
        });
    }

    let inputs: Vec<usize> = candidates.iter().map(|(i, _)| *i).collect();
    let in_total: u64 = candidates.iter().map(|(_, t)| t.amount).sum();

    // A sweep still needs two outputs, so the second is a zero-amount dummy.
    let weight = estimate_tx_weight(
        inputs.len(),
        options.ring_size,
        MIN_OUTPUTS,
        options.extra_size,
    );
    let fee = fee_from_weight(options.fee_per_byte, weight);
    if fee >= in_total {
        return Err(SpendError::NotEnough {
            available: in_total,
            needed: fee,
            fee,
        });
    }

    Ok(SpendPlan {
        inputs,
        amounts: vec![in_total - fee],
        change: 0,
        fee,
        estimated_weight: weight,
        sweep: true,
    })
}

/// The subaddress account an output belongs to, for change.
pub fn change_index(plan: &SpendPlan, transfers: &[Transfer]) -> SubaddressIndex {
    plan.inputs
        .first()
        .and_then(|i| transfers.get(*i))
        .map(|t| SubaddressIndex::new(t.subaddress.major, 0))
        .unwrap_or(SubaddressIndex::MAIN)
}

/// The quantization the fee is rounded to. Exposed so a caller can say why a
/// fee has the shape it does.
pub const fn quantization() -> u64 {
    FEE_QUANTIZATION_MASK
}

#[cfg(test)]
mod tests {
    use super::*;
    use wow_crypto::types::{KeyImage, PublicKey};

    fn transfer(amount: u64, height: u64, seed: u8) -> Transfer {
        Transfer {
            block_height: height,
            txid: [seed; 32],
            derivation: wow_crypto::types::KeyDerivation::ZERO,
            internal_output_index: 0,
            global_output_index: seed as u64,
            public_key: PublicKey([seed; 32]),
            key_image: Some(KeyImage([seed; 32])),
            mask: [0u8; 32],
            amount,
            subaddress: SubaddressIndex::MAIN,
            spent: false,
            spent_height: 0,
            unlock_time: 0,
            is_coinbase: false,
            timestamp: 0,
        }
    }

    fn options(fee_per_byte: u64) -> SpendOptions {
        SpendOptions {
            fee_per_byte,
            chain_height: 1_000,
            now: 1_700_000_000,
            ..Default::default()
        }
    }

    /// The estimator grows the way the transaction does: with inputs, with
    /// outputs, and with the ring.
    #[test]
    fn the_estimate_grows_with_the_transaction() {
        let base = estimate_tx_weight(1, 22, 2, 44);
        assert!(base > 1_000, "a one-in two-out ring-22 tx is over a kB");

        assert!(estimate_tx_weight(2, 22, 2, 44) > base, "another input");
        assert!(estimate_tx_weight(1, 22, 3, 44) > base, "another output");
        assert!(estimate_tx_weight(1, 32, 2, 44) > base, "a larger ring");
        assert_eq!(
            estimate_tx_weight(1, 22, 2, 100) - base,
            56,
            "extra bytes pass straight through"
        );
    }

    /// The clawback applies above two outputs and not at or below, which is
    /// what makes batching cost something.
    #[test]
    fn the_clawback_starts_above_two_outputs() {
        let size2 = estimate_tx_size(1, 22, 2, 44) as u64;
        let weight2 = estimate_tx_weight(1, 22, 2, 44);
        assert_eq!(size2, weight2, "no clawback at two outputs");

        let size3 = estimate_tx_size(1, 22, 3, 44) as u64;
        let weight3 = estimate_tx_weight(1, 22, 3, 44);
        assert!(weight3 > size3, "three outputs pay a clawback");
    }

    /// The fee is the weight times the per-byte rate, rounded up to the
    /// quantization — 1,000, not Monero's 10,000, because of the extra decimal.
    #[test]
    fn the_fee_is_quantized() {
        assert_eq!(quantization(), 1_000);

        // 1,234 weight at 3 per byte is 3,702, which rounds to 4,000.
        assert_eq!(fee_from_weight(3, 1_234), 4_000);
        // An exact multiple is left alone.
        assert_eq!(fee_from_weight(1, 2_000), 2_000);
        // Zero stays zero.
        assert_eq!(fee_from_weight(0, 5_000), 0);
        // Every fee is a multiple of the mask.
        for w in [1u64, 999, 1_000, 1_001, 123_456] {
            assert_eq!(fee_from_weight(7, w) % 1_000, 0, "weight {w}");
        }
    }

    /// A plan covers the destinations and the fee, and the change balances.
    #[test]
    fn a_plan_balances() {
        let transfers = vec![transfer(10_000_000_000, 100, 1)];
        let p = plan(&transfers, &[4_000_000_000], &options(3)).expect("a plan");

        assert_eq!(p.inputs, vec![0]);
        assert_eq!(p.amounts, vec![4_000_000_000]);
        assert!(p.fee > 0);
        assert_eq!(
            p.change + p.amounts[0] + p.fee,
            10_000_000_000,
            "inputs equal outputs plus fee"
        );
        assert_eq!(p.output_count(), 2, "one destination plus change");
    }

    /// A zero fee rate still produces a balanced plan, which is the degenerate
    /// case a test network runs at.
    #[test]
    fn a_zero_fee_rate_plans() {
        let transfers = vec![transfer(5_000, 100, 1)];
        let p = plan(&transfers, &[3_000], &options(0)).expect("a plan");
        assert_eq!(p.fee, 0);
        assert_eq!(p.change, 2_000);
    }

    /// Several inputs are taken, largest first, until the target is covered.
    #[test]
    fn it_takes_the_fewest_inputs() {
        let transfers = vec![
            transfer(1_000_000_000, 100, 1),
            transfer(9_000_000_000, 100, 2),
            transfer(3_000_000_000, 100, 3),
        ];
        let p = plan(&transfers, &[8_000_000_000], &options(3)).expect("a plan");
        assert_eq!(p.inputs, vec![1], "the 9 WOW output alone covers it");

        let p = plan(&transfers, &[11_000_000_000], &options(3)).expect("a plan");
        assert_eq!(p.inputs, vec![1, 2], "largest first");
    }

    /// Not enough money is an error that says how much was available.
    #[test]
    fn not_enough_is_reported_with_the_numbers() {
        let transfers = vec![transfer(1_000, 100, 1)];
        let e = plan(&transfers, &[5_000], &options(3)).expect_err("too little");
        match e {
            SpendError::NotEnough {
                available, needed, ..
            } => {
                assert_eq!(available, 1_000);
                assert!(needed >= 5_000);
            }
            other => panic!("{other}"),
        }
    }

    /// Locked, spent and view-only outputs are not spendable.
    #[test]
    fn ineligible_outputs_are_skipped() {
        let mut spent = transfer(9_000_000_000, 100, 1);
        spent.spent = true;

        let mut locked = transfer(9_000_000_000, 999, 2);
        locked.unlock_time = 5_000; // a height far ahead

        let mut no_image = transfer(9_000_000_000, 100, 3);
        no_image.key_image = None;

        let good = transfer(9_000_000_000, 100, 4);
        let transfers = vec![spent, locked, no_image, good];

        let eligible = spendable(&transfers, &options(3));
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].0, 3, "only the last one");

        let p = plan(&transfers, &[1_000_000], &options(3)).expect("a plan");
        assert_eq!(p.inputs, vec![3]);
    }

    /// An output too young to spend is skipped: four confirmations, per
    /// `specs/12` §4.2.
    #[test]
    fn the_spendable_age_is_respected() {
        let transfers = vec![transfer(9_000_000_000, 998, 1)];
        // Height 1,000 means the output is two blocks old.
        assert!(spendable(&transfers, &options(3)).is_empty());

        let mut later = options(3);
        later.chain_height = 1_002;
        assert_eq!(spendable(&transfers, &later).len(), 1);
    }

    /// `ignore_above` and `ignore_below` are honoured.
    #[test]
    fn the_ignore_thresholds_are_honoured() {
        let transfers = vec![
            transfer(100, 100, 1),
            transfer(50_000, 100, 2),
            transfer(9_000_000_000, 100, 3),
        ];

        let mut o = options(3);
        o.ignore_below = 1_000;
        o.ignore_above = 1_000_000;
        let eligible = spendable(&transfers, &o);
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].1.amount, 50_000);
    }

    /// Spending is confined to one account when asked.
    #[test]
    fn it_can_spend_from_one_account() {
        let mut other = transfer(9_000_000_000, 100, 1);
        other.subaddress = SubaddressIndex::new(3, 7);
        let mine = transfer(8_000_000_000, 100, 2);
        let transfers = vec![other, mine];

        let mut o = options(3);
        o.from_account = Some(0);
        let eligible = spendable(&transfers, &o);
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].0, 1);

        o.from_account = Some(3);
        assert_eq!(spendable(&transfers, &o)[0].0, 0);
    }

    /// The fee settles: the plan's fee is what its own weight implies, so a
    /// node recomputing it agrees.
    #[test]
    fn the_fee_settles_at_a_fixed_point() {
        let transfers = vec![
            transfer(3_000_000_000, 100, 1),
            transfer(3_000_000_000, 100, 2),
            transfer(3_000_000_000, 100, 3),
        ];
        let p = plan(&transfers, &[7_000_000_000], &options(11)).expect("a plan");

        let recomputed = fee_from_weight(
            11,
            estimate_tx_weight(p.inputs.len(), 22, p.output_count(), 44),
        );
        assert_eq!(p.fee, recomputed, "the fee matches its own weight");
        assert_eq!(
            p.estimated_weight,
            estimate_tx_weight(p.inputs.len(), 22, p.output_count(), 44)
        );
    }

    /// Too many destinations is refused, counting the change output.
    #[test]
    fn too_many_destinations_is_refused() {
        let transfers = vec![transfer(u64::MAX / 2, 100, 1)];
        let many: Vec<u64> = (0..MAX_OUTPUTS as u64).map(|i| i + 1).collect();
        assert_eq!(
            plan(&transfers, &many, &options(3)),
            Err(SpendError::TooManyDestinations(MAX_OUTPUTS))
        );

        // One fewer leaves room for change.
        let ok: Vec<u64> = (0..MAX_OUTPUTS as u64 - 1).map(|i| i + 1).collect();
        assert!(plan(&transfers, &ok, &options(3)).is_ok());
    }

    /// Degenerate requests are refused rather than planned.
    #[test]
    fn degenerate_requests_are_refused() {
        let transfers = vec![transfer(1_000_000, 100, 1)];
        assert_eq!(
            plan(&transfers, &[], &options(3)),
            Err(SpendError::NoDestinations)
        );
        assert_eq!(
            plan(&transfers, &[100, 0], &options(3)),
            Err(SpendError::ZeroAmount)
        );
    }

    /// A sweep takes everything and pays the fee out of it, leaving no change.
    #[test]
    fn a_sweep_takes_everything() {
        let transfers = vec![
            transfer(3_000_000_000, 100, 1),
            transfer(4_000_000_000, 100, 2),
            transfer(5_000_000_000, 100, 3),
        ];
        let p = plan_sweep(&transfers, &options(3)).expect("a sweep");

        assert_eq!(p.inputs.len(), 3, "every eligible output");
        assert_eq!(p.change, 0, "a sweep leaves nothing behind");
        assert_eq!(
            p.amounts[0] + p.fee,
            12_000_000_000,
            "the fee comes out of the amount"
        );
        assert_eq!(p.output_count(), 2, "still two outputs, the second a dummy");
    }

    /// A sweep of nothing, and a sweep that cannot cover its own fee, are
    /// errors rather than transactions that would be rejected.
    #[test]
    fn a_sweep_that_cannot_pay_is_refused() {
        assert!(plan_sweep(&[], &options(3)).is_err());

        let dust = vec![transfer(10, 100, 1)];
        let e = plan_sweep(&dust, &options(1_000)).expect_err("cannot pay");
        assert!(matches!(e, SpendError::NotEnough { .. }), "{e}");
    }

    /// Change goes back to the account the inputs came from, at its main
    /// address.
    #[test]
    fn change_returns_to_the_spending_account() {
        let mut t = transfer(9_000_000_000, 100, 1);
        t.subaddress = SubaddressIndex::new(2, 5);
        let transfers = vec![t];

        let mut o = options(3);
        o.from_account = Some(2);
        let p = plan(&transfers, &[1_000_000], &o).expect("a plan");
        assert_eq!(change_index(&p, &transfers), SubaddressIndex::new(2, 0));
    }

    /// A new fee moves the change and leaves what the payee gets alone.
    #[test]
    fn a_new_fee_moves_the_change() {
        let transfers = vec![transfer(10_000_000_000, 100, 1)];
        let p = plan(&transfers, &[4_000_000_000], &options(3)).expect("a plan");
        assert!(!p.sweep);

        let lower = p.with_fee(p.fee - 1_000).expect("a lower fee");
        assert_eq!(lower.amounts, p.amounts, "the payee is untouched");
        assert_eq!(lower.change, p.change + 1_000);
        assert_eq!(lower.inputs, p.inputs);

        let higher = p.with_fee(p.fee + 5_000).expect("a higher fee");
        assert_eq!(higher.change, p.change - 5_000);

        assert!(matches!(
            p.with_fee(p.fee + p.change + 1),
            Err(SpendError::NotEnough { .. })
        ));
    }

    /// A sweep's new fee comes out of the amount, and there is still no change.
    #[test]
    fn a_new_fee_on_a_sweep_moves_the_amount() {
        let transfers = vec![transfer(7_000_000_000, 100, 1)];
        let p = plan_sweep(&transfers, &options(3)).expect("a sweep");
        assert!(p.sweep);

        let lower = p.with_fee(p.fee - 1_000).expect("a lower fee");
        assert_eq!(lower.change, 0);
        assert_eq!(lower.amounts[0], p.amounts[0] + 1_000);
        assert_eq!(lower.amounts[0] + lower.fee, 7_000_000_000);

        assert!(matches!(
            p.with_fee(7_000_000_000),
            Err(SpendError::NotEnough { .. })
        ));
    }

    /// The usual transaction's `tx_extra` is 44 bytes with or without a
    /// payment id, because a dummy stands in for a missing one.
    #[test]
    fn the_extra_size_counts_the_dummy_payment_id() {
        assert_eq!(extra_size(2, false, false), 44, "a dummy");
        assert_eq!(extra_size(2, true, false), 44, "a real one, the same size");
        assert_eq!(extra_size(3, false, false), 33, "no dummy past two outputs");
        assert_eq!(extra_size(3, true, false), 44);
        assert_eq!(extra_size(2, false, true), 33 + 2 + 64, "keys, no dummy");
        assert_eq!(
            SpendOptions::default().extra_size,
            extra_size(2, false, false)
        );
    }
}
