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

use wow_consensus::constants;
use wow_consensus::fee::{quantize_up, FEE_QUANTIZATION_MASK};
use wow_crypto::types::{KeyImage, SubaddressIndex};

use crate::refresh::Transfer;

/// `FEE_CALCULATION_MAX_RETRIES`.
pub const FEE_CALCULATION_MAX_RETRIES: usize = 10;

/// `BULLETPROOF_PLUS_MAX_OUTPUTS`.
pub const MAX_OUTPUTS: usize = 16;

/// The heaviest transaction this wallet will build:
/// `TX_WEIGHT_TARGET(get_upper_transaction_weight_limit())`.
///
/// `get_upper_transaction_weight_limit` is `full_reward_zone / 2` less the
/// coinbase reserve, and `TX_WEIGHT_TARGET` takes two thirds of that. The
/// reference derives the zone from the daemon's current median; this uses the
/// constant, which is what the daemon reports unless blocks have been running
/// large, and errs small -- a transaction under the limit is relayed whatever
/// the median is doing, where one over it is refused after the wallet has
/// already fetched every ring and signed every input.
///
/// At ring size 22 an input costs about 880 bytes, so this is a little over a
/// hundred of them in one transaction.
pub const fn default_weight_limit() -> u64 {
    let upper =
        constants::BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2 - constants::COINBASE_BLOB_RESERVED_SIZE as u64;
    upper * 2 / 3
}

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
    /// The heaviest transaction to build. See [`default_weight_limit`].
    pub weight_limit: u64,
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
            weight_limit: default_weight_limit(),
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
    /// Outputs a sweep left behind because taking them would have made the
    /// transaction too heavy to relay.
    ///
    /// Zero for every other plan, and for a sweep that took everything. When
    /// it is not zero the caller has to say so: someone who asked to sweep a
    /// wallet and was told nothing would reasonably believe it is now empty.
    pub left_behind: usize,
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

/// An amount in WOW, as a person reads it: `12`, `0.0003`, with no trailing
/// zeros. What an error says is in these, not in atomic units, which read as a
/// hundred billion times too much.
pub fn money(atomic: u64) -> String {
    use wow_consensus::constants::{COIN, CRYPTONOTE_DISPLAY_DECIMAL_POINT};
    let (whole, frac) = (atomic / COIN, atomic % COIN);
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!(
        "{frac:0width$}",
        width = CRYPTONOTE_DISPLAY_DECIMAL_POINT as usize
    );
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

fn wow(atomic: &u64) -> String {
    format!("{} WOW", money(*atomic))
}

/// Before any input is picked there is no fee yet, and "a fee of 0" would
/// say there is none to pay.
fn fee_note(fee: &u64) -> String {
    if *fee == 0 {
        String::new()
    } else {
        format!(", including a fee of {}", wow(fee))
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
        "not enough unlocked funds: {} available, {} needed{}",
        wow(.available),
        wow(.needed),
        fee_note(.fee)
    )]
    NotEnough {
        available: u64,
        needed: u64,
        fee: u64,
    },
    #[error("the fee did not settle after {0} attempts")]
    FeeDidNotSettle(usize),
    #[error(
        "the transaction would weigh {weight}, over the {limit} a node will relay: \
         send a smaller amount, or sweep, which splits by weight"
    )]
    TooHeavy { weight: u64, limit: u64 },
    #[error("this wallet has no output with that key image")]
    NoSuchOutput,
    #[error("that output has already been spent")]
    OutputSpent,
    #[error("that output is not spendable yet: it is locked, or too new")]
    OutputLocked,
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
    rng: &mut dyn crate::decoys::RandomSource,
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

    let mut candidates = spendable(transfers, options);
    let available: u64 = candidates.iter().map(|(_, t)| t.amount).sum();

    let mut chosen: Vec<usize> = Vec::new();
    let mut in_total = 0u64;
    let mut fee = 0u64;
    let mut weight = 0u64;

    for _ in 0..FEE_CALCULATION_MAX_RETRIES {
        // Take inputs until they cover the send plus the fee we currently
        // believe in. Inputs already taken are kept: the loop only ever raises
        // the fee, so a second pass appends rather than starting over, and the
        // choice does not wobble as the fee settles.
        let target = sending.saturating_add(fee);
        while in_total < target {
            let need = target - in_total;
            let Some(pick) = choose_input(&candidates, need, rng) else {
                return Err(SpendError::NotEnough {
                    available,
                    needed: target,
                    fee,
                });
            };
            let (i, t) = candidates.swap_remove(pick);
            chosen.push(i);
            in_total += t.amount;
        }

        // The change output exists unless it would be zero — and even then an
        // output is needed to reach two, so the count is the same either way.
        let outputs = (destinations.len() + 1).max(MIN_OUTPUTS);
        let next_weight =
            estimate_tx_weight(chosen.len(), options.ring_size, outputs, options.extra_size);

        // Refused here rather than by the node. A wallet that built one anyway
        // would find out only after fetching a ring for every input and
        // signing each one -- the slowest, most expensive way to learn it.
        if next_weight > options.weight_limit {
            return Err(SpendError::TooHeavy {
                weight: next_weight,
                limit: options.weight_limit,
            });
        }
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
                left_behind: 0,
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

/// Which output pays next.
///
/// # Why this is not simply the largest
///
/// Largest-first is the obvious policy and it is a fingerprint. Every wallet
/// that uses it produces transactions whose inputs, seen from outside, are
/// exactly the outputs an observer would have guessed — which is a signature
/// that says *this* software built *this* transaction, and one more fact to
/// hang on whoever sent it. `decoys.rs` makes this argument at length about
/// ring members; it applies just as much to the real spend.
///
/// So: among the outputs that could finish the job on their own, one is taken
/// **at random**. That keeps the input count as low as largest-first would --
/// each input costs weight, a fee and a ring to fetch -- while making which
/// output pays unpredictable from the amounts alone. Only when nothing left
/// can cover what remains does it fall back to taking the largest, because at
/// that point every remaining output will be needed anyway and the order
/// stops mattering.
///
/// `wallet2` reaches for the same two ideas from a different direction:
/// `pick_preferred_rct_inputs` looks for a single output that covers the
/// amount, and `select_transfers` picks at random among what is left.
fn choose_input(
    candidates: &[(usize, &Transfer)],
    need: u64,
    rng: &mut dyn crate::decoys::RandomSource,
) -> Option<usize> {
    if candidates.is_empty() {
        return None;
    }
    let finishers: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, (_, t))| t.amount >= need)
        .map(|(pos, _)| pos)
        .collect();
    if !finishers.is_empty() {
        let pick = rng.below(finishers.len() as u64) as usize;
        return Some(finishers[pick]);
    }
    // Nothing covers the rest by itself, so every remaining output is going to
    // be needed. Take the largest to get there in the fewest.
    candidates
        .iter()
        .enumerate()
        .max_by_key(|(_, (_, t))| t.amount)
        .map(|(pos, _)| pos)
}

/// Plan a sweep: send **everything** eligible to one destination.
///
/// The difference from [`plan`] is that the amount is an output of the
/// calculation rather than an input — the fee comes out of what is being sent,
/// so there is no change and the destination gets whatever is left.
pub fn plan_sweep(transfers: &[Transfer], options: &SpendOptions) -> Result<SpendPlan, SpendError> {
    let mut candidates = spendable(transfers, options);
    if candidates.is_empty() {
        return Err(SpendError::NotEnough {
            available: 0,
            needed: 0,
            fee: 0,
        });
    }

    // Largest first, so a sweep that cannot take everything takes the most
    // money it can and leaves the smallest outputs for the next one.
    candidates.sort_by_key(|(_, t)| std::cmp::Reverse(t.amount));

    // How many inputs fit. At ring size 22 an input costs about 880 bytes, so
    // a wallet with a few hundred outputs used to produce a transaction
    // several times over the relay limit: perfectly valid, signed, and
    // refused by every node it was offered to.
    //
    // `wallet2` splits a sweep across as many transactions as it needs. This
    // builds one and reports what it left, so sweeping such a wallet is
    // running `sweep_all` until it says it took everything. Less convenient,
    // and it never signs a transaction that cannot be relayed.
    let mut n = 0usize;
    while n < candidates.len() {
        // A sweep still needs two outputs, so the second is a zero-amount
        // dummy.
        let weight = estimate_tx_weight(n + 1, options.ring_size, MIN_OUTPUTS, options.extra_size);
        if weight > options.weight_limit {
            break;
        }
        n += 1;
    }
    if n == 0 {
        return Err(SpendError::TooHeavy {
            weight: estimate_tx_weight(1, options.ring_size, MIN_OUTPUTS, options.extra_size),
            limit: options.weight_limit,
        });
    }
    let left_behind = candidates.len() - n;
    candidates.truncate(n);

    let inputs: Vec<usize> = candidates.iter().map(|(i, _)| *i).collect();
    let in_total: u64 = candidates.iter().map(|(_, t)| t.amount).sum();

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
        left_behind,
    })
}

/// Plan a sweep of **one** output: `sweep_single`.
///
/// The one case where a wallet's own choice of input is the point rather than
/// an implementation detail. Somebody sweeping a single output is usually
/// separating it from the rest of the wallet on purpose — an output with a
/// history they do not want mixed into a later transaction, or one a payer
/// can already link to them.
///
/// `key_image` names it, because that is what `unspent_outputs` prints and
/// what the reference's `sweep_single` takes.
pub fn plan_sweep_single(
    transfers: &[Transfer],
    key_image: &KeyImage,
    options: &SpendOptions,
) -> Result<SpendPlan, SpendError> {
    let (index, transfer) = transfers
        .iter()
        .enumerate()
        .find(|(_, t)| t.key_image.as_ref() == Some(key_image))
        .ok_or(SpendError::NoSuchOutput)?;
    if transfer.spent {
        return Err(SpendError::OutputSpent);
    }
    if spendable(std::slice::from_ref(transfer), options).is_empty() {
        return Err(SpendError::OutputLocked);
    }

    let weight = estimate_tx_weight(1, options.ring_size, MIN_OUTPUTS, options.extra_size);
    let fee = fee_from_weight(options.fee_per_byte, weight);
    if fee >= transfer.amount {
        return Err(SpendError::NotEnough {
            available: transfer.amount,
            needed: fee,
            fee,
        });
    }

    Ok(SpendPlan {
        inputs: vec![index],
        amounts: vec![transfer.amount - fee],
        change: 0,
        fee,
        estimated_weight: weight,
        sweep: true,
        left_behind: 0,
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
    use wow_crypto::types::PublicKey;

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
            payment_id: None,
        }
    }

    /// A deterministic source, so a plan can be reproduced exactly. Not a
    /// CSPRNG, and not what a wallet passes.
    struct Seq(u64);

    impl crate::decoys::RandomSource for Seq {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
    }

    fn seq() -> Seq {
        Seq(0x5eed)
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

    /// A sweep of a wallet with more outputs than fit takes the largest it
    /// can and says how many it left.
    ///
    /// This is the case that used to produce a signed, valid transaction
    /// several times over the relay limit, which every node refuses. At ring
    /// size 22 an input costs about 880 bytes, so the cap lands a little over
    /// a hundred.
    #[test]
    fn a_sweep_too_heavy_for_one_transaction_is_capped_and_says_so() {
        // Amounts spread widely, so "largest first" is a decision with a
        // consequence rather than an ordering of equals.
        let transfers: Vec<Transfer> = (0..255u16)
            .map(|i| transfer(1_000 * (u64::from(i) + 1), 1, i as u8))
            .collect();
        let opts = options(3);

        let p = plan_sweep(&transfers, &opts).expect("a sweep");
        assert!(
            p.inputs.len() < transfers.len(),
            "255 inputs cannot fit in one transaction"
        );
        assert_eq!(
            p.left_behind,
            transfers.len() - p.inputs.len(),
            "what it could not take is reported, not silently dropped"
        );
        assert!(
            p.estimated_weight <= opts.weight_limit,
            "{} is over the {} a node will relay",
            p.estimated_weight,
            opts.weight_limit
        );
        // One more input would not have fitted: the cap is tight, not timid.
        assert!(
            estimate_tx_weight(p.inputs.len() + 1, opts.ring_size, MIN_OUTPUTS, opts.extra_size)
                > opts.weight_limit
        );

        // Largest first, so what is left behind is the small change.
        let taken: u64 = p.inputs.iter().map(|&i| transfers[i].amount).sum();
        let everything: u64 = transfers.iter().map(|t| t.amount).sum();
        assert!(taken > everything / 2, "the money goes, not the dust");
    }

    /// Which output pays is not a function of the amounts.
    ///
    /// Largest-first was a fingerprint: an observer who knew the wallet's
    /// outputs could name the inputs before seeing the transaction. Two
    /// different sources must be able to reach two different plans over the
    /// same wallet.
    #[test]
    fn which_output_pays_is_not_decided_by_its_size() {
        // Ten outputs, any one of which covers the amount on its own.
        let transfers: Vec<Transfer> = (0..10u8)
            .map(|i| transfer(1_000_000_000 + u64::from(i) * 1_000, 1, i))
            .collect();

        let mut seen = std::collections::HashSet::new();
        for seed in 0..40u64 {
            let mut rng = Seq(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            let p = plan(&transfers, &[500_000_000], &options(3), &mut rng).expect("a plan");
            assert_eq!(p.inputs.len(), 1, "one output covers it, so one is taken");
            seen.insert(p.inputs[0]);
        }
        assert!(
            seen.len() > 1,
            "every source chose the same output: selection is still deterministic"
        );

        // And in particular it is not always the largest, which is what the
        // old policy did every single time.
        let largest = transfers.len() - 1;
        assert!(
            seen.iter().any(|&i| i != largest),
            "still always the largest"
        );
    }

    /// Randomness must not cost inputs. An output that finishes the job is
    /// always preferred to two that do.
    #[test]
    fn a_single_output_that_covers_it_is_always_enough() {
        let transfers = vec![
            transfer(1_000, 1, 1),
            transfer(2_000, 1, 2),
            transfer(9_000_000_000, 1, 3),
            transfer(3_000, 1, 4),
        ];
        for seed in 0..20u64 {
            let mut rng = Seq(seed.wrapping_mul(0x2545_f491_4f6c_dd1d));
            let p = plan(&transfers, &[1_000_000_000], &options(3), &mut rng).expect("a plan");
            assert_eq!(
                p.inputs,
                vec![2],
                "only the third output can cover it alone"
            );
        }
    }

    /// When nothing left covers what remains, every remaining output is going
    /// to be needed, so it takes the largest and gets there in the fewest.
    #[test]
    fn what_cannot_be_covered_alone_is_taken_largest_first() {
        let transfers: Vec<Transfer> = (0..6u8)
            .map(|i| transfer(1_000_000 * (u64::from(i) + 1), 1, i))
            .collect();
        // 21,000,000 in all; asking for nearly that takes everything.
        let p = plan(&transfers, &[20_000_000], &options(0), &mut seq()).expect("a plan");
        assert_eq!(p.inputs.len(), 6);
    }

    /// `sweep_single` takes the output named and no other, whatever else the
    /// wallet holds.
    #[test]
    fn sweeping_one_output_takes_that_one_and_no_other() {
        let transfers = vec![
            transfer(9_000_000, 1, 1),
            transfer(5_000_000, 1, 2),
            transfer(7_000_000, 1, 3),
        ];
        let wanted = transfers[1].key_image.expect("an image");

        let p = plan_sweep_single(&transfers, &wanted, &options(3)).expect("a sweep");
        assert_eq!(p.inputs, vec![1], "not the largest, the one asked for");
        assert!(p.sweep);
        assert_eq!(p.change, 0);
        assert_eq!(p.left_behind, 0, "nothing was left behind; one was chosen");
        assert_eq!(p.amounts[0] + p.fee, 5_000_000);
    }

    /// An output that is not this wallet's, or is already spent, is refused by
    /// name rather than quietly swept from somewhere else.
    #[test]
    fn sweeping_an_output_the_wallet_cannot_spend_says_which_problem() {
        let mut transfers = vec![transfer(9_000_000, 1, 1)];
        let mine = transfers[0].key_image.expect("an image");

        let e = plan_sweep_single(&transfers, &KeyImage([0xaa; 32]), &options(3))
            .expect_err("not ours");
        assert!(matches!(e, SpendError::NoSuchOutput), "{e}");

        transfers[0].spent = true;
        let e = plan_sweep_single(&transfers, &mine, &options(3)).expect_err("spent");
        assert!(matches!(e, SpendError::OutputSpent), "{e}");
    }

    /// An output worth less than the fee to move it cannot be swept, and says
    /// so with the numbers rather than as a generic failure.
    #[test]
    fn sweeping_an_output_that_cannot_pay_its_own_fee_is_refused() {
        let transfers = vec![transfer(1_000, 1, 1)];
        let wanted = transfers[0].key_image.expect("an image");
        let e = plan_sweep_single(&transfers, &wanted, &options(1_000)).expect_err("too small");
        match e {
            SpendError::NotEnough { available, fee, .. } => {
                assert_eq!(available, 1_000);
                assert!(fee >= 1_000);
            }
            other => panic!("expected NotEnough, got {other}"),
        }
    }

    /// A sweep that fits takes everything and leaves nothing to report.
    #[test]
    fn a_sweep_that_fits_leaves_nothing_behind() {
        let transfers = vec![transfer(5_000, 1, 1), transfer(3_000, 1, 2)];
        let p = plan_sweep(&transfers, &options(3)).expect("a sweep");
        assert_eq!(p.inputs.len(), 2);
        assert_eq!(p.left_behind, 0);
    }

    /// An ordinary send that would not be relayed is refused while it is still
    /// arithmetic — before a ring has been fetched for every input and every
    /// one of them signed.
    #[test]
    fn a_send_too_heavy_to_relay_is_refused_before_it_is_built() {
        // Dust, so covering the amount takes every one of them.
        let transfers: Vec<Transfer> = (0..255u16)
            .map(|i| transfer(1_000, 1, i as u8))
            .collect();
        let e = plan(&transfers, &[250_000], &options(3), &mut seq()).expect_err("too heavy");
        match e {
            SpendError::TooHeavy { weight, limit } => {
                assert!(weight > limit);
                assert_eq!(limit, default_weight_limit());
            }
            other => panic!("expected TooHeavy, got {other}"),
        }
    }

    /// The limit is `TX_WEIGHT_TARGET(get_upper_transaction_weight_limit())`
    /// over the default weight zone, and a single input is nowhere near it.
    #[test]
    fn the_default_weight_limit_is_the_references() {
        assert_eq!(default_weight_limit(), (300_000 / 2 - 600) * 2 / 3);
        assert_eq!(default_weight_limit(), 99_600);
        assert!(estimate_tx_weight(1, 22, 2, 44) < default_weight_limit());
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
        let p = plan(&transfers, &[4_000_000_000], &options(3), &mut seq()).expect("a plan");

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
        let p = plan(&transfers, &[3_000], &options(0), &mut seq()).expect("a plan");
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
        let p = plan(&transfers, &[8_000_000_000], &options(3), &mut seq()).expect("a plan");
        assert_eq!(p.inputs, vec![1], "the 9 WOW output alone covers it");

        let p = plan(&transfers, &[11_000_000_000], &options(3), &mut seq()).expect("a plan");
        assert_eq!(p.inputs, vec![1, 2], "largest first");
    }

    /// Not enough money is an error that says how much was available.
    #[test]
    fn not_enough_is_reported_with_the_numbers() {
        let transfers = vec![transfer(1_000, 100, 1)];
        let e = plan(&transfers, &[5_000], &options(3), &mut seq()).expect_err("too little");
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

    /// It says how much in WOW, not in atomic units: twelve WOW is "12", not
    /// "1200000000000", and a fee not yet worked out is not "a fee of 0".
    #[test]
    fn not_enough_says_how_much_in_wow() {
        assert_eq!(money(0), "0");
        assert_eq!(money(1_200_000_000_000), "12");
        assert_eq!(money(30_000_000), "0.0003");
        assert_eq!(money(1), "0.00000000001");

        let e = SpendError::NotEnough {
            available: 0,
            needed: 1_200_000_000_000,
            fee: 0,
        };
        assert_eq!(
            e.to_string(),
            "not enough unlocked funds: 0 WOW available, 12 WOW needed"
        );
        let e = SpendError::NotEnough {
            available: 250_000_000_000,
            needed: 1_200_030_000_000,
            fee: 30_000_000,
        };
        assert_eq!(
            e.to_string(),
            "not enough unlocked funds: 2.5 WOW available, 12.0003 WOW needed, including a fee \
             of 0.0003 WOW"
        );
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

        let p = plan(&transfers, &[1_000_000], &options(3), &mut seq()).expect("a plan");
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
        let p = plan(&transfers, &[7_000_000_000], &options(11), &mut seq()).expect("a plan");

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
            plan(&transfers, &many, &options(3), &mut seq()),
            Err(SpendError::TooManyDestinations(MAX_OUTPUTS))
        );

        // One fewer leaves room for change.
        let ok: Vec<u64> = (0..MAX_OUTPUTS as u64 - 1).map(|i| i + 1).collect();
        assert!(plan(&transfers, &ok, &options(3), &mut seq()).is_ok());
    }

    /// Degenerate requests are refused rather than planned.
    #[test]
    fn degenerate_requests_are_refused() {
        let transfers = vec![transfer(1_000_000, 100, 1)];
        assert_eq!(
            plan(&transfers, &[], &options(3), &mut seq()),
            Err(SpendError::NoDestinations)
        );
        assert_eq!(
            plan(&transfers, &[100, 0], &options(3), &mut seq()),
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
        let p = plan(&transfers, &[1_000_000], &o, &mut seq()).expect("a plan");
        assert_eq!(change_index(&p, &transfers), SubaddressIndex::new(2, 0));
    }

    /// A new fee moves the change and leaves what the payee gets alone.
    #[test]
    fn a_new_fee_moves_the_change() {
        let transfers = vec![transfer(10_000_000_000, 100, 1)];
        let p = plan(&transfers, &[4_000_000_000], &options(3), &mut seq()).expect("a plan");
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
