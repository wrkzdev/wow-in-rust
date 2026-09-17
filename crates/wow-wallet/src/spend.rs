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

use std::collections::{BTreeMap, BTreeSet};

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
/// encrypted-id tag and eight bytes. `additional_keys` is whether per-output
/// keys are written, which takes a subaddress paid alongside another payee:
/// a tag, a count and a key per output. Two outputs with those are two payees
/// and no change, with no one view key to encrypt a dummy to, so no dummy.
///
/// Paying one subaddress, with change, needs no per-output keys, and is the
/// same size as paying a standard address.
pub fn extra_size(n_outputs: usize, payment_id: bool, additional_keys: bool) -> usize {
    let mut size = 1 + 32;
    if payment_id || (n_outputs == MIN_OUTPUTS && !additional_keys) {
        size += 2 + 1 + 8;
    }
    if additional_keys {
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
    /// The subaddress account to spend from. A transaction spends from one
    /// account only, as `wallet2` does: funds from two would tie the two
    /// together on chain.
    pub account: u32,
    /// The minor indices within `account` to spend from. Empty is every one
    /// that holds anything, or for a sweep one of them at random.
    pub subaddr_indices: Vec<u32>,
    /// `ignore_outputs_above` / `ignore_outputs_below`: outputs outside the
    /// range are not picked to pay a transfer.
    pub ignore_above: u64,
    pub ignore_below: u64,
    /// `ignore_fractional_outputs`: leave out outputs worth less than the fee
    /// one more input costs. On by default, as in `wallet2`.
    pub ignore_fractional_outputs: bool,
    /// `min_output_count` / `min_output_value`: a second input that is not
    /// needed is not added when fewer than this many outputs of at least this
    /// value would be left. Both zero means `wallet2`'s defaults, five of 2
    /// WOW.
    pub min_output_count: u32,
    pub min_output_value: u64,
    /// Change still to come back to `account` from transactions not yet in a
    /// block, which counts toward its balance as `balance_per_subaddress`
    /// counts it.
    pub pending_change: u64,
    /// A sweep's `below_amount`: only outputs worth less than this. Zero is
    /// every output.
    pub sweep_below: u64,
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
            account: 0,
            subaddr_indices: Vec::new(),
            ignore_above: constants::MONEY_SUPPLY,
            ignore_below: 0,
            ignore_fractional_outputs: true,
            min_output_count: 0,
            min_output_value: 0,
            pending_change: 0,
            sweep_below: 0,
            chain_height: 0,
            now: 0,
            weight_limit: default_weight_limit(),
        }
    }
}

/// What to build, once the arithmetic has settled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendPlan {
    /// Indices into the transfer list, in the order they were picked.
    pub inputs: Vec<usize>,
    /// The amount going to each destination, in the order given.
    pub amounts: Vec<u64>,
    /// The change, which the caller sends back to itself. Zero means no change
    /// output, or for a single destination a dummy one to reach two.
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
    /// Total outputs: `get_num_outputs`, the destinations, change if there is
    /// any, and a dummy to reach two.
    pub fn output_count(&self) -> usize {
        (self.amounts.len() + usize::from(self.change > 0)).max(MIN_OUTPUTS)
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
    #[error(
        "No transaction created: no output in this account is eligible to spend, once outputs \
         below the fee they cost and outside ignore-outputs-above and -below are left out"
    )]
    NothingToSpend,
    #[error("the tx uses funds from multiple accounts")]
    MultipleAccounts,
}

/// `DEFAULT_MIN_OUTPUT_COUNT`.
pub const DEFAULT_MIN_OUTPUT_COUNT: u32 = 5;
/// `DEFAULT_MIN_OUTPUT_VALUE`: 2 WOW.
pub const DEFAULT_MIN_OUTPUT_VALUE: u64 = 2 * constants::COIN;
/// `SECOND_OUTPUT_RELATEDNESS_THRESHOLD`.
const SECOND_OUTPUT_RELATEDNESS_THRESHOLD: f32 = 0.0;

/// Which transfers are eligible to spend.
///
/// Unspent, unlocked, with a key image known, in the account asked for and
/// inside `ignore_below..=ignore_above`. A view-only wallet has no key
/// images, so it can select nothing, which is the correct answer rather than
/// an error the caller has to special-case.
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
        .filter(|(_, t)| t.subaddress.major == options.account)
        .collect()
}

/// `wallet2::get_output_relatedness`: "a handwavy estimation of how much two
/// outputs are related". From one transaction, fully; from one block, or
/// blocks close together, somewhat; otherwise not at all.
///
/// Two outputs spent together tell an observer that one wallet held both. If
/// they arrived together as well, that says little more; if they were paid a
/// block apart, it links two payments.
pub fn output_relatedness(a: &Transfer, b: &Transfer) -> f32 {
    if a.txid == b.txid {
        return 1.0;
    }
    match a.block_height.abs_diff(b.block_height) {
        0 => 0.9,
        1 => 0.8,
        2..=9 => 0.2,
        _ => 0.0,
    }
}

/// `wallet2::pop_best_value_from`: take, out of `unused`, one of the outputs
/// least related to those already `selected`: the smallest of them when
/// `smallest`, and otherwise one at random.
fn pop_best_value(
    transfers: &[Transfer],
    unused: &mut Vec<usize>,
    selected: &[usize],
    smallest: bool,
    rng: &mut dyn crate::decoys::RandomSource,
) -> usize {
    let mut candidates: Vec<usize> = Vec::new();
    let mut best = 1.0f32;
    for (n, &i) in unused.iter().enumerate() {
        let mut relatedness = 0.0f32;
        for &s in selected {
            let r = output_relatedness(&transfers[i], &transfers[s]);
            if r > relatedness {
                relatedness = r;
                if relatedness == 1.0 {
                    break;
                }
            }
        }
        if relatedness < best {
            best = relatedness;
            candidates.clear();
        }
        if relatedness == best {
            candidates.push(n);
        }
    }
    let pick = if smallest {
        let mut at = 0;
        for (n, &c) in candidates.iter().enumerate() {
            if transfers[unused[c]].amount < transfers[unused[candidates[at]]].amount {
                at = n;
            }
        }
        at
    } else {
        rng.below(candidates.len() as u64) as usize
    };
    // `pop_index`: the last element takes the popped one's place.
    unused.swap_remove(candidates[pick])
}

/// `pop_if_present`.
fn pop_if_present(unused: &mut Vec<usize>, index: usize) {
    if let Some(at) = unused.iter().position(|&i| i == index) {
        unused.swap_remove(at);
    }
}

/// Whether `t` may pay a transfer from `account`'s `indices`, in the checks
/// every selection path in `create_transactions_2` shares.
fn eligible(t: &Transfer, options: &SpendOptions, indices: &BTreeSet<u32>) -> bool {
    !t.spent
        && t.key_image.is_some()
        && t.unlocked(options.chain_height, options.now)
        && t.subaddress.major == options.account
        && indices.contains(&t.subaddress.minor)
}

fn outside_range(t: &Transfer, options: &SpendOptions) -> bool {
    t.amount > options.ignore_above || t.amount < options.ignore_below
}

/// `wallet2::pick_preferred_rct_inputs`: "to build a tx that's 1 or 2 inputs,
/// and 2 outputs, which will get us a known fee".
///
/// The first output, oldest first, that covers `needed` alone. Failing that,
/// the least related pair from one subaddress that covers it together, the
/// first pair found among equals, and as soon as an unrelated pair is found.
/// Nothing when neither exists.
fn pick_preferred_inputs(
    transfers: &[Transfer],
    needed: u64,
    options: &SpendOptions,
    indices: &BTreeSet<u32>,
) -> Vec<usize> {
    for (i, t) in transfers.iter().enumerate() {
        if eligible(t, options, indices) && t.amount >= needed && !outside_range(t, options) {
            return vec![i];
        }
    }

    let mut picks = Vec::new();
    let mut current = 1.0f32;
    for (i, t) in transfers.iter().enumerate() {
        if !eligible(t, options, indices) || outside_range(t, options) {
            continue;
        }
        for (j, t2) in transfers.iter().enumerate().skip(i + 1) {
            if outside_range(t2, options) {
                continue;
            }
            if !t2.spent
                && t2.key_image.is_some()
                && t.amount.saturating_add(t2.amount) >= needed
                && t2.unlocked(options.chain_height, options.now)
                && t2.subaddress == t.subaddress
            {
                // "update our picks if those outputs are less related than any
                // we already found. If the same, don't update, and oldest
                // suitable outputs will be used in preference."
                let relatedness = output_relatedness(t, t2);
                if relatedness < current {
                    picks = vec![i, j];
                    if relatedness == 0.0 {
                        return picks;
                    }
                    current = relatedness;
                }
            }
        }
    }
    picks
}

/// `get_num_outputs`: the destinations, change unless the inputs match them
/// exactly, and a dummy to reach two.
fn num_outputs(destinations: &[u64], found: u64) -> usize {
    let needed: u64 = destinations.iter().sum();
    (destinations.len() + usize::from(found != needed)).max(MIN_OUTPUTS)
}

/// `fractional_threshold` in `create_transactions_2` and `_all`: what one
/// more input costs in fee, from the weight of two inputs less one.
fn fractional_threshold(options: &SpendOptions) -> u64 {
    let one = estimate_tx_weight(1, options.ring_size, 2, 0);
    let two = estimate_tx_weight(2, options.ring_size, 2, 0);
    options.fee_per_byte.saturating_mul(two - one)
}

/// Plan a transaction: pick inputs, settle the fee.
///
/// `destinations` are the amounts going out, not counting change. The caller
/// supplies the addresses; this only does arithmetic, because which address
/// change goes to is a policy question and the amounts are not.
///
/// # Which outputs pay
///
/// `wallet2::create_transactions_2`, for one transaction:
///
/// - only outputs of one account, from the minor indices asked for or every
///   one that holds anything, grouped by subaddress, the group with the most
///   unlocked first; less than the fee an input costs, or outside the ignore
///   range, left out;
/// - first choice is `pick_preferred_rct_inputs`: the oldest output that pays
///   the whole of it with the fee a two-input transaction would need, or the
///   least related pair from one subaddress that does, which brings that
///   subaddress's group to the front;
/// - otherwise outputs are taken from the front group one at a time, at
///   random among those least related to what is already taken, moving to the
///   next group when one runs out;
/// - and a transaction that one input paid for gets a second, the smallest of
///   the least related, when that one is unrelated to the first and taking it
///   still leaves enough outputs of some size, so that most transactions have
///   two inputs and two outputs.
///
/// The C++ builds the transaction to measure it at the point it decides the
/// inputs are enough, and goes back for more if the real fee is higher. Here
/// the estimate decides, and [`crate::transfer::construct_settled`] then
/// settles on the built weight; the estimate runs over, so an input the real
/// fee would have needed is never missing. A send that would need a second
/// transaction to finish is refused as [`SpendError::TooHeavy`].
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
    let needed_money = destinations
        .iter()
        .try_fold(0u64, |sum, d| sum.checked_add(*d))
        .ok_or(SpendError::NotEnough {
            available: 0,
            needed: u64::MAX,
            fee: 0,
        })?;

    // `balance_per_subaddress` and `unlocked_balance_per_subaddress`, for the
    // account.
    let mut balance: BTreeMap<u32, u64> = BTreeMap::new();
    let mut unlocked: BTreeMap<u32, u64> = BTreeMap::new();
    for t in transfers
        .iter()
        .filter(|t| t.subaddress.major == options.account && !t.spent)
    {
        *balance.entry(t.subaddress.minor).or_default() += t.amount;
        let u = unlocked.entry(t.subaddress.minor).or_default();
        if t.unlocked(options.chain_height, options.now) {
            *u += t.amount;
        }
    }
    // "all changes go to 0-th subaddress (in the current subaddress account)"
    if options.pending_change > 0 {
        *balance.entry(0).or_default() += options.pending_change;
    }
    let indices: BTreeSet<u32> = if options.subaddr_indices.is_empty() {
        balance.keys().copied().collect()
    } else {
        options.subaddr_indices.iter().copied().collect()
    };

    // "early out if we know we can't make it anyway"
    let min_fee = options.fee_per_byte.saturating_mul(estimate_tx_size(
        1,
        options.ring_size,
        2,
        options.extra_size,
    ) as u64);
    let total_needed = needed_money.saturating_add(min_fee);
    let subtotal = |per: &BTreeMap<u32, u64>| -> u64 {
        indices.iter().filter_map(|m| per.get(m)).sum()
    };
    let (balance_subtotal, unlocked_subtotal) = (subtotal(&balance), subtotal(&unlocked));
    if total_needed > balance_subtotal.min(unlocked_subtotal)
        || min_fee > balance_subtotal.min(unlocked_subtotal)
    {
        return Err(SpendError::NotEnough {
            available: unlocked_subtotal,
            needed: needed_money,
            fee: 0,
        });
    }

    // Every eligible output, grouped by the subaddress it is at, the group with
    // the most unlocked first.
    let threshold = fractional_threshold(options);
    let mut groups: Vec<(u32, Vec<usize>)> = Vec::new();
    for (i, t) in transfers.iter().enumerate() {
        if options.ignore_fractional_outputs && t.amount < threshold {
            continue;
        }
        if !eligible(t, options, &indices) || outside_range(t, options) {
            continue;
        }
        match groups.iter_mut().find(|(minor, _)| *minor == t.subaddress.minor) {
            Some((_, group)) => group.push(i),
            None => groups.push((t.subaddress.minor, vec![i])),
        }
    }
    groups.sort_by_key(|(minor, _)| std::cmp::Reverse(unlocked.get(minor).copied().unwrap_or(0)));
    if groups.is_empty() {
        return Err(SpendError::NothingToSpend);
    }

    let two_input_fee = fee_from_weight(
        options.fee_per_byte,
        estimate_tx_weight(2, options.ring_size, 2, options.extra_size),
    );
    let mut preferred = pick_preferred_inputs(
        transfers,
        needed_money.saturating_add(two_input_fee),
        options,
        &indices,
    );
    if let Some(&first) = preferred.first() {
        // "bring the list of available outputs stored by the same subaddress
        // index to the front of the list"
        let minor = transfers[first].subaddress.minor;
        if let Some(at) = groups.iter().skip(1).position(|(m, _)| *m == minor) {
            groups.swap(0, at + 1);
        }
    }

    let limit = options.weight_limit;
    let weight_with = |inputs: usize, outputs: usize| {
        estimate_tx_weight(inputs, options.ring_size, outputs, options.extra_size)
    };

    let mut dsts: Vec<u64> = destinations.to_vec();
    let mut tx_dsts: Vec<u64> = Vec::new();
    let mut original_output_index = 0usize;
    let mut selected: Vec<usize> = Vec::new();
    let mut adding_fee = false;
    let mut needed_fee = 0u64;
    let mut available_for_fee = 0u64;
    let mut made: Option<SpendPlan> = None;

    // "while we have something to send, or we need to gather more fee, or we
    // have just one input in that tx, which is rct (to try and make all/most
    // rct txes 2/2)"
    while dsts.first().is_some_and(|d| *d > 0)
        || adding_fee
        || !preferred.is_empty()
        || (selected.len() <= 1 && !groups[0].1.is_empty())
    {
        if groups[0].1.is_empty() {
            return Err(SpendError::NotEnough {
                available: unlocked_subtotal,
                needed: needed_money,
                fee: needed_fee,
            });
        }

        let idx = if let Some(p) = preferred.pop() {
            pop_if_present(&mut groups[0].1, p);
            p
        } else if dsts.first().is_none_or(|d| *d == 0) && !adding_fee {
            // The 2/2 case: a small output to clean up the wallet, but only if
            // spending it costs nothing in privacy or in spare outputs.
            let mut candidates = groups[0].1.clone();
            let second = pop_best_value(transfers, &mut candidates, &selected, true, rng);
            let (min_value, min_count) =
                if options.min_output_value == 0 && options.min_output_count == 0 {
                    (DEFAULT_MIN_OUTPUT_VALUE, DEFAULT_MIN_OUTPUT_COUNT)
                } else {
                    (options.min_output_value, options.min_output_count)
                };
            let above = groups[0]
                .1
                .iter()
                .filter(|&&i| transfers[i].amount >= min_value)
                .count();
            if transfers[second].amount >= min_value && above < min_count as usize {
                break;
            }
            if output_relatedness(&transfers[second], &transfers[selected[0]])
                > SECOND_OUTPUT_RELATEDNESS_THRESHOLD
            {
                break;
            }
            pop_if_present(&mut groups[0].1, second);
            second
        } else {
            pop_best_value(transfers, &mut groups[0].1, &selected, false, rng)
        };
        selected.push(idx);
        let mut available = transfers[idx].amount;

        let mut out_slots_exhausted = false;
        if adding_fee {
            available_for_fee = available_for_fee.saturating_add(available);
        } else {
            while let Some(&d) = dsts.first() {
                if d > available || weight_with(selected.len(), tx_dsts.len() + 1) >= limit {
                    break;
                }
                // "we can fully pay that destination"
                if !add_destination(&mut tx_dsts, d, original_output_index) {
                    out_slots_exhausted = true;
                    break;
                }
                available -= d;
                dsts.remove(0);
                original_output_index += 1;
            }
            if !out_slots_exhausted
                && available > 0
                && !dsts.is_empty()
                && weight_with(selected.len(), tx_dsts.len() + 1) < limit
            {
                // "we can partially fill that destination"
                if add_destination(&mut tx_dsts, available, original_output_index) {
                    dsts[0] -= available;
                } else {
                    out_slots_exhausted = true;
                }
            }
        }

        let try_tx = if out_slots_exhausted {
            true
        } else if !preferred.is_empty() {
            false
        } else if adding_fee {
            available_for_fee >= needed_fee
        } else {
            let weight = weight_with(selected.len(), tx_dsts.len() + 1);
            let full = dsts.is_empty() || weight >= limit;
            if full && tx_dsts.is_empty() {
                return Err(SpendError::TooHeavy { weight, limit });
            }
            full
        };

        if try_tx {
            let found: u64 = selected.iter().map(|&i| transfers[i].amount).sum();
            let outputs = num_outputs(&tx_dsts, found);
            let weight = weight_with(selected.len(), outputs);
            needed_fee = fee_from_weight(options.fee_per_byte, weight);
            let paying = tx_dsts.iter().sum::<u64>().saturating_add(needed_fee);
            if found < paying {
                // "We don't have enough for the basic fee, switching to
                // adding_fee"
                adding_fee = true;
            } else if !dsts.is_empty() {
                // The C++ makes this transaction and starts another for the
                // rest, carving its fee from a partial payment if it must.
                // This wallet sends one.
                return Err(SpendError::TooHeavy {
                    weight: weight_with(selected.len(), tx_dsts.len() + 1),
                    limit,
                });
            } else {
                // "We made a tx": what building it would show, from the
                // estimate, which runs over the built weight.
                adding_fee = false;
                available_for_fee = found - tx_dsts.iter().sum::<u64>();
                made = Some(SpendPlan {
                    inputs: selected.clone(),
                    amounts: tx_dsts.clone(),
                    change: found - paying,
                    fee: needed_fee,
                    estimated_weight: weight,
                    sweep: false,
                    left_behind: 0,
                });
            }
        }

        // "if unused_*_indices is empty ... and if we still have something to
        // pay, pop front of unused_*_indices_per_subaddr"
        if (dsts.first().is_some_and(|d| *d > 0) || adding_fee)
            && groups[0].1.is_empty()
            && groups.len() > 1
        {
            groups.remove(0);
        }
    }

    if adding_fee {
        return Err(SpendError::NotEnough {
            available: unlocked_subtotal,
            needed: needed_money,
            fee: needed_fee,
        });
    }
    made.ok_or(SpendError::FeeDidNotSettle(FEE_CALCULATION_MAX_RETRIES))
}

/// `TX::add` in `create_transactions_2`, with `merge_destinations` off: pay
/// `amount` toward the destination at `index`, a new output when it is the
/// next one. False when that would pass the outputs a transaction may have,
/// change aside.
fn add_destination(tx_dsts: &mut Vec<u64>, amount: u64, index: usize) -> bool {
    if index == tx_dsts.len() {
        if tx_dsts.len() >= MAX_OUTPUTS - 1 {
            return false;
        }
        tx_dsts.push(0);
    }
    tx_dsts[index] += amount;
    true
}

/// Plan a sweep: send everything eligible to one destination,
/// `wallet2::create_transactions_all` and `create_transactions_from`.
///
/// The amount is an output of the calculation rather than an input: the fee
/// comes out of what is being sent, so there is no change and the destination
/// gets whatever is left.
///
/// # Which outputs go
///
/// One account's, and of those, when no minor index is named, one
/// subaddress's, chosen at random, the main address only if nothing else
/// holds anything: sweeping two subaddresses into one transaction would tie
/// them together. Outputs worth less than their own fee are left out, and so
/// are those not below `sweep_below` when it is set. They are taken at random
/// among those least related to what is already taken, until there are no
/// more or the transaction's estimated weight reaches the limit.
///
/// `wallet2` splits what does not fit across more transactions. This builds
/// the first and reports how many it left, so sweeping such a wallet is
/// running `sweep_all` until it says it took everything. Less convenient, and
/// it never signs a transaction that cannot be relayed.
pub fn plan_sweep(
    transfers: &[Transfer],
    options: &SpendOptions,
    rng: &mut dyn crate::decoys::RandomSource,
) -> Result<SpendPlan, SpendError> {
    let nothing = SpendError::NotEnough {
        available: 0,
        needed: 0,
        fee: 0,
    };
    // "No unlocked balance in the specified account"
    let unlocked_balance: u64 = transfers
        .iter()
        .filter(|t| t.subaddress.major == options.account && !t.spent)
        .filter(|t| t.unlocked(options.chain_height, options.now))
        .map(|t| t.amount)
        .sum();
    if unlocked_balance == 0 {
        return Err(nothing);
    }

    let threshold = fractional_threshold(options);
    let mut by_minor: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    let mut fund_found = false;
    for (i, t) in transfers.iter().enumerate() {
        if options.ignore_fractional_outputs && t.amount < threshold {
            continue;
        }
        if !t.spent
            && t.key_image.is_some()
            && t.unlocked(options.chain_height, options.now)
            && t.subaddress.major == options.account
            && (options.subaddr_indices.is_empty()
                || options.subaddr_indices.contains(&t.subaddress.minor))
        {
            fund_found = true;
            if options.sweep_below == 0 || t.amount < options.sweep_below {
                by_minor.entry(t.subaddress.minor).or_default().push(i);
            }
        }
    }
    // "No unlocked balance in the specified subaddress(es)", and "The
    // smallest amount found is not below the specified threshold".
    if !fund_found {
        return Err(nothing);
    }
    if by_minor.is_empty() {
        return Err(SpendError::NothingToSpend);
    }

    let mut unused: Vec<usize> = if options.subaddr_indices.is_empty() {
        // "choose non-empty subaddress randomly (with index=0 being chosen
        // last)"
        if by_minor.len() > 1 {
            by_minor.remove(&0);
        }
        let pick = rng.below(by_minor.len() as u64) as usize;
        by_minor.into_values().nth(pick).unwrap_or_default()
    } else {
        by_minor.into_values().flatten().collect()
    };

    let mut selected: Vec<usize> = Vec::new();
    while !unused.is_empty() {
        selected.push(pop_best_value(transfers, &mut unused, &selected, false, rng));
        // Two outputs: the destination, and change or its dummy.
        let weight = estimate_tx_weight(
            selected.len(),
            options.ring_size,
            MIN_OUTPUTS,
            options.extra_size,
        );
        if weight >= options.weight_limit {
            break;
        }
    }

    let in_total: u64 = selected.iter().map(|&i| transfers[i].amount).sum();
    let weight = estimate_tx_weight(
        selected.len(),
        options.ring_size,
        MIN_OUTPUTS,
        options.extra_size,
    );
    let fee = fee_from_weight(options.fee_per_byte, weight);
    // "Transaction cannot pay for itself"
    if fee >= in_total {
        return Err(SpendError::NotEnough {
            available: in_total,
            needed: fee,
            fee,
        });
    }

    Ok(SpendPlan {
        inputs: selected,
        amounts: vec![in_total - fee],
        change: 0,
        fee,
        estimated_weight: weight,
        sweep: true,
        left_behind: unused.len(),
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
/// what the reference's `sweep_single` takes. As in
/// `create_transactions_single`, neither the account nor the ignore settings
/// apply: the output is the one asked for.
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
    if !transfer.unlocked(options.chain_height, options.now) {
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

    /// Options for these tests, which pick among small amounts: outputs worth
    /// less than their own fee are kept in, except where a test says.
    fn options(fee_per_byte: u64) -> SpendOptions {
        SpendOptions {
            fee_per_byte,
            chain_height: 1_000,
            now: 1_700_000_000,
            ignore_fractional_outputs: false,
            ..Default::default()
        }
    }

    fn at(amount: u64, height: u64, seed: u8, major: u32, minor: u32) -> Transfer {
        Transfer {
            subaddress: SubaddressIndex::new(major, minor),
            ..transfer(amount, height, seed)
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

    /// A sweep of a wallet with more outputs than fit takes inputs until the
    /// estimate reaches the limit, as `create_transactions_from` does before
    /// it starts another transaction, and says how many it left.
    ///
    /// This is the case that used to produce a signed, valid transaction
    /// several times over the relay limit, which every node refuses. At ring
    /// size 22 an input costs about 880 bytes, so the cap lands a little over
    /// a hundred.
    #[test]
    fn a_sweep_too_heavy_for_one_transaction_is_capped_and_says_so() {
        let transfers: Vec<Transfer> = (0..255u16)
            .map(|i| transfer(1_000_000 * (u64::from(i) + 1), u64::from(i), i as u8))
            .collect();
        let opts = options(3);

        let p = plan_sweep(&transfers, &opts, &mut seq()).expect("a sweep");
        assert!(
            p.inputs.len() < transfers.len(),
            "255 inputs cannot fit in one transaction"
        );
        assert_eq!(
            p.left_behind,
            transfers.len() - p.inputs.len(),
            "what it could not take is reported, not silently dropped"
        );
        let weight = |n: usize| estimate_tx_weight(n, opts.ring_size, MIN_OUTPUTS, opts.extra_size);
        assert_eq!(p.estimated_weight, weight(p.inputs.len()));
        assert!(
            weight(p.inputs.len()) >= opts.weight_limit
                && weight(p.inputs.len() - 1) < opts.weight_limit,
            "the input that reached the limit is the last one taken"
        );
        let mut distinct = p.inputs.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), p.inputs.len());
    }

    /// The first output, oldest first, that pays the amount and a two-input
    /// fee alone is the one `pick_preferred_rct_inputs` takes, whatever the
    /// source of randomness.
    #[test]
    fn the_oldest_output_that_covers_it_alone_is_preferred() {
        // Ten outputs, any one of which covers the amount on its own, paid in
        // ten neighbouring blocks.
        let transfers: Vec<Transfer> = (0..10u8)
            .map(|i| transfer(1_000_000_000 + u64::from(i) * 1_000, u64::from(i) + 1, i))
            .collect();

        for seed in 0..10u64 {
            let mut rng = Seq(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            let p = plan(&transfers, &[500_000_000], &options(3), &mut rng).expect("a plan");
            // No second input either: every other output was paid within ten
            // blocks of it, so none is unrelated.
            assert_eq!(p.inputs, vec![0]);
        }
    }

    /// A transaction one input pays for takes a second, the smallest of those
    /// least related to it, when that one is unrelated, so that most
    /// transactions are two in, two out.
    #[test]
    fn an_unrelated_second_input_is_added() {
        let transfers = vec![
            transfer(9_000_000_000, 100, 1),
            transfer(3_000_000_000, 500, 2),
            transfer(1_000_000_000, 700, 3),
            transfer(2_000_000_000, 105, 4),
        ];
        let o = options(3);
        let p = plan(&transfers, &[1_000_000_000], &o, &mut seq()).expect("a plan");
        assert_eq!(p.inputs, vec![0, 2], "the smallest unrelated one");
        assert_eq!(
            p.fee,
            fee_from_weight(3, estimate_tx_weight(2, o.ring_size, 2, o.extra_size))
        );
        assert_eq!(p.change, 10_000_000_000 - 1_000_000_000 - p.fee);
    }

    /// No second input when it would leave fewer than five outputs of 2 WOW,
    /// or when it is related to the first.
    #[test]
    fn a_second_input_that_costs_something_is_not_added() {
        let big = 300_000_000_000;
        let transfers = vec![transfer(big * 3, 100, 1), transfer(big, 500, 2)];
        let p = plan(&transfers, &[1_000_000_000], &options(3), &mut seq()).expect("a plan");
        assert_eq!(p.inputs, vec![0], "too few outputs of value would be left");

        let transfers = vec![transfer(9_000_000_000, 100, 1), transfer(1_000, 101, 2)];
        let p = plan(&transfers, &[1_000_000_000], &options(3), &mut seq()).expect("a plan");
        assert_eq!(p.inputs, vec![0], "paid a block apart, so related");
    }

    /// With no one output enough, the least related pair from one subaddress
    /// that is enough together is preferred, an unrelated one as soon as it is
    /// found.
    #[test]
    fn an_unrelated_pair_is_preferred() {
        let transfers = vec![
            transfer(3_000_000_000, 100, 1),
            transfer(3_000_000_000, 101, 2),
            transfer(3_000_000_000, 500, 3),
        ];
        let p = plan(&transfers, &[5_000_000_000], &options(3), &mut seq()).expect("a plan");
        assert_eq!(p.inputs, vec![2, 0], "the pair a block apart is passed over");
    }

    /// Inputs come from the account asked for only, the subaddress with the
    /// most unlocked first, and from the next once that one runs out.
    #[test]
    fn inputs_come_from_one_account_the_fullest_subaddress_first() {
        let transfers = vec![
            at(1_000_000_000, 100, 1, 0, 1),
            at(2_000_000_000, 300, 2, 0, 2),
            at(2_000_000_000, 600, 3, 0, 2),
            at(9_000_000_000, 900, 4, 1, 0),
        ];
        let p = plan(&transfers, &[4_500_000_000], &options(0), &mut seq()).expect("a plan");
        assert_eq!(p.inputs.len(), 3);
        let mut first_two = p.inputs[..2].to_vec();
        first_two.sort_unstable();
        assert_eq!(first_two, vec![1, 2], "subaddress 2 holds more");
        assert_eq!(p.inputs[2], 0, "then subaddress 1");

        let mut o = options(0);
        o.account = 1;
        let p = plan(&transfers, &[4_500_000_000], &o, &mut seq()).expect("a plan");
        assert_eq!(p.inputs, vec![3], "the other account's only output");

        o.account = 0;
        o.subaddr_indices = vec![1];
        assert!(matches!(
            plan(&transfers, &[4_500_000_000], &o, &mut seq()),
            Err(SpendError::NotEnough { .. })
        ));
    }

    /// Outputs worth less than the fee one more input costs are left out, as
    /// `ignore_fractional_outputs` has it by default.
    #[test]
    fn outputs_worth_less_than_their_fee_are_left_out() {
        let o = SpendOptions {
            ignore_fractional_outputs: true,
            ..options(3)
        };
        let threshold = 3 * (estimate_tx_weight(2, 22, 2, 0) - estimate_tx_weight(1, 22, 2, 0));
        let transfers = vec![
            transfer(threshold - 1, 100, 1),
            transfer(9_000_000_000, 500, 2),
        ];
        let p = plan(&transfers, &[1_000_000_000], &o, &mut seq()).expect("a plan");
        assert_eq!(p.inputs, vec![1], "the fractional one is no second input");

        let p = plan_sweep(&transfers, &o, &mut seq()).expect("a sweep");
        assert_eq!(p.inputs, vec![1], "nor swept");
        assert_eq!(p.left_behind, 0, "and not left behind either: ignored");
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
        let p = plan_sweep(&transfers, &options(3), &mut seq()).expect("a sweep");
        assert_eq!(p.inputs.len(), 2);
        assert_eq!(p.left_behind, 0);
    }

    /// A sweep takes one subaddress's outputs, chosen at random, and the main
    /// address's only when nothing else holds anything: sweeping two
    /// subaddresses together would tie them to each other.
    #[test]
    fn a_sweep_takes_one_subaddress_and_the_main_address_last() {
        let transfers = vec![
            at(5_000_000_000, 100, 1, 0, 0),
            at(5_000_000_000, 300, 2, 0, 1),
            at(6_000_000_000, 500, 3, 0, 2),
            at(7_000_000_000, 700, 4, 0, 2),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..16u64 {
            let mut rng = Seq(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            let p = plan_sweep(&transfers, &options(3), &mut rng).expect("a sweep");
            let mut inputs = p.inputs.clone();
            inputs.sort_unstable();
            assert!(inputs == vec![1] || inputs == vec![2, 3], "{inputs:?}");
            seen.insert(inputs);
        }
        assert_eq!(seen.len(), 2, "either subaddress, at random");

        let p = plan_sweep(&transfers[..1], &options(3), &mut seq()).expect("a sweep");
        assert_eq!(p.inputs, vec![0], "the main address when it is all there is");

        // Named indices are swept together.
        let o = SpendOptions {
            subaddr_indices: vec![0, 2],
            ..options(3)
        };
        let mut inputs = plan_sweep(&transfers, &o, &mut seq()).expect("a sweep").inputs;
        inputs.sort_unstable();
        assert_eq!(inputs, vec![0, 2, 3]);

        // And `below_amount` leaves out what is not below it.
        let o = SpendOptions {
            subaddr_indices: vec![2],
            sweep_below: 7_000_000_000,
            ..options(3)
        };
        let p = plan_sweep(&transfers, &o, &mut seq()).expect("a sweep");
        assert_eq!(p.inputs, vec![2]);
        assert_eq!(p.left_behind, 0, "the larger one was never a candidate");
    }

    /// An ordinary send that would not be relayed is refused while it is still
    /// arithmetic — before a ring has been fetched for every input and every
    /// one of them signed.
    #[test]
    fn a_send_too_heavy_to_relay_is_refused_before_it_is_built() {
        // Small outputs, so covering the amount takes far more than fit.
        let transfers: Vec<Transfer> = (0..255u16)
            .map(|i| transfer(1_000_000, u64::from(i), i as u8))
            .collect();
        let e = plan(&transfers, &[250_000_000], &options(3), &mut seq()).expect_err("too heavy");
        match e {
            SpendError::TooHeavy { weight, limit } => {
                assert!(weight >= limit);
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

        // No one output covers 11, and the only pair that does is the 9 and
        // the 3, the later-received taken first.
        let p = plan(&transfers, &[11_000_000_000], &options(3), &mut seq()).expect("a plan");
        assert_eq!(p.inputs, vec![2, 1], "the pair that covers it");
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

    /// Spending is confined to one account, account 0 unless another is named.
    #[test]
    fn it_spends_from_one_account() {
        let mut other = transfer(9_000_000_000, 100, 1);
        other.subaddress = SubaddressIndex::new(3, 7);
        let mine = transfer(8_000_000_000, 100, 2);
        let transfers = vec![other, mine];

        let mut o = options(3);
        let eligible = spendable(&transfers, &o);
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].0, 1);

        o.account = 3;
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
        let p = plan_sweep(&transfers, &options(3), &mut seq()).expect("a sweep");

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
        assert!(plan_sweep(&[], &options(3), &mut seq()).is_err());

        let dust = vec![transfer(10, 100, 1)];
        let e = plan_sweep(&dust, &options(1_000), &mut seq()).expect_err("cannot pay");
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
        o.account = 2;
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
        let p = plan_sweep(&transfers, &options(3), &mut seq()).expect("a sweep");
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
