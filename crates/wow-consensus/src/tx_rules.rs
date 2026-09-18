//! Coinbase and transaction validation.
//!
//! `specs/06-consensus-rules.md` §4 and §5.
//!
//! Everything here is a pure function of a transaction, a hard-fork version and
//! whatever chain context the rule needs, passed explicitly. Nothing reaches
//! into storage: `check_tx_inputs`'s one database dependency —
//! `get_num_outputs(amount)`, which decides whether a pre-RingCT amount is
//! *mixable* — arrives as a closure.
//!
//! Signature verification (§5.11) and double-spend detection (§5.12) are not
//! here. The first belongs with the RingCT code and the second is a property of
//! the chain, not of a transaction.

use wow_types::block::MAX_VOTE;
use wow_types::{Block, RctType, Transaction, TxIn, TxOut, TxOutTarget};

use crate::constants::*;
use crate::hardfork::gates::*;

/// Why a transaction or coinbase was rejected.
///
/// The variants carry enough to say *which* input or output failed, because a
/// bare "invalid ring size" over a 22-ring transaction is not a debuggable
/// message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxError {
    // -- §4 miner block-header signing (HF 18+) --
    /// From HF 18 the coinbase must have **exactly one** output.
    CoinbaseOutputCount {
        found: usize,
    },
    /// `block.vote > MAX_VOTE` (`specs/06` §4.3).
    InvalidVote {
        vote: u16,
    },
    /// The HF 18 header signature does not verify against the coinbase
    /// output's one-time key.
    MinerSignature,

    // -- §5.1 coinbase --
    /// `miner_tx.vin.len() != 1` or `vin[0]` is not `txin_gen`.
    BadCoinbaseInput,
    /// From HF 15 the coinbase must be v2.
    CoinbaseVersionTooLow {
        version: u64,
    },
    /// From HF 15 a v2 coinbase must carry `RCTTypeNull`.
    CoinbaseHasRctSignatures {
        rct_type: RctType,
    },
    /// `txin_gen.height != block height`.
    CoinbaseHeightMismatch {
        found: u64,
        expected: u64,
    },
    /// The coinbase unlock time is not what the regime demands (§5.1.1).
    CoinbaseUnlockTime {
        found: u64,
        expected: u64,
    },
    /// The output amounts sum past `u64`.
    OutputsOverflow,

    // -- §5.2 semantics --
    NoInputs,
    /// The same key image appears twice in one transaction.
    DuplicateKeyImage {
        index: usize,
    },
    /// An input is not `txin_to_key`.
    UnsupportedInputType {
        index: usize,
        tag: u8,
    },
    /// A v2 transaction has a non-zero output amount.
    NonZeroOutputAmountInV2 {
        index: usize,
    },
    /// An output target is not a key type at all.
    InvalidOutputTarget {
        index: usize,
        tag: u8,
    },
    /// v1 only: `sum(inputs) < sum(outputs)`.
    OutputsExceedInputs,
    /// The input sum overflows.
    InputsOverflow,
    /// v1 only: the signature count does not match the inputs.
    WrongSignatureCount {
        expected: usize,
        found: usize,
    },

    // -- §5.3 ring size --
    /// From HF 15 every input must have the same ring size.
    VaryingRingSize {
        min: usize,
        max: usize,
    },
    /// Below the minimum, with nothing unmixable to justify it.
    RingTooSmall {
        mixin: usize,
        min_mixin: usize,
    },
    /// Below the minimum, with unmixable inputs but more than one mixable one.
    TooManyMixableInputs {
        mixable: usize,
    },
    /// Not one of the ring sizes this fork allows.
    InvalidRingSize {
        mixin: usize,
        min_mixin: usize,
    },

    // -- §5.4 version bounds --
    TxVersionTooHigh {
        version: u64,
        max: u64,
    },
    TxVersionTooLow {
        version: u64,
        min: u64,
    },

    // -- §5.5 / §5.6 outputs --
    /// The output type is wrong for this fork.
    WrongOutputType {
        index: usize,
        tag: u8,
    },
    /// At HF 20 exactly, all outputs must be of the *same* type.
    MixedOutputTypes {
        index: usize,
        tag: u8,
        first: u8,
    },
    /// From HF 15 a v2 transaction needs at least two outputs.
    TooFewOutputs {
        found: usize,
    },

    // -- §5.7 / §5.8 --
    /// Key images must be strictly decreasing by `memcmp`.
    UnsortedInputs {
        index: usize,
    },
    /// From HF 15 a referenced output must be at least 4 blocks old.
    OutputTooRecent {
        max_used_block_height: u64,
        chain_height: u64,
    },

    // -- §5.10 --
    /// This RingCT type is not permitted at this fork.
    ForbiddenRctType {
        rct_type: RctType,
    },
}

/// `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` — 60 blocks, below HF 16.
pub const MINED_MONEY_UNLOCK_WINDOW: u64 = 60;
/// `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_V2` — 288 blocks, from HF 18.
pub const MINED_MONEY_UNLOCK_WINDOW_V2: u64 = 288;

/// The coinbase unlock time the chain demands at `height` (`specs/06` §5.1.1).
///
/// Three regimes:
///
/// ```text
/// hf >= 18:  height + 288
/// hf 16, 17: height + 2 * u64::from_str_radix(&hex(block_id(height - N))[..3], 16) + 288
/// hf <  16:  height + 60
/// ```
///
/// where `N` is 1337 on mainnet and 5 elsewhere.
///
/// # The three hex characters
///
/// `specs/06` §9.9 flags this and it is worth restating, because getting it
/// wrong rejects every HF 16–17 block. `pod_to_hex` prints the 32 bytes of the
/// block id in **storage order**, lowercase, and the C takes `substr(0, 3)` of
/// that string — the first byte and the high nibble of the second, as a
/// 12-bit big-endian number in `0..=0xfff`. Doubled, that is `0..=8190`, so
/// the window ran from 288 to 8478 blocks (1 to ~29 days at 300 s).
///
/// It is *not* a little-endian read of the first two bytes, and not a read of
/// the last bytes. Pass `block_id` as the raw 32 bytes and this does the rest.
pub fn coinbase_unlock_time(
    hf_version: u8,
    height: u64,
    referenced_block_id: Option<&[u8; 32]>,
) -> u64 {
    if hf_version >= HF_VERSION_FIXED_UNLOCK {
        return height + MINED_MONEY_UNLOCK_WINDOW_V2;
    }
    if hf_version >= HF_VERSION_DYNAMIC_UNLOCK {
        let id = referenced_block_id.expect("HF 16-17 needs the referenced block id");
        return height + dynamic_unlock_window(id);
    }
    height + MINED_MONEY_UNLOCK_WINDOW
}

/// How far back the HF 16–17 rule looks: 1337 blocks on mainnet, 5 elsewhere.
pub const fn dynamic_unlock_lookback(network: wow_types::Network) -> u64 {
    match network {
        wow_types::Network::Mainnet => 1337,
        _ => 5,
    }
}

/// `blk_num * 2 + 288` from the first three hex characters of a block id.
///
/// Split out because it is the piece most likely to be written as a byte-swap
/// (`specs/15` §3.2 asks for it to be checked against real blocks).
pub fn dynamic_unlock_window(block_id: &[u8; 32]) -> u64 {
    // pod_to_hex prints byte 0 as the first two characters and byte 1's high
    // nibble as the third, so the three characters are this 12-bit value.
    let twelve_bits = (u64::from(block_id[0]) << 4) | u64::from(block_id[1] >> 4);
    twelve_bits * 2 + MINED_MONEY_UNLOCK_WINDOW_V2
}

/// `prevalidate_miner_transaction` — the whole of it (`specs/06` §4 and §5.1).
///
/// The two halves are one function in the C++
/// (`Blockchain::prevalidate_miner_transaction`) and they stay one here, so
/// that a caller cannot run §5.1 alone and accept HF 18+ blocks signed by
/// nobody. Both of the C++'s call sites — `handle_block_to_main_chain` and
/// `handle_alternative_block` — go through this, and so do both of ours.
///
/// `hf_version` is the block's own `major_version`: `specs/06` §2 step 6 has
/// already refused a block whose version is not the one the fork table demands.
pub fn prevalidate_miner_tx(
    block: &Block,
    hf_version: u8,
    height: u64,
    expected_unlock_time: u64,
) -> Result<(), TxError> {
    check_miner_signature(block, hf_version)?;
    check_coinbase(&block.miner_tx, hf_version, height, expected_unlock_time)
}

/// Miner block-header signing (`specs/06` §4), the first block of
/// `prevalidate_miner_transaction`. A no-op below HF 18.
///
/// # This is what makes Wownero solo-mined
///
/// The signature is made with the **one-time secret key of the coinbase
/// output**, which only the holder of the mining address's private spend key
/// can derive (`specs/06` §4.1). Three rules here each rule out pooled mining
/// on their own: the reward cannot be split, because there is exactly one
/// output; the signature cannot be produced by a pool, because it needs the
/// spend key; and hashing cannot be delegated, because `signature` sits inside
/// the hashing blob and so must be remade for every nonce (§4.2).
///
/// Skipping this check does not fail closed. It accepts blocks the C++
/// rejects, so a node without it follows a chain the rest of the network does
/// not have — including one mined to an address whose keys nobody held.
pub fn check_miner_signature(block: &Block, hf_version: u8) -> Result<(), TxError> {
    if hf_version < HF_VERSION_BLOCK_HEADER_MINER_SIG {
        return Ok(());
    }
    let vout = &block.miner_tx.prefix.vout;

    // 1. Exactly one coinbase output.
    if vout.len() != 1 {
        return Err(TxError::CoinbaseOutputCount { found: vout.len() });
    }
    // 2. The output types, which §5.1 checks again at the end. The C++ calls
    //    `check_output_types` twice as well, and the order is what matters:
    //    this call runs before the vote and the signature, so a wrong output
    //    type is reported as one rather than as a bad signature.
    check_output_types(vout, hf_version)?;
    // 3. The vote is consensus-bounded from HF 18.
    if block.header.vote > MAX_VOTE {
        return Err(TxError::InvalidVote {
            vote: block.header.vote,
        });
    }
    // 4, 5, 6. Verify the signature over `sig_data` with the output's key.
    //
    // `sig_data` is None only below HF 18, which it reads off the header's own
    // `major_version` rather than off `hf_version`. The two agree by the time
    // this runs. A block where they did not is one the C++ would hash without
    // the signature field and then reject, so rejecting is right here too.
    let Some(sig_data) = block.sig_data() else {
        return Err(TxError::MinerSignature);
    };
    // Step 2 passed, so the target is a key type and this is always Some.
    let Some(output_key) = vout[0].target.public_key() else {
        return Err(TxError::MinerSignature);
    };
    if !wow_crypto::check_signature(&sig_data, &output_key, &block.header.signature) {
        return Err(TxError::MinerSignature);
    }
    Ok(())
}

/// `validate_miner_transaction`'s prevalidation (`specs/06` §5.1), everything
/// except the reward arithmetic — that is
/// [`crate::emission::validate_miner_reward`].
///
/// This is the §5.1 half alone. Prefer [`prevalidate_miner_tx`], which runs
/// the HF 18 header-signature block (§4) that has to come first.
pub fn check_coinbase(
    tx: &Transaction,
    hf_version: u8,
    height: u64,
    expected_unlock_time: u64,
) -> Result<(), TxError> {
    if tx.prefix.vin.len() != 1 {
        return Err(TxError::BadCoinbaseInput);
    }
    let TxIn::Gen {
        height: claimed_height,
    } = tx.prefix.vin[0]
    else {
        return Err(TxError::BadCoinbaseInput);
    };

    if tx.prefix.version <= 1 && hf_version >= HF_VERSION_MIN_V2_COINBASE_TX {
        return Err(TxError::CoinbaseVersionTooLow {
            version: tx.prefix.version,
        });
    }
    if hf_version >= HF_VERSION_REJECT_SIGS_IN_COINBASE
        && tx.prefix.version >= 2
        && tx.rct_signatures.ty != RctType::Null
    {
        return Err(TxError::CoinbaseHasRctSignatures {
            rct_type: tx.rct_signatures.ty,
        });
    }
    if claimed_height != height {
        return Err(TxError::CoinbaseHeightMismatch {
            found: claimed_height,
            expected: height,
        });
    }
    if tx.prefix.unlock_time != expected_unlock_time {
        return Err(TxError::CoinbaseUnlockTime {
            found: tx.prefix.unlock_time,
            expected: expected_unlock_time,
        });
    }
    check_outs_overflow(&tx.prefix.vout)?;
    check_output_types(&tx.prefix.vout, hf_version)?;
    Ok(())
}

/// `check_outs_overflow` — the output amounts must sum inside `u64`.
pub fn check_outs_overflow(vout: &[TxOut]) -> Result<u64, TxError> {
    let mut sum = 0u64;
    for o in vout {
        sum = sum.checked_add(o.amount).ok_or(TxError::OutputsOverflow)?;
    }
    Ok(sum)
}

/// `check_output_types` (`specs/06` §5.5).
///
/// ```text
/// hf >  20:  txout_to_tagged_key only
/// hf <  20:  txout_to_key only
/// hf == 20:  either -- but every output in the transaction must match the
///            type of vout[0]
/// ```
///
/// The same-type clause at HF 20 is **not** in `specs/06` §5.5's pseudocode
/// (`docs/spec-deltas.md` §14). Mainnet is at HF 20, so this is live.
pub fn check_output_types(vout: &[TxOut], hf_version: u8) -> Result<(), TxError> {
    for (i, o) in vout.iter().enumerate() {
        let tag = o.target.tag();
        if hf_version > HF_VERSION_VIEW_TAGS {
            if !matches!(o.target, TxOutTarget::ToTaggedKey { .. }) {
                return Err(TxError::WrongOutputType { index: i, tag });
            }
        } else if hf_version < HF_VERSION_VIEW_TAGS {
            if !matches!(o.target, TxOutTarget::ToKey { .. }) {
                return Err(TxError::WrongOutputType { index: i, tag });
            }
        } else {
            // The grace period: either type, but not both in one transaction.
            if !matches!(
                o.target,
                TxOutTarget::ToKey { .. } | TxOutTarget::ToTaggedKey { .. }
            ) {
                return Err(TxError::WrongOutputType { index: i, tag });
            }
            let first = vout[0].target.tag();
            if tag != first {
                return Err(TxError::MixedOutputTypes {
                    index: i,
                    tag,
                    first,
                });
            }
        }
    }
    Ok(())
}

/// `specs/06` §5.6: from HF 15 a v2 transaction needs at least two outputs.
///
/// Coinbase is exempt — it is validated by [`check_coinbase`].
pub fn check_min_outputs(tx: &Transaction, hf_version: u8) -> Result<(), TxError> {
    if hf_version >= HF_VERSION_MIN_2_OUTPUTS && tx.prefix.version >= 2 && tx.prefix.vout.len() < 2
    {
        return Err(TxError::TooFewOutputs {
            found: tx.prefix.vout.len(),
        });
    }
    Ok(())
}

/// `specs/06` §5.7: key images strictly decreasing under `memcmp`.
///
/// The C rejects when `memcmp(current, last) >= 0`, so equal images are
/// rejected here as well as by the duplicate check — two rules that happen to
/// overlap.
pub fn check_inputs_sorted(tx: &Transaction) -> Result<(), TxError> {
    let mut last: Option<&[u8; 32]> = None;
    for (i, input) in tx.prefix.vin.iter().enumerate() {
        let TxIn::ToKey { k_image, .. } = input else {
            continue;
        };
        let bytes = k_image.as_bytes();
        if let Some(prev) = last {
            if bytes.as_slice() >= prev.as_slice() {
                return Err(TxError::UnsortedInputs { index: i });
            }
        }
        last = Some(bytes);
    }
    Ok(())
}

/// `specs/06` §5.8: from HF 15 every referenced output must be at least
/// `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` (4) blocks old.
pub fn check_min_output_age(
    hf_version: u8,
    max_used_block_height: u64,
    chain_height: u64,
) -> Result<(), TxError> {
    if hf_version < HF_VERSION_ENFORCE_MIN_AGE {
        return Ok(());
    }
    if max_used_block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE > chain_height {
        return Err(TxError::OutputTooRecent {
            max_used_block_height,
            chain_height,
        });
    }
    Ok(())
}

/// `rct::is_rct_old_bulletproof` — the two types Wownero inserted into the
/// numbering, 3 and 4.
pub const fn is_rct_old_bulletproof(ty: RctType) -> bool {
    matches!(ty, RctType::FullBulletproof | RctType::SimpleBulletproof)
}

/// `rct::is_rct_bulletproof` — **includes CLSAG**, which is the part that
/// surprises. CLSAG (7) is a signature scheme, but it carries *Bulletproof*
/// range proofs, so the `hf > 18` gate that forbids "Bulletproof range proofs"
/// forbids CLSAG along with types 3 through 6.
pub const fn is_rct_bulletproof(ty: RctType) -> bool {
    matches!(
        ty,
        RctType::SimpleBulletproof
            | RctType::FullBulletproof
            | RctType::Bulletproof
            | RctType::Bulletproof2
            | RctType::Clsag
    )
}

/// `rct::is_rct_bp_plus_legacy` — type 8 only.
pub const fn is_rct_bp_plus_legacy(ty: RctType) -> bool {
    matches!(ty, RctType::BulletproofPlus)
}

/// `rct::is_rct_bp_plus_full` — type 9 only.
pub const fn is_rct_bp_plus_full(ty: RctType) -> bool {
    matches!(ty, RctType::BulletproofPlusFullCommit)
}

/// `specs/06` §5.10: which RingCT types this fork permits.
///
/// Transcribed as the C's **nine sequential gates**, in order, rather than as a
/// per-type table — `specs/06` §5.10 presents it as a table and two of the
/// gates are missing from it (`docs/spec-deltas.md` §15).
///
/// ```text
/// 1. hf < 13, v>=2: type == Bulletproof2 (6)           -> reject
/// 2. hf > 13, v>=2: type == Bulletproof (5)            -> reject
/// 3. hf < 16, v>=2: type == Clsag (7)                  -> reject
/// 4. hf > 16, v>=2: type <= Bulletproof2 (6)           -> reject
/// 5. hf > 11, v>=2: is_rct_old_bulletproof (3, 4)      -> reject
/// 6. hf < 18, v>=2: is_rct_bp_plus_legacy (8)
///                   OR bulletproofs_plus non-empty     -> reject
/// 7. hf > 18, v>=2: is_rct_bulletproof (3,4,5,6,7)     -> reject
/// 8. hf < 21, v>=2: is_rct_bp_plus_full (9)            -> reject
/// 9. hf > 21:       is_rct_bp_plus_legacy (8)          -> reject
/// ```
///
/// Every bound is **strictly** greater or less, so each gate permits *two*
/// adjacent types across its whole height range — which is exactly why the
/// "+1 gate" forks 14, 17, 19 and 21 exist, to close each window one range
/// later.
///
/// Two details the table form loses. Gates 1–8 are guarded by
/// `tx.version >= 2`, so a v1 transaction skips them entirely; **gate 9 is
/// not**, though it is inert for v1 because such a transaction carries
/// `RCTTypeNull`. And gate 6 rejects on *proofs present* as well as on the
/// type, so a transaction claiming an older type while carrying BP+ proofs is
/// caught.
pub fn check_rct_type_allowed(
    ty: RctType,
    tx_version: u64,
    has_bulletproofs_plus: bool,
    hf_version: u8,
) -> Result<(), TxError> {
    let reject = || Err(TxError::ForbiddenRctType { rct_type: ty });

    if tx_version >= 2 {
        if hf_version < HF_VERSION_SMALLER_BP && ty == RctType::Bulletproof2 {
            return reject();
        }
        if hf_version > HF_VERSION_SMALLER_BP && ty == RctType::Bulletproof {
            return reject();
        }
        if hf_version < HF_VERSION_CLSAG && ty == RctType::Clsag {
            return reject();
        }
        if hf_version > HF_VERSION_CLSAG && (ty as u8) <= (RctType::Bulletproof2 as u8) {
            return reject();
        }
        if hf_version > 11 && is_rct_old_bulletproof(ty) {
            return reject();
        }
        if hf_version < HF_VERSION_BULLETPROOF_PLUS
            && (is_rct_bp_plus_legacy(ty) || has_bulletproofs_plus)
        {
            return reject();
        }
        if hf_version > HF_VERSION_BULLETPROOF_PLUS && is_rct_bulletproof(ty) {
            return reject();
        }
        if hf_version < HF_VERSION_BP_PLUS_FULL_COMMIT && is_rct_bp_plus_full(ty) {
            return reject();
        }
    }
    // Note: no version guard on this one, matching the C.
    if hf_version > HF_VERSION_BP_PLUS_FULL_COMMIT && is_rct_bp_plus_legacy(ty) {
        return reject();
    }
    Ok(())
}

/// [`check_rct_type_allowed`] applied to a whole transaction.
pub fn check_tx_rct_type(tx: &Transaction, hf_version: u8) -> Result<(), TxError> {
    check_rct_type_allowed(
        tx.rct_signatures.ty,
        tx.prefix.version,
        !tx.rct_signatures.bulletproofs_plus.is_empty(),
        hf_version,
    )
}

/// How a transaction's inputs classify for the ring-size rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MixinSummary {
    /// The smallest `key_offsets.len() - 1` over all `txin_to_key` inputs.
    ///
    /// `usize::MAX` when there are none, matching the C's
    /// `std::numeric_limits<size_t>::max()` initialiser — which then fails the
    /// `min != max` check at HF 15 and above.
    pub min_actual_mixin: usize,
    /// The largest, or 0 when there are no `txin_to_key` inputs.
    pub max_actual_mixin: usize,
    pub n_mixable: usize,
    pub n_unmixable: usize,
}

/// Classify the inputs (`specs/06` §5.3, first half).
///
/// `num_outputs(amount)` is `m_db->get_num_outputs(amount)`. Amount 0 (RingCT)
/// is **always** considered mixable without consulting it — the C's comment
/// says why: right after the RingCT fork there genuinely were not enough to mix
/// with, and the rule would have stalled the chain.
pub fn summarise_mixin(
    tx: &Transaction,
    hf_version: u8,
    num_outputs: impl Fn(u64) -> u64,
) -> MixinSummary {
    let min_mixin = min_mixin(hf_version);
    let mut s = MixinSummary {
        min_actual_mixin: usize::MAX,
        max_actual_mixin: 0,
        n_mixable: 0,
        n_unmixable: 0,
    };

    for input in &tx.prefix.vin {
        let TxIn::ToKey {
            amount,
            key_offsets,
            ..
        } = input
        else {
            continue;
        };
        if *amount == 0 {
            s.n_mixable += 1;
        } else if num_outputs(*amount) <= min_mixin as u64 {
            s.n_unmixable += 1;
        } else {
            s.n_mixable += 1;
        }
        // `key_offsets.len() - 1` would underflow on an empty ring; the C reads
        // `size() - 1` on a `size_t` and wraps to SIZE_MAX, which then fails
        // every bound below. `saturating_sub` reaches the same verdict without
        // the wrap.
        let ring_mixin = key_offsets.len().saturating_sub(1);
        s.min_actual_mixin = s.min_actual_mixin.min(ring_mixin);
        s.max_actual_mixin = s.max_actual_mixin.max(ring_mixin);
    }
    s
}

/// `min_mixin` — 21 from HF 9, 7 before.
pub const fn min_mixin(hf_version: u8) -> usize {
    if hf_version >= HF_VERSION_MIN_MIXIN_21 {
        21
    } else {
        7
    }
}

/// `specs/06` §5.3, second half: the ring-size branch table.
///
/// Transcribed clause for clause, including the third one, which is vacuous —
/// `hf < 9 && hf >= 7 + 2` can never hold. The spec says to keep it; removing
/// it would be safe today but introduces a difference from upstream for no
/// gain.
#[allow(
    clippy::impossible_comparisons,
    reason = "`hf < 9 && hf >= 7 + 2` is the vacuous third clause of the C's               branch table. `specs/06` §5.3 says to keep it as written: it is               harmless, and removing it introduces a difference from upstream               for no gain. `the_vacuous_clause_never_fires` asserts it stays               vacuous, so a future table change cannot make it fire unnoticed."
)]
pub fn check_ring_size(s: &MixinSummary, hf_version: u8) -> Result<(), TxError> {
    let min_mixin = min_mixin(hf_version);

    if hf_version >= HF_VERSION_SAME_MIXIN && s.min_actual_mixin != s.max_actual_mixin {
        return Err(TxError::VaryingRingSize {
            min: s.min_actual_mixin,
            max: s.max_actual_mixin,
        });
    }

    // The grace period at HF 9: a ring of 8 (mixin 7) is still accepted while
    // the network moves to 22.
    let below_min = s.min_actual_mixin < min_mixin
        && !(hf_version == HF_VERSION_MIN_MIXIN_21 && s.min_actual_mixin == 7);

    if below_min {
        if s.n_unmixable == 0 {
            return Err(TxError::RingTooSmall {
                mixin: s.min_actual_mixin,
                min_mixin,
            });
        }
        if s.n_mixable > 1 {
            return Err(TxError::TooManyMixableInputs {
                mixable: s.n_mixable,
            });
        }
        return Ok(());
    }

    let invalid = (hf_version > HF_VERSION_MIN_MIXIN_21 && s.min_actual_mixin > 21)
        || (hf_version == HF_VERSION_MIN_MIXIN_21
            && s.min_actual_mixin != 21
            && s.min_actual_mixin != 7)
        // Vacuous: HF_VERSION_MIN_MIXIN_7 + 2 == 9 == HF_VERSION_MIN_MIXIN_21.
        || (hf_version < HF_VERSION_MIN_MIXIN_21
            && hf_version >= HF_VERSION_MIN_MIXIN_7 + 2
            && s.min_actual_mixin > 7)
        || ((hf_version == HF_VERSION_MIN_MIXIN_7
            || hf_version == HF_VERSION_MIN_MIXIN_7 + 1)
            && s.min_actual_mixin != 7);

    if invalid {
        return Err(TxError::InvalidRingSize {
            mixin: s.min_actual_mixin,
            min_mixin,
        });
    }
    Ok(())
}

/// `specs/06` §5.4: transaction version bounds.
///
/// ```text
/// max = if hf <= 3 { 1 } else { 2 }
/// min = if n_unmixable > 0 { 1 } else if hf >= 6 { 2 } else { 1 }
/// ```
///
/// The `n_unmixable > 0` escape is what still lets a v1 transaction spend
/// pre-RingCT dust long after RingCT became mandatory.
pub fn check_tx_version(version: u64, hf_version: u8, n_unmixable: usize) -> Result<(), TxError> {
    let max = if hf_version <= 3 { 1 } else { 2 };
    if version > max {
        return Err(TxError::TxVersionTooHigh { version, max });
    }
    let min = if n_unmixable > 0 {
        1
    } else if hf_version >= HF_VERSION_ENFORCE_RCT {
        2
    } else {
        1
    };
    if version < min {
        return Err(TxError::TxVersionTooLow { version, min });
    }
    Ok(())
}

/// `check_tx_semantic`'s pre-input checks (`specs/06` §5.2).
///
/// Returns the fee for a v1 transaction (`sum(inputs) - sum(outputs)`); a v2
/// transaction carries its fee in `rct_signatures` and this returns `None`.
pub fn check_tx_semantic(tx: &Transaction) -> Result<Option<u64>, TxError> {
    if tx.prefix.vin.is_empty() {
        return Err(TxError::NoInputs);
    }

    // check_inputs_types_supported, plus the duplicate-key-image scan.
    let mut seen: Vec<&[u8; 32]> = Vec::with_capacity(tx.prefix.vin.len());
    let mut inputs_sum = 0u64;
    for (i, input) in tx.prefix.vin.iter().enumerate() {
        let TxIn::ToKey {
            amount, k_image, ..
        } = input
        else {
            return Err(TxError::UnsupportedInputType {
                index: i,
                tag: input.tag(),
            });
        };
        let bytes = k_image.as_bytes();
        if seen.contains(&bytes) {
            return Err(TxError::DuplicateKeyImage { index: i });
        }
        seen.push(bytes);
        inputs_sum = inputs_sum
            .checked_add(*amount)
            .ok_or(TxError::InputsOverflow)?;
    }

    // check_outs_valid: a key target, and for v2 a zero amount.
    for (i, o) in tx.prefix.vout.iter().enumerate() {
        if o.target.public_key().is_none() {
            return Err(TxError::InvalidOutputTarget {
                index: i,
                tag: o.target.tag(),
            });
        }
        if tx.prefix.version >= 2 && o.amount != 0 {
            return Err(TxError::NonZeroOutputAmountInV2 { index: i });
        }
    }
    let outputs_sum = check_outs_overflow(&tx.prefix.vout)?;

    if tx.prefix.version >= 2 {
        return Ok(None);
    }

    // v1: the fee is the difference, and one signature row per input.
    if outputs_sum > inputs_sum {
        return Err(TxError::OutputsExceedInputs);
    }
    if tx.signatures.len() != tx.prefix.vin.len() {
        return Err(TxError::WrongSignatureCount {
            expected: tx.prefix.vin.len(),
            found: tx.signatures.len(),
        });
    }
    Ok(Some(inputs_sum - outputs_sum))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wow_crypto::random::Rng;
    use wow_types::{BlockHeader, KeyImage, PublicKey, TransactionPrefix, ViewTag};

    fn key(n: u8) -> PublicKey {
        PublicKey([n; 32])
    }

    fn image(n: u8) -> KeyImage {
        KeyImage([n; 32])
    }

    fn out_to_key(n: u8) -> TxOut {
        TxOut {
            amount: 0,
            target: TxOutTarget::ToKey { key: key(n) },
        }
    }

    fn out_tagged(n: u8) -> TxOut {
        TxOut {
            amount: 0,
            target: TxOutTarget::ToTaggedKey {
                key: key(n),
                view_tag: ViewTag(n),
            },
        }
    }

    fn tx(version: u64, vin: Vec<TxIn>, vout: Vec<TxOut>) -> Transaction {
        Transaction {
            prefix: TransactionPrefix {
                version,
                unlock_time: 0,
                vin,
                vout,
                extra: Vec::new(),
            },
            signatures: Vec::new(),
            rct_signatures: Default::default(),
            prefix_size: 0,
            unprunable_size: 0,
        }
    }

    fn to_key(amount: u64, ring: usize, img: u8) -> TxIn {
        TxIn::ToKey {
            amount,
            key_offsets: vec![1; ring],
            k_image: image(img),
        }
    }

    // ---- §4 miner block-header signing (HF 18+) ----

    /// A block at `version` whose coinbase pays a fresh key, with a valid
    /// header signature by that key's secret. Returns the block and the key,
    /// so a test can re-sign after tampering.
    fn signed_block(version: u8) -> (Block, PublicKey, wow_types::SecretKey) {
        let mut rng = Rng::deterministic_test_seed();
        let (public, secret) = rng.generate_keys();
        let target = if version >= HF_VERSION_VIEW_TAGS {
            TxOutTarget::ToTaggedKey {
                key: public,
                view_tag: ViewTag(9),
            }
        } else {
            TxOutTarget::ToKey { key: public }
        };
        let mut block = Block {
            header: BlockHeader {
                major_version: version,
                minor_version: version,
                nonce: 0x0102_0304,
                vote: 1,
                ..Default::default()
            },
            miner_tx: tx(
                2,
                vec![TxIn::Gen { height: 5 }],
                vec![TxOut { amount: 7, target }],
            ),
            tx_hashes: Vec::new(),
        };
        resign(&mut block, &public, &secret);
        (block, public, secret)
    }

    fn resign(block: &mut Block, public: &PublicKey, secret: &wow_types::SecretKey) {
        let mut rng = Rng::deterministic_test_seed();
        let sig_data = block.sig_data().expect("HF 18+ has sig_data");
        block.header.signature =
            wow_crypto::generate_signature(&mut rng, &sig_data, public, secret).unwrap();
    }

    #[test]
    fn a_signed_header_passes_from_hf_18() {
        for version in [HF_VERSION_BLOCK_HEADER_MINER_SIG, HF_VERSION_VIEW_TAGS] {
            let (block, ..) = signed_block(version);
            assert_eq!(
                check_miner_signature(&block, version),
                Ok(()),
                "hf {version}"
            );
        }
    }

    /// Below HF 18 the header carries no signature at all, so §4 must not
    /// look: a block with a garbage signature, an out-of-range vote and two
    /// coinbase outputs is fine at HF 17, because neither field is even
    /// serialized there.
    #[test]
    fn the_rule_does_not_exist_below_hf_18() {
        let (mut block, ..) = signed_block(HF_VERSION_BLOCK_HEADER_MINER_SIG);
        block.header.major_version = HF_VERSION_BLOCK_HEADER_MINER_SIG - 1;
        block.header.signature = Default::default();
        block.header.vote = 40_000;
        block.miner_tx.prefix.vout.push(out_to_key(3));
        assert_eq!(
            check_miner_signature(&block, HF_VERSION_BLOCK_HEADER_MINER_SIG - 1),
            Ok(())
        );
    }

    /// The check that makes pooled mining impossible: the reward cannot be
    /// split, because there is exactly one output to split.
    #[test]
    fn the_coinbase_must_have_exactly_one_output_from_hf_18() {
        let v = HF_VERSION_BLOCK_HEADER_MINER_SIG;
        let (mut block, public, secret) = signed_block(v);

        block.miner_tx.prefix.vout.push(out_to_key(3));
        resign(&mut block, &public, &secret);
        assert_eq!(
            check_miner_signature(&block, v),
            Err(TxError::CoinbaseOutputCount { found: 2 }),
            "a pool payout coinbase, signed or not"
        );

        block.miner_tx.prefix.vout.clear();
        assert_eq!(
            check_miner_signature(&block, v),
            Err(TxError::CoinbaseOutputCount { found: 0 })
        );
    }

    /// An unsigned block is what `get_block_template` hands a pool or a
    /// stratum miner, and what the C++ miner produces without `--spendkey`.
    #[test]
    fn an_unsigned_header_is_rejected() {
        let v = HF_VERSION_BLOCK_HEADER_MINER_SIG;
        let (mut block, ..) = signed_block(v);
        block.header.signature = Default::default();
        assert_eq!(
            check_miner_signature(&block, v),
            Err(TxError::MinerSignature)
        );
    }

    /// Signed with a key that is not the coinbase output's: mining to an
    /// address whose spend key the miner does not hold.
    #[test]
    fn a_signature_by_the_wrong_key_is_rejected() {
        let v = HF_VERSION_BLOCK_HEADER_MINER_SIG;
        let (mut block, ..) = signed_block(v);
        // The same seed, so the first pair is the one signed_block used;
        // the second is guaranteed to be a different key.
        let mut rng = Rng::deterministic_test_seed();
        rng.generate_keys();
        let (other_public, other_secret) = rng.generate_keys();
        resign(&mut block, &other_public, &other_secret);
        assert_eq!(
            check_miner_signature(&block, v),
            Err(TxError::MinerSignature)
        );
    }

    /// `specs/06` §4.2: `signature` is inside the hashing blob, so it covers
    /// the nonce. This is what stops a miner delegating the search: every
    /// nonce needs a fresh signature, and so needs the spend key.
    #[test]
    fn the_signature_covers_the_nonce() {
        let v = HF_VERSION_BLOCK_HEADER_MINER_SIG;
        let (mut block, ..) = signed_block(v);
        assert_eq!(check_miner_signature(&block, v), Ok(()));
        block.header.nonce = block.header.nonce.wrapping_add(1);
        assert_eq!(
            check_miner_signature(&block, v),
            Err(TxError::MinerSignature),
            "a signature hoisted out of the nonce loop would verify here"
        );
    }

    /// `sig_data` zeroes `signature` but keeps `vote`, so the signature
    /// commits to the vote (`specs/05` §4.4).
    #[test]
    fn the_signature_covers_the_vote() {
        let v = HF_VERSION_BLOCK_HEADER_MINER_SIG;
        let (mut block, ..) = signed_block(v);
        block.header.vote = 2;
        assert_eq!(
            check_miner_signature(&block, v),
            Err(TxError::MinerSignature)
        );
    }

    #[test]
    fn the_vote_is_bounded_from_hf_18() {
        let v = HF_VERSION_BLOCK_HEADER_MINER_SIG;
        let (mut block, public, secret) = signed_block(v);
        for vote in 0..=MAX_VOTE {
            block.header.vote = vote;
            resign(&mut block, &public, &secret);
            assert_eq!(check_miner_signature(&block, v), Ok(()), "vote {vote}");
        }
        // The vote is checked before the signature, so a perfectly valid
        // signature over vote 3 must not save it.
        block.header.vote = MAX_VOTE + 1;
        resign(&mut block, &public, &secret);
        assert_eq!(
            check_miner_signature(&block, v),
            Err(TxError::InvalidVote { vote: 3 })
        );
    }

    /// The C++ checks output types inside the §4 block as well as at the end
    /// of §5.1, and the earlier call is what reports a wrong type. Getting
    /// the order wrong would report a bad signature instead.
    #[test]
    fn a_wrong_output_type_is_reported_as_one_not_as_a_bad_signature() {
        let v = HF_VERSION_VIEW_TAGS + 1;
        let (mut block, public, secret) = signed_block(v);
        block.miner_tx.prefix.vout[0].target = TxOutTarget::ToKey { key: key(1) };
        resign(&mut block, &public, &secret);
        assert_eq!(
            check_miner_signature(&block, v),
            Err(TxError::WrongOutputType { index: 0, tag: 2 })
        );
    }

    /// §4 runs before §5.1: an unsigned block whose coinbase height is also
    /// wrong fails on the signature, as it does in the C++.
    #[test]
    fn prevalidation_runs_the_signature_block_first() {
        let v = HF_VERSION_BLOCK_HEADER_MINER_SIG;
        let (mut block, ..) = signed_block(v);
        block.header.signature = Default::default();
        assert_eq!(
            prevalidate_miner_tx(&block, v, 999, 0),
            Err(TxError::MinerSignature),
            "not CoinbaseHeightMismatch"
        );
    }

    // ---- §5.1.1 coinbase unlock time ----

    /// `specs/06` §9.9: the three hex characters are read from the *printed*
    /// hex, which is storage order — a 12-bit big-endian value from bytes 0
    /// and 1. Byte-swapping is the failure the spec warns about.
    #[test]
    fn the_dynamic_unlock_window_reads_the_first_three_hex_characters() {
        let mut id = [0u8; 32];
        id[0] = 0xab;
        id[1] = 0xcd;
        // pod_to_hex gives "abcd..." and substr(0, 3) is "abc" == 2748.
        assert_eq!(dynamic_unlock_window(&id), 2748 * 2 + 288);

        // The low nibble of byte 1 is not read.
        let mut id2 = id;
        id2[1] = 0xc0;
        assert_eq!(dynamic_unlock_window(&id2), dynamic_unlock_window(&id));
        // The high nibble of byte 1 is.
        let mut id3 = id;
        id3[1] = 0xdd;
        assert_ne!(dynamic_unlock_window(&id3), dynamic_unlock_window(&id));

        // A byte-swapped reading would give "cdab" -> "cda"; assert we differ.
        let swapped = (u64::from(id[1]) << 4) | u64::from(id[0] >> 4);
        assert_ne!(dynamic_unlock_window(&id), swapped * 2 + 288);

        // Nothing past byte 1 matters.
        let mut id4 = id;
        id4[2..].fill(0xff);
        assert_eq!(dynamic_unlock_window(&id4), dynamic_unlock_window(&id));
    }

    /// The window's range, which the spec states as 288..=8478.
    #[test]
    fn the_dynamic_unlock_window_spans_one_to_twentynine_days() {
        let zero = [0u8; 32];
        assert_eq!(dynamic_unlock_window(&zero), 288, "1 day at 300 s");

        let mut max = [0u8; 32];
        max[0] = 0xff;
        max[1] = 0xf0;
        assert_eq!(dynamic_unlock_window(&max), 0xfff * 2 + 288);
        assert_eq!(dynamic_unlock_window(&max), 8478);
        assert_eq!(8478 * 300 / 86_400, 29, "~29 days");
    }

    #[test]
    fn the_three_unlock_regimes() {
        let id = [0x10u8; 32];
        assert_eq!(coinbase_unlock_time(15, 1_000, None), 1_060);
        assert_eq!(coinbase_unlock_time(7, 1_000, None), 1_060);
        // HF 16/17 is dynamic.
        assert_eq!(
            coinbase_unlock_time(16, 1_000, Some(&id)),
            1_000 + dynamic_unlock_window(&id)
        );
        assert_eq!(
            coinbase_unlock_time(17, 1_000, Some(&id)),
            1_000 + dynamic_unlock_window(&id)
        );
        // HF 18 fixes it.
        assert_eq!(coinbase_unlock_time(18, 1_000, None), 1_288);
        assert_eq!(coinbase_unlock_time(20, 1_000, None), 1_288);
    }

    #[test]
    fn the_lookback_is_network_specific() {
        assert_eq!(dynamic_unlock_lookback(wow_types::Network::Mainnet), 1337);
        assert_eq!(dynamic_unlock_lookback(wow_types::Network::Testnet), 5);
        assert_eq!(dynamic_unlock_lookback(wow_types::Network::Stagenet), 5);
    }

    // ---- §5.1 coinbase ----

    #[test]
    fn a_well_formed_coinbase_passes() {
        let mut t = tx(2, vec![TxIn::Gen { height: 500 }], vec![out_tagged(1)]);
        t.prefix.unlock_time = 500 + 288;
        assert_eq!(check_coinbase(&t, 20, 500, 788), Ok(()));
    }

    #[test]
    fn a_coinbase_must_have_exactly_one_gen_input() {
        let t = tx(2, vec![], vec![out_tagged(1)]);
        assert_eq!(
            check_coinbase(&t, 20, 5, 293),
            Err(TxError::BadCoinbaseInput)
        );

        let t = tx(
            2,
            vec![TxIn::Gen { height: 5 }, TxIn::Gen { height: 5 }],
            vec![out_tagged(1)],
        );
        assert_eq!(
            check_coinbase(&t, 20, 5, 293),
            Err(TxError::BadCoinbaseInput)
        );

        let t = tx(2, vec![to_key(0, 22, 1)], vec![out_tagged(1)]);
        assert_eq!(
            check_coinbase(&t, 20, 5, 293),
            Err(TxError::BadCoinbaseInput)
        );
    }

    /// From HF 15 the coinbase must be v2; below it, v1 is fine.
    #[test]
    fn the_coinbase_version_gate() {
        let mut t = tx(1, vec![TxIn::Gen { height: 5 }], vec![out_to_key(1)]);
        t.prefix.unlock_time = 65;
        assert_eq!(check_coinbase(&t, 14, 5, 65), Ok(()), "v1 fine below HF 15");
        assert_eq!(
            check_coinbase(&t, 15, 5, 65),
            Err(TxError::CoinbaseVersionTooLow { version: 1 })
        );
    }

    #[test]
    fn the_coinbase_height_must_match() {
        let mut t = tx(2, vec![TxIn::Gen { height: 4 }], vec![out_tagged(1)]);
        t.prefix.unlock_time = 293;
        assert_eq!(
            check_coinbase(&t, 20, 5, 293),
            Err(TxError::CoinbaseHeightMismatch {
                found: 4,
                expected: 5
            })
        );
    }

    #[test]
    fn the_coinbase_unlock_time_must_match() {
        let mut t = tx(2, vec![TxIn::Gen { height: 5 }], vec![out_tagged(1)]);
        t.prefix.unlock_time = 292;
        assert_eq!(
            check_coinbase(&t, 20, 5, 293),
            Err(TxError::CoinbaseUnlockTime {
                found: 292,
                expected: 293
            })
        );
    }

    #[test]
    fn coinbase_outputs_must_not_overflow() {
        let mut t = tx(2, vec![TxIn::Gen { height: 5 }], Vec::new());
        t.prefix.unlock_time = 293;
        t.prefix.vout = vec![
            TxOut {
                amount: u64::MAX,
                target: TxOutTarget::ToTaggedKey {
                    key: key(1),
                    view_tag: ViewTag(1),
                },
            },
            TxOut {
                amount: 1,
                target: TxOutTarget::ToTaggedKey {
                    key: key(2),
                    view_tag: ViewTag(2),
                },
            },
        ];
        assert_eq!(
            check_coinbase(&t, 20, 5, 293),
            Err(TxError::OutputsOverflow)
        );
    }

    // ---- §5.5 output types ----

    /// `specs/15` §3.2 asks for this specifically: `txout_to_key` must be
    /// accepted at **exactly** HF 20. Rejecting it there rejects live blocks.
    #[test]
    fn txout_to_key_is_accepted_at_exactly_hf_20() {
        let plain = vec![out_to_key(1), out_to_key(2)];
        let tagged = vec![out_tagged(1), out_tagged(2)];

        for hf in [7u8, 15, 18, 19] {
            assert_eq!(check_output_types(&plain, hf), Ok(()), "hf {hf}");
            assert!(check_output_types(&tagged, hf).is_err(), "hf {hf}");
        }

        // HF 20: the grace period. Both are legal.
        assert_eq!(check_output_types(&plain, 20), Ok(()));
        assert_eq!(check_output_types(&tagged, 20), Ok(()));

        // HF 21: tagged only.
        assert!(check_output_types(&plain, 21).is_err());
        assert_eq!(check_output_types(&tagged, 21), Ok(()));
    }

    /// The clause `specs/06` §5.5 omits (`docs/spec-deltas.md` §14): at HF 20
    /// the two types may not be mixed inside one transaction.
    #[test]
    fn hf20_forbids_mixing_the_two_output_types() {
        let mixed = vec![out_to_key(1), out_tagged(2)];
        assert_eq!(
            check_output_types(&mixed, 20),
            Err(TxError::MixedOutputTypes {
                index: 1,
                tag: 3,
                first: 2
            })
        );
        // The other order fails too, and at index 1 again.
        let mixed = vec![out_tagged(1), out_to_key(2)];
        assert_eq!(
            check_output_types(&mixed, 20),
            Err(TxError::MixedOutputTypes {
                index: 1,
                tag: 2,
                first: 3
            })
        );
        // Uniform of either type is fine.
        assert_eq!(check_output_types(&[out_to_key(1)], 20), Ok(()));
        assert_eq!(check_output_types(&[out_tagged(1)], 20), Ok(()));
        // An empty output list vacuously passes, as the C's loop does.
        assert_eq!(check_output_types(&[], 20), Ok(()));
    }

    #[test]
    fn a_script_output_is_never_a_valid_type() {
        let scripted = vec![TxOut {
            amount: 0,
            target: TxOutTarget::ToScriptHash { hash: [0u8; 32] },
        }];
        for hf in [7u8, 19, 20, 21] {
            assert!(check_output_types(&scripted, hf).is_err(), "hf {hf}");
        }
    }

    // ---- §5.6 minimum outputs ----

    #[test]
    fn from_hf15_a_v2_transaction_needs_two_outputs() {
        let one = tx(2, vec![to_key(0, 22, 1)], vec![out_to_key(1)]);
        assert_eq!(check_min_outputs(&one, 14), Ok(()));
        assert_eq!(
            check_min_outputs(&one, 15),
            Err(TxError::TooFewOutputs { found: 1 })
        );

        let two = tx(
            2,
            vec![to_key(0, 22, 1)],
            vec![out_to_key(1), out_to_key(2)],
        );
        assert_eq!(check_min_outputs(&two, 20), Ok(()));

        // v1 is exempt.
        let v1 = tx(1, vec![to_key(1, 8, 1)], vec![out_to_key(1)]);
        assert_eq!(check_min_outputs(&v1, 20), Ok(()));
    }

    // ---- §5.7 sorted inputs ----

    /// Strictly *decreasing* by `memcmp` — the C rejects `>= 0`, so equal
    /// images fail here too.
    #[test]
    fn key_images_must_strictly_decrease() {
        let ok = tx(
            2,
            vec![to_key(0, 22, 3), to_key(0, 22, 2), to_key(0, 22, 1)],
            vec![],
        );
        assert_eq!(check_inputs_sorted(&ok), Ok(()));

        let ascending = tx(2, vec![to_key(0, 22, 1), to_key(0, 22, 2)], vec![]);
        assert_eq!(
            check_inputs_sorted(&ascending),
            Err(TxError::UnsortedInputs { index: 1 })
        );

        let equal = tx(2, vec![to_key(0, 22, 5), to_key(0, 22, 5)], vec![]);
        assert_eq!(
            check_inputs_sorted(&equal),
            Err(TxError::UnsortedInputs { index: 1 }),
            "equal is not strictly decreasing"
        );

        // One input is trivially sorted.
        let single = tx(2, vec![to_key(0, 22, 9)], vec![]);
        assert_eq!(check_inputs_sorted(&single), Ok(()));
    }

    /// The comparison is bytewise `memcmp`, not numeric on any word — the two
    /// disagree as soon as a byte past the first differs.
    #[test]
    fn the_sort_is_bytewise() {
        let mut a = [0u8; 32];
        a[0] = 0x01;
        a[31] = 0xff;
        let mut b = [0u8; 32];
        b[0] = 0x02;
        // memcmp: b > a because byte 0 decides. So [b, a] is decreasing.
        let t = tx(
            2,
            vec![
                TxIn::ToKey {
                    amount: 0,
                    key_offsets: vec![1; 22],
                    k_image: KeyImage(b),
                },
                TxIn::ToKey {
                    amount: 0,
                    key_offsets: vec![1; 22],
                    k_image: KeyImage(a),
                },
            ],
            vec![],
        );
        assert_eq!(check_inputs_sorted(&t), Ok(()));
    }

    // ---- §5.8 minimum age ----

    #[test]
    fn the_minimum_output_age_is_four_blocks() {
        // Below HF 15 there is no rule at all.
        assert_eq!(check_min_output_age(14, 1_000, 1_000), Ok(()));

        // From HF 15: max_used + 4 <= chain_height.
        assert_eq!(check_min_output_age(15, 996, 1_000), Ok(()));
        assert_eq!(
            check_min_output_age(15, 997, 1_000),
            Err(TxError::OutputTooRecent {
                max_used_block_height: 997,
                chain_height: 1_000
            })
        );
        assert_eq!(CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, 4);
    }

    // ---- §5.4 version bounds ----

    #[test]
    fn transaction_version_bounds() {
        // hf <= 3: v1 only.
        assert_eq!(check_tx_version(1, 3, 0), Ok(()));
        assert_eq!(
            check_tx_version(2, 3, 0),
            Err(TxError::TxVersionTooHigh { version: 2, max: 1 })
        );

        // hf 4, 5: v1 or v2, no minimum.
        assert_eq!(check_tx_version(1, 5, 0), Ok(()));
        assert_eq!(check_tx_version(2, 5, 0), Ok(()));

        // hf >= 6: v2 required, unless something unmixable is being spent.
        assert_eq!(
            check_tx_version(1, 6, 0),
            Err(TxError::TxVersionTooLow { version: 1, min: 2 })
        );
        assert_eq!(
            check_tx_version(1, 20, 1),
            Ok(()),
            "an unmixable input still permits v1"
        );
        assert_eq!(check_tx_version(2, 20, 0), Ok(()));
        assert_eq!(
            check_tx_version(3, 20, 0),
            Err(TxError::TxVersionTooHigh { version: 3, max: 2 })
        );
    }

    // ---- §5.3 ring size ----

    fn summary(min: usize, max: usize, mixable: usize, unmixable: usize) -> MixinSummary {
        MixinSummary {
            min_actual_mixin: min,
            max_actual_mixin: max,
            n_mixable: mixable,
            n_unmixable: unmixable,
        }
    }

    /// Mainnet today: ring size exactly 22, i.e. mixin exactly 21.
    #[test]
    fn hf20_requires_ring_size_22_exactly() {
        assert_eq!(check_ring_size(&summary(21, 21, 1, 0), 20), Ok(()));
        // 22 is above the cap.
        assert_eq!(
            check_ring_size(&summary(22, 22, 1, 0), 20),
            Err(TxError::InvalidRingSize {
                mixin: 22,
                min_mixin: 21
            })
        );
        // 20 is below, with nothing unmixable to justify it.
        assert_eq!(
            check_ring_size(&summary(20, 20, 1, 0), 20),
            Err(TxError::RingTooSmall {
                mixin: 20,
                min_mixin: 21
            })
        );
    }

    /// From HF 15 every input must have the same ring size.
    #[test]
    fn varying_ring_sizes_are_rejected_from_hf15() {
        let varying = summary(21, 22, 2, 0);
        assert_eq!(
            check_ring_size(&varying, 15),
            Err(TxError::VaryingRingSize { min: 21, max: 22 })
        );
        // Below HF 15 the constant-size rule does not exist, so this falls
        // through to the bound check -- which 21 passes.
        assert_eq!(check_ring_size(&varying, 14), Ok(()));
    }

    /// The HF 9 grace period: a mixin of 7 *or* 21, nothing else.
    #[test]
    fn hf9_accepts_both_ring_sizes() {
        assert_eq!(check_ring_size(&summary(21, 21, 1, 0), 9), Ok(()));
        assert_eq!(check_ring_size(&summary(7, 7, 1, 0), 9), Ok(()));
        for m in [6usize, 8, 10, 20, 22] {
            assert!(
                check_ring_size(&summary(m, m, 1, 0), 9).is_err(),
                "mixin {m} must be rejected at HF 9"
            );
        }
    }

    /// HF 7 and 8 demand exactly 7, in both directions.
    #[test]
    fn hf7_and_hf8_require_mixin_seven_exactly() {
        for hf in [7u8, 8] {
            assert_eq!(check_ring_size(&summary(7, 7, 1, 0), hf), Ok(()));
            assert_eq!(
                check_ring_size(&summary(8, 8, 1, 0), hf),
                Err(TxError::InvalidRingSize {
                    mixin: 8,
                    min_mixin: 7
                }),
                "hf {hf}"
            );
            // Below 7 hits the unmixable branch instead.
            assert_eq!(
                check_ring_size(&summary(6, 6, 1, 0), hf),
                Err(TxError::RingTooSmall {
                    mixin: 6,
                    min_mixin: 7
                })
            );
        }
    }

    /// A small ring is allowed only to spend unmixable dust, and then only
    /// alongside at most one mixable input.
    #[test]
    fn a_small_ring_needs_unmixable_inputs() {
        // Unmixable present, one mixable: allowed.
        assert_eq!(check_ring_size(&summary(2, 2, 1, 1), 20), Ok(()));
        assert_eq!(check_ring_size(&summary(0, 0, 0, 1), 20), Ok(()));
        // Two mixable alongside: rejected.
        assert_eq!(
            check_ring_size(&summary(2, 2, 2, 1), 20),
            Err(TxError::TooManyMixableInputs { mixable: 2 })
        );
        // No unmixable at all: rejected.
        assert_eq!(
            check_ring_size(&summary(2, 2, 1, 0), 20),
            Err(TxError::RingTooSmall {
                mixin: 2,
                min_mixin: 21
            })
        );
    }

    /// The third clause of the branch table is vacuous, and this records that
    /// it stays so for every version — if a future table change made it fire,
    /// this test says so.
    #[test]
    #[allow(clippy::impossible_comparisons, reason = "that is what is asserted")]
    fn the_vacuous_clause_never_fires() {
        for hf in 0u8..=30 {
            let fires = hf < HF_VERSION_MIN_MIXIN_21 && hf >= HF_VERSION_MIN_MIXIN_7 + 2;
            assert!(!fires, "the clause fired at hf {hf}");
        }
        assert_eq!(HF_VERSION_MIN_MIXIN_7 + 2, HF_VERSION_MIN_MIXIN_21);
    }

    /// A transaction with no `txin_to_key` inputs leaves `min_actual_mixin` at
    /// `SIZE_MAX`, which the C then compares against `max = 0`. From HF 15 that
    /// is a "varying ring size" rejection, not a pass.
    #[test]
    fn no_key_inputs_leaves_the_sentinel() {
        let t = tx(2, vec![TxIn::Gen { height: 1 }], vec![]);
        let s = summarise_mixin(&t, 20, |_| 1_000);
        assert_eq!(s.min_actual_mixin, usize::MAX);
        assert_eq!(s.max_actual_mixin, 0);
        assert_eq!(
            check_ring_size(&s, 20),
            Err(TxError::VaryingRingSize {
                min: usize::MAX,
                max: 0
            })
        );
    }

    /// Amount 0 is mixable without consulting the database at all — the C
    /// comments that this was needed right after the RingCT fork.
    #[test]
    fn ringct_inputs_are_always_mixable() {
        let t = tx(2, vec![to_key(0, 22, 1)], vec![]);
        let s = summarise_mixin(&t, 20, |_| panic!("must not be consulted for amount 0"));
        assert_eq!(s.n_mixable, 1);
        assert_eq!(s.n_unmixable, 0);
        assert_eq!(s.min_actual_mixin, 21);
        assert_eq!(s.max_actual_mixin, 21);
    }

    /// A non-zero amount is unmixable iff `get_num_outputs(amount) <= min_mixin`
    /// — note `<=`, so exactly `min_mixin` available outputs still counts as
    /// unmixable.
    #[test]
    fn the_unmixable_threshold_is_inclusive() {
        let t = tx(2, vec![to_key(100, 8, 1)], vec![]);

        let s = summarise_mixin(&t, 20, |_| 21);
        assert_eq!(s.n_unmixable, 1, "exactly min_mixin is still unmixable");
        let s = summarise_mixin(&t, 20, |_| 22);
        assert_eq!(s.n_mixable, 1);
        assert_eq!(s.n_unmixable, 0);

        // Below HF 9 the threshold is 7, not 21.
        let s = summarise_mixin(&t, 8, |_| 8);
        assert_eq!(s.n_mixable, 1);
        let s = summarise_mixin(&t, 8, |_| 7);
        assert_eq!(s.n_unmixable, 1);
    }

    #[test]
    fn mixin_is_ring_size_minus_one() {
        let t = tx(
            2,
            vec![to_key(0, 22, 3), to_key(0, 8, 2), to_key(0, 11, 1)],
            vec![],
        );
        let s = summarise_mixin(&t, 20, |_| 1_000);
        assert_eq!(s.min_actual_mixin, 7, "ring 8");
        assert_eq!(s.max_actual_mixin, 21, "ring 22");
        assert_eq!(s.n_mixable, 3);
    }

    // ---- §5.10 RingCT gating ----

    /// Each gate permits **two** adjacent types for its whole range, which is
    /// why forks 14, 17 and 19 exist to close each window.
    #[test]
    fn rct_gates_permit_two_types_at_the_boundary() {
        // HF 13 permits Bulletproof (5) and Bulletproof2 (6).
        assert_eq!(
            check_rct_type_allowed(RctType::Bulletproof, 2, false, 13),
            Ok(())
        );
        assert_eq!(
            check_rct_type_allowed(RctType::Bulletproof2, 2, false, 13),
            Ok(())
        );
        assert!(check_rct_type_allowed(RctType::Bulletproof2, 2, false, 12).is_err());
        assert!(check_rct_type_allowed(RctType::Bulletproof, 2, false, 14).is_err());

        // HF 16 permits Bulletproof2 (6) and Clsag (7).
        assert_eq!(
            check_rct_type_allowed(RctType::Bulletproof2, 2, false, 16),
            Ok(())
        );
        assert_eq!(check_rct_type_allowed(RctType::Clsag, 2, false, 16), Ok(()));
        assert!(check_rct_type_allowed(RctType::Clsag, 2, false, 15).is_err());
        assert!(check_rct_type_allowed(RctType::Bulletproof2, 2, false, 17).is_err());

        // HF 18 permits Clsag (7) and BulletproofPlus (8).
        assert_eq!(check_rct_type_allowed(RctType::Clsag, 2, false, 18), Ok(()));
        assert_eq!(
            check_rct_type_allowed(RctType::BulletproofPlus, 2, false, 18),
            Ok(())
        );
        assert!(check_rct_type_allowed(RctType::BulletproofPlus, 2, false, 17).is_err());

        // HF 21 permits BulletproofPlus (8) and BulletproofPlusFullCommit (9).
        assert_eq!(
            check_rct_type_allowed(RctType::BulletproofPlus, 2, false, 21),
            Ok(())
        );
        assert_eq!(
            check_rct_type_allowed(RctType::BulletproofPlusFullCommit, 2, false, 21),
            Ok(())
        );
        assert!(check_rct_type_allowed(RctType::BulletproofPlusFullCommit, 2, false, 20).is_err());
        assert!(check_rct_type_allowed(RctType::BulletproofPlus, 2, false, 22).is_err());
    }

    /// Mainnet is at HF 20, where `BulletproofPlus` is the only permitted type.
    #[test]
    fn hf20_permits_only_bulletproof_plus() {
        let all = [
            RctType::Full,
            RctType::Simple,
            RctType::FullBulletproof,
            RctType::SimpleBulletproof,
            RctType::Bulletproof,
            RctType::Bulletproof2,
            RctType::Clsag,
            RctType::BulletproofPlus,
            RctType::BulletproofPlusFullCommit,
        ];
        for t in all {
            let allowed = check_rct_type_allowed(t, 2, false, 20).is_ok();
            assert_eq!(
                allowed,
                t == RctType::BulletproofPlus,
                "{t:?} at HF 20 should be {}",
                if t == RctType::BulletproofPlus {
                    "allowed"
                } else {
                    "forbidden"
                }
            );
        }
    }

    /// Wownero's `FullBulletproof` (3) and `SimpleBulletproof` (4) exist only
    /// to shift the numbering (`specs/05`), and no such transaction was ever
    /// made — but they are *structurally* legal below HF 12, because the gate
    /// that forbids them is `hf > 11`. `specs/06` §5.10's table omits that gate
    /// entirely (`docs/spec-deltas.md` §15).
    #[test]
    fn the_two_inserted_types_are_forbidden_only_from_hf12() {
        for ty in [RctType::FullBulletproof, RctType::SimpleBulletproof] {
            for hf in 7u8..=11 {
                assert_eq!(
                    check_rct_type_allowed(ty, 2, false, hf),
                    Ok(()),
                    "{ty:?} at hf {hf}"
                );
            }
            for hf in 12u8..=22 {
                assert!(
                    check_rct_type_allowed(ty, 2, false, hf).is_err(),
                    "{ty:?} at hf {hf}"
                );
            }
            // A v1 transaction skips gates 1-8 entirely.
            assert_eq!(check_rct_type_allowed(ty, 1, false, 20), Ok(()));
        }
    }

    /// Gate 6 rejects on *proofs present* as well as on the type: a
    /// transaction claiming CLSAG while carrying BP+ proofs is caught below
    /// HF 18. The table form of §5.10 loses this.
    #[test]
    fn bulletproof_plus_proofs_are_gated_independently_of_the_type() {
        assert_eq!(check_rct_type_allowed(RctType::Clsag, 2, false, 17), Ok(()));
        assert_eq!(
            check_rct_type_allowed(RctType::Clsag, 2, true, 17),
            Err(TxError::ForbiddenRctType {
                rct_type: RctType::Clsag
            }),
            "BP+ proofs are not allowed before HF 18 whatever the type says"
        );
        // From HF 18 the proofs are fine.
        assert_eq!(check_rct_type_allowed(RctType::Clsag, 2, true, 18), Ok(()));
    }

    /// Gate 9 has no `tx.version >= 2` guard in the C. It is inert for v1 only
    /// because such a transaction carries `RCTTypeNull`.
    #[test]
    fn the_last_gate_applies_to_v1_too() {
        assert_eq!(
            check_rct_type_allowed(RctType::BulletproofPlus, 1, false, 22),
            Err(TxError::ForbiddenRctType {
                rct_type: RctType::BulletproofPlus
            })
        );
        // Which is what a real v1 transaction carries, and it passes.
        assert_eq!(check_rct_type_allowed(RctType::Null, 1, false, 22), Ok(()));
    }

    // ---- §5.2 semantics ----

    #[test]
    fn semantics_reject_an_input_free_transaction() {
        let t = tx(2, vec![], vec![out_to_key(1), out_to_key(2)]);
        assert_eq!(check_tx_semantic(&t), Err(TxError::NoInputs));
    }

    #[test]
    fn semantics_reject_a_repeated_key_image() {
        let t = tx(
            2,
            vec![to_key(0, 22, 7), to_key(0, 22, 7)],
            vec![out_to_key(1), out_to_key(2)],
        );
        assert_eq!(
            check_tx_semantic(&t),
            Err(TxError::DuplicateKeyImage { index: 1 })
        );
    }

    #[test]
    fn semantics_reject_a_non_key_input() {
        let t = tx(2, vec![TxIn::Gen { height: 3 }], vec![out_to_key(1)]);
        assert_eq!(
            check_tx_semantic(&t),
            Err(TxError::UnsupportedInputType {
                index: 0,
                tag: 0xff
            })
        );
    }

    /// A v2 output amount must be zero; the value lives in the commitment.
    #[test]
    fn v2_outputs_must_have_zero_amounts() {
        let mut t = tx(
            2,
            vec![to_key(0, 22, 1)],
            vec![out_to_key(1), out_to_key(2)],
        );
        t.prefix.vout[1].amount = 1;
        assert_eq!(
            check_tx_semantic(&t),
            Err(TxError::NonZeroOutputAmountInV2 { index: 1 })
        );

        // v1 may carry amounts -- but they still have to be funded, so the
        // input needs a matching amount.
        t.prefix.version = 1;
        t.prefix.vin = vec![to_key(5, 8, 1)];
        t.signatures = vec![Vec::new()];
        assert_eq!(check_tx_semantic(&t), Ok(Some(4)), "5 in, 1 out, fee 4");
    }

    /// v1 carries its fee as the input/output difference and needs one
    /// signature row per input.
    #[test]
    fn v1_fee_is_the_difference() {
        let mut t = tx(
            1,
            vec![to_key(1_000, 8, 2), to_key(500, 8, 1)],
            vec![TxOut {
                amount: 1_200,
                target: TxOutTarget::ToKey { key: key(9) },
            }],
        );
        t.signatures = vec![Vec::new(), Vec::new()];
        assert_eq!(check_tx_semantic(&t), Ok(Some(300)));

        // Spending more than is available.
        t.prefix.vout[0].amount = 1_600;
        assert_eq!(check_tx_semantic(&t), Err(TxError::OutputsExceedInputs));

        // A missing signature row.
        t.prefix.vout[0].amount = 1_200;
        t.signatures.pop();
        assert_eq!(
            check_tx_semantic(&t),
            Err(TxError::WrongSignatureCount {
                expected: 2,
                found: 1
            })
        );
    }

    /// v2 reports no fee here: it lives in `rct_signatures.txn_fee`.
    #[test]
    fn v2_reports_no_semantic_fee() {
        let t = tx(
            2,
            vec![to_key(0, 22, 1)],
            vec![out_to_key(1), out_to_key(2)],
        );
        assert_eq!(check_tx_semantic(&t), Ok(None));
    }

    #[test]
    fn input_sums_must_not_overflow() {
        let t = tx(
            1,
            vec![to_key(u64::MAX, 8, 2), to_key(1, 8, 1)],
            vec![out_to_key(1)],
        );
        assert_eq!(check_tx_semantic(&t), Err(TxError::InputsOverflow));
    }
}
