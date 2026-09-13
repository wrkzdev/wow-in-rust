//! Block templates (`specs/09` §6.1, `specs/11` §4.1).
//!
//! `Blockchain::create_block_template`: a block extending the tip, paying its
//! coinbase to one address, holding the best-paying transactions the weight
//! limit allows. Built from values the caller read under the chain lock, so
//! nothing here can race a block landing halfway through.
//!
//! # The coinbase is built until its weight stops moving
//!
//! The reward depends on the block's weight, the weight includes the coinbase,
//! and the coinbase's size depends on how many bytes the reward's varint
//! takes. `specs/09` §6.1 step 4: build it, measure it, rebuild with the
//! measured weight, up to ten times. It settles in two -- a coinbase is nowhere
//! near the penalty zone -- but the loop is what makes that a consequence
//! rather than an assumption.

use std::collections::HashSet;

use wow_consensus::constants::COINBASE_BLOB_RESERVED_SIZE;
use wow_consensus::emission::{get_block_reward, median};
use wow_consensus::hardfork::gates::{
    HF_VERSION_DYNAMIC_UNLOCK, HF_VERSION_FIXED_UNLOCK, HF_VERSION_MIN_V2_COINBASE_TX,
    HF_VERSION_VIEW_TAGS,
};
use wow_consensus::hardfork::HardFork;
use wow_consensus::timestamp::timestamp_check_window;
use wow_consensus::tx_rules;
use wow_crypto::random::Rng;
use wow_crypto::types::{Hash256, KeyImage, PublicKey, Signature};
use wow_storage::db::BlockchainDb;
use wow_storage::lmdb::LmdbDb;
use wow_types::address::{Address, AddressKind};
use wow_types::block::{Block, BlockHeader};
use wow_types::rct::RctSignatures;
use wow_types::tx::{Transaction, TransactionPrefix, TxIn, TxOut, TxOutTarget};
use wow_types::Network;

use crate::mempool::TxPool;

/// `TX_EXTRA_NONCE_MAX_COUNT`: the most extra-nonce bytes a template carries.
pub const MAX_RESERVE_SIZE: usize = 255;
/// Coinbase rebuilds before giving up on a stable weight (`specs/09` §6.1).
const WEIGHT_ROUNDS: usize = 10;

/// What the chain says about the block that would come next.
#[derive(Clone, Copy, Debug)]
pub struct NextBlock {
    pub height: u64,
    pub prev_id: Hash256,
    pub difficulty: u128,
    /// `m_current_block_cumul_weight_median`.
    pub median_weight: u64,
    pub already_generated_coins: u64,
}

/// What the coinbase's extra nonce holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtraNonce {
    /// Zero bytes for a pool to write its own nonce into; `reserved_offset`
    /// says where.
    Reserve(usize),
    /// These bytes, as `get_block_template`'s `extra_nonce` gives them.
    Given(Vec<u8>),
}

/// A block ready for a nonce.
#[derive(Clone, Debug)]
pub struct Template {
    pub block: Block,
    pub height: u64,
    pub difficulty: u128,
    /// The coinbase amount: base reward plus fees.
    pub expected_reward: u64,
    /// Where in the block blob the reserved extra nonce starts; zero when none
    /// was reserved.
    pub reserved_offset: u64,
    pub seed_height: u64,
    pub seed_hash: Hash256,
    pub next_seed_hash: Hash256,
    /// The coinbase's transaction public key, from which the HF 18 signing key
    /// is derived (`specs/06` §4.1).
    pub tx_public: PublicKey,
    /// The coinbase output's one-time key, which the signature verifies
    /// against.
    pub output_key: PublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateError {
    /// `CORE_RPC_ERROR_CODE_MINING_TO_SUBADDRESS`.
    Subaddress,
    /// `CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE`.
    ReserveTooBig { size: usize },
    /// The address's keys are not valid points.
    BadAddress,
    /// The chain could not be read, or the block could not be made to fit.
    Chain(String),
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateError::Subaddress => f.write_str("Mining to subaddress is not supported"),
            TemplateError::ReserveTooBig { size } => {
                write!(
                    f,
                    "Too big reserved size, maximum {MAX_RESERVE_SIZE}, got {size}"
                )
            }
            TemplateError::BadAddress => f.write_str("the mining address's keys are not valid"),
            TemplateError::Chain(e) => write!(f, "cannot build a block template: {e}"),
        }
    }
}

impl std::error::Error for TemplateError {}

fn chain(e: impl std::fmt::Display) -> TemplateError {
    TemplateError::Chain(e.to_string())
}

/// `add_tx_pub_key_to_extra`, then `add_extra_nonce_to_tx_extra` when there
/// is a nonce.
///
/// Written by hand rather than through the `tx_extra` serializer because the
/// C++ writes the nonce's length as **one byte**, not a varint. The two agree
/// below 128; above it only this matches the reference's bytes, which a pool
/// computing `reserved_offset` for itself relies on.
fn coinbase_extra(tx_public: &PublicKey, nonce: &[u8]) -> Vec<u8> {
    let mut extra = Vec::with_capacity(35 + nonce.len());
    // TX_EXTRA_TAG_PUBKEY
    extra.push(0x01);
    extra.extend_from_slice(&tx_public.0);
    if !nonce.is_empty() {
        // TX_EXTRA_NONCE
        extra.push(0x02);
        extra.push(nonce.len() as u8);
        extra.extend_from_slice(nonce);
    }
    extra
}

/// `Blockchain::create_block_template` for a block extending the tip.
#[allow(
    clippy::too_many_arguments,
    reason = "the inputs the C++ reads from its members"
)]
pub fn build(
    db: &LmdbDb,
    network: Network,
    next: &NextBlock,
    pool: &TxPool,
    address: &Address,
    extra: &ExtraNonce,
    now: u64,
    rng: &mut Rng,
) -> Result<Template, TemplateError> {
    if address.kind == AddressKind::Subaddress {
        return Err(TemplateError::Subaddress);
    }
    let (nonce, reserving) = match extra {
        ExtraNonce::Reserve(n) => (vec![0u8; *n], *n > 0),
        ExtraNonce::Given(bytes) => (bytes.clone(), false),
    };
    if nonce.len() > MAX_RESERVE_SIZE {
        return Err(TemplateError::ReserveTooBig { size: nonce.len() });
    }

    let hf = HardFork::new(network);
    let height = next.height;
    let version = hf.required_version(height);

    // Step 2: now, or the median of the recent timestamps when now is earlier
    // than it, so the block passes `check_block_timestamp`.
    let window = timestamp_check_window(version) as u64;
    let timestamp = if height >= window {
        let mut recent = Vec::with_capacity(window as usize);
        for h in height - window..height {
            recent.push(db.get_block_timestamp(h).map_err(chain)?);
        }
        now.max(median(&mut recent))
    } else {
        now
    };

    let reward_at = |weight: u64| {
        get_block_reward(
            next.median_weight,
            weight,
            next.already_generated_coins,
            version,
        )
        .ok()
    };

    // Step 3, `fill_block_template`: best fee per weight first, under twice
    // the median less the coinbase's reserve, and only while each transaction
    // pays for the penalty it causes -- the coinbase must not shrink.
    let max_weight = (2 * next.median_weight).saturating_sub(COINBASE_BLOB_RESERVED_SIZE as u64);
    let mut best = reward_at(0).unwrap_or(0);
    let mut tx_hashes = Vec::new();
    let mut spent: HashSet<KeyImage> = HashSet::new();
    let (mut txs_weight, mut fees) = (0u64, 0u64);
    for (id, entry) in pool.by_fee() {
        // A transaction kept back from relay is not announced by a block
        // either.
        if entry.do_not_relay || txs_weight + entry.weight > max_weight {
            continue;
        }
        let Some(reward) = reward_at(txs_weight + entry.weight) else {
            continue;
        };
        let coinbase = reward.saturating_add(fees).saturating_add(entry.fee);
        if coinbase < best {
            continue;
        }
        let Ok(tx) = Transaction::from_blob(&entry.blob) else {
            continue;
        };
        let images: Vec<KeyImage> = tx
            .prefix
            .vin
            .iter()
            .filter_map(|i| match i {
                TxIn::ToKey { k_image, .. } => Some(*k_image),
                _ => None,
            })
            .collect();
        let unusable = images
            .iter()
            .any(|ki| spent.contains(ki) || db.has_key_image(ki).unwrap_or(true));
        if unusable {
            continue;
        }
        spent.extend(images);
        tx_hashes.push(id);
        txs_weight += entry.weight;
        fees = fees.saturating_add(entry.fee);
        best = coinbase;
    }

    // Step 4: the coinbase, one output to the miner.
    let (tx_public, tx_secret) = rng.generate_keys();
    let derivation = wow_crypto::generate_key_derivation(&address.keys.view_public_key, &tx_secret)
        .ok_or(TemplateError::BadAddress)?;
    let output_key = wow_crypto::derive_public_key(&derivation, 0, &address.keys.spend_public_key)
        .ok_or(TemplateError::BadAddress)?;
    let target = if version >= HF_VERSION_VIEW_TAGS {
        TxOutTarget::ToTaggedKey {
            key: output_key,
            view_tag: wow_crypto::derive_view_tag(&derivation, 0),
        }
    } else {
        TxOutTarget::ToKey { key: output_key }
    };

    let unlock_time = if (HF_VERSION_DYNAMIC_UNLOCK..HF_VERSION_FIXED_UNLOCK).contains(&version) {
        let referenced = height
            .checked_sub(tx_rules::dynamic_unlock_lookback(network))
            .ok_or_else(|| chain("the dynamic unlock window reaches below genesis"))?;
        let id = db.get_block_hash(referenced).map_err(chain)?;
        tx_rules::coinbase_unlock_time(version, height, Some(&id))
    } else {
        tx_rules::coinbase_unlock_time(version, height, None)
    };

    let extra = coinbase_extra(&tx_public, &nonce);
    let tx_version = if version >= HF_VERSION_MIN_V2_COINBASE_TX {
        2
    } else {
        1
    };

    let mut coinbase_weight = 0u64;
    let mut settled = None;
    for _ in 0..WEIGHT_ROUNDS {
        let base = reward_at(txs_weight + coinbase_weight)
            .ok_or_else(|| chain("the block is over its weight limit"))?;
        let amount = base.saturating_add(fees);
        let tx = Transaction {
            prefix: TransactionPrefix {
                version: tx_version,
                unlock_time,
                vin: vec![TxIn::Gen { height }],
                vout: vec![TxOut {
                    amount,
                    target: target.clone(),
                }],
                extra: extra.clone(),
            },
            signatures: Vec::new(),
            rct_signatures: if tx_version >= 2 {
                RctSignatures::null()
            } else {
                RctSignatures::default()
            },
            prefix_size: 0,
            unprunable_size: 0,
        };
        let mut w = wow_serialize::binary::Writer::with_capacity(256);
        tx.write(&mut w);
        let blob = w.into_vec();
        let measured = blob.len() as u64;
        if measured == coinbase_weight {
            // Re-parsed, so the recorded region sizes describe this blob.
            settled = Some((Transaction::from_blob(&blob).map_err(chain)?, amount));
            break;
        }
        coinbase_weight = measured;
    }
    let (coinbase, expected_reward) =
        settled.ok_or_else(|| chain("the coinbase weight did not settle"))?;

    let block = Block {
        header: BlockHeader {
            major_version: version,
            // The legacy vote: the highest version this node knows.
            minor_version: hf.ideal_version_top(),
            timestamp,
            prev_id: next.prev_id,
            nonce: 0,
            signature: Signature::ZERO,
            vote: 0,
        },
        miner_tx: coinbase,
        tx_hashes,
    };

    // `reserved_offset`: past the transaction public key, the nonce tag and
    // the nonce's one-byte length.
    let reserved_offset = if reserving {
        block
            .to_blob()
            .windows(32)
            .position(|w| w == &tx_public.0[..])
            .map(|p| (p + 32 + 2) as u64)
            .unwrap_or(0)
    } else {
        0
    };

    // The seed block must already be on the chain; before it is, the seed is
    // the null hash (`specs/03` §3.4).
    let (seed_height, next_seed_height) = wow_randomwow::seed::rx_seedheights(height);
    let hash_at = |h: u64| -> Result<Hash256, TemplateError> {
        if h < height {
            db.get_block_hash(h).map_err(chain)
        } else {
            Ok([0u8; 32])
        }
    };

    Ok(Template {
        height,
        difficulty: next.difficulty,
        expected_reward,
        reserved_offset,
        seed_height,
        seed_hash: hash_at(seed_height)?,
        next_seed_hash: hash_at(next_seed_height)?,
        tx_public,
        output_key,
        block,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key, then the nonce with a one-byte length, as the C++ lays them
    /// out -- which is what `reserved_offset` counts past.
    #[test]
    fn the_extra_carries_the_key_then_the_nonce_with_a_one_byte_length() {
        let key = PublicKey([7u8; 32]);
        let extra = coinbase_extra(&key, &[0u8; 8]);
        assert_eq!(extra[0], 0x01);
        assert_eq!(&extra[1..33], &key.0);
        assert_eq!(&extra[33..35], &[0x02, 8]);
        assert_eq!(&extra[35..], &[0u8; 8]);
        assert_eq!(
            coinbase_extra(&key, &[]).len(),
            33,
            "no nonce field without a nonce"
        );
        // 200 would take two bytes as a varint; the reference writes one.
        let long = coinbase_extra(&key, &[0u8; 200]);
        assert_eq!((long[34], long.len()), (200, 35 + 200));
    }

    #[test]
    fn the_errors_carry_the_reference_wording() {
        assert_eq!(
            TemplateError::Subaddress.to_string(),
            "Mining to subaddress is not supported"
        );
        assert!(TemplateError::ReserveTooBig { size: 300 }
            .to_string()
            .contains("255"));
    }
}
