//! Sending: a plan, rings, a signed transaction, and a relay (`specs/12` §4).
//!
//! In two steps, so a program can show what a transaction costs before
//! anything leaves the wallet. [`Session::prepare_send`] plans the spend, picks
//! the rings, and builds and signs the transaction at the fee its own weight
//! needs. [`Session::commit_send`] relays it and records it. wallet-cli asks in
//! between, wallet-rpc does not, and a GUI shows a dialog.

use curve25519_dalek::scalar::Scalar;
use wow_crypto::types::{AccountPublicAddress, Hash256, KeyImage};
use wow_daemon_client::{DaemonError, SendResult};
use wow_types::address::{Address, AddressKind};
use wow_types::Network;

use crate::decoys::{self, DecoyError, GammaPicker, RandomSource};
use crate::files::{now, Session};
use crate::priority::{self, PrioritySettings};
use crate::spend::{self, SpendError, SpendOptions, SpendPlan};
use crate::transfer::{self, Destination, Outputs, SettleError, SpendableOutput, TransferError};

/// What to send.
#[derive(Clone, Debug)]
pub struct SendRequest<'a> {
    /// Where to, as typed.
    pub address: &'a str,
    /// How much, in atomic units. `None` sends everything unlocked, less the
    /// fee (`sweep_all`).
    pub amount: Option<u64>,
    /// 0 to 4, where 0 lets the wallet choose ([`crate::priority`]).
    pub priority: u32,
    pub ring_size: usize,
    /// A payment id given apart from the address. An integrated address
    /// carries its own, and giving both is refused.
    pub payment_id: Option<[u8; 8]>,
    /// Sweep exactly this one output and nothing else (`sweep_single`).
    ///
    /// Only read when `amount` is `None`; an amount says what to send, and
    /// which outputs pay for it is the wallet's business.
    pub sweep_output: Option<wow_crypto::types::KeyImage>,
}

/// A transaction built and signed, and not yet relayed.
#[derive(Clone, Debug)]
pub struct PreparedSend {
    /// The address it pays, as it was given.
    pub address: String,
    /// The plan as built: its inputs, the amount sent, the change, and the fee
    /// the built transaction's weight needs, with that weight.
    pub plan: SpendPlan,
    /// The fee tier it pays, after [`priority::adjust_priority`].
    pub priority: u32,
    pub payment_id: Option<[u8; 8]>,
    pub txid: Hash256,
    /// The transaction, serialized for relay.
    pub blob: Vec<u8>,
    /// The key images it spends, in input order.
    pub key_images: Vec<KeyImage>,
    /// Transactions in the daemon's pool found spending this wallet's outputs,
    /// not sent from here, and now counted as spent.
    pub noted_in_pool: Vec<Hash256>,
    /// Why the pool could not be read, when it could not. Not a reason to
    /// refuse the send.
    pub pool_unread: Option<String>,
}

/// What the daemon said to a prepared transaction.
#[derive(Clone, Debug)]
pub struct Relayed {
    /// Its answer. A refusal is an answer rather than an error, and its flags
    /// say why.
    pub result: SendResult,
    /// After a refusal as a double spend: the transactions in the pool found
    /// spending this wallet's outputs, now counted as spent so the next attempt
    /// picks others.
    pub noted_in_pool: Vec<Hash256>,
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("a view-only wallet cannot spend: it has no spend key")]
    ViewOnly,
    #[error("no daemon is set")]
    NoDaemon,
    #[error("that address is not valid for {network}: {reason}")]
    Address {
        network: &'static str,
        reason: String,
    },
    #[error("that is an integrated address; it already carries a payment id")]
    TwoPaymentIds,
    #[error("a payment id cannot go to a subaddress: its payee could not read it")]
    PaymentIdToSubaddress,
    #[error("cannot get a fee estimate: {0}")]
    FeeEstimate(DaemonError),
    #[error("cannot get the output distribution: {0}")]
    Distribution(DecoyError),
    #[error(transparent)]
    Plan(#[from] SpendError),
    #[error("cannot build a ring: {0}")]
    Ring(DecoyError),
    #[error("the daemon's ring members do not match ours: {0}")]
    RingMismatch(DecoyError),
    #[error("an output this wallet holds is damaged: {0}")]
    Damaged(&'static str),
    #[error("{0}")]
    Entropy(String),
    #[error("cannot build the transaction: {0}")]
    Build(TransferError),
    #[error("cannot reach the daemon to relay: {0}")]
    Relay(DaemonError),
}

impl Session {
    /// Plan, ring, build and sign a transaction, and relay nothing.
    ///
    /// What can be refused without a daemon is refused first. The transaction
    /// is built before anyone is asked to confirm it, as the C++ builds it: the
    /// fee is its built weight's, and weighing it takes building it.
    pub fn prepare_send(&mut self, request: &SendRequest<'_>) -> Result<PreparedSend, SendError> {
        if self.is_view_only() {
            return Err(SendError::ViewOnly);
        }
        let client = self.daemon.clone().ok_or(SendError::NoDaemon)?;

        let decoded = Address::decode_for(request.address, self.network)
            .map_err(|e| bad_address(self.network, e))?;

        // An integrated address carries its own payment id, and giving a second
        // one is ambiguous rather than additive.
        let payment_id = match (decoded.payment_id, request.payment_id) {
            (Some(_), Some(_)) => return Err(SendError::TwoPaymentIds),
            (Some(p), None) => Some(p),
            (None, other) => other,
        };
        // The C++ takes an id only in an integrated address, which is never a
        // subaddress: a subaddress is what replaced payment ids.
        if payment_id.is_some() && decoded.kind == AddressKind::Subaddress {
            return Err(SendError::PaymentIdToSubaddress);
        }

        // Fees, at the tier `adjust_priority` settles on.
        let tiers = client
            .get_fee_estimate(priority::FEE_ESTIMATE_GRACE_BLOCKS)
            .map_err(SendError::FeeEstimate)?;
        let priority = priority::adjust_priority(
            &client,
            request.priority,
            PrioritySettings::from_keys_file(&self.keys_file),
            self.state.scan_height(),
            &tiers,
        );
        let fee_per_byte = priority::fee_per_byte(&tiers, priority);

        // Another copy of this wallet may have spent some of these outputs
        // since the last refresh: better found in the pool now than as a
        // refusal. A pool that cannot be read is no reason not to send.
        let (noted_in_pool, pool_unread) = match self.note_pool_spends() {
            Ok(noted) => (noted, None),
            Err(e) => (Vec::new(), Some(e)),
        };

        let subaddress = decoded.kind == AddressKind::Subaddress;
        let options = SpendOptions {
            ring_size: request.ring_size,
            fee_per_byte,
            // One payee and change: no per-output keys, even to a subaddress.
            extra_size: spend::extra_size(2, payment_id.is_some(), false),
            chain_height: self.chain_height(),
            now: now(),
            ..Default::default()
        };
        // One source for the whole transaction: which of this wallet's outputs
        // pay, and which of the chain's outputs hide them. Both are choices an
        // observer must not be able to make for us.
        let mut rng = crate::entropy::seeded_rng().map_err(SendError::Entropy)?;

        let plan = match (request.amount, &request.sweep_output) {
            (Some(amount), _) => {
                spend::plan(&self.state.transfers, &[amount], &options, &mut rng)
            }
            (None, Some(k)) => spend::plan_sweep_single(&self.state.transfers, k, &options),
            (None, None) => spend::plan_sweep(&self.state.transfers, &options),
        }?;

        // A ring for each input, of members the chain has unlocked, or no node
        // will take the transaction.
        //
        // The distribution is asked for whole, to the node's tip, as
        // `wallet2::get_rct_distribution` asks for it before every
        // transaction, and checked as `get_outs` checks it.
        let distribution = decoys::rct_distribution(&client).map_err(SendError::Distribution)?;
        let max_real_index = plan
            .inputs
            .iter()
            .map(|&i| self.state.transfers[i].global_output_index)
            .max()
            .unwrap_or(0);
        decoys::check_distribution(&distribution.offsets, max_real_index)
            .map_err(SendError::Distribution)?;
        let picker = GammaPicker::new(&distribution.offsets).map_err(SendError::Ring)?;

        // Every input's ring in one request of the reference's shape, checked
        // member by member and then as a whole (`decoys::select_rings`).
        let mut masks = Vec::with_capacity(plan.inputs.len());
        let mut reals = Vec::with_capacity(plan.inputs.len());
        for &i in &plan.inputs {
            let t = &self.state.transfers[i];
            let mask = wow_crypto::ops::decode_scalar(&t.mask)
                .ok_or(SendError::Damaged("its stored mask is not a scalar"))?;
            reals.push(decoys::RealOutput {
                global_index: t.global_output_index,
                public_key: t.public_key.0,
                commitment: wow_crypto::rct::commit(t.amount, &mask).0,
            });
            masks.push(mask);
        }
        let rings = decoys::select_rings(
            &distribution.offsets,
            &picker,
            &mut rng,
            &reals,
            request.ring_size,
            None,
            |indices| decoys::fetch_members(&client, indices),
        )
        .map_err(|e| match e {
            DecoyError::RealOutputNotReturned(_) => SendError::RingMismatch(e),
            other => SendError::Ring(other),
        })?;

        let mut inputs = Vec::with_capacity(plan.inputs.len());
        let mut key_images = Vec::with_capacity(plan.inputs.len());
        for ((&i, (ring, keys)), mask) in plan.inputs.iter().zip(&rings).zip(masks) {
            let t = &self.state.transfers[i];
            let assembled = decoys::assemble_ring(
                ring,
                keys,
                &t.public_key,
                &wow_crypto::rct::commit(t.amount, &mask),
            )
            .map_err(SendError::RingMismatch)?;

            let secret_key = crate::refresh::one_time_secret_key(&self.keys_file.account, t)
                .ok_or(SendError::ViewOnly)?;
            let key_image = t.key_image.ok_or(SendError::Damaged("no key image"))?;
            key_images.push(key_image);

            inputs.push(SpendableOutput {
                public_key: t.public_key,
                secret_key,
                mask,
                amount: t.amount,
                key_image,
                ring: assembled.members,
                global_indices: assembled.indices,
                real_index: assembled.real_index,
            });
        }

        // Outputs: the payee, and change back to the primary address, named
        // as change. The builder shuffles them.
        //
        // A transaction still needs two outputs when there is no change, as
        // after a sweep or a send of exactly what an output holds, and
        // `transfer_selected_rct` sends that zero "to a random address, to
        // avoid confusing the sender with a 0 amount output". An output of
        // nothing back to this wallet would be one more thing on chain that
        // is always the sender's. The address is a throwaway account's, and
        // the output is derived from this wallet's view key as change is, so
        // nobody holds the key to it.
        let payee = decoded.keys;
        let change_to = self.keys_file.account.keys.account_address;
        let view_secret_key = self.keys_file.account.keys.view_secret_key;
        let dummy = crate::account::AccountBase::from_spend_key(
            wow_crypto::types::SecretKey(rng.random_scalar()),
            0,
        )
        .ok_or_else(|| SendError::Entropy("cannot make an address for zero change".into()))?
        .keys
        .account_address;
        let outputs = |p: &SpendPlan| outputs_for(p, (payee, subaddress), change_to, dummy);
        let settled = transfer::construct_settled(
            &inputs,
            &plan,
            fee_per_byte,
            payment_id,
            &outputs,
            &view_secret_key,
            &mut || random_scalar(&mut rng),
        )
        .map_err(|e| match e {
            SettleError::Plan(e) => SendError::Plan(e),
            SettleError::Build(e) => SendError::Build(e),
        })?;

        Ok(PreparedSend {
            address: request.address.to_string(),
            txid: transfer::transaction_hash(&settled.built.tx),
            plan: settled.plan,
            priority,
            payment_id,
            blob: settled.blob,
            key_images,
            noted_in_pool,
            pool_unread,
        })
    }

    /// Relay a prepared transaction and, once a daemon has taken it, record
    /// it: its inputs spent, and where it went when `store-tx-info` is on.
    /// `wallet2::commit_tx`.
    ///
    /// A caller asked not to relay does not call this at all. That is what
    /// `do_not_relay` means in `wallet_rpc_server::fill_response`, which then
    /// skips `commit_tx` entirely: the transaction is built and handed back,
    /// and no node hears of it until someone relays it. Showing it to a node
    /// "without passing it on" would still show it to that node.
    ///
    /// Saving is the caller's to do, and soon: a wallet that forgot a send
    /// would offer the same inputs to the next one.
    pub fn commit_send(&mut self, prepared: &PreparedSend) -> Result<Relayed, SendError> {
        let client = self.daemon.clone().ok_or(SendError::NoDaemon)?;
        let result = client
            .send_raw_transaction(&prepared.blob, false)
            .map_err(SendError::Relay)?;

        if !result.accepted() {
            let noted_in_pool = if result.double_spend {
                // When the first spend is in the pool, its outputs are held
                // back now, so the next attempt does not pick them again.
                self.dirty = true;
                self.note_pool_spends().unwrap_or_default()
            } else {
                Vec::new()
            };
            return Ok(Relayed {
                result,
                noted_in_pool,
            });
        }

        let store = self.keys_file.store_tx_info();
        let payees = if store {
            vec![prepared.address.as_str()]
        } else {
            Vec::new()
        };
        self.state.record_sent(
            prepared.txid,
            &prepared.plan,
            &payees,
            prepared.payment_id.filter(|_| store),
            now(),
        );
        self.dirty = true;
        Ok(Relayed {
            result,
            noted_in_pool: Vec::new(),
        })
    }
}

/// The outputs of a plan paying one address: the payee, and change to
/// `change_to`, or, when there is no change, nothing to `dummy`
/// (`transfer_selected_rct`). Whichever of the two takes the change is named
/// as change, so its output is derived from the sender's view key.
fn outputs_for(
    plan: &SpendPlan,
    (payee, payee_is_subaddress): (AccountPublicAddress, bool),
    change_to: AccountPublicAddress,
    dummy: AccountPublicAddress,
) -> Outputs {
    let (change, amount) = if plan.change > 0 {
        (change_to, plan.change)
    } else {
        (dummy, 0)
    };
    Outputs {
        destinations: vec![
            Destination {
                address: payee,
                is_subaddress: payee_is_subaddress,
                amount: plan.amounts[0],
            },
            Destination {
                address: change,
                is_subaddress: false,
                amount,
            },
        ],
        change: Some(change),
    }
}

/// A uniform scalar from 256 bits of `rng`.
fn random_scalar(rng: &mut wow_crypto::random::Rng) -> Scalar {
    let mut b = [0u8; 32];
    for chunk in b.chunks_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    Scalar::from_bytes_mod_order(b)
}

fn bad_address(network: Network, e: impl std::fmt::Display) -> SendError {
    SendError::Address {
        network: network.name(),
        reason: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn wallet(seed: u8) -> Session {
        let spend = wow_crypto::types::SecretKey(wow_crypto::ops::sc_reduce32(&[seed; 32]));
        let account = crate::account::AccountBase::from_spend_key(spend, 0).expect("keys");
        Session::create_in(
            Box::new(MemoryStore::new("test")),
            Network::Mainnet,
            String::new(),
            1,
            account,
            "English",
            0,
        )
        .expect("create")
    }

    fn request(address: &str) -> SendRequest<'_> {
        SendRequest {
            address,
            amount: Some(1_000_000),
            priority: 0,
            ring_size: decoys::RING_SIZE,
            payment_id: None,
            sweep_output: None,
        }
    }

    /// What can be refused without asking a daemon anything is refused before
    /// one is asked, and says what it is.
    #[test]
    fn a_send_is_refused_before_the_daemon_is_asked() {
        let mut s = wallet(3);
        let own = s.primary_address();
        assert!(matches!(
            s.prepare_send(&request(&own)),
            Err(SendError::NoDaemon)
        ));

        // Nothing listens here, and nothing below gets far enough to call it.
        s.daemon = Some(wow_daemon_client::DaemonClient::new("127.0.0.1:1"));
        let keys = s.keys_file.account.keys.account_address;

        let testnet = Address::standard(Network::Testnet, keys).encode();
        assert!(matches!(
            s.prepare_send(&request(&testnet)),
            Err(SendError::Address { .. })
        ));

        let integrated = Address::integrated(Network::Mainnet, keys, [1; 8]).encode();
        let mut both = request(&integrated);
        both.payment_id = Some([2; 8]);
        assert!(matches!(
            s.prepare_send(&both),
            Err(SendError::TwoPaymentIds)
        ));

        let subaddress = Address::subaddress(Network::Mainnet, keys).encode();
        let mut to_subaddress = request(&subaddress);
        to_subaddress.payment_id = Some([2; 8]);
        assert!(matches!(
            s.prepare_send(&to_subaddress),
            Err(SendError::PaymentIdToSubaddress)
        ));

        s.keys_file.account.forget_spend_key();
        assert!(matches!(
            s.prepare_send(&request(&own)),
            Err(SendError::ViewOnly)
        ));
    }

    /// Change goes back to this wallet, and no change goes, as nothing, to
    /// the throwaway address, named as change either way.
    #[test]
    fn zero_change_goes_to_a_throwaway_address() {
        let payee = wallet(5).keys_file.account.keys.account_address;
        let me = wallet(6).keys_file.account.keys.account_address;
        let dummy = wallet(7).keys_file.account.keys.account_address;
        let mut plan = SpendPlan {
            inputs: vec![0],
            amounts: vec![700],
            change: 250,
            fee: 50,
            estimated_weight: 0,
            sweep: false,
            left_behind: 0,
        };

        let o = outputs_for(&plan, (payee, true), me, dummy);
        assert_eq!(o.change, Some(me));
        assert_eq!(o.destinations[0].address, payee);
        assert!(o.destinations[0].is_subaddress);
        assert_eq!(
            (o.destinations[1].address, o.destinations[1].amount),
            (me, 250)
        );

        plan.change = 0;
        let o = outputs_for(&plan, (payee, false), me, dummy);
        assert_eq!(o.change, Some(dummy));
        assert_eq!(
            (o.destinations[1].address, o.destinations[1].amount),
            (dummy, 0)
        );
        assert_eq!(o.destinations.len(), 2, "still two outputs");
    }
}
