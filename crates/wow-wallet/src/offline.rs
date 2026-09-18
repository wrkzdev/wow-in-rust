//! Cold signing, as operations on a wallet (`specs/12` §8).
//!
//! [`crate::cold`] has the four file formats; this has what the two halves of
//! a pair do with them. A **watch-only** wallet holds the view key, watches the
//! chain, and can plan a spend but not sign it. A **cold** wallet holds the
//! spend key and never touches a network.
//!
//! # The round trip
//!
//! ```text
//! watch-only                              cold (offline)
//! ----------                              --------------
//! export_outputs      --- outputs --->    import_outputs
//! import_key_images   <-- key images ---  export_key_images
//!
//! prepare_unsigned    --- unsigned --->   describe / sign_unsigned
//! submit_signed       <--- signed -----   (writes the signed set)
//! ```
//!
//! The first exchange is what makes a watch-only wallet useful at all: it
//! cannot compute a key image, so without it it cannot tell a spent output
//! from an unspent one, and its balance is whatever it has ever received.
//! `simplewallet` says as much in its balance line —
//! "(Some owned outputs have missing key images - export_outputs,
//! import_outputs, export_key_images, and import_key_images needed)".
//!
//! # What a watch-only wallet can plan
//!
//! Everything except the signatures. It knows its outputs, their amounts and
//! masks, the fee schedule and the output distribution, so it can pick inputs,
//! pick rings and settle a fee. It builds a transaction to weigh it, with zero
//! where the one-time secret keys go, and throws it away
//! ([`crate::send::Session::plan_send`]); what crosses to the cold half is the
//! `tx_construction_data`, which holds no secret.
//!
//! The C++ does exactly this, and it is worth saying why it is safe:
//! `generate_key_image_helper_precomp` has "for watch-only wallet, simply copy
//! the known output pubkey" and leaves the secret key null, so
//! `create_transactions_2` on a watch-only wallet runs the whole build with a
//! null spend key. The result is a correctly shaped, invalidly signed
//! transaction, and only its weight is kept.
//!
//! # The trusted-daemon gate
//!
//! `import_key_images` asks a node whether each key image is spent, which
//! hands that node the wallet's whole output set. `simplewallet` refuses it
//! outright on an untrusted daemon —
//! "this command requires a trusted daemon. Enable with --trusted-daemon" —
//! and so does this.
//!
//! # What is not here
//!
//! Multisig, and the hardware-device path (`cold_sign_tx`), which shares these
//! two file formats. A set carrying multisig signatures is refused when it is
//! parsed rather than half-signed.

use wow_crypto::random::Rng;
use wow_crypto::types::{
    AccountPublicAddress, Hash256, Hash8, KeyDerivation, KeyImage, PublicKey, SecretKey,
    SubaddressIndex,
};
use wow_daemon_client::{DaemonError, KeyImageStatus, SendResult};
use wow_types::address::Address;
use wow_types::Network;

use crate::cold::{
    self, ColdError, ExportedKeyImages, ExportedOutputs, ExportedTransferDetails, PendingTx,
    RctConfig, RingEntry, SignedKeyImage, SignedTxSet, TxConstructionData, TxDestinationEntry,
    TxSourceEntry, UnsignedTxSet,
};
use crate::files::{now, Session};
use crate::refresh::Transfer;
use crate::send::{random_scalar, SendError, SendRequest};
use crate::spend::SpendPlan;
use crate::transfer::{self, Change, Destination, SpendableOutput};

#[derive(Debug, thiserror::Error)]
pub enum OfflineError {
    #[error("wallet is watch-only and cannot export key images")]
    WatchOnly,
    #[error("this command requires a trusted daemon. Enable with --trusted-daemon")]
    UntrustedDaemon,
    #[error("no daemon is set")]
    NoDaemon,
    #[error("cannot reach the daemon: {0}")]
    Daemon(DaemonError),
    #[error(transparent)]
    Cold(#[from] ColdError),
    #[error("{0}")]
    Entropy(String),
    /// `THROW_WALLET_EXCEPTION_IF(m_has_ever_refreshed_from_node, ...)`.
    #[error("Hot wallets cannot import outputs")]
    HotWallet,
    #[error("Nothing requested")]
    NothingRequested,
    #[error("Incremental mode is incompatible with non-zero start")]
    IncrementalWithStart,
    #[error("Offset larger than known outputs")]
    OffsetTooLarge,
    #[error("Offset is larger than total outputs")]
    OffsetPastTotal,
    #[error("Imported outputs omit more outputs that we know of. Try using export_outputs all")]
    ImportOmitsOutputs,
    #[error("The blockchain is out of date compared to the signed key images")]
    OutOfDate,
    #[error("More key images returned that we know outputs for")]
    TooManyKeyImages,
    #[error(
        "this wallet was scanned by a build that did not keep the transaction public keys its \
         outputs came from, so it cannot export them; run rescan_bc first"
    )]
    NoTxKeys,
    #[error(
        "key_image generated ephemeral public key not matched with output_key at index {0}; this \
         wallet's keys do not match the outputs it holds"
    )]
    KeyMismatch(usize),
    #[error("key_image generated not matched with cached key image at index {0}")]
    CachedKeyImageMismatch(usize),
    #[error(
        "key image {1} at index {0} is out of the validity domain: it is not a point of the prime \
         order subgroup"
    )]
    KeyImageDomain(usize, KeyImage),
    #[error("signature check failed at index {0}, key image {1}")]
    BadSignature(usize, KeyImage),
    #[error("the output at index {0} does not belong to this wallet")]
    NotOurs(usize),
    #[error("Empty sources")]
    EmptySources,
    /// `error::nonzero_unlock_time`, which Wownero refuses outright
    /// (`specs/06` §6.3).
    #[error("Transaction has non-zero unlock time")]
    NonzeroUnlockTime,
    #[error("cannot build the transaction: {0}")]
    Build(transfer::TransferError),
    #[error("Claimed change does not go to a paid address")]
    ChangeNotPaid,
    #[error("Claimed change is larger than payment to the change address")]
    ChangeTooLarge,
    #[error("Change goes to more than one address")]
    ChangeToManyAddresses,
    #[error("{0}")]
    Send(#[from] SendError),
    #[error("an output this wallet holds is damaged: {0}")]
    Damaged(&'static str),
}

type Result<T> = std::result::Result<T, OfflineError>;

/// What `import_key_images` learned: the height the imported outputs reach,
/// and how much of the wallet is spent and unspent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportedKeyImages {
    pub height: u64,
    pub spent: u64,
    pub unspent: u64,
}

/// An unsigned transfer set, and what the wallet that made it knows.
#[derive(Debug)]
pub struct UnsignedTransfer {
    pub set: UnsignedTxSet,
    /// The file: magic, version, and the sealed archive.
    pub blob: Vec<u8>,
    /// The plan as settled, at the fee the built weight needs.
    pub plan: SpendPlan,
    pub priority: u32,
    pub payment_id: Option<Hash8>,
    /// Pool spends noted while planning ([`Session::note_pool_spends`]).
    pub noted_in_pool: Vec<Hash256>,
    pub pool_unread: Option<String>,
}

/// A signed transfer set, and what the wallet that signed it kept.
///
/// `Debug` is written by hand rather than derived: `tx_keys` holds real
/// transaction secret keys, and a `{:?}` of this on the cold machine — into a
/// log, a panic message or a crash report — would put them where the whole
/// arrangement exists to keep them out of.
pub struct SignedTransfer {
    pub set: SignedTxSet,
    /// The file to hand back to the watch-only half.
    pub blob: Vec<u8>,
    pub txids: Vec<Hash256>,
    /// The transactions themselves, for `sign_transfer export_raw` and for the
    /// RPC's `tx_raw_list`.
    pub raw: Vec<Vec<u8>>,
    /// Per transaction, the transaction secret key and then its per-output
    /// keys. These stay on the cold side: `sign_tx` zeroes the copy inside the
    /// signed set, "don't send it back to the untrusted view wallet".
    pub tx_keys: Vec<Vec<SecretKey>>,
    /// How many outputs the set carried and this wallet took in.
    pub imported_outputs: usize,
}

impl std::fmt::Debug for SignedTransfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedTransfer")
            .field("txids", &self.txids)
            .field("transactions", &self.set.ptx.len())
            .field("key_images", &self.set.key_images.len())
            .field("imported_outputs", &self.imported_outputs)
            .field("tx_keys", &format_args!("<{} kept>", self.tx_keys.len()))
            .finish_non_exhaustive()
    }
}

/// What `submit_transfer` did.
#[derive(Debug)]
pub struct Submitted {
    pub txids: Vec<Hash256>,
    /// One per transaction, in order. A refusal is an answer, not an error.
    pub results: Vec<SendResult>,
    /// How many key images the signed set taught this wallet.
    pub imported_key_images: usize,
}

// -- describe_transfer -----------------------------------------------------

/// One input, as `describe_transfer` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescribedSource {
    pub amount: u64,
    pub global_index: u64,
    pub rct: bool,
    pub public_key: PublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescribedRecipient {
    pub address: String,
    pub amount: u64,
}

/// One transaction, as `describe_transfer` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferDescription {
    pub amount_in: u64,
    pub amount_out: u64,
    /// The smallest ring in the transaction. `u32::MAX` for a transaction with
    /// no inputs, which is what the C++ initialises it to and never lowers.
    pub ring_size: u32,
    pub unlock_time: u64,
    pub sources: Vec<DescribedSource>,
    pub recipients: Vec<DescribedRecipient>,
    /// Hex, or empty for none. A dummy id of zeros counts as none.
    pub payment_id: String,
    pub change_amount: u64,
    pub change_address: String,
    pub fee: u64,
    /// Outputs of nothing: the zero-amount output a transaction with no change
    /// carries.
    pub dummy_outputs: u32,
    pub extra: Vec<u8>,
}

/// Every transaction in a set, added up.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransferSummary {
    pub amount_in: u64,
    pub amount_out: u64,
    pub recipients: Vec<DescribedRecipient>,
    pub change_amount: u64,
    pub change_address: String,
    pub fee: u64,
}

/// `describe_transfer`'s answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DescribedTransfers {
    pub summary: TransferSummary,
    pub txs: Vec<TransferDescription>,
}

impl Session {
    // -- the watch-only half: outputs out --------------------------------

    /// `wallet2::export_outputs(all, start, count)`.
    ///
    /// `all` false is the incremental form: it begins at the first output
    /// whose key image is not known, or is known and still being asked for,
    /// and the importer already has the ones below. `all` true takes
    /// everything, subject to `start` and `count`.
    pub fn export_outputs(&self, all: bool, start: u32, count: u32) -> Result<ExportedOutputs> {
        if count == 0 {
            return Err(OfflineError::NothingRequested);
        }
        if !all && start > 0 {
            return Err(OfflineError::IncrementalWithStart);
        }

        let transfers = &self.state.transfers;
        let offset = if all {
            start as usize
        } else {
            transfers
                .iter()
                .position(|t| !(t.key_image.is_some() && !t.key_image_request))
                .unwrap_or(transfers.len())
        };

        let mut outputs = Vec::new();
        for (n, t) in transfers.iter().enumerate().skip(offset) {
            if (n - offset) as u64 >= u64::from(count) {
                break;
            }
            // A cache written before the keys were kept would export zeros,
            // and the cold wallet would fail to derive anything from them. Say
            // so here rather than there.
            if t.tx_public_key == PublicKey::ZERO {
                return Err(OfflineError::NoTxKeys);
            }
            outputs.push(ExportedTransferDetails {
                public_key: t.public_key,
                internal_output_index: t.internal_output_index,
                global_output_index: t.global_output_index,
                tx_public_key: t.tx_public_key,
                flags: output_flags(t),
                amount: t.amount,
                additional_tx_keys: t.additional_tx_keys.clone(),
                subaddress: t.subaddress,
            });
        }

        Ok(ExportedOutputs {
            offset: offset as u64,
            total: transfers.len() as u64,
            outputs,
        })
    }

    /// [`Session::export_outputs`] as the file `export_outputs_to_str` writes.
    pub fn export_outputs_to_file(&self, all: bool, start: u32, count: u32) -> Result<Vec<u8>> {
        let set = self.export_outputs(all, start, count)?;
        let keys = &self.keys_file.account.keys;
        let mut rng = self.entropy()?;
        Ok(set.to_file(&keys.account_address, &keys.view_secret_key, &mut rng)?)
    }

    // -- the cold half: outputs in ---------------------------------------

    /// `wallet2::import_outputs`, the `exported_transfer_details` overload.
    ///
    /// Returns how many outputs the wallet now holds. Every entry it writes
    /// gets a key image, which is the point: the cold half is the only one
    /// that can compute them.
    pub fn import_outputs(&mut self, outputs: &ExportedOutputs) -> Result<usize> {
        if self.state.ever_refreshed {
            return Err(OfflineError::HotWallet);
        }
        if self.is_view_only() {
            return Err(OfflineError::WatchOnly);
        }

        let offset = usize::try_from(outputs.offset).map_err(|_| OfflineError::OffsetTooLarge)?;
        let total = usize::try_from(outputs.total).map_err(|_| OfflineError::OffsetPastTotal)?;
        if offset > self.state.transfers.len() {
            return Err(OfflineError::ImportOmitsOutputs);
        }
        if offset + outputs.outputs.len() > total {
            return Err(OfflineError::OffsetPastTotal);
        }

        let original_size = self.state.transfers.len();
        if offset + outputs.outputs.len() > self.state.transfers.len() {
            self.state
                .transfers
                .resize(offset + outputs.outputs.len(), blank_transfer());
        } else if total < self.state.transfers.len() {
            self.state.transfers.truncate(total);
        }

        let account = self.keys_file.account.clone();
        for (i, etd) in outputs.outputs.iter().enumerate() {
            let at = i + offset;

            // "skip those we've already imported, or which have different
            // data": the derivation costs a scalar multiplication per output,
            // and a cold wallet may be handed the same list twice.
            if at < original_size {
                let held = &self.state.transfers[at];
                let same = held.key_image.is_some()
                    && held.internal_output_index == etd.internal_output_index
                    && held.public_key == etd.public_key;
                if same {
                    continue;
                }
            }

            // The subaddress index comes with the output, so the derivation
            // does not have to be searched for: try the transaction's own key
            // and then this output's additional key, and take whichever gives
            // back the output's public key. That is
            // `generate_key_image_helper` with `create_one_off_subaddress`
            // already done.
            let (derivation, secret) = derive_for_output(
                &account,
                etd.subaddress,
                &etd.public_key,
                &etd.tx_public_key,
                &etd.additional_tx_keys,
                etd.internal_output_index,
            )
            .ok_or(OfflineError::KeyMismatch(at))?;
            let key_image = wow_crypto::generate_key_image(&etd.public_key, &secret)
                .ok_or(OfflineError::KeyMismatch(at))?;

            self.state.transfers[at] = Transfer {
                // "setup td with cheap loaded data": no block, no
                // transaction id, and the identity mask -- the real mask
                // reaches this wallet in a `tx_source_entry` when it signs.
                block_height: 0,
                txid: wow_crypto::NULL_HASH,
                internal_output_index: etd.internal_output_index,
                global_output_index: etd.global_output_index,
                public_key: etd.public_key,
                derivation,
                tx_public_key: etd.tx_public_key,
                additional_tx_keys: etd.additional_tx_keys.clone(),
                key_image: Some(key_image),
                // The exporter asked for these, and `export_key_images all
                // false` hands back exactly the ones that were asked for.
                key_image_request: true,
                mask: cold::IDENTITY_MASK,
                amount: etd.amount,
                subaddress: etd.subaddress,
                spent: etd.flags & cold::flags::SPENT != 0,
                spent_height: 0,
                unlock_time: 0,
                is_coinbase: false,
                timestamp: 0,
                payment_id: None,
                frozen: etd.flags & cold::flags::FROZEN != 0,
            };
        }

        self.state.reindex();
        self.dirty = true;
        Ok(self.state.transfers.len())
    }

    /// [`Session::import_outputs`] from the file form.
    pub fn import_outputs_from_file(&mut self, blob: &[u8]) -> Result<usize> {
        let keys = &self.keys_file.account.keys;
        let set = ExportedOutputs::from_file(blob, &keys.account_address, &keys.view_secret_key)?;
        self.import_outputs(&set)
    }

    // -- the cold half: key images out -----------------------------------

    /// `wallet2::export_key_images(all)`.
    ///
    /// Each key image comes with a one-member ring signature over the key
    /// image itself, made with the output's one-time secret key, which is what
    /// proves to the watch-only half that the image belongs to the output.
    pub fn export_key_images(&self, all: bool) -> Result<ExportedKeyImages> {
        if self.is_view_only() {
            return Err(OfflineError::WatchOnly);
        }
        let mut rng = self.entropy()?;
        let transfers = &self.state.transfers;
        let offset = if all {
            0
        } else {
            transfers
                .iter()
                .position(|t| t.key_image_request)
                .unwrap_or(transfers.len())
        };

        let mut images = Vec::with_capacity(transfers.len() - offset);
        for (n, t) in transfers.iter().enumerate().skip(offset) {
            let secret = crate::refresh::one_time_secret_key(&self.keys_file.account, t)
                .ok_or(OfflineError::WatchOnly)?;
            let public =
                wow_crypto::secret_key_to_public_key(&secret).ok_or(OfflineError::KeyMismatch(n))?;
            if public != t.public_key {
                return Err(OfflineError::KeyMismatch(n));
            }
            let key_image = wow_crypto::generate_key_image(&t.public_key, &secret)
                .ok_or(OfflineError::KeyMismatch(n))?;
            if t.key_image.is_some_and(|known| known != key_image) {
                return Err(OfflineError::CachedKeyImageMismatch(n));
            }
            let signature = cold::sign_key_image(&mut rng, &key_image, &t.public_key, &secret)
                .ok_or(OfflineError::KeyMismatch(n))?;
            images.push(SignedKeyImage {
                key_image,
                signature,
            });
        }

        Ok(ExportedKeyImages {
            offset: offset as u32,
            images,
        })
    }

    /// [`Session::export_key_images`] as the file `export_key_images` writes.
    pub fn export_key_images_to_file(&self, all: bool) -> Result<Vec<u8>> {
        let set = self.export_key_images(all)?;
        let keys = &self.keys_file.account.keys;
        let mut rng = self.entropy()?;
        Ok(set.to_file(&keys.account_address, &keys.view_secret_key, &mut rng)?)
    }

    // -- the watch-only half: key images in ------------------------------

    /// `wallet2::import_key_images(signed_key_images, offset, spent, unspent,
    /// check_spent)`.
    ///
    /// Every signature is checked, except where this wallet already holds the
    /// same key image for that output — the reference skips it there too, and
    /// it is the common case on a second import.
    pub fn import_key_images(
        &mut self,
        images: &[SignedKeyImage],
        offset: usize,
        check_spent: bool,
    ) -> Result<ImportedKeyImages> {
        if check_spent && !self.state.trusted_daemon {
            return Err(OfflineError::UntrustedDaemon);
        }
        if offset > self.state.transfers.len() {
            return Err(OfflineError::OffsetTooLarge);
        }
        if images.len() > self.state.transfers.len() - offset {
            return Err(OfflineError::OutOfDate);
        }
        if images.is_empty() && offset == 0 {
            return Ok(ImportedKeyImages::default());
        }

        for (n, signed) in images.iter().enumerate() {
            let t = &self.state.transfers[n + offset];
            if t.key_image == Some(signed.key_image) {
                continue;
            }
            // "Key image out of validity domain": a key image outside the
            // prime-order subgroup would let one output be spent twice.
            if !in_prime_order_subgroup(&signed.key_image) {
                return Err(OfflineError::KeyImageDomain(n + offset, signed.key_image));
            }
            if !cold::check_key_image_signature(
                &signed.key_image,
                &t.public_key,
                &signed.signature,
            ) {
                return Err(OfflineError::BadSignature(n + offset, signed.key_image));
            }
        }

        for (n, signed) in images.iter().enumerate() {
            let t = &mut self.state.transfers[n + offset];
            t.key_image = Some(signed.key_image);
            t.key_image_request = false;
        }
        self.state.reindex();
        self.dirty = true;

        if check_spent && !images.is_empty() {
            let client = self.daemon.clone().ok_or(OfflineError::NoDaemon)?;
            let key_images: Vec<[u8; 32]> = images.iter().map(|i| i.key_image.0).collect();
            let status = client
                .is_key_image_spent(&key_images)
                .map_err(OfflineError::Daemon)?;
            if status.len() != images.len() {
                // "daemon returned wrong response for is_key_image_spent,
                // wrong amounts count".
                return Err(OfflineError::Daemon(DaemonError::BadField("spent_status")));
            }
            for (n, s) in status.iter().enumerate() {
                self.state.transfers[n + offset].spent = *s != KeyImageStatus::Unspent;
            }
        }
        // What the reference does next and this does not: for each output the
        // node says is spent in a block, ask `/gettransactions` for the
        // transaction that spent it and file a `confirmed_transfer_details`
        // for it. That is history, not money: the balance here is already
        // right, and a refresh finds the spends and records them the way every
        // other spend is recorded ([`crate::history`]).

        // "accumulate outputs before the updated data", and then the updated
        // ones. A frozen output is left out of both, as it is left out of the
        // balance.
        let mut spent = 0u64;
        let mut unspent = 0u64;
        for t in self.state.transfers.iter().take(offset + images.len()) {
            if t.frozen {
                continue;
            }
            if t.spent {
                spent += t.amount;
            } else {
                unspent += t.amount;
            }
        }

        // "this can be 0 if we do not know the height".
        let height = self
            .state
            .transfers
            .get(images.len() + offset - 1)
            .map_or(0, |t| t.block_height);

        Ok(ImportedKeyImages {
            height,
            spent,
            unspent,
        })
    }

    /// [`Session::import_key_images`] from the file form.
    pub fn import_key_images_from_file(
        &mut self,
        blob: &[u8],
        check_spent: bool,
    ) -> Result<ImportedKeyImages> {
        let set = {
            let keys = &self.keys_file.account.keys;
            ExportedKeyImages::from_file(blob, &keys.account_address, &keys.view_secret_key)?
        };
        self.import_key_images(&set.images, set.offset as usize, check_spent)
    }

    /// The unsigned variant: key images with no signatures, as a signed
    /// transfer set carries them (`wallet2.cpp` 14341).
    ///
    /// No signature to check, so nothing is checked; a mismatch with a known
    /// image is a warning in the reference, which "trusts the imported one".
    /// Returns how many were taken.
    pub fn set_key_images(&mut self, images: &[KeyImage], offset: usize) -> Result<usize> {
        if images.len() + offset > self.state.transfers.len() {
            return Err(OfflineError::TooManyKeyImages);
        }
        for (n, &k) in images.iter().enumerate() {
            let t = &mut self.state.transfers[n + offset];
            if t.key_image.is_some_and(|known| known != k) {
                wow_log::warn!(
                    "wallet.wallet2",
                    "imported key image differs from previously known key image at index {n}: \
                     trusting imported one"
                );
            }
            t.key_image = Some(k);
            t.key_image_request = false;
        }
        self.state.reindex();
        self.dirty = true;
        Ok(images.len())
    }

    // -- the watch-only half: an unsigned set ----------------------------

    /// Plan a spend and write it out unsigned: `create_transactions_2`
    /// followed by `save_tx` / `dump_tx_to_str`.
    ///
    /// The transaction is built, to weigh it and settle the fee, and then
    /// dropped: what goes in the file is the `tx_construction_data`, plus this
    /// wallet's outputs so the cold half can fill in the indices it refers to.
    /// Nothing is recorded as spent — that happens when the signed set comes
    /// back and is submitted ([`Session::submit_signed`]).
    pub fn prepare_unsigned(&mut self, request: &SendRequest<'_>) -> Result<UnsignedTransfer> {
        let mut planned = self.plan_send(request, false)?;
        let settled = planned.settle(&self.keys_file.account.keys.view_secret_key)?;

        // The destinations as the builder was given them: the payee, and
        // change or, when there is no change, nothing to a throwaway address.
        let plan = &settled.plan;
        let payee_amount = plan.amounts[0];
        let change_amount = plan.change;
        let payee = TxDestinationEntry {
            // `tx_destination_entry::original`, which `describe_transfer`
            // shows back so an integrated address is not reduced to the
            // standard one inside it.
            original: request.address.to_string(),
            amount: payee_amount,
            address: planned.payee,
            is_subaddress: planned.payee_is_subaddress,
            is_integrated: Address::decode_for(request.address, self.network)
                .map(|a| a.payment_id.is_some())
                .unwrap_or(false),
        };
        let change = if change_amount > 0 {
            TxDestinationEntry {
                original: String::new(),
                amount: change_amount,
                address: planned.change_to,
                is_subaddress: planned.change_is_subaddress,
                is_integrated: false,
            }
        } else {
            TxDestinationEntry {
                original: String::new(),
                amount: 0,
                address: planned.dummy,
                is_subaddress: false,
                is_integrated: false,
            }
        };

        // `tx_extra` as the build laid it out, with the payment id
        // **decrypted**: the signer makes its own transaction key and has to
        // encrypt the id again
        // (`get_construction_data_with_decrypted_short_payment_id`).
        let extra = extra_with_decrypted_payment_id(
            &settled.built.tx.prefix.extra,
            planned.payment_id.unwrap_or([0u8; 8]),
        );

        // `sources` stays in the order the inputs were picked;
        // `selected_transfers` is permuted into the order the transaction puts
        // them in, which is descending key image, as
        // `transfer_selected_rct`'s `apply_permutation(ins_order, ...)` leaves
        // it.
        let mut sources: Vec<TxSourceEntry> = planned
            .inputs
            .iter()
            .map(|inp| TxSourceEntry {
                outputs: inp
                    .ring
                    .iter()
                    .zip(&inp.global_indices)
                    .map(|(m, &global_index)| RingEntry {
                        global_index,
                        public_key: m.dest,
                        commitment: m.mask,
                    })
                    .collect(),
                real_output: inp.real_index as u64,
                real_out_tx_key: PublicKey::ZERO,
                real_out_additional_tx_keys: Vec::new(),
                real_output_in_tx_index: 0,
                amount: inp.amount,
                rct: true,
                mask: inp.mask.to_bytes(),
                multisig_klrki: [0u8; 128],
            })
            .collect();
        // The ring alone does not say which transaction paid us, and a signer
        // needs that to derive the key again.
        for (source, &i) in sources.iter_mut().zip(&plan.inputs) {
            let t = &self.state.transfers[i];
            source.real_out_tx_key = t.tx_public_key;
            source.real_out_additional_tx_keys = t.additional_tx_keys.clone();
            source.real_output_in_tx_index = t.internal_output_index;
        }

        let mut order: Vec<usize> = (0..planned.inputs.len()).collect();
        order.sort_by(|&a, &b| {
            planned.inputs[b]
                .key_image
                .0
                .cmp(&planned.inputs[a].key_image.0)
        });
        let selected_transfers: Vec<u64> =
            order.iter().map(|&n| plan.inputs[n] as u64).collect();

        let mut subaddr_indices: Vec<u32> = plan
            .inputs
            .iter()
            .map(|&i| self.state.transfers[i].subaddress.minor)
            .collect();
        subaddr_indices.sort_unstable();
        subaddr_indices.dedup();

        let construction = TxConstructionData {
            sources,
            change_dts: change.clone(),
            splitted_dsts: vec![payee.clone(), change],
            selected_transfers,
            extra,
            unlock_time: 0,
            use_rct: true,
            use_view_tags: true,
            rct_config: RctConfig::default(),
            dests: vec![payee],
            subaddr_account: planned.account,
            subaddr_indices,
        };

        // "txs.new_transfers = export_outputs()", incremental: the cold half
        // has the ones it already knows.
        let new_transfers = self.export_outputs(false, 0, u32::MAX)?;
        let set = UnsignedTxSet {
            txes: vec![construction],
            new_transfers,
        };
        let mut rng = self.entropy()?;
        let blob = set.to_file(&self.keys_file.account.keys.view_secret_key, &mut rng)?;

        Ok(UnsignedTransfer {
            set,
            blob,
            plan: settled.plan,
            priority: planned.priority,
            payment_id: planned.payment_id,
            noted_in_pool: std::mem::take(&mut planned.noted_in_pool),
            pool_unread: planned.pool_unread.take(),
        })
    }

    /// `parse_unsigned_tx_from_str`.
    pub fn load_unsigned(&self, blob: &[u8]) -> Result<UnsignedTxSet> {
        Ok(UnsignedTxSet::from_file(
            blob,
            &self.keys_file.account.keys.view_secret_key,
        )?)
    }

    /// `parse_tx_from_str`, without the key image import that follows it.
    pub fn load_signed(&self, blob: &[u8]) -> Result<SignedTxSet> {
        Ok(SignedTxSet::from_file(
            blob,
            &self.keys_file.account.keys.view_secret_key,
        )?)
    }

    // -- the cold half: signing ------------------------------------------

    /// `wallet2::sign_tx(unsigned_tx_set&, txs, signed_tx_set&)` followed by
    /// `sign_tx_dump_to_str`.
    ///
    /// The outputs the set carries are imported first, as the reference does,
    /// because `selected_transfers` indexes into them.
    pub fn sign_unsigned(&mut self, set: &UnsignedTxSet) -> Result<SignedTransfer> {
        if self.is_view_only() {
            return Err(OfflineError::WatchOnly);
        }
        let imported_outputs = if set.new_transfers.outputs.is_empty() {
            0
        } else {
            self.import_outputs(&set.new_transfers)?
        };

        let mut rng = self.entropy()?;
        let view_secret_key = self.keys_file.account.keys.view_secret_key;
        let mut signed = SignedTxSet::default();
        let mut txids = Vec::with_capacity(set.txes.len());
        let mut raw = Vec::with_capacity(set.txes.len());
        let mut tx_keys = Vec::with_capacity(set.txes.len());

        for cd in &set.txes {
            if cd.sources.is_empty() {
                return Err(OfflineError::EmptySources);
            }
            if cd.unlock_time != 0 {
                return Err(OfflineError::NonzeroUnlockTime);
            }

            let inputs = self.spendable_from_sources(cd)?;
            let destinations: Vec<Destination> = cd
                .splitted_dsts
                .iter()
                .map(|d| Destination {
                    address: d.address,
                    is_subaddress: d.is_subaddress,
                    amount: d.amount,
                })
                .collect();
            // The payment id the watch-only half saved, in the clear. `None`
            // and a dummy of zeros produce the same `extra`, so a set with
            // neither is not a special case.
            let payment_id = payment_id_from_extra(&cd.extra);
            let change = Change {
                address: cd.change_dts.address,
                view_secret_key: &view_secret_key,
            };

            let built = transfer::construct_with_change(
                &inputs,
                &destinations,
                Some(change),
                cd.fee(),
                payment_id,
                &mut || random_scalar(&mut rng),
            )
            .map_err(OfflineError::Build)?;

            let mut w = wow_serialize::binary::Writer::with_capacity(8192);
            built.tx.write(&mut w);
            let blob = w.into_vec();
            let txid = transfer::transaction_hash(&built.tx);

            // The key images the transaction spends, in input order, as
            // `boost::to_string(in.k_image) + " "` writes them.
            let mut in_order = Vec::with_capacity(built.tx.prefix.vin.len());
            for input in &built.tx.prefix.vin {
                match input {
                    wow_types::tx::TxIn::ToKey { k_image, .. } => in_order.push(*k_image),
                    _ => return Err(OfflineError::Damaged("an input is not a txin_to_key")),
                }
            }

            // Whatever of this transaction comes back to this wallet, so the
            // watch-only half learns the change output's key image before the
            // block arrives: `signed_txes.tx_key_images`.
            for r in crate::scan::scan_transaction(&built.tx, &self.state.keys())
                .unwrap_or_default()
            {
                if let Some(k) = r.key_image {
                    signed.tx_key_images.push((r.public_key, k));
                }
            }

            signed.ptx.push(PendingTx {
                tx: built.tx,
                dust: 0,
                dust_added_to_fee: false,
                fee: cd.fee(),
                change_dts: cd.change_dts.clone(),
                selected_transfers: cd.selected_transfers.clone(),
                key_images: cold::key_image_list(&in_order),
                // "don't send it back to the untrusted view wallet".
                tx_key: SecretKey::ZERO,
                additional_tx_keys: Vec::new(),
                dests: cd.dests.clone(),
                construction_data: cd.clone(),
                multisig_tx_key_entropy: SecretKey::ZERO,
            });
            txids.push(txid);
            raw.push(blob);
            let mut keys = vec![built.tx_secret_key];
            keys.extend(built.additional_tx_secret_keys);
            tx_keys.push(keys);
        }

        // "add key images": every one this wallet knows, in its own output
        // order, so one file teaches the watch-only half all of them.
        signed.key_images = self
            .state
            .transfers
            .iter()
            .map(|t| t.key_image.unwrap_or(KeyImage::ZERO))
            .collect();

        let blob = signed.to_file(&view_secret_key, &mut rng)?;
        Ok(SignedTransfer {
            set: signed,
            blob,
            txids,
            raw,
            tx_keys,
            imported_outputs,
        })
    }

    /// One [`SpendableOutput`] per source: the ring as it was chosen, and the
    /// one-time secret key derived again from the transaction key the source
    /// carries.
    fn spendable_from_sources(&self, cd: &TxConstructionData) -> Result<Vec<SpendableOutput>> {
        let account = &self.keys_file.account;
        let mut inputs = Vec::with_capacity(cd.sources.len());
        for (n, src) in cd.sources.iter().enumerate() {
            let real = usize::try_from(src.real_output)
                .ok()
                .and_then(|i| src.outputs.get(i))
                .ok_or(OfflineError::Damaged("an input's real output is missing"))?;

            // Which subaddress this output went to is not in the source, so
            // it is looked up as scanning looks it up: the implied spend key,
            // against this wallet's subaddress table.
            let (derivation, subaddress) = subaddress_for_output(
                account,
                &self.state.subaddresses,
                &real.public_key,
                &src.real_out_tx_key,
                &src.real_out_additional_tx_keys,
                src.real_output_in_tx_index,
            )
            .ok_or(OfflineError::NotOurs(n))?;
            let secret_key = one_time_key_from(
                account,
                &derivation,
                src.real_output_in_tx_index,
                subaddress,
            );
            let public = wow_crypto::secret_key_to_public_key(&secret_key)
                .ok_or(OfflineError::KeyMismatch(n))?;
            if public != real.public_key {
                return Err(OfflineError::KeyMismatch(n));
            }
            let key_image = wow_crypto::generate_key_image(&real.public_key, &secret_key)
                .ok_or(OfflineError::KeyMismatch(n))?;
            let mask = wow_crypto::ops::decode_scalar(&src.mask)
                .ok_or(OfflineError::Damaged("an input's mask is not a scalar"))?;

            inputs.push(SpendableOutput {
                public_key: real.public_key,
                secret_key,
                mask,
                amount: src.amount,
                key_image,
                ring: src
                    .outputs
                    .iter()
                    .map(|o| wow_crypto::clsag::RingMember {
                        dest: o.public_key,
                        mask: o.commitment,
                    })
                    .collect(),
                global_indices: src.outputs.iter().map(|o| o.global_index).collect(),
                real_index: src.real_output as usize,
            });
        }
        Ok(inputs)
    }

    // -- the watch-only half: submitting ---------------------------------

    /// `submit_transfer`: take in the signed set's key images, relay each
    /// transaction, and record it as a send.
    ///
    /// The key images come in first, as `parse_tx_from_str` takes them in
    /// before it hands the transactions over, so that a transaction refused by
    /// the node still leaves this wallet knowing its own images.
    pub fn submit_signed(&mut self, set: &SignedTxSet) -> Result<Submitted> {
        let client = self.daemon.clone().ok_or(OfflineError::NoDaemon)?;

        let imported_key_images = self.set_key_images(&set.key_images, 0)?;
        // `m_cold_key_images`: the key images of these transactions' own
        // outputs, which this wallet could not compute. Held against the
        // outputs when they are found, which for the change output is the
        // block this transaction lands in.
        for &(public_key, key_image) in &set.tx_key_images {
            if let Some(&i) = self.state.by_public_key.get(&public_key) {
                self.state.transfers[i].key_image = Some(key_image);
                self.state.transfers[i].key_image_request = false;
            }
        }
        self.state.reindex();

        let store = self.keys_file.store_tx_info();
        let mut txids = Vec::with_capacity(set.ptx.len());
        let mut results = Vec::with_capacity(set.ptx.len());
        for ptx in &set.ptx {
            let mut w = wow_serialize::binary::Writer::with_capacity(8192);
            ptx.tx.write(&mut w);
            let blob = w.into_vec();
            let txid = transfer::transaction_hash(&ptx.tx);

            let result = client
                .send_raw_transaction(&blob, false)
                .map_err(OfflineError::Daemon)?;
            txids.push(txid);
            if !result.accepted() {
                results.push(result);
                continue;
            }

            // `commit_tx`: the inputs are spent, and where it went is kept
            // when `store-tx-info` is on. The plan is rebuilt from the
            // construction data, which is the only record of it this wallet
            // has -- it never saw the transaction being built.
            let plan = plan_from_pending(ptx, self.state.transfers.len());
            let payees: Vec<String> = if store {
                ptx.construction_data
                    .dests
                    .iter()
                    .map(|d| self.describe_address(d))
                    .collect()
            } else {
                Vec::new()
            };
            let payee_refs: Vec<&str> = payees.iter().map(String::as_str).collect();
            let payment_id = payment_id_from_extra(&ptx.construction_data.extra)
                .filter(|p| *p != [0u8; 8])
                .filter(|_| store);
            self.state
                .record_sent(txid, &plan, &payee_refs, payment_id, now());
            results.push(result);
        }
        self.dirty = true;

        Ok(Submitted {
            txids,
            results,
            imported_key_images,
        })
    }

    // -- both halves: describing -----------------------------------------

    /// `describe_transfer`: what a set of transactions does, for a user to
    /// check before signing or submitting.
    pub fn describe(&self, txes: &[TxConstructionData]) -> Result<DescribedTransfers> {
        let mut out = DescribedTransfers::default();
        // Insertion-ordered rather than hashed: the C++ walks an
        // `unordered_map` here, so its recipient order is whatever its buckets
        // give. A stable order is a nicety, not a difference in meaning.
        let mut all_dests: Vec<(AccountPublicAddress, String, u64)> = Vec::new();
        let mut first_change: Option<AccountPublicAddress> = None;

        for cd in txes {
            let mut desc = TransferDescription {
                amount_in: 0,
                amount_out: 0,
                ring_size: u32::MAX,
                unlock_time: cd.unlock_time,
                sources: Vec::new(),
                recipients: Vec::new(),
                payment_id: String::new(),
                change_amount: 0,
                change_address: String::new(),
                fee: 0,
                dummy_outputs: 0,
                extra: cd.extra.clone(),
            };

            // A dummy id of zeros is "no payment id", as it is everywhere
            // else.
            let payment_id = payment_id_from_extra(&cd.extra).filter(|p| *p != [0u8; 8]);
            if let Some(p) = payment_id {
                desc.payment_id = wow_crypto::hex::encode(&p);
            }

            for src in &cd.sources {
                // `real_output_in_tx_index`, not `real_output`: the
                // reference indexes the ring by the output's index within its
                // own transaction, which is a long-standing upstream quirk and
                // is reproduced so the two agree. It is only ever shown.
                let entry = usize::try_from(src.real_output_in_tx_index)
                    .ok()
                    .and_then(|i| src.outputs.get(i))
                    .ok_or(OfflineError::Damaged("an input's real output is missing"))?;
                desc.sources.push(DescribedSource {
                    amount: src.amount,
                    global_index: entry.global_index,
                    rct: src.rct,
                    public_key: entry.public_key,
                });
                desc.amount_in += src.amount;
                desc.ring_size = desc.ring_size.min(src.outputs.len() as u32);
            }

            let mut dests: Vec<(AccountPublicAddress, String, u64)> = Vec::new();
            for d in &cd.splitted_dsts {
                let address = self.describe_address_with(d, payment_id);
                match dests.iter_mut().find(|(a, _, _)| *a == d.address) {
                    Some((_, _, amount)) => *amount += d.amount,
                    None => dests.push((d.address, address, d.amount)),
                }
                desc.amount_out += d.amount;
            }

            // Claimed change has to be change: it must go to an address this
            // transaction pays, it cannot be more than that address is paid,
            // and across a set it must be one address. Without these a set
            // could claim most of what it sends is change and a user
            // confirming it would be told a tiny amount was leaving.
            if cd.change_dts.amount > 0 {
                match first_change {
                    None => first_change = Some(cd.change_dts.address),
                    Some(a) if a != cd.change_dts.address => {
                        return Err(OfflineError::ChangeToManyAddresses)
                    }
                    Some(_) => {}
                }
                let left = {
                    let claimed = dests
                        .iter_mut()
                        .find(|(a, _, _)| *a == cd.change_dts.address)
                        .ok_or(OfflineError::ChangeNotPaid)?;
                    if claimed.2 < cd.change_dts.amount {
                        return Err(OfflineError::ChangeTooLarge);
                    }
                    claimed.2 -= cd.change_dts.amount;
                    claimed.2
                };
                desc.change_amount += cd.change_dts.amount;
                if left == 0 {
                    dests.retain(|(a, _, _)| *a != cd.change_dts.address);
                }
            }

            for (address, text, amount) in dests {
                if amount == 0 {
                    desc.dummy_outputs += 1;
                    continue;
                }
                desc.recipients.push(DescribedRecipient {
                    address: text.clone(),
                    amount,
                });
                match all_dests.iter_mut().find(|(a, _, _)| *a == address) {
                    Some((_, _, total)) => *total += amount,
                    None => all_dests.push((address, text, amount)),
                }
            }

            if desc.change_amount > 0 {
                // The reference takes the address from the *first*
                // construction data and its account, not from this one's:
                // change goes to one address across the whole set, which is
                // what the check above enforces.
                let first = &txes[0];
                desc.change_address = encode_address(
                    self.network,
                    first.change_dts.address,
                    first.subaddr_account > 0,
                );
                out.summary.change_address = desc.change_address.clone();
            }

            desc.fee = desc.amount_in.saturating_sub(desc.amount_out);
            out.summary.amount_in += desc.amount_in;
            out.summary.amount_out += desc.amount_out;
            out.summary.change_amount += desc.change_amount;
            out.summary.fee += desc.fee;
            out.txs.push(desc);
        }

        out.summary.recipients = all_dests
            .into_iter()
            .map(|(_, address, amount)| DescribedRecipient { address, amount })
            .collect();
        Ok(out)
    }

    /// A destination's address as text: the one the user typed when there is
    /// one, and otherwise the plain encoding.
    fn describe_address(&self, d: &TxDestinationEntry) -> String {
        self.describe_address_with(d, None)
    }

    /// `tx_destination_entry::address`, and the `describe_transfer` rule that
    /// a standard address in a transaction carrying an encrypted id is shown
    /// as the integrated address it came from.
    fn describe_address_with(&self, d: &TxDestinationEntry, payment_id: Option<Hash8>) -> String {
        let plain = encode_address(self.network, d.address, d.is_subaddress);
        if let Some(p) = payment_id {
            if !d.is_subaddress && d.original != plain {
                return Address::integrated(self.network, d.address, p).encode();
            }
        }
        if d.original.is_empty() {
            plain
        } else {
            d.original.clone()
        }
    }

    /// `m_export_format == ExportFormat::Ascii`: whether a file written for
    /// the other half should be wrapped in PEM armour
    /// ([`crate::cold::wrap_ascii`]).
    ///
    /// It is a *file* setting, not a format one: `save_to_file` wraps and
    /// `export_outputs_to_str` does not, which is why the RPC's
    /// `outputs_data_hex` is never wrapped and a file written by
    /// `export_outputs` may be. Read from the keys file, where `set
    /// export-format` puts it, and `Binary` (0) when it says nothing.
    pub fn export_ascii(&self) -> bool {
        self.keys_file
            .settings
            .get("export_format")
            .and_then(serde_json::Value::as_u64)
            == Some(1)
    }

    /// Entropy for one operation, refused rather than substituted.
    fn entropy(&self) -> Result<Rng> {
        crate::entropy::seeded_rng().map_err(OfflineError::Entropy)
    }
}

/// `exported_transfer_details::m_flags`, from one of this wallet's outputs.
///
/// `m_rct` is always set: every output this chain has carried since RingCT is
/// one, and nothing here records a pre-RingCT output. `m_key_image_partial` is
/// multisig's and is never set.
fn output_flags(t: &Transfer) -> u8 {
    let mut flags = cold::flags::RCT;
    if t.spent {
        flags |= cold::flags::SPENT;
    }
    if t.frozen {
        flags |= cold::flags::FROZEN;
    }
    if t.key_image.is_some() {
        flags |= cold::flags::KEY_IMAGE_KNOWN;
    }
    if t.key_image_request {
        flags |= cold::flags::KEY_IMAGE_REQUEST;
    }
    flags
}

/// A key image is a point of the prime-order subgroup, and
/// `import_key_images` checks it: "Key image out of validity domain",
/// `scalarmultKey(ki2rct(key_image), curveOrder()) == identity`.
///
/// The test here is equivalent and does not need `l` as a scalar — a
/// `curve25519_dalek::Scalar` is reduced modulo `l`, so writing `l` in one
/// gives zero and `0 * P` is the identity for every `P`. Instead: for
/// `P = P' + T` with `T` in the torsion subgroup, `8P = 8P'`, and dividing
/// that by eight recovers `P'`, which equals `P` only when `T` is zero.
fn in_prime_order_subgroup(key_image: &KeyImage) -> bool {
    let Some(p) = wow_crypto::ops::decode_point(&key_image.0) else {
        return false;
    };
    let inv_eight = curve25519_dalek::scalar::Scalar::from(8u64).invert();
    inv_eight * wow_crypto::ops::mul8(&p) == p
}

/// The one-time secret key for an output, given the derivation it was found
/// under and which of this wallet's addresses it paid.
///
/// `generate_key_image_helper_precomp`: `Hs(D || i) + b`, plus the subaddress
/// secret for anything but the main address.
///
/// [`crate::refresh::one_time_secret_key`] is the same calculation from a
/// [`Transfer`], which is what the send path has. Here there is no
/// `Transfer` — the derivation has just been recovered from a transaction key
/// a file carried — so it takes the pieces.
fn one_time_key_from(
    account: &crate::AccountBase,
    derivation: &KeyDerivation,
    output_index: u64,
    subaddress: SubaddressIndex,
) -> SecretKey {
    let mut x =
        wow_crypto::derive_secret_key(derivation, output_index, &account.keys.spend_secret_key);
    if !subaddress.is_main() {
        let m = wow_crypto::keys::subaddress_secret_key(&account.keys.view_secret_key, subaddress);
        x = SecretKey(wow_crypto::ops::sc_add(&x.0, &m.0));
    }
    x
}

/// The derivation and secret key for an imported output whose subaddress index
/// is already known: the transaction's own key first, then this output's
/// additional key, and whichever gives back the output's public key wins.
fn derive_for_output(
    account: &crate::AccountBase,
    subaddress: SubaddressIndex,
    public_key: &PublicKey,
    tx_public_key: &PublicKey,
    additional: &[PublicKey],
    output_index: u64,
) -> Option<(KeyDerivation, SecretKey)> {
    let view = &account.keys.view_secret_key;
    let candidates = [
        wow_crypto::generate_key_derivation(tx_public_key, view),
        usize::try_from(output_index)
            .ok()
            .and_then(|i| additional.get(i))
            .and_then(|k| wow_crypto::generate_key_derivation(k, view)),
    ];
    for d in candidates.into_iter().flatten() {
        let secret = one_time_key_from(account, &d, output_index, subaddress);
        if wow_crypto::secret_key_to_public_key(&secret).as_ref() == Some(public_key) {
            return Some((d, secret));
        }
    }
    None
}

/// The derivation and subaddress index for an output whose index is *not*
/// known: `is_out_to_acc_precomp`, the way scanning finds it.
fn subaddress_for_output(
    account: &crate::AccountBase,
    subaddresses: &crate::SubaddressTable,
    public_key: &PublicKey,
    tx_public_key: &PublicKey,
    additional: &[PublicKey],
    output_index: u64,
) -> Option<(KeyDerivation, SubaddressIndex)> {
    let view = &account.keys.view_secret_key;
    let candidates = [
        wow_crypto::generate_key_derivation(tx_public_key, view),
        usize::try_from(output_index)
            .ok()
            .and_then(|i| additional.get(i))
            .and_then(|k| wow_crypto::generate_key_derivation(k, view)),
    ];
    for d in candidates.into_iter().flatten() {
        let Some(spend) = wow_crypto::derive_subaddress_public_key(public_key, &d, output_index)
        else {
            continue;
        };
        if let Some(index) = subaddresses.get(&spend) {
            return Some((d, index));
        }
    }
    None
}

/// The payment id `tx_extra` carries, as a construction data holds it: in the
/// clear, because the signer encrypts it again under its own transaction key.
pub fn payment_id_from_extra(extra: &[u8]) -> Option<Hash8> {
    let parsed = wow_types::tx_extra::parse_tx_extra(extra);
    parsed.fields.iter().find_map(|f| match f {
        wow_types::tx_extra::TxExtraField::Nonce(n) => match n.as_slice() {
            [0x01, id @ ..] => id.try_into().ok(),
            _ => None,
        },
        _ => None,
    })
}

/// `tx_extra` with its encrypted payment id replaced by the plaintext one:
/// `get_construction_data_with_decrypted_short_payment_id`.
///
/// The nonce is removed and added again, which is what the reference does, and
/// the result is sorted as `sort_tx_extra` sorts it.
fn extra_with_decrypted_payment_id(extra: &[u8], payment_id: Hash8) -> Vec<u8> {
    let parsed = wow_types::tx_extra::parse_tx_extra(extra);
    let mut fields: Vec<wow_types::tx_extra::TxExtraField> = Vec::with_capacity(3);
    let mut had_nonce = false;
    for f in parsed.fields {
        match f {
            wow_types::tx_extra::TxExtraField::Nonce(_) => {
                had_nonce = true;
                let mut nonce = Vec::with_capacity(9);
                nonce.push(0x01);
                nonce.extend_from_slice(&payment_id);
                fields.push(wow_types::tx_extra::TxExtraField::Nonce(nonce));
            }
            other => fields.push(other),
        }
    }
    if !had_nonce {
        return extra.to_vec();
    }
    wow_types::tx_extra::serialize_tx_extra(&fields, true)
}

/// The plan a `pending_tx` implies, so that submitting it records the same
/// send an online wallet would have recorded.
fn plan_from_pending(ptx: &PendingTx, held: usize) -> SpendPlan {
    let inputs: Vec<usize> = ptx
        .selected_transfers
        .iter()
        .filter_map(|&i| usize::try_from(i).ok())
        .filter(|&i| i < held)
        .collect();
    let sent: u64 = ptx
        .construction_data
        .dests
        .iter()
        .map(|d| d.amount)
        .sum();
    SpendPlan {
        inputs,
        amounts: vec![sent],
        change: ptx.change_dts.amount,
        fee: ptx.fee,
        estimated_weight: 0,
        sweep: false,
        left_behind: 0,
    }
}

/// A blank output, for the gaps `import_outputs` leaves when it resizes past
/// what the file describes: `m_transfers.resize(...)` default-constructs them,
/// and the entries the file does describe are written over them.
fn blank_transfer() -> Transfer {
    Transfer {
        block_height: 0,
        txid: wow_crypto::NULL_HASH,
        internal_output_index: 0,
        global_output_index: 0,
        public_key: PublicKey::ZERO,
        derivation: KeyDerivation::ZERO,
        tx_public_key: PublicKey::ZERO,
        additional_tx_keys: Vec::new(),
        key_image: None,
        key_image_request: false,
        mask: [0u8; 32],
        amount: 0,
        subaddress: SubaddressIndex::MAIN,
        spent: false,
        spent_height: 0,
        unlock_time: 0,
        is_coinbase: false,
        timestamp: 0,
        payment_id: None,
        frozen: false,
    }
}

/// An address as text, standard or subaddress:
/// `get_account_address_as_str(nettype, is_subaddress, addr)`.
fn encode_address(network: Network, keys: AccountPublicAddress, is_subaddress: bool) -> String {
    if is_subaddress {
        Address::subaddress(network, keys).encode()
    } else {
        Address::standard(network, keys).encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    use crate::AccountBase;
    use curve25519_dalek::scalar::Scalar;
    use wow_crypto::types::EcPoint;

    fn rng() -> Rng {
        Rng::deterministic_test_seed()
    }

    fn account(seed: u8) -> AccountBase {
        let spend = SecretKey(wow_crypto::ops::sc_reduce32(&[seed; 32]));
        AccountBase::from_spend_key(spend, 0).expect("keys")
    }

    fn session(account: AccountBase) -> Session {
        Session::create_in(
            Box::new(MemoryStore::new("cold-test")),
            Network::Mainnet,
            String::new(),
            1,
            account,
            "English",
            0,
        )
        .expect("create")
    }

    /// The pair: the cold half with the spend key, and the watch-only half
    /// with the same view key and no spend key.
    fn pair(seed: u8) -> (Session, Session) {
        let full = account(seed);
        let mut watching = full.clone();
        watching.forget_spend_key();
        (session(full), session(watching))
    }

    /// One output paid to `to`, built the way a real transaction pays one, so
    /// that the cold half can derive its key from the transaction public key
    /// alone.
    fn paid_output(to: &AccountBase, rng: &mut Rng, index: u64, amount: u64) -> (Transfer, Scalar) {
        let tx_secret = SecretKey(rng.random_scalar());
        let tx_public = wow_crypto::secret_key_to_public_key(&tx_secret).expect("R");
        let derivation =
            wow_crypto::generate_key_derivation(&tx_public, &to.keys.view_secret_key).expect("d");
        let public_key = wow_crypto::derive_public_key(
            &derivation,
            index,
            &to.keys.account_address.spend_public_key,
        )
        .expect("P");
        let mask = Scalar::from_bytes_mod_order(rng.random_scalar());

        (
            Transfer {
                block_height: 100,
                txid: [7u8; 32],
                internal_output_index: index,
                global_output_index: 4_000 + index,
                public_key,
                derivation,
                tx_public_key: tx_public,
                additional_tx_keys: Vec::new(),
                // A watch-only wallet cannot compute one, and says it wants it.
                key_image: None,
                key_image_request: true,
                mask: mask.to_bytes(),
                amount,
                subaddress: SubaddressIndex::MAIN,
                spent: false,
                spent_height: 0,
                unlock_time: 0,
                is_coinbase: false,
                timestamp: 1_700_000_000,
                payment_id: None,
                frozen: false,
            },
            mask,
        )
    }

    /// The whole first exchange: the watch-only half sends its outputs, the
    /// cold half computes their key images and sends them back, and the
    /// watch-only half ends up knowing them.
    #[test]
    fn outputs_out_and_key_images_back() {
        let (mut cold, mut watch) = pair(3);
        let mut r = rng();
        let (t0, _) = paid_output(&cold.keys_file.account, &mut r, 0, 1_000_000);
        let (t1, _) = paid_output(&cold.keys_file.account, &mut r, 1, 2_000_000);
        watch.state.transfers = vec![t0.clone(), t1.clone()];
        watch.state.reindex();

        // Incremental: neither key image is known, so it starts at zero.
        let exported = watch.export_outputs(false, 0, u32::MAX).expect("export");
        assert_eq!((exported.offset, exported.total), (0, 2));
        assert_eq!(exported.outputs.len(), 2);
        assert_eq!(
            exported.outputs[0].flags,
            cold::flags::RCT | cold::flags::KEY_IMAGE_REQUEST
        );
        assert_eq!(exported.outputs[1].tx_public_key, t1.tx_public_key);

        let file = watch
            .export_outputs_to_file(false, 0, u32::MAX)
            .expect("file");
        assert_eq!(cold.import_outputs_from_file(&file).expect("import"), 2);

        // The cold half now holds both, with the key images the watch-only
        // half could not compute, and with the placeholder mask.
        assert_eq!(cold.state.transfers.len(), 2);
        assert!(cold.state.transfers[0].key_image.is_some());
        assert_eq!(cold.state.transfers[0].mask, cold::IDENTITY_MASK);
        assert_eq!(cold.state.transfers[0].public_key, t0.public_key);
        assert!(cold.state.transfers[1].key_image_request, "asked for");
        assert_eq!(cold.state.transfers[1].amount, 2_000_000);

        // Back the other way. Incremental again: every imported output was
        // asked for, so the export starts at zero.
        let images = cold.export_key_images(false).expect("export");
        assert_eq!(images.offset, 0);
        assert_eq!(images.images.len(), 2);
        for (n, signed) in images.images.iter().enumerate() {
            assert!(
                cold::check_key_image_signature(
                    &signed.key_image,
                    &cold.state.transfers[n].public_key,
                    &signed.signature
                ),
                "signature {n}"
            );
        }

        let file = cold.export_key_images_to_file(false).expect("file");
        // `check_spent` is off: with it on the wallet would have to ask a node,
        // and that is what the trusted-daemon gate is about.
        let imported = watch
            .import_key_images_from_file(&file, false)
            .expect("import");
        assert_eq!(imported.height, 100);
        assert_eq!(imported.spent, 0);
        assert_eq!(imported.unspent, 3_000_000);
        assert_eq!(
            watch.state.transfers[0].key_image,
            cold.state.transfers[0].key_image
        );
        assert!(!watch.state.transfers[0].key_image_request, "no longer");
        assert_eq!(watch.state.by_key_image.len(), 2);

        // And now the incremental export has nothing left to say.
        let again = watch.export_outputs(false, 0, u32::MAX).expect("export");
        assert_eq!(again.offset, 2);
        assert!(again.outputs.is_empty());
    }

    /// A watch-only wallet cannot sign, and a wallet that has scanned the
    /// chain cannot be turned into a cold one.
    #[test]
    fn the_halves_refuse_each_others_work() {
        let (mut cold, mut watch) = pair(4);
        assert!(matches!(
            watch.export_key_images(false),
            Err(OfflineError::WatchOnly)
        ));
        assert!(matches!(
            watch.import_outputs(&ExportedOutputs::default()),
            Err(OfflineError::WatchOnly)
        ));

        cold.state.ever_refreshed = true;
        assert!(matches!(
            cold.import_outputs(&ExportedOutputs::default()),
            Err(OfflineError::HotWallet)
        ));

        // `count` of zero asks for nothing, and a non-zero `start` contradicts
        // the incremental form.
        assert!(matches!(
            watch.export_outputs(true, 0, 0),
            Err(OfflineError::NothingRequested)
        ));
        assert!(matches!(
            watch.export_outputs(false, 5, u32::MAX),
            Err(OfflineError::IncrementalWithStart)
        ));
    }

    /// `import_key_images` wants a trusted daemon before it asks one whether
    /// anything is spent, as `simplewallet` does.
    #[test]
    fn checking_spent_status_needs_a_trusted_daemon() {
        let (_, mut watch) = pair(5);
        assert!(matches!(
            watch.import_key_images(&[], 0, true),
            Err(OfflineError::UntrustedDaemon)
        ));
        watch.state.trusted_daemon = true;
        // Nothing to import and nothing known, so nothing is asked of a node.
        assert_eq!(
            watch.import_key_images(&[], 0, true).expect("empty"),
            ImportedKeyImages::default()
        );
    }

    /// A signature made for another output does not pass, and neither does a
    /// key image outside the prime-order subgroup.
    #[test]
    fn a_bad_key_image_is_refused() {
        let (mut cold, mut watch) = pair(6);
        let mut r = rng();
        let (t0, _) = paid_output(&cold.keys_file.account, &mut r, 0, 1_000_000);
        watch.state.transfers = vec![t0];
        watch.state.reindex();
        let file = watch
            .export_outputs_to_file(false, 0, u32::MAX)
            .expect("file");
        cold.import_outputs_from_file(&file).expect("import");
        let mut images = cold.export_key_images(false).expect("export");

        // A different output's signature.
        let other = SecretKey(r.random_scalar());
        let other_public = wow_crypto::secret_key_to_public_key(&other).expect("P");
        let other_image =
            wow_crypto::generate_key_image(&other_public, &other).expect("an image");
        images.images[0].signature =
            cold::sign_key_image(&mut r, &other_image, &other_public, &other).expect("sign");
        assert!(matches!(
            watch.import_key_images(&images.images, 0, false),
            Err(OfflineError::BadSignature(0, _))
        ));

        // A key image with a torsion component: the identity point has order
        // one, which is in the subgroup, so use a point of order eight.
        let torsion = KeyImage([
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ]);
        assert!(!in_prime_order_subgroup(&torsion));
        assert!(in_prime_order_subgroup(
            &cold.state.transfers[0].key_image.expect("an image")
        ));
        images.images[0].key_image = torsion;
        assert!(matches!(
            watch.import_key_images(&images.images, 0, false),
            Err(OfflineError::KeyImageDomain(0, _))
        ));
    }

    /// One transaction's worth of construction data, paying `payee` out of one
    /// output the cold wallet owns.
    fn construction(
        cold: &AccountBase,
        transfer: &Transfer,
        mask: Scalar,
        payee: AccountPublicAddress,
        decoy: (PublicKey, EcPoint),
    ) -> TxConstructionData {
        let commitment = wow_crypto::rct::commit(transfer.amount, &mask);
        let change_amount = 50_000;
        let fee = 50_000;
        let payee_amount = transfer.amount - change_amount - fee;
        let change = TxDestinationEntry {
            original: String::new(),
            amount: change_amount,
            address: cold.keys.account_address,
            is_subaddress: false,
            is_integrated: false,
        };
        let to_payee = TxDestinationEntry {
            original: String::new(),
            amount: payee_amount,
            address: payee,
            is_subaddress: false,
            is_integrated: false,
        };
        TxConstructionData {
            sources: vec![TxSourceEntry {
                // Ascending global index, as the wire form needs.
                outputs: vec![
                    RingEntry {
                        global_index: transfer.global_output_index,
                        public_key: transfer.public_key,
                        commitment,
                    },
                    RingEntry {
                        global_index: transfer.global_output_index + 17,
                        public_key: decoy.0,
                        commitment: decoy.1,
                    },
                ],
                real_output: 0,
                real_out_tx_key: transfer.tx_public_key,
                real_out_additional_tx_keys: Vec::new(),
                real_output_in_tx_index: transfer.internal_output_index,
                amount: transfer.amount,
                rct: true,
                mask: mask.to_bytes(),
                multisig_klrki: [0u8; 128],
            }],
            change_dts: change.clone(),
            splitted_dsts: vec![to_payee.clone(), change],
            selected_transfers: vec![0],
            extra: Vec::new(),
            unlock_time: 0,
            use_rct: true,
            use_view_tags: true,
            rct_config: RctConfig::default(),
            dests: vec![to_payee],
            subaddr_account: 0,
            subaddr_indices: vec![0],
        }
    }

    /// The second exchange: the cold half signs an unsigned set, and what it
    /// writes parses back, balances, and names the change it was told about.
    #[test]
    fn an_unsigned_set_is_signed_and_reads_back() {
        let (mut cold, mut watch) = pair(7);
        let mut r = rng();
        let (t0, mask) = paid_output(&cold.keys_file.account, &mut r, 0, 1_000_000);
        watch.state.transfers = vec![t0.clone()];
        watch.state.reindex();

        let payee = account(8).keys.account_address;
        let decoy_secret = SecretKey(r.random_scalar());
        let decoy = (
            wow_crypto::secret_key_to_public_key(&decoy_secret).expect("a decoy"),
            wow_crypto::rct::commit(9_999, &Scalar::from_bytes_mod_order(r.random_scalar())),
        );
        let cd = construction(&cold.keys_file.account, &t0, mask, payee, decoy);

        let set = UnsignedTxSet {
            txes: vec![cd.clone()],
            new_transfers: watch.export_outputs(false, 0, u32::MAX).expect("outputs"),
        };
        // Through the file, so the whole format is exercised rather than the
        // structure alone.
        let blob = set
            .to_file(&watch.keys_file.account.keys.view_secret_key, &mut r)
            .expect("write");
        let loaded = cold.load_unsigned(&blob).expect("load");
        assert_eq!(loaded, set);

        let signed = cold.sign_unsigned(&loaded).expect("sign");
        assert_eq!(signed.imported_outputs, 1);
        assert_eq!(signed.set.ptx.len(), 1);
        assert_eq!(signed.txids.len(), 1);
        assert_eq!(signed.tx_keys[0].len(), 1, "one key, no subaddress payee");
        // The transaction key is kept on this side only.
        assert_eq!(signed.set.ptx[0].tx_key, SecretKey::ZERO);
        assert_ne!(signed.tx_keys[0][0], SecretKey::ZERO);

        let ptx = &signed.set.ptx[0];
        assert_eq!(ptx.fee, 50_000);
        assert_eq!(ptx.tx.prefix.vin.len(), 1);
        assert_eq!(ptx.tx.prefix.vout.len(), 2);
        assert!(transfer::commitments_balance(&ptx.tx.rct_signatures));
        assert!(ptx.key_images.ends_with(' '));
        // The change comes back to this wallet, so its key image is known here
        // and is sent on so the watch-only half learns it early.
        assert_eq!(signed.set.tx_key_images.len(), 1);
        assert_eq!(signed.set.key_images.len(), 1);

        // The watch-only half reads it back.
        let back = watch.load_signed(&signed.blob).expect("parse");
        assert_eq!(back.ptx.len(), 1);
        assert_eq!(back.ptx[0].fee, 50_000);
        assert_eq!(back.ptx[0].construction_data, cd);
        assert_eq!(
            crate::transfer::transaction_hash(&back.ptx[0].tx),
            signed.txids[0]
        );
        assert_eq!(back.key_images, signed.set.key_images);

        // And taking in its key images is enough to know the output is ours.
        assert_eq!(watch.set_key_images(&back.key_images, 0).expect("set"), 1);
        assert_eq!(
            watch.state.transfers[0].key_image,
            cold.state.transfers[0].key_image
        );
    }

    /// `describe_transfer`: what the user is shown before signing.
    #[test]
    fn a_set_describes_what_it_does() {
        let (cold, _) = pair(9);
        let mut r = rng();
        let (t0, mask) = paid_output(&cold.keys_file.account, &mut r, 0, 1_000_000);
        let payee = account(10).keys.account_address;
        let decoy_secret = SecretKey(r.random_scalar());
        let decoy = (
            wow_crypto::secret_key_to_public_key(&decoy_secret).expect("a decoy"),
            wow_crypto::rct::commit(1, &Scalar::from_bytes_mod_order(r.random_scalar())),
        );
        let cd = construction(&cold.keys_file.account, &t0, mask, payee, decoy);

        let described = cold.describe(&[cd.clone()]).expect("describe");
        assert_eq!(described.txs.len(), 1);
        let d = &described.txs[0];
        assert_eq!(d.amount_in, 1_000_000);
        assert_eq!(d.amount_out, 950_000);
        assert_eq!(d.fee, 50_000);
        assert_eq!(d.ring_size, 2);
        assert_eq!(d.change_amount, 50_000);
        assert_eq!(d.sources.len(), 1);
        assert_eq!(d.sources[0].global_index, t0.global_output_index);
        assert_eq!(d.recipients.len(), 1, "change is not a recipient");
        assert_eq!(d.recipients[0].amount, 900_000);
        assert_eq!(
            d.recipients[0].address,
            Address::standard(Network::Mainnet, payee).encode()
        );
        assert_eq!(
            d.change_address,
            cold.primary_address(),
            "change goes back to this wallet"
        );
        assert_eq!(d.payment_id, "", "none carried");
        assert_eq!(d.dummy_outputs, 0);
        assert_eq!(described.summary.amount_in, 1_000_000);
        assert_eq!(described.summary.fee, 50_000);
        assert_eq!(described.summary.recipients.len(), 1);

        // Change that does not go to a paid address is refused rather than
        // shown: a set could otherwise claim most of what it sends is change.
        let mut lying = cd.clone();
        lying.change_dts.address = account(11).keys.account_address;
        assert!(matches!(
            cold.describe(&[lying]),
            Err(OfflineError::ChangeNotPaid)
        ));

        let mut greedy = cd;
        greedy.change_dts.amount = 900_000;
        assert!(matches!(
            cold.describe(&[greedy]),
            Err(OfflineError::ChangeTooLarge)
        ));
    }

    /// A set with no inputs, or one asking for an unlock time, is refused
    /// rather than signed.
    #[test]
    fn a_set_that_cannot_be_signed_is_refused() {
        let (mut cold, _) = pair(12);
        let empty = UnsignedTxSet {
            txes: vec![TxConstructionData::default()],
            new_transfers: ExportedOutputs::default(),
        };
        assert!(matches!(
            cold.sign_unsigned(&empty),
            Err(OfflineError::EmptySources)
        ));

        let mut r = rng();
        let (t0, mask) = paid_output(&cold.keys_file.account, &mut r, 0, 1_000_000);
        let payee = account(13).keys.account_address;
        let decoy_secret = SecretKey(r.random_scalar());
        let decoy = (
            wow_crypto::secret_key_to_public_key(&decoy_secret).expect("a decoy"),
            wow_crypto::rct::commit(1, &Scalar::from_bytes_mod_order(r.random_scalar())),
        );
        let mut cd = construction(&cold.keys_file.account, &t0, mask, payee, decoy);
        cd.unlock_time = 100;
        let locked = UnsignedTxSet {
            txes: vec![cd],
            new_transfers: ExportedOutputs::default(),
        };
        assert!(matches!(
            cold.sign_unsigned(&locked),
            Err(OfflineError::NonzeroUnlockTime)
        ));
    }

    /// The payment id a construction data carries is in the clear, and
    /// replacing it is what `get_construction_data_with_decrypted_short_payment_id`
    /// does.
    #[test]
    fn the_payment_id_travels_in_the_clear() {
        use wow_types::tx_extra::{serialize_tx_extra, TxExtraField};

        let encrypted = serialize_tx_extra(
            &[
                TxExtraField::Pubkey(PublicKey([1u8; 32])),
                TxExtraField::Nonce(vec![0x01, 9, 9, 9, 9, 9, 9, 9, 9]),
            ],
            true,
        );
        assert_eq!(payment_id_from_extra(&encrypted), Some([9u8; 8]));

        let plain = extra_with_decrypted_payment_id(&encrypted, [4u8; 8]);
        assert_eq!(payment_id_from_extra(&plain), Some([4u8; 8]));
        // The transaction public key is left where it was.
        let parsed = wow_types::tx_extra::parse_tx_extra(&plain);
        assert_eq!(parsed.tx_pubkey(), Some(PublicKey([1u8; 32])));

        // Nothing to replace: the bytes come back untouched.
        let none = serialize_tx_extra(&[TxExtraField::Pubkey(PublicKey([2u8; 32]))], true);
        assert_eq!(extra_with_decrypted_payment_id(&none, [4u8; 8]), none);
        assert_eq!(payment_id_from_extra(&none), None);
    }
}
