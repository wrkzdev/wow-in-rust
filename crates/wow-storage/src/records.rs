//! Byte-exact record layouts for `data.mdb`.
//!
//! `specs/10-storage-lmdb.md` §4.
//!
//! Every record is the raw memory image of a `#pragma pack(push, 1)` C++
//! struct in host byte order (`specs/10` §3.3). This module decodes and encodes
//! them **field by field with length checks** — `specs/10` §1.1 is explicit
//! that a `transmute` of a slice into a struct is never acceptable, and the
//! crate forbids `unsafe` outright so the question does not arise.
//!
//! Offsets below are decimal and match the spec's tables so the two can be
//! diffed. Each type carries its `LEN`, and every decoder rejects a
//! wrong-length input rather than reading a short record as zeros.

use crate::comparator::compare_hash32;

/// A record did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The value was not the length this record type requires.
    ///
    /// For `output_amounts` this is how the two forms are told apart, so it is
    /// carried rather than collapsed into a generic error.
    WrongLength { expected: usize, found: usize },
    /// `output_amounts` values are 64 or 96 bytes; this was neither.
    NotAnOutputRecord { found: usize },
    /// A `tx_outputs` value was not a whole number of `u64`s.
    RaggedOutputIndices { found: usize },
    /// A `properties` key was not NUL-terminated.
    UnterminatedPropertyKey,
    /// An `alt_blocks` value was shorter than its fixed header.
    AltBlockTooShort { found: usize },
}

// ---------------------------------------------------------------------------
// little-endian field helpers
// ---------------------------------------------------------------------------

fn u64_at(s: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(s[off..off + 8].try_into().expect("bounds checked by LEN"))
}

fn hash_at(s: &[u8], off: usize) -> [u8; 32] {
    s[off..off + 32].try_into().expect("bounds checked by LEN")
}

fn put_u64(out: &mut [u8], off: usize, v: u64) {
    out[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn put_hash(out: &mut [u8], off: usize, v: &[u8; 32]) {
    out[off..off + 32].copy_from_slice(v);
}

fn need(s: &[u8], expected: usize) -> Result<(), RecordError> {
    if s.len() == expected {
        Ok(())
    } else {
        Err(RecordError::WrongLength {
            expected,
            found: s.len(),
        })
    }
}

// ---------------------------------------------------------------------------
// §4.2 mdb_block_info
// ---------------------------------------------------------------------------

/// `mdb_block_info` (= `mdb_block_info_4`), **96 bytes** (`specs/10` §4.2).
///
/// The value of `block_info`, stored under the [`crate::comparator::ZEROKEY`]
/// dummy key with the height as the dupsort prefix.
///
/// Three earlier versions exist — `_1` without `bi_cum_rct`, `_2` without
/// `bi_long_term_block_weight`, `_3` with a single 64-bit difficulty. A
/// version-5 database contains only `_4`, so this decodes that and rejects
/// anything else by length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BlockInfo {
    /// Offset 0.
    pub height: u64,
    /// Offset 8.
    pub timestamp: u64,
    /// Offset 16 — `already_generated_coins`.
    pub coins: u64,
    /// Offset 24 — the block weight, a `size_t` widened to `u64`.
    pub weight: u64,
    /// Offsets 32 and 40 — cumulative difficulty, low then high.
    pub cumulative_difficulty: u128,
    /// Offset 48.
    pub hash: [u8; 32],
    /// Offset 80 — the running RingCT output total.
    ///
    /// Computed in `add_block`; see [`cumulative_rct_outputs`].
    pub cum_rct: u64,
    /// Offset 88 — **not recomputable** from block weights
    /// (`specs/06` §3.4); this record is authoritative.
    pub long_term_block_weight: u64,
}

impl BlockInfo {
    pub const LEN: usize = 96;

    pub fn decode(s: &[u8]) -> Result<Self, RecordError> {
        need(s, Self::LEN)?;
        Ok(BlockInfo {
            height: u64_at(s, 0),
            timestamp: u64_at(s, 8),
            coins: u64_at(s, 16),
            weight: u64_at(s, 24),
            // Two separate u64 fields, low first.
            cumulative_difficulty: u128::from(u64_at(s, 32)) | (u128::from(u64_at(s, 40)) << 64),
            hash: hash_at(s, 48),
            cum_rct: u64_at(s, 80),
            long_term_block_weight: u64_at(s, 88),
        })
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        put_u64(&mut out, 0, self.height);
        put_u64(&mut out, 8, self.timestamp);
        put_u64(&mut out, 16, self.coins);
        put_u64(&mut out, 24, self.weight);
        put_u64(&mut out, 32, self.cumulative_difficulty as u64);
        put_u64(&mut out, 40, (self.cumulative_difficulty >> 64) as u64);
        put_hash(&mut out, 48, &self.hash);
        put_u64(&mut out, 80, self.cum_rct);
        put_u64(&mut out, 88, self.long_term_block_weight);
        out
    }
}

/// `bi_cum_rct` as `add_block` computes it (`specs/10` §4.2).
///
/// ```text
/// n = (if miner_tx.version == 2 { miner_tx.vout.len() } else { 0 })
///   + sum over txs of (if tx.version == 2 { tx.vout.len() } else { 0 })
/// if height > 0 && block.major_version >= 4 { n += block_info[height - 1].bi_cum_rct }
/// ```
///
/// The `major_version >= 4` guard is always true on Wownero — the table starts
/// at 7 — but reproduce it: without it, a chain whose first blocks were v1
/// would restart the running total rather than continue it.
pub fn cumulative_rct_outputs(
    height: u64,
    block_major_version: u8,
    miner_tx_version: u64,
    miner_tx_outputs: usize,
    // (version, output count) for each non-coinbase transaction.
    txs: impl IntoIterator<Item = (u64, usize)>,
    previous_cum_rct: u64,
) -> u64 {
    let mut n = if miner_tx_version == 2 {
        miner_tx_outputs as u64
    } else {
        0
    };
    for (version, outs) in txs {
        if version == 2 {
            n += outs as u64;
        }
    }
    if height > 0 && block_major_version >= 4 {
        n += previous_cum_rct;
    }
    n
}

// ---------------------------------------------------------------------------
// §4.3 blk_height
// ---------------------------------------------------------------------------

/// `blk_height`, the value of `block_heights`, **40 bytes** (`specs/10` §4.3).
///
/// Dupsort-compared by [`compare_hash32`] over bytes 0..32.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BlockHeight {
    /// Offset 0 — the dupsort prefix.
    pub hash: [u8; 32],
    /// Offset 32.
    pub height: u64,
}

impl BlockHeight {
    pub const LEN: usize = 40;

    pub fn decode(s: &[u8]) -> Result<Self, RecordError> {
        need(s, Self::LEN)?;
        Ok(BlockHeight {
            hash: hash_at(s, 0),
            height: u64_at(s, 32),
        })
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        put_hash(&mut out, 0, &self.hash);
        put_u64(&mut out, 32, self.height);
        out
    }

    /// The dupsort ordering LMDB applies to this table.
    pub fn dup_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
        compare_hash32(a, b)
    }
}

// ---------------------------------------------------------------------------
// §4.4 txindex
// ---------------------------------------------------------------------------

/// `txindex`, the value of `tx_indices`, **56 bytes** (`specs/10` §4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TxIndex {
    /// Offset 0 — the tx hash, and the dupsort prefix.
    pub key: [u8; 32],
    /// Offset 32 — where `tx_data_t` begins.
    pub tx_id: u64,
    /// Offset 40.
    pub unlock_time: u64,
    /// Offset 48 — despite the name, this is the **height** of the containing
    /// block, not a block id.
    pub block_id: u64,
}

impl TxIndex {
    pub const LEN: usize = 56;

    pub fn decode(s: &[u8]) -> Result<Self, RecordError> {
        need(s, Self::LEN)?;
        Ok(TxIndex {
            key: hash_at(s, 0),
            tx_id: u64_at(s, 32),
            unlock_time: u64_at(s, 40),
            block_id: u64_at(s, 48),
        })
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        put_hash(&mut out, 0, &self.key);
        put_u64(&mut out, 32, self.tx_id);
        put_u64(&mut out, 40, self.unlock_time);
        put_u64(&mut out, 48, self.block_id);
        out
    }

    pub fn dup_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
        compare_hash32(a, b)
    }
}

// ---------------------------------------------------------------------------
// §4.5 outkey / pre_rct_outkey
// ---------------------------------------------------------------------------

/// `outkey` / `pre_rct_outkey`, the value of `output_amounts`
/// (`specs/10` §4.5).
///
/// **The record length is the type tag.** `add_output` fills one buffer and
/// then sets `mv_size` to 96 when `amount == 0` and 64 otherwise, truncating
/// the commitment. There is no discriminant byte; readers dispatch on the
/// length, and `get_output_key(.., include_commitment)` synthesises
/// `commitment = zeroCommit(amount)` for the short form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct OutKey {
    /// Offset 0 — the dupsort prefix, compared with `compare_uint64`.
    pub amount_index: u64,
    /// Offset 8 — the global output id.
    pub output_id: u64,
    /// Offset 16 — the one-time output public key.
    pub pubkey: [u8; 32],
    /// Offset 48.
    pub unlock_time: u64,
    /// Offset 56.
    pub height: u64,
    /// Offset 64, **present only in the 96-byte RingCT form**.
    pub commitment: Option<[u8; 32]>,
}

impl OutKey {
    /// `pre_rct_outkey`: `amount != 0`, no commitment.
    pub const LEN_PRE_RCT: usize = 64;
    /// `outkey`: `amount == 0`, with the commitment.
    pub const LEN_RCT: usize = 96;

    pub fn decode(s: &[u8]) -> Result<Self, RecordError> {
        let commitment = match s.len() {
            Self::LEN_PRE_RCT => None,
            Self::LEN_RCT => Some(hash_at(s, 64)),
            found => return Err(RecordError::NotAnOutputRecord { found }),
        };
        Ok(OutKey {
            amount_index: u64_at(s, 0),
            output_id: u64_at(s, 8),
            pubkey: hash_at(s, 16),
            unlock_time: u64_at(s, 48),
            height: u64_at(s, 56),
            commitment,
        })
    }

    /// The encoded length this record will take: 96 with a commitment, 64
    /// without.
    pub const fn len(&self) -> usize {
        if self.commitment.is_some() {
            Self::LEN_RCT
        } else {
            Self::LEN_PRE_RCT
        }
    }

    /// Always false — an `OutKey` is a fixed-layout record, never empty. Present
    /// only because `len` without `is_empty` is a clippy lint.
    pub const fn is_empty(&self) -> bool {
        false
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.len()];
        put_u64(&mut out, 0, self.amount_index);
        put_u64(&mut out, 8, self.output_id);
        put_hash(&mut out, 16, &self.pubkey);
        put_u64(&mut out, 48, self.unlock_time);
        put_u64(&mut out, 56, self.height);
        if let Some(c) = &self.commitment {
            put_hash(&mut out, 64, c);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// §4.6 outtx
// ---------------------------------------------------------------------------

/// `outtx`, the value of `output_txs`, **48 bytes** (`specs/10` §4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct OutTx {
    /// Offset 0 — the dupsort prefix, compared with `compare_uint64`.
    pub output_id: u64,
    /// Offset 8.
    pub tx_hash: [u8; 32],
    /// Offset 40 — the output's index **within its transaction**, not global.
    pub local_index: u64,
}

impl OutTx {
    pub const LEN: usize = 48;

    pub fn decode(s: &[u8]) -> Result<Self, RecordError> {
        need(s, Self::LEN)?;
        Ok(OutTx {
            output_id: u64_at(s, 0),
            tx_hash: hash_at(s, 8),
            local_index: u64_at(s, 40),
        })
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        put_u64(&mut out, 0, self.output_id);
        put_hash(&mut out, 8, &self.tx_hash);
        put_u64(&mut out, 40, self.local_index);
        out
    }
}

// ---------------------------------------------------------------------------
// §4.7 tx_outputs
// ---------------------------------------------------------------------------

/// `tx_outputs` — a bare `u64[n]` array of amount output indices, with **no
/// count prefix** (`specs/10` §4.7).
///
/// An empty vector is stored as a zero-length value, which is a legitimate
/// record rather than a missing one.
pub fn decode_tx_outputs(s: &[u8]) -> Result<Vec<u64>, RecordError> {
    if !s.len().is_multiple_of(8) {
        return Err(RecordError::RaggedOutputIndices { found: s.len() });
    }
    Ok(s.as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect())
}

/// Encode `tx_outputs`.
pub fn encode_tx_outputs(indices: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(indices.len() * 8);
    for i in indices {
        out.extend_from_slice(&i.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// §4.9 txpool_tx_meta_t
// ---------------------------------------------------------------------------

/// How a transaction reached the pool (`specs/10` §4.9).
///
/// Not stored directly: it is reconstructed from five flags spread across two
/// bytes, and `set_relay_method` clears all five before setting one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RelayMethod {
    /// `do_not_relay = 1`.
    None,
    /// `is_local = 1`.
    Local,
    /// `is_forwarding = 1`.
    Forward,
    /// `dandelionpp_stem = 1`.
    Stem,
    /// `kept_by_block = 1`.
    Block,
    /// All five clear.
    #[default]
    Fluff,
}

/// `txpool_tx_meta_t`, **192 bytes** (`specs/10` §4.9).
///
/// Unlike the other records this struct is *not* inside a `#pragma pack` block,
/// but every field is naturally aligned so `sizeof` is 192 with no inserted
/// padding. The 76-byte tail exists so the struct can grow without a schema
/// migration; it is written as zeros and **preserved on read-modify-write**,
/// which is why [`padding`](TxPoolMeta::padding) is kept rather than discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxPoolMeta {
    /// Offset 0.
    pub max_used_block_id: [u8; 32],
    /// Offset 32.
    pub last_failed_id: [u8; 32],
    /// Offset 64.
    pub weight: u64,
    /// Offset 72.
    pub fee: u64,
    /// Offset 80.
    pub max_used_block_height: u64,
    /// Offset 88.
    pub last_failed_height: u64,
    /// Offset 96.
    pub receive_time: u64,
    /// Offset 104 — overloaded; see `specs/09` §2.2.
    pub last_relayed_time: u64,
    /// Offset 112 — a whole `u8`, not a bit.
    pub kept_by_block: bool,
    /// Offset 113 — independent of the relay method.
    pub relayed: bool,
    /// Offset 114 — a whole `u8`, not a bit.
    pub do_not_relay: bool,
    /// Byte 115, bit 0.
    pub double_spend_seen: bool,
    /// Byte 115, bit 1.
    pub pruned: bool,
    /// Byte 115, bit 2.
    pub is_local: bool,
    /// Byte 115, bit 3.
    pub dandelionpp_stem: bool,
    /// Byte 115, bit 4.
    pub is_forwarding: bool,
    /// Byte 115, bits 5–7, and bytes 116..192.
    ///
    /// Preserved verbatim so a round-trip through this node does not discard
    /// fields a newer C++ build may have written.
    pub bf_padding: u8,
    /// Bytes 116..192.
    pub padding: [u8; 76],
}

impl Default for TxPoolMeta {
    fn default() -> Self {
        TxPoolMeta {
            max_used_block_id: [0; 32],
            last_failed_id: [0; 32],
            weight: 0,
            fee: 0,
            max_used_block_height: 0,
            last_failed_height: 0,
            receive_time: 0,
            last_relayed_time: 0,
            kept_by_block: false,
            relayed: false,
            do_not_relay: false,
            double_spend_seen: false,
            pruned: false,
            is_local: false,
            dandelionpp_stem: false,
            is_forwarding: false,
            bf_padding: 0,
            padding: [0; 76],
        }
    }
}

impl TxPoolMeta {
    pub const LEN: usize = 192;

    pub fn decode(s: &[u8]) -> Result<Self, RecordError> {
        need(s, Self::LEN)?;
        // Itanium ABI: u8 bitfields are allocated from the least significant
        // bit up, so bit 0 is the first member declared.
        let bits = s[115];
        Ok(TxPoolMeta {
            max_used_block_id: hash_at(s, 0),
            last_failed_id: hash_at(s, 32),
            weight: u64_at(s, 64),
            fee: u64_at(s, 72),
            max_used_block_height: u64_at(s, 80),
            last_failed_height: u64_at(s, 88),
            receive_time: u64_at(s, 96),
            last_relayed_time: u64_at(s, 104),
            kept_by_block: s[112] != 0,
            relayed: s[113] != 0,
            do_not_relay: s[114] != 0,
            double_spend_seen: bits & 0b0000_0001 != 0,
            pruned: bits & 0b0000_0010 != 0,
            is_local: bits & 0b0000_0100 != 0,
            dandelionpp_stem: bits & 0b0000_1000 != 0,
            is_forwarding: bits & 0b0001_0000 != 0,
            bf_padding: bits >> 5,
            padding: s[116..192].try_into().expect("bounds checked by LEN"),
        })
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        put_hash(&mut out, 0, &self.max_used_block_id);
        put_hash(&mut out, 32, &self.last_failed_id);
        put_u64(&mut out, 64, self.weight);
        put_u64(&mut out, 72, self.fee);
        put_u64(&mut out, 80, self.max_used_block_height);
        put_u64(&mut out, 88, self.last_failed_height);
        put_u64(&mut out, 96, self.receive_time);
        put_u64(&mut out, 104, self.last_relayed_time);
        out[112] = u8::from(self.kept_by_block);
        out[113] = u8::from(self.relayed);
        out[114] = u8::from(self.do_not_relay);
        out[115] = u8::from(self.double_spend_seen)
            | (u8::from(self.pruned) << 1)
            | (u8::from(self.is_local) << 2)
            | (u8::from(self.dandelionpp_stem) << 3)
            | (u8::from(self.is_forwarding) << 4)
            | (self.bf_padding << 5);
        out[116..192].copy_from_slice(&self.padding);
        out
    }

    /// `get_relay_method` (`specs/10` §4.9).
    ///
    /// The state word mixes two storage locations: `kept_by_block` and
    /// `do_not_relay` are whole bytes (112 and 114) while the other three are
    /// bits in byte 115.
    ///
    /// The C builds the word and switches on it, so a record with two flags set
    /// falls through to the default. That is reproduced here: only the five
    /// single-bit words name a method, and anything else is `Fluff`.
    pub fn relay_method(&self) -> RelayMethod {
        let state = u8::from(self.kept_by_block)
            | (u8::from(self.do_not_relay) << 1)
            | (u8::from(self.is_local) << 2)
            | (u8::from(self.is_forwarding) << 3)
            | (u8::from(self.dandelionpp_stem) << 4);
        match state {
            1 => RelayMethod::Block,
            2 => RelayMethod::None,
            4 => RelayMethod::Local,
            8 => RelayMethod::Forward,
            16 => RelayMethod::Stem,
            _ => RelayMethod::Fluff,
        }
    }

    /// `set_relay_method` — clears all five flags, then sets exactly one (or
    /// none, for `Fluff`).
    pub fn set_relay_method(&mut self, method: RelayMethod) {
        self.kept_by_block = false;
        self.do_not_relay = false;
        self.is_local = false;
        self.is_forwarding = false;
        self.dandelionpp_stem = false;
        match method {
            RelayMethod::None => self.do_not_relay = true,
            RelayMethod::Local => self.is_local = true,
            RelayMethod::Forward => self.is_forwarding = true,
            RelayMethod::Stem => self.dandelionpp_stem = true,
            RelayMethod::Block => self.kept_by_block = true,
            RelayMethod::Fluff => {}
        }
    }
}

// ---------------------------------------------------------------------------
// §4.10 alt_blocks
// ---------------------------------------------------------------------------

/// `alt_block_data_t` plus the block blob, in one value (`specs/10` §4.10).
///
/// The header is 40 bytes and the blob follows immediately with no length
/// prefix — the value's own length delimits it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AltBlock {
    /// Offset 0.
    pub height: u64,
    /// Offset 8.
    pub cumulative_weight: u64,
    /// Offsets 16 and 24, low then high.
    pub cumulative_difficulty: u128,
    /// Offset 32.
    pub already_generated_coins: u64,
    /// Offset 40 to the end of the value.
    pub blob: Vec<u8>,
}

impl AltBlock {
    /// The fixed header, before the blob.
    pub const HEADER_LEN: usize = 40;

    pub fn decode(s: &[u8]) -> Result<Self, RecordError> {
        if s.len() < Self::HEADER_LEN {
            return Err(RecordError::AltBlockTooShort { found: s.len() });
        }
        Ok(AltBlock {
            height: u64_at(s, 0),
            cumulative_weight: u64_at(s, 8),
            cumulative_difficulty: u128::from(u64_at(s, 16)) | (u128::from(u64_at(s, 24)) << 64),
            already_generated_coins: u64_at(s, 32),
            blob: s[Self::HEADER_LEN..].to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; Self::HEADER_LEN];
        put_u64(&mut out, 0, self.height);
        put_u64(&mut out, 8, self.cumulative_weight);
        put_u64(&mut out, 16, self.cumulative_difficulty as u64);
        put_u64(&mut out, 24, (self.cumulative_difficulty >> 64) as u64);
        put_u64(&mut out, 32, self.already_generated_coins);
        out.extend_from_slice(&self.blob);
        out
    }
}

// ---------------------------------------------------------------------------
// §4.1 properties keys
// ---------------------------------------------------------------------------

/// A `properties` key, **NUL-terminated, with the NUL counted**
/// (`specs/10` §4.1).
///
/// The C++ uses `MDB_val_copy<const char*>` with `strlen(s) + 1`, so
/// `properties["version"]` is the eight-byte key `b"version\0"`. Writing seven
/// bytes creates a *new* key rather than reading the existing one, and the
/// database then looks empty of properties while still holding them.
pub fn property_key(name: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(name.len() + 1);
    k.extend_from_slice(name.as_bytes());
    k.push(0);
    k
}

/// Read a `properties` key back, rejecting one that is not NUL-terminated.
pub fn property_name(key: &[u8]) -> Result<&str, RecordError> {
    match key.split_last() {
        Some((0, rest)) => {
            std::str::from_utf8(rest).map_err(|_| RecordError::UnterminatedPropertyKey)
        }
        _ => Err(RecordError::UnterminatedPropertyKey),
    }
}

/// `properties["version"]`, the schema version. A version-5 database is what
/// `specs/10` §2.3 targets.
pub const PROPERTY_VERSION: &str = "version";
/// `properties["pruning_seed"]`, a `u32`.
pub const PROPERTY_PRUNING_SEED: &str = "pruning_seed";
/// `properties["max_block_size"]`, a `u64`.
pub const PROPERTY_MAX_BLOCK_SIZE: &str = "max_block_size";

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        for (i, b) in a.iter_mut().enumerate() {
            *b = n.wrapping_add(i as u8);
        }
        a
    }

    /// `specs/10` §4: every length is byte-exact and must be asserted, because
    /// a wrong one shifts every field after it.
    #[test]
    fn the_record_lengths_are_exact() {
        assert_eq!(BlockInfo::LEN, 96);
        assert_eq!(BlockHeight::LEN, 40);
        assert_eq!(TxIndex::LEN, 56);
        assert_eq!(OutKey::LEN_PRE_RCT, 64);
        assert_eq!(OutKey::LEN_RCT, 96);
        assert_eq!(OutTx::LEN, 48);
        assert_eq!(TxPoolMeta::LEN, 192);
        assert_eq!(AltBlock::HEADER_LEN, 40);
    }

    #[test]
    fn block_info_round_trips() {
        let b = BlockInfo {
            height: 514_000,
            timestamp: 1_645_949_729,
            coins: 123_456_789_012_345,
            weight: 95,
            cumulative_difficulty: (1u128 << 70) | 0x000d_1724_d5d5_c513,
            hash: h(7),
            cum_rct: 9_876_543,
            long_term_block_weight: 300_000,
        };
        let e = b.encode();
        assert_eq!(e.len(), BlockInfo::LEN);
        assert_eq!(BlockInfo::decode(&e), Ok(b));
    }

    /// The cumulative difficulty is **two** `u64` fields, low at 32 and high at
    /// 40. Storing it as one 128-bit little-endian value happens to give the
    /// same bytes, but reading the fields in the wrong order does not.
    #[test]
    fn block_info_splits_the_difficulty_low_word_first() {
        let b = BlockInfo {
            cumulative_difficulty: 0x1111_1111_1111_1111u128 | (0x2222_2222_2222_2222u128 << 64),
            ..Default::default()
        };
        let e = b.encode();
        assert_eq!(&e[32..40], &[0x11; 8], "low word at offset 32");
        assert_eq!(&e[40..48], &[0x22; 8], "high word at offset 40");
        assert_eq!(
            BlockInfo::decode(&e).unwrap().cumulative_difficulty,
            b.cumulative_difficulty
        );
    }

    #[test]
    fn block_info_fields_sit_at_their_documented_offsets() {
        let b = BlockInfo {
            height: 1,
            timestamp: 2,
            coins: 3,
            weight: 4,
            cumulative_difficulty: 5,
            hash: h(0xaa),
            cum_rct: 6,
            long_term_block_weight: 7,
        };
        let e = b.encode();
        assert_eq!(u64::from_le_bytes(e[0..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(e[8..16].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(e[16..24].try_into().unwrap()), 3);
        assert_eq!(u64::from_le_bytes(e[24..32].try_into().unwrap()), 4);
        assert_eq!(u64::from_le_bytes(e[32..40].try_into().unwrap()), 5);
        assert_eq!(&e[48..80], &h(0xaa));
        assert_eq!(u64::from_le_bytes(e[80..88].try_into().unwrap()), 6);
        assert_eq!(u64::from_le_bytes(e[88..96].try_into().unwrap()), 7);
    }

    /// A short or long value must be rejected, not read as zeros — an older
    /// `mdb_block_info_1`/`_2`/`_3` record has a different length and would
    /// otherwise decode to nonsense.
    #[test]
    fn a_wrong_length_block_info_is_rejected() {
        for len in [0usize, 64, 72, 88, 95, 97, 192] {
            assert_eq!(
                BlockInfo::decode(&vec![0u8; len]),
                Err(RecordError::WrongLength {
                    expected: 96,
                    found: len
                })
            );
        }
    }

    /// `specs/10` §4.2: the running RingCT total counts only v2 transactions
    /// and carries forward from the previous height.
    #[test]
    fn cumulative_rct_counts_only_v2_outputs() {
        // A v2 coinbase with 1 output plus two v2 txs with 2 and 3 outputs.
        let n = cumulative_rct_outputs(100, 20, 2, 1, [(2u64, 2usize), (2, 3)], 1_000);
        assert_eq!(n, 1_000 + 1 + 2 + 3);

        // v1 transactions contribute nothing.
        let n = cumulative_rct_outputs(100, 20, 1, 5, [(1u64, 9usize), (2, 3)], 1_000);
        assert_eq!(n, 1_000 + 3, "the v1 coinbase and v1 tx are not counted");
    }

    /// The `major_version >= 4` guard and the `height > 0` guard both stop the
    /// carry-forward. Always true on Wownero, but reproduce it.
    #[test]
    fn cumulative_rct_guards_the_carry_forward() {
        assert_eq!(
            cumulative_rct_outputs(0, 20, 2, 1, [], 1_000),
            1,
            "height 0 does not carry forward"
        );
        assert_eq!(
            cumulative_rct_outputs(100, 3, 2, 1, [], 1_000),
            1,
            "major_version 3 does not carry forward"
        );
        assert_eq!(
            cumulative_rct_outputs(100, 4, 2, 1, [], 1_000),
            1_001,
            "major_version 4 does"
        );
    }

    #[test]
    fn block_height_round_trips() {
        let b = BlockHeight {
            hash: h(3),
            height: 331_170,
        };
        let e = b.encode();
        assert_eq!(&e[..32], &h(3), "the hash is the dupsort prefix");
        assert_eq!(BlockHeight::decode(&e), Ok(b));
        assert_eq!(
            BlockHeight::dup_cmp(&e, &e),
            std::cmp::Ordering::Equal,
            "dupsort is compare_hash32 over the prefix"
        );
    }

    #[test]
    fn tx_index_round_trips() {
        let t = TxIndex {
            key: h(11),
            tx_id: 42,
            unlock_time: 288,
            block_id: 514_000,
        };
        let e = t.encode();
        assert_eq!(&e[..32], &h(11));
        assert_eq!(TxIndex::decode(&e), Ok(t));
        // `block_id` is a height; it must not be read as a hash.
        assert_eq!(u64::from_le_bytes(e[48..56].try_into().unwrap()), 514_000);
    }

    /// `specs/10` §4.5: the length *is* the discriminant. This is the property
    /// `specs/15` §3.3 asks to assert — "the two `output_amounts` lengths are
    /// exactly 64 and 96".
    #[test]
    fn the_output_record_length_is_the_type_tag() {
        let pre_rct = OutKey {
            amount_index: 5,
            output_id: 900,
            pubkey: h(1),
            unlock_time: 0,
            height: 12,
            commitment: None,
        };
        let rct = OutKey {
            commitment: Some(h(2)),
            ..pre_rct
        };

        assert_eq!(pre_rct.encode().len(), 64);
        assert_eq!(rct.encode().len(), 96);
        assert_eq!(OutKey::decode(&pre_rct.encode()), Ok(pre_rct));
        assert_eq!(OutKey::decode(&rct.encode()), Ok(rct));

        // The first 64 bytes are identical -- the RingCT form is the same
        // buffer with the commitment appended, which is how `add_output`
        // produces it.
        assert_eq!(&rct.encode()[..64], &pre_rct.encode()[..]);
    }

    #[test]
    fn an_output_record_of_any_other_length_is_rejected() {
        for len in [0usize, 48, 63, 65, 80, 95, 97, 128] {
            assert_eq!(
                OutKey::decode(&vec![0u8; len]),
                Err(RecordError::NotAnOutputRecord { found: len })
            );
        }
    }

    #[test]
    fn out_tx_round_trips() {
        let o = OutTx {
            output_id: 7_654_321,
            tx_hash: h(9),
            local_index: 1,
        };
        let e = o.encode();
        assert_eq!(u64::from_le_bytes(e[..8].try_into().unwrap()), 7_654_321);
        assert_eq!(OutTx::decode(&e), Ok(o));
    }

    /// `specs/10` §4.7: no count prefix, and an empty vector is a legitimate
    /// zero-length record.
    #[test]
    fn tx_outputs_have_no_count_prefix() {
        let v = vec![1u64, 2, 3_000_000_000];
        let e = encode_tx_outputs(&v);
        assert_eq!(e.len(), 24, "3 * 8, with nothing else");
        assert_eq!(decode_tx_outputs(&e), Ok(v));

        assert_eq!(encode_tx_outputs(&[]).len(), 0);
        assert_eq!(decode_tx_outputs(&[]), Ok(Vec::new()));
    }

    #[test]
    fn a_ragged_tx_outputs_value_is_rejected() {
        for len in [1usize, 7, 9, 15] {
            assert_eq!(
                decode_tx_outputs(&vec![0u8; len]),
                Err(RecordError::RaggedOutputIndices { found: len })
            );
        }
    }

    #[test]
    fn txpool_meta_round_trips() {
        let mut m = TxPoolMeta {
            max_used_block_id: h(1),
            last_failed_id: h(2),
            weight: 2_000,
            fee: 30_000_000,
            max_used_block_height: 500_000,
            last_failed_height: 0,
            receive_time: 1_700_000_000,
            last_relayed_time: 1_700_000_300,
            relayed: true,
            double_spend_seen: true,
            pruned: true,
            ..Default::default()
        };
        m.set_relay_method(RelayMethod::Stem);

        let e = m.encode();
        assert_eq!(e.len(), 192);
        assert_eq!(TxPoolMeta::decode(&e), Ok(m));
    }

    /// `specs/10` §4.9: the bitfield is allocated from the least significant
    /// bit up, in declaration order. Getting the order wrong swaps, say,
    /// `pruned` and `is_local`.
    #[test]
    fn the_bitfield_is_least_significant_bit_first() {
        type SetFlag = fn(&mut TxPoolMeta);
        let cases: [(SetFlag, u8); 5] = [
            (|m| m.double_spend_seen = true, 0b0000_0001),
            (|m| m.pruned = true, 0b0000_0010),
            (|m| m.is_local = true, 0b0000_0100),
            (|m| m.dandelionpp_stem = true, 0b0000_1000),
            (|m| m.is_forwarding = true, 0b0001_0000),
        ];
        for (set, expected) in cases {
            let mut m = TxPoolMeta::default();
            set(&mut m);
            assert_eq!(m.encode()[115], expected);
            assert_eq!(TxPoolMeta::decode(&m.encode()), Ok(m));
        }
    }

    /// Bytes 112 and 114 are whole `u8` fields, **not** bits in byte 115 —
    /// the state word that names the relay method spans two locations.
    #[test]
    fn kept_by_block_and_do_not_relay_are_whole_bytes() {
        let mut m = TxPoolMeta {
            kept_by_block: true,
            ..Default::default()
        };
        assert_eq!(m.encode()[112], 1);
        assert_eq!(m.encode()[115], 0, "not a bit in the bitfield");

        m = TxPoolMeta {
            do_not_relay: true,
            ..Default::default()
        };
        assert_eq!(m.encode()[114], 1);
        assert_eq!(m.encode()[115], 0);

        // `relayed` (113) is independent of the relay method.
        m = TxPoolMeta {
            relayed: true,
            ..Default::default()
        };
        assert_eq!(m.encode()[113], 1);
        assert_eq!(m.relay_method(), RelayMethod::Fluff);
    }

    /// `set_relay_method` clears all five flags first, so setting a second
    /// method does not leave the first set.
    #[test]
    fn setting_a_relay_method_clears_the_others() {
        let mut m = TxPoolMeta::default();
        for method in [
            RelayMethod::None,
            RelayMethod::Local,
            RelayMethod::Forward,
            RelayMethod::Stem,
            RelayMethod::Block,
            RelayMethod::Fluff,
        ] {
            m.set_relay_method(method);
            assert_eq!(m.relay_method(), method, "{method:?} did not round-trip");
        }

        m.set_relay_method(RelayMethod::Block);
        assert!(m.kept_by_block);
        m.set_relay_method(RelayMethod::Stem);
        assert!(!m.kept_by_block, "the previous method was not cleared");
        assert!(m.dandelionpp_stem);
    }

    /// The C builds a state word and switches on it, so two flags set at once
    /// hits the default arm rather than naming a method.
    #[test]
    fn two_flags_at_once_is_not_a_method() {
        let m = TxPoolMeta {
            kept_by_block: true,
            is_local: true,
            ..Default::default()
        };
        assert_eq!(m.relay_method(), RelayMethod::Fluff, "state word 0b101");
    }

    /// The 76-byte tail is preserved across a decode/encode cycle so a record
    /// written by a newer C++ build is not silently truncated.
    #[test]
    fn the_padding_tail_survives_a_round_trip() {
        let mut raw = [0u8; 192];
        for (i, b) in raw[116..192].iter_mut().enumerate() {
            *b = 0x80 | (i as u8);
        }
        // And the unused top bits of the bitfield.
        raw[115] = 0b1110_0000;

        let m = TxPoolMeta::decode(&raw).unwrap();
        assert_eq!(m.bf_padding, 0b111);
        assert_eq!(m.encode(), raw, "decode then encode must be the identity");
    }

    #[test]
    fn alt_block_round_trips_with_its_blob() {
        let a = AltBlock {
            height: 500_123,
            cumulative_weight: 1_234,
            cumulative_difficulty: (3u128 << 64) | 7,
            already_generated_coins: 99,
            blob: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let e = a.encode();
        assert_eq!(e.len(), 44, "40-byte header plus a 4-byte blob");
        assert_eq!(&e[16..24], &7u64.to_le_bytes(), "difficulty low word");
        assert_eq!(&e[24..32], &3u64.to_le_bytes(), "difficulty high word");
        assert_eq!(AltBlock::decode(&e), Ok(a));

        // The header alone is valid, with an empty blob.
        let bare = AltBlock::decode(&e[..40]).unwrap();
        assert!(bare.blob.is_empty());
    }

    #[test]
    fn a_short_alt_block_is_rejected() {
        assert_eq!(
            AltBlock::decode(&[0u8; 39]),
            Err(RecordError::AltBlockTooShort { found: 39 })
        );
    }

    /// `specs/10` §4.1: the NUL is part of the key. Writing seven bytes for
    /// `"version"` creates a new key rather than finding the existing one.
    #[test]
    fn property_keys_include_the_nul() {
        let k = property_key(PROPERTY_VERSION);
        assert_eq!(k, b"version\0");
        assert_eq!(k.len(), 8);
        assert_ne!(k.as_slice(), b"version".as_slice());

        assert_eq!(property_name(&k), Ok("version"));
        assert_eq!(
            property_name(b"version"),
            Err(RecordError::UnterminatedPropertyKey),
            "a key without the terminator is not one of ours"
        );
        assert_eq!(
            property_name(b""),
            Err(RecordError::UnterminatedPropertyKey)
        );

        assert_eq!(property_key(PROPERTY_PRUNING_SEED), b"pruning_seed\0");
        assert_eq!(property_key(PROPERTY_MAX_BLOCK_SIZE), b"max_block_size\0");
    }

    /// The `properties` table uses `compare_string`, and shorter-first means
    /// the NUL-terminated key sorts after its own prefix.
    #[test]
    fn property_keys_sort_with_compare_string() {
        use crate::comparator::compare_string;
        let v = property_key("version");
        let p = property_key("pruning_seed");
        assert_eq!(compare_string(&p, &v), std::cmp::Ordering::Less);
        assert_eq!(compare_string(&v, &v), std::cmp::Ordering::Equal);
    }
}
