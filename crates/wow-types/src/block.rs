//! Blocks: the header, the block, and every hash derived from them.
//!
//! `specs/05-blocks-and-transactions.md` §1, §3.5 and §4.

use wow_crypto::hash::{cn_fast_hash, tree_hash};
use wow_crypto::types::{Hash256, Signature};
use wow_serialize::binary::{BinSerialize, Reader, Writer};
use wow_serialize::error::{Error, Result};
use wow_serialize::varint::write_varint;

use crate::limits::{CRYPTONOTE_MAX_TX_PER_BLOCK, HF_VERSION_BLOCK_HEADER_MINER_SIG};
use crate::tx::Transaction;

/// Wownero's on-chain proposal vote. `0 = abstain, 1 = yes, 2 = no`.
///
/// `vote > 2` is a **consensus failure** from HF 18 (`specs/05` §1.1), but it
/// still parses — the header is a raw `u16` LE.
pub const MAX_VOTE: u16 = 2;

/// `block_header` (`specs/05` §1.1).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BlockHeader {
    pub major_version: u8,
    /// Doubles as the legacy hard-fork vote:
    /// `get_block_vote(b) = if minor_version == 0 { 1 } else { minor_version }`.
    pub minor_version: u8,
    pub timestamp: u64,
    pub prev_id: Hash256,
    /// A raw 4-byte LE integer, **not** a varint.
    pub nonce: u32,
    /// Present iff `major_version >= 18`. The Schnorr miner signature over
    /// `sig_data` (`specs/06` §4).
    pub signature: Signature,
    /// Present iff `major_version >= 18`. A raw 2-byte LE integer.
    pub vote: u16,
}

impl BlockHeader {
    /// `get_block_vote(b)` — the legacy hard-fork vote carried by
    /// `minor_version` (`specs/06` §1).
    pub fn hard_fork_vote(&self) -> u8 {
        if self.minor_version == 0 {
            1
        } else {
            self.minor_version
        }
    }

    /// Does this header carry `signature` and `vote` on the wire?
    pub fn has_miner_signature(&self) -> bool {
        self.major_version >= HF_VERSION_BLOCK_HEADER_MINER_SIG
    }

    pub fn write(&self, w: &mut Writer) {
        self.write_with_signature(w, true)
    }

    /// Serialize the header, optionally zeroing `signature`.
    ///
    /// `sig_data` zeroes only `signature` and keeps `vote` intact, so the
    /// signature commits to the vote while remaining computable
    /// (`specs/05` §4.4).
    fn write_with_signature(&self, w: &mut Writer, include_signature: bool) {
        w.write_varint(u64::from(self.major_version));
        w.write_varint(u64::from(self.minor_version));
        w.write_varint(self.timestamp);
        w.write_bytes(&self.prev_id);
        w.write_u32_le(self.nonce);
        if self.has_miner_signature() {
            if include_signature {
                w.write_bytes(&self.signature.to_bytes());
            } else {
                w.write_bytes(&[0u8; Signature::LEN]);
            }
            w.write_u16_le(self.vote);
        }
    }

    pub fn read(r: &mut Reader<'_>) -> Result<BlockHeader> {
        // `VARINT_FIELD` on a uint8_t reads with bits = 8.
        let major_version = r.read_varint_u8()?;
        let minor_version = r.read_varint_u8()?;
        let timestamp = r.read_varint()?;
        let prev_id = r.read_array::<32>()?;
        let nonce = r.read_u32_le()?;

        let mut signature = Signature::ZERO;
        let mut vote = 0u16;
        // The reader MUST branch on the *just-decoded* major_version, not on an
        // out-of-band expectation (`specs/04` §1.4).
        if major_version >= HF_VERSION_BLOCK_HEADER_MINER_SIG {
            signature = Signature::from_bytes(&r.read_array::<64>()?);
            vote = r.read_u16_le()?;
        }

        Ok(BlockHeader {
            major_version,
            minor_version,
            timestamp,
            prev_id,
            nonce,
            signature,
            vote,
        })
    }
}

/// A block (`specs/05` §1.2).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Block {
    pub header: BlockHeader,
    pub miner_tx: Transaction,
    pub tx_hashes: Vec<Hash256>,
}

impl core::ops::Deref for Block {
    type Target = BlockHeader;
    fn deref(&self) -> &BlockHeader {
        &self.header
    }
}

impl Block {
    pub fn write(&self, w: &mut Writer) {
        self.header.write(w);
        self.miner_tx.write(w);
        w.write_varint(self.tx_hashes.len() as u64);
        for h in &self.tx_hashes {
            w.write_bytes(h);
        }
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Block> {
        let header = BlockHeader::read(r)?;
        let miner_tx = Transaction::read(r)?;

        let n = r.read_varint()?;
        let n = usize::try_from(n).map_err(|_| Error::LimitExceeded("tx_hashes"))?;
        if n > CRYPTONOTE_MAX_TX_PER_BLOCK {
            return Err(Error::LimitExceeded(
                "tx_hashes > CRYPTONOTE_MAX_TX_PER_BLOCK",
            ));
        }
        // 32 bytes each, so the remaining input bounds the count.
        if n > r.remaining() / 32 {
            return Err(Error::UnexpectedEof);
        }
        let mut tx_hashes = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            tx_hashes.push(r.read_array::<32>()?);
        }

        Ok(Block {
            header,
            miner_tx,
            tx_hashes,
        })
    }

    /// Parse a block blob. Mirrors `parse_and_validate_block_from_blob`, which
    /// does **not** require the whole blob to be consumed.
    pub fn from_blob(blob: &[u8]) -> Result<Block> {
        let mut r = Reader::new(blob);
        Block::read(&mut r)
    }

    pub fn to_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.into_vec()
    }

    /// `get_tx_tree_hash(block)` — the transaction Merkle root.
    ///
    /// The leaf list is `[miner_tx_hash] ++ tx_hashes` (`specs/05` §3.5).
    pub fn tx_tree_hash(&self) -> Option<Hash256> {
        let mut leaves = Vec::with_capacity(self.tx_hashes.len() + 1);
        leaves.push(crate::hashes::transaction_hash(&self.miner_tx)?);
        leaves.extend_from_slice(&self.tx_hashes);
        tree_hash(&leaves)
    }

    /// The **block hashing blob**, `get_block_hashing_blob` (`specs/05` §4.1):
    ///
    /// ```text
    /// serialize(block_header) || tx_tree_root || varint(tx_hashes.len() + 1)
    /// ```
    ///
    /// This is the **proof-of-work input**, fed to the PoW function verbatim
    /// (`get_block_longhash` passes it straight through).
    ///
    /// It is *not*, by itself, the block-id preimage — see [`Block::block_id`].
    pub fn hashing_blob(&self) -> Option<Vec<u8>> {
        self.hashing_blob_inner(true)
    }

    fn hashing_blob_inner(&self, include_signature: bool) -> Option<Vec<u8>> {
        let root = self.tx_tree_hash()?;
        let mut w = Writer::with_capacity(128);
        self.header.write_with_signature(&mut w, include_signature);
        w.write_bytes(&root);
        // `+ 1` for the coinbase.
        w.write_varint(self.tx_hashes.len() as u64 + 1);
        Some(w.into_vec())
    }

    /// The block id.
    ///
    /// ```text
    /// block_id = cn_fast_hash( varint(hashing_blob.len()) || hashing_blob )
    /// ```
    ///
    /// # The length prefix
    ///
    /// `specs/05` §4.2 says `block_id = cn_fast_hash(block_hashing_blob)`, and
    /// `specs/05` §4.3 and `specs/03` §1 both say the block id and the PoW hash
    /// take the **same** blob and "differ only in the hash function". That is
    /// not what the reference does, and following it literally produces a wrong
    /// id for every block on the chain.
    ///
    /// `calculate_block_hash` reads:
    ///
    /// ```cpp
    /// bool hash_result = get_object_hash(get_block_hashing_blob(b), res);
    /// ```
    ///
    /// and `get_object_hash` is a **template**:
    ///
    /// ```cpp
    /// template<class t_object>
    /// bool get_object_hash(const t_object& o, crypto::hash& res)
    /// {
    ///   get_blob_hash(t_serializable_object_to_blob(o), res);
    ///   return true;
    /// }
    /// ```
    ///
    /// Instantiated with `t_object = blobdata` (a `std::string`), so the blob is
    /// run through the binary archive **a second time** — and a `std::string`
    /// serializes as `varint(len) || bytes` (`specs/04` §1.2). The PoW path
    /// (`get_block_longhash`) and the miner-signature path (`get_sig_data`)
    /// both hash the blob directly instead, with no prefix.
    ///
    /// The prefix is not always one byte: an HF 18+ header is 66 bytes longer,
    /// which pushes the blob past 127 bytes and the varint to two bytes.
    ///
    /// **Not** the hash of the full block blob either.
    pub fn block_id(&self) -> Option<Hash256> {
        let blob = self.hashing_blob()?;
        Some(cn_fast_hash(&length_prefixed(&blob)))
    }

    /// `sig_data` — the message the HF 18 miner signature covers
    /// (`specs/05` §4.4).
    ///
    /// The same blob as [`Block::hashing_blob`] but with `signature` zeroed and
    /// `vote` left intact.
    ///
    /// `get_sig_data` calls `crypto::cn_fast_hash(blob.data(), blob.size(), …)`
    /// directly, so — unlike [`Block::block_id`] — there is **no** length
    /// prefix here.
    pub fn sig_data(&self) -> Option<Hash256> {
        if !self.header.has_miner_signature() {
            return None;
        }
        Some(cn_fast_hash(&self.hashing_blob_inner(false)?))
    }

    /// The number of transactions in the block, coinbase included.
    pub fn tx_count(&self) -> usize {
        self.tx_hashes.len() + 1
    }
}

impl BinSerialize for Block {
    fn write(&self, w: &mut Writer) {
        Block::write(self, w)
    }
}

impl BinSerialize for BlockHeader {
    fn write(&self, w: &mut Writer) {
        BlockHeader::write(self, w)
    }
}

/// Build a hashing blob from parts, for callers that already have the root.
///
/// Exposed so the miner can vary the nonce without rebuilding the Merkle tree.
pub fn hashing_blob_from_parts(header: &BlockHeader, root: &Hash256, tx_count: usize) -> Vec<u8> {
    let mut w = Writer::with_capacity(128);
    header.write(&mut w);
    w.write_bytes(root);
    let mut v = Vec::new();
    write_varint(&mut v, tx_count as u64);
    w.write_bytes(&v);
    w.into_vec()
}

/// `t_serializable_object_to_blob` applied to a `std::string`: `varint(len)`
/// followed by the bytes (`specs/04` §1.2).
///
/// Only the block id needs this, and only because `get_object_hash` is a
/// template that gets instantiated on the already-serialized blob. See
/// [`Block::block_id`].
fn length_prefixed(blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blob.len() + 2);
    write_varint(&mut out, blob.len() as u64);
    out.extend_from_slice(blob);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wow_crypto::hex;

    /// Mainnet genesis, taken from a synced node. Hard-coded so the block-id
    /// rule stays pinned even without the generated corpus.
    const GENESIS_BLOB: &str = "070700000000000000000000000000000000000000000000000000000000000000000046000000013c01ff0001ffffffffff1f029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121012a1a936be5d91c01ee876e38c13fab0ee11cbe86011a2bf7740fb5ebd39d267d00";
    const GENESIS_ID: &str = "a3fd635dd5cb55700317783469ba749b5259f0eeac2420ab2c27eb3ff5ffdc5c";
    const GENESIS_MINER: &str = "14b2e27d20eb3f7678e3e48d479856a44b5db84a6d9ba23dec67158f27374842";

    /// The block id's preimage carries a varint length prefix that the PoW
    /// input does not (see [`Block::block_id`]). Hashing the bare blob — which
    /// is what `specs/05` §4.2 says to do — gives this instead, and it is wrong
    /// for every block on the chain.
    const GENESIS_ID_WITHOUT_PREFIX: &str =
        "b07b20e713b10439494de0a03b55c3a2b91a8130c73b506c45b8c838c4fb5d93";

    fn genesis() -> (Block, Vec<u8>) {
        let blob = hex::decode(GENESIS_BLOB).expect("genesis hex");
        (Block::from_blob(&blob).expect("parse genesis"), blob)
    }

    #[test]
    fn mainnet_genesis_hashes() {
        let (b, blob) = genesis();

        // Round-trip first: everything below is meaningless otherwise.
        let mut w = Writer::new();
        b.write(&mut w);
        assert_eq!(w.as_slice(), &blob[..]);

        assert_eq!(b.header.major_version, 7);
        assert_eq!(b.header.minor_version, 7);
        assert_eq!(b.header.timestamp, 0);
        assert_eq!(b.header.prev_id, [0u8; 32]);
        assert_eq!(b.header.nonce, 70, "GENESIS_NONCE, mainnet");
        assert!(b.tx_hashes.is_empty());
        assert!(!b.header.has_miner_signature());

        let mut mw = Writer::new();
        b.miner_tx.write(&mut mw);
        let miner_blob = mw.into_vec();
        let mh = crate::hashes::transaction_hash_from_blob(&b.miner_tx, &miner_blob).unwrap();
        assert_eq!(hex::encode(&mh), GENESIS_MINER);

        assert_eq!(hex::encode(&b.block_id().unwrap()), GENESIS_ID);
    }

    /// The length prefix is the whole difference, and it deserves a test of its
    /// own: this is the assertion that catches a literal reading of
    /// `specs/05` §4.2.
    #[test]
    fn block_id_prefixes_the_hashing_blob_with_its_length() {
        let (b, _) = genesis();
        let blob = b.hashing_blob().unwrap();

        // The PoW input is the bare blob...
        assert_eq!(blob.len(), 72);
        // ...and hashing it directly is NOT the block id.
        assert_eq!(
            hex::encode(&wow_crypto::cn_fast_hash(&blob)),
            GENESIS_ID_WITHOUT_PREFIX
        );
        assert_ne!(GENESIS_ID_WITHOUT_PREFIX, GENESIS_ID);

        // The block id prefixes it with varint(72) = 0x48.
        let prefixed = length_prefixed(&blob);
        assert_eq!(prefixed[0], 72);
        assert_eq!(&prefixed[1..], &blob[..]);
        assert_eq!(
            hex::encode(&wow_crypto::cn_fast_hash(&prefixed)),
            GENESIS_ID
        );
        assert_eq!(hex::encode(&b.block_id().unwrap()), GENESIS_ID);
    }

    /// The prefix is not always one byte. An HF 18+ header carries 64 bytes of
    /// signature plus a 2-byte vote, which pushes the hashing blob past 127 and
    /// the varint to two bytes.
    #[test]
    fn the_length_prefix_can_be_two_bytes() {
        let (mut b, _) = genesis();
        let short = b.hashing_blob().unwrap();
        assert!(short.len() < 128);
        assert_eq!(length_prefixed(&short).len(), short.len() + 1);

        b.header.major_version = 18;
        b.header.vote = 1;
        let long = b.hashing_blob().unwrap();
        assert_eq!(long.len(), short.len() + 64 + 2, "signature + vote");
        assert!(long.len() > 127, "len = {}", long.len());
        assert_eq!(
            length_prefixed(&long).len(),
            long.len() + 2,
            "a two-byte varint"
        );

        // Truncating the prefix to one byte would give a different, wrong id.
        let mut one_byte = vec![long.len() as u8];
        one_byte.extend_from_slice(&long);
        assert_ne!(b.block_id().unwrap(), wow_crypto::cn_fast_hash(&one_byte));
    }

    /// `sig_data` hashes the blob **without** the length prefix, unlike the
    /// block id — `get_sig_data` calls `cn_fast_hash` directly.
    #[test]
    fn sig_data_has_no_length_prefix() {
        let (mut b, _) = genesis();
        assert_eq!(b.sig_data(), None, "undefined below HF 18");

        b.header.major_version = 18;
        b.header.vote = 2;
        b.header.signature = wow_crypto::types::Signature {
            c: wow_crypto::types::EcScalar([0x11; 32]),
            r: wow_crypto::types::EcScalar([0x22; 32]),
        };

        let zeroed = b.hashing_blob_inner(false).unwrap();
        assert_eq!(b.sig_data().unwrap(), wow_crypto::cn_fast_hash(&zeroed));
        assert_ne!(
            b.sig_data().unwrap(),
            wow_crypto::cn_fast_hash(&length_prefixed(&zeroed)),
            "sig_data must not carry the block id's length prefix"
        );

        // Zeroing the signature keeps the vote, so flipping the vote changes
        // sig_data. That is what makes the signature commit to the vote.
        let with_vote_2 = b.sig_data().unwrap();
        b.header.vote = 1;
        assert_ne!(b.sig_data().unwrap(), with_vote_2);
    }

    /// The PoW input is the bare hashing blob (`get_block_longhash` passes it
    /// through untouched): header, then the 32-byte root, then
    /// `varint(tx_count + 1)`.
    #[test]
    fn pow_input_is_the_bare_hashing_blob() {
        let (b, _) = genesis();
        let blob = b.hashing_blob().unwrap();
        let mut hw = Writer::new();
        b.header.write(&mut hw);
        assert_eq!(blob.len(), hw.len() + 32 + 1);
        assert_eq!(&blob[..hw.len()], hw.as_slice());
        assert_eq!(
            &blob[hw.len()..hw.len() + 32],
            &b.tx_tree_hash().unwrap()[..]
        );
        assert_eq!(*blob.last().unwrap(), 1u8, "varint(0 + 1)");
    }

    #[test]
    fn tx_count_includes_the_coinbase() {
        let (mut b, _) = genesis();
        assert_eq!(b.tx_count(), 1);
        b.tx_hashes = vec![[1u8; 32], [2u8; 32]];
        assert_eq!(b.tx_count(), 3);
        assert_eq!(*b.hashing_blob().unwrap().last().unwrap(), 3);
    }

    /// `get_block_vote(b) = if minor_version == 0 { 1 } else { minor_version }`
    /// (`specs/06` §1).
    #[test]
    fn hard_fork_vote_treats_zero_as_one() {
        let mut h = BlockHeader {
            minor_version: 0,
            ..Default::default()
        };
        assert_eq!(h.hard_fork_vote(), 1, "minor_version 0 votes for 1");
        h.minor_version = 7;
        assert_eq!(h.hard_fork_vote(), 7);
        h.minor_version = 20;
        assert_eq!(h.hard_fork_vote(), 20);
    }

    #[test]
    fn a_block_with_too_many_tx_hashes_is_rejected() {
        let (b, _) = genesis();
        let mut w = Writer::new();
        b.header.write(&mut w);
        b.miner_tx.write(&mut w);
        w.write_varint(CRYPTONOTE_MAX_TX_PER_BLOCK as u64 + 1);
        assert!(matches!(
            Block::from_blob(w.as_slice()),
            Err(Error::LimitExceeded(_)) | Err(Error::UnexpectedEof)
        ));
    }

    /// Truncating the genesis blob is the cleanest live demonstration of the
    /// varint EOF tolerance (`wow_serialize::varint::read_varint_bits`).
    ///
    /// The block's final field is `varint(tx_hashes.len())`, which for genesis
    /// is the single byte `0x00`. Dropping exactly that byte leaves a blob the
    /// reference still parses — as a block with zero tx hashes, i.e. the same
    /// block. Every shorter cut falls inside a fixed-size field and fails.
    ///
    /// So the property to assert is that the *only* truncation that reproduces
    /// the block is the one-byte one, not that none does.
    #[test]
    fn only_dropping_the_trailing_varint_reparses_as_the_whole_block() {
        let (b, blob) = genesis();
        assert_eq!(*blob.last().unwrap(), 0x00, "varint(0) tx hashes");

        let mut identical = Vec::new();
        for cut in 0..blob.len() {
            if let Ok(t) = Block::from_blob(&blob[..cut]) {
                if t == b {
                    identical.push(cut);
                }
            }
        }
        assert_eq!(
            identical,
            vec![blob.len() - 1],
            "only the missing trailing varint should reparse identically"
        );
    }

    /// The header fields are reachable through `Deref`.
    #[test]
    fn deref_exposes_the_header() {
        let (b, _) = genesis();
        assert_eq!(b.major_version, 7);
        assert_eq!(b.nonce, 70);
    }
}
