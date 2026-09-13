//! The genesis block, per network.
//!
//! `generate_genesis_block` (`src/cryptonote_core/cryptonote_tx_utils.cpp`),
//! driven by `GENESIS_TX` and `GENESIS_NONCE` from `cryptonote_config.h`.
//!
//! # Why a node needs this
//!
//! `specs/10` §7: "The C++ stores nothing identifying the network in
//! `properties`, so infer it from the **genesis block hash** in `blocks[0]` and
//! refuse a mismatch. (This is a real hazard: a testnet and a mainnet
//! `data.mdb` are structurally identical.)"
//!
//! Pointing a mainnet node at a testnet database is otherwise silent — the
//! schema matches, the tip reads back, and the chain simply disagrees with
//! everyone.

use wow_types::{Block, Network};

/// `GENESIS_TX` — the coinbase blob, as hex, for each network.
const MAINNET_GENESIS_TX: &str = "013c01ff0001ffffffffff1f029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121012a1a936be5d91c01ee876e38c13fab0ee11cbe86011a2bf7740fb5ebd39d267d";
const TESTNET_GENESIS_TX: &str = "013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a28e9d0bc890d1";
const STAGENET_GENESIS_TX: &str = "013c01ff0001ffffffffffff0302df5d56da0c7d643ddd1ce61901c7bdc5fb1738bfe39fbe69c28a3a7032729c0f2101168d0c4ca86fb55a4cf6a36d31431be1c53a3bd7411bb24e8832410289fa6f3b";

/// `GENESIS_NONCE`.
const MAINNET_GENESIS_NONCE: u32 = 70;
const TESTNET_GENESIS_NONCE: u32 = 10_001;
const STAGENET_GENESIS_NONCE: u32 = 10_002;

/// `CURRENT_BLOCK_MAJOR_VERSION` / `..._MINOR_VERSION` as the genesis block
/// carries them.
///
/// Both are **7** on Wownero, not 1 — which is why
/// `HardFork::required_version(0)` has to floor at the table's first entry
/// rather than at `ORIGINAL_VERSION` (`docs/spec-deltas.md` §12).
const GENESIS_MAJOR_VERSION: u8 = 7;
const GENESIS_MINOR_VERSION: u8 = 7;

/// The genesis coinbase and nonce for a network.
///
/// `Fakechain` uses mainnet's, matching `Network::config()`.
fn parts(network: Network) -> (&'static str, u32) {
    match network.config() {
        Network::Testnet => (TESTNET_GENESIS_TX, TESTNET_GENESIS_NONCE),
        Network::Stagenet => (STAGENET_GENESIS_TX, STAGENET_GENESIS_NONCE),
        _ => (MAINNET_GENESIS_TX, MAINNET_GENESIS_NONCE),
    }
}

/// The genesis block's wire blob.
///
/// ```text
/// major_version  varint  7
/// minor_version  varint  7
/// timestamp      varint  0
/// prev_id        [32]    zero
/// nonce          u32 LE  GENESIS_NONCE
/// miner_tx               GENESIS_TX
/// tx_hashes      varint  0
/// ```
///
/// The nonce is a **raw 4-byte little-endian integer**, not a varint
/// (`specs/05` §1.1) — the one field in the header that is not varint-encoded.
pub fn genesis_blob(network: Network) -> Vec<u8> {
    let (tx_hex, nonce) = parts(network);
    let tx = wow_crypto::hex::decode(tx_hex).expect("GENESIS_TX is valid hex");

    let mut out = Vec::with_capacity(tx.len() + 48);
    out.push(GENESIS_MAJOR_VERSION);
    out.push(GENESIS_MINOR_VERSION);
    out.push(0); // timestamp
    out.extend_from_slice(&[0u8; 32]); // prev_id
    out.extend_from_slice(&nonce.to_le_bytes());
    out.extend_from_slice(&tx);
    out.push(0); // no transactions
    out
}

/// The genesis block.
pub fn genesis_block(network: Network) -> Block {
    Block::from_blob(&genesis_blob(network)).expect("the genesis blob parses")
}

/// The genesis block's id — what identifies a `data.mdb`'s network.
pub fn genesis_id(network: Network) -> wow_crypto::types::Hash256 {
    genesis_block(network)
        .block_id()
        .expect("the genesis block hashes")
}

/// Which network a `data.mdb` belongs to, from its `blocks[0]` hash.
///
/// `None` when the hash matches no network, which is the case worth refusing
/// loudly (`specs/10` §7).
pub fn network_from_genesis(hash: &wow_crypto::types::Hash256) -> Option<Network> {
    [Network::Mainnet, Network::Testnet, Network::Stagenet]
        .into_iter()
        .find(|n| &genesis_id(*n) == hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wow_crypto::hex;

    /// The mainnet genesis id, from a synced node.
    const MAINNET_ID: &str = "a3fd635dd5cb55700317783469ba749b5259f0eeac2420ab2c27eb3ff5ffdc5c";

    /// The blob this builds must be exactly what the chain stores, byte for
    /// byte — it is `blocks[0]`.
    #[test]
    fn the_mainnet_genesis_blob_is_the_real_one() {
        const BLOB: &str = "070700000000000000000000000000000000000000000000000000000000000000000046000000013c01ff0001ffffffffff1f029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121012a1a936be5d91c01ee876e38c13fab0ee11cbe86011a2bf7740fb5ebd39d267d00";
        assert_eq!(hex::encode(&genesis_blob(Network::Mainnet)), BLOB);
    }

    #[test]
    fn the_mainnet_genesis_id_matches_the_chain() {
        assert_eq!(hex::encode(&genesis_id(Network::Mainnet)), MAINNET_ID);
    }

    /// Genesis carries version **7**, not 1 — the fact
    /// `docs/spec-deltas.md` §12 turns on.
    #[test]
    fn genesis_carries_version_seven() {
        for n in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            let b = genesis_block(n);
            assert_eq!(b.header.major_version, 7, "{n:?}");
            assert_eq!(b.header.minor_version, 7, "{n:?}");
            assert_eq!(b.header.timestamp, 0);
            assert_eq!(b.header.prev_id, [0u8; 32]);
            assert!(b.tx_hashes.is_empty());
        }
    }

    /// The nonce is a raw little-endian `u32`, and each network has its own.
    #[test]
    fn each_network_has_its_own_nonce() {
        assert_eq!(genesis_block(Network::Mainnet).header.nonce, 70);
        assert_eq!(genesis_block(Network::Testnet).header.nonce, 10_001);
        assert_eq!(genesis_block(Network::Stagenet).header.nonce, 10_002);

        // Raw LE, not a varint: byte 35 onward is the nonce.
        let blob = genesis_blob(Network::Testnet);
        assert_eq!(&blob[35..39], &10_001u32.to_le_bytes());
    }

    /// **The check `specs/10` §7 requires.** The three networks must have
    /// distinct genesis hashes, or a database could not be told apart.
    #[test]
    fn the_networks_have_distinct_genesis_hashes() {
        let m = genesis_id(Network::Mainnet);
        let t = genesis_id(Network::Testnet);
        let s = genesis_id(Network::Stagenet);

        assert_ne!(m, t);
        assert_ne!(m, s);
        assert_ne!(t, s);

        assert_eq!(network_from_genesis(&m), Some(Network::Mainnet));
        assert_eq!(network_from_genesis(&t), Some(Network::Testnet));
        assert_eq!(network_from_genesis(&s), Some(Network::Stagenet));
    }

    /// An unknown hash is `None`, not a guess. Pointing a node at someone
    /// else's database should stop, not proceed.
    #[test]
    fn an_unknown_genesis_is_not_guessed() {
        assert_eq!(network_from_genesis(&[0u8; 32]), None);
        assert_eq!(network_from_genesis(&[0xff; 32]), None);
    }

    /// Fakechain shares mainnet's genesis, matching `Network::config()`.
    #[test]
    fn fakechain_uses_mainnets_genesis() {
        assert_eq!(genesis_id(Network::Fakechain), genesis_id(Network::Mainnet));
    }

    /// The coinbase pays the premine, and the amount differs per network — the
    /// `ffffffffff1f` vs `ffffffffffff03` in the two blobs.
    #[test]
    fn the_genesis_coinbase_differs_between_networks() {
        let m = genesis_block(Network::Mainnet);
        let t = genesis_block(Network::Testnet);
        assert_ne!(
            m.miner_tx.prefix.vout[0].amount,
            t.miner_tx.prefix.vout[0].amount
        );
        assert!(m.miner_tx.prefix.vout[0].amount > 0);
    }
}
