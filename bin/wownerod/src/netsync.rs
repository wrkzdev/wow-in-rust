//! Syncing this node's chain from a peer (`specs/08` §5).
//!
//! The bridge between `wow-p2p`, which moves bytes, and `wow-core`, which
//! decides what is valid. Keeping the two apart is deliberate: a protocol fault
//! and a consensus rejection are different problems with different responses,
//! and a layer that conflated them would blame the peer for our own bug or
//! the other way round.

use std::sync::Arc;

use wow_core::chain::Blockchain;
use wow_crypto::types::Hash256;
use wow_p2p::sync::{self, ChainTip};
use wow_p2p::{CoreSyncData, NodeIdentity, Peer};
use wow_storage::db::BlockchainDb;
use wow_storage::lmdb::LmdbDb;
use wow_types::block::Block;
use wow_types::tx::Transaction;
use wow_types::Network;

/// The proof-of-work this node can check.
///
/// `specs/03` §2: RandomWOW from major version 13, CryptoNight variant 1 at
/// versions 7 and 8, variants 2 and 4 at 9-12. The middle range is a gap, and
/// outside the trusted zone it is a **refusal**, not a skip -- a node that
/// waved through a block it could not verify would be trusting whoever sent it,
/// which is the one thing a node exists not to do.
///
/// Inside the trusted zone the proof is not computed at all, so the gap never
/// comes up: every height needing variant 2 or 4 is below the last checkpoint.
/// That is a statement about today's checkpoint list, not about the variants
/// being unnecessary -- a chain replayed with checkpoints disabled still needs
/// them, and so does anyone who wants to know the chain is what it claims.
struct ChainPow {
    seeds: wow_randomwow::vm::SeedCache,
    /// Below this height the proof is not computed, matching the reference's
    /// `fast_check`. See [`LocalChain::new`].
    trusted_below: u64,
}

impl ChainPow {
    fn new(trusted_below: u64) -> ChainPow {
        ChainPow {
            seeds: wow_randomwow::vm::SeedCache::new(wow_randomwow::vm::verify_flags()),
            trusted_below,
        }
    }
}

impl wow_core::pow::PowVerifier for ChainPow {
    /// `specs/06` §2 step 6 allows the proof to be skipped "unless a
    /// precomputed hash covers this height". Below the last checkpoint, one
    /// does. This is also what makes the CryptoNight v2/v4 gap survivable: the
    /// heights that need them are all inside the checkpointed range.
    fn may_skip(&self, height: u64) -> bool {
        height < self.trusted_below
    }

    fn pow_hash(
        &self,
        height: u64,
        major_version: u8,
        hashing_blob: &[u8],
        seed_hash: &Hash256,
    ) -> Result<Hash256, wow_core::pow::PowError> {
        // `RX_BLOCK_VERSION` is 13 (`specs/03` §3).
        if major_version >= 13 {
            let cache = self
                .seeds
                .get(seed_hash)
                .map_err(|e| wow_core::pow::PowError::RandomWow(e.to_string()))?;
            // Light mode: a cache rather than the 2 GiB dataset. Verification
            // is one hash per block, where mining is millions, so the dataset's
            // build cost would dwarf what it saves.
            let mut vm = wow_randomwow::vm::Vm::light(wow_randomwow::vm::verify_flags(), cache)
                .map_err(|e| wow_core::pow::PowError::RandomWow(e.to_string()))?;
            return Ok(vm.hash(hashing_blob));
        }

        match major_version {
            7 | 8 => wow_crypto::cn::cn_slow_hash_v1(hashing_blob)
                .map_err(|e| wow_core::pow::PowError::RandomWow(e.to_string())),
            v => Err(wow_core::pow::PowError::CryptoNightNotImplemented {
                height,
                variant: if v >= 11 { "variant 4" } else { "variant 2" },
            }),
        }
    }
}

/// The local chain, as the sync loop sees it.
pub struct LocalChain {
    chain: Blockchain<LmdbDb>,
    db: Arc<LmdbDb>,
    /// Block hashes from genesis, for the short history.
    ///
    /// A few megabytes for this chain, and it saves a database read per entry
    /// on every request — which happens once per batch, so it is not the cost
    /// that matters; not having to ask the database mid-sync is.
    hashes: Vec<Hash256>,
}

impl LocalChain {
    /// Open the chain, trusting everything at or below the last hard-coded
    /// checkpoint.
    ///
    /// This is the reference's own position, reached by a different route.
    /// `PER_BLOCK_CHECKPOINT` has the C++ skip proof-of-work and
    /// `check_tx_inputs` for every block covered by its embedded `blocks.dat`,
    /// and it is not optional: Wownero mainnet contains blocks that today's
    /// rules reject, so a node that verified from genesis could not sync at
    /// all. `docs/spec-deltas.md` §23 has the evidence, down to the block.
    ///
    /// This node has 39 checkpoints rather than a hash per block, so between
    /// two of them it is trusting the `prev_id` chain and finds a forgery at
    /// the next checkpoint rather than immediately. Above the last checkpoint
    /// -- the range where a reorg is still possible and where this node's
    /// answers actually matter -- every rule is enforced.
    pub fn new(db: Arc<LmdbDb>, network: Network) -> Result<LocalChain, String> {
        let checkpoints = wow_consensus::checkpoints::Checkpoints::new(network);
        // `last_height` is the last checkpointed block, and it is itself
        // verified against the checkpoint, so the trusted range ends *after*
        // it. A chain with no checkpoints verifies everything.
        let trusted_below = checkpoints.last_height().map(|h| h + 1).unwrap_or(0);

        let mut chain =
            Blockchain::new(db.clone(), Arc::new(ChainPow::new(trusted_below)), network)
                .map_err(|e| format!("cannot open the chain: {e:?}"))?;
        chain.trust_below(trusted_below);

        let height = db.height();
        let mut hashes = Vec::with_capacity(height as usize);
        for h in 0..height {
            hashes.push(
                db.get_block_hash(h)
                    .map_err(|e| format!("cannot read the block at height {h}: {e}"))?,
            );
        }

        Ok(LocalChain { chain, db, hashes })
    }

    /// The height below which this node is trusting checkpoints rather than
    /// verifying. See [`LocalChain::new`].
    pub fn trusted_below(&self) -> u64 {
        self.chain.trusted_below()
    }

    /// What this node tells a peer about its chain.
    pub fn sync_data(&self, network: Network) -> CoreSyncData {
        let height = self.height();
        CoreSyncData {
            current_height: height,
            cumulative_difficulty: self.cumulative_difficulty(),
            top_id: self.top_id(),
            top_version: wow_consensus::hardfork::HardFork::new(network)
                .required_version(height.saturating_sub(1)),
            pruning_seed: 0,
        }
    }
}

impl ChainTip for LocalChain {
    fn height(&self) -> u64 {
        self.db.height()
    }

    fn cumulative_difficulty(&self) -> u128 {
        let height = self.height();
        if height == 0 {
            return 0;
        }
        self.db
            .get_block_cumulative_difficulty(height - 1)
            .unwrap_or(0)
    }

    fn top_id(&self) -> Hash256 {
        let height = self.height();
        if height == 0 {
            return wow_crypto::NULL_HASH;
        }
        self.db
            .get_block_hash(height - 1)
            .unwrap_or(wow_crypto::NULL_HASH)
    }

    fn short_history(&self) -> Vec<Hash256> {
        sync::short_history(&self.hashes)
    }

    fn have_block(&self, id: &Hash256) -> bool {
        self.db.block_exists(id).unwrap_or(false)
    }

    fn add_block(&mut self, blob: &[u8], txs: &[Vec<u8>]) -> Result<(), String> {
        let block = Block::from_blob(blob).map_err(|e| format!("the block does not parse: {e}"))?;

        // `specs/08` §5.5: the transactions must match the block's `tx_hashes`,
        // in order. A peer that sends a different set is a protocol violation,
        // and checking here rather than trusting it is what stops a peer
        // choosing which transactions this node validates.
        if txs.len() != block.tx_hashes.len() {
            return Err(format!(
                "the block names {} transactions and {} came with it",
                block.tx_hashes.len(),
                txs.len()
            ));
        }
        let mut parsed = Vec::with_capacity(txs.len());
        for (i, blob) in txs.iter().enumerate() {
            let tx = Transaction::from_blob(blob)
                .map_err(|e| format!("transaction {i} does not parse: {e}"))?;
            let id = wow_types::hashes::transaction_hash_from_blob(&tx, blob)
                .ok_or_else(|| format!("transaction {i} has no hash"))?;
            if id != block.tx_hashes[i] {
                return Err(format!(
                    "transaction {i} is {} where the block names {}",
                    wow_crypto::hex::encode(&id),
                    wow_crypto::hex::encode(&block.tx_hashes[i])
                ));
            }
            parsed.push((tx, blob.clone()));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.chain
            .add_block(&block, blob, &parsed, now)
            .map_err(|e| format!("{e:?}"))?;

        if let Some(id) = block.block_id() {
            self.hashes.push(id);
        }
        Ok(())
    }
}

/// Sync from one peer, printing progress.
pub fn run(db: LmdbDb, network: Network, address: &str, max_batches: usize) -> Result<(), String> {
    let db = Arc::new(db);
    let mut chain = LocalChain::new(db, network)?;

    // A peer id that is not the same twice, so a node does not look like a
    // self-connection to a peer it reconnects to.
    let peer_id = {
        let mut rng = wow_wallet_entropy()?;
        let mut b = [0u8; 8];
        rng.fill(&mut b);
        u64::from_le_bytes(b)
    };

    let identity = NodeIdentity {
        network,
        peer_id,
        // Zero: this node does not accept inbound connections, and saying so
        // keeps it out of peer lists it cannot honour (`specs/08` §3.3).
        my_port: 0,
    };

    let ours = chain.sync_data(network);
    println!(
        "Local chain: height {}, cumulative difficulty {}",
        ours.current_height, ours.cumulative_difficulty
    );
    // Say plainly what is and is not being verified. The reference does the
    // same thing silently, and "synced" reads as "verified" to almost everyone.
    let trusted = chain.trusted_below();
    if trusted > 0 {
        println!(
            "Blocks below {trusted} are covered by hard-coded checkpoints: their proof of work
             and transaction rules are not re-checked, which is what the C++ node also does
             (docs/spec-deltas.md §23). Everything from {trusted} up is fully verified."
        );
    }
    println!("Connecting to {address}...");

    let mut peer = Peer::connect(address, &identity, &ours)
        .map_err(|e| format!("cannot handshake with {address}: {e}"))?;

    println!(
        "Connected to peer {:016x} at {}: height {}, top version {}",
        peer.peer_id,
        peer.address(),
        peer.sync.current_height,
        peer.sync.top_version
    );
    if !peer.known_peers.is_empty() {
        println!("It told us about {} other peers.", peer.known_peers.len());
    }

    let start = chain.height();
    let began = std::time::Instant::now();
    let progress = sync::sync_from(&mut chain, &mut peer, max_batches, |p| {
        let secs = began.elapsed().as_secs_f64().max(0.001);
        println!(
            "  height {} / {} ({} added, {:.0} blocks/s; {:.0}% waiting on the peer, {:.0}% verifying)",
            start + p.blocks_added,
            p.peer_height,
            p.blocks_added,
            p.blocks_added as f64 / secs,
            100.0 * p.waiting.as_secs_f64() / secs,
            100.0 * p.applying.as_secs_f64() / secs,
        );
    })
    .map_err(|e| e.to_string())?;

    println!(
        "Added {} block(s); now at height {}.",
        progress.blocks_added,
        chain.height()
    );
    if progress.caught_up {
        println!("Caught up with that peer.");
    } else {
        println!(
            "Stopped after {max_batches} batch(es); the peer is at {}. Run again to continue.",
            progress.peer_height
        );
    }
    Ok(())
}

/// A generator seeded from the operating system.
///
/// The daemon has no wallet, but the same seeding applies: a peer id drawn from
/// a predictable source would collide across restarts, and two nodes sharing one
/// would each read the other as a self-connection and hang up.
#[cfg(windows)]
fn wow_wallet_entropy() -> Result<wow_crypto::random::Rng, String> {
    // Reuse the wallet's, rather than carrying a second copy of the FFI.
    wow_wallet::entropy::seeded_rng()
}

#[cfg(not(windows))]
fn wow_wallet_entropy() -> Result<wow_crypto::random::Rng, String> {
    use std::io::Read;

    let mut state = [0u8; wow_crypto::keccak::HASH_STATE_BYTES];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut state))
        .map_err(|e| format!("cannot read entropy: {e}"))?;
    Ok(wow_crypto::random::Rng::from_state(state))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trusted boundary comes from the checkpoint list and sits one block
    /// *past* the last checkpoint, because that checkpoint is itself verified.
    ///
    /// Mainnet's last checkpoint is height 838,800, so everything from 838,801
    /// up is fully validated -- which is the range where a reorg is still
    /// possible and where this node's answers matter.
    #[test]
    fn the_trusted_boundary_follows_the_last_checkpoint() {
        for network in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            let cp = wow_consensus::checkpoints::Checkpoints::new(network);
            let expected = cp.last_height().map(|h| h + 1).unwrap_or(0);
            if network == Network::Mainnet {
                assert_eq!(expected, 838_801);
            }
            assert!(
                expected == 0 || expected > cp.last_height().expect("some"),
                "the last checkpoint is verified, not trusted"
            );
        }
    }

    /// A network with no checkpoints trusts nothing. Fakechain is the one that
    /// matters: a regtest chain has no checkpoints, and a node that trusted a
    /// range there would accept blocks nobody had checked.
    #[test]
    fn a_chain_without_checkpoints_verifies_everything() {
        let cp = wow_consensus::checkpoints::Checkpoints::new(Network::Fakechain);
        assert!(cp.is_empty());
        assert_eq!(cp.last_height().map(|h| h + 1).unwrap_or(0), 0);
    }

    /// Inside the trusted zone the proof is not computed, so the missing
    /// CryptoNight variants never come up; outside it, they are a refusal.
    #[test]
    fn the_cryptonight_gap_is_a_refusal_outside_the_trusted_zone() {
        use wow_core::pow::PowVerifier;

        let pow = ChainPow::new(100);
        assert!(pow.may_skip(0));
        assert!(pow.may_skip(99));
        assert!(!pow.may_skip(100));

        // Major version 9 needs CryptoNight v2, which this build does not have.
        let e = pow
            .pow_hash(100, 9, b"blob", &[0u8; 32])
            .expect_err("variant 2 is not implemented");
        assert!(
            matches!(e, wow_core::pow::PowError::CryptoNightNotImplemented { .. }),
            "a block whose proof cannot be checked is refused, never waved through: {e}"
        );
    }

    /// A peer id is drawn fresh, so two runs do not look like a
    /// self-connection to each other.
    #[test]
    fn peer_ids_differ_between_runs() {
        let mut a = wow_wallet_entropy().expect("entropy");
        let mut b = wow_wallet_entropy().expect("entropy");
        let mut x = [0u8; 8];
        let mut y = [0u8; 8];
        a.fill(&mut x);
        b.fill(&mut y);
        assert_ne!(x, y);
    }
}
