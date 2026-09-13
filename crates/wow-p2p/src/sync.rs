//! Chain synchronisation (`specs/08` §5).
//!
//! Ask a peer where our chains diverge, then pull the blocks after that point
//! and hand them to the caller in order.
//!
//! # One peer at a time
//!
//! `specs/08` §5.6 describes a span queue: several peers each assigned a height
//! range, completed spans reordered for in-order application. This is the
//! simple form the same section calls acceptable — "a simple one-peer-at-a-time
//! sync is acceptable for M2 but will be slow" — and slow it is. A span queue
//! is a throughput change, not a correctness one, and it can be added without
//! moving anything below.
//!
//! # Batches are aligned to the seed epoch
//!
//! `specs/08` §5.4 says to align requests to `SEEDHASH_EPOCH_BLOCKS` so one
//! batch shares a RandomWOW seed (`specs/03` §3.4). A seed change costs a
//! dataset rebuild, which is seconds; straddling epochs on every batch would
//! turn a sync into a series of them.

use wow_crypto::types::Hash256;

use crate::messages::{self, BlockEntry};
use crate::peer::{Peer, PeerError};

/// What the sync loop needs from the local chain.
///
/// A trait so this crate does not depend on the block validator: `wow-p2p`
/// moves bytes and checks the protocol, `wow-core` decides what is valid, and
/// keeping the two apart means a protocol bug cannot be mistaken for a
/// consensus one.
pub trait ChainTip {
    /// One past the highest block held.
    fn height(&self) -> u64;

    /// The cumulative difficulty at the tip, for deciding who is ahead.
    fn cumulative_difficulty(&self) -> u128;

    /// The tip's hash.
    fn top_id(&self) -> Hash256;

    /// The short chain history (`specs/08` §5.2): the last ten block ids, then
    /// exponentially spaced ones, genesis last.
    fn short_history(&self) -> Vec<Hash256>;

    /// Whether a block is already held.
    fn have_block(&self, id: &Hash256) -> bool;

    /// Validate and append. The error is the caller's own; a rejection stops
    /// the sync, because every block after it descends from one this node will
    /// not accept.
    fn add_block(&mut self, blob: &[u8], txs: &[Vec<u8>]) -> Result<(), String>;
}

/// What one round of syncing did.
///
/// The two durations are split because they have different fixes. Time spent
/// waiting on the peer is a batching or peer-selection problem; time spent in
/// `add_block` is this node's own. Reporting one total would hide which.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub blocks_added: u64,
    /// The height the peer says it is at.
    pub peer_height: u64,
    /// True when this node has caught up with that peer.
    pub caught_up: bool,
    /// Time spent waiting for the peer to answer.
    pub waiting: std::time::Duration,
    /// Time spent validating and storing what it sent.
    pub applying: std::time::Duration,
}

#[derive(Debug)]
pub enum SyncError {
    Peer(PeerError),
    /// A block the peer sent was not accepted by the local rules. The sync
    /// stops here: everything after it builds on a block this node rejects.
    Rejected {
        height: u64,
        reason: String,
    },
    /// The peer offered a chain that does not attach to ours.
    NoCommonAncestor,
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Peer(e) => write!(f, "{e}"),
            SyncError::Rejected { height, reason } => {
                write!(f, "the block at height {height} was rejected: {reason}")
            }
            SyncError::NoCommonAncestor => f.write_str("the peer's chain does not attach to ours"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<PeerError> for SyncError {
    fn from(e: PeerError) -> Self {
        SyncError::Peer(e)
    }
}

/// How many blocks to ask for at once.
///
/// Starts at the reference's default and grows toward the maximum, because a
/// round trip per twenty blocks is most of the cost of a long sync.
#[derive(Clone, Copy, Debug)]
pub struct BatchSize {
    current: usize,
}

impl Default for BatchSize {
    fn default() -> Self {
        BatchSize {
            current: messages::BLOCKS_DEFAULT_COUNT,
        }
    }
}

impl BatchSize {
    /// The next batch, clipped so it does not cross a seed-hash epoch.
    ///
    /// `specs/08` §5.4. Crossing an epoch means the batch spans two RandomWOW
    /// seeds and the verifier rebuilds its dataset mid-batch.
    pub fn next(&self, from_height: u64, available: usize) -> usize {
        let to_epoch_end =
            messages::SEEDHASH_EPOCH_BLOCKS - (from_height % messages::SEEDHASH_EPOCH_BLOCKS);
        self.current
            .min(available)
            .min(to_epoch_end as usize)
            .max(1)
    }

    /// Grow after a batch that came back whole.
    ///
    /// The ceiling is `MAX_OBJECT_REQUEST_COUNT`, not `BLOCKS_MAX_COUNT`: the
    /// reference drops a peer that asks for more than a hundred objects in one
    /// request, and does it by closing the socket rather than answering, so the
    /// symptom is an unexplained end-of-file several batches into a sync.
    pub fn grow(&mut self) {
        self.current = (self.current * 2).min(messages::MAX_OBJECT_REQUEST_COUNT);
    }

    /// Shrink after one that did not.
    pub fn shrink(&mut self) {
        self.current = (self.current / 2).max(messages::BLOCKS_DEFAULT_COUNT);
    }
}

/// Sync from one peer until caught up or `max_batches` have been pulled.
///
/// The bound matters: a peer that keeps reporting a higher height would
/// otherwise hold the caller forever.
pub fn sync_from<C: ChainTip>(
    chain: &mut C,
    peer: &mut Peer,
    max_batches: usize,
    mut on_progress: impl FnMut(&Progress),
) -> Result<Progress, SyncError> {
    let mut total = Progress {
        peer_height: peer.sync.current_height,
        ..Default::default()
    };

    // `specs/08` §5.1: a peer with no chain has nothing to offer.
    if peer.sync.current_height == 0 {
        return Err(SyncError::Peer(PeerError::EmptyChain));
    }
    // And one that is not ahead of us has nothing to give either.
    if peer.sync.cumulative_difficulty <= chain.cumulative_difficulty()
        && peer.sync.top_id != chain.top_id()
    {
        total.caught_up = true;
        return Ok(total);
    }

    let mut batch = BatchSize::default();

    for _ in 0..max_batches {
        let history = chain.short_history();
        let entry = peer.request_chain(&history)?;

        // The first id is the split point and we must already have it;
        // `Peer::request_chain` has checked it came from our history.
        let wanted: Vec<Hash256> = entry
            .block_ids
            .iter()
            .copied()
            .filter(|id| !chain.have_block(id))
            .collect();

        if wanted.is_empty() {
            total.caught_up = true;
            total.peer_height = entry.total_height.max(total.peer_height);
            on_progress(&total);
            return Ok(total);
        }

        // Heights run from the split point, so the first block we want sits at
        // `start_height` plus however many of the returned ids we already had.
        let already = entry.block_ids.len() - wanted.len();
        let mut height = entry.start_height + already as u64;

        let mut taken = 0usize;
        while taken < wanted.len() {
            let size = batch.next(height, wanted.len() - taken);
            let slice = &wanted[taken..taken + size];

            let asked_at = std::time::Instant::now();
            let response = peer.request_blocks(slice)?;
            total.waiting += asked_at.elapsed();

            if response.blocks.is_empty() {
                batch.shrink();
                break;
            }

            let apply_at = std::time::Instant::now();
            for (i, block) in response.blocks.iter().enumerate() {
                apply(chain, block, height + i as u64)?;
                total.blocks_added += 1;
            }
            total.applying += apply_at.elapsed();

            if response.blocks.len() == slice.len() {
                batch.grow();
            } else {
                batch.shrink();
            }

            taken += response.blocks.len();
            height += response.blocks.len() as u64;
            total.peer_height = response.current_blockchain_height.max(total.peer_height);

            // Keep what we would tell a peer about ourselves current. The
            // reference invokes `COMMAND_TIMED_SYNC` on an open connection, and
            // answering it with the height this node started at would have the
            // peer believe we had made no progress at all.
            peer.our_sync.current_height = chain.height();
            peer.our_sync.cumulative_difficulty = chain.cumulative_difficulty();
            peer.our_sync.top_id = chain.top_id();

            on_progress(&total);
        }

        if chain.height() >= total.peer_height {
            total.caught_up = true;
            return Ok(total);
        }
    }

    Ok(total)
}

fn apply<C: ChainTip>(chain: &mut C, block: &BlockEntry, height: u64) -> Result<(), SyncError> {
    chain
        .add_block(&block.block, &block.txs)
        .map_err(|reason| SyncError::Rejected { height, reason })
}

/// The short chain history from a list of block hashes, genesis first.
///
/// `specs/08` §5.2: the last ten sequentially, then exponentially increasing
/// gaps, and **always genesis last**. Newest first.
pub fn short_history(hashes: &[Hash256]) -> Vec<Hash256> {
    let mut out = Vec::new();
    if hashes.is_empty() {
        return out;
    }

    let len = hashes.len();
    let mut i = 0usize;
    let mut step = 1usize;
    while i < len {
        out.push(hashes[len - 1 - i]);
        if out.len() > 10 {
            step *= 2;
        }
        i += step;
    }
    let genesis = hashes[0];
    if out.last() != Some(&genesis) {
        out.push(genesis);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u32) -> Hash256 {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&n.to_le_bytes());
        h
    }

    /// The history is newest first, dense near the tip, sparse below, genesis
    /// last.
    #[test]
    fn the_short_history_has_the_documented_shape() {
        assert!(short_history(&[]).is_empty());

        let hashes: Vec<Hash256> = (0u32..100).map(hash).collect();
        let history = short_history(&hashes);

        for (i, h) in history.iter().take(10).enumerate() {
            assert_eq!(*h, hashes[99 - i], "the first ten are sequential");
        }
        assert!(
            history.len() < 25,
            "the gaps keep it short: {}",
            history.len()
        );
        assert_eq!(
            *history.last().expect("non-empty"),
            hashes[0],
            "genesis is always last"
        );
    }

    /// A batch never crosses a seed-hash epoch, because that would make one
    /// request span two RandomWOW seeds.
    #[test]
    fn batches_stop_at_a_seed_epoch() {
        let batch = BatchSize { current: 2_048 };

        // Starting on a boundary: the whole epoch is available.
        assert_eq!(batch.next(0, 10_000), 2_048);
        assert_eq!(batch.next(2_048, 10_000), 2_048);

        // Ten blocks before a boundary: stop at it.
        assert_eq!(batch.next(2_048 - 10, 10_000), 10);
        assert_eq!(batch.next(4_096 - 1, 10_000), 1);

        // Never more than what is available, and never zero.
        assert_eq!(batch.next(0, 5), 5);
        assert_eq!(batch.next(0, 0), 1, "a batch is at least one block");
    }

    /// The batch grows toward the maximum and shrinks back to the default,
    /// never past either.
    #[test]
    fn the_batch_size_stays_within_its_bounds() {
        let mut b = BatchSize::default();
        assert_eq!(b.current, messages::BLOCKS_DEFAULT_COUNT);

        for _ in 0..20 {
            b.grow();
        }
        assert_eq!(
            b.current,
            messages::MAX_OBJECT_REQUEST_COUNT,
            "capped at what one request may ask for, not at the span maximum"
        );

        for _ in 0..20 {
            b.shrink();
        }
        assert_eq!(
            b.current,
            messages::BLOCKS_DEFAULT_COUNT,
            "floored at the default"
        );
    }

    /// A rejection names the height, because "a block was rejected" during a
    /// 500,000-block sync is not actionable.
    #[test]
    fn a_rejection_names_the_height() {
        let e = SyncError::Rejected {
            height: 114_969,
            reason: "proof of work is too weak".into(),
        };
        let text = e.to_string();
        assert!(text.contains("114969"), "{text}");
        assert!(text.contains("too weak"), "{text}");
    }
}
