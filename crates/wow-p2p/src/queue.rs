//! The block queue: one sync spread over several peers (`specs/08` §5.6).
//!
//! The reference's `block_queue`. Every connection whose peer is ahead reserves
//! a *span* -- a run of block ids no other connection has asked for -- and asks
//! its peer for those blocks. What comes back is filed here by height, and one
//! applier takes spans off the front, in order, as soon as the next one the
//! chain needs is in. Peers download in parallel; the chain still grows one
//! block at a time.
//!
//! # What keeps one slow or vanished peer from stalling the rest
//!
//! * A connection that closes gives back the spans it had not delivered, and
//!   their ids are free for any other connection to reserve.
//! * The span the chain needs *next*, if its owner has not delivered it within
//!   [`NEXT_SPAN_THRESHOLD`] -- [`NEXT_SPAN_THRESHOLD_STANDBY`] for a connection
//!   with nothing else to do -- may be asked for again by another connection.
//!   Whichever answer lands first fills it; the other is dropped.
//! * Downloading further ahead pauses once the queue holds
//!   [`NSPANS_THRESHOLD`] filled spans *and* [`SIZE_THRESHOLD`] bytes, except
//!   within [`FORCE_DOWNLOAD_NEAR_BLOCKS`] of the tip -- so a fast peer cannot
//!   fill memory with blocks that wait an hour for the applier, and the blocks
//!   the applier is waiting on are never the ones held back.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use wow_crypto::types::Hash256;

use crate::messages::BlockEntry;

/// `BLOCK_QUEUE_NSPANS_THRESHOLD`.
pub const NSPANS_THRESHOLD: usize = 10;
/// `BLOCK_QUEUE_SIZE_THRESHOLD`.
pub const SIZE_THRESHOLD: usize = 100 * 1024 * 1024;
/// `BLOCK_QUEUE_FORCE_DOWNLOAD_NEAR_BLOCKS`.
pub const FORCE_DOWNLOAD_NEAR_BLOCKS: u64 = 1_000;
/// `REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD`.
pub const NEXT_SPAN_THRESHOLD: Duration = Duration::from_secs(30);
/// `REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY`.
pub const NEXT_SPAN_THRESHOLD_STANDBY: Duration = Duration::from_secs(5);

/// A run of consecutive blocks, asked for or delivered.
#[derive(Clone, Debug)]
pub struct Span {
    pub start: u64,
    pub ids: Vec<Hash256>,
    /// Empty while the span is only reserved.
    pub blocks: Vec<BlockEntry>,
    /// The connection that reserved it, or that delivered it.
    pub conn: u64,
    pub origin: SocketAddr,
    /// When it was last asked for.
    pub requested: Instant,
    /// Bytes per second it arrived at.
    pub rate: f64,
    /// Bytes of block and transaction data.
    pub size: usize,
}

impl Span {
    pub fn is_filled(&self) -> bool {
        !self.blocks.is_empty()
    }

    /// One past the last height.
    pub fn end(&self) -> u64 {
        self.start + self.ids.len() as u64
    }
}

/// A span as `sync_info` reports it.
#[derive(Clone, Debug, PartialEq)]
pub struct SpanInfo {
    pub start_height: u64,
    pub nblocks: u64,
    pub connection_id: u64,
    pub remote_address: SocketAddr,
    /// Bytes per second.
    pub rate: f64,
    /// This connection's rate against the fastest one's, `0..=1`.
    pub speed: f64,
    pub size: u64,
    pub filled: bool,
}

/// The spans in flight.
#[derive(Debug, Default)]
pub struct BlockQueue {
    spans: BTreeMap<u64, Span>,
    /// Every id in a span, with its height.
    heights: HashMap<Hash256, u64>,
    /// Ids of spans handed to the applier and not yet on the chain.
    applying: HashMap<Hash256, u64>,
}

impl BlockQueue {
    pub fn new() -> BlockQueue {
        BlockQueue::default()
    }

    /// No spans, and nothing being applied.
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty() && self.applying.is_empty()
    }

    pub fn len(&self) -> usize {
        self.spans.len()
    }

    /// Whether some connection has asked for this block, or it is being
    /// applied.
    pub fn requested(&self, id: &Hash256) -> bool {
        self.heights.contains_key(id) || self.applying.contains_key(id)
    }

    /// The height a queued block sits at.
    pub fn height_of(&self, id: &Hash256) -> Option<u64> {
        self.heights
            .get(id)
            .or_else(|| self.applying.get(id))
            .copied()
    }

    pub fn filled_spans(&self) -> usize {
        self.spans.values().filter(|s| s.is_filled()).count()
    }

    pub fn data_size(&self) -> usize {
        self.spans.values().map(|s| s.size).sum()
    }

    /// Whether downloading further ahead should wait for the applier.
    pub fn is_full(&self) -> bool {
        self.filled_spans() >= NSPANS_THRESHOLD && self.data_size() >= SIZE_THRESHOLD
    }

    fn insert(&mut self, span: Span) {
        for (i, id) in span.ids.iter().enumerate() {
            self.heights.insert(*id, span.start + i as u64);
        }
        self.spans.insert(span.start, span);
    }

    fn remove(&mut self, start: u64) -> Option<Span> {
        let span = self.spans.remove(&start)?;
        for id in &span.ids {
            self.heights.remove(id);
        }
        Some(span)
    }

    /// `reserve_span`: the first run of `ids` nobody has asked for.
    ///
    /// `ids` is a peer's chain from `first_height`. Ids already requested are
    /// skipped, and the run stops at the next one; `limit(start, free)` caps
    /// its length. Returns the span's start and ids, or `None` when there is
    /// nothing free -- or when a span already starts at that height, which a
    /// peer on another fork can offer.
    pub fn reserve(
        &mut self,
        conn: u64,
        origin: SocketAddr,
        first_height: u64,
        ids: &[Hash256],
        limit: impl Fn(u64, usize) -> usize,
        now: Instant,
    ) -> Option<(u64, Vec<Hash256>)> {
        let skip = ids.iter().position(|id| !self.requested(id))?;
        let start = first_height + skip as u64;
        if self.spans.contains_key(&start) {
            return None;
        }
        let free = ids[skip..]
            .iter()
            .take_while(|id| !self.requested(id))
            .count();
        let n = limit(start, free).min(free);
        if n == 0 {
            return None;
        }
        let reserved = ids[skip..skip + n].to_vec();
        self.insert(Span {
            start,
            ids: reserved.clone(),
            blocks: Vec::new(),
            conn,
            origin,
            requested: now,
            rate: 0.0,
            size: 0,
        });
        Some((start, reserved))
    }

    /// File blocks a peer sent for the span asked for at `start`.
    ///
    /// `blocks` answers the first `blocks.len()` of `ids`; fewer than asked
    /// for gives the rest back. A span given back while the request was in
    /// flight is taken anyway if nobody else has asked for those blocks since.
    /// Returns false when the blocks are not wanted: another connection
    /// delivered them first, or reserved them after they were given back.
    #[allow(
        clippy::too_many_arguments,
        reason = "a span's fields, as the response supplies them"
    )]
    pub fn fill(
        &mut self,
        start: u64,
        ids: &[Hash256],
        blocks: Vec<BlockEntry>,
        conn: u64,
        origin: SocketAddr,
        rate: f64,
        size: usize,
    ) -> bool {
        let n = blocks.len();
        if n == 0 || n > ids.len() {
            return false;
        }
        let matches = match self.spans.get(&start) {
            Some(s) => !s.is_filled() && s.ids.len() >= n && s.ids[..n] == ids[..n],
            None => {
                if ids[..n].iter().any(|id| self.requested(id)) {
                    return false;
                }
                self.insert(Span {
                    start,
                    ids: ids[..n].to_vec(),
                    blocks,
                    conn,
                    origin,
                    requested: Instant::now(),
                    rate,
                    size,
                });
                return true;
            }
        };
        if !matches {
            return false;
        }
        let Some(mut span) = self.remove(start) else {
            return false;
        };
        span.ids.truncate(n);
        span.blocks = blocks;
        span.conn = conn;
        span.origin = origin;
        span.rate = rate;
        span.size = size;
        self.insert(span);
        true
    }

    /// The span the chain can take next: the lowest, when it is filled and
    /// starts at or below `height`. It moves to the applying set until
    /// [`BlockQueue::applied`].
    ///
    /// Spans whose last block the chain already has (`have`) are dropped on
    /// the way, filled or not -- their blocks arrived some other way, such as
    /// an announcement.
    pub fn take_next(&mut self, height: u64, have: impl Fn(&Hash256) -> bool) -> Option<Span> {
        loop {
            let (&start, first) = self.spans.iter().next()?;
            if first.ids.last().is_some_and(&have) {
                self.remove(start);
                continue;
            }
            if start > height || !first.is_filled() {
                return None;
            }
            let span = self.remove(start)?;
            for (i, id) in span.ids.iter().enumerate() {
                self.applying.insert(*id, span.start + i as u64);
            }
            return Some(span);
        }
    }

    /// The applier is done with a span, whatever became of it.
    pub fn applied(&mut self, span: &Span) {
        for id in &span.ids {
            self.applying.remove(id);
        }
    }

    /// Give back a connection's spans: those not yet delivered, or with `all`,
    /// every one.
    pub fn flush(&mut self, conn: u64, all: bool) {
        let starts: Vec<u64> = self
            .spans
            .values()
            .filter(|s| s.conn == conn && (all || !s.is_filled()))
            .map(|s| s.start)
            .collect();
        for start in starts {
            self.remove(start);
        }
    }

    /// Drop every span. Spans being applied finish as they are.
    pub fn clear(&mut self) {
        self.spans.clear();
        self.heights.clear();
    }

    /// The span the chain needs next, if it has been asked for and not
    /// delivered for `after`: its start, ids and owner.
    pub fn overdue_next(
        &self,
        height: u64,
        after: Duration,
        now: Instant,
    ) -> Option<(u64, Vec<Hash256>, u64)> {
        let first = self.spans.values().next()?;
        (first.start <= height
            && !first.is_filled()
            && now.saturating_duration_since(first.requested) >= after)
            .then(|| (first.start, first.ids.clone(), first.conn))
    }

    /// A span was asked for again.
    pub fn touch(&mut self, start: u64, now: Instant) {
        if let Some(s) = self.spans.get_mut(&start) {
            s.requested = now;
        }
    }

    /// The last block of this connection's highest span, so its next chain
    /// request starts from what it has already offered.
    pub fn last_known(&self, conn: u64) -> Option<Hash256> {
        self.spans
            .values()
            .rev()
            .find(|s| s.conn == conn)
            .and_then(|s| s.ids.last().copied())
    }

    /// `get_next_needed_height`: the first height at or above `height` no
    /// span covers.
    pub fn next_needed_height(&self, height: u64) -> u64 {
        let mut covered = height;
        for s in self.spans.values() {
            if s.end() <= height {
                continue;
            }
            if s.start > covered {
                return covered;
            }
            covered = covered.max(s.end());
        }
        covered
    }

    /// `get_speed`: a connection's download rate against the fastest one's.
    ///
    /// Each connection's rate is a running average weighted towards its
    /// latest span, as in the reference. A connection with no delivered span
    /// is assumed to be fast.
    pub fn speed(&self, conn: u64) -> f64 {
        let mut rates: BTreeMap<u64, f64> = BTreeMap::new();
        for s in self.spans.values().filter(|s| s.is_filled()) {
            rates
                .entry(s.conn)
                .and_modify(|r| *r = (*r + s.rate) / 2.0)
                .or_insert(s.rate);
        }
        let best = rates.values().copied().fold(0.0, f64::max);
        match rates.get(&conn) {
            Some(&r) if r > 0.0 && best > 0.0 => r / best,
            _ => 1.0,
        }
    }

    /// `get_overview`: one character per span -- `.` reserved, `o` filled, `m`
    /// the one the chain takes next, `<` below the chain -- with `_` for gaps.
    pub fn overview(&self, height: u64) -> String {
        if self.spans.is_empty() {
            return "[]".into();
        }
        let mut s = String::from("[");
        let mut expected = height;
        for span in self.spans.values() {
            if expected > span.start {
                s.push('<');
                continue;
            }
            let n = span.ids.len().max(1) as u64;
            if expected < span.start {
                let gaps = ((span.start - expected) / n).max(1);
                s.extend(std::iter::repeat_n('_', gaps as usize));
            }
            s.push(if !span.is_filled() {
                '.'
            } else if span.start == height {
                'm'
            } else {
                'o'
            });
            expected = span.end();
        }
        s.push(']');
        s
    }

    /// The spans, lowest first, for `sync_info`.
    pub fn info(&self) -> Vec<SpanInfo> {
        self.spans
            .values()
            .map(|s| SpanInfo {
                start_height: s.start,
                nblocks: s.ids.len() as u64,
                connection_id: s.conn,
                remote_address: s.origin,
                rate: s.rate,
                speed: self.speed(s.conn),
                size: s.size as u64,
                filled: s.is_filled(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> Hash256 {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&n.to_le_bytes());
        h
    }

    fn ids(from: u64, n: u64) -> Vec<Hash256> {
        (from..from + n).map(id).collect()
    }

    fn blocks(n: usize) -> Vec<BlockEntry> {
        (0..n)
            .map(|i| BlockEntry {
                block: vec![i as u8; 10],
                txs: Vec::new(),
                block_weight: 0,
            })
            .collect()
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// Two connections offered the same chain reserve different spans of it:
    /// the second skips what the first asked for.
    #[test]
    fn a_second_connection_skips_what_the_first_reserved() {
        let mut q = BlockQueue::new();
        let chain = ids(100, 300);
        let now = Instant::now();

        let (start, a) = q
            .reserve(1, addr(1), 100, &chain, |_, free| free.min(100), now)
            .unwrap();
        assert_eq!((start, a.len()), (100, 100));

        let (start, b) = q
            .reserve(2, addr(2), 100, &chain, |_, free| free.min(100), now)
            .unwrap();
        assert_eq!(start, 200, "past the first connection's span");
        assert_eq!(b[0], id(200));
        assert!(q.requested(&id(150)) && q.requested(&id(250)));
        assert!(!q.requested(&id(300)));
        assert_eq!(q.height_of(&id(250)), Some(250));
        assert_eq!(q.next_needed_height(100), 300);
        assert_eq!(q.overview(100), "[..]");
    }

    /// Spans come out in height order, and only once the one the chain needs
    /// is in -- a later span arriving first waits.
    #[test]
    fn spans_are_taken_in_height_order() {
        let mut q = BlockQueue::new();
        let now = Instant::now();
        let chain = ids(10, 40);
        q.reserve(1, addr(1), 10, &chain, |_, _| 20, now).unwrap();
        q.reserve(2, addr(2), 10, &chain, |_, _| 20, now).unwrap();

        assert!(q.fill(30, &ids(30, 20), blocks(20), 2, addr(2), 5.0, 200));
        assert!(
            q.take_next(10, |_| false).is_none(),
            "height 10 is not in yet"
        );
        assert_eq!(q.overview(10), "[.o]");

        assert!(q.fill(10, &ids(10, 20), blocks(20), 1, addr(1), 10.0, 200));
        assert_eq!(q.overview(10), "[mo]");
        let first = q.take_next(10, |_| false).unwrap();
        assert_eq!(first.start, 10);
        assert!(q.requested(&id(15)), "still requested while being applied");
        q.applied(&first);
        assert!(!q.requested(&id(15)));

        assert_eq!(q.take_next(30, |_| false).unwrap().start, 30);
        assert!(q.take_next(50, |_| false).is_none());
    }

    /// A short delivery keeps what came and frees the rest; a duplicate
    /// delivery is refused.
    #[test]
    fn a_short_delivery_gives_the_rest_back() {
        let mut q = BlockQueue::new();
        let now = Instant::now();
        let chain = ids(0, 50);
        let (start, asked) = q.reserve(1, addr(1), 0, &chain, |_, _| 50, now).unwrap();

        assert!(q.fill(start, &asked, blocks(30), 1, addr(1), 1.0, 300));
        assert!(q.requested(&id(29)));
        assert!(!q.requested(&id(30)), "the undelivered ids are free again");
        assert!(
            !q.fill(start, &asked, blocks(30), 2, addr(2), 1.0, 300),
            "already delivered"
        );

        let (start, rest) = q.reserve(2, addr(2), 0, &chain, |_, _| 50, now).unwrap();
        assert_eq!((start, rest.len()), (30, 20));
    }

    /// A closed connection's reserved spans go back; its delivered ones stay
    /// for the applier. A late answer for a span given back is still taken
    /// when nobody has reserved those blocks since.
    #[test]
    fn a_closed_connection_gives_back_what_it_had_not_delivered() {
        let mut q = BlockQueue::new();
        let now = Instant::now();
        let chain = ids(0, 40);
        q.reserve(1, addr(1), 0, &chain, |_, _| 20, now).unwrap();
        q.reserve(1, addr(1), 0, &chain, |_, _| 20, now).unwrap();
        assert!(q.fill(0, &ids(0, 20), blocks(20), 1, addr(1), 1.0, 1));

        q.flush(1, false);
        assert_eq!(q.len(), 1, "the delivered span stays");
        assert!(!q.requested(&id(25)));

        assert!(
            q.fill(20, &ids(20, 20), blocks(20), 1, addr(1), 1.0, 1),
            "a late answer nobody else has taken over"
        );
        q.flush(1, true);
        assert!(q.is_empty());
    }

    /// The next span, reserved and undelivered past the threshold, is offered
    /// to other connections; asking again restarts the clock.
    #[test]
    fn an_overdue_next_span_can_be_asked_for_again() {
        let mut q = BlockQueue::new();
        let then = Instant::now();
        let chain = ids(5, 10);
        q.reserve(7, addr(7), 5, &chain, |_, _| 10, then).unwrap();

        assert!(q.overdue_next(5, NEXT_SPAN_THRESHOLD, then).is_none());
        let later = then + NEXT_SPAN_THRESHOLD;
        let (start, again, owner) = q.overdue_next(5, NEXT_SPAN_THRESHOLD, later).unwrap();
        assert_eq!((start, again.len(), owner), (5, 10, 7));
        assert!(
            q.overdue_next(4, NEXT_SPAN_THRESHOLD, later).is_none(),
            "not the span the chain needs yet"
        );

        q.touch(5, later);
        assert!(q.overdue_next(5, NEXT_SPAN_THRESHOLD, later).is_none());
    }

    /// Spans whose blocks the chain already has are dropped rather than
    /// blocking the ones behind them.
    #[test]
    fn spans_the_chain_already_has_are_dropped() {
        let mut q = BlockQueue::new();
        let now = Instant::now();
        let chain = ids(0, 40);
        q.reserve(1, addr(1), 0, &chain, |_, _| 20, now).unwrap();
        q.reserve(2, addr(2), 0, &chain, |_, _| 20, now).unwrap();
        assert!(q.fill(20, &ids(20, 20), blocks(20), 2, addr(2), 1.0, 1));

        let have = |h: &Hash256| u64::from_le_bytes(h[..8].try_into().unwrap()) < 20;
        let next = q.take_next(20, have).expect("the first span was dropped");
        assert_eq!(next.start, 20);
    }

    #[test]
    fn the_queue_thresholds_are_the_reference_ones() {
        assert_eq!(NSPANS_THRESHOLD, 10);
        assert_eq!(SIZE_THRESHOLD, 100 * 1024 * 1024);
        assert_eq!(FORCE_DOWNLOAD_NEAR_BLOCKS, 1_000);
        assert_eq!(NEXT_SPAN_THRESHOLD, Duration::from_secs(30));
        assert_eq!(NEXT_SPAN_THRESHOLD_STANDBY, Duration::from_secs(5));
    }

    /// The fastest connection is 1; one delivering at half its rate, 0.5.
    #[test]
    fn speed_is_relative_to_the_fastest_connection() {
        let mut q = BlockQueue::new();
        let now = Instant::now();
        let chain = ids(0, 40);
        q.reserve(1, addr(1), 0, &chain, |_, _| 20, now).unwrap();
        q.reserve(2, addr(2), 0, &chain, |_, _| 20, now).unwrap();
        q.fill(0, &ids(0, 20), blocks(20), 1, addr(1), 100.0, 1);
        q.fill(20, &ids(20, 20), blocks(20), 2, addr(2), 50.0, 1);
        assert_eq!(q.speed(1), 1.0);
        assert_eq!(q.speed(2), 0.5);
        assert_eq!(q.speed(9), 1.0, "unknown connections are assumed fast");
        assert_eq!(q.info().len(), 2);
    }
}
