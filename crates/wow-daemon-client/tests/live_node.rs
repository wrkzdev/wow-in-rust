//! Checks against a **real** Wownero node, run on demand.
//!
//! Every test here is `#[ignore]`: they need the network and a third party's
//! server, so they must never run in an ordinary `cargo test`. Run them when
//! something is about to be pointed at a live daemon:
//!
//! ```sh
//! WOW_LIVE_NODE=node2.monerodevs.org:34568 \
//!   cargo test -p wow-daemon-client --test live_node -- --ignored --nocapture
//! ```
//!
//! They exist because the bugs that matter here are interoperation bugs. Our
//! own daemon has differed from the reference where no test of it could see --
//! it answered a wallet's history one block later than the reference does, and
//! it writes fields the reference omits -- so a test suite that only ever talks
//! to our daemon agrees with itself and says nothing about whether a wallet can
//! reach the network.

use wow_daemon_client::DaemonClient;

fn node() -> Option<String> {
    std::env::var("WOW_LIVE_NODE").ok()
}

fn client() -> Option<DaemonClient> {
    node().map(|a| DaemonClient::new(&a))
}

#[test]
#[ignore = "needs a live node; set WOW_LIVE_NODE"]
fn the_node_reports_a_mainnet_tip() {
    let Some(c) = client() else {
        eprintln!("set WOW_LIVE_NODE to run this");
        return;
    };
    let info = c.get_info().expect("get_info");
    eprintln!(
        "height {} nettype {} synchronized {}",
        info.height, info.nettype, info.synchronized
    );
    assert!(info.height > 800_000, "a mainnet node is past 800k");
    assert_eq!(info.nettype, "mainnet");
}

/// The two calls a **send** depends on, which no offline test reaches.
///
/// Picking ring members means asking the daemon where the RingCT outputs are
/// (`get_output_distribution`) and then fetching the chosen ones
/// (`get_outs`). If either is wrong, a wallet builds transactions the network
/// rejects -- and it will not find out until it tries to spend.
#[test]
#[ignore = "needs a live node; set WOW_LIVE_NODE"]
fn the_decoy_endpoints_answer() {
    let Some(c) = client() else {
        eprintln!("set WOW_LIVE_NODE to run this");
        return;
    };
    let info = c.get_info().expect("get_info");
    let tip = info.height - 1;

    // Amount zero is the RingCT pool, which is the only one a modern wallet
    // draws from. Asked for as `wallet2` asks: per-block counts, compressed,
    // to the node's own tip.
    let answer = c
        .get_output_distribution(&[0], 0, 0, false, true)
        .expect("get_output_distribution");
    assert_eq!(answer.len(), 1, "one distribution for the one amount");
    let answer = &answer[0];
    assert_eq!(answer.amount, 0);
    assert!(
        answer.distribution.len() > 1000,
        "the distribution covers the chain: {} entries from height {}",
        answer.distribution.len(),
        answer.start_height
    );

    // Added up, the counts are running totals, and the last is the number of
    // RingCT outputs ever made.
    let mut total = answer.base;
    for n in &answer.distribution {
        total = total.checked_add(*n).expect("the counts do not overflow");
    }
    eprintln!("{} RingCT outputs over {} entries", total, dist.len());
    assert!(total > 1_000_000, "a chain this old has millions");

    // Fetch a handful spread across the pool. These are what a ring is made
    // of, so a wrong key or a missing commitment here is a transaction the
    // network will refuse.
    let wanted: Vec<(u64, u64)> = [0u64, total / 4, total / 2, total - 1]
        .iter()
        .map(|i| (0u64, *i))
        .collect();
    let outs = c.get_outs(&wanted, false).expect("get_outs");
    assert_eq!(outs.len(), wanted.len(), "one answer per request");

    for (i, o) in outs.iter().enumerate() {
        assert_ne!(o.key, [0u8; 32], "output {i} has no one-time key");
        assert_ne!(o.mask, [0u8; 32], "output {i} has no commitment");
        assert!(o.height <= tip, "output {i} claims height {}", o.height);
    }
    eprintln!("fetched {} ring members, all well formed", outs.len());
}

/// What `adjust_priority` asks before it picks a fee tier. If any of these
/// fails, a transfer given no priority still pays the low tier, but by the
/// fallback rather than by looking -- so a broken call would go unnoticed.
#[test]
#[ignore = "needs a live node; set WOW_LIVE_NODE"]
fn the_fee_priority_inputs_answer() {
    let Some(c) = client() else {
        eprintln!("set WOW_LIVE_NODE to run this");
        return;
    };
    let tiers = c.get_fee_estimate(10).expect("get_fee_estimate");
    assert_eq!(
        tiers.len(),
        4,
        "four tiers from the 2021 scaling: {tiers:?}"
    );
    assert!(tiers.windows(2).all(|w| w[0] <= w[1]), "ordered: {tiers:?}");

    let info = c.get_info().expect("get_info");
    assert!(
        info.block_weight_limit >= 600_000,
        "twice a median floored at 300,000: {}",
        info.block_weight_limit
    );

    let weights = c
        .get_block_weights(info.height - 10, info.height - 1)
        .expect("getblockheadersrange");
    assert_eq!(weights.len(), 10, "one weight per block asked for");
    assert!(weights.iter().all(|w| *w > 0), "every block has a coinbase");

    c.get_transaction_pool().expect("get_transaction_pool");
    eprintln!(
        "tiers {tiers:?}, limit {}, recent weights {weights:?}",
        info.block_weight_limit
    );
}

/// A wallet's refresh call, against the real thing.
#[test]
#[ignore = "needs a live node; set WOW_LIVE_NODE"]
fn a_refresh_from_the_tip_returns_blocks() {
    let Some(c) = client() else {
        eprintln!("set WOW_LIVE_NODE to run this");
        return;
    };
    let info = c.get_info().expect("get_info");
    let from = info.height - 1;

    // What a freshly created wallet sends: a start height at the tip block and
    // a history holding only genesis.
    let genesis = wow_consensus::genesis::genesis_id(wow_types::Network::Mainnet);
    let got = c
        .get_blocks(&[genesis], from, false, false, 0)
        .expect("get_blocks");
    assert!(!got.blocks.is_empty(), "the tip block comes back");
    assert_eq!(got.start_height, from);
    eprintln!(
        "{} block(s) from height {}, daemon at {}",
        got.blocks.len(),
        got.start_height,
        got.current_height
    );
}

/// The second call of a refresh, which the first cannot show: a history ending
/// at a block the wallet has is answered **from** that block, not after it.
///
/// A wallet that expects the block after reads the repeated one as a reorg, on
/// every batch. The two batches of early blocks are tens of megabytes.
#[test]
#[ignore = "needs a live node; set WOW_LIVE_NODE"]
fn a_second_batch_starts_at_the_last_block_of_the_first() {
    let Some(c) = client() else {
        eprintln!("set WOW_LIVE_NODE to run this");
        return;
    };
    let genesis = wow_consensus::genesis::genesis_id(wow_types::Network::Mainnet);

    let first = c
        .get_blocks(&[genesis], 0, false, false, 0)
        .expect("first batch");
    assert_eq!(
        first.start_height, 0,
        "a history of genesis alone starts at it"
    );
    let last = first.blocks.last().expect("blocks");
    let last_id = wow_types::block::Block::from_blob(&last.block)
        .expect("parses")
        .block_id()
        .expect("an id");
    let last_height = first.start_height + first.blocks.len() as u64 - 1;

    let second = c
        .get_blocks(&[last_id, genesis], 0, false, false, 0)
        .expect("second batch");
    assert_eq!(
        second.start_height, last_height,
        "the block both have, again"
    );
    assert_eq!(
        second.blocks.first().map(|b| &b.block),
        Some(&last.block),
        "and it is that very block"
    );
    eprintln!(
        "first {} block(s) from 0; second from {}",
        first.blocks.len(),
        second.start_height
    );
}

/// The relay endpoint answers, and rejects a transaction it cannot parse.
///
/// One malformed blob, sent with `do_not_relay` so nothing is propagated. The
/// point is not the rejection -- it is that the *plumbing* works: the request
/// is shaped right, the response parses, and a refusal comes back as a value
/// with a reason rather than as a transport error. That is the last link in
/// the send path that can be checked without funds.
#[test]
#[ignore = "needs a live node; set WOW_LIVE_NODE"]
fn the_relay_endpoint_rejects_a_malformed_transaction() {
    let Some(c) = client() else {
        eprintln!("set WOW_LIVE_NODE to run this");
        return;
    };

    let res = c
        .send_raw_transaction(&[0u8; 16], true)
        .expect("the call itself must succeed; the transaction is what fails");

    eprintln!("status {:?} reason {:?}", res.status, res.reason);
    assert_ne!(
        res.status, "OK",
        "sixteen zero bytes are not a transaction: {res:?}"
    );
    assert!(
        !res.status.is_empty(),
        "a rejection names itself rather than coming back blank"
    );
}
