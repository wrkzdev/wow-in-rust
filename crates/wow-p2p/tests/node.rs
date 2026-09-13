//! Nodes talking to each other over loopback (`specs/08`).
//!
//! The chain here is an in-memory stand-in for the daemon's: blocks are real
//! block blobs from the committed fixture, re-linked by `prev_id`, and a block
//! is "valid" when it extends the tip. That is all the network layer needs --
//! what these tests check is the protocol around the chain: the handshake in
//! both directions, a sync across several batches, announcements, relay,
//! ping-backs, bans, and the peer lists surviving a stop.
//!
//! One test drives the node with [`wow_p2p::Peer`] instead, the client that has
//! synced from live C++ nodes. A server this node's own client can sync from
//! is a server speaking the same protocol as the one that client was tested
//! against.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wow_crypto::keccak::HASH_STATE_BYTES;
use wow_crypto::random::Rng;
use wow_crypto::types::Hash256;
use wow_p2p::addressbook::{AddressBook, BanTarget, STATE_FILENAME};
use wow_p2p::messages::{BlockEntry, CoreSyncData};
use wow_p2p::node::{BlockVerdict, ChainReply, Config, Core, Node, TxVerdict};
use wow_p2p::sync::{self, ChainTip};
use wow_p2p::{NodeIdentity, Peer};
use wow_types::{Block, Network};

// ---------------------------------------------------------------------------
// an in-memory chain
// ---------------------------------------------------------------------------

/// A coinbase-only block from the committed fixture, to re-link.
fn template() -> Vec<u8> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/blocks/hf18/index.tsv");
    let text = std::fs::read_to_string(&path).expect("fixture");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| wow_crypto::hex::decode(l.split('\t').nth(3)?))
        .find(|b| {
            Block::from_blob(b)
                .map(|b| b.tx_hashes.is_empty())
                .unwrap_or(false)
        })
        .expect("a coinbase-only block")
}

fn make_block(template: &[u8], prev: Hash256, nonce: u32) -> (Hash256, Vec<u8>) {
    let mut b = Block::from_blob(template).unwrap();
    b.header.prev_id = prev;
    b.header.nonce = nonce;
    let blob = b.to_blob();
    let id = Block::from_blob(&blob).unwrap().block_id().unwrap();
    (id, blob)
}

fn tx_id(blob: &[u8]) -> Hash256 {
    let mut id = [0u8; 32];
    let n = blob.len().min(32);
    id[..n].copy_from_slice(&blob[..n]);
    id
}

struct MemCore {
    chain: Mutex<Vec<(Hash256, Vec<u8>)>>,
    pool: Mutex<HashMap<Hash256, Vec<u8>>>,
    /// Blocks handed to peers that asked for them.
    served: AtomicUsize,
}

impl MemCore {
    fn new(genesis: &(Hash256, Vec<u8>)) -> Arc<MemCore> {
        Arc::new(MemCore {
            chain: Mutex::new(vec![genesis.clone()]),
            pool: Mutex::new(HashMap::new()),
            served: AtomicUsize::new(0),
        })
    }

    /// Another node holding the same chain.
    fn copy_of(other: &MemCore) -> Arc<MemCore> {
        Arc::new(MemCore {
            chain: Mutex::new(other.chain.lock().unwrap().clone()),
            pool: Mutex::new(HashMap::new()),
            served: AtomicUsize::new(0),
        })
    }

    fn served(&self) -> usize {
        self.served.load(Ordering::Relaxed)
    }

    fn height(&self) -> usize {
        self.chain.lock().unwrap().len()
    }

    fn tip(&self) -> Hash256 {
        self.chain.lock().unwrap().last().unwrap().0
    }

    /// Mine `n` more blocks, returning the last as an announcement would carry it.
    fn extend(&self, n: usize, template: &[u8]) -> BlockEntry {
        let mut chain = self.chain.lock().unwrap();
        let mut last = Vec::new();
        for _ in 0..n {
            let prev = chain.last().unwrap().0;
            let (id, blob) = make_block(template, prev, chain.len() as u32);
            last = blob.clone();
            chain.push((id, blob));
        }
        BlockEntry {
            block: last,
            txs: Vec::new(),
            block_weight: 0,
        }
    }

    fn has_tx(&self, id: &Hash256) -> bool {
        self.pool.lock().unwrap().contains_key(id)
    }

    fn accept(&self, blob: &[u8]) -> BlockVerdict {
        let Some(id) = Block::from_blob(blob).ok().and_then(|b| b.block_id()) else {
            return BlockVerdict::Rejected {
                reason: "does not parse".into(),
                ban: true,
            };
        };
        let prev = Block::from_blob(blob).unwrap().header.prev_id;
        let mut chain = self.chain.lock().unwrap();
        if chain.iter().any(|(i, _)| *i == id) {
            return BlockVerdict::AlreadyHave;
        }
        if chain.last().unwrap().0 != prev {
            return BlockVerdict::Orphan;
        }
        chain.push((id, blob.to_vec()));
        BlockVerdict::Added
    }
}

impl Core for MemCore {
    fn sync_data(&self) -> CoreSyncData {
        let chain = self.chain.lock().unwrap();
        CoreSyncData {
            current_height: chain.len() as u64,
            cumulative_difficulty: chain.len() as u128,
            top_id: chain.last().unwrap().0,
            top_version: 20,
            pruning_seed: 0,
        }
    }

    fn short_history(&self) -> Vec<Hash256> {
        let ids: Vec<Hash256> = self.chain.lock().unwrap().iter().map(|(i, _)| *i).collect();
        sync::short_history(&ids)
    }

    fn have_block(&self, id: &Hash256) -> bool {
        self.chain.lock().unwrap().iter().any(|(i, _)| i == id)
    }

    fn chain_reply(&self, history: &[Hash256]) -> Option<ChainReply> {
        let chain = self.chain.lock().unwrap();
        let start = history
            .iter()
            .find_map(|h| chain.iter().position(|(i, _)| i == h))?;
        let end = chain.len().min(start + 10_000);
        Some(ChainReply {
            start_height: start as u64,
            total_height: chain.len() as u64,
            cumulative_difficulty: chain.len() as u128,
            block_ids: chain[start..end].iter().map(|(i, _)| *i).collect(),
            block_weights: vec![0; end - start],
            first_block: chain[start].1.clone(),
        })
    }

    fn blocks(&self, ids: &[Hash256]) -> (Vec<BlockEntry>, Vec<Hash256>) {
        let chain = self.chain.lock().unwrap();
        let mut found = Vec::new();
        let mut missed = Vec::new();
        for id in ids {
            match chain.iter().find(|(i, _)| i == id) {
                Some((_, blob)) => {
                    self.served.fetch_add(1, Ordering::Relaxed);
                    found.push(BlockEntry {
                        block: blob.clone(),
                        txs: Vec::new(),
                        block_weight: 0,
                    });
                }
                None => missed.push(*id),
            }
        }
        (found, missed)
    }

    fn apply_blocks(&self, blocks: &[BlockEntry]) -> (usize, Option<BlockVerdict>) {
        for (i, b) in blocks.iter().enumerate() {
            match self.accept(&b.block) {
                BlockVerdict::Added | BlockVerdict::AlreadyHave => {}
                other => return (i, Some(other)),
            }
        }
        (blocks.len(), None)
    }

    fn new_block(&self, entry: &BlockEntry) -> BlockVerdict {
        self.accept(&entry.block)
    }

    fn block_with_txs(&self, id: &Hash256, _indices: &[u64]) -> Option<BlockEntry> {
        let chain = self.chain.lock().unwrap();
        chain
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, b)| BlockEntry {
                block: b.clone(),
                txs: Vec::new(),
                block_weight: 0,
            })
    }

    fn incoming_txs(&self, txs: &[Vec<u8>]) -> Vec<TxVerdict> {
        let mut pool = self.pool.lock().unwrap();
        txs.iter()
            .map(|blob| {
                let id = tx_id(blob);
                match pool.entry(id) {
                    std::collections::hash_map::Entry::Occupied(_) => TxVerdict::Known { id },
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(blob.clone());
                        TxVerdict::Accepted { id, relay: true }
                    }
                }
            })
            .collect()
    }

    fn pool_txs_except(&self, known: &HashSet<Hash256>) -> Vec<Vec<u8>> {
        self.pool
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| !known.contains(*id))
            .map(|(_, b)| b.clone())
            .collect()
    }

    fn pool_hashes(&self) -> Vec<Hash256> {
        self.pool.lock().unwrap().keys().copied().collect()
    }

    fn tx_relayed(&self, _ids: &[Hash256]) {}
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn config(exclusive: Vec<SocketAddr>) -> Config {
    let mut c = Config::new(Network::Mainnet);
    c.listen = Some("127.0.0.1:0".parse().unwrap());
    c.seed_nodes = Vec::new();
    c.exclusive_nodes = exclusive;
    c.allow_local_ip = true;
    c.max_connections_per_ip = 8;
    c.out_peers = 4;
    c
}

fn rng(seed: u8) -> Rng {
    Rng::from_state([seed; HASH_STATE_BYTES])
}

fn wait_until(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("wow-p2p-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Two nodes sharing a genesis, `a` ahead by `lead` blocks and listening; `b`
/// dialling only `a`.
fn pair(lead: usize) -> (Node, Arc<MemCore>, Node, Arc<MemCore>, Vec<u8>) {
    let t = template();
    let genesis = make_block(&t, [0u8; 32], 0);
    let a_core = MemCore::new(&genesis);
    a_core.extend(lead, &t);
    let b_core = MemCore::new(&genesis);

    let a = Node::start(config(Vec::new()), a_core.clone(), rng(1)).expect("start a");
    let b = Node::start(
        config(vec![a.local_addr().unwrap()]),
        b_core.clone(),
        rng(2),
    )
    .expect("start b");
    (a, a_core, b, b_core, t)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// **The sync.** A node behind its peer fetches the chain across several
/// batches -- the first request is twenty blocks and grows to the hundred one
/// request may carry -- and then reports itself synchronised.
#[test]
fn a_node_syncs_a_chain_from_its_peer() {
    let (_a, a_core, b, b_core, _) = pair(249);
    assert_eq!(a_core.height(), 250);

    wait_until("the chain to arrive", 60, || b_core.height() == 250);
    assert_eq!(b_core.tip(), a_core.tip());
    wait_until("the node to call itself synchronised", 20, || {
        b.sync_status().synchronized
    });

    let status = b.sync_status();
    assert_eq!(status.height, 250);
    assert_eq!(status.outgoing, 1);
    assert!(!status.busy_syncing);
}

/// A block announced after the sync reaches the peer as a fluffy block, and
/// is added there.
#[test]
fn a_new_block_reaches_a_synced_peer() {
    let (a, a_core, b, b_core, t) = pair(30);
    wait_until("the sync", 60, || b.sync_status().synchronized);
    assert_eq!(b_core.height(), 31);

    let entry = a_core.extend(1, &t);
    a.relay_block(&entry);
    wait_until("the announced block", 20, || b_core.height() == 32);
    assert_eq!(b_core.tip(), a_core.tip());
}

/// A transaction this node originates reaches its peer -- through the
/// Dandelion++ stem, since the peer is this node's only outgoing connection.
#[test]
fn a_transaction_reaches_the_peer() {
    let (_a, a_core, b, b_core, _) = pair(3);
    wait_until("the sync", 60, || b.sync_status().synchronized);
    // Let an epoch pick its stem peers.
    std::thread::sleep(Duration::from_millis(800));

    let blob = b"a transaction, long enough to be told apart by its prefix".to_vec();
    let id = tx_id(&blob);
    b_core.pool.lock().unwrap().insert(id, blob.clone());
    b.relay_transaction(id, blob);

    wait_until("the transaction at the peer", 60, || a_core.has_tx(&id));
}

/// The network id is the fork guard: a testnet node gets no connection to a
/// mainnet one, in either direction.
#[test]
fn a_peer_on_another_network_is_refused() {
    let t = template();
    let genesis = make_block(&t, [0u8; 32], 0);
    let a = Node::start(config(Vec::new()), MemCore::new(&genesis), rng(1)).unwrap();

    let mut cfg = config(vec![a.local_addr().unwrap()]);
    cfg.network = Network::Testnet;
    let c = Node::start(cfg, MemCore::new(&genesis), rng(3)).unwrap();

    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(a.connection_count(), 0);
    assert_eq!(c.connection_count(), 0);
}

/// An incoming peer whose advertised port answers a ping as that peer is
/// white-listed; nothing else puts an incoming address there (`specs/08`
/// §4.2).
#[test]
fn a_reachable_peer_is_white_listed_after_a_ping_back() {
    let (a, _, b, _, _) = pair(1);
    let b_listens = b.local_addr().unwrap();

    wait_until("the ping-back", 20, || {
        a.peer_lists().0.iter().any(|r| r.addr == b_listens)
    });
    // And the dialler lists what it dialled.
    assert!(b
        .peer_lists()
        .0
        .iter()
        .any(|r| Some(r.addr) == a.local_addr()));
}

/// A banned address gets no connection.
#[test]
fn a_banned_address_cannot_connect() {
    let t = template();
    let genesis = make_block(&t, [0u8; 32], 0);
    let a = Node::start(config(Vec::new()), MemCore::new(&genesis), rng(1)).unwrap();
    a.ban(BanTarget::Host("127.0.0.1".parse().unwrap()), 3_600);

    let b = Node::start(
        config(vec![a.local_addr().unwrap()]),
        MemCore::new(&genesis),
        rng(2),
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(a.connection_count(), 0);
    assert_eq!(b.connection_count(), 0);
    assert_eq!(a.bans().len(), 1);
}

/// Stopping closes the connections, remembers the outgoing ones as anchors,
/// and saves the peer lists for the next run.
#[test]
fn stopping_saves_the_peer_lists() {
    let scratch = Scratch::new("state");
    let t = template();
    let genesis = make_block(&t, [0u8; 32], 0);
    let a = Node::start(config(Vec::new()), MemCore::new(&genesis), rng(1)).unwrap();

    let mut cfg = config(vec![a.local_addr().unwrap()]);
    let state = scratch.0.join(STATE_FILENAME);
    cfg.state_file = Some(state.clone());
    let b = Node::start(cfg, MemCore::new(&genesis), rng(2)).unwrap();
    wait_until("the connection", 20, || b.connection_count() == 1);

    b.stop();
    let saved = AddressBook::load(&state, true).expect("saved state");
    assert_eq!(
        saved.anchors().first().map(|r| r.addr),
        a.local_addr(),
        "the outgoing peer is an anchor"
    );
    assert!(saved.white().iter().any(|r| Some(r.addr) == a.local_addr()));
    wait_until("the peer to notice", 10, || a.connection_count() == 0);
}

/// [`Peer`] -- the client that has synced from live C++ nodes -- syncs from
/// this node. The serving side of the chain protocol is checked against a
/// client that is itself checked against the reference.
#[test]
fn the_single_peer_client_syncs_from_a_node() {
    struct Local(Arc<MemCore>);
    impl ChainTip for Local {
        fn height(&self) -> u64 {
            self.0.height() as u64
        }
        fn cumulative_difficulty(&self) -> u128 {
            self.0.height() as u128
        }
        fn top_id(&self) -> Hash256 {
            self.0.tip()
        }
        fn short_history(&self) -> Vec<Hash256> {
            Core::short_history(&*self.0)
        }
        fn have_block(&self, id: &Hash256) -> bool {
            Core::have_block(&*self.0, id)
        }
        fn add_block(&mut self, blob: &[u8], _txs: &[Vec<u8>]) -> Result<(), String> {
            match self.0.accept(blob) {
                BlockVerdict::Added => Ok(()),
                other => Err(format!("{other:?}")),
            }
        }
    }

    let t = template();
    let genesis = make_block(&t, [0u8; 32], 0);
    let server_core = MemCore::new(&genesis);
    server_core.extend(180, &t);
    let server = Node::start(config(Vec::new()), server_core.clone(), rng(1)).unwrap();

    let mut local = Local(MemCore::new(&genesis));
    let identity = NodeIdentity {
        network: Network::Mainnet,
        peer_id: 0x77,
        my_port: 0,
    };
    let ours = CoreSyncData {
        current_height: 1,
        cumulative_difficulty: 1,
        top_id: genesis.0,
        top_version: 20,
        pruning_seed: 0,
    };
    let mut peer = match Peer::connect(server.local_addr().unwrap(), &identity, &ours) {
        Ok(p) => p,
        Err(e) => panic!("handshake with the node: {e}"),
    };
    assert_eq!(peer.sync.current_height, 181);

    let progress = sync::sync_from(&mut local, &mut peer, 100, |_| {}).expect("sync");
    assert!(progress.caught_up);
    assert_eq!(local.0.height(), 181);
    assert_eq!(local.0.tip(), server_core.tip());
}

/// Two peers holding the same chain of `len` blocks past genesis, listening,
/// and a node behind them that dials both.
fn behind_two(len: usize) -> (Node, Arc<MemCore>, Node, Arc<MemCore>, Node, Arc<MemCore>) {
    let t = template();
    let genesis = make_block(&t, [0u8; 32], 0);
    let a_core = MemCore::new(&genesis);
    a_core.extend(len, &t);
    let c_core = MemCore::copy_of(&a_core);
    let b_core = MemCore::new(&genesis);

    let a = Node::start(config(Vec::new()), a_core.clone(), rng(1)).unwrap();
    let c = Node::start(config(Vec::new()), c_core.clone(), rng(3)).unwrap();
    let b = Node::start(
        config(vec![a.local_addr().unwrap(), c.local_addr().unwrap()]),
        b_core.clone(),
        rng(2),
    )
    .unwrap();
    (a, a_core, c, c_core, b, b_core)
}

/// **The span queue.** A node behind two peers that hold the same chain
/// fetches it from both at once -- each serves part of the sync -- and still
/// adds it in order, ending on the same tip with an empty queue.
#[test]
fn a_sync_is_spread_across_peers() {
    let (_a, a_core, _c, c_core, b, b_core) = behind_two(2_000);

    wait_until("the chain from both peers", 120, || {
        b_core.height() == 2_001
    });
    assert_eq!(b_core.tip(), a_core.tip());
    assert!(
        a_core.served() > 0 && c_core.served() > 0,
        "both peers served blocks: {} and {}",
        a_core.served(),
        c_core.served()
    );
    wait_until("the node to call itself synchronised", 30, || {
        b.sync_status().synchronized
    });
    assert!(b.spans().is_empty(), "nothing left in the queue");
    assert_eq!(b.queue_overview(), "[]");
    assert_eq!(b.sync_status().outgoing, 2);
}

/// **IPv6.** A node listening on IPv6 alone is dialled, handshaken and synced
/// from over IPv6: the protocol is the same whatever the address family.
#[test]
fn a_node_syncs_over_ipv6() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        eprintln!("skipped: no IPv6 loopback on this host");
        return;
    }
    let t = template();
    let genesis = make_block(&t, [0u8; 32], 0);
    let a_core = MemCore::new(&genesis);
    a_core.extend(40, &t);
    let b_core = MemCore::new(&genesis);

    let mut a_cfg = config(Vec::new());
    a_cfg.listen = None;
    a_cfg.listen_v6 = Some("[::1]:0".parse().unwrap());
    let a = Node::start(a_cfg, a_core.clone(), rng(1)).unwrap();
    assert!(a.local_addr().is_none());
    let a_v6 = a.local_addr_v6().expect("an IPv6 listener");

    // `b` listens on both families on one port, as a node does by default: it
    // advertises that port, and the ping-back reaches it over IPv6.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut b_cfg = config(vec![a_v6]);
    b_cfg.listen = Some(SocketAddr::from(([127, 0, 0, 1], port)));
    b_cfg.listen_v6 = Some(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)));
    let b = Node::start(b_cfg, b_core.clone(), rng(2)).unwrap();
    assert_eq!(
        b.local_addr().map(|a| a.port()),
        b.local_addr_v6().map(|a| a.port()),
        "one port for both families"
    );

    wait_until("the chain over IPv6", 60, || b_core.height() == 41);
    assert_eq!(b_core.tip(), a_core.tip());
    assert!(b.connections().iter().all(|c| c.address.is_ipv6()));
    wait_until("the IPv6 peer on the white list", 20, || {
        a.peer_lists()
            .0
            .iter()
            .any(|r| Some(r.addr) == b.local_addr_v6())
    });
}

/// A peer that goes away mid-sync gives back what it had not delivered, and
/// the other peer finishes the job.
#[test]
fn a_sync_finishes_when_a_peer_goes_away() {
    let (a, a_core, _c, _c_core, b, b_core) = behind_two(3_000);

    wait_until("the sync to start", 60, || b_core.height() > 100);
    a.stop();
    wait_until("the rest of the chain from the remaining peer", 120, || {
        b_core.height() == 3_001
    });
    assert_eq!(b_core.tip(), a_core.tip());
    wait_until("the node to call itself synchronised", 30, || {
        b.sync_status().synchronized
    });
}
