//! The built-in miner (`specs/09` §6.3, `specs/06` §4, `specs/03`).
//!
//! # Wownero mining is solo mining
//!
//! From HF 18 every block header carries a signature by the coinbase output's
//! one-time key, which only the holder of the address's **spend** key can
//! derive (`specs/06` §4.1). So the miner needs `--spendkey`, and `specs/09`
//! §6.3 asks a Rust daemon to refuse to mine at HF 18+ without it -- where the
//! C++ mines blocks the network then rejects. It also checks the key belongs to
//! the address, which turns a typo into an error at start rather than hours of
//! wasted work.
//!
//! The signature covers the nonce, so it is made again for every attempt; a
//! miner that signed once per template would submit nothing but rejects
//! (`specs/06` §4.2: "MUST NOT hoist the signature out of the loop").
//!
//! # Threads, nonces and the dataset
//!
//! Each worker builds its own templates and its own RandomWOW VM. Nonces are
//! the C++'s: one random starting point, each thread offset from it by its
//! index and stepping by the thread count, so no two search the same nonce.
//! The ~2.3 GiB dataset is built once per seed and shared; if it cannot be
//! allocated the miner falls back to light mode, slower but working.
//!
//! What this node cannot verify it does not mine: CryptoNight variants 2 and 4
//! (versions 9 to 12) are not implemented, and a template at those versions
//! stops the miner with that reason.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wow_consensus::hardfork::gates::{HF_VERSION_BLOCK_HEADER_MINER_SIG, RX_BLOCK_VERSION};
use wow_crypto::random::Rng;
use wow_crypto::types::{Hash256, PublicKey, SecretKey};
use wow_randomwow::vm::{mine_flags, verify_flags, Cache, Dataset, Vm};
use wow_types::address::Address;
use wow_types::block::Block;

use crate::template::Template;

const LOG: &str = "miner";
/// How long a worker hashes one template before fetching a fresh one, so new
/// pool transactions and a moving clock make it into the block.
const TEMPLATE_LIFETIME: Duration = Duration::from_secs(10);
/// Hashes between checks for a new tip, a stale template or a stop.
const CHECK_EVERY: u64 = 16;

/// `--spendkey`. Its `Debug` prints nothing of the key, because the options
/// it sits in derive `Debug`.
#[derive(Clone)]
pub struct SpendKey(SecretKey);

impl std::fmt::Debug for SpendKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SpendKey(..)")
    }
}

impl SpendKey {
    /// The hex form `--spendkey` takes.
    pub fn parse(hex: &str) -> Result<SpendKey, String> {
        let bytes: [u8; 32] =
            wow_crypto::hex::decode_array(hex.trim()).ok_or("--spendkey is not 32 bytes of hex")?;
        if !wow_crypto::sc_check(&bytes) {
            return Err("--spendkey is not a secret key: it is not a reduced scalar".into());
        }
        Ok(SpendKey(SecretKey(bytes)))
    }
}

/// `--vote` (`specs/06` §4.3): `yes` is 1, `no` is 2, and anything else is
/// refused rather than read as no vote.
pub fn parse_vote(s: &str) -> Result<u16, String> {
    match s {
        "yes" => Ok(1),
        "no" => Ok(2),
        other => Err(format!("--vote: expected yes or no, got `{other}`")),
    }
}

/// The address's secret keys, checked against it.
#[derive(Clone)]
pub struct Keys {
    spend: SecretKey,
    view: SecretKey,
}

impl Keys {
    /// Refuses a spend key that does not belong to `address`.
    ///
    /// The miner derives the view key from the spend key
    /// (`view_key_from_spend_key`, `specs/06` §4.1), so one key checks both
    /// halves of the address.
    pub fn new(key: &SpendKey, address: &Address) -> Result<Keys, String> {
        let spend = key.0;
        let view = wow_crypto::view_key_from_spend_key(&spend);
        let public = |k: &SecretKey| {
            wow_crypto::secret_key_to_public_key(k).ok_or("--spendkey is not a valid secret key")
        };
        if public(&spend)? != address.keys.spend_public_key
            || public(&view)? != address.keys.view_public_key
        {
            return Err(
                "--spendkey does not belong to the mining address, so every block signed \
                 with it would be rejected"
                    .into(),
            );
        }
        Ok(Keys { spend, view })
    }
}

/// Sign a block header as HF 18+ requires (`specs/06` §4.1): with the one-time
/// secret key of the coinbase output, over `sig_data`, the vote set first
/// because the signature covers it.
pub fn sign_header(
    block: &mut Block,
    tx_public: &PublicKey,
    output_key: &PublicKey,
    keys: &Keys,
    vote: u16,
    rng: &mut Rng,
) -> Result<(), String> {
    block.header.vote = vote;
    let derivation = wow_crypto::generate_key_derivation(tx_public, &keys.view)
        .ok_or("the coinbase public key does not decode")?;
    let one_time = wow_crypto::derive_secret_key(&derivation, 0, &keys.spend);
    let sig_data = block
        .sig_data()
        .ok_or("a block below version 18 has no signature field")?;
    block.header.signature = wow_crypto::generate_signature(rng, &sig_data, output_key, &one_time)
        .ok_or("the one-time key is not canonical")?;
    Ok(())
}

/// Where the miner gets work and hands in blocks.
pub trait Work: Send + Sync {
    /// A template paying `address`.
    fn template(&self, address: &Address, rng: &mut Rng) -> Result<Template, String>;
    /// Submit a solved block; true when it joined the main chain.
    fn submit(&self, blob: &[u8]) -> bool;
    /// The chain height, to notice a template going stale.
    fn height(&self) -> u64;
    /// Whether the node is catching up, when mining would only be on a stale
    /// tip.
    fn busy(&self) -> bool {
        false
    }
}

/// The proof-of-work function for one template's version.
enum Hasher {
    /// Versions 7 and 8.
    CryptoNightV1,
    RandomWow(Box<Vm>),
}

impl Hasher {
    fn hash(&mut self, blob: &[u8]) -> Result<Hash256, String> {
        match self {
            Hasher::CryptoNightV1 => {
                wow_crypto::cn::cn_slow_hash_v1(blob).map_err(|e| e.to_string())
            }
            Hasher::RandomWow(vm) => Ok(vm.hash(blob)),
        }
    }
}

/// The RandomWOW cache and dataset for the current seed.
type Seeded = Option<(Hash256, u32, Arc<Cache>, Option<Arc<Dataset>>)>;

/// Proof-of-work hashers, sharing one RandomWOW cache (and dataset) per seed.
pub struct PowCache {
    seed: Mutex<Seeded>,
    threads: usize,
    /// Build the dataset for fast hashing, or stay in light mode.
    full: bool,
}

impl PowCache {
    pub fn new(threads: usize, full: bool) -> PowCache {
        PowCache {
            seed: Mutex::new(None),
            threads: threads.max(1),
            full,
        }
    }

    fn hasher(&self, version: u8, seed: &Hash256) -> Result<Hasher, String> {
        if version < RX_BLOCK_VERSION {
            return match version {
                7 | 8 => Ok(Hasher::CryptoNightV1),
                v => Err(format!(
                    "a version {v} block needs CryptoNight {}, which is not implemented",
                    if v >= 11 { "variant 4" } else { "variant 2" }
                )),
            };
        }

        let mut slot = self.seed.lock().unwrap_or_else(|e| e.into_inner());
        if !matches!(&*slot, Some((s, ..)) if s == seed) {
            let flags = if self.full {
                mine_flags()
            } else {
                verify_flags()
            };
            let cache = Arc::new(Cache::new(flags, seed).map_err(|e| e.to_string())?);
            let dataset = if self.full {
                wow_log::info!(LOG, "building the RandomWOW dataset for a new seed");
                match Dataset::new(flags, &cache, self.threads) {
                    Ok(d) => Some(Arc::new(d)),
                    Err(e) => {
                        wow_log::warn!(LOG, "no full dataset ({e}); mining in light mode");
                        None
                    }
                }
            } else {
                None
            };
            *slot = Some((*seed, flags, cache, dataset));
        }
        let Some((_, flags, cache, dataset)) = &*slot else {
            return Err("no RandomWOW cache".into());
        };
        let vm = match dataset {
            Some(d) => Vm::full(*flags, cache.clone(), d.clone()),
            None => Vm::light(*flags, cache.clone()),
        }
        .map_err(|e| e.to_string())?;
        Ok(Hasher::RandomWow(Box::new(vm)))
    }
}

/// Search nonces from `start`, `step` apart, for one meeting the template's
/// difficulty, signing each attempt from HF 18 (`specs/06` §4.2).
///
/// `attempt` is told how many hashes have missed so far after each miss;
/// returning false gives up, which is `Ok(None)`.
#[allow(
    clippy::too_many_arguments,
    reason = "the search's inputs, each distinct"
)]
pub fn solve(
    t: &Template,
    keys: Option<&Keys>,
    vote: u16,
    start: u32,
    step: u32,
    pow: &PowCache,
    rng: &mut Rng,
    attempt: &mut dyn FnMut(u64) -> bool,
) -> Result<Option<Block>, String> {
    let version = t.block.header.major_version;
    let signs = version >= HF_VERSION_BLOCK_HEADER_MINER_SIG;
    if signs && keys.is_none() {
        return Err(
            "the chain is at hard fork 18 or later, where a block header must be signed with \
             the spend key of the address it pays, and there is no --spendkey"
                .into(),
        );
    }
    let mut hasher = pow.hasher(version, &t.seed_hash)?;
    let mut block = t.block.clone();
    let mut nonce = start;
    let mut missed = 0u64;
    loop {
        block.header.nonce = nonce;
        nonce = nonce.wrapping_add(step);
        if let (true, Some(k)) = (signs, keys) {
            sign_header(&mut block, &t.tx_public, &t.output_key, k, vote, rng)?;
        }
        let blob = block
            .hashing_blob()
            .ok_or("the template has no hashing blob")?;
        if wow_types::check_hash(&hasher.hash(&blob)?, t.difficulty) {
            return Ok(Some(block));
        }
        missed += 1;
        if !attempt(missed) {
            return Ok(None);
        }
    }
}

/// What `mining_status` reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub active: bool,
    /// Hashes per second since the miner started.
    pub speed: u64,
    pub threads: usize,
    pub address: String,
    pub blocks_found: u64,
}

struct State {
    running: AtomicBool,
    hashes: AtomicU64,
    found: AtomicU64,
    started: Instant,
    threads: usize,
    address: String,
}

/// A running miner.
pub struct Miner {
    state: Arc<State>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl Miner {
    /// Start `threads` workers. Refuses to start at HF 18+ without keys, since
    /// every block would be rejected.
    #[allow(
        clippy::too_many_arguments,
        reason = "the mining options, each distinct"
    )]
    pub fn start(
        work: Arc<dyn Work>,
        address: Address,
        address_text: String,
        threads: usize,
        keys: Option<Keys>,
        vote: u16,
        needs_signature: bool,
        rng: impl Fn() -> Result<Rng, String>,
    ) -> Result<Miner, String> {
        if needs_signature && keys.is_none() {
            return Err(
                "mining at hard fork 18 or later needs --spendkey: each block header must be \
                 signed with the spend key of the address the coinbase pays, and a block \
                 without that signature is rejected"
                    .into(),
            );
        }
        let threads = threads.max(1);
        let mut rngs = (0..threads).map(|_| rng()).collect::<Result<Vec<_>, _>>()?;
        let mut starter = [0u8; 4];
        rngs[0].fill(&mut starter);
        let starter = u32::from_le_bytes(starter);

        let state = Arc::new(State {
            running: AtomicBool::new(true),
            hashes: AtomicU64::new(0),
            found: AtomicU64::new(0),
            started: Instant::now(),
            threads,
            address: address_text,
        });
        let pow = Arc::new(PowCache::new(threads, true));

        let mut workers = Vec::with_capacity(threads);
        for (index, mut worker_rng) in rngs.into_iter().enumerate() {
            let (shared, work, keys, pow) =
                (state.clone(), work.clone(), keys.clone(), pow.clone());
            let start = starter.wrapping_add(index as u32);
            let spawned = std::thread::Builder::new()
                .name(format!("miner-{index}"))
                .spawn(move || {
                    worker(
                        &shared,
                        &*work,
                        &pow,
                        &address,
                        keys.as_ref(),
                        vote,
                        start,
                        &mut worker_rng,
                    )
                });
            match spawned {
                Ok(handle) => workers.push(handle),
                Err(e) => {
                    state.running.store(false, Ordering::SeqCst);
                    for w in workers {
                        let _ = w.join();
                    }
                    return Err(format!("cannot start a mining thread: {e}"));
                }
            }
        }
        wow_log::info!(LOG, "mining to {} on {threads} thread(s)", state.address);
        Ok(Miner {
            state,
            workers: Mutex::new(workers),
        })
    }

    pub fn is_running(&self) -> bool {
        self.state.running.load(Ordering::Relaxed)
    }

    /// Stop and wait for the workers.
    pub fn stop(&self) {
        self.state.running.store(false, Ordering::SeqCst);
        let workers: Vec<JoinHandle<()>> = self
            .workers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect();
        for w in workers {
            let _ = w.join();
        }
    }

    pub fn status(&self) -> Status {
        let elapsed = self.state.started.elapsed().as_secs().max(1);
        Status {
            active: self.is_running(),
            speed: self.state.hashes.load(Ordering::Relaxed) / elapsed,
            threads: self.state.threads,
            address: self.state.address.clone(),
            blocks_found: self.state.found.load(Ordering::Relaxed),
        }
    }
}

impl Drop for Miner {
    fn drop(&mut self) {
        self.stop();
    }
}

#[allow(clippy::too_many_arguments, reason = "what one worker thread owns")]
fn worker(
    state: &State,
    work: &dyn Work,
    pow: &PowCache,
    address: &Address,
    keys: Option<&Keys>,
    vote: u16,
    start: u32,
    rng: &mut Rng,
) {
    let step = state.threads as u32;
    let mut nonce = start;
    while state.running.load(Ordering::Relaxed) {
        if work.busy() {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        let t = match work.template(address, rng) {
            Ok(t) => t,
            Err(e) => {
                wow_log::warn!(LOG, "no block template: {e}");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };

        let deadline = Instant::now() + TEMPLATE_LIFETIME;
        let mut missed = 0u64;
        let result = solve(&t, keys, vote, nonce, step, pow, rng, &mut |n| {
            missed = n;
            state.hashes.fetch_add(1, Ordering::Relaxed);
            !(n.is_multiple_of(CHECK_EVERY)
                && (!state.running.load(Ordering::Relaxed)
                    || Instant::now() >= deadline
                    || work.height() != t.height))
        });
        // Past every nonce tried, including the one that won.
        nonce = nonce.wrapping_add((missed as u32).wrapping_add(1).wrapping_mul(step));

        match result {
            Ok(Some(block)) => {
                state.hashes.fetch_add(1, Ordering::Relaxed);
                if work.submit(&block.to_blob()) {
                    state.found.fetch_add(1, Ordering::Relaxed);
                    wow_log::info!(
                        LOG,
                        "mined block {} at height {}",
                        block
                            .block_id()
                            .map(|id| wow_crypto::hex::encode(&id))
                            .unwrap_or_default(),
                        t.height
                    );
                }
            }
            Ok(None) => {}
            Err(e) => {
                wow_log::error!(LOG, "{e}; mining stopped");
                state.running.store(false, Ordering::SeqCst);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wow_crypto::types::AccountPublicAddress;
    use wow_types::Network;

    fn rng(seed: u8) -> Rng {
        Rng::from_state([seed; wow_crypto::keccak::HASH_STATE_BYTES])
    }

    fn account(seed: u8) -> (SpendKey, Address) {
        let (_, spend) = rng(seed).generate_keys();
        let view = wow_crypto::view_key_from_spend_key(&spend);
        let keys = AccountPublicAddress {
            spend_public_key: wow_crypto::secret_key_to_public_key(&spend).unwrap(),
            view_public_key: wow_crypto::secret_key_to_public_key(&view).unwrap(),
        };
        (SpendKey(spend), Address::standard(Network::Mainnet, keys))
    }

    /// The spend key must be the address's: a wrong one would sign blocks the
    /// network rejects.
    #[test]
    fn a_spend_key_is_checked_against_the_address() {
        let (key, address) = account(1);
        assert!(Keys::new(&key, &address).is_ok());
        let (other, _) = account(2);
        assert!(Keys::new(&other, &address)
            .err()
            .unwrap()
            .contains("does not belong"));

        let hex = wow_crypto::hex::encode(&key.0 .0);
        assert_eq!(SpendKey::parse(&hex).unwrap().0, key.0);
        assert!(SpendKey::parse("abcd").unwrap_err().contains("32 bytes"));
        assert!(SpendKey::parse(&"ff".repeat(32)).is_err(), "not reduced");
        assert_eq!(format!("{key:?}"), "SpendKey(..)");

        assert_eq!(parse_vote("yes"), Ok(1));
        assert_eq!(parse_vote("no"), Ok(2));
        assert!(parse_vote("1").is_err());
    }

    /// **The HF 18 rule, end to end.** A header signed the way the miner signs
    /// it verifies the way consensus checks it: against the coinbase output
    /// key, over `sig_data`, which covers the vote and the nonce.
    #[test]
    fn a_signed_header_verifies_as_consensus_checks_it() {
        let (key, address) = account(3);
        let keys = Keys::new(&key, &address).unwrap();
        let mut r = rng(4);

        let (tx_public, tx_secret) = r.generate_keys();
        let d =
            wow_crypto::generate_key_derivation(&address.keys.view_public_key, &tx_secret).unwrap();
        let output_key =
            wow_crypto::derive_public_key(&d, 0, &address.keys.spend_public_key).unwrap();

        let mut block = Block::default();
        block.header.major_version = 18;
        block.header.minor_version = 18;
        block.miner_tx.prefix.version = 2;
        block.miner_tx.prefix.vin = vec![wow_types::TxIn::Gen { height: 1 }];
        let block = Block::from_blob(&block.to_blob()).unwrap();

        for vote in [0u16, 1, 2] {
            let mut b = block.clone();
            b.header.nonce = u32::from(vote) * 7;
            sign_header(&mut b, &tx_public, &output_key, &keys, vote, &mut r).unwrap();
            assert_eq!(b.header.vote, vote);
            assert!(wow_crypto::check_signature(
                &b.sig_data().unwrap(),
                &output_key,
                &b.header.signature
            ));

            // Moving the nonce afterwards breaks it: the signature has to be
            // made for every attempt.
            let mut moved = b.clone();
            moved.header.nonce += 1;
            assert!(!wow_crypto::check_signature(
                &moved.sig_data().unwrap(),
                &output_key,
                &moved.header.signature
            ));
        }
    }

    fn template_at(version: u8, difficulty: u128) -> Template {
        let mut block = Block::default();
        block.header.major_version = version;
        block.header.minor_version = version;
        block.miner_tx.prefix.version = 1;
        block.miner_tx.prefix.vin = vec![wow_types::TxIn::Gen { height: 1 }];
        Template {
            block: Block::from_blob(&block.to_blob()).unwrap(),
            height: 1,
            difficulty,
            expected_reward: 0,
            reserved_offset: 0,
            seed_height: 0,
            seed_hash: [0; 32],
            next_seed_hash: [0; 32],
            tx_public: PublicKey::ZERO,
            output_key: PublicKey::ZERO,
        }
    }

    /// The search takes the first nonce that meets the target, gives up when
    /// told to, and refuses what it cannot hash or sign.
    #[test]
    fn the_search_finds_stops_and_refuses() {
        let pow = PowCache::new(1, false);
        let mut r = rng(7);

        let found = solve(&template_at(7, 1), None, 0, 5, 3, &pow, &mut r, &mut |_| {
            true
        })
        .unwrap()
        .unwrap();
        assert_eq!(found.header.nonce, 5, "difficulty 1 takes the first hash");

        let mut seen = 0;
        let none = solve(
            &template_at(7, u128::MAX),
            None,
            0,
            0,
            3,
            &pow,
            &mut r,
            &mut |n| {
                seen = n;
                n < 3
            },
        )
        .unwrap();
        assert!(none.is_none());
        assert_eq!(seen, 3);

        let e = solve(&template_at(9, 1), None, 0, 0, 1, &pow, &mut r, &mut |_| {
            true
        })
        .unwrap_err();
        assert!(e.contains("variant 2"), "{e}");
        let e = solve(
            &template_at(18, 1),
            None,
            0,
            0,
            1,
            &pow,
            &mut r,
            &mut |_| true,
        )
        .unwrap_err();
        assert!(e.contains("--spendkey"), "{e}");
    }

    #[test]
    fn mining_past_hf18_without_keys_is_refused() {
        struct NoWork;
        impl Work for NoWork {
            fn template(&self, _: &Address, _: &mut Rng) -> Result<Template, String> {
                Err("unused".into())
            }
            fn submit(&self, _: &[u8]) -> bool {
                false
            }
            fn height(&self) -> u64 {
                0
            }
        }
        let (_, address) = account(5);
        let e = Miner::start(
            Arc::new(NoWork),
            address,
            "addr".into(),
            1,
            None,
            0,
            true,
            || Ok(rng(6)),
        )
        .err()
        .unwrap();
        assert!(e.contains("--spendkey"), "{e}");
    }
}
