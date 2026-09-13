//! Mining over RPC (`specs/11` §3, §4.1, §4.3; `specs/09` §6).
//!
//! # Templates at hard fork 18
//!
//! `get_block_template` is served at every version, since explorers and
//! monitoring read it, but from HF 18 a block built from it is rejected unless
//! whoever submits it signs the header with the spend key of the address it
//! pays (`specs/06` §4.1) -- which a pool cannot. `specs/11` §4.1 asks for a
//! warning in the log when it is called then, so an operator is not left
//! wondering why every submitted block fails.
//!
//! # `generateblocks`
//!
//! Regtest's: it mines at whatever difficulty the chain asks, which with
//! `--fixed-difficulty 1` is any hash. The C++ leaves the header unsigned, so
//! past HF 18 it only makes blocks that are refused; this one signs them when
//! the daemon has the address's `--spendkey`, and says why it cannot
//! otherwise.

use std::sync::Arc;

use serde_json::{json, Value};
use wow_consensus::hardfork::gates::{HF_VERSION_BLOCK_HEADER_MINER_SIG, RX_BLOCK_VERSION};
use wow_consensus::hardfork::HardFork;
use wow_crypto::random::Rng;
use wow_p2p::node::{BlockVerdict, Node};
use wow_storage::db::BlockchainDb;
use wow_types::address::{Address, AddressKind};

use super::admin::body_json;
use super::methods::{base, error, hex, internal, untrusted, with_difficulty, RpcError, RpcResult};
use super::Server;
use crate::miner::{self, Keys, Miner, PowCache, Work};
use crate::netsync::seeded_rng;
use crate::node::NodeCore;
use crate::template::{ExtraNonce, Template, TemplateError, MAX_RESERVE_SIZE};

const LOG: &str = "miner";

/// The chain and the network, as the miner uses them.
struct NodeWork {
    core: Arc<NodeCore>,
    p2p: Option<Arc<Node>>,
}

impl Work for NodeWork {
    fn template(&self, address: &Address, rng: &mut Rng) -> Result<Template, String> {
        self.core
            .block_template(address, &ExtraNonce::Reserve(0), rng)
            .map_err(|e| e.to_string())
    }

    fn submit(&self, blob: &[u8]) -> bool {
        submit(&self.core, self.p2p.as_deref(), blob).is_ok()
    }

    fn height(&self) -> u64 {
        self.core.height()
    }

    fn busy(&self) -> bool {
        self.p2p
            .as_ref()
            .is_some_and(|p| p.sync_status().busy_syncing)
    }
}

/// Add a mined block and announce it; the verdict when it did not join the
/// main chain.
fn submit(core: &NodeCore, p2p: Option<&Node>, blob: &[u8]) -> Result<(), BlockVerdict> {
    let (verdict, relay) = core.submit_block(blob);
    match verdict {
        BlockVerdict::Added => {
            if let (Some(p), Some(entry)) = (p2p, relay) {
                p.relay_block(&entry);
            }
            Ok(())
        }
        other => {
            wow_log::warn!(LOG, "a mined block was not accepted: {other:?}");
            Err(other)
        }
    }
}

fn writable(server: &Server) -> Result<&NodeCore, RpcError> {
    server.core().ok_or_else(|| {
        RpcError::new(
            error::UNSUPPORTED_RPC,
            "the database is open read-only, so no block can be added",
        )
    })
}

/// A main address on this node's network.
fn mining_address(server: &Server, text: &str) -> Result<Address, RpcError> {
    let address = Address::decode_for(text, server.config().network).map_err(|e| {
        RpcError::new(
            error::WRONG_WALLET_ADDRESS,
            format!("Failed to parse wallet address: {e}"),
        )
    })?;
    if address.kind == AddressKind::Subaddress {
        return Err(RpcError::new(
            error::MINING_TO_SUBADDRESS,
            "Mining to subaddress is not supported",
        ));
    }
    Ok(address)
}

/// The address's keys from `--spendkey`, when the daemon was given one.
fn keys_for(server: &Server, address: &Address) -> Result<Option<Keys>, RpcError> {
    server
        .config()
        .spendkey
        .as_ref()
        .map(|k| Keys::new(k, address))
        .transpose()
        .map_err(|e| RpcError::new(error::WRONG_PARAM, e))
}

fn template_error(e: TemplateError) -> RpcError {
    let code = match e {
        TemplateError::Subaddress => error::MINING_TO_SUBADDRESS,
        TemplateError::ReserveTooBig { .. } => error::TOO_BIG_RESERVE_SIZE,
        TemplateError::BadAddress => error::WRONG_WALLET_ADDRESS,
        TemplateError::Chain(_) => error::INTERNAL_ERROR,
    };
    RpcError::new(code, e.to_string())
}

fn wallet_address(params: &Value) -> Result<&str, RpcError> {
    params
        .get("wallet_address")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "wallet_address is missing"))
}

/// `prev_block`, which may only name the tip. Building on another block is
/// not supported, and a template quietly built on the tip instead would be
/// worse than a refusal.
fn check_prev_block(server: &Server, params: &Value) -> Result<(), RpcError> {
    let Some(text) = params
        .get("prev_block")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return Ok(());
    };
    let db = server.db();
    let tip = db
        .get_block_hash(db.height().saturating_sub(1))
        .map_err(internal)?;
    if wow_crypto::hex::decode(text).as_deref() == Some(&tip[..]) {
        Ok(())
    } else {
        Err(RpcError::new(
            error::WRONG_PARAM,
            "prev_block other than the current tip is not supported",
        ))
    }
}

/// `get_block_template` / `getblocktemplate` (`specs/11` §4.1).
pub fn get_block_template(server: &Server, params: &Value) -> RpcResult {
    let core = writable(server)?;
    let text = wallet_address(params)?;
    let reserve = params
        .get("reserve_size")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if reserve > MAX_RESERVE_SIZE as u64 {
        return Err(RpcError::new(
            error::TOO_BIG_RESERVE_SIZE,
            format!("Too big reserved size, maximum {MAX_RESERVE_SIZE}"),
        ));
    }
    let extra = match params
        .get("extra_nonce")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        Some(_) if reserve != 0 => {
            return Err(RpcError::new(
                error::WRONG_PARAM,
                "Cannot specify both a reserve_size and an extra_nonce",
            ))
        }
        Some(h) => ExtraNonce::Given(
            wow_crypto::hex::decode(h)
                .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "extra_nonce is not hex"))?,
        ),
        None => ExtraNonce::Reserve(reserve as usize),
    };
    let address = mining_address(server, text)?;
    check_prev_block(server, params)?;
    if server.sync_status().busy_syncing {
        return Err(RpcError::new(error::CORE_BUSY, "Core is busy"));
    }

    let mut rng = seeded_rng().map_err(internal)?;
    let t = core
        .block_template(&address, &extra, &mut rng)
        .map_err(template_error)?;
    let version = t.block.header.major_version;
    if version >= HF_VERSION_BLOCK_HEADER_MINER_SIG {
        wow_log::warn!(
            LOG,
            "get_block_template at hard fork {version}: a block built from it is rejected \
             unless its header is signed with the spend key of {text} (specs/06 §4.1)"
        );
    }

    let randomwow = version >= RX_BLOCK_VERSION;
    let mut m = base("OK", untrusted());
    m.insert("blocktemplate_blob".into(), json!(hex(&t.block.to_blob())));
    m.insert(
        "blockhashing_blob".into(),
        json!(t.block.hashing_blob().map(|b| hex(&b)).unwrap_or_default()),
    );
    m.insert("height".into(), json!(t.height));
    m.insert("expected_reward".into(), json!(t.expected_reward));
    m.insert("prev_hash".into(), json!(hex(&t.block.header.prev_id)));
    m.insert("reserved_offset".into(), json!(t.reserved_offset));
    m.insert("seed_height".into(), json!(t.seed_height));
    m.insert(
        "seed_hash".into(),
        json!(if randomwow {
            hex(&t.seed_hash)
        } else {
            String::new()
        }),
    );
    m.insert(
        "next_seed_hash".into(),
        json!(if randomwow && t.next_seed_hash != t.seed_hash {
            hex(&t.next_seed_hash)
        } else {
            String::new()
        }),
    );
    // Always 0 in a template: the vote goes in with the signature.
    m.insert("vote".into(), json!(0));
    Ok(with_difficulty(m, "difficulty", t.difficulty))
}

/// `generateblocks` **R**, regtest only (`specs/11` §4.3).
pub fn generateblocks(server: &Server, params: &Value) -> RpcResult {
    if !server.config().regtest {
        return Err(RpcError::new(
            error::REGTEST_REQUIRED,
            "Regtest required when generating blocks",
        ));
    }
    let core = writable(server)?;
    let count = params
        .get("amount_of_blocks")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "amount_of_blocks is missing"))?;
    let address = mining_address(server, wallet_address(params)?)?;
    check_prev_block(server, params)?;
    let keys = keys_for(server, &address)?;
    let mut nonce = params
        .get("starting_nonce")
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;

    let pow = PowCache::new(1, false);
    let mut rng = seeded_rng().map_err(internal)?;
    let mut blocks = Vec::new();
    let mut height = 0;
    for _ in 0..count {
        let t = core
            .block_template(&address, &ExtraNonce::Reserve(1), &mut rng)
            .map_err(template_error)?;
        let block = miner::solve(&t, keys.as_ref(), 0, nonce, 1, &pow, &mut rng, &mut |_| {
            true
        })
        .map_err(internal)?
        .ok_or_else(|| internal("the search stopped without a block"))?;
        nonce = block.header.nonce.wrapping_add(1);
        let id = block
            .block_id()
            .ok_or_else(|| internal("the mined block has no id"))?;
        submit(core, server.p2p(), &block.to_blob()).map_err(|v| {
            RpcError::new(
                error::BLOCK_NOT_ACCEPTED,
                format!("Block not accepted: {v:?}"),
            )
        })?;
        blocks.push(hex(&id));
        height = t.height;
    }
    let mut m = base("OK", untrusted());
    m.insert("height".into(), json!(height));
    m.insert("blocks".into(), json!(blocks));
    Ok(Value::Object(m))
}

/// Start the built-in miner: `/start_mining`, the console and
/// `--start-mining` all come here.
pub fn start(server: &Server, text: &str, threads: usize) -> Result<(), RpcError> {
    let core = server.core_handle().ok_or_else(|| {
        RpcError::new(
            error::UNSUPPORTED_RPC,
            "the database is open read-only, so nothing mined could be added",
        )
    })?;
    let address = mining_address(server, text)?;
    let keys = keys_for(server, &address)?;
    let needs_signature = HardFork::new(server.config().network).required_version(core.height())
        >= HF_VERSION_BLOCK_HEADER_MINER_SIG;

    let mut slot = server.miner();
    if slot.as_ref().is_some_and(Miner::is_running) {
        return Err(RpcError::new(error::WRONG_PARAM, "Already mining"));
    }
    let work: Arc<dyn Work> = Arc::new(NodeWork {
        core,
        p2p: server.p2p_handle(),
    });
    let miner = Miner::start(
        work,
        address,
        text.to_string(),
        threads,
        keys,
        server.config().vote,
        needs_signature,
        seeded_rng,
    )
    .map_err(|e| RpcError::new(error::WRONG_PARAM, e))?;
    *slot = Some(miner);
    Ok(())
}

/// `/start_mining` **R**.
pub fn start_mining(server: &Server, body: &[u8]) -> RpcResult {
    let req = body_json(body)?;
    if req
        .get("do_background_mining")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(RpcError::new(
            error::UNSUPPORTED_RPC,
            "background mining is not implemented",
        ));
    }
    let text = req
        .get("miner_address")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(error::WRONG_PARAM, "miner_address is missing"))?;
    let threads = req
        .get("threads_count")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .max(1) as usize;
    start(server, text, threads)?;
    Ok(Value::Object(base("OK", untrusted())))
}

/// `/stop_mining` **R**.
pub fn stop_mining(server: &Server) -> RpcResult {
    let miner = server.miner().take();
    match miner {
        Some(m) if m.is_running() => {
            m.stop();
            wow_log::info!(LOG, "mining stopped");
            Ok(Value::Object(base("OK", untrusted())))
        }
        _ => Err(RpcError::new(error::WRONG_PARAM, "Mining never started")),
    }
}

/// `mining_status`'s `pow_algorithm` for a version.
fn pow_algorithm(version: u8) -> &'static str {
    match version {
        0..=6 => "Cryptonight",
        7 | 8 => "CNv1 (Cryptonight variant 1)",
        9 | 10 => "CNv2 (Cryptonight variant 2)",
        11 | 12 => "CNv4 (Cryptonight variant 4)",
        _ => "RandomWOW",
    }
}

/// `/mining_status` **R**.
pub fn mining_status(server: &Server) -> RpcResult {
    let core = writable(server)?;
    let status = server
        .miner()
        .as_ref()
        .map(Miner::status)
        .unwrap_or_default();
    let next = core.next_block().map_err(internal)?;
    let version = HardFork::new(server.config().network).required_version(next.height);
    let reward = wow_consensus::emission::get_block_reward(
        next.median_weight,
        0,
        next.already_generated_coins,
        version,
    )
    .unwrap_or(0);

    let mut m = base("OK", untrusted());
    m.insert("active".into(), json!(status.active));
    m.insert(
        "speed".into(),
        json!(if status.active { status.speed } else { 0 }),
    );
    m.insert(
        "threads_count".into(),
        json!(if status.active { status.threads } else { 0 }),
    );
    m.insert(
        "address".into(),
        json!(if status.active {
            status.address
        } else {
            String::new()
        }),
    );
    m.insert("pow_algorithm".into(), json!(pow_algorithm(version)));
    m.insert("is_background_mining_enabled".into(), json!(false));
    m.insert("bg_idle_threshold".into(), json!(0));
    m.insert("bg_min_idle_seconds".into(), json!(0));
    m.insert("bg_ignore_battery".into(), json!(false));
    m.insert("bg_target".into(), json!(0));
    m.insert(
        "block_target".into(),
        json!(wow_consensus::constants::DIFFICULTY_TARGET_V2),
    );
    m.insert("block_reward".into(), json!(reward));
    Ok(with_difficulty(m, "difficulty", next.difficulty))
}
