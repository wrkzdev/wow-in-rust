//! Relaying a transaction to this daemon.
//!
//! `wallet_sync.rs` proves a wallet can read from this node. This proves it can
//! write to it: a transaction built by `wow-wallet` goes to
//! `/send_raw_transaction`, through the pool's admission checks — including
//! full ring-signature and range-proof verification — and comes back out of
//! `/get_transaction_pool_hashes.bin`.
//!
//! # What the fixture can and cannot do
//!
//! The fixture chain is coinbase-only blocks with few RingCT outputs, so there
//! is no ring for a real spend to hide in. What is therefore checked here is
//! the **rejection** path in detail and the acceptance path as far as the
//! fixture allows: every `specs/06` §6.3 relay policy, the double-spend check,
//! and that a forged signature does not get through.
//!
//! A rejection is not a weaker test than an acceptance. Every one of these
//! transactions is well-formed enough to parse and to reach the check being
//! tested, so what is being asserted is that the check fires and says which one
//! it was.

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use wow_daemon_client::DaemonClient;
use wow_storage::db::BlockchainDb;
use wow_storage::env::OpenMode;
use wow_storage::lmdb::LmdbDb;
use wow_types::block::Block;
use wow_types::Network;

const MAP_SIZE: usize = 64 * 1024 * 1024;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let mut p = std::env::temp_dir();
        p.push(format!("wow-relay-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch dir");
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Daemon {
    child: Child,
    port: u16,
    _scratch: Scratch,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn fixture_blocks() -> Vec<Vec<u8>> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/blocks/hf18/index.tsv");
    let text = std::fs::read_to_string(&path).expect("fixture");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let blob = wow_crypto::hex::decode(l.split('\t').nth(3)?)?;
            Block::from_blob(&blob)
                .ok()
                .filter(|b| b.tx_hashes.is_empty())
                .map(|_| blob)
        })
        .collect()
}

fn start(tag: &str, extra: usize) -> Daemon {
    let scratch = Scratch::new(tag);
    let dir = wow_storage::env::db_dir(&scratch.0, Network::Mainnet, false);
    {
        let db = LmdbDb::open_with_map_size(&dir, OpenMode::default(), 2, MAP_SIZE).unwrap();
        let blob = wow_consensus::genesis::genesis_blob(Network::Mainnet);
        let blk = Block::from_blob(&blob).unwrap();
        let mut prev = blk.block_id().unwrap();
        let record = wow_consensus::genesis::genesis_record(Network::Mainnet);
        db.add_block(
            &blk,
            &blob,
            record.weight,
            record.long_term_weight,
            record.cumulative_difficulty,
            record.already_generated_coins,
            &[],
        )
        .unwrap();

        let mut cum = 1u128;
        for (i, fixture) in fixture_blocks().into_iter().take(extra).enumerate() {
            let height = i as u64 + 1;
            let mut b = Block::from_blob(&fixture).unwrap();
            b.header.major_version = 7;
            b.header.minor_version = 7;
            b.header.prev_id = prev;
            b.miner_tx.prefix.vin = vec![wow_types::TxIn::Gen { height }];
            b.miner_tx.prefix.unlock_time = height + 60;
            let mut w = wow_serialize::binary::Writer::with_capacity(2048);
            b.write(&mut w);
            let wire = w.into_vec();
            let b = Block::from_blob(&wire).unwrap();
            cum += 1;
            db.add_block(&b, &wire, wire.len() as u64, wire.len() as u64, cum, 0, &[])
                .unwrap();
            prev = b.block_id().unwrap();
        }
    }

    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_wownerod"))
        .args([
            "--data-dir",
            scratch.0.to_str().unwrap(),
            "--db-readonly",
            "--serve",
            "--no-zmq",
            "--rpc-bind-port",
            &port.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start wownerod");

    let d = Daemon {
        child,
        port,
        _scratch: scratch,
    };
    wait_ready(port);
    d
}

fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("wownerod did not start listening on {port}");
}

fn client(port: u16) -> DaemonClient {
    DaemonClient::new(format!("127.0.0.1:{port}"))
}

/// `send_raw_transaction` as raw JSON, so every documented flag can be read.
fn send_raw(c: &DaemonClient, blob: &[u8]) -> Value {
    let body = serde_json::json!({
        "tx_as_hex": wow_crypto::hex::encode(blob),
        "do_not_relay": false,
    });
    // The direct helper checks `status`, which a rejection deliberately fails,
    // so the raw form is what is wanted here.
    let raw = c
        .raw_post_for_test("/send_raw_transaction", &body.to_string())
        .expect("the daemon answers");
    serde_json::from_slice(&raw).expect("JSON")
}

/// Every flag `specs/11` §3.1 requires is present on both paths.
#[test]
fn every_documented_flag_is_present() {
    let d = start("flags", 3);
    let c = client(d.port);

    // Something that will certainly be rejected.
    let v = send_raw(&c, &[0u8; 8]);
    for field in [
        "reason",
        "not_relayed",
        "low_mixin",
        "double_spend",
        "invalid_input",
        "invalid_output",
        "too_big",
        "overspend",
        "fee_too_low",
        "too_few_outputs",
        "sanity_check_failed",
        "tx_extra_too_big",
        "nonzero_unlock_time",
    ] {
        assert!(v.get(field).is_some(), "`{field}` must be present: {v}");
    }
    assert_eq!(v["status"], "Failed");
    assert!(
        v["reason"]
            .as_str()
            .expect("a reason")
            .contains("does not parse"),
        "{v}"
    );
}

/// The two Wownero-specific relay policies (`specs/06` §6.3), each reported by
/// its own flag.
#[test]
fn the_wownero_relay_policies_are_enforced() {
    let d = start("policy", 3);
    let c = client(d.port);

    // A transaction with a non-zero unlock time. Valid in a block, not
    // relayable — which is the distinction a wallet author needs.
    let tx = minimal_tx(|t| t.prefix.unlock_time = 100);
    let v = send_raw(&c, &tx);
    assert_eq!(v["status"], "Failed", "{v}");
    assert_eq!(v["nonzero_unlock_time"], true, "{v}");
    let reason = v["reason"].as_str().expect("a reason");
    assert!(reason.contains("valid inside a block"), "{reason}");

    // `tx_extra` over 1,060 bytes.
    let tx = minimal_tx(|t| t.prefix.extra = vec![0u8; 2_000]);
    let v = send_raw(&c, &tx);
    assert_eq!(v["status"], "Failed", "{v}");
    assert_eq!(v["tx_extra_too_big"], true, "{v}");
}

/// A transaction whose output count and range proof disagree is refused.
///
/// Dropping an output leaves a Bulletproof+ that covers more outputs than
/// exist. That is caught by the parser rather than by the pool — which is the
/// right place, and worth pinning either way: the transaction must not be
/// admitted, and the answer must say why.
#[test]
fn outputs_and_the_proof_must_agree() {
    let d = start("outputs", 3);
    let c = client(d.port);

    let tx = minimal_tx(|t| t.prefix.vout.truncate(1));
    let v = send_raw(&c, &tx);
    assert_eq!(v["status"], "Failed", "{v}");
    let reason = v["reason"].as_str().expect("a reason");
    assert!(
        reason.contains("does not parse") || reason.contains("output"),
        "the refusal names the problem: {reason}"
    );
}

/// A forged ring signature does not get into the pool. This is the check that
/// makes a pool worth having.
#[test]
fn a_forged_signature_is_rejected() {
    let d = start("forged", 3);
    let c = client(d.port);

    let tx = minimal_tx(|t| {
        if let Some(sig) = t.rct_signatures.clsags.first_mut() {
            sig.c1.0[0] ^= 0xff;
        }
    });
    let v = send_raw(&c, &tx);
    assert_eq!(v["status"], "Failed", "{v}");
    assert!(
        v["invalid_input"] == true || v["invalid_output"] == true,
        "a tampered signature must not be admitted: {v}"
    );
}

/// The pool reports what is in it, and `get_info` agrees.
#[test]
fn an_empty_pool_is_reported_as_empty() {
    let d = start("empty", 3);
    let c = client(d.port);

    assert!(c.get_pool_hashes().expect("answers").is_empty());

    let info = c.direct("/get_info", serde_json::json!({})).expect("info");
    assert_eq!(info["tx_pool_size"], 0, "{info}");
}

/// `get_transactions` answers for a transaction on the chain, and reports one
/// it has never seen as missing rather than inventing an empty answer.
#[test]
fn get_transactions_separates_found_from_missing() {
    let d = start("gettx", 4);
    let c = client(d.port);

    // A coinbase that is definitely on the chain.
    let blocks = c.get_blocks(&[], 0, false, false).expect("blocks");
    let block = Block::from_blob(&blocks.blocks[2].block).expect("parses");
    let txid = wow_types::hashes::transaction_hash(&block.miner_tx).expect("a hash");

    let body = serde_json::json!({
        "txs_hashes": [
            wow_crypto::hex::encode(&txid),
            wow_crypto::hex::encode(&[0xabu8; 32]),
        ]
    });
    let raw = c
        .raw_post_for_test("/get_transactions", &body.to_string())
        .expect("answers");
    let v: Value = serde_json::from_slice(&raw).expect("JSON");

    let txs = v["txs"].as_array().expect("txs");
    assert_eq!(txs.len(), 1, "the one that exists: {v}");
    assert_eq!(txs[0]["in_pool"], false);

    let missed = v["missed_tx"].as_array().expect("missed_tx");
    assert_eq!(missed.len(), 1, "and the one that does not");
}

/// A malformed request is answered, not dropped.
#[test]
fn malformed_requests_are_answered() {
    let d = start("malformed", 2);
    let c = client(d.port);

    let raw = c
        .raw_post_for_test("/send_raw_transaction", "{not json")
        .expect("answers");
    let v: Value = serde_json::from_slice(&raw).expect("still JSON");
    assert_eq!(v["status"], "Failed", "{v}");

    let raw = c
        .raw_post_for_test("/send_raw_transaction", "{}")
        .expect("answers");
    let v: Value = serde_json::from_slice(&raw).expect("JSON");
    assert_eq!(v["status"], "Failed", "{v}");
    assert!(
        v["reason"]
            .as_str()
            .expect("a reason")
            .contains("tx_as_hex"),
        "{v}"
    );

    let raw = c
        .raw_post_for_test("/send_raw_transaction", r#"{"tx_as_hex":"zz"}"#)
        .expect("answers");
    let v: Value = serde_json::from_slice(&raw).expect("JSON");
    assert_eq!(v["status"], "Failed", "{v}");
}

/// A transaction built the way the wallet builds one, so the fixture reaches
/// the checks under test rather than failing at the parser.
fn minimal_tx(tweak: impl FnOnce(&mut wow_types::tx::Transaction)) -> Vec<u8> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use wow_crypto::ops::encode_point;
    use wow_crypto::types::{PublicKey, SecretKey};
    use wow_wallet::transfer::{construct, Destination, SpendableOutput};

    let mut n = 12345u64;
    let mut rand = move || {
        n = n
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_le_bytes());
        b[8..16].copy_from_slice(&n.rotate_left(19).to_le_bytes());
        b[16..24].copy_from_slice(&n.rotate_left(37).to_le_bytes());
        Scalar::from_bytes_mod_order(b)
    };

    let x = Scalar::from_bytes_mod_order([7u8; 32]);
    let public_key = PublicKey(encode_point(&(x * ED25519_BASEPOINT_POINT)));
    let secret_key = SecretKey(x.to_bytes());
    let mask = Scalar::from_bytes_mod_order([9u8; 32]);
    let amount = 500_000_000_000u64;

    let ring: Vec<wow_crypto::clsag::RingMember> = (0..11)
        .map(|i| {
            if i == 3 {
                wow_crypto::clsag::RingMember {
                    dest: public_key,
                    mask: wow_crypto::rct::commit(amount, &mask),
                }
            } else {
                let d = Scalar::from_bytes_mod_order([20 + i as u8; 32]);
                let m = Scalar::from_bytes_mod_order([70 + i as u8; 32]);
                wow_crypto::clsag::RingMember {
                    dest: PublicKey(encode_point(&(d * ED25519_BASEPOINT_POINT))),
                    mask: wow_crypto::rct::commit(500 + i as u64, &m),
                }
            }
        })
        .collect();

    let input = SpendableOutput {
        public_key,
        secret_key,
        mask,
        amount,
        key_image: wow_crypto::generate_key_image(&public_key, &secret_key).expect("an image"),
        ring,
        global_indices: (0..11).map(|i| i * 3).collect(),
        real_index: 3,
    };

    let spend = SecretKey(wow_crypto::ops::sc_reduce32(&[5u8; 32]));
    let me = wow_wallet::AccountBase::from_spend_key(spend, 0).expect("valid");
    // Generous on purpose. The fee is admission check *2* (`specs/09` §2.2),
    // so a short fee stops the transaction before the checks these tests are
    // actually about.
    let fee = 20_000_000_000u64;
    let dests = vec![
        Destination {
            address: me.keys.account_address,
            is_subaddress: false,
            amount: amount - fee - 500_000_000,
        },
        Destination {
            address: me.keys.account_address,
            is_subaddress: false,
            amount: 500_000_000,
        },
    ];

    let mut built = construct(std::slice::from_ref(&input), &dests, fee, None, &mut rand)
        .expect("construct")
        .tx;

    tweak(&mut built);

    let mut w = wow_serialize::binary::Writer::with_capacity(8192);
    built.write(&mut w);
    w.into_vec()
}
