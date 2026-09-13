//! The publisher's messages (`src/rpc/zmq_pub.cpp`).
//!
//! Each is `topic:json` -- the topic bare, then a colon, then JSON -- and is
//! built only when someone has subscribed to a prefix of its topic, which
//! spares serialising blocks nobody is listening for.

use std::sync::Arc;

use serde_json::{json, Value};
use wow_types::block::Block;
use wow_zmq::Publisher;

use super::json;
use crate::node::{Event, Listener, MinerData, PoolTx};

pub const CHAIN_FULL: &str = "json-full-chain_main";
pub const CHAIN_MINIMAL: &str = "json-minimal-chain_main";
pub const MINER_DATA: &str = "json-full-miner_data";
pub const TXPOOL_FULL: &str = "json-full-txpool_add";
pub const TXPOOL_MINIMAL: &str = "json-minimal-txpool_add";

/// The node's announcements, published.
pub struct Publish {
    publisher: Arc<Publisher>,
}

impl Publish {
    pub fn new(publisher: Arc<Publisher>) -> Publish {
        Publish { publisher }
    }

    fn send(&self, topic: &str, body: impl FnOnce() -> Value) {
        if !self.publisher.wants(topic) {
            return;
        }
        let mut message = Vec::with_capacity(topic.len() + 256);
        message.extend_from_slice(topic.as_bytes());
        message.push(b':');
        message.extend_from_slice(body().to_string().as_bytes());
        self.publisher.publish(&message);
    }
}

impl Listener for Publish {
    fn wants(&self, event: Event) -> bool {
        let wants = |topic| self.publisher.wants(topic);
        match event {
            Event::TxpoolAdd => wants(TXPOOL_FULL) || wants(TXPOOL_MINIMAL),
            Event::MinerData => wants(MINER_DATA),
            Event::ChainMain => wants(CHAIN_FULL) || wants(CHAIN_MINIMAL),
        }
    }

    fn txpool_add(&self, txs: &[PoolTx]) {
        self.send(TXPOOL_FULL, || {
            Value::Array(
                txs.iter()
                    .map(|t| json::transaction(&t.tx, false))
                    .collect(),
            )
        });
        self.send(TXPOOL_MINIMAL, || {
            Value::Array(
                txs.iter()
                    .map(|t| {
                        json!({
                            "id": json::hex(&t.id),
                            "blob_size": t.blob_size,
                            "weight": t.weight,
                            "fee": t.fee,
                        })
                    })
                    .collect(),
            )
        });
    }

    fn miner_data(&self, d: &MinerData) {
        self.send(MINER_DATA, || {
            json!({
                "major_version": d.major_version,
                "height": d.height,
                "prev_id": json::hex(&d.prev_id),
                "seed_hash": json::hex(&d.seed_hash),
                // `cryptonote::hex(difficulty_type)`: 0x and no leading zeros.
                "difficulty": format!("{:#x}", d.difficulty),
                "median_weight": d.median_weight,
                "already_generated_coins": d.already_generated_coins,
                "tx_backlog": d.tx_backlog.iter().map(|(id, weight, fee)| json!({
                    "id": json::hex(id),
                    "weight": weight,
                    "fee": fee,
                })).collect::<Vec<_>>(),
            })
        });
    }

    fn chain_main(&self, height: u64, block: &Block) {
        self.send(CHAIN_FULL, || json!([json::block(block)]));
        self.send(CHAIN_MINIMAL, || {
            json!({
                "first_height": height,
                "first_prev_id": json::hex(&block.header.prev_id),
                "ids": [json::hex(&block.block_id().unwrap_or_default())],
            })
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};
    use wow_types::tx::Transaction;
    use wow_zmq::SubSocket;

    fn publisher() -> (Arc<Publisher>, Publish) {
        let p =
            Arc::new(Publisher::start(vec![TcpListener::bind("127.0.0.1:0").unwrap()]).unwrap());
        (p.clone(), Publish::new(p))
    }

    fn subscribe(p: &Arc<Publisher>, publish: &Publish, prefix: &[u8], event: Event) -> SubSocket {
        let mut s = SubSocket::connect(p.local_addrs()[0], Duration::from_secs(5)).unwrap();
        s.subscribe(prefix).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !publish.wants(event) {
            assert!(Instant::now() < deadline, "the subscription never arrived");
            std::thread::sleep(Duration::from_millis(10));
        }
        s
    }

    fn split(message: Vec<u8>) -> (String, Value) {
        let text = String::from_utf8(message).unwrap();
        let (topic, body) = text.split_once(':').unwrap();
        (topic.to_string(), serde_json::from_str(body).unwrap())
    }

    #[test]
    fn miner_data_is_published_in_the_cpp_form() {
        let (p, publish) = publisher();
        assert!(!publish.wants(Event::MinerData), "nobody listens yet");
        let mut sub = subscribe(&p, &publish, b"json-full-miner", Event::MinerData);
        assert!(!publish.wants(Event::ChainMain));

        publish.miner_data(&MinerData {
            major_version: 20,
            height: 7,
            prev_id: [1; 32],
            seed_hash: [2; 32],
            difficulty: 0x1234,
            median_weight: 300_000,
            already_generated_coins: 5,
            tx_backlog: vec![([3; 32], 1_500, 42)],
        });
        let (topic, v) = split(sub.recv().unwrap());
        assert_eq!(topic, MINER_DATA);
        assert_eq!(v["difficulty"], "0x1234");
        assert_eq!(v["height"], 7);
        assert_eq!(v["prev_id"], "01".repeat(32));
        assert_eq!(
            v["tx_backlog"],
            json!([{"id": "03".repeat(32), "weight": 1_500, "fee": 42}])
        );
    }

    #[test]
    fn a_minimal_txpool_subscriber_gets_ids_and_sizes_only() {
        let (p, publish) = publisher();
        let mut sub = subscribe(&p, &publish, b"json-minimal", Event::TxpoolAdd);
        let blob = std::fs::read(format!(
            "{}/../../tests/corpus/txs/TX1",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let tx = Transaction::from_blob(&blob).unwrap();
        publish.txpool_add(&[PoolTx {
            id: [9; 32],
            tx,
            blob_size: blob.len(),
            weight: 2_000,
            fee: 77,
        }]);
        let (topic, v) = split(sub.recv().unwrap());
        assert_eq!(topic, TXPOOL_MINIMAL);
        assert_eq!(
            v,
            json!([{"id": "09".repeat(32), "blob_size": blob.len(), "weight": 2_000, "fee": 77}])
        );
    }
}
