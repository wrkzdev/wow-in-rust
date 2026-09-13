//! The ZMQ interface (`specs/09` §3.2; `zmq_server.cpp`, `daemon_handler.cpp`
//! and `zmq_pub.cpp` in the C++).
//!
//! Two sockets, speaking ZMTP through [`wow_zmq`]:
//!
//! * a REP socket on `--zmq-rpc-bind-ip`:`--zmq-rpc-bind-port`, answering
//!   the C++'s JSON-RPC methods ([`handler`]). On unless `--no-zmq`, as in the
//!   C++;
//! * with `--zmq-pub`, a PUB socket announcing blocks, miner data and pool
//!   additions ([`publish`]).
//!
//! # Not the HTTP RPC
//!
//! Other method names, other JSON -- a transaction is an object, not a blob
//! -- and other errors. What a C++ client expects of this socket is what it
//! serves. It has neither TLS nor a login, which is why binding it beyond
//! loopback needs `--confirm-zmq-rpc-external-bind`.

pub mod handler;
pub mod json;
pub mod publish;

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use wow_zmq::{Publisher, RepServer};

use crate::cli::Config;
use crate::node::NodeCore;
use crate::rpc::Server;

const LOG: &str = "global";

/// The listeners, bound before anything else starts, so a port already in use
/// stops the node while there is nothing yet to unwind.
pub struct Bound {
    rpc: TcpListener,
    publishers: Vec<TcpListener>,
}

pub fn bind(cfg: &Config) -> Result<Bound, String> {
    let bare = cfg
        .zmq_rpc_bind_ip
        .trim_start_matches('[')
        .trim_end_matches(']');
    let ip: std::net::IpAddr = bare
        .parse()
        .map_err(|_| "Invalid IP address given for --zmq-rpc-bind-ip".to_string())?;
    let addr = SocketAddr::new(ip, cfg.zmq_rpc_bind_port);
    let rpc = wow_p2p::net::listen(addr)
        .map_err(|e| format!("Failed to add TCP socket({addr}) to ZMQ RPC Server: {e}"))?;
    let publishers = cfg
        .zmq_pub
        .iter()
        .map(|a| {
            wow_p2p::net::listen(*a)
                .map_err(|e| format!("Failed to initialize zmq_pub on tcp://{a}: {e}"))
        })
        .collect::<Result<_, _>>()?;
    Ok(Bound { rpc, publishers })
}

/// The sockets, serving.
pub struct Zmq {
    rpc: RepServer,
    publisher: Option<Arc<Publisher>>,
}

/// Serve the bound sockets. The publisher hears from `core`; a read-only node
/// has none, and publishes nothing.
pub fn start(
    bound: Bound,
    server: Arc<Server>,
    core: Option<&NodeCore>,
    restricted: bool,
) -> Result<Zmq, String> {
    let handler = handler::Handler::new(server, restricted);
    let rpc = RepServer::start(bound.rpc, Arc::new(move |req: &[u8]| handler.handle(req)))
        .map_err(|e| format!("cannot start the ZMQ RPC server: {e}"))?;
    wow_log::info!(
        LOG,
        "ZMQ RPC listening on tcp://{}{}",
        rpc.local_addr(),
        if restricted { " (restricted)" } else { "" }
    );

    let publisher = if bound.publishers.is_empty() {
        None
    } else {
        let p = Arc::new(
            Publisher::start(bound.publishers)
                .map_err(|e| format!("cannot start the ZMQ publisher: {e}"))?,
        );
        for a in p.local_addrs() {
            wow_log::info!(LOG, "ZMQ publishing on tcp://{a}");
        }
        match core {
            Some(c) => c.set_listener(Arc::new(publish::Publish::new(p.clone()))),
            None => wow_log::warn!(
                LOG,
                "--zmq-pub: the database is open read-only, so nothing will be published"
            ),
        }
        Some(p)
    };
    Ok(Zmq { rpc, publisher })
}

impl Zmq {
    pub fn stop(&self) {
        self.rpc.stop();
        if let Some(p) = &self.publisher {
            p.stop();
        }
    }
}
