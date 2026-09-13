//! The server sockets: [`RepServer`], answering requests, and [`Publisher`],
//! fanning messages out to subscribers.
//!
//! Each connection is a thread, as elsewhere in the node. Stopping a server
//! shuts every connection's socket down, which ends its blocking read.

use std::collections::HashMap;
use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::zmtp::{self, Frame, SocketType, ZmtpError, MAX_CONTROL_FRAME};

const LOG: &str = "net.zmq";
/// A peer has this long to finish its greeting and READY.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// `ZMQ_SNDHWM`'s default: messages queued for one subscriber before more
/// are dropped.
const SUBSCRIBER_QUEUE: usize = 1_000;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A request handler: the request's body in, the reply's body out.
pub type Handler = dyn Fn(&[u8]) -> Vec<u8> + Send + Sync;

/// The open connections, to shut down when the server stops.
#[derive(Default)]
struct Connections {
    next: AtomicU64,
    open: Mutex<HashMap<u64, TcpStream>>,
}

impl Connections {
    fn add(&self, s: &TcpStream) -> Option<u64> {
        let handle = s.try_clone().ok()?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        lock(&self.open).insert(id, handle);
        Some(id)
    }

    fn remove(&self, id: u64) {
        lock(&self.open).remove(&id);
    }

    fn close_all(&self) {
        for (_, s) in lock(&self.open).drain() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

fn accept_loop(
    listener: TcpListener,
    stopped: impl Fn() -> bool,
    name: &'static str,
    serve: Arc<dyn Fn(TcpStream) + Send + Sync>,
) {
    if listener.set_nonblocking(true).is_err() {
        wow_log::error!(LOG, "cannot poll a ZMQ listener; it accepts nothing");
        return;
    }
    while !stopped() {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_nodelay(true);
                let serve = serve.clone();
                let _ = std::thread::Builder::new()
                    .name(name.into())
                    .spawn(move || serve(stream));
            }
            Err(_) => std::thread::sleep(ACCEPT_POLL),
        }
    }
}

fn log_end(what: &str, e: ZmtpError) {
    if !matches!(e, ZmtpError::Closed) {
        wow_log::debug!(LOG, "{what}: {e}");
    }
}

/// A REP socket, as `--zmq-rpc-bind-port` serves: each request from a REQ or
/// DEALER peer is answered by the handler, one at a time per connection.
pub struct RepServer {
    stop: Arc<AtomicBool>,
    connections: Arc<Connections>,
    thread: Mutex<Option<JoinHandle<()>>>,
    local_addr: SocketAddr,
}

impl RepServer {
    /// Listen on `listener` and answer with `handler`.
    pub fn start(listener: TcpListener, handler: Arc<Handler>) -> std::io::Result<RepServer> {
        let local_addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Connections::default());
        let (s, c) = (stop.clone(), connections.clone());
        let serve: Arc<dyn Fn(TcpStream) + Send + Sync> = Arc::new(move |stream| {
            serve_rep(stream, &*handler, &c, &s);
        });
        let s = stop.clone();
        let thread = std::thread::Builder::new()
            .name("zmq-rpc".into())
            .spawn(move || {
                accept_loop(
                    listener,
                    || s.load(Ordering::Relaxed),
                    "zmq-rpc-conn",
                    serve,
                )
            })?;
        Ok(RepServer {
            stop,
            connections,
            thread: Mutex::new(Some(thread)),
            local_addr,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = lock(&self.thread).take() {
            let _ = t.join();
        }
        self.connections.close_all();
    }
}

impl Drop for RepServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve_rep(
    mut stream: TcpStream,
    handler: &Handler,
    connections: &Connections,
    stop: &AtomicBool,
) {
    let Some(id) = connections.add(&stream) else {
        return;
    };
    if stop.load(Ordering::Relaxed) {
        connections.remove(id);
        return;
    }
    let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    let result: Result<(), ZmtpError> =
        zmtp::handshake(&mut stream, SocketType::Rep).and_then(|_| {
            let _ = stream.set_read_timeout(None);
            loop {
                let parts = zmtp::read_message(&mut stream)?;
                // The envelope is everything up to and including the empty
                // delimiter a REQ peer puts first; a DEALER may put routing
                // frames before it. A message without one is dropped, as libzmq's
                // REP drops it.
                let Some(split) = parts.iter().position(Vec::is_empty) else {
                    continue;
                };
                let request: Vec<u8> = parts[split + 1..].concat();
                let reply = handler(&request);
                let mut out = Vec::with_capacity(reply.len() + 16);
                for part in &parts[..=split] {
                    out.extend(zmtp::encode_frame(true, false, part));
                }
                out.extend(zmtp::encode_frame(false, false, &reply));
                stream.write_all(&out)?;
            }
        });
    if let Err(e) = result {
        log_end("ZMQ RPC connection", e);
    }
    connections.remove(id);
}

/// One subscriber: what it subscribed to, and its queue.
struct Subscriber {
    prefixes: Mutex<Vec<Vec<u8>>>,
    outbox: SyncSender<Vec<u8>>,
}

struct PubShared {
    stop: AtomicBool,
    connections: Connections,
    subscribers: Mutex<HashMap<u64, Arc<Subscriber>>>,
}

/// A PUB socket, as `--zmq-pub` serves. Subscriptions are prefixes of a
/// message's bytes; the empty prefix is everything.
pub struct Publisher {
    shared: Arc<PubShared>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    local_addrs: Vec<SocketAddr>,
}

impl Publisher {
    /// Accept subscribers on every listener given.
    pub fn start(listeners: Vec<TcpListener>) -> std::io::Result<Publisher> {
        let shared = Arc::new(PubShared {
            stop: AtomicBool::new(false),
            connections: Connections::default(),
            subscribers: Mutex::new(HashMap::new()),
        });
        let mut local_addrs = Vec::with_capacity(listeners.len());
        let mut threads = Vec::with_capacity(listeners.len());
        for listener in listeners {
            local_addrs.push(listener.local_addr()?);
            let s = shared.clone();
            let serve: Arc<dyn Fn(TcpStream) + Send + Sync> =
                Arc::new(move |stream| serve_subscriber(stream, &s));
            let watcher = shared.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("zmq-pub".into())
                    .spawn(move || {
                        accept_loop(
                            listener,
                            || watcher.stop.load(Ordering::Relaxed),
                            "zmq-pub-conn",
                            serve,
                        )
                    })?,
            );
        }
        Ok(Publisher {
            shared,
            threads: Mutex::new(threads),
            local_addrs,
        })
    }

    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local_addrs
    }

    pub fn subscriber_count(&self) -> usize {
        lock(&self.shared.subscribers).len()
    }

    /// Whether some subscriber subscribed to a prefix of `topic`. The C++
    /// builds a topic's message only then (`zmq_pub::sub_request`), which
    /// spares serialising blocks nobody listens for.
    pub fn wants(&self, topic: &str) -> bool {
        lock(&self.shared.subscribers).values().any(|s| {
            lock(&s.prefixes)
                .iter()
                .any(|p| topic.as_bytes().starts_with(p))
        })
    }

    /// Send `message` to each subscriber with a subscription it starts with.
    /// A subscriber whose queue is full misses it, as with libzmq's PUB.
    pub fn publish(&self, message: &[u8]) {
        let frame = zmtp::encode_frame(false, false, message);
        for s in lock(&self.shared.subscribers).values() {
            if lock(&s.prefixes).iter().any(|p| message.starts_with(p)) {
                let _ = s.outbox.try_send(frame.clone());
            }
        }
    }

    pub fn stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for t in lock(&self.threads).drain(..) {
            let _ = t.join();
        }
        self.shared.connections.close_all();
    }
}

impl Drop for Publisher {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve_subscriber(mut stream: TcpStream, shared: &Arc<PubShared>) {
    let Some(id) = shared.connections.add(&stream) else {
        return;
    };
    if shared.stop.load(Ordering::Relaxed) {
        shared.connections.remove(id);
        return;
    }
    let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    if let Err(e) = zmtp::handshake(&mut stream, SocketType::Pub) {
        log_end("ZMQ subscriber handshake", e);
        shared.connections.remove(id);
        return;
    }
    let _ = stream.set_read_timeout(None);

    let (tx, rx) = sync_channel::<Vec<u8>>(SUBSCRIBER_QUEUE);
    let subscriber = Arc::new(Subscriber {
        prefixes: Mutex::new(Vec::new()),
        outbox: tx.clone(),
    });
    lock(&shared.subscribers).insert(id, subscriber.clone());

    if let Ok(mut writer) = stream.try_clone() {
        let _ = std::thread::Builder::new()
            .name("zmq-pub-write".into())
            .spawn(move || {
                for frame in rx {
                    if writer.write_all(&frame).is_err() {
                        break;
                    }
                }
                let _ = writer.shutdown(Shutdown::Both);
            });
    }

    let subscribe = |prefix: &[u8], on: bool| {
        let mut prefixes = lock(&subscriber.prefixes);
        if on {
            prefixes.push(prefix.to_vec());
        } else if let Some(i) = prefixes.iter().position(|p| p == prefix) {
            prefixes.swap_remove(i);
        }
    };
    loop {
        match zmtp::read_frame(&mut stream, MAX_CONTROL_FRAME) {
            // ZMTP 3.1 subscribes with commands ...
            Ok(Frame::Command { name, data }) => {
                if name.eq_ignore_ascii_case("SUBSCRIBE") {
                    subscribe(&data, true);
                } else if name.eq_ignore_ascii_case("CANCEL") {
                    subscribe(&data, false);
                } else if name.eq_ignore_ascii_case("PING") {
                    let context = data.get(2..).unwrap_or(&[]);
                    let _ = tx.try_send(zmtp::encode_command(
                        "PONG",
                        &context[..context.len().min(16)],
                    ));
                } else if name.eq_ignore_ascii_case("ERROR") {
                    break;
                }
            }
            // ... 3.0, with messages whose first byte says which.
            Ok(Frame::Message { body, .. }) => match body.split_first() {
                Some((1, prefix)) => subscribe(prefix, true),
                Some((0, prefix)) => subscribe(prefix, false),
                _ => {}
            },
            Err(e) => {
                log_end("ZMQ subscriber", e);
                break;
            }
        }
    }

    lock(&shared.subscribers).remove(&id);
    drop(tx);
    let _ = stream.shutdown(Shutdown::Both);
    shared.connections.remove(id);
}
