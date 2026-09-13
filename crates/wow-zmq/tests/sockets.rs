//! The sockets against each other over loopback.

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wow_zmq::zmtp::{self, SocketType, ZmtpError};
use wow_zmq::{Publisher, RepServer, ReqSocket, SubSocket};

const TIMEOUT: Duration = Duration::from_secs(5);

fn loopback() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

fn echo_server() -> (RepServer, SocketAddr) {
    let server = RepServer::start(
        loopback(),
        Arc::new(|req: &[u8]| {
            let mut reply = b"re:".to_vec();
            reply.extend_from_slice(req);
            reply
        }),
    )
    .unwrap();
    let addr = server.local_addr();
    (server, addr)
}

/// **REQ/REP.** Requests on one connection are answered in turn, and two
/// clients are served at once.
#[test]
fn a_rep_server_answers_requests() {
    let (_server, addr) = echo_server();
    let mut a = ReqSocket::connect(addr, TIMEOUT).unwrap();
    let mut b = ReqSocket::connect(addr, TIMEOUT).unwrap();
    for i in 0..3 {
        let body = format!("hello {i}");
        assert_eq!(
            a.request(body.as_bytes()).unwrap(),
            format!("re:hello {i}").as_bytes()
        );
    }
    assert_eq!(b.request(b"from b").unwrap(), b"re:from b");

    let big = vec![b'x'; 70_000];
    assert_eq!(a.request(&big).unwrap().len(), 70_003, "a long frame");
}

/// A DEALER's routing frames before the delimiter come back with the reply.
#[test]
fn the_envelope_is_returned() {
    let (_server, addr) = echo_server();
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    zmtp::handshake(&mut s, SocketType::Dealer).unwrap();

    let mut out = zmtp::encode_frame(true, false, b"route");
    out.extend(zmtp::encode_frame(true, false, b""));
    out.extend(zmtp::encode_frame(false, false, b"body"));
    s.write_all(&out).unwrap();
    let parts = zmtp::read_message(&mut s).unwrap();
    assert_eq!(
        parts,
        vec![b"route".to_vec(), Vec::new(), b"re:body".to_vec()]
    );
}

/// A socket type that cannot talk to REP is refused in the handshake.
#[test]
fn a_mismatched_socket_type_is_refused() {
    let (_server, addr) = echo_server();
    let e = SubSocket::connect(addr, TIMEOUT).err().expect("refused");
    assert!(
        matches!(e, ZmtpError::Incompatible { .. } | ZmtpError::Peer(_)),
        "{e}"
    );
}

/// A frame over 10 MiB ends the connection rather than being read.
#[test]
fn an_oversized_request_ends_the_connection() {
    let (_server, addr) = echo_server();
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    zmtp::handshake(&mut s, SocketType::Req).unwrap();
    let mut header = vec![0x03u8];
    header.extend_from_slice(&(11u64 * 1024 * 1024).to_be_bytes());
    s.write_all(&header).unwrap();
    assert!(zmtp::read_message(&mut s).is_err(), "closed, not answered");
}

/// **PUB/SUB.** Each subscriber hears what it subscribed to and nothing else;
/// the publisher knows which topics have listeners.
#[test]
fn subscribers_hear_only_their_prefixes() {
    let publisher = Publisher::start(vec![loopback()]).unwrap();
    let addr = publisher.local_addrs()[0];

    let mut chain = SubSocket::connect(addr, TIMEOUT).unwrap();
    chain.subscribe(b"json-minimal-chain").unwrap();
    let mut everything = SubSocket::connect(addr, TIMEOUT).unwrap();
    everything.subscribe(b"").unwrap();

    wait_until("both subscriptions", || {
        publisher.subscriber_count() == 2 && publisher.wants("json-full-txpool_add")
    });
    assert!(publisher.wants("json-minimal-chain_main"));

    publisher.publish(b"json-full-txpool_add:[]");
    publisher.publish(b"json-minimal-chain_main:{\"first_height\":1}");

    assert_eq!(
        chain.recv().unwrap(),
        b"json-minimal-chain_main:{\"first_height\":1}"
    );
    assert_eq!(everything.recv().unwrap(), b"json-full-txpool_add:[]");
    assert_eq!(
        everything.recv().unwrap(),
        b"json-minimal-chain_main:{\"first_height\":1}"
    );

    chain.set_timeout(Duration::from_millis(300)).unwrap();
    assert!(chain.recv().is_err(), "nothing else for this subscriber");
}

/// A ZMTP 3.0 peer subscribes with a message whose first byte is 1.
#[test]
fn a_zmtp_3_0_subscription_is_understood() {
    let publisher = Publisher::start(vec![loopback()]).unwrap();
    let mut s = TcpStream::connect(publisher.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    zmtp::handshake(&mut s, SocketType::Sub).unwrap();
    s.write_all(&zmtp::encode_frame(false, false, b"\x01topic-a"))
        .unwrap();

    wait_until("the subscription", || publisher.wants("topic-a:"));
    assert!(!publisher.wants("topic-b"));
    publisher.publish(b"topic-a:1");
    assert_eq!(
        zmtp::read_message(&mut s).unwrap(),
        vec![b"topic-a:1".to_vec()]
    );

    // And cancels with a 0.
    s.write_all(&zmtp::encode_frame(false, false, b"\x00topic-a"))
        .unwrap();
    wait_until("the cancel", || !publisher.wants("topic-a:"));
}

/// Stopping a server closes its connections.
#[test]
fn stopping_closes_connections() {
    let (server, addr) = echo_server();
    let mut client = ReqSocket::connect(addr, TIMEOUT).unwrap();
    assert!(client.request(b"1").is_ok());
    server.stop();
    assert!(client.request(b"2").is_err());
}
