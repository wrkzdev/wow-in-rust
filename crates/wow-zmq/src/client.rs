//! Client sockets: [`ReqSocket`] to ask a REP server, [`SubSocket`] to hear a
//! PUB one. What the daemon's tests talk to it with, and enough for a tool.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::zmtp::{self, SocketType, ZmtpError};

fn connect(
    addr: SocketAddr,
    timeout: Duration,
    ours: SocketType,
) -> Result<(TcpStream, u8), ZmtpError> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let _ = stream.set_nodelay(true);
    let peer = zmtp::handshake(&mut stream, ours)?;
    Ok((stream, peer.minor))
}

/// A REQ socket on one connection.
pub struct ReqSocket {
    stream: TcpStream,
}

impl ReqSocket {
    /// Connect and handshake, with `timeout` for that and for each reply.
    pub fn connect(addr: SocketAddr, timeout: Duration) -> Result<ReqSocket, ZmtpError> {
        let (stream, _) = connect(addr, timeout, SocketType::Req)?;
        Ok(ReqSocket { stream })
    }

    /// Send a request and wait for its reply.
    pub fn request(&mut self, body: &[u8]) -> Result<Vec<u8>, ZmtpError> {
        let mut out = zmtp::encode_frame(true, false, &[]);
        out.extend(zmtp::encode_frame(false, false, body));
        self.stream.write_all(&out)?;
        loop {
            let parts = zmtp::read_message(&mut self.stream)?;
            // The REP side echoes the empty delimiter; a reply without it is
            // not one, and is dropped as libzmq's REQ drops it.
            if let Some((delimiter, reply)) = parts.split_first() {
                if delimiter.is_empty() {
                    return Ok(reply.concat());
                }
            }
        }
    }
}

/// A SUB socket on one connection.
pub struct SubSocket {
    stream: TcpStream,
    minor: u8,
}

impl SubSocket {
    /// Connect and handshake. `timeout` also bounds each [`SubSocket::recv`].
    pub fn connect(addr: SocketAddr, timeout: Duration) -> Result<SubSocket, ZmtpError> {
        let (stream, minor) = connect(addr, timeout, SocketType::Sub)?;
        Ok(SubSocket { stream, minor })
    }

    /// Hear messages starting with `prefix`; the empty prefix is everything.
    pub fn subscribe(&mut self, prefix: &[u8]) -> Result<(), ZmtpError> {
        let frame = if self.minor >= 1 {
            zmtp::encode_command("SUBSCRIBE", prefix)
        } else {
            let mut body = Vec::with_capacity(1 + prefix.len());
            body.push(1);
            body.extend_from_slice(prefix);
            zmtp::encode_frame(false, false, &body)
        };
        self.stream.write_all(&frame)?;
        Ok(())
    }

    /// The next message, its parts joined.
    pub fn recv(&mut self) -> Result<Vec<u8>, ZmtpError> {
        Ok(zmtp::read_message(&mut self.stream)?.concat())
    }

    pub fn set_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.stream.set_read_timeout(Some(timeout))
    }
}
