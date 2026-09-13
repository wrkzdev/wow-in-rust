//! ZMTP 3.1 framing and the NULL-mechanism handshake (RFC 23, RFC 37).
//!
//! A connection opens with a 64-byte greeting from each side, then a READY
//! command from each side naming its socket type. After that everything is
//! frames: a flags byte, a one- or eight-byte big-endian size, and the body.
//! A message is one or more frames, all but the last flagged MORE. A command
//! frame carries its name, length-prefixed, before its data.

use std::io::{Read, Write};

/// `ZMQ_MAXMSGSIZE` as the C++ daemon sets it: 10 MiB.
pub const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024;

/// The largest frame accepted where only small ones belong: the handshake,
/// and a subscriber's subscriptions.
pub const MAX_CONTROL_FRAME: u64 = 64 * 1024;

pub const GREETING_LEN: usize = 64;

const FLAG_MORE: u8 = 0x01;
const FLAG_LONG: u8 = 0x02;
const FLAG_COMMAND: u8 = 0x04;

#[derive(Debug)]
pub enum ZmtpError {
    Io(std::io::Error),
    /// The connection closed.
    Closed,
    /// The peer's greeting is not one this side can answer.
    Greeting(String),
    /// A frame or command that breaks the protocol.
    Protocol(String),
    /// A frame or message over the size limit.
    TooLarge(u64),
    /// The peer's socket type cannot talk to this one.
    Incompatible {
        ours: SocketType,
        theirs: String,
    },
    /// The peer sent an ERROR command.
    Peer(String),
}

impl std::fmt::Display for ZmtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZmtpError::Io(e) => write!(f, "{e}"),
            ZmtpError::Closed => f.write_str("the connection closed"),
            ZmtpError::Greeting(w) => write!(f, "greeting: {w}"),
            ZmtpError::Protocol(w) => write!(f, "protocol: {w}"),
            ZmtpError::TooLarge(n) => {
                write!(
                    f,
                    "a message of {n} bytes, over the {MAX_MESSAGE_SIZE} limit"
                )
            }
            ZmtpError::Incompatible { ours, theirs } => {
                write!(f, "a {theirs} socket cannot talk to a {}", ours.name())
            }
            ZmtpError::Peer(reason) => write!(f, "the peer reported an error: {reason}"),
        }
    }
}

impl std::error::Error for ZmtpError {}

impl From<std::io::Error> for ZmtpError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe => ZmtpError::Closed,
            _ => ZmtpError::Io(e),
        }
    }
}

fn protocol(what: &str) -> ZmtpError {
    ZmtpError::Protocol(what.to_string())
}

/// ZeroMQ socket types, as READY names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketType {
    Pair,
    Pub,
    Sub,
    Req,
    Rep,
    Dealer,
    Router,
    Pull,
    Push,
    XPub,
    XSub,
}

impl SocketType {
    pub fn name(self) -> &'static str {
        match self {
            SocketType::Pair => "PAIR",
            SocketType::Pub => "PUB",
            SocketType::Sub => "SUB",
            SocketType::Req => "REQ",
            SocketType::Rep => "REP",
            SocketType::Dealer => "DEALER",
            SocketType::Router => "ROUTER",
            SocketType::Pull => "PULL",
            SocketType::Push => "PUSH",
            SocketType::XPub => "XPUB",
            SocketType::XSub => "XSUB",
        }
    }

    pub fn from_name(name: &[u8]) -> Option<SocketType> {
        [
            SocketType::Pair,
            SocketType::Pub,
            SocketType::Sub,
            SocketType::Req,
            SocketType::Rep,
            SocketType::Dealer,
            SocketType::Router,
            SocketType::Pull,
            SocketType::Push,
            SocketType::XPub,
            SocketType::XSub,
        ]
        .into_iter()
        .find(|t| t.name().as_bytes().eq_ignore_ascii_case(name))
    }

    /// RFC 23's table of which socket types may be connected.
    pub fn accepts(self, peer: SocketType) -> bool {
        use SocketType::*;
        match self {
            Req => matches!(peer, Rep | Router),
            Rep => matches!(peer, Req | Dealer),
            Dealer => matches!(peer, Rep | Dealer | Router),
            Router => matches!(peer, Req | Dealer | Router),
            Pub | XPub => matches!(peer, Sub | XSub),
            Sub | XSub => matches!(peer, Pub | XPub),
            Push => peer == Pull,
            Pull => peer == Push,
            Pair => peer == Pair,
        }
    }
}

/// This side's greeting: ZMTP 3.1, the NULL mechanism, not a server (NULL has
/// no roles).
pub fn greeting() -> [u8; GREETING_LEN] {
    let mut g = [0u8; GREETING_LEN];
    g[0] = 0xff;
    g[9] = 0x7f;
    g[10] = 3;
    g[11] = 1;
    g[12..16].copy_from_slice(b"NULL");
    g
}

/// Check a peer's greeting, returning its minor version.
pub fn check_greeting(g: &[u8; GREETING_LEN]) -> Result<u8, ZmtpError> {
    if g[0] != 0xff || g[9] & 0x01 == 0 {
        return Err(ZmtpError::Greeting("not a ZMTP greeting".into()));
    }
    if g[10] < 3 {
        return Err(ZmtpError::Greeting(format!(
            "ZMTP {}.{} is too old; 3.0 or later is needed",
            g[10], g[11]
        )));
    }
    let mechanism = &g[12..32];
    let end = mechanism.iter().position(|b| *b == 0).unwrap_or(20);
    if &mechanism[..end] != b"NULL" || mechanism[end..].iter().any(|b| *b != 0) {
        return Err(ZmtpError::Greeting(format!(
            "the {} security mechanism is not supported",
            String::from_utf8_lossy(&mechanism[..end])
        )));
    }
    Ok(g[11])
}

/// One frame read off a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Message { more: bool, body: Vec<u8> },
    Command { name: String, data: Vec<u8> },
}

/// A frame on the wire.
pub fn encode_frame(more: bool, command: bool, body: &[u8]) -> Vec<u8> {
    let mut flags = 0u8;
    if more {
        flags |= FLAG_MORE;
    }
    if command {
        flags |= FLAG_COMMAND;
    }
    let mut out = Vec::with_capacity(body.len() + 9);
    if body.len() > 255 {
        out.push(flags | FLAG_LONG);
        out.extend_from_slice(&(body.len() as u64).to_be_bytes());
    } else {
        out.push(flags);
        out.push(body.len() as u8);
    }
    out.extend_from_slice(body);
    out
}

/// A command frame.
pub fn encode_command(name: &str, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + name.len() + data.len());
    body.push(name.len() as u8);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(data);
    encode_frame(false, true, &body)
}

fn push_property(data: &mut Vec<u8>, name: &str, value: &[u8]) {
    data.push(name.len() as u8);
    data.extend_from_slice(name.as_bytes());
    data.extend_from_slice(&(value.len() as u32).to_be_bytes());
    data.extend_from_slice(value);
}

/// READY, announcing this side's socket type.
pub fn encode_ready(ours: SocketType) -> Vec<u8> {
    let mut data = Vec::new();
    push_property(&mut data, "Socket-Type", ours.name().as_bytes());
    encode_command("READY", &data)
}

/// ERROR, with its reason.
pub fn encode_error(reason: &str) -> Vec<u8> {
    let reason = &reason.as_bytes()[..reason.len().min(255)];
    let mut data = Vec::with_capacity(1 + reason.len());
    data.push(reason.len() as u8);
    data.extend_from_slice(reason);
    encode_command("ERROR", &data)
}

/// The reason in an ERROR command's data.
pub fn error_reason(data: &[u8]) -> String {
    let n = data.first().copied().unwrap_or(0) as usize;
    String::from_utf8_lossy(data.get(1..1 + n).unwrap_or(&data[data.len().min(1)..])).into_owned()
}

/// READY's metadata: name-length octet, name, four-byte value length, value.
pub fn parse_properties(mut data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ZmtpError> {
    let mut out = Vec::new();
    while let Some(&n) = data.first() {
        let n = n as usize;
        let header = data
            .get(1..5 + n)
            .ok_or_else(|| protocol("a truncated property"))?;
        let name = String::from_utf8_lossy(&header[..n]).into_owned();
        let len_bytes: [u8; 4] = header[n..n + 4]
            .try_into()
            .map_err(|_| protocol("a truncated property"))?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        let rest = &data[5 + n..];
        let value = rest
            .get(..len)
            .ok_or_else(|| protocol("a truncated property value"))?;
        out.push((name, value.to_vec()));
        data = &rest[len..];
    }
    Ok(out)
}

/// Read one frame, refusing one larger than `max` before allocating it.
pub fn read_frame(r: &mut impl Read, max: u64) -> Result<Frame, ZmtpError> {
    let mut flags = [0u8; 1];
    r.read_exact(&mut flags)?;
    let flags = flags[0];
    if flags & !(FLAG_MORE | FLAG_LONG | FLAG_COMMAND) != 0 {
        return Err(protocol("reserved frame flags are set"));
    }
    let size = if flags & FLAG_LONG != 0 {
        let mut b = [0u8; 8];
        r.read_exact(&mut b)?;
        u64::from_be_bytes(b)
    } else {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        u64::from(b[0])
    };
    if size > max {
        return Err(ZmtpError::TooLarge(size));
    }
    let mut body = vec![0u8; size as usize];
    r.read_exact(&mut body)?;

    if flags & FLAG_COMMAND == 0 {
        return Ok(Frame::Message {
            more: flags & FLAG_MORE != 0,
            body,
        });
    }
    if flags & FLAG_MORE != 0 {
        return Err(protocol("a command frame with MORE set"));
    }
    let n = *body.first().ok_or_else(|| protocol("an empty command"))? as usize;
    let name = body
        .get(1..1 + n)
        .ok_or_else(|| protocol("a truncated command name"))?;
    Ok(Frame::Command {
        name: String::from_utf8_lossy(name).into_owned(),
        data: body[1 + n..].to_vec(),
    })
}

/// Answer the commands that may arrive between messages: PING gets its PONG,
/// ERROR ends the connection, and the rest are ignored.
pub fn answer_command(w: &mut impl Write, name: &str, data: &[u8]) -> Result<(), ZmtpError> {
    if name.eq_ignore_ascii_case("PING") {
        // A two-byte TTL, then up to sixteen bytes of context to echo.
        let context = data.get(2..).unwrap_or(&[]);
        w.write_all(&encode_command("PONG", &context[..context.len().min(16)]))?;
    } else if name.eq_ignore_ascii_case("ERROR") {
        return Err(ZmtpError::Peer(error_reason(data)));
    }
    Ok(())
}

/// One whole message, its parts in order, answering commands met on the way.
/// The parts together may not exceed [`MAX_MESSAGE_SIZE`].
pub fn read_message<S: Read + Write>(stream: &mut S) -> Result<Vec<Vec<u8>>, ZmtpError> {
    let mut parts = Vec::new();
    let mut total = 0u64;
    loop {
        match read_frame(stream, MAX_MESSAGE_SIZE)? {
            Frame::Message { more, body } => {
                total += body.len() as u64;
                if total > MAX_MESSAGE_SIZE {
                    return Err(ZmtpError::TooLarge(total));
                }
                parts.push(body);
                if !more {
                    return Ok(parts);
                }
            }
            Frame::Command { name, data } => answer_command(stream, &name, &data)?,
        }
    }
}

/// What a handshake learned about the peer.
#[derive(Clone, Debug)]
pub struct Handshake {
    pub socket_type: SocketType,
    /// The peer's ZMTP minor version: 0 sends subscriptions as messages, 1 as
    /// SUBSCRIBE commands.
    pub minor: u8,
    pub properties: Vec<(String, Vec<u8>)>,
}

/// The NULL-mechanism handshake for a socket of type `ours`.
///
/// This side's greeting goes out before the peer's is read. libzmq sends its
/// greeting in pieces and waits to see the other side's signature before
/// sending the rest, so a side that waited for a whole greeting first would
/// wait forever.
pub fn handshake<S: Read + Write>(
    stream: &mut S,
    ours: SocketType,
) -> Result<Handshake, ZmtpError> {
    stream.write_all(&greeting())?;
    stream.flush()?;
    let mut theirs = [0u8; GREETING_LEN];
    stream.read_exact(&mut theirs)?;
    let minor = check_greeting(&theirs)?;

    stream.write_all(&encode_ready(ours))?;
    stream.flush()?;
    match read_frame(stream, MAX_CONTROL_FRAME)? {
        Frame::Command { name, data } if name.eq_ignore_ascii_case("READY") => {
            let properties = parse_properties(&data)?;
            let type_name = properties
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("Socket-Type"))
                .map(|(_, v)| v.clone())
                .ok_or_else(|| protocol("READY names no Socket-Type"))?;
            let theirs_name = String::from_utf8_lossy(&type_name).into_owned();
            let socket_type = SocketType::from_name(&type_name)
                .filter(|t| ours.accepts(*t))
                .ok_or(ZmtpError::Incompatible {
                    ours,
                    theirs: theirs_name,
                });
            match socket_type {
                Ok(socket_type) => Ok(Handshake {
                    socket_type,
                    minor,
                    properties,
                }),
                Err(e) => {
                    let _ = stream.write_all(&encode_error("Invalid socket type"));
                    Err(e)
                }
            }
        }
        Frame::Command { name, data } if name.eq_ignore_ascii_case("ERROR") => {
            Err(ZmtpError::Peer(error_reason(&data)))
        }
        _ => Err(protocol("the peer's first frame was not READY")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn a_greeting_is_checked() {
        assert_eq!(check_greeting(&greeting()).unwrap(), 1);

        let mut v30 = greeting();
        v30[11] = 0;
        assert_eq!(check_greeting(&v30).unwrap(), 0, "3.0 is accepted");

        let mut v2 = greeting();
        v2[10] = 2;
        assert!(matches!(check_greeting(&v2), Err(ZmtpError::Greeting(_))));

        let mut curve = greeting();
        curve[12..17].copy_from_slice(b"CURVE");
        let e = check_greeting(&curve).unwrap_err().to_string();
        assert!(e.contains("CURVE"), "{e}");

        let mut junk = greeting();
        junk[0] = b'G';
        assert!(check_greeting(&junk).is_err());
    }

    /// Short and long frames, and a command, read back as written.
    #[test]
    fn frames_round_trip() {
        let long = vec![7u8; 300];
        let mut wire = encode_frame(true, false, b"");
        wire.extend(encode_frame(false, false, &long));
        wire.extend(encode_command("PING", &[0, 10, b'x']));

        let mut r = Cursor::new(wire);
        assert_eq!(
            read_frame(&mut r, MAX_MESSAGE_SIZE).unwrap(),
            Frame::Message {
                more: true,
                body: Vec::new()
            }
        );
        assert_eq!(
            read_frame(&mut r, MAX_MESSAGE_SIZE).unwrap(),
            Frame::Message {
                more: false,
                body: long
            }
        );
        assert_eq!(
            read_frame(&mut r, MAX_MESSAGE_SIZE).unwrap(),
            Frame::Command {
                name: "PING".into(),
                data: vec![0, 10, b'x']
            }
        );
        assert!(matches!(
            read_frame(&mut r, MAX_MESSAGE_SIZE),
            Err(ZmtpError::Closed)
        ));
    }

    /// A frame claiming more than the limit is refused on its header, before
    /// any allocation.
    #[test]
    fn an_oversized_frame_is_refused_before_allocating() {
        let mut wire = vec![FLAG_LONG];
        wire.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(
            read_frame(&mut Cursor::new(wire), MAX_MESSAGE_SIZE),
            Err(ZmtpError::TooLarge(u64::MAX))
        ));
        assert!(matches!(
            read_frame(&mut Cursor::new(vec![0x08, 0]), MAX_MESSAGE_SIZE),
            Err(ZmtpError::Protocol(_))
        ));
    }

    #[test]
    fn ready_properties_parse_and_truncation_is_an_error() {
        let ready = encode_ready(SocketType::Rep);
        let Frame::Command { name, data } = read_frame(&mut Cursor::new(ready), 1024).unwrap()
        else {
            panic!("a command");
        };
        assert_eq!(name, "READY");
        let props = parse_properties(&data).unwrap();
        assert_eq!(props, vec![("Socket-Type".into(), b"REP".to_vec())]);

        assert!(parse_properties(&data[..data.len() - 1]).is_err());
        assert!(parse_properties(&[11, b'S']).is_err());
        assert_eq!(error_reason(&encode_error("nope")[8..]), "nope");
    }

    #[test]
    fn socket_types_pair_as_rfc_23_says() {
        assert!(SocketType::Rep.accepts(SocketType::Req));
        assert!(SocketType::Rep.accepts(SocketType::Dealer));
        assert!(!SocketType::Rep.accepts(SocketType::Sub));
        assert!(SocketType::Pub.accepts(SocketType::Sub));
        assert!(SocketType::Pub.accepts(SocketType::XSub));
        assert!(!SocketType::Pub.accepts(SocketType::Req));
        assert_eq!(SocketType::from_name(b"xpub"), Some(SocketType::XPub));
        assert_eq!(SocketType::from_name(b"CLIENT"), None);
    }
}
