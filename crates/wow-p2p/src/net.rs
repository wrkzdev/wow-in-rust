//! Listening sockets, IPv4 and IPv6 side by side (`specs/09` §3.2).
//!
//! The C++ binds its IPv6 acceptor with `v6_only` set, so the IPv4 and IPv6
//! listeners can share a port. Without it an IPv6 socket on Linux takes IPv4
//! connections too, and whichever listener binds second fails with "address in
//! use". The standard library cannot set the option before binding, so the
//! sockets are made through `socket2`.

use std::net::{SocketAddr, TcpListener};

use socket2::{Domain, Protocol, Socket, Type};

const LOG: &str = "net";

/// Bind and listen on `addr`. An IPv6 address takes IPv6 connections only.
pub fn listen(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // As the C++ does outside Windows, where the option means something else:
    // a restarted node can bind while old connections sit in TIME_WAIT.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(socket.into())
}

/// The listeners for one server, as the C++'s `init_server` binds them.
///
/// An IPv4 failure is fatal when `require_ipv4` is set (`--p2p-ignore-ipv4`
/// and `--rpc-ignore-ipv4` clear it); an IPv6 failure only when nothing else
/// bound. Each failure is logged either way. `what` names the server in the
/// messages.
pub fn listen_dual(
    v4: Option<SocketAddr>,
    v6: Option<SocketAddr>,
    require_ipv4: bool,
    what: &str,
) -> Result<(Option<TcpListener>, Option<TcpListener>), String> {
    let mut ipv4 = None;
    if let Some(addr) = v4 {
        match listen(addr) {
            Ok(l) => ipv4 = Some(l),
            Err(e) => {
                let msg = format!("cannot listen for {what} on {addr}: {e}");
                if require_ipv4 {
                    return Err(msg);
                }
                wow_log::error!(LOG, "{msg}");
            }
        }
    }
    let mut ipv6 = None;
    if let Some(addr) = v6 {
        match listen(addr) {
            Ok(l) => ipv6 = Some(l),
            Err(e) => {
                let msg = format!("cannot listen for {what} on {addr}: {e}");
                if ipv4.is_none() {
                    return Err(msg);
                }
                wow_log::error!(LOG, "{msg}");
            }
        }
    }
    if ipv4.is_none() && ipv6.is_none() && (v4.is_some() || v6.is_some()) {
        return Err(format!("{what}: no listener could be bound"));
    }
    Ok((ipv4, ipv6))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_v6_works() -> bool {
        listen("[::1]:0".parse().unwrap()).is_ok()
    }

    /// **Dual stack on one port.** An IPv6 listener leaves the IPv4 side of
    /// its port alone, in either order, so both families can listen at once.
    #[test]
    fn ipv4_and_ipv6_listeners_share_a_port() {
        if !loopback_v6_works() {
            eprintln!("skipped: no IPv6 loopback on this host");
            return;
        }
        let v4 = listen("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = v4.local_addr().unwrap().port();
        let v6 = listen(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)))
            .expect("the IPv6 side of the same port");
        assert_eq!(v6.local_addr().unwrap().port(), port);

        let unspecified = listen("[::]:0".parse().unwrap()).unwrap();
        let port = unspecified.local_addr().unwrap().port();
        assert!(
            listen(SocketAddr::from(([0, 0, 0, 0], port))).is_ok(),
            "an IPv6 wildcard listener does not take IPv4's port"
        );
    }

    /// `init_server`'s rules: IPv4 is fatal only when required, IPv6 only
    /// when nothing else bound.
    #[test]
    fn a_failed_bind_is_fatal_only_when_nothing_else_will_do() {
        let taken = listen("127.0.0.1:0".parse().unwrap()).unwrap();
        let busy = taken.local_addr().unwrap();

        assert!(listen_dual(Some(busy), None, true, "test").is_err());
        assert!(
            listen_dual(Some(busy), None, false, "test").is_err(),
            "nothing bound at all"
        );
        let (v4, v6) =
            listen_dual(Some("127.0.0.1:0".parse().unwrap()), None, true, "test").unwrap();
        assert!(v4.is_some() && v6.is_none());

        if loopback_v6_works() {
            let (v4, v6) =
                listen_dual(Some(busy), Some("[::1]:0".parse().unwrap()), false, "test").unwrap();
            assert!(
                v4.is_none() && v6.is_some(),
                "IPv6 alone, IPv4 not required"
            );
            assert!(
                listen_dual(Some(busy), Some("[::1]:0".parse().unwrap()), true, "test").is_err(),
                "IPv4 required"
            );
        }
    }
}
