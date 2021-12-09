use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio::net::TcpSocket;

pub(super) async fn dial_v4(
    dest: SocketAddrV4,
    bind_addr: SocketAddrV4,
) -> io::Result<tokio::net::TcpStream> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(if dest.ip().is_loopback() {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)
    } else {
        bind_addr.into()
    })?;
    socket.connect(dest.into()).await
}

pub(super) async fn dial_v6(
    dest: SocketAddrV6,
    bind_addr: SocketAddrV6,
) -> io::Result<tokio::net::TcpStream> {
    let socket = TcpSocket::new_v6()?;
    socket.bind(if dest.ip().is_loopback() {
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0)
    } else {
        bind_addr.into()
    })?;
    socket.connect(dest.into()).await
}
