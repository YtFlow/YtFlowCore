use std::future::Future;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::ReadBuf;

use crate::flow::*;

pub(super) enum ResolvingAddr {
    Resolving(Pin<Box<dyn Future<Output = FlowResult<SocketAddr>> + Send + 'static>>),
    Ready(SocketAddr),
}

// TODO: 为啥
unsafe impl Sync for ResolvingAddr {}

pub(super) struct UdpSocket {
    pub(super) resolver: Arc<dyn Resolver>,
    pub(super) socket: tokio::net::UdpSocket,
    pub(super) tx_buf: Option<(ResolvingAddr, Buffer)>,
    pub(super) rx_buf: Vec<u8>,
}

impl DatagramSession for UdpSocket {
    fn poll_send_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let Self { tx_buf, socket, .. } = &mut *self;
        let (addr, buf) = loop {
            match tx_buf.as_mut() {
                Some((ResolvingAddr::Resolving(fut), _buf)) => {
                    match ready!(fut.as_mut().poll(cx)) {
                        Ok(addr) => {
                            let buf = tx_buf.take().unwrap().1;
                            *tx_buf = Some((ResolvingAddr::Ready(addr), buf));
                            continue;
                        }
                        Err(_) => {
                            *tx_buf = None;
                            return Poll::Ready(());
                        }
                    }
                }
                Some((ResolvingAddr::Ready(addr), buf)) => break (*addr, buf),
                None => return Poll::Ready(()),
            }
        };
        let _ = ready!(socket.poll_send_to(cx, &buf, addr));
        *tx_buf = None;
        Poll::Ready(())
    }
    fn send_to(mut self: Pin<&mut Self>, dst: DestinationAddr, buf: Buffer) {
        let port = dst.port;
        match dst.dest {
            Destination::Ip(ip) => {
                let addr = SocketAddr::new(ip, port);
                if self.socket.try_send_to(&buf, addr).is_err() {
                    self.tx_buf = Some((ResolvingAddr::Ready(addr), buf));
                }
            }
            Destination::DomainName(domain) => {
                let resolver = self.resolver.clone();
                let is_v6 = self.socket.local_addr().unwrap().is_ipv6();
                self.tx_buf = Some((
                    ResolvingAddr::Resolving(Box::pin(async move {
                        let ip = if is_v6 {
                            resolver.resolve_ipv6(domain).await?[0].into()
                        } else {
                            resolver.resolve_ipv4(domain).await?[0].into()
                        };
                        Ok(SocketAddr::new(ip, port))
                    })),
                    buf,
                ));
            }
        }
    }

    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<(DestinationAddr, Buffer)>> {
        let Self {
            rx_buf: buf,
            socket,
            ..
        } = &mut *self;
        let mut buf = ReadBuf::new(buf);
        let addr = match ready!(socket.poll_recv_from(cx, &mut buf)).ok() {
            Some(addr) => addr,
            None => return Poll::Ready(None),
        };
        let buf = buf.filled().to_vec();
        Poll::Ready(Some((addr.into(), buf)))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.poll_send_ready(cx).map(|()| Ok(()))
    }
}

pub(super) async fn dial_v4(bind_addr: SocketAddrV4) -> io::Result<tokio::net::UdpSocket> {
    tokio::net::UdpSocket::bind(bind_addr).await
}

pub(super) async fn dial_v6(bind_addr: SocketAddrV6) -> io::Result<tokio::net::UdpSocket> {
    tokio::net::UdpSocket::bind(bind_addr).await
}
