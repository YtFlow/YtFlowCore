use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::ready;

use std::collections::BTreeMap;
use std::net::ToSocketAddrs;
use std::sync::Weak;

use async_trait::async_trait;
use flume::{bounded, SendError};

use crate::flow::*;

fn create_socket_v4(
    remote_ip_indicator: Ipv4Addr,
    bind_v4: &impl Fn(&mut socket2::Socket) -> FlowResult<()>,
) -> FlowResult<socket2::Socket> {
    let mut socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    prepare_socket(&socket)?;
    if remote_ip_indicator.is_loopback() {
        socket.bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())?
    } else {
        bind_v4(&mut socket)?
    };
    Ok(socket)
}

fn create_socket_v6(
    remote_ip_indicator: Ipv6Addr,
    bind_v6: &impl Fn(&mut socket2::Socket) -> FlowResult<()>,
) -> FlowResult<socket2::Socket> {
    let mut socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    prepare_socket(&socket)?;
    if remote_ip_indicator.is_loopback() {
        socket.bind(&SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0).into())?
    } else {
        bind_v6(&mut socket)?
    };
    Ok(socket)
}

fn prepare_socket(socket: &socket2::Socket) -> io::Result<()> {
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    Ok(())
}

pub fn listen_udp(
    next: Weak<dyn DatagramSessionHandler>,
    addr: impl ToSocketAddrs + Send + 'static,
) -> io::Result<tokio::task::JoinHandle<()>> {
    let mut session_map = BTreeMap::new();
    let null_resolver: Arc<dyn Resolver> = Arc::new(crate::plugin::null::Null);
    let listener = std::net::UdpSocket::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(tokio::spawn(async move {
        let listener = Arc::new(
            tokio::net::UdpSocket::from_std(listener)
                .expect("Calling listen_udp when runtime is not set"),
        );
        let listen_addr: DestinationAddr = match listener.local_addr() {
            Ok(addr) => addr,
            // TODO: log error
            Err(_) => return,
        }
        .into();
        let mut buf = [0u8; 4096];
        loop {
            let (size, from) = match listener.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => {
                    // TODO: log error
                    break;
                }
            };
            let tx = session_map.entry(from).or_insert_with(|| {
                let (tx, rx) = bounded(64);
                if let Some(next) = next.upgrade() {
                    next.on_session(
                        Box::new(MultiplexedDatagramSessionAdapter::new(
                            UdpSocket {
                                socket: listener.clone(),
                                tx_buf: None,
                                resolver: null_resolver.clone(),
                            },
                            rx.into_stream(),
                            120,
                        )),
                        Box::new(FlowContext {
                            local_peer: from,
                            remote_peer: listen_addr.clone(),
                        }),
                    );
                }
                tx
            });
            if let Err(SendError(_)) = tx
                .send_async((listen_addr.clone(), buf[..size].to_vec()))
                .await
            {
                session_map.remove(&from);
            }
        }
    }))
}

pub(super) enum ResolvingAddr {
    Resolving(Pin<Box<dyn Future<Output = FlowResult<SocketAddr>> + Send + 'static>>),
    Ready(SocketAddr),
}

// Safety: ResolvingAddr is never shared between threads.
unsafe impl Sync for ResolvingAddr {}

pub(super) struct UdpSocket {
    pub(super) resolver: Arc<dyn Resolver>,
    pub(super) socket: Arc<tokio::net::UdpSocket>,
    pub(super) tx_buf: Option<(ResolvingAddr, Buffer)>,
}

impl MultiplexedDatagramSession for UdpSocket {
    fn on_close(&mut self) {}
    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
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
        let _ = ready!(socket.poll_send_to(cx, buf, addr));
        *tx_buf = None;
        Poll::Ready(())
    }
    fn send_to(&mut self, dst: DestinationAddr, buf: Buffer) {
        let port = dst.port;
        match dst.host {
            HostName::Ip(ip) => {
                let addr = SocketAddr::new(ip, port);
                if self.socket.try_send_to(&buf, addr).is_err() {
                    self.tx_buf = Some((ResolvingAddr::Ready(addr), buf));
                }
            }
            HostName::DomainName(domain) => {
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
}

pub async fn dial_datagram_session(
    context: &FlowContext,
    resolver: Arc<dyn Resolver>,
    bind_v4: Option<impl Fn(&mut socket2::Socket) -> FlowResult<()>>,
    bind_v6: Option<impl Fn(&mut socket2::Socket) -> FlowResult<()>>,
) -> FlowResult<Box<dyn DatagramSession>> {
    let socket = match (context.remote_peer.host.clone(), bind_v4, bind_v6) {
        (HostName::Ip(IpAddr::V4(ip)), Some(bind_v4), _) => create_socket_v4(ip, &bind_v4)?,
        (HostName::Ip(IpAddr::V6(ip)), _, Some(bind_v6)) => create_socket_v6(ip, &bind_v6)?,
        (HostName::DomainName(domain), Some(bind_v4), None) => {
            let ips = resolver.resolve_ipv4(domain).await?;
            let mut ret = Err(FlowError::NoOutbound);
            for ip in ips {
                ret = create_socket_v4(ip, &bind_v4);
            }
            ret?
        }
        (HostName::DomainName(domain), None, Some(bind_v6)) => {
            let ips = resolver.resolve_ipv6(domain).await?;
            let mut ret = Err(FlowError::NoOutbound);
            for ip in ips {
                ret = create_socket_v6(ip, &bind_v6);
            }
            ret?
        }
        (HostName::DomainName(domain), Some(bind_v4), Some(bind_v6)) => {
            let (ip_tx, mut ip_rx) = tokio::sync::mpsc::channel::<IpAddr>(1);
            tokio::spawn({
                let resolver = resolver.clone();
                async move { super::resolve_dual_stack_ips(domain, &*resolver, ip_tx).await }
            });
            let mut ret = Err(FlowError::NoOutbound);
            while let Some(ip) = ip_rx.recv().await {
                ret = match ip {
                    IpAddr::V4(ip) => create_socket_v4(ip, &bind_v4),
                    IpAddr::V6(ip) => create_socket_v6(ip, &bind_v6),
                };
                if ret.is_ok() {
                    break;
                }
            }
            ret?
        }
        _ => return Err(FlowError::NoOutbound),
    };
    let socket = tokio::net::UdpSocket::from_std(socket.into())?;
    socket.writable().await?;
    let socket = Arc::new(socket);
    let (tx, rx) = bounded(0);
    tokio::spawn({
        let socket = socket.clone();
        async move {
            let mut buf = [0u8; 4096];
            loop {
                let (size, from) = socket.recv_from(&mut buf).await?;
                if let Err(SendError(_)) = tx.send_async((from.into(), buf[..size].to_vec())).await
                {
                    break io::Result::Ok(());
                };
            }
        }
    });
    Ok(Box::new(MultiplexedDatagramSessionAdapter::new(
        UdpSocket {
            socket,
            tx_buf: None,
            resolver,
        },
        rx.into_stream(),
        u32::MAX as u64 - 1,
    )))
}

#[async_trait]
impl DatagramSessionFactory for super::SocketOutboundFactory {
    async fn bind(&self, context: Box<FlowContext>) -> FlowResult<Box<dyn DatagramSession>> {
        let Self {
            bind_addr_v4,
            bind_addr_v6,
            ..
        } = self;

        let resolver = match self.resolver.upgrade() {
            Some(r) => r,
            None => return Err(FlowError::NoOutbound),
        };
        dial_datagram_session(
            &context,
            resolver,
            bind_addr_v4.clone().map(|addr| {
                move |s: &mut socket2::Socket| s.bind(&addr.into()).map_err(FlowError::from)
            }),
            bind_addr_v6.clone().map(|addr| {
                move |s: &mut socket2::Socket| s.bind(&addr.into()).map_err(FlowError::from)
            }),
        )
        .await
    }
}
