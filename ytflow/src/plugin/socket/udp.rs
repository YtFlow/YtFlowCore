use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::ReadBuf;
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};

use async_trait::async_trait;

use crate::flow::*;

const IPV6_RESOLUTION_TIMEOUT: tokio::time::Duration = Duration::from_secs(30);

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

pub(super) enum ResolvingAddr {
    Resolving(
        Pin<
            Box<
                dyn Future<Output = (FlowResult<Ipv4Addr>, FlowResult<Ipv6Addr>, u16)>
                    + Send
                    + 'static,
            >,
        >,
    ),
    Ready((Option<Ipv4Addr>, Option<Ipv6Addr>, u16)),
}

// Safety: ResolvingAddr is never shared between threads.
unsafe impl Sync for ResolvingAddr {}

pub(super) enum MaybeBoundSocket<BindFn> {
    Disabled,
    Unbound(BindFn),
    Bound(tokio::net::UdpSocket),
}

impl<BindFn> MaybeBoundSocket<BindFn> {
    fn is_disabled(&self) -> bool {
        matches!(self, MaybeBoundSocket::Disabled)
    }
    fn poll_recv_from(&mut self, cx: &mut Context<'_>) -> Poll<Option<(DestinationAddr, Buffer)>> {
        loop {
            break match self {
                MaybeBoundSocket::Disabled => Poll::Ready(None),
                // TODO: comment why
                MaybeBoundSocket::Unbound(_) => Poll::Pending,
                MaybeBoundSocket::Bound(socket) => {
                    let mut buf = Vec::with_capacity(1600);
                    let mut read_buf = ReadBuf::uninit(buf.spare_capacity_mut());
                    match ready!(socket.poll_recv_from(cx, &mut read_buf)) {
                        Ok(from) => {
                            let len = read_buf.filled().len();
                            unsafe { buf.set_len(len) };
                            Poll::Ready(Some((from.into(), buf)))
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(_) => Poll::Ready(None),
                    }
                }
            };
        }
    }
}

impl<BindFn: Fn(Ipv4Addr) -> FlowResult<socket2::Socket>> MaybeBoundSocket<BindFn> {
    fn bind_v4_and_get(&mut self, indicator: Ipv4Addr) -> FlowResult<&tokio::net::UdpSocket> {
        match self {
            MaybeBoundSocket::Disabled => Err(FlowError::NoOutbound),
            MaybeBoundSocket::Unbound(bind_fn) => {
                let socket = bind_fn(indicator)?;
                let socket = tokio::net::UdpSocket::from_std(socket.into())?;
                *self = MaybeBoundSocket::Bound(socket);
                match self {
                    MaybeBoundSocket::Bound(socket) => Ok(socket),
                    _ => unreachable!(),
                }
            }
            MaybeBoundSocket::Bound(socket) => Ok(socket),
        }
    }
}

impl<BindFn: Fn(Ipv6Addr) -> FlowResult<socket2::Socket>> MaybeBoundSocket<BindFn> {
    fn bind_v6_and_get(&mut self, indicator: Ipv6Addr) -> FlowResult<&tokio::net::UdpSocket> {
        match self {
            MaybeBoundSocket::Disabled => Err(FlowError::NoOutbound),
            MaybeBoundSocket::Unbound(bind_fn) => {
                let socket = bind_fn(indicator)?;
                let socket = tokio::net::UdpSocket::from_std(socket.into())?;
                *self = MaybeBoundSocket::Bound(socket);
                match self {
                    MaybeBoundSocket::Bound(socket) => Ok(socket),
                    _ => unreachable!(),
                }
            }
            MaybeBoundSocket::Bound(socket) => Ok(socket),
        }
    }
}

struct UdpSocket<BindFnV4, BindFnV6> {
    resolver: Arc<dyn Resolver>,
    socket_v4: MaybeBoundSocket<BindFnV4>,
    socket_v6: MaybeBoundSocket<BindFnV6>,
    bind_notify: (Option<oneshot::Sender<()>>, Option<oneshot::Receiver<()>>),
    tx_buf: Option<(ResolvingAddr, Buffer)>,
    rx_v6_next: bool,
}

fn poll_recv_from_two<BindA, BindB>(
    cx: &mut Context<'_>,
    socket_a: &mut MaybeBoundSocket<BindA>,
    socket_b: &mut MaybeBoundSocket<BindB>,
) -> Poll<Option<(DestinationAddr, Buffer)>> {
    let res_a = socket_a.poll_recv_from(cx);
    if let ret @ Poll::Ready(Some(_)) = res_a {
        return ret;
    }
    let res_b = socket_b.poll_recv_from(cx);
    match (res_a, res_b) {
        (a @ Poll::Ready(Some(_)), _) => a,
        (_, b @ Poll::Ready(Some(_))) => b,
        (Poll::Pending, _) | (_, Poll::Pending) => Poll::Pending,
        (Poll::Ready(None), Poll::Ready(None)) => Poll::Ready(None),
    }
}

impl<
        BindFnV4: Fn(Ipv4Addr) -> FlowResult<socket2::Socket> + Send + Sync + 'static,
        BindFnV6: Fn(Ipv6Addr) -> FlowResult<socket2::Socket> + Send + Sync + 'static,
    > DatagramSession for UdpSocket<BindFnV4, BindFnV6>
{
    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Self {
            tx_buf,
            socket_v4,
            socket_v6,
            bind_notify: (bind_notify_tx, _),
            ..
        } = &mut *self;
        let ((v4, v6, port), buf) = loop {
            match tx_buf.as_mut() {
                Some((ResolvingAddr::Resolving(fut), _buf)) => {
                    match ready!(fut.as_mut().poll(cx)) {
                        (Ok(v4), v6, port) => {
                            let buf = tx_buf.take().unwrap().1;
                            *tx_buf = Some((ResolvingAddr::Ready((Some(v4), v6.ok(), port)), buf));
                            continue;
                        }
                        (v4, Ok(v6), port) => {
                            let buf = tx_buf.take().unwrap().1;
                            *tx_buf = Some((ResolvingAddr::Ready((v4.ok(), Some(v6), port)), buf));
                            continue;
                        }
                        (Err(_), Err(_), _) => {
                            *tx_buf = None;
                            return Poll::Ready(());
                        }
                    }
                }
                Some((ResolvingAddr::Ready(addr), buf)) => break (*addr, buf),
                None => return Poll::Ready(()),
            }
        };
        *bind_notify_tx = None;

        if let Some(v6) = v6 {
            if let Ok(socket) = socket_v6.bind_v6_and_get(v6) {
                let _ = ready!(socket.poll_send_ready(cx));
                let _ =
                    ready!(socket.poll_send_to(cx, buf, SocketAddrV6::new(v6, port, 0, 0).into()));
                *tx_buf = None;
                return Poll::Ready(());
            }
        } else if let Some(v4) = v4 {
            if let Ok(socket) = socket_v4.bind_v4_and_get(v4) {
                let _ = ready!(socket.poll_send_ready(cx));
                let _ = ready!(socket.poll_send_to(cx, buf, SocketAddrV4::new(v4, port).into()));
                *tx_buf = None;
                return Poll::Ready(());
            }
        }
        Poll::Ready(())
    }
    fn send_to(&mut self, dst: DestinationAddr, buf: Buffer) {
        let port = dst.port;
        match dst.host {
            HostName::Ip(IpAddr::V4(v4)) => {
                self.tx_buf = Some((ResolvingAddr::Ready((Some(v4), None, port)), buf));
            }
            HostName::Ip(IpAddr::V6(v6)) => {
                self.tx_buf = Some((ResolvingAddr::Ready((None, Some(v6), port)), buf));
            }
            HostName::DomainName(domain) => {
                let resolver = self.resolver.clone();
                let v4_disabled = self.socket_v4.is_disabled();
                let v6_disabled = self.socket_v6.is_disabled();
                self.tx_buf = Some((
                    ResolvingAddr::Resolving(Box::pin(async move {
                        let (res_v4, res_v6) = tokio::join!(
                            async {
                                if v4_disabled {
                                    Err(FlowError::NoOutbound)
                                } else {
                                    resolver.resolve_ipv4(domain.clone()).await
                                }
                            },
                            timeout(IPV6_RESOLUTION_TIMEOUT, async {
                                if v6_disabled {
                                    Err(FlowError::NoOutbound)
                                } else {
                                    resolver.resolve_ipv6(domain.clone()).await
                                }
                            })
                        );
                        (
                            res_v4.map(|ips| ips[0]),
                            res_v6
                                .or_else(|_| {
                                    Err(FlowError::Io(io::Error::new(
                                        io::ErrorKind::TimedOut,
                                        "IPv6 resolver timeout",
                                    )))
                                })
                                .flatten()
                                .map(|ips| ips[0]),
                            port,
                        )
                    })),
                    buf,
                ));
            }
        }
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        ready!(self.poll_send_ready(cx));
        Poll::Ready(Ok(()))
    }

    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>> {
        if let Some(bind_notify_rx) = &mut self.bind_notify.1 {
            let _ = ready!(Pin::new(bind_notify_rx).poll(cx));
            self.bind_notify.1 = None;
        }
        let rx_v6_next = self.rx_v6_next;
        self.rx_v6_next = !rx_v6_next;
        // For fairness
        if rx_v6_next {
            poll_recv_from_two(cx, &mut self.socket_v6, &mut self.socket_v4)
        } else {
            poll_recv_from_two(cx, &mut self.socket_v4, &mut self.socket_v6)
        }
    }
}

pub async fn dial_datagram_session(
    context: &FlowContext,
    resolver: Arc<dyn Resolver>,
    bind_v4: Option<impl Fn(&mut socket2::Socket) -> FlowResult<()> + Send + Sync + 'static>,
    bind_v6: Option<impl Fn(&mut socket2::Socket) -> FlowResult<()> + Send + Sync + 'static>,
) -> FlowResult<Box<dyn DatagramSession>> {
    let socket_v4 = if context.af_sensitive && !context.local_peer.is_ipv4() {
        MaybeBoundSocket::Disabled
    } else {
        MaybeBoundSocket::Unbound(move |ip: Ipv4Addr| {
            if let Some(bind_v4) = &bind_v4 {
                create_socket_v4(ip, bind_v4)
            } else {
                Err(FlowError::NoOutbound)
            }
        })
    };
    let socket_v6 = if context.af_sensitive && !context.local_peer.is_ipv6() {
        MaybeBoundSocket::Disabled
    } else {
        MaybeBoundSocket::Unbound(move |ip: Ipv6Addr| {
            if let Some(bind_v6) = &bind_v6 {
                create_socket_v6(ip, bind_v6)
            } else {
                Err(FlowError::NoOutbound)
            }
        })
    };
    let (tx, rx) = oneshot::channel();

    Ok(Box::new(UdpSocket {
        socket_v4,
        socket_v6,
        bind_notify: (Some(tx), Some(rx)),
        tx_buf: None,
        resolver,
        rx_v6_next: false,
    }))
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
