use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use crate::flow::*;

fn prepare_socket(socket: &socket2::Socket) -> io::Result<()> {
    socket.set_nodelay(true)?;
    socket.set_tcp_keepalive(super::SOCKET_KEEPALIVE)?;
    socket.set_nonblocking(true)?;
    Ok(())
}

pub fn listen_tcp(
    next: Weak<dyn StreamHandler>,
    addr: impl ToSocketAddrs + Send + 'static,
) -> io::Result<tokio::task::JoinHandle<()>> {
    let listener = std::net::TcpListener::bind(addr)?;
    let socket = socket2::Socket::from(listener);
    socket.set_reuse_address(true)?;
    prepare_socket(&socket)?;
    let listener = tokio::net::TcpListener::from_std(socket.into())?;
    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, connector)) => {
                    let next = match next.upgrade() {
                        Some(lower) => lower,
                        None => break,
                    };
                    let remote_peer = match stream.local_addr() {
                        Ok(addr) => addr,
                        // TODO: log error
                        Err(_) => continue,
                    }
                    .into();
                    next.on_stream(
                        Box::new(CompatFlow::new(stream, 4096)),
                        Buffer::new(),
                        Box::new(FlowContext {
                            local_peer: connector,
                            remote_peer,
                            af_sensitive: false,
                        }),
                    )
                }
                // TODO: log error
                Err(_) => break,
            }
        }
    }))
}

async fn dial_socket_v4(
    ip: Ipv4Addr,
    port: u16,
    bind_v4: &impl Fn(&mut socket2::Socket) -> FlowResult<()>,
) -> FlowResult<TcpStream> {
    let mut socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    prepare_socket(&socket)?;
    if ip.is_loopback() {
        socket.bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())?
    } else {
        bind_v4(&mut socket)?
    };
    let socket = TcpSocket::from_std_stream(socket.into());
    Ok(socket.connect(SocketAddrV4::new(ip, port).into()).await?)
}

async fn dial_socket_v6(
    ip: Ipv6Addr,
    port: u16,
    bind_v6: &impl Fn(&mut socket2::Socket) -> FlowResult<()>,
) -> FlowResult<TcpStream> {
    let mut socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    prepare_socket(&socket)?;
    if ip.is_loopback() {
        socket.bind(&SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0).into())?
    } else {
        bind_v6(&mut socket)?
    };
    let socket = TcpSocket::from_std_stream(socket.into());
    Ok(socket
        .connect(SocketAddrV6::new(ip, port, 0, 0).into())
        .await?)
}

pub async fn dial_stream(
    context: &FlowContext,
    resolver: Arc<dyn Resolver>,
    bind_v4: Option<impl Fn(&mut socket2::Socket) -> FlowResult<()>>,
    bind_v6: Option<impl Fn(&mut socket2::Socket) -> FlowResult<()>>,
    initial_data: &[u8],
) -> FlowResult<(Box<dyn Stream>, Buffer)> {
    let port = context.remote_peer.port;
    let mut tcp_stream = match (context.remote_peer.host.clone(), bind_v4, bind_v6) {
        (HostName::Ip(IpAddr::V4(ip)), Some(bind_v4), _) => {
            dial_socket_v4(ip, port, &bind_v4).await?
        }
        (HostName::Ip(IpAddr::V6(ip)), _, Some(bind_v6)) => {
            dial_socket_v6(ip, port, &bind_v6).await?
        }
        (HostName::DomainName(domain), Some(bind_v4), None) => {
            let mut ip_iter = resolver.resolve_ipv4(domain).await?.into_iter();
            let mut ret = Err(FlowError::NoOutbound);
            let mut futs = FuturesUnordered::new();
            while let Some(ip) = ip_iter.next() {
                futs.push(dial_socket_v4(ip, port, &bind_v4));
                if timeout(super::CONN_ATTEMPT_DELAY, async {
                    while let Some(r) = futs.next().await {
                        ret = r;
                        if ret.is_ok() {
                            return true;
                        }
                    }
                    false
                })
                .await
                    == Ok(true)
                {
                    break;
                }
            }
            loop {
                match ret {
                    Ok(stream) => break stream,
                    Err(e) => match futs.next().await {
                        Some(r) => {
                            ret = r;
                            continue;
                        }
                        None => return Err(e),
                    },
                }
            }
        }
        (HostName::DomainName(domain), None, Some(bind_v6)) => {
            let mut ip_iter = resolver.resolve_ipv6(domain).await?.into_iter();
            let mut ret = Err(FlowError::NoOutbound);
            let mut futs = FuturesUnordered::new();
            while let Some(ip) = ip_iter.next() {
                futs.push(dial_socket_v6(ip, port, &bind_v6));
                if timeout(super::CONN_ATTEMPT_DELAY, async {
                    while let Some(r) = futs.next().await {
                        ret = r;
                        if ret.is_ok() {
                            return true;
                        }
                    }
                    false
                })
                .await
                    == Ok(true)
                {
                    break;
                }
            }
            loop {
                match ret {
                    Ok(stream) => break stream,
                    Err(e) => match futs.next().await {
                        Some(r) => {
                            ret = r;
                            continue;
                        }
                        None => return Err(e),
                    },
                }
            }
        }
        (HostName::DomainName(domain), Some(bind_v4), Some(bind_v6)) => {
            let (ip_tx, mut ip_rx) = tokio::sync::mpsc::channel::<IpAddr>(1);
            tokio::spawn({
                let resolver = resolver.clone();
                async move { super::resolve_dual_stack_ips(domain, &*resolver, ip_tx).await }
            });
            let mut ret = Err(FlowError::NoOutbound);
            let mut futs = FuturesUnordered::new();
            while let Some(ip) = ip_rx.recv().await {
                futs.push({
                    let (bind_v4, bind_v6) = (&bind_v4, &bind_v6);
                    async move {
                        Ok(match ip {
                            IpAddr::V4(ip) => dial_socket_v4(ip, port, &bind_v4).await?,
                            IpAddr::V6(ip) => dial_socket_v6(ip, port, &bind_v6).await?,
                        })
                    }
                });
                if timeout(super::CONN_ATTEMPT_DELAY, async {
                    while let Some(r) = futs.next().await {
                        ret = r;
                        if ret.is_ok() {
                            return true;
                        }
                    }
                    false
                })
                .await
                    == Ok(true)
                {
                    break;
                }
            }
            loop {
                match ret {
                    Ok(stream) => break stream,
                    Err(e) => match futs.next().await {
                        Some(r) => {
                            ret = r;
                            continue;
                        }
                        None => return Err(e),
                    },
                }
            }
        }
        _ => return Err(FlowError::NoOutbound),
    };
    if !initial_data.is_empty() {
        tcp_stream.write_all(initial_data).await?;
    }
    Ok((Box::new(CompatFlow::new(tcp_stream, 4096)), Buffer::new()))
}

#[async_trait]
impl StreamOutboundFactory for super::SocketOutboundFactory {
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let Self {
            bind_addr_v4,
            bind_addr_v6,
            ..
        } = self;

        let resolver = self.resolver.upgrade().ok_or(FlowError::NoOutbound)?;
        dial_stream(
            &context,
            resolver,
            bind_addr_v4.clone().map(|addr| {
                move |s: &mut socket2::Socket| s.bind(&addr.into()).map_err(FlowError::from)
            }),
            bind_addr_v6.clone().map(|addr| {
                move |s: &mut socket2::Socket| s.bind(&addr.into()).map_err(FlowError::from)
            }),
            initial_data,
        )
        .await
    }
}
