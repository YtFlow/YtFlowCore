mod tcp;
mod udp;

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use flume::{bounded, SendError};
use tokio::io::AsyncWriteExt;
use tokio::net::ToSocketAddrs;

use crate::flow::*;
use crate::plugin::netif::NetifSelector;

pub struct SocketOutboundFactory {
    pub resolver: Weak<dyn Resolver>,
    pub netif_selector: Arc<NetifSelector>,
}

pub fn listen_tcp(next: Weak<dyn StreamHandler>, addr: impl ToSocketAddrs + Send + 'static) {
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        loop {
            match listener.accept().await {
                Ok((stream, connector)) => {
                    let next = match next.upgrade() {
                        Some(lower) => lower,
                        None => break Ok(()),
                    };
                    let remote_peer = stream.local_addr()?.into();
                    next.on_stream(
                        Box::new(CompactFlow::new(stream, 4096)),
                        Box::new(FlowContext {
                            local_peer: connector,
                            remote_peer,
                        }),
                    )
                }
                // TODO: log error
                Err(e) => break Err(e),
            }
        }
    });
}

pub fn listen_udp(
    next: Weak<dyn DatagramSessionHandler>,
    addr: impl ToSocketAddrs + Send + 'static,
) {
    let mut session_map = BTreeMap::new();
    let null_resolver: Arc<dyn Resolver> = Arc::new(crate::plugin::null::Null);
    tokio::spawn(async move {
        let listener = Arc::new(tokio::net::UdpSocket::bind(addr).await?);
        let listen_addr: DestinationAddr = listener.local_addr()?.into();
        let mut buf = [0u8; 4096];
        loop {
            let (size, from) = match listener.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => {
                    // TODO: log error
                    break io::Result::Ok(());
                }
            };
            let tx = session_map.entry(from).or_insert_with(|| {
                let (tx, rx) = bounded(64);
                if let Some(next) = next.upgrade() {
                    next.on_session(
                        Box::new(MultiplexedDatagramSessionAdapter::new(
                            udp::UdpSocket {
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
    });
}

#[async_trait]
impl StreamOutboundFactory for SocketOutboundFactory {
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<Box<dyn Stream>> {
        let port = context.remote_peer.port;
        let (bind_addr_v4, bind_addr_v6) = self
            .netif_selector
            .read(|netif| (netif.ipv4_addr, netif.ipv6_addr));
        let mut tcp_stream = match (context.remote_peer.dest.clone(), bind_addr_v4, bind_addr_v6) {
            (Destination::Ip(IpAddr::V4(ip)), _, _) if ip.is_loopback() => {
                tcp::dial_v4(
                    SocketAddrV4::new(ip, port),
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
                )
                .await?
            }
            (Destination::Ip(IpAddr::V6(ip)), _, _) if ip.is_loopback() => {
                tcp::dial_v6(
                    SocketAddrV6::new(ip, port, 0, 0),
                    SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0),
                )
                .await?
            }
            (Destination::Ip(IpAddr::V4(ip)), Some(bind_addr), _) => {
                tcp::dial_v4(SocketAddrV4::new(ip, port), bind_addr).await?
            }
            (Destination::Ip(IpAddr::V6(ip)), _, Some(bind_addr)) => {
                tcp::dial_v6(SocketAddrV6::new(ip, port, 0, 0), bind_addr).await?
            }
            (Destination::DomainName(domain), Some(bind_addr), _) => {
                let resolver = match self.resolver.upgrade() {
                    Some(r) => r,
                    None => return Err(FlowError::NoOutbound),
                };
                let ip = match resolver.resolve_ipv4(domain).await?.get(0) {
                    Some(ip) => *ip,
                    None => return Err(FlowError::NoOutbound),
                };
                // TODO: Preferred IF, IPv6, RFC8305 Happy Eyeballs v2
                tcp::dial_v4(SocketAddrV4::new(ip, port), bind_addr).await?
            }
            _ => return Err(FlowError::NoOutbound),
        };
        if initial_data.len() > 0 {
            tcp_stream.write_all(initial_data).await?;
        }
        Ok(Box::new(CompactFlow::new(tcp_stream, 4096)))
    }
}

#[async_trait]
impl DatagramSessionFactory for SocketOutboundFactory {
    async fn bind(&self, context: Box<FlowContext>) -> FlowResult<Box<dyn DatagramSession>> {
        let (bind_addr_v4, bind_addr_v6) = self
            .netif_selector
            .read(|netif| (netif.ipv4_addr, netif.ipv6_addr));
        let socket = match (context.remote_peer.dest.clone(), bind_addr_v4, bind_addr_v6) {
            (Destination::Ip(IpAddr::V4(ip)), _, _) if ip.is_loopback() => {
                udp::dial_v4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?
            }
            (Destination::Ip(IpAddr::V6(ip)), _, _) if ip.is_loopback() => {
                udp::dial_v6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)).await?
            }
            (Destination::Ip(IpAddr::V4(_)), Some(bind_addr), _) => udp::dial_v4(bind_addr).await?,
            (Destination::Ip(IpAddr::V6(_)), _, Some(bind_addr)) => udp::dial_v6(bind_addr).await?,
            (Destination::DomainName(domain), Some(bind_addr), _) => {
                let resolver = match self.resolver.upgrade() {
                    Some(r) => r,
                    None => return Err(FlowError::NoOutbound),
                };
                let _ip = match resolver.resolve_ipv4(domain).await?.get(0) {
                    Some(ip) => *ip,
                    None => return Err(FlowError::NoOutbound),
                };
                // TODO: IP is localhost, Preferred IF, IPv6, RFC8305 Happy Eyeballs v2
                udp::dial_v4(bind_addr).await?
            }
            _ => return Err(FlowError::NoOutbound),
        };

        let resolver = match self.resolver.upgrade() {
            Some(r) => r,
            None => return Err(FlowError::NoOutbound),
        };
        socket.writable().await?;
        let socket = Arc::new(socket);
        let (tx, rx) = bounded(0);
        tokio::spawn({
            let socket = socket.clone();
            async move {
                let mut buf = [0u8; 4096];
                loop {
                    let (size, from) = socket.recv_from(&mut buf).await?;
                    if let Err(SendError(_)) =
                        tx.send_async((from.into(), buf[..size].to_vec())).await
                    {
                        break io::Result::Ok(());
                    };
                }
            }
        });
        Ok(Box::new(MultiplexedDatagramSessionAdapter::new(
            udp::UdpSocket {
                socket,
                tx_buf: None,
                resolver,
            },
            rx.into_stream(),
            u32::MAX as u64 - 1,
        )))
    }
}
