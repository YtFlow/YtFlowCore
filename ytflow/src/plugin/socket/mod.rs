mod tcp;
mod udp;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use crate::flow::*;
use crate::plugin::netif::NetifSelector;

pub struct SocketOutboundFactory {
    pub resolver: Weak<dyn Resolver>,
    pub netif_selector: Arc<NetifSelector>,
}

#[async_trait]
impl StreamOutboundFactory for SocketOutboundFactory {
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<Pin<Box<dyn Stream>>> {
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
        Ok(Box::pin(tcp::TcpStream {
            inner: tcp_stream,
            rx_buf: None,
            tx_buf: Some((vec![0; 4 * 1024], 4 * 1024)),
        }))
    }
}

#[async_trait]
impl DatagramSessionFactory for SocketOutboundFactory {
    async fn bind(&self, context: Box<FlowContext>) -> FlowResult<Pin<Box<dyn DatagramSession>>> {
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
                let ip = match resolver.resolve_ipv4(domain).await?.get(0) {
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
        Ok(Box::pin(udp::UdpSocket {
            socket,
            tx_buf: None,
            rx_buf: vec![0; 2000],
            resolver,
        }))
    }
}
