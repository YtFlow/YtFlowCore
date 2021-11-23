use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering::{Acquire, Relaxed};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use tokio::sync::RwLock;

use super::{Netif, NetifSelector};
use crate::flow::*;
use crate::plugin::host_resolver::HostResolver;
use crate::plugin::redirect::{DatagramSessionRedirectFactory, StreamRedirectOutboundFactory};

pub struct NetifHostResolver {
    inner: RwLock<(
        HostResolver,
        Vec<Arc<dyn StreamOutboundFactory>>,
        Vec<Arc<dyn DatagramSessionFactory>>,
    )>,
    selector: Arc<NetifSelector>,
    tcp_next: Weak<dyn StreamOutboundFactory>,
    udp_next: Weak<dyn DatagramSessionFactory>,
    change_token: AtomicU8,
}

impl NetifHostResolver {
    pub fn new(
        selector: Arc<NetifSelector>,
        tcp_next: Weak<dyn StreamOutboundFactory>,
        udp_next: Weak<dyn DatagramSessionFactory>,
    ) -> Self {
        let token = selector.change_token.load(Acquire);
        let servers = selector.read(|netif| netif.dns_servers.clone());
        let inner = RwLock::new(create_host_resolver(udp_next.clone(), servers));

        Self {
            inner,
            selector,
            tcp_next,
            udp_next,
            change_token: AtomicU8::new(token),
        }
    }
    async fn ensure_up_to_date(&self) {
        let old_token = self.change_token.load(Relaxed);
        let new_token = self.selector.change_token.load(Relaxed);
        if old_token == new_token {
            return;
        }

        let mut guard = self.inner.write().await;

        let old_token = self.change_token.load(Relaxed);
        let new_token = self.selector.change_token.load(Acquire);
        if old_token == new_token {
            return;
        }

        let servers = self.selector.read(|netif| netif.dns_servers.clone());
        *guard = create_host_resolver(self.udp_next.clone(), servers);

        self.change_token.store(new_token, Relaxed);
    }
}

fn create_host_resolver(
    udp_next: Weak<dyn DatagramSessionFactory>,
    servers: Vec<IpAddr>,
) -> (
    HostResolver,
    Vec<Arc<dyn StreamOutboundFactory>>,
    Vec<Arc<dyn DatagramSessionFactory>>,
) {
    // TODO: tcp factories
    let mut udp_factories = Vec::with_capacity(servers.len());
    let mut weak_udp_factories = Vec::with_capacity(servers.len());

    for server in servers {
        let remote_peer = DestinationAddr {
            dest: Destination::Ip(server),
            port: 53,
        };
        let factory = Arc::new(crate::plugin::redirect::DatagramSessionRedirectFactory {
            remote_peer: move || remote_peer.clone(),
            next: udp_next.clone(),
        });
        weak_udp_factories.push(Arc::downgrade(&factory) as _);
        udp_factories.push(factory as _);
    }

    (
        HostResolver::new(weak_udp_factories.into_iter()),
        vec![],
        udp_factories,
    )
}

#[async_trait]
impl Resolver for NetifHostResolver {
    async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        self.ensure_up_to_date().await;
        let guard = self.inner.read().await;
        guard.0.resolve_ipv4(domain).await
    }
    async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        self.ensure_up_to_date().await;
        let guard = self.inner.read().await;
        guard.0.resolve_ipv6(domain).await
    }
    async fn resolve_reverse(&'_ self, ip: IpAddr) -> FlowResult<String> {
        self.ensure_up_to_date().await;
        let guard = self.inner.read().await;
        guard.0.resolve_reverse(ip).await
    }
}
