use std::net::IpAddr;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering::{Acquire, Relaxed};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use tokio::sync::RwLock;

use super::{FamilyPreference, NetifSelector};
use crate::flow::*;
use crate::plugin::host_resolver::HostResolver;
use crate::plugin::null::Null;

#[allow(dead_code)]
pub struct NetifHostResolver {
    inner: RwLock<(
        HostResolver,
        Vec<Arc<dyn StreamOutboundFactory>>,
        Vec<Arc<dyn DatagramSessionFactory>>,
    )>,
    selector: Arc<NetifSelector>,
    tcp_next: Arc<dyn StreamOutboundFactory>,
    udp_next: Arc<dyn DatagramSessionFactory>,
    change_token: AtomicU8,
    _socket_resolver: Arc<Null>,
}

impl NetifHostResolver {
    pub fn new(selector: Arc<NetifSelector>) -> Self {
        let token = selector.change_token.load(Acquire);
        let servers = selector.read(|netif| netif.dns_servers.clone());

        let socket_resolver = Arc::new(Null);
        let socket_factory = Arc::new(crate::plugin::socket::SocketOutboundFactory {
            resolver: Arc::downgrade(&socket_resolver) as _,
            netif_selector: selector.clone(),
        });
        let inner = RwLock::new(create_host_resolver(
            Arc::downgrade(&(socket_factory.clone() as _)),
            servers,
        ));

        Self {
            inner,
            selector,
            tcp_next: socket_factory.clone(),
            udp_next: socket_factory,
            change_token: AtomicU8::new(token),
            _socket_resolver: socket_resolver,
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

        let servers = self.selector.read(|netif| match self.selector.prefer {
            FamilyPreference::NoPreference => netif.dns_servers.clone(),
            FamilyPreference::PreferIpv4 => netif
                .dns_servers
                .iter()
                .filter(|d| d.is_ipv4())
                .cloned()
                .collect(),
            FamilyPreference::PreferIpv6 => netif
                .dns_servers
                .iter()
                .filter(|d| d.is_ipv6())
                .cloned()
                .collect(),
        });
        *guard = create_host_resolver(Arc::downgrade(&self.udp_next), servers);

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
