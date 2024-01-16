use std::net::IpAddr;
use std::sync::{Arc, Weak};

use arc_swap::AsRaw;
use tokio::sync::RwLock;

use super::{FamilyPreference, NetifSelector};
use crate::flow::*;
use crate::plugin::host_resolver::HostResolver;

pub(super) struct NetifHostResolver {
    inner: RwLock<(
        HostResolver,
        usize,
        Vec<Arc<dyn StreamOutboundFactory>>,
        Vec<Arc<dyn DatagramSessionFactory>>,
    )>,
    selector: Weak<NetifSelector>,
}

impl NetifHostResolver {
    pub fn new(selector: Weak<NetifSelector>) -> Self {
        Self {
            inner: RwLock::new((HostResolver::new([], []), 0, vec![], vec![])),
            selector,
        }
    }
    async fn ensure_up_to_date(&self) {
        let Some(selector) = self.selector.upgrade() else {
            return;
        };
        {
            let guard = self.inner.read().await;
            let old_ptr = guard.1;
            if selector.cached_netif.load().as_raw() as usize == old_ptr {
                return;
            }
        }

        let mut guard = self.inner.write().await;

        let netif = selector.cached_netif.load();
        let old_ptr = guard.1;
        let new_ptr = netif.as_raw() as usize;
        if new_ptr == old_ptr {
            return;
        }

        let preference = selector.selection.load().1;
        let servers = netif.dns_servers().await;
        let servers = servers.iter().cloned().filter(|dns| match preference {
            FamilyPreference::Both => true,
            FamilyPreference::Ipv4Only => dns.is_ipv4(),
            FamilyPreference::Ipv6Only => dns.is_ipv6(),
        });
        let (resolver, tcp_next, udp_next) = create_host_resolver(self.selector.clone(), servers);
        *guard = (resolver, new_ptr, tcp_next, udp_next);
    }

    pub async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        self.ensure_up_to_date().await;
        let guard = self.inner.read().await;
        guard.0.resolve_ipv4(domain).await
    }
    pub async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        self.ensure_up_to_date().await;
        let guard = self.inner.read().await;
        guard.0.resolve_ipv6(domain).await
    }
}

fn create_host_resolver(
    udp_next: Weak<dyn DatagramSessionFactory>,
    servers: impl IntoIterator<Item = IpAddr>,
) -> (
    HostResolver,
    Vec<Arc<dyn StreamOutboundFactory>>,
    Vec<Arc<dyn DatagramSessionFactory>>,
) {
    // TODO: tcp factories
    let mut udp_factories = vec![];
    let mut weak_udp_factories = vec![];

    for server in servers {
        let remote_peer = DestinationAddr {
            host: HostName::Ip(server),
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
        HostResolver::new(weak_udp_factories, []),
        vec![],
        udp_factories,
    )
}
