pub mod doh_adapter;
mod udp_adapter;

use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use trust_dns_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::name_server::{
    GenericConnection, GenericConnectionProvider, RuntimeProvider, TokioHandle, TokioRuntime,
};
use trust_dns_resolver::AsyncResolver;

use crate::flow::*;
use udp_adapter::*;

#[derive(Clone)]
struct FlowRuntime {}

impl RuntimeProvider for FlowRuntime {
    type Handle = <TokioRuntime as RuntimeProvider>::Handle;
    type Timer = <TokioRuntime as RuntimeProvider>::Timer;
    type Tcp = <TokioRuntime as RuntimeProvider>::Tcp;
    type Udp = FlowDatagramSocket;
}

pub struct HostResolver {
    inner: AsyncResolver<GenericConnection, GenericConnectionProvider<FlowRuntime>>,
    factory_ids: Vec<u32>,
    _doh: Vec<Arc<doh_adapter::DohDatagramAdapterFactory>>,
}

impl HostResolver {
    pub fn new(
        datagram_hosts: impl IntoIterator<Item = Weak<dyn DatagramSessionFactory>>,
        doh: impl IntoIterator<Item = doh_adapter::DohDatagramAdapterFactory>,
    ) -> Self {
        let datagram_hosts = datagram_hosts.into_iter();
        let doh = doh.into_iter();
        let size_hint = datagram_hosts.size_hint().1.unwrap_or(0) + doh.size_hint().1.unwrap_or(0);
        let doh_factories = doh.map(Arc::new).collect::<Vec<_>>();
        let mut dns_configs = Vec::with_capacity(size_hint);
        let mut factory_ids = Vec::with_capacity(size_hint);
        {
            // The iterator may recursively create new HostResolvers.
            // Holding the lock across iterations may cause deadlock.
            for factory in &doh_factories {
                let mut guard = UDP_FACTORIES.write().unwrap();
                let (max_id, factories) = &mut *guard;
                *max_id = max_id.wrapping_add(1);
                factories.insert(*max_id, Arc::downgrade(factory) as _);
                dns_configs.push(NameServerConfig {
                    socket_addr: SocketAddr::new(max_id.to_ne_bytes().into(), 53),
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                    trust_nx_responses: false,
                });
                factory_ids.push(*max_id);
            }
            for factory in datagram_hosts {
                let mut guard = UDP_FACTORIES.write().unwrap();
                let (max_id, factories) = &mut *guard;
                *max_id = max_id.wrapping_add(1);
                factories.insert(*max_id, factory);
                dns_configs.push(NameServerConfig {
                    socket_addr: SocketAddr::new(max_id.to_ne_bytes().into(), 53),
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                    trust_nx_responses: false,
                });
                factory_ids.push(*max_id);
            }
        }
        dns_configs.shrink_to_fit();
        factory_ids.shrink_to_fit();
        let inner =
            AsyncResolver::<GenericConnection, GenericConnectionProvider<FlowRuntime>>::new(
                ResolverConfig::from_parts(None, vec![], NameServerConfigGroup::from(dns_configs)),
                ResolverOpts::default(),
                TokioHandle,
            )
            .unwrap();
        Self {
            inner,
            factory_ids,
            _doh: doh_factories,
        }
    }
}

fn resolve_error_to_flow_error(e: ResolveError) -> FlowError {
    use std::io::{Error, ErrorKind};
    use trust_dns_resolver::error::ResolveErrorKind::*;
    match e.kind() {
        Message(s) => Error::new(ErrorKind::Other, *s),
        Msg(s) => Error::new(ErrorKind::Other, s.as_str()),
        NoRecordsFound { .. } => Error::new(ErrorKind::NotFound, "DNS record not found"),
        Io(e) => Error::new(e.kind(), "DNS IO error"),
        Proto(_) => return FlowError::UnexpectedData,
        Timeout => Error::new(ErrorKind::TimedOut, "DNS timeout"),
    }
    .into()
}

#[async_trait]
impl Resolver for HostResolver {
    async fn resolve_ipv4(&self, mut domain: String) -> ResolveResultV4 {
        if !domain.ends_with('.') {
            domain.push('.');
        }
        let res = self
            .inner
            .ipv4_lookup(domain.as_str())
            .await
            .map_err(resolve_error_to_flow_error)?;
        let res = res.into_iter().collect();
        Ok(res)
    }
    async fn resolve_ipv6(&self, mut domain: String) -> ResolveResultV6 {
        if !domain.ends_with('.') {
            domain.push('.');
        }
        let res = self
            .inner
            .ipv6_lookup(domain.as_str())
            .await
            .map_err(resolve_error_to_flow_error)?;
        let res = res.into_iter().collect();
        Ok(res)
    }
}

impl Drop for HostResolver {
    fn drop(&mut self) {
        let mut guard = UDP_FACTORIES.write().unwrap();
        let (_, factories) = &mut *guard;
        for id in &self.factory_ids {
            factories.remove(id);
        }
    }
}
