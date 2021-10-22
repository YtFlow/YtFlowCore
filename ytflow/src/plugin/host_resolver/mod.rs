mod udp_adapter;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Weak;

use async_trait::async_trait;
use lru::LruCache;
use parking_lot::{const_mutex, Mutex};
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

const CACHE_CAPACITY: usize = 1024;

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
    cache_v4: Mutex<LruCache<Ipv4Addr, String>>,
    cache_v6: Mutex<LruCache<Ipv6Addr, String>>,
}

impl HostResolver {
    pub fn new(datagram_hosts: Vec<Weak<dyn DatagramSessionFactory>>) -> Self {
        let mut dns_configs = Vec::with_capacity(datagram_hosts.len());
        let mut factory_ids = Vec::with_capacity(datagram_hosts.len());
        dns_configs.reserve(datagram_hosts.len());
        {
            let mut guard = UDP_FACTORIES.write();
            let (max_id, factories) = &mut *guard;
            for factory in datagram_hosts {
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
            cache_v4: const_mutex(LruCache::new(CACHE_CAPACITY)),
            cache_v6: const_mutex(LruCache::new(CACHE_CAPACITY)),
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
        for &ip in &res {
            self.cache_v4.lock().put(ip, domain.clone());
        }
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
        for &ip in &res {
            self.cache_v6.lock().put(ip, domain.clone());
        }
        Ok(res)
    }
    async fn resolve_reverse(&'_ self, ip: IpAddr) -> FlowResult<String> {
        if let Some(s) = match &ip {
            IpAddr::V4(ip) => self.cache_v4.lock().get(ip).map(|s| s.clone()),
            IpAddr::V6(ip) => self.cache_v6.lock().get(ip).map(|s| s.clone()),
        } {
            return Ok(s);
        }
        let res = self
            .inner
            .reverse_lookup(ip)
            .await
            .map_err(resolve_error_to_flow_error)?;
        Ok(res.iter().next().unwrap().to_ascii())
    }
}

impl Drop for HostResolver {
    fn drop(&mut self) {
        let mut guard = UDP_FACTORIES.write();
        let (_, factories) = &mut *guard;
        for id in &self.factory_ids {
            factories.remove(id);
        }
    }
}
