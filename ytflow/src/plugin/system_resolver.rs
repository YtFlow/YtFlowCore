use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use lru::LruCache;
use parking_lot::{const_mutex, Mutex};
use tokio::net::lookup_host;
use tokio::sync::Semaphore;

use crate::flow::*;

pub struct SystemResolver {
    concurrency_limit: Semaphore,
    cache_v4: Mutex<LruCache<Ipv4Addr, String>>,
    cache_v6: Mutex<LruCache<Ipv6Addr, String>>,
}

impl SystemResolver {
    pub fn new(concurrency_limit: usize) -> Self {
        Self {
            concurrency_limit: Semaphore::new(concurrency_limit),
            cache_v4: const_mutex(LruCache::new(128)),
            cache_v6: const_mutex(LruCache::new(128)),
        }
    }
}

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        let _permit = self.concurrency_limit.acquire().await.unwrap();
        let ips = lookup_host(domain.clone() + ":0").await?;
        let mut cache = self.cache_v4.lock();
        Ok(ips
            .filter_map(|saddr| match saddr.ip() {
                IpAddr::V4(ip) => Some(ip),
                _ => None,
            })
            .inspect(|ip| (cache.put(*ip, domain.clone()), ()).1)
            .collect())
    }
    async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        let _permit = self.concurrency_limit.acquire().await.unwrap();
        let ips = lookup_host(domain.clone() + ":0").await?;
        let mut cache = self.cache_v6.lock();
        Ok(ips
            .filter_map(|saddr| match saddr.ip() {
                IpAddr::V6(ip) => Some(ip),
                _ => None,
            })
            .inspect(|ip| (cache.put(*ip, domain.clone()), ()).1)
            .collect())
    }
    async fn resolve_reverse(&self, ip: IpAddr) -> FlowResult<String> {
        Ok(match ip {
            IpAddr::V4(ip) => {
                let mut cache = self.cache_v4.lock();
                cache.get(&ip).cloned().ok_or(FlowError::NoOutbound)?
            }
            IpAddr::V6(ip) => {
                let mut cache = self.cache_v6.lock();
                cache.get(&ip).cloned().ok_or(FlowError::NoOutbound)?
            }
        })
    }
}
