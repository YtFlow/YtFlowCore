use std::net::IpAddr;

use async_trait::async_trait;
use tokio::net::lookup_host;

use crate::flow::*;

pub struct SystemResolver {}

impl SystemResolver {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        let ips = lookup_host(domain.clone() + ":0").await?;
        Ok(ips
            .filter_map(|saddr| match saddr.ip() {
                IpAddr::V4(ip) => Some(ip),
                _ => None,
            })
            .collect())
    }
    async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        let ips = lookup_host(domain.clone() + ":0").await?;
        Ok(ips
            .filter_map(|saddr| match saddr.ip() {
                IpAddr::V6(ip) => Some(ip),
                _ => None,
            })
            .collect())
    }
}
