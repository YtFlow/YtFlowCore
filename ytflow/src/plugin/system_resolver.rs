use std::io::{self, ErrorKind};
use std::net::IpAddr;

use async_trait::async_trait;
use smallvec::SmallVec;
use tokio::net::lookup_host;

use crate::flow::*;

#[derive(Default)]
pub struct SystemResolver {}

impl SystemResolver {
    pub fn new() -> Self {
        Default::default()
    }
}

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        let ips = lookup_host(domain.clone() + ":0").await?;
        let records = ips
            .filter_map(|saddr| match saddr.ip() {
                IpAddr::V4(ip) => Some(ip),
                _ => None,
            })
            .collect::<SmallVec<_>>();
        if records.is_empty() {
            Err(io::Error::new(ErrorKind::NotFound, "IPv4 record not found").into())
        } else {
            Ok(records)
        }
    }
    async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        let ips = lookup_host(domain.clone() + ":0").await?;
        let records = ips
            .filter_map(|saddr| match saddr.ip() {
                IpAddr::V6(ip) => Some(ip),
                _ => None,
            })
            .collect::<SmallVec<_>>();
        if records.is_empty() {
            Err(io::Error::new(ErrorKind::NotFound, "IPv6 record not found").into())
        } else {
            Ok(records)
        }
    }
}
