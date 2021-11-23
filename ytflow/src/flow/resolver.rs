use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use smallvec::SmallVec;

use super::FlowResult;

pub type ResolvedV4 = SmallVec<[Ipv4Addr; 4]>;
pub type ResolvedV6 = SmallVec<[Ipv6Addr; 2]>;
pub type ResolveResultV4 = super::FlowResult<SmallVec<[Ipv4Addr; 4]>>;
pub type ResolveResultV6 = super::FlowResult<SmallVec<[Ipv6Addr; 2]>>;

#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4;
    async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6;
    async fn resolve_reverse(&self, ip: IpAddr) -> FlowResult<String>;
}
