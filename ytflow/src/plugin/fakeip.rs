use std::sync::atomic::{AtomicU16, Ordering};

use async_trait::async_trait;
use smallvec::smallvec;

use crate::flow::*;

pub struct FakeIp {
    prefix_v4: u16,
    prefix_v6: [u8; 14],
    current: AtomicU16,
}

impl FakeIp {
    pub fn new(prefix_v4: [u8; 2], prefix_v6: [u8; 14]) -> Self {
        Self {
            prefix_v4: u16::from_be_bytes(prefix_v4),
            prefix_v6,
            current: AtomicU16::new(1),
        }
    }
    fn lookup_or_alloc(&self, _domain: String) -> u16 {
        self.current.fetch_add(1, Ordering::Relaxed)
    }
}

#[async_trait]
impl Resolver for FakeIp {
    async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        Ok(smallvec![(((self.prefix_v4 as u32) << 16)
            | (self.lookup_or_alloc(domain) as u32))
            .to_be_bytes()
            .into()])
    }
    async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        let mut bytes = [0; 16];
        bytes[..14].copy_from_slice(&self.prefix_v6);
        let index = self.lookup_or_alloc(domain);
        bytes[14] = (index >> 8) as u8;
        bytes[15] = (index & 0xFF) as u8;
        Ok(smallvec![bytes.into()])
    }
}
