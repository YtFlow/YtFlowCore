use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use lru::LruCache;
use smallvec::smallvec;

use crate::flow::*;

const CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1000).unwrap();

struct Inner {
    current: u16,
    cache: LruCache<String, u16>,
}

pub struct FakeIp {
    prefix_v4: u16,
    prefix_v6: [u8; 14],
    inner: Mutex<Inner>,
}

impl FakeIp {
    pub fn new(prefix_v4: [u8; 2], prefix_v6: [u8; 14]) -> Self {
        // TODO: persist current cursor into cache
        Self {
            prefix_v4: u16::from_be_bytes(prefix_v4),
            prefix_v6,
            inner: Mutex::new(Inner {
                current: 1,
                cache: LruCache::new(CACHE_SIZE),
            }),
        }
    }
    fn lookup_or_alloc(&self, domain: String) -> u16 {
        let mut inner = self.inner.lock().unwrap();
        let cached = inner.cache.get(&*domain).copied();
        if let Some(cached) = cached {
            return cached;
        }
        let ret = inner.current;
        inner.cache.put(domain, ret);
        inner.current += 1;
        ret
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
