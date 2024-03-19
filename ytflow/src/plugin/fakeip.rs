use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use smallvec::smallvec;
use tokio::sync::Notify;

use crate::data::PluginCache;
use crate::flow::*;

const CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(1000).unwrap();
const PLUGIN_CACHE_KEY: &str = "map";

struct Inner {
    current: u16,
    cache: LruCache<String, u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InnerCache {
    current: u16,
    cache: BTreeMap<String, u16>,
}

pub struct FakeIp {
    prefix_v4: u16,
    prefix_v6: [u8; 14],
    inner: Arc<Mutex<Inner>>,
    plugin_cache: PluginCache,
    new_notify: Arc<Notify>,
}

impl FakeIp {
    pub fn new(prefix_v4: [u8; 2], prefix_v6: [u8; 14], plugin_cache: PluginCache) -> Self {
        let mut lru = LruCache::new(CACHE_CAPACITY);
        let inner = match plugin_cache
            .get::<InnerCache>(PLUGIN_CACHE_KEY)
            .ok()
            .flatten()
        {
            Some(cache) => {
                for (k, v) in cache.cache {
                    lru.put(k, v);
                }
                Inner {
                    current: cache.current,
                    cache: lru,
                }
            }
            None => Inner {
                current: 1,
                cache: lru,
            },
        };
        Self {
            prefix_v4: u16::from_be_bytes(prefix_v4),
            prefix_v6,
            inner: Arc::new(Mutex::new(inner)),
            plugin_cache,
            new_notify: Arc::new(Notify::new()),
        }
    }
    fn lookup_or_alloc(&self, domain: String) -> u16 {
        let ret = {
            let mut inner = self.inner.lock().unwrap();
            let cached = inner.cache.get(&*domain).copied();
            if let Some(cached) = cached {
                return cached;
            }
            let ret = inner.current;
            inner.cache.put(domain, ret);
            inner.current = inner.current.wrapping_add(1);
            ret
        };
        self.new_notify.notify_one();
        ret
    }
    fn save_cache(&self) {
        let cache = {
            let inner = self.inner.lock().unwrap();
            InnerCache {
                current: inner.current,
                cache: inner.cache.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            }
        };
        self.plugin_cache.set(PLUGIN_CACHE_KEY, &cache).ok();
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

impl Drop for FakeIp {
    fn drop(&mut self) {
        self.save_cache();
    }
}

pub async fn cache_writer(plugin: Arc<FakeIp>) {
    let (plugin, notify) = {
        let notify = plugin.new_notify.clone();
        let weak = Arc::downgrade(&plugin);
        drop(plugin);
        (weak, notify)
    };
    if plugin.strong_count() == 0 {
        panic!("fakeip has no strong reference left for cache_writer");
    }

    use tokio::select;
    use tokio::time::{sleep, Duration};
    loop {
        let mut notified_fut = notify.notified();
        let mut sleep_fut = sleep(Duration::from_secs(3600));
        'debounce: loop {
            select! {
                _ = notified_fut => {
                    notified_fut = notify.notified();
                    sleep_fut = sleep(Duration::from_secs(3));
                }
                _ = sleep_fut => {
                    break 'debounce;
                }
            }
        }
        match plugin.upgrade() {
            Some(plugin) => plugin.save_cache(),
            None => break,
        }
    }
}
