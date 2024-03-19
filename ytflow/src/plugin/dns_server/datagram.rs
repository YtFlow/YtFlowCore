use std::collections::BTreeMap;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, Weak};

use futures::future::poll_fn;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, Semaphore};
use trust_dns_resolver::proto::op::{Message as DnsMessage, MessageType, ResponseCode};
use trust_dns_resolver::proto::rr::{RData, Record, RecordType};
use trust_dns_resolver::proto::serialize::binary::BinDecodable;

use crate::data::PluginCache;
use crate::flow::*;

const CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).unwrap();
const REVERSE_MAPPING_V4_CACHE_KEY: &str = "rev_v4";
const REVERSE_MAPPING_V6_CACHE_KEY: &str = "rev_v6";

pub struct DnsServer {
    concurrency_limit: Arc<Semaphore>,
    resolver: Weak<dyn Resolver>,
    ttl: u32,
    pub(super) reverse_mapping_v4: Arc<Mutex<LruCache<Ipv4Addr, String>>>,
    pub(super) reverse_mapping_v6: Arc<Mutex<LruCache<Ipv6Addr, String>>>,
    plugin_cache: PluginCache,
    pub(super) new_notify: Arc<Notify>,
}

#[derive(Debug, Clone, Default, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct ReverseMappingCache<T: Ord>(BTreeMap<T, String>);

impl DnsServer {
    pub fn new(
        concurrency_limit: usize,
        resolver: Weak<dyn Resolver>,
        ttl: u32,
        plugin_cache: PluginCache,
    ) -> Self {
        let concurrency_limit = Arc::new(Semaphore::new(concurrency_limit));
        let mut reverse_mapping_v4 = LruCache::new(CACHE_CAPACITY);
        let mut reverse_mapping_v6 = LruCache::new(CACHE_CAPACITY);
        if let Some(reverse_mapping_v4_cache) = plugin_cache
            .get::<ReverseMappingCache<_>>(REVERSE_MAPPING_V4_CACHE_KEY)
            .ok()
            .flatten()
        {
            for (k, v) in reverse_mapping_v4_cache.0 {
                reverse_mapping_v4.put(k, v);
            }
        }
        if let Some(reverse_mapping_v6_cache) = plugin_cache
            .get::<ReverseMappingCache<_>>(REVERSE_MAPPING_V6_CACHE_KEY)
            .ok()
            .flatten()
        {
            for (k, v) in reverse_mapping_v6_cache.0 {
                reverse_mapping_v6.put(k, v);
            }
        }
        DnsServer {
            concurrency_limit,
            resolver,
            ttl,
            reverse_mapping_v4: Arc::new(Mutex::new(reverse_mapping_v4)),
            reverse_mapping_v6: Arc::new(Mutex::new(reverse_mapping_v6)),
            plugin_cache,
            new_notify: Arc::new(Notify::new()),
        }
    }

    fn save_reverse_mapping_cache<T: Serialize + Hash + Eq + Ord + Clone>(
        &self,
        cache: &Mutex<LruCache<T, String>>,
        key: &str,
    ) {
        let cache = {
            let inner = cache.lock().unwrap();
            ReverseMappingCache(
                (&*inner)
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            )
        };
        self.plugin_cache.set(key, &cache).ok();
    }
    pub(crate) fn save_cache(&self) {
        self.save_reverse_mapping_cache(&self.reverse_mapping_v4, REVERSE_MAPPING_V4_CACHE_KEY);
        self.save_reverse_mapping_cache(&self.reverse_mapping_v6, REVERSE_MAPPING_V6_CACHE_KEY);
    }
}

impl DatagramSessionHandler for DnsServer {
    fn on_session(&self, mut session: Box<dyn DatagramSession>, _context: Box<FlowContext>) {
        let resolver = match self.resolver.upgrade() {
            Some(resolver) => resolver,
            None => return,
        };
        let concurrency_limit = self.concurrency_limit.clone();
        let ttl = self.ttl;
        let reverse_mapping_v4 = self.reverse_mapping_v4.clone();
        let reverse_mapping_v6 = self.reverse_mapping_v6.clone();
        let new_notify = self.new_notify.clone();
        tokio::spawn(async move {
            let mut send_ready = true;
            while let Some((dest, buf)) = poll_fn(|cx| {
                if !send_ready {
                    send_ready = session.as_mut().poll_send_ready(cx).is_ready()
                }
                session.as_mut().poll_recv_from(cx)
            })
            .await
            {
                let _concurrency_permit = match concurrency_limit.acquire().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };

                let mut msg = match DnsMessage::from_bytes(&buf) {
                    Ok(msg) => msg,
                    Err(_) => continue,
                };
                let mut res_code = ResponseCode::NoError;
                let mut ans_records = Vec::with_capacity(msg.queries().len());
                let mut notify_cache_update = false;
                for query in msg.queries() {
                    let name = query.name();
                    let name_str = name.to_lowercase().to_ascii();
                    match query.query_type() {
                        RecordType::A => {
                            let ips = match resolver.resolve_ipv4(name_str.clone()).await {
                                Ok(addrs) => addrs,
                                Err(_) => {
                                    res_code = ResponseCode::NXDomain;
                                    continue;
                                }
                            };
                            let mut reverse_mapping = reverse_mapping_v4.lock().unwrap();
                            for ip in &ips {
                                notify_cache_update |= reverse_mapping
                                    .peek_mut(ip)
                                    .filter(|n| *n == &name_str)
                                    .is_none();
                                reverse_mapping.get_or_insert(*ip, || name_str.clone());
                            }
                            ans_records.extend(
                                ips.into_iter().map(|addr| {
                                    Record::from_rdata(name.clone(), ttl, RData::A(addr))
                                }),
                            )
                        }
                        RecordType::AAAA => {
                            let ips = match resolver.resolve_ipv6(name_str.clone()).await {
                                Ok(addrs) => addrs,
                                Err(_) => {
                                    res_code = ResponseCode::NXDomain;
                                    continue;
                                }
                            };
                            let mut reverse_mapping = reverse_mapping_v6.lock().unwrap();
                            for ip in &ips {
                                notify_cache_update |= reverse_mapping
                                    .peek_mut(ip)
                                    .filter(|n| *n == &name_str)
                                    .is_none();
                                reverse_mapping.get_or_insert(*ip, || name_str.clone());
                            }
                            ans_records.extend(ips.into_iter().map(|addr| {
                                Record::from_rdata(name.clone(), ttl, RData::AAAA(addr))
                            }))
                        }
                        // TODO: SRV
                        _ => {
                            res_code = ResponseCode::NotImp;
                            continue;
                        }
                    }
                }
                if notify_cache_update {
                    new_notify.notify_one();
                }

                *msg.set_message_type(MessageType::Response)
                    .set_response_code(res_code)
                    .answers_mut() = ans_records;

                let response = match msg.to_vec() {
                    Ok(vec) => vec,
                    Err(_) => continue,
                };
                if !send_ready {
                    poll_fn(|cx| session.as_mut().poll_send_ready(cx)).await;
                }
                session.as_mut().send_to(dest, response);
                send_ready = false;
            }
            poll_fn(|cx| session.as_mut().poll_shutdown(cx)).await
        });
    }
}
