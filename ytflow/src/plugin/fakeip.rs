use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use smallvec::smallvec;

use crate::flow::*;

const CAPACITY: u16 = 1024;

pub struct FakeIp {
    prefix_v4: u16,
    prefix_v6: [u8; 14],
    inner: Mutex<(u16, HashMap<String, u16>, HashMap<u16, String>)>,
}

impl FakeIp {
    pub fn new(prefix_v4: [u8; 2], prefix_v6: [u8; 14]) -> Self {
        Self {
            prefix_v4: u16::from_be_bytes(prefix_v4),
            prefix_v6,
            inner: Mutex::new((0, HashMap::new(), HashMap::new())),
        }
    }
    fn lookup_or_alloc(&self, domain: String) -> u16 {
        let mut guard = self.inner.lock().unwrap();
        let (index, table, rtable) = &mut *guard;
        if let Some(suffix) = table.get(&domain) {
            return *suffix;
        }

        *index = index.wrapping_add(1);
        let index_to_remove = index.wrapping_sub(CAPACITY);
        if let Some(domain_to_remove) = rtable.remove(&index_to_remove) {
            table.remove(&domain_to_remove);
            if table.len() > 100 && table.capacity() > table.len() * 5 / 2 {
                table.shrink_to_fit();
            }
            if rtable.len() > 100 && rtable.capacity() > rtable.len() * 5 / 2 {
                rtable.shrink_to_fit();
            }
        }

        rtable.insert(*index, domain.clone());
        table.insert(domain, *index);

        *index
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
    async fn resolve_reverse(&'_ self, ip: IpAddr) -> FlowResult<String> {
        let index = u16::from_be_bytes(match ip {
            IpAddr::V4(ip) => [ip.octets()[2], ip.octets()[3]],
            IpAddr::V6(ip) => [ip.octets()[14], ip.octets()[15]],
        });
        let guard = self.inner.lock().unwrap();
        guard.2.get(&index).cloned().ok_or(FlowError::NoOutbound)
    }
}
