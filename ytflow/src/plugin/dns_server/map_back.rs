use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, Weak};
use std::task::{ready, Context, Poll};

use lru::LruCache;

use super::DnsServer;
use crate::flow::*;

#[derive(Clone)]
struct BackMapper {
    reverse_mapping_v4: Arc<Mutex<LruCache<Ipv4Addr, String>>>,
    reverse_mapping_v6: Arc<Mutex<LruCache<Ipv6Addr, String>>>,
}

impl BackMapper {
    fn map_back_host(&self, host: &mut HostName) {
        match host {
            HostName::DomainName(_) => (),
            HostName::Ip(IpAddr::V4(ip)) => {
                *host = self
                    .reverse_mapping_v4
                    .lock()
                    .unwrap()
                    .get(ip)
                    .map(|n| HostName::DomainName(n.clone()))
                    .unwrap_or(host.clone())
            }
            HostName::Ip(IpAddr::V6(ip)) => {
                *host = self
                    .reverse_mapping_v6
                    .lock()
                    .unwrap()
                    .get(ip)
                    .map(|n| HostName::DomainName(n.clone()))
                    .unwrap_or(host.clone())
            }
        }
    }
}

pub struct MapBackStreamHandler {
    back_mapper: BackMapper,
    next: Weak<dyn StreamHandler>,
}

impl MapBackStreamHandler {
    pub fn new(handler: &DnsServer, next: Weak<dyn StreamHandler>) -> Self {
        Self {
            back_mapper: BackMapper {
                reverse_mapping_v4: handler.reverse_mapping_v4.clone(),
                reverse_mapping_v6: handler.reverse_mapping_v6.clone(),
            },
            next,
        }
    }
}

impl StreamHandler for MapBackStreamHandler {
    fn on_stream(
        &self,
        lower: Box<dyn Stream>,
        initial_data: Buffer,
        mut context: Box<FlowContext>,
    ) {
        let Some(next) = self.next.upgrade() else {
            return;
        };
        self.back_mapper
            .map_back_host(&mut context.remote_peer.host);
        next.on_stream(lower, initial_data, context)
    }
}

pub struct MapBackDatagramSessionHandler {
    back_mapper: BackMapper,
    next: Weak<dyn DatagramSessionHandler>,
}

impl DatagramSessionHandler for MapBackDatagramSessionHandler {
    fn on_session(&self, session: Box<dyn DatagramSession>, mut context: Box<FlowContext>) {
        let Some(next) = self.next.upgrade() else {
            return;
        };
        self.back_mapper
            .map_back_host(&mut context.remote_peer.host);
        next.on_session(
            Box::new(MapBackDatagramSession {
                back_mapper: self.back_mapper.clone(),
                lower: session,
                local_forward_mapping: Default::default(),
            }),
            context,
        )
    }
}

struct MapBackDatagramSession {
    back_mapper: BackMapper,
    lower: Box<dyn DatagramSession>,
    local_forward_mapping: HashMap<String, IpAddr>,
}

impl MapBackDatagramSessionHandler {
    pub fn new(handler: &DnsServer, next: Weak<dyn DatagramSessionHandler>) -> Self {
        Self {
            back_mapper: BackMapper {
                reverse_mapping_v4: handler.reverse_mapping_v4.clone(),
                reverse_mapping_v6: handler.reverse_mapping_v6.clone(),
            },
            next,
        }
    }
}

impl DatagramSession for MapBackDatagramSession {
    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>> {
        let Some((mut dest, buf)) = ready!(self.lower.as_mut().poll_recv_from(cx)) else {
            return Poll::Ready(None);
        };
        if let HostName::Ip(ip) = &dest.host {
            let ip = *ip;
            self.back_mapper.map_back_host(&mut dest.host);
            if let HostName::DomainName(domain) = &dest.host {
                self.local_forward_mapping.insert(domain.clone(), ip);
            }
        }
        Poll::Ready(Some((dest, buf)))
    }

    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.lower.as_mut().poll_send_ready(cx)
    }

    fn send_to(&mut self, mut remote_peer: DestinationAddr, buf: Buffer) {
        if let HostName::DomainName(domain) = &remote_peer.host
            && let Some(ip) = self.local_forward_mapping.get(domain)
        {
            remote_peer.host = HostName::Ip(*ip);
        }
        self.lower.send_to(remote_peer, buf)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.as_mut().poll_shutdown(cx)
    }
}
