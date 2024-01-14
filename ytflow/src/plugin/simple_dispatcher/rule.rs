use super::Condition;
use crate::flow::{FlowContext, HostName};

pub struct Rule<N> {
    pub src_cond: Condition,
    pub dst_cond: Condition,
    pub next: N,
}

impl<N: Clone> Rule<N> {
    pub(super) fn matches(&self, context: &FlowContext) -> Option<N> {
        // Match src
        {
            let Condition {
                ip_ranges,
                port_ranges,
            } = &self.src_cond;
            let ip = context.local_peer.ip();
            let port = context.local_peer.port();
            if !ip_ranges.iter().any(|r| r.inner.contains(&ip)) {
                return None;
            }
            if !port_ranges.iter().any(|r| r.inner.contains(&port)) {
                return None;
            }
        }
        // Match dst
        {
            let Condition {
                ip_ranges,
                port_ranges,
            } = &self.dst_cond;
            let port = context.remote_peer.port;
            if !port_ranges.iter().any(|r| r.inner.contains(&port)) {
                return None;
            }
            match &context.remote_peer.host {
                HostName::Ip(ip) if !ip_ranges.iter().any(|r| r.inner.contains(ip)) => None,
                HostName::DomainName(_) => None,
                _ => Some(self.next.clone()),
            }
        }
    }
}
