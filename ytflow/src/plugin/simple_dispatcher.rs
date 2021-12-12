use std::ops::RangeInclusive;

use std::sync::Weak;

use cidr::IpCidr;
use serde::Deserialize;
use smallvec::SmallVec;

use crate::flow::*;

#[derive(Clone, Deserialize)]
pub struct Condition {
    pub ip_ranges: SmallVec<[IpCidr; 2]>,
    pub port_ranges: SmallVec<[RangeInclusive<u16>; 4]>,
}

pub struct Rule<N> {
    pub src_cond: Condition,
    pub dst_cond: Condition,
    pub next: N,
}

impl<N: Clone> Rule<N> {
    fn matches(&self, context: &FlowContext) -> Option<N> {
        // Match src
        {
            let Condition {
                ip_ranges,
                port_ranges,
            } = &self.src_cond;
            let ip = context.local_peer.ip();
            let port = context.local_peer.port();
            if !ip_ranges.iter().any(|r| r.contains(&ip)) {
                return None;
            }
            if !port_ranges.iter().any(|r| r.contains(&port)) {
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
            if !port_ranges.iter().any(|r| r.contains(&port)) {
                return None;
            }
            match &context.remote_peer.dest {
                Destination::Ip(ip) if !ip_ranges.iter().any(|r| r.contains(ip)) => return None,
                Destination::DomainName(_) => return None,
                _ => Some(self.next.clone()),
            }
        }
    }
}

pub type StreamRule = Rule<Weak<dyn StreamHandler>>;
pub type DatagramRule = Rule<Weak<dyn DatagramSessionHandler>>;

pub struct SimpleStreamDispatcher {
    pub rules: Vec<StreamRule>,
    pub fallback: Weak<dyn StreamHandler>,
}

pub struct SimpleDatagramDispatcher {
    pub rules: Vec<DatagramRule>,
    pub fallback: Weak<dyn DatagramSessionHandler>,
}

impl StreamHandler for SimpleStreamDispatcher {
    fn on_stream(&self, lower: Box<dyn Stream>, context: Box<FlowContext>) {
        let handler = self
            .rules
            .iter()
            .find_map(|r| r.matches(&context))
            .unwrap_or_else(|| self.fallback.clone());
        if let Some(handler) = handler.upgrade() {
            handler.on_stream(lower, context)
        }
    }
}

impl DatagramSessionHandler for SimpleDatagramDispatcher {
    fn on_session(&self, session: Box<dyn DatagramSession>, context: Box<FlowContext>) {
        let handler = self
            .rules
            .iter()
            .find_map(|r| r.matches(&context))
            .unwrap_or_else(|| self.fallback.clone());
        if let Some(handler) = handler.upgrade() {
            handler.on_session(session, context)
        }
    }
}
