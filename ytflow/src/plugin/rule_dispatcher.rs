use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use futures::future::join;
use smallvec::SmallVec;

mod builder;
pub(self) mod rules;
mod set;

use crate::flow::*;

pub use builder::RuleDispatcherBuilder;

type ActionSet = SmallVec<[Action; 8]>;
pub const ACTION_LIMIT: usize = 15;

// High 8 bits: ActionHandle (maximum 255 actions, but in doc we say 15)
// Low 24 bits: RuleId (maximum 16M rules, equivalent to 105 copies of SukkaW reject domain set)
#[derive(Clone, Copy, Debug)]
pub struct RuleHandle(u32);
pub type RuleId = u32;
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActionHandle(u8);

impl RuleHandle {
    pub fn new(action: ActionHandle, rule_id: RuleId) -> Self {
        Self((action.0 as u32) << 24 | (rule_id & 0x00ffffff))
    }
    pub fn action(&self) -> ActionHandle {
        ActionHandle((self.0 >> 24) as u8)
    }
    pub fn set_action(&mut self, action: ActionHandle) {
        self.0 = (self.0 & 0x00ffffff) | ((action.0 as u32) << 24);
    }
    pub fn rule_id(&self) -> RuleId {
        self.0 & 0x00ffffff
    }
    pub fn set_rule_id(&mut self, rule_id: RuleId) {
        self.0 = (self.0 & 0xff000000) | (rule_id & 0x00ffffff);
    }
}

pub struct Action {
    pub tcp_next: Weak<dyn StreamHandler>,
    pub udp_next: Weak<dyn DatagramSessionHandler>,
    pub resolver: Weak<dyn Resolver>,
}

pub struct RuleDispatcher {
    pub resolver: Option<Weak<dyn Resolver>>, // TODO: set to None when no IP rules
    pub rule_set: set::RuleSet,
    pub actions: ActionSet,
    pub fallback: Action,
    pub me: Weak<Self>,
}

struct AsyncMatchContext {
    me: Arc<RuleDispatcher>,
    src: SocketAddr,
    dst_domain: String,
    dst_port: u16,
    resolver: Arc<dyn Resolver>,
}

impl AsyncMatchContext {
    async fn try_match(&self) -> FlowResult<&Action> {
        let (v4_res, v6_res) = join(
            self.resolver.resolve_ipv4(self.dst_domain.clone()),
            self.resolver.resolve_ipv6(self.dst_domain.clone()),
        )
        .await;
        let dst_ip_v4 = v4_res.unwrap_or_default().first().copied();
        let dst_ip_v6 = v6_res.unwrap_or_default().first().copied();
        let dst_domain = Some(self.dst_domain.as_str());
        let res = self
            .me
            .rule_set
            .r#match(self.src, dst_ip_v4, dst_ip_v6, dst_domain, self.dst_port)
            .map(|id| self.me.actions.get(id.0 as usize));
        match res {
            Some(Some(a)) => Ok(a),
            Some(None) => Err(FlowError::NoOutbound),
            None => Ok(&self.me.fallback),
        }
    }
}

enum TryMatchResult<'a> {
    Matched(&'a Action),
    NeedAsync(AsyncMatchContext),
    Err(FlowError),
}

impl RuleDispatcher {
    fn try_match(&'_ self, context: &FlowContext) -> TryMatchResult<'_> {
        let src = context.local_peer;
        let mut dst_ip_v4 = None;
        let mut dst_ip_v6 = None;
        let mut dst_domain = None;
        match (&context.remote_peer.host, &self.resolver) {
            (HostName::DomainName(domain), Some(resolver)) if self.rule_set.should_resolve() => {
                let Some(resolver) = resolver.upgrade() else {
                    return TryMatchResult::Err(FlowError::NoOutbound);
                };
                return TryMatchResult::NeedAsync(AsyncMatchContext {
                    me: self.me.upgrade().unwrap(),
                    src,
                    dst_domain: domain.clone(),
                    dst_port: context.remote_peer.port,
                    resolver,
                });
            }
            (HostName::DomainName(domain), _) => dst_domain = Some(domain.as_str()),
            (HostName::Ip(IpAddr::V4(v4)), _) => dst_ip_v4 = Some(*v4),
            (HostName::Ip(IpAddr::V6(v6)), _) => dst_ip_v6 = Some(*v6),
        }
        let res = self
            .rule_set
            .r#match(
                src,
                dst_ip_v4,
                dst_ip_v6,
                dst_domain,
                context.remote_peer.port,
            )
            .map(|id| self.actions.get(id.0 as usize));
        match res {
            Some(Some(a)) => TryMatchResult::Matched(a),
            Some(None) => TryMatchResult::Err(FlowError::NoOutbound),
            None => TryMatchResult::Matched(&self.fallback),
        }
    }
    fn try_match_with(
        &self,
        context: Box<FlowContext>,
        cb: impl FnOnce(Box<FlowContext>, &Action) + Send + 'static,
    ) {
        match self.try_match(&context) {
            TryMatchResult::Matched(a) => cb(context, a),
            TryMatchResult::NeedAsync(a) => {
                tokio::spawn(async move {
                    match a.try_match().await {
                        Ok(a) => cb(context, a),
                        Err(_) => {
                            // TODO: log error
                            return;
                        }
                    }
                });
            }
            TryMatchResult::Err(_) => {
                // TODO: log error
                return;
            }
        }
    }
}

impl StreamHandler for RuleDispatcher {
    fn on_stream(&self, lower: Box<dyn Stream>, initial_data: Buffer, context: Box<FlowContext>) {
        self.try_match_with(context, |context, a| {
            if let Some(tcp_next) = a.tcp_next.upgrade() {
                tcp_next.on_stream(lower, initial_data, context)
            }
        })
    }
}

impl DatagramSessionHandler for RuleDispatcher {
    fn on_session(&self, session: Box<dyn DatagramSession>, context: Box<FlowContext>) {
        self.try_match_with(context, |context, a| {
            if let Some(udp_next) = a.udp_next.upgrade() {
                udp_next.on_session(session, context)
            }
        })
    }
}

#[async_trait]
impl Resolver for RuleDispatcher {
    async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        let action = match self
            .rule_set
            .match_domain(&domain)
            .map(|id| self.actions.get(id.0 as usize))
        {
            Some(Some(a)) => a,
            Some(None) => return Err(FlowError::NoOutbound),
            None => &self.fallback,
        };
        let resolver = action.resolver.upgrade().ok_or(FlowError::NoOutbound)?;
        resolver.resolve_ipv4(domain).await
    }
    async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        let action = match self
            .rule_set
            .match_domain(&domain)
            .map(|id| self.actions.get(id.0 as usize))
        {
            Some(Some(a)) => a,
            Some(None) => return Err(FlowError::NoOutbound),
            None => &self.fallback,
        };
        let resolver = action.resolver.upgrade().ok_or(FlowError::NoOutbound)?;
        resolver.resolve_ipv6(domain).await
    }
}
