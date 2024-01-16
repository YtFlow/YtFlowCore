use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use futures::future::join;
use smallvec::SmallVec;

use super::*;

pub type ActionSet = SmallVec<[Action; 8]>;

pub struct RuleDispatcher {
    pub resolver: Option<Weak<dyn Resolver>>, // TODO: set to None when no IP rules
    pub rule_set: set::RuleSet,
    pub actions: ActionSet,
    pub fallback: Action,
    pub me: Weak<Self>,
}

struct AsyncMatchContext {
    src: Option<SocketAddr>,
    dst_domain: String,
    dst_port: Option<u16>,
    resolver: Arc<dyn Resolver>,
}

impl AsyncMatchContext {
    async fn try_match<'m>(&self, me: &'m RuleDispatcher) -> FlowResult<&'m Action> {
        let (v4_res, v6_res) = join(
            self.resolver.resolve_ipv4(self.dst_domain.clone()),
            self.resolver.resolve_ipv6(self.dst_domain.clone()),
        )
        .await;
        let dst_ip_v4 = v4_res.unwrap_or_default().first().copied();
        let dst_ip_v6 = v6_res.unwrap_or_default().first().copied();
        let dst_domain = Some(self.dst_domain.as_str());
        let res = me
            .rule_set
            .r#match(self.src, dst_ip_v4, dst_ip_v6, dst_domain, self.dst_port)
            .map(|id| me.actions.get(id.0 as usize));
        match res {
            Some(Some(a)) => Ok(a),
            Some(None) => Err(FlowError::NoOutbound),
            None => Ok(&me.fallback),
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
        let src = Some(context.local_peer);
        let dst_port = Some(context.remote_peer.port);
        let mut dst_ip_v4 = None;
        let mut dst_ip_v6 = None;
        let mut dst_domain = None;
        match (&context.remote_peer.host, &self.resolver) {
            (HostName::DomainName(domain), Some(resolver))
                if self.rule_set.should_resolve(src, domain, dst_port) =>
            {
                let Some(resolver) = resolver.upgrade() else {
                    return TryMatchResult::Err(FlowError::NoOutbound);
                };
                return TryMatchResult::NeedAsync(AsyncMatchContext {
                    src,
                    dst_domain: domain.clone(),
                    dst_port,
                    resolver,
                });
            }
            (HostName::DomainName(domain), _) => dst_domain = Some(domain.as_str()),
            (HostName::Ip(IpAddr::V4(v4)), _) => dst_ip_v4 = Some(*v4),
            (HostName::Ip(IpAddr::V6(v6)), _) => dst_ip_v6 = Some(*v6),
        }
        let res = self
            .rule_set
            .r#match(src, dst_ip_v4, dst_ip_v6, dst_domain, dst_port)
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
                let me = self.me.upgrade().unwrap();
                tokio::spawn(async move {
                    match a.try_match(&me).await {
                        Ok(a) => cb(context, a),
                        Err(_) => {
                            // TODO: log error
                            return;
                        }
                    }
                });
            }
            TryMatchResult::Err(_e) => {
                // TODO: log error
                return;
            }
        }
    }
    async fn match_domain(&self, domain: &str) -> FlowResult<&Action> {
        if let (Some(resolver), true) = (
            self.resolver.as_ref(),
            self.rule_set.should_resolve(None, domain, None),
        ) {
            AsyncMatchContext {
                src: None,
                dst_domain: domain.into(),
                dst_port: None,
                resolver: resolver.upgrade().ok_or(FlowError::NoOutbound)?,
            }
            .try_match(self)
            .await
        } else {
            let res = self
                .rule_set
                .r#match(None, None, None, Some(domain), None)
                .map(|id| self.actions.get(id.0 as usize));
            match res {
                Some(Some(a)) => Ok(a),
                Some(None) => Err(FlowError::NoOutbound),
                None => Ok(&self.fallback),
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
        let action = self.match_domain(&domain).await?;
        let resolver = action.resolver.upgrade().ok_or(FlowError::NoOutbound)?;
        resolver.resolve_ipv4(domain).await
    }
    async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        let action = self.match_domain(&domain).await?;
        let resolver = action.resolver.upgrade().ok_or(FlowError::NoOutbound)?;
        resolver.resolve_ipv6(domain).await
    }
}
