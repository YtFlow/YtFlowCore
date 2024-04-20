use std::sync::{Arc, Weak};

use arc_swap::ArcSwap;
use async_trait::async_trait;

use super::*;
use crate::flow::*;

pub struct NetifSelector {
    pub(super) selection: ArcSwap<(SelectionMode, FamilyPreference)>,
    pub(super) cached_netif: ArcSwap<sys::Netif>,
    provider: sys::NetifProvider,
    resolver: sys::Resolver,
    outbound_resolver: Option<Weak<dyn Resolver>>,
    me: Weak<Self>,
}

impl NetifSelector {
    pub fn new(
        selection: SelectionMode,
        prefer: FamilyPreference,
        create_outbound_resolver: impl FnOnce(&Weak<Self>) -> Option<Weak<dyn Resolver>>,
    ) -> Arc<Self> {
        let dummy_netif = sys::Netif {
            name: String::from("dummy_netif_awaiting_change"),
            ..sys::Netif::default()
        };
        Arc::<Self>::new_cyclic(|this| {
            let outbound_resolver = create_outbound_resolver(this);
            let this = this.clone();
            let provider = sys::NetifProvider::new({
                let this = this.clone();
                move || {
                    if let Some(this) = this.upgrade() {
                        this.update();
                    }
                }
            });
            Self {
                selection: ArcSwap::new(Arc::new((selection, prefer))),
                cached_netif: ArcSwap::new(Arc::new(dummy_netif)),
                provider,
                resolver: sys::Resolver::new(this.clone()),
                outbound_resolver,
                me: this,
            }
        })
    }

    pub(super) fn update(&self) {
        let netif = match self.pick_netif() {
            Some(netif) => netif,
            None => return,
        };
        let guard = self.cached_netif.load();
        if netif == **guard {
            return;
        }
        self.cached_netif.compare_and_swap(guard, Arc::new(netif));
    }

    fn pick_netif(&self) -> Option<sys::Netif> {
        let selection_guard = self.selection.load();
        let (selection, _) = &**selection_guard;
        let netif = match selection {
            SelectionMode::Auto => self.provider.select_best(),
            SelectionMode::Manual(name) => self.provider.select(name.as_str()),
        }?;
        Some(netif)
    }
}

#[async_trait]
impl StreamOutboundFactory for NetifSelector {
    async fn create_outbound(
        &self,
        context: &mut FlowContext,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let preference = self.selection.load().1;
        let netif = self.cached_netif.load();
        let resolver = self
            .outbound_resolver
            .as_ref()
            .map(|r| r.upgrade().ok_or(FlowError::NoOutbound))
            .transpose()?
            .unwrap_or_else(|| self.me.upgrade().unwrap());
        crate::plugin::socket::dial_stream(
            context,
            resolver,
            // A workaround for E0308 "one type is more general than the other"
            // https://github.com/rust-lang/rust/issues/70263
            Some(|s: &mut _| sys::bind_socket_v4(&netif, s)).filter(|_| {
                matches!(
                    preference,
                    FamilyPreference::Both | FamilyPreference::Ipv4Only,
                )
            }),
            Some(|s: &mut _| sys::bind_socket_v6(&netif, s)).filter(|_| {
                matches!(
                    preference,
                    FamilyPreference::Both | FamilyPreference::Ipv6Only,
                )
            }),
            initial_data,
        )
        .await
    }
}

#[async_trait]
impl DatagramSessionFactory for NetifSelector {
    async fn bind(&self, context: Box<FlowContext>) -> FlowResult<Box<dyn DatagramSession>> {
        let preference = self.selection.load().1;
        let netif = self.cached_netif.load_full();
        let resolver = self
            .outbound_resolver
            .as_ref()
            .map(|r| r.upgrade().ok_or(FlowError::NoOutbound))
            .transpose()?
            .unwrap_or_else(|| self.me.upgrade().unwrap());
        crate::plugin::socket::dial_datagram_session(
            &context,
            resolver,
            // A workaround for E0308 "one type is more general than the other"
            // https://github.com/rust-lang/rust/issues/70263
            Some({
                let netif = netif.clone();
                move |s: &mut _| sys::bind_socket_v4(&netif, s)
            })
            .filter(|_| {
                matches!(
                    preference,
                    FamilyPreference::Both | FamilyPreference::Ipv4Only,
                )
            }),
            Some(move |s: &mut _| sys::bind_socket_v6(&netif, s)).filter(|_| {
                matches!(
                    preference,
                    FamilyPreference::Both | FamilyPreference::Ipv6Only,
                )
            }),
        )
        .await
    }
}

#[async_trait]
impl Resolver for NetifSelector {
    async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        self.resolver.resolve_ipv4(domain).await
    }

    async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        self.resolver.resolve_ipv6(domain).await
    }
}
