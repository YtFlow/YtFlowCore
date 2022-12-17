// Windows does not provide per-link hostname resolution.
// On Linux, fallback to resolver when sytemd-resolved is not available.
#[cfg(any(windows, target_os = "linux"))]
mod resolver;
mod responder;
mod sys;

use std::net::IpAddr;
use std::sync::{Arc, Weak};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use responder::Responder;

use crate::flow::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "netif")]
pub enum SelectionMode {
    Auto,
    Manual(String),
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum FamilyPreference {
    Both,
    Ipv4Only,
    Ipv6Only,
}

pub struct NetifSelector {
    pub(super) selection: ArcSwap<(SelectionMode, FamilyPreference)>,
    pub(super) cached_netif: ArcSwap<sys::Netif>,
    provider: sys::NetifProvider,
    resolver: sys::Resolver,
    me: Weak<Self>,
}

impl NetifSelector {
    pub fn new(selection: SelectionMode, prefer: FamilyPreference) -> Arc<Self> {
        let dummy_netif = sys::Netif {
            name: String::from("dummy_netif_awaiting_change"),
            ..sys::Netif::default()
        };
        Arc::<Self>::new_cyclic(|this| {
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
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let preference = self.selection.load().1;
        let netif = self.cached_netif.load();
        crate::plugin::socket::dial_stream(
            &context,
            self.me.upgrade().unwrap(),
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
        let netif = self.cached_netif.load();
        crate::plugin::socket::dial_datagram_session(
            &context,
            self.me.upgrade().unwrap(),
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

    async fn resolve_reverse(&self, ip: IpAddr) -> FlowResult<String> {
        self.resolver.resolve_reverse(ip).await
    }
}
