mod resolver;
mod sys;

use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{
    atomic::{AtomicU8, Ordering::Release},
    Arc,
};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

pub use resolver::NetifHostResolver;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "netif")]
pub enum SelectionMode {
    Auto,
    Manual(String),
    Virtual(Netif),
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum FamilyPreference {
    NoPreference,
    PreferIpv4,
    PreferIpv6,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Netif {
    pub name: String,
    pub ipv4_addr: Option<SocketAddrV4>,
    pub ipv6_addr: Option<SocketAddrV6>,
    pub dns_servers: Vec<IpAddr>,
}

pub struct NetifSelector {
    selection: SelectionMode,
    prefer: FamilyPreference,
    cached_netif: ArcSwap<Netif>,
    change_token: AtomicU8,
    provider: sys::NetifProvider,
}

impl NetifSelector {
    pub fn new(selection: SelectionMode, prefer: FamilyPreference) -> Option<Arc<Self>> {
        let dummy_netif = Netif {
            name: String::from("dummy_netif_awaiting_change"),
            ..Netif::default()
        };
        Some(Arc::<Self>::new_cyclic(|this| {
            let this = this.clone();
            let provider = sys::NetifProvider::new(move || {
                if let Some(this) = this.upgrade() {
                    if let Some(netif) = this.pick_netif() {
                        this.cached_netif.store(Arc::new(netif));
                        this.change_token.fetch_add(1, Release);
                    }
                }
            });
            Self {
                selection,
                prefer,
                cached_netif: ArcSwap::new(Arc::new(dummy_netif)),
                provider,
                change_token: AtomicU8::new(0),
            }
        }))
    }

    pub fn read<R, C: FnOnce(&Netif) -> R>(&self, callback: C) -> R {
        let guard = self.cached_netif.load();
        callback(&guard)
    }

    fn pick_netif(&self) -> Option<Netif> {
        let mut netif = match &self.selection {
            SelectionMode::Auto => self.provider.select_best(),
            SelectionMode::Manual(name) => self.provider.select(name.as_str()),
            SelectionMode::Virtual(netif) => Some(netif.clone()),
        }?;
        match (self.prefer, &mut netif.ipv4_addr, &mut netif.ipv6_addr) {
            (FamilyPreference::PreferIpv4, Some(_), v6) => *v6 = None,
            (FamilyPreference::PreferIpv6, v4, Some(_)) => *v4 = None,
            _ => {}
        }
        Some(netif)
    }
}
