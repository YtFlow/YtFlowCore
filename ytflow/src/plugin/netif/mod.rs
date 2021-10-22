mod resolver;
mod sys;

use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{
    atomic::{AtomicU8, Ordering::Release},
    Arc,
};

use arc_swap::ArcSwap;

use crate::flow::*;

pub enum SelectionMode {
    Auto,
    Manual(String),
    Virtual(Netif),
}

pub enum FamilyPreference {
    NoPreference,
    PreferIpv4,
    PreferIpv6,
}

#[derive(Debug, Clone)]
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
    monitor: sys::ChangeMonitor,
    change_token: AtomicU8,
}

impl NetifSelector {
    pub fn new(selection: SelectionMode, prefer: FamilyPreference) -> Option<Arc<Self>> {
        let netif = pick_netif(&selection, &prefer)?;
        Some(Arc::<Self>::new_cyclic(|this| {
            let this = this.clone();
            Self {
                selection,
                prefer,
                cached_netif: ArcSwap::new(Arc::new(netif)),
                monitor: sys::ChangeMonitor::new(move || {
                    if let Some(this) = this.upgrade() {
                        if let Some(netif) = pick_netif(&this.selection, &this.prefer) {
                            this.cached_netif.store(Arc::new(netif));
                            this.change_token.fetch_add(1, Release);
                        }
                    }
                }),
                change_token: AtomicU8::new(0),
            }
        }))
    }

    pub fn read<R, C: FnOnce(&Netif) -> R>(&self, callback: C) -> R {
        let guard = self.cached_netif.load();
        callback(&guard)
    }
}

fn pick_netif(selection: &SelectionMode, prefer: &FamilyPreference) -> Option<Netif> {
    let mut netif = match selection {
        SelectionMode::Auto => sys::select_best(),
        SelectionMode::Manual(name) => sys::select(name.as_str()),
        SelectionMode::Virtual(netif) => Some(netif.clone()),
    }?;
    match (prefer, &mut netif.ipv4_addr, &mut netif.ipv6_addr) {
        (FamilyPreference::PreferIpv4, Some(_), v6) => *v6 = None,
        (FamilyPreference::PreferIpv6, v4, Some(_)) => *v4 = None,
        _ => {}
    }
    Some(netif)
}
