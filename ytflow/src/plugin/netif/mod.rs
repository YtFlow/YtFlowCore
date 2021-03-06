mod resolver;
mod responder;
mod sys;

use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{
    atomic::{AtomicU8, Ordering::Release},
    Arc,
};

use arc_swap::ArcSwap;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

pub use resolver::NetifHostResolver;
pub use responder::Responder;

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

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Netif {
    pub name: String,
    pub ipv4_addr: Option<SocketAddrV4>,
    pub ipv6_addr: Option<SocketAddrV6>,
    #[serde(serialize_with = "serialize_ipaddrs")]
    #[serde(deserialize_with = "deserialize_ipaddrs")]
    pub dns_servers: Vec<IpAddr>,
}

pub struct NetifSelector {
    pub(super) selection: ArcSwap<(SelectionMode, FamilyPreference)>,
    pub(super) cached_netif: ArcSwap<Netif>,
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
                    this.update();
                }
            });
            Self {
                selection: ArcSwap::new(Arc::new((selection, prefer))),
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
        self.change_token.fetch_add(1, Release);
    }

    fn pick_netif(&self) -> Option<Netif> {
        let selection_guard = self.selection.load();
        let (selection, prefer) = &**selection_guard;
        let mut netif = match selection {
            SelectionMode::Auto => self.provider.select_best(),
            SelectionMode::Manual(name) => self.provider.select(name.as_str()),
            SelectionMode::Virtual(netif) => Some(netif.clone()),
        }?;
        match (prefer, &mut netif.ipv4_addr, &mut netif.ipv6_addr) {
            (FamilyPreference::PreferIpv4, Some(_), v6) => *v6 = None,
            (FamilyPreference::PreferIpv6, v4, Some(_)) => *v4 = None,
            _ => {}
        }
        Some(netif)
    }
}

pub(crate) fn serialize_ipaddrs<S>(ipaddrs: &Vec<IpAddr>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.collect_seq(ipaddrs.iter().map(|ip| ip.to_string()))
}

pub(crate) fn deserialize_ipaddrs<'de, D>(deserializer: D) -> Result<Vec<IpAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let ipaddrs: Vec<String> = Deserialize::deserialize(deserializer)?;
    ipaddrs
        .into_iter()
        .map(|ip| {
            ip.parse()
                .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(&ip), &"IP address"))
        })
        .collect()
}
