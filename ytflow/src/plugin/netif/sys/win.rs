use std::net::SocketAddrV6;

use super::super::*;
use crate::bindings::Windows::Foundation::EventRegistrationToken;
use crate::bindings::Windows::Networking::Connectivity::*;

#[derive(Debug)]
enum Rate {
    Recommended,
    Backup,
    NotRecommended,
}

fn enum_adapters() -> Vec<(Netif, Rate)> {
    use ipconfig::{IfType, OperStatus};

    ipconfig::get_adapters()
        .unwrap_or_default()
        .into_iter()
        .map(|adapter| {
            let rate = if adapter.oper_status() != OperStatus::IfOperStatusUp
                || adapter.gateways().is_empty()
                || adapter.physical_address().map_or(0, |a| a.len()) == 0
            {
                Rate::NotRecommended
            } else if adapter.if_type() == IfType::Ieee80211 {
                Rate::Backup
            } else {
                Rate::Recommended
            };
            (
                Netif {
                    name: adapter.friendly_name().to_owned(),
                    ipv4_addr: adapter.ip_addresses().iter().find_map(|ip| match ip {
                        IpAddr::V4(v4) => Some(SocketAddrV4::new(*v4, 0)),
                        _ => None,
                    }),
                    ipv6_addr: adapter.ip_addresses().iter().find_map(|ip| match ip {
                        IpAddr::V6(v6) => {
                            Some(SocketAddrV6::new(*v6, 0, 0, adapter.ipv6_if_index()))
                        }
                        _ => None,
                    }),
                    dns_servers: adapter.dns_servers().to_vec(),
                },
                rate,
            )
        })
        .collect()
}

pub struct NetifProvider {
    event_token: EventRegistrationToken,
}

impl NetifProvider {
    pub fn new<C: Fn() + Clone + Send + 'static>(callback: C) -> NetifProvider {
        let cb_cloned = callback.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            cb_cloned()
        });
        let event_token = NetworkInformation::NetworkStatusChanged(
            NetworkStatusChangedEventHandler::new(move |_sender| {
                callback();
                Ok(())
            }),
        )
        .unwrap();
        NetifProvider { event_token }
    }

    pub fn select(&self, name: &str) -> Option<Netif> {
        let adapters = enum_adapters();
        adapters
            .into_iter()
            .find(|(a, _)| a.name == name)
            .map(|(a, _)| a)
    }

    pub fn select_best(&self) -> Option<Netif> {
        let adapters = enum_adapters();
        let mut backup = None;
        for (adapter, rate) in adapters {
            match rate {
                Rate::Recommended => return Some(adapter),
                Rate::Backup if backup.is_none() => backup = Some(adapter),
                _ => continue,
            }
        }
        backup
    }
}

impl Drop for NetifProvider {
    fn drop(&mut self) {
        NetworkInformation::RemoveNetworkStatusChanged(self.event_token).unwrap();
    }
}
