use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use futures::{StreamExt, TryStreamExt};
use parking_lot::{const_mutex, Mutex};
use rtnetlink::sys::SocketAddr;
use rtnetlink::Handle;
use tokio::task::JoinHandle;

use super::super::*;

#[derive(Debug)]
struct Recommended(bool);

pub struct NetifProvider {
    known_netifs: Arc<Mutex<Vec<(Netif, Recommended)>>>,
    monitor_handle: JoinHandle<()>,
}

impl NetifProvider {
    pub fn new<C: Fn() + Send + 'static>(callback: C) -> Self {
        use netlink_packet_route::constants::*;

        let (mut conn, handle, mut messages) =
            rtnetlink::new_connection().expect("Cannot create rtnetlink socket");

        let groups = RTNLGRP_LINK
            | RTNLGRP_IPV4_IFADDR
            | RTNLGRP_IPV6_IFADDR
            | RTNLGRP_IPV4_ROUTE
            | RTNLGRP_IPV6_ROUTE
            | RTNLGRP_MPLS_ROUTE
            | RTNLGRP_IPV4_MROUTE
            | RTNLGRP_IPV6_MROUTE
            | RTNLGRP_NEIGH
            | RTNLGRP_IPV4_NETCONF
            | RTNLGRP_IPV6_NETCONF
            | RTNLGRP_IPV4_RULE
            | RTNLGRP_IPV6_RULE
            | RTNLGRP_NSID
            | RTNLGRP_MPLS_NETCONF;

        let addr = SocketAddr::new(0, groups);
        conn.socket_mut()
            .bind(&addr)
            .expect("Failed to bind to rtnetlink socket");

        tokio::spawn(conn);
        let known_netifs = Arc::new(const_mutex(vec![]));
        let monitor_handle = tokio::spawn({
            let known_netifs = known_netifs.clone();
            async move {
                loop {
                    *known_netifs.lock() = receive_netifs(&handle).await;
                    callback();
                    let _ = messages.next().await;
                }
            }
        });
        let provider = NetifProvider {
            known_netifs: known_netifs.clone(),
            monitor_handle,
        };

        provider
    }

    pub fn select(&self, name: &str) -> Option<Netif> {
        self.known_netifs
            .lock()
            .iter()
            .find(|(netif, _)| netif.name == name)
            .map(|(netif, _)| netif.clone())
    }

    pub fn select_best(&self) -> Option<Netif> {
        self.known_netifs
            .lock()
            .iter()
            .find(|(_, best)| best.0)
            .map(|(netif, _)| netif.clone())
    }
}

impl Drop for NetifProvider {
    fn drop(&mut self) {
        self.monitor_handle.abort();
    }
}

async fn receive_netifs(handle: &Handle) -> Vec<(Netif, Recommended)> {
    use netlink_packet_route::{AF_INET, AF_INET6, ARPHRD_ETHER, IFF_LOWER_UP, IFF_UP};
    use rtnetlink::packet::address::Nla as AddrNla;
    use rtnetlink::packet::link::nlas::Nla as LinkNla;

    let mut addr_stream = handle.address().get().execute();
    let mut addr_dict: BTreeMap<u32, (Vec<Ipv4Addr>, Vec<Ipv6Addr>)> = BTreeMap::new();
    while let Some(addr) = addr_stream.try_next().await.ok().flatten() {
        let (v4, v6) = addr_dict.entry(addr.header.index).or_default();
        let ip_nla = addr.nlas.into_iter().find_map(|nla| match nla {
            AddrNla::Address(addr) => Some(addr),
            _ => None,
        });
        match (addr.header.family as _, ip_nla.as_deref()) {
            (AF_INET, Some(&[a, b, c, d])) => v4.push(Ipv4Addr::new(a, b, c, d)),
            (AF_INET6, Some(buf)) if buf.len() = 16 => {
                let octets: &[u8; 16] = buf.try_into().unwrap();
                v6.push((*octets).into());
            }
            _ => {}
        }
    }
    let mut stream = handle.link().get().execute();
    let mut ret = vec![];
    while let Some(netif) = stream.try_next().await.ok().flatten() {
        let flags = netif.header.flags;
        let is_up = (flags & IFF_UP) != 0 && (flags & IFF_LOWER_UP) != 0;
        let is_ether = netif.header.link_layer_type == ARPHRD_ETHER;
        let index = netif.header.index;
        if let Some(ifname) = netif.nlas.into_iter().find_map(|nla| match nla {
            LinkNla::IfName(name) => Some(name),
            _ => None,
        }) {
            let (v4, v6) = addr_dict.remove(&index).unwrap_or_default();
            ret.push((
                Netif {
                    name: ifname,
                    ipv4_addr: v4.first().map(|ip| SocketAddrV4::new(*ip, 0)),
                    ipv6_addr: v6.first().map(|ip| SocketAddrV6::new(*ip, 0, 0, index)),
                    // Directly invoke systemd-resolved for netif-specific DNS resolution
                    dns_servers: vec![],
                },
                Recommended(is_up && is_ether),
            ))
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Weak;

    #[test]
    fn test_provider() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let _provider = Arc::new_cyclic(|this| {
                let this: Weak<NetifProvider> = this.clone();
                NetifProvider::new(move || {
                    if let Some(this) = this.upgrade() {
                        println!("{:?}", this.select("lo"));
                        println!("{:?}", this.select_best());
                        let _ = tx.try_send(());
                    }
                })
            });
            let _ = rx.recv().await;
        })
    }
}
