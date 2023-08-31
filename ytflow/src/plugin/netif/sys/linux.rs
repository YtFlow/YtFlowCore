mod dns;

use std::collections::BTreeMap;
use std::ffi::{c_uint, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use futures::{StreamExt, TryStreamExt};
use netlink_sys::SocketAddr;
use rtnetlink::Handle;
use tokio::task::JoinHandle;

use super::super::*;
pub use dns::Resolver;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Netif {
    pub name: String,
    pub bsd_name: CString,
    pub if_idx: c_uint,
}

impl Netif {
    pub async fn dns_servers(&self) -> Vec<IpAddr> {
        dns::retrieve_all_link_dns_servers()
            .await
            .remove(self.bsd_name.to_str().unwrap_or_default())
            .unwrap_or_default()
    }
}

#[derive(Debug)]
struct Recommended(bool);

pub struct NetifProvider {
    known_netifs: Arc<Mutex<Vec<(Netif, Recommended)>>>,
    monitor_handle: JoinHandle<()>,
}

impl NetifProvider {
    pub fn new<C: Fn() + Send + 'static>(callback: C) -> Self {
        use netlink_packet_route::constants::*;
        use netlink_sys::AsyncSocket;

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
            .socket_mut()
            .bind(&addr)
            .expect("Failed to bind to rtnetlink socket");

        tokio::spawn(conn);
        let known_netifs = Arc::new(Mutex::new(vec![]));
        let monitor_handle = tokio::spawn({
            let known_netifs = known_netifs.clone();
            async move {
                loop {
                    *known_netifs.lock().unwrap() = receive_netifs(&handle).await;
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
            .unwrap()
            .iter()
            .find(|(netif, _)| netif.name == name)
            .map(|(netif, _)| netif.clone())
    }

    pub fn select_best(&self) -> Option<Netif> {
        self.known_netifs
            .lock()
            .unwrap()
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
    use netlink_packet_route::address::Nla as AddrNla;
    use netlink_packet_route::constants::*;
    use netlink_packet_route::link::nlas::Nla as LinkNla;

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
            (AF_INET6, Some(buf)) if buf.len() == 16 => {
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
            let mut bsd_name = ifname.clone().into_bytes();
            bsd_name.push(0);
            let Ok(bsd_name) = CString::from_vec_with_nul(bsd_name) else {
                continue;
            };
            ret.push((
                Netif {
                    bsd_name,
                    name: ifname,
                    if_idx: index,
                },
                Recommended(is_up && is_ether),
            ))
        }
    }
    ret
}

pub fn bind_socket_v4(netif: &Netif, socket: &mut socket2::Socket) -> FlowResult<()> {
    socket.bind_device(Some(netif.bsd_name.as_bytes_with_nul()))?;
    Ok(())
}
pub fn bind_socket_v6(netif: &Netif, socket: &mut socket2::Socket) -> FlowResult<()> {
    socket.bind_device(Some(netif.bsd_name.as_bytes_with_nul()))?;
    Ok(())
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
