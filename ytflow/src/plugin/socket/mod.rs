mod tcp;
mod udp;

use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Weak;
use std::time::Duration;

use futures::future::{select, Either, FusedFuture, FutureExt};
use itertools::Itertools;
use socket2::TcpKeepalive;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use tokio::{pin, select};

use crate::flow::*;

pub use tcp::{dial_stream, listen_tcp};
pub use udp::{dial_datagram_session, listen_udp};

// See https://datatracker.ietf.org/doc/html/rfc8305
const CONN_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
const RESOLUTION_DELAY: Duration = Duration::from_millis(50);
const SOCKET_KEEPALIVE: &'static TcpKeepalive =
    &TcpKeepalive::new().with_time(Duration::from_secs(600));

pub struct SocketOutboundFactory {
    pub resolver: Weak<dyn Resolver>,
    pub bind_addr_v4: Option<SocketAddrV4>,
    pub bind_addr_v6: Option<SocketAddrV6>,
}

async fn resolve_dual_stack_ips(domain: String, resolver: &dyn Resolver, ip_tx: Sender<IpAddr>) {
    pin! {
        let v6_task = resolver.resolve_ipv6(domain.clone()).fuse();
        let v4_task = resolver.resolve_ipv4(domain).fuse();
    };
    match select(v6_task, v4_task).await {
        Either::Left((Err(_), v4_task)) => {
            if let Ok(ips) = v4_task.await {
                for ip in ips {
                    if ip_tx.send(ip.into()).await.is_err() {
                        return;
                    }
                }
            }
        }
        Either::Right((Err(_), v6_task)) => {
            if let Ok(ips) = v6_task.await {
                for ip in ips {
                    if ip_tx.send(ip.into()).await.is_err() {
                        return;
                    }
                }
            }
        }
        Either::Left((Ok(mut ipv6), mut v4_task)) => {
            ipv6.reverse();
            'outer: while let Some(ip) = ipv6.pop() {
                select! {
                    r = ip_tx.send(ip.into()) => {
                        if r.is_err() {
                            return;
                        }
                    }
                    Ok(ipv4) = v4_task.as_mut() => {
                        ipv6.reverse();
                        let ipv4 = ipv4.into_iter().map(IpAddr::from);
                        let ipv6 = ipv6.into_iter().map(IpAddr::from);
                        for ip in ipv4.interleave(ipv6) {
                            if ip_tx.send(ip).await.is_err() {
                                return;
                            }
                        }
                        break 'outer;
                    }
                }
            }
            if v4_task.is_terminated() {
                return;
            }
            if let Ok(ips) = v4_task.await {
                for ip in ips {
                    if ip_tx.send(ip.into()).await.is_err() {
                        return;
                    }
                }
            }
        }
        Either::Right((Ok(mut ipv4), mut v6_task)) => {
            // Not using tokio::time::timeout because Timeout is !Unpin,  so we cannot get back the
            // inner future later.
            let timeout_task = sleep(RESOLUTION_DELAY).fuse();
            select! {
                biased;

                r = v6_task.as_mut() => {
                    let ipv6 = r.unwrap_or_default();
                    let ipv4 = ipv4.into_iter().map(IpAddr::from);
                    let ipv6 = ipv6.into_iter().map(IpAddr::from);
                    for ip in ipv6.interleave(ipv4) {
                        if ip_tx.send(ip).await.is_err() {
                            return;
                        }
                    }
                }
                _ = timeout_task => {
                    ipv4.reverse();
                    'outer: while let Some(ip) = ipv4.pop() {
                        select! {
                            r = ip_tx.send(ip.into()) => {
                                if r.is_err() {
                                    return;
                                }
                            }
                            Ok(ipv6) = v6_task.as_mut() => {
                                ipv4.reverse();
                                let ipv4 = ipv4.into_iter().map(IpAddr::from);
                                let ipv6 = ipv6.into_iter().map(IpAddr::from);
                                for ip in ipv6.interleave(ipv4) {
                                    if ip_tx.send(ip).await.is_err() {
                                        return;
                                    }
                                }
                                break 'outer;
                            }
                        }
                    }
                    if v6_task.is_terminated() {
                        return;
                    }
                    if let Ok(ips) = v6_task.await {
                        for ip in ips {
                            if ip_tx.send(ip.into()).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}
