mod forward;
mod reverse;

pub use forward::{DatagramForwardResolver, StreamForwardResolver};
pub use reverse::{DatagramReverseResolver, StreamReverseResolver};

use std::net::IpAddr;
use std::sync::Arc;

use crate::flow::*;

async fn try_resolve_forward(
    is_ipv6: bool,
    resolver: Arc<dyn Resolver>,
    domain: String,
    port: u16,
) -> DestinationAddr {
    match if is_ipv6 {
        resolver
            .resolve_ipv6(domain.clone())
            .await
            .ok()
            .and_then(|ips| ips.first().cloned())
            .map(Into::into)
    } else {
        resolver
            .resolve_ipv4(domain.clone())
            .await
            .ok()
            .and_then(|ips| ips.first().cloned())
            .map(Into::into)
    } {
        Some(ip) => DestinationAddr {
            dest: Destination::Ip(ip),
            port,
        },

        None => DestinationAddr {
            dest: Destination::DomainName(domain),
            port,
        },
    }
}

async fn try_resolve_reverse(
    resolver: Arc<dyn Resolver>,
    ip: IpAddr,
    port: u16,
) -> DestinationAddr {
    match resolver.resolve_reverse(ip).await {
        Ok(domain) => DestinationAddr {
            dest: Destination::DomainName(domain),
            port,
        },
        Err(_) => DestinationAddr {
            dest: Destination::Ip(ip),
            port,
        },
    }
}
