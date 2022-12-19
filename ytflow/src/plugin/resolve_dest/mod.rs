mod forward;

pub use forward::{DatagramForwardResolver, StreamForwardResolver};

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
            host: HostName::Ip(ip),
            port,
        },

        None => DestinationAddr {
            host: HostName::DomainName(domain),
            port,
        },
    }
}
