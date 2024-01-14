use std::collections::HashMap;
use std::io;
use std::str::FromStr;
use std::sync::Weak;

use libc::{AF_INET, AF_INET6};
use thiserror::Error;
use tokio::sync::OnceCell;
use zbus_systemd::resolve1::ManagerProxy;
use zbus_systemd::zbus::{self, Connection};
use zbus_systemd::zvariant::{Array, Structure, Value};

use super::*;
use crate::flow::*;
use crate::plugin::netif::resolver::NetifHostResolver;
use crate::plugin::netif::NetifSelector;

static DBUS_SESSION_CONN: OnceCell<zbus::Result<Connection>> = OnceCell::const_new();
static DBUS_SYSTEM_CONN: OnceCell<zbus::Result<Connection>> = OnceCell::const_new();

#[derive(Debug, Error)]
enum ProxyInitError {
    #[error("error during initializing the connection")]
    Conn(#[from] &'static zbus::Error),
    #[error("error during initializing the proxy from a connection")]
    Proxy(#[from] zbus::Error),
}
type ProxyInitResult<T> = Result<T, ProxyInitError>;

async fn init_dbus_session_conn() -> &'static zbus::Result<Connection> {
    DBUS_SESSION_CONN
        .get_or_init(|| Connection::session())
        .await
}

async fn init_dbus_system_conn() -> &'static zbus::Result<Connection> {
    DBUS_SYSTEM_CONN.get_or_init(|| Connection::system()).await
}

async fn init_resolved_manager_proxy<'a>(
    obj: &'a OnceCell<ProxyInitResult<ManagerProxy<'static>>>,
) -> &'a ProxyInitResult<ManagerProxy<'static>> {
    obj.get_or_init(|| async {
        let conn = match init_dbus_session_conn().await {
            Ok(conn) => conn,
            Err(e) => return Err(ProxyInitError::Conn(e)),
        };
        Ok(ManagerProxy::new(conn).await?)
    })
    .await
}

pub struct ResolvedResolver {
    selector: Weak<NetifSelector>,
    resolved_manager_proxy: Arc<OnceCell<ProxyInitResult<ManagerProxy<'static>>>>,
}

impl ResolvedResolver {
    pub fn new(selector: Weak<NetifSelector>) -> Self {
        let resolved_manager_proxy = Arc::new(OnceCell::new());
        tokio::spawn({
            let resolved_manager_proxy = resolved_manager_proxy.clone();
            async move {
                // Pre-load DBus connection and proxy object
                let _ = init_resolved_manager_proxy(&resolved_manager_proxy).await;
            }
        });
        ResolvedResolver {
            selector,
            resolved_manager_proxy,
        }
    }

    async fn ensure_proxy(&self) -> FlowResult<&'_ ManagerProxy<'static>> {
        match init_resolved_manager_proxy(&self.resolved_manager_proxy).await {
            Ok(p) => Ok(p),
            // TODO: log detailed error
            Err(_) => Err(FlowError::Io(std::io::ErrorKind::ConnectionAborted.into())),
        }
    }
    async fn execute_resolve(
        &self,
        domain: String,
        family: i32,
    ) -> FlowResult<(Vec<(i32, i32, Vec<u8>)>, String, u64)> {
        let Some(selector) = self.selector.upgrade() else {
            return Err(io::Error::from(io::ErrorKind::NotConnected).into());
        };
        let proxy = self.ensure_proxy().await?;
        let if_idx = selector.cached_netif.load().if_idx as _;
        let res = proxy
            .resolve_hostname(if_idx, domain, family, 0)
            .await
            .map_err(|_| FlowError::Io(io::ErrorKind::BrokenPipe.into()))?; // TODO: log detailed error
        Ok(res)
    }

    pub async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        let (ips, _, _) = self.execute_resolve(domain, AF_INET).await?;
        Ok(ips
            .into_iter()
            .filter_map(|i| <[_; 4]>::try_from(i.2).ok())
            .map(From::from)
            .collect())
    }
    pub async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        let (ips, _, _) = self.execute_resolve(domain, AF_INET6).await?;
        Ok(ips
            .into_iter()
            .filter_map(|i| <[_; 16]>::try_from(i.2).ok())
            .map(From::from)
            .collect())
    }
}

pub struct Resolver {
    resolved: ResolvedResolver,
    fallback: NetifHostResolver,
}

impl Resolver {
    pub fn new(selector: Weak<NetifSelector>) -> Self {
        Self {
            resolved: ResolvedResolver::new(selector.clone()),
            fallback: NetifHostResolver::new(selector),
        }
    }

    pub async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        if let Ok(res) = self.resolved.resolve_ipv4(domain.clone()).await {
            return Ok(res);
        }
        self.fallback.resolve_ipv4(domain).await
    }
    pub async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        if let Ok(res) = self.resolved.resolve_ipv6(domain.clone()).await {
            return Ok(res);
        }
        self.fallback.resolve_ipv6(domain).await
    }
}

pub async fn retrieve_all_link_dns_servers() -> HashMap<String, Vec<IpAddr>> {
    let Ok(conn) = init_dbus_system_conn().await else {
        return Default::default();
    };
    // TODO: handle errors
    let Ok(res) = conn
        .call_method(
            Some("org.freedesktop.NetworkManager"),
            "/org/freedesktop/NetworkManager/DnsManager",
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.NetworkManager.DnsManager", "Configuration"),
        )
        .await
    else {
        return Default::default();
    };
    let body: Structure = res.body().unwrap();
    let Some(Value::Value(body)) = body.fields().first() else {
        return Default::default();
    };
    let Value::Array(body) = &**body else {
        return Default::default();
    };

    let mut res = HashMap::<String, Vec<IpAddr>>::new();
    for netif_dict in body.into_iter().filter_map(|v| {
        if let Value::Dict(d) = v {
            Some(d)
        } else {
            None
        }
    }) {
        let netif_name: String = netif_dict
            .get::<_, str>("interface")
            .ok()
            .flatten()
            .unwrap_or_default()
            .to_string();
        let servers = res.entry(netif_name).or_default();
        let netif_servers = netif_dict
            .get::<_, Array>("nameservers")
            .ok()
            .flatten()
            .into_iter()
            .flat_map(|a| a.to_vec())
            .filter_map(|v| {
                let s = match v {
                    Value::Str(s) => Some(s),
                    _ => None,
                }?;
                IpAddr::from_str(&s).ok()
            });
        servers.extend(netif_servers);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::netif::sys::Netif;
    use crate::plugin::netif::{FamilyPreference, SelectionMode};

    #[tokio::test]
    async fn test_lookup() {
        let selector = NetifSelector::new(
            SelectionMode::Manual("wlp3s0".into()),
            FamilyPreference::Both,
        );
        selector.cached_netif.store(Arc::new(Netif {
            name: "wlp3s0".into(),
            bsd_name: CString::from_vec_with_nul(b"wlp3s0\0"[..].into()).unwrap(),
            if_idx: 1,
        }));
        let resolver = super::Resolver::new(Arc::downgrade(&selector));
        let now = std::time::SystemTime::now();
        println!(
            "{:?} {:?}",
            resolver.resolve_ipv6("google.com".into()).await,
            now.elapsed()
        );
        println!(
            "{:?}",
            resolver
                .resolve_ipv4("baidu.skldjflksdfjkds.com".into())
                .await
        );
    }
}
