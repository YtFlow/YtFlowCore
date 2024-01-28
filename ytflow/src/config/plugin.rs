mod dns_server;
mod dyn_outbound;
mod fakeip;
mod forward;
mod host_resolver;
mod http_obfs;
mod http_proxy;
mod ip_stack;
mod list_dispatcher;
mod netif;
mod null;
mod redirect;
mod reject;
mod resolve_dest;
mod rule_dispatcher;
mod shadowsocks;
mod simple_dispatcher;
mod socket;
mod socket_listener;
mod socks5;
mod switch;
mod system_resolver;
mod tls;
mod tls_obfs;
mod trojan;
mod vmess;
mod vpntun;
mod ws;

pub use dns_server::*;
pub use dyn_outbound::*;
pub use fakeip::*;
pub use forward::*;
pub use host_resolver::*;
pub use http_obfs::*;
pub use http_proxy::*;
pub use ip_stack::*;
pub use list_dispatcher::ListDispatcherFactory;
pub use netif::*;
pub use null::*;
pub use redirect::*;
pub use reject::*;
pub use resolve_dest::*;
pub use rule_dispatcher::RuleDispatcherFactory;
pub use shadowsocks::*;
pub use simple_dispatcher::*;
pub use socket::*;
pub use socket_listener::*;
pub use socks5::*;
pub use switch::*;
pub use system_resolver::*;
pub use tls::*;
pub use tls_obfs::*;
pub use trojan::*;
pub use vmess::*;
pub use vpntun::*;
pub use ws::*;

use crate::data::PluginId;

#[derive(Debug, Clone)]
pub struct Plugin {
    pub id: Option<PluginId>,
    pub name: String,
    pub plugin: String,
    pub plugin_version: u16,
    pub param: Vec<u8>,
}
