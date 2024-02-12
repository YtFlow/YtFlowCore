use serde::{Deserialize, Serialize};

mod http;
mod shadowsocks;
mod socks5;
mod trojan;
mod vmess;

pub use http::HttpProxy;
pub use shadowsocks::ShadowsocksProxy;
pub use socks5::Socks5Proxy;
pub use trojan::TrojanProxy;
pub use vmess::VMessProxy;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyProtocolType {
    Shadowsocks(shadowsocks::ShadowsocksProxy),
    Trojan(trojan::TrojanProxy),
    Http(http::HttpProxy),
    Socks5(socks5::Socks5Proxy),
    VMess(vmess::VMessProxy),
}
