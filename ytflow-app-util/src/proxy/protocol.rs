pub mod http;
pub mod shadowsocks;
pub mod socks5;
pub mod trojan;
pub mod vmess;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProtocolType {
    Shadowsocks(shadowsocks::ShadowsocksProxy),
    Trojan(trojan::TrojanProxy),
    Http(http::HttpProxy),
    Socks5(socks5::Socks5Proxy),
    VMess(vmess::VMessProxy),
}
