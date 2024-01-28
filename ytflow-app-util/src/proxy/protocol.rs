pub mod http;
pub mod shadowsocks;
pub mod socks5;
pub mod trojan;
pub mod vmess;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProtocolType {
    Shadowsocks(shadowsocks::ShadowsocksProxy),
}
