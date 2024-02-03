use std::net::IpAddr;

use thiserror::Error;
use ytflow::flow::HostName;

use crate::proxy::protocol::ProxyProtocolType;
use crate::proxy::Proxy;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EncodeError {
    #[error("too many legs")]
    TooManyLegs,
    #[error(r#""{0}" contains invalid UTF-8 bytes"#)]
    InvalidEncoding(&'static str),
    #[error(r#""{0}" cannot be encoded"#)]
    UnsupportedComponent(&'static str),
}

pub type EncodeResult<T> = Result<T, EncodeError>;

pub fn encode_share_link(proxy: &Proxy) -> EncodeResult<String> {
    let leg = match &*proxy.legs {
        [] => return Ok("".into()),
        [leg] => leg,
        _ => return Err(EncodeError::TooManyLegs),
    };

    match &leg.protocol {
        ProxyProtocolType::Shadowsocks(_) => todo!(),
        ProxyProtocolType::Trojan(_) => todo!(),
        ProxyProtocolType::Http(p) => p.encode_share_link(leg, proxy),
        ProxyProtocolType::Socks5(p) => p.encode_share_link(leg, proxy),
        ProxyProtocolType::VMess(_) => todo!(),
    }
}

pub(super) fn url_encode_host(host: &HostName) -> String {
    match host {
        HostName::Ip(IpAddr::V6(ip)) => format!("[{}]", ip),
        host => host.to_string(),
    }
}
