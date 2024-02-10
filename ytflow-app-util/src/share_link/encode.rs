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
        ProxyProtocolType::Shadowsocks(p) => p.encode_share_link(leg, proxy),
        ProxyProtocolType::Trojan(p) => p.encode_share_link(leg, proxy),
        ProxyProtocolType::Http(p) => p.encode_share_link(leg, proxy),
        ProxyProtocolType::Socks5(p) => p.encode_share_link(leg, proxy),
        ProxyProtocolType::VMess(p) => p.encode_share_link(leg, proxy),
    }
}

pub(super) fn url_encode_host(host: &HostName) -> String {
    match host {
        HostName::Ip(IpAddr::V6(ip)) => format!("[{}]", ip),
        host => host.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_bytes::ByteBuf;
    use uuid::uuid;

    use ytflow::flow::DestinationAddr;
    use ytflow::plugin::shadowsocks::SupportedCipher;
    use ytflow::plugin::vmess::SupportedSecurity;

    use crate::proxy::protocol::{
        http::HttpProxy, shadowsocks::ShadowsocksProxy, socks5::Socks5Proxy, trojan::TrojanProxy,
        vmess::VMessProxy,
    };
    use crate::proxy::tls::ProxyTlsLayer;
    use crate::proxy::ProxyLeg;

    use super::*;

    #[test]
    fn test_encode_share_link_no_leg() {
        let res = encode_share_link(&Proxy {
            name: "".into(),
            legs: vec![],
            udp_supported: false,
        })
        .unwrap();
        assert_eq!(res, "");
    }
    #[test]
    fn test_encode_share_link_too_many_legs() {
        let res = encode_share_link(&Proxy {
            name: "".into(),
            legs: vec![
                ProxyLeg {
                    protocol: ProxyProtocolType::Trojan(TrojanProxy {
                        password: ByteBuf::from(b""),
                    }),
                    dest: DestinationAddr {
                        host: HostName::Ip([1, 1, 1, 1].into()),
                        port: 1080,
                    },
                    obfs: None,
                    tls: None,
                },
                ProxyLeg {
                    protocol: ProxyProtocolType::Trojan(TrojanProxy {
                        password: ByteBuf::from(b""),
                    }),
                    dest: DestinationAddr {
                        host: HostName::Ip([1, 1, 1, 1].into()),
                        port: 1080,
                    },
                    obfs: None,
                    tls: None,
                },
            ],
            udp_supported: false,
        });
        assert_eq!(res, Err(EncodeError::TooManyLegs));
    }
    #[test]
    fn test_encode_share_link_protocols() {
        let cases: [(Proxy, &str); 5] = [
            (
                Proxy {
                    name: "c/d".into(),
                    legs: vec![ProxyLeg {
                        protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                            cipher: SupportedCipher::Aes256Cfb,
                            password: ByteBuf::from(b"UYL1EvkfI0cT6NOY"),
                        }),
                        dest: DestinationAddr {
                            host: HostName::DomainName("a.co".into()),
                            port: 1080,
                        },
                        obfs: None,
                        tls: None,
                    }],
                    udp_supported: true,
                },
                "ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ%3D%3D@a.co:1080#c%2Fd",
            ),
            (
                Proxy {
                    name: "c/d".into(),
                    legs: vec![ProxyLeg {
                        protocol: ProxyProtocolType::Trojan(TrojanProxy {
                            password: ByteBuf::from("a/b"),
                        }),
                        dest: DestinationAddr {
                            host: HostName::DomainName("a.co".into()),
                            port: 10443,
                        },
                        obfs: None,
                        tls: Some(ProxyTlsLayer {
                            alpn: vec![],
                            sni: None,
                            skip_cert_check: Some(false),
                        }),
                    }],
                    udp_supported: false,
                },
                "trojan://a%2Fb@a.co:10443#c%2Fd",
            ),
            (
                Proxy {
                    name: "c/d".into(),
                    legs: vec![ProxyLeg {
                        protocol: ProxyProtocolType::Http(HttpProxy {
                            username: ByteBuf::from("a/b"),
                            password: ByteBuf::from("p/d"),
                        }),
                        dest: DestinationAddr {
                            host: HostName::DomainName("a.co".into()),
                            port: 1080,
                        },
                        obfs: None,
                        tls: None,
                    }],
                    udp_supported: false,
                },
                "http://a%2Fb:p%2Fd@a.co:1080/#c%2Fd",
            ),
            (
                Proxy {
                    name: "c/d".into(),
                    legs: vec![ProxyLeg {
                        protocol: ProxyProtocolType::Socks5(Socks5Proxy {
                            username: ByteBuf::from("a/b"),
                            password: ByteBuf::from("p/d"),
                        }),
                        dest: DestinationAddr {
                            host: HostName::DomainName("a.co".into()),
                            port: 1080,
                        },
                        obfs: None,
                        tls: None,
                    }],
                    udp_supported: false,
                },
                "socks5://a%2Fb:p%2Fd@a.co:1080#c%2Fd",
            ),
            (
                Proxy {
                    name: "n".into(),
                    legs: vec![ProxyLeg {
                        protocol: ProxyProtocolType::VMess(VMessProxy {
                            user_id: uuid!("22222222-3333-4444-5555-666666666666"),
                            alter_id: 114,
                            security: SupportedSecurity::Aes128Gcm,
                        }),
                        dest: DestinationAddr {
                            host: HostName::DomainName("a.co".into()),
                            port: 1080,
                        },
                        obfs: None,
                        tls: None,
                    }],
                    udp_supported: true,
                },
                "vmess://eyJ2IjoiMiIsInBzIjoibiIsImFpZCI6IjExNCIsImlkIjoiMjIyMjIyMjItMzMzMy00NDQ0LTU1NTUtNjY2NjY2NjY2NjY2Iiwic2N5IjoiYWVzLTEyOC1nY20iLCJhZGQiOiJhLmNvIiwicG9ydCI6IjEwODAiLCJ0eXBlIjoibm9uZSIsIm5ldCI6InRjcCIsImhvc3QiOm51bGwsInBhdGgiOm51bGwsInRscyI6IiIsInNuaSI6bnVsbCwiYWxwbiI6IiJ9",
            ),
        ];
        for (proxy, share_link) in cases {
            let link = encode_share_link(&proxy).unwrap();
            assert_eq!(link, share_link);
        }
    }

    #[test]
    fn test_url_encode_host() {
        let cases: [(HostName, &str); 3] = [
            (HostName::Ip([1, 1, 1, 1].into()), "1.1.1.1"),
            (
                HostName::Ip([1, 1, 1, 1, 1, 1, 1, 1].into()),
                "[1:1:1:1:1:1:1:1]",
            ),
            (HostName::DomainName("a.co".into()), "a.co"),
        ];
        for (host, encoded) in cases {
            let res = url_encode_host(&host);
            assert_eq!(res, encoded);
        }
    }
}
