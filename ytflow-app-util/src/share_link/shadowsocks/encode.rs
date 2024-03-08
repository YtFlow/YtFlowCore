use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use url::Url;

use crate::proxy::obfs::ProxyObfsType;
use crate::proxy::protocol::ShadowsocksProxy;
use crate::proxy::{Proxy, ProxyLeg};
use crate::share_link::encode::{url_encode_host, EncodeError, EncodeResult};

impl ShadowsocksProxy {
    pub(in super::super) fn encode_share_link(
        &self,
        leg: &ProxyLeg,
        proxy: &Proxy,
    ) -> EncodeResult<String> {
        if proxy.legs.len() != 1 {
            return Err(EncodeError::TooManyLegs);
        }
        if leg.tls.is_some() {
            return Err(EncodeError::UnsupportedComponent("tls"));
        }
        let host = url_encode_host(&leg.dest.host);
        let username = {
            let mut buf = self.cipher.to_string().into_bytes();
            buf.reserve(1 + self.password.len());
            buf.push(b':');
            buf.extend_from_slice(&self.password);
            percent_encode(STANDARD.encode(buf).as_bytes(), NON_ALPHANUMERIC).to_string()
        };
        let mut url = Url::parse(&format!(
            "ss://{}@{}:{}#{}",
            username,
            host,
            leg.dest.port,
            percent_encode(proxy.name.as_bytes(), NON_ALPHANUMERIC),
        ))
        .expect("host name should be valid");

        let plugin_param = match &leg.obfs {
            Some(ProxyObfsType::HttpObfs(http_obfs)) => Some(format!(
                "obfs-local;obfs=http;obfs-host={};obfs-uri={}",
                http_obfs.host, http_obfs.path
            )),
            Some(ProxyObfsType::TlsObfs(tls_obfs)) => {
                Some(format!("obfs-local;obfs=tls;obfs-host={}", tls_obfs.host))
            }
            None => None,
            _ => return Err(EncodeError::UnsupportedComponent("obfs")),
        };
        let mut query = url.query_pairs_mut();
        if let Some(plugin_param) = plugin_param {
            query.append_pair("plugin", &plugin_param);
        }
        drop(query);
        if url.query() == Some("") {
            url.set_query(None);
        }

        Ok(url.to_string())
    }
}

#[cfg(test)]
mod tests {
    use serde_bytes::ByteBuf;
    use ytflow::flow::{DestinationAddr, HostName};
    use ytflow::plugin::shadowsocks::SupportedCipher;

    use crate::proxy::obfs::{HttpObfsObfs, TlsObfsObfs};
    use crate::proxy::protocol::ProxyProtocolType;

    use super::*;

    #[test]
    fn test_encode_share_link() {
        let proxy = Proxy {
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
        };
        let leg = &proxy.legs[0];
        let ss = match &leg.protocol {
            ProxyProtocolType::Shadowsocks(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let url = ss.encode_share_link(leg, &proxy).unwrap();
        assert_eq!(
            url,
            "ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ%3D%3D@a.co:1080#c%2Fd",
        );
    }
    #[test]
    fn test_encode_share_link_http_obfs() {
        let proxy = Proxy {
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
                obfs: Some(ProxyObfsType::HttpObfs(HttpObfsObfs {
                    host: "obfs.co".into(),
                    path: "/obfs".into(),
                })),
                tls: None,
            }],
            udp_supported: true,
        };
        let leg = &proxy.legs[0];
        let ss = match &leg.protocol {
            ProxyProtocolType::Shadowsocks(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let url = ss.encode_share_link(leg, &proxy).unwrap();
        assert_eq!(
            url,
            "ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ%3D%3D@a.co:1080?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dobfs.co%3Bobfs-uri%3D%2Fobfs#c%2Fd"
        );
    }
    #[test]
    fn test_encode_share_link_tls_obfs() {
        let proxy = Proxy {
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
                obfs: Some(ProxyObfsType::TlsObfs(TlsObfsObfs {
                    host: "obfs.co".into(),
                })),
                tls: None,
            }],
            udp_supported: true,
        };
        let leg = &proxy.legs[0];
        let ss = match &leg.protocol {
            ProxyProtocolType::Shadowsocks(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let url = ss.encode_share_link(leg, &proxy).unwrap();
        assert_eq!(
            url,
            "ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ%3D%3D@a.co:1080?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dobfs.co#c%2Fd"
        );
    }
    #[test]
    fn test_encode_share_link_too_many_legs() {
        let proxy = Proxy {
            name: "c/d".into(),
            legs: vec![
                ProxyLeg {
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
                },
                ProxyLeg {
                    protocol: ProxyProtocolType::Http(Default::default()),
                    dest: DestinationAddr {
                        host: HostName::DomainName("b.co".into()),
                        port: 1080,
                    },
                    obfs: None,
                    tls: None,
                },
            ],
            udp_supported: true,
        };
        let leg = &proxy.legs[0];
        let ss = match &leg.protocol {
            ProxyProtocolType::Shadowsocks(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let res = ss.encode_share_link(leg, &proxy);
        assert_eq!(res.unwrap_err(), EncodeError::TooManyLegs);
    }
    #[test]
    fn test_encode_share_link_tls() {
        let proxy = Proxy {
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
                tls: Some(Default::default()),
            }],
            udp_supported: true,
        };
        let leg = &proxy.legs[0];
        let ss = match &leg.protocol {
            ProxyProtocolType::Shadowsocks(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let res = ss.encode_share_link(leg, &proxy);
        assert_eq!(res.unwrap_err(), EncodeError::UnsupportedComponent("tls"));
    }
    #[test]
    fn test_encode_share_link_unknown_obfs() {
        let proxy = Proxy {
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
                obfs: Some(ProxyObfsType::WebSocket(Default::default())),
                tls: None,
            }],
            udp_supported: true,
        };
        let leg = &proxy.legs[0];
        let ss = match &leg.protocol {
            ProxyProtocolType::Shadowsocks(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let res = ss.encode_share_link(leg, &proxy);
        assert_eq!(res.unwrap_err(), EncodeError::UnsupportedComponent("obfs"));
    }
}
