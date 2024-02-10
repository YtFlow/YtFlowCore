use percent_encoding::{percent_decode_str, percent_encode, NON_ALPHANUMERIC};
use serde_bytes::ByteBuf;
use url::Url;

use ytflow::flow::DestinationAddr;

use super::decode::{
    extract_name_from_frag, parse_host_transparent, DecodeError, DecodeResult, QueryMap,
};
use super::encode::{url_encode_host, EncodeError, EncodeResult};
use crate::proxy::protocol::trojan::TrojanProxy;
use crate::proxy::protocol::ProxyProtocolType;
use crate::proxy::tls::ProxyTlsLayer;
use crate::proxy::{Proxy, ProxyLeg};

impl TrojanProxy {
    pub(super) fn decode_share_link(url: &Url, queries: &mut QueryMap) -> DecodeResult<Proxy> {
        if !matches!(&*queries.remove("security").unwrap_or_default(), "" | "tls") {
            return Err(DecodeError::UnknownValue("security"));
        }

        let password = ByteBuf::from(
            percent_decode_str(url.username())
                .decode_utf8()
                .map_err(|_| DecodeError::InvalidEncoding)?
                .into_owned(),
        );
        let host = parse_host_transparent(url)?;
        let port = url.port().unwrap_or(443);
        let skip_cert_check = queries.remove("allowInsecure").map(|s| s == "1");
        let sni = queries.remove("sni").map(|s| s.into_owned());
        let alpn = queries
            .remove("alpn")
            .map(|s| s.split(',').map(|a| a.to_owned()).collect())
            .unwrap_or_default();

        let leg = ProxyLeg {
            protocol: ProxyProtocolType::Trojan(TrojanProxy { password }),
            dest: DestinationAddr { host, port },
            obfs: None,
            tls: Some(ProxyTlsLayer {
                alpn,
                sni,
                skip_cert_check,
            }),
        };

        Ok(Proxy {
            name: extract_name_from_frag(url, &leg.dest)?,
            legs: vec![leg],
            udp_supported: false,
        })
    }

    pub(super) fn encode_share_link(&self, leg: &ProxyLeg, proxy: &Proxy) -> EncodeResult<String> {
        if proxy.legs.len() != 1 {
            return Err(EncodeError::TooManyLegs);
        }
        if leg.obfs.is_some() {
            return Err(EncodeError::UnsupportedComponent("obfs"));
        }
        let Some(tls) = &leg.tls else {
            return Err(EncodeError::UnsupportedComponent("tls"));
        };
        let host = url_encode_host(&leg.dest.host);
        let mut url = Url::parse(&format!(
            "trojan://{}@{}:{}#{}",
            percent_encode(&self.password, NON_ALPHANUMERIC).to_string(),
            host,
            leg.dest.port,
            percent_encode(proxy.name.as_bytes(), NON_ALPHANUMERIC),
        ))
        .expect("host name should be valid");

        let mut query = url.query_pairs_mut();
        if tls.skip_cert_check == Some(true) {
            query.append_pair("allowInsecure", "1");
        }
        if let Some(sni) = tls.sni.as_ref().filter(|s| !s.is_empty()) {
            query.append_pair("sni", sni);
        }
        let alpn = tls.alpn.join(",");
        if !alpn.is_empty() {
            query.append_pair("alpn", &alpn);
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
    use ytflow::flow::HostName;

    use super::*;
    use crate::proxy::obfs::ProxyObfsType;
    use crate::proxy::tls::ProxyTlsLayer;

    #[test]
    fn test_decode_share_link() {
        let url = Url::parse(&format!(
            "trojan://a%2fb@a.co:10443?alpn=ipv9,http/1.1&sni=b.com&allowInsecure=1#c/d",
        ))
        .unwrap();
        let mut queries = url.query_pairs().collect::<QueryMap>();
        let proxy = TrojanProxy::decode_share_link(&url, &mut queries).unwrap();
        assert_eq!(
            proxy,
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
                        alpn: vec!["ipv9".into(), "http/1.1".into()],
                        sni: Some("b.com".into()),
                        skip_cert_check: Some(true),
                    }),
                }],
                udp_supported: false
            },
        );
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_share_link_invalid_password() {
        let url = Url::parse("trojan://%ff@a.com").unwrap();
        let mut queries = QueryMap::new();
        let proxy = TrojanProxy::decode_share_link(&url, &mut queries);
        assert_eq!(proxy.unwrap_err(), DecodeError::InvalidEncoding);
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_share_link_no_port() {
        let url = Url::parse("trojan://aa@a.com").unwrap();
        let mut queries = QueryMap::new();
        let proxy = TrojanProxy::decode_share_link(&url, &mut queries).unwrap();
        assert_eq!(
            proxy,
            Proxy {
                name: "a.com:443".into(),
                legs: vec![ProxyLeg {
                    protocol: ProxyProtocolType::Trojan(TrojanProxy {
                        password: ByteBuf::from("aa"),
                    }),
                    dest: DestinationAddr {
                        host: HostName::from_domain_name("a.com".into()).unwrap(),
                        port: 443,
                    },
                    obfs: None,
                    tls: Some(ProxyTlsLayer {
                        alpn: vec![],
                        sni: None,
                        skip_cert_check: None,
                    }),
                }],
                udp_supported: false
            }
        );
    }
    #[test]
    fn test_decode_share_link_unknown_security() {
        let url = Url::parse("trojan://a%2fb@a.co:10443?security=qtls").unwrap();
        let mut queries = url.query_pairs().collect::<QueryMap>();
        let proxy = TrojanProxy::decode_share_link(&url, &mut queries);
        assert_eq!(proxy.unwrap_err(), DecodeError::UnknownValue("security"));
    }

    #[test]
    fn test_encode_share_link() {
        let proxy = Proxy {
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
                    alpn: vec!["ipv9".into(), "http/1.1".into()],
                    sni: Some("b.com".into()),
                    skip_cert_check: Some(true),
                }),
            }],
            udp_supported: false,
        };
        let leg = &proxy.legs[0];
        let trojan = match &leg.protocol {
            ProxyProtocolType::Trojan(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let url = trojan.encode_share_link(leg, &proxy).unwrap();
        assert_eq!(
            url,
            "trojan://a%2Fb@a.co:10443?allowInsecure=1&sni=b.com&alpn=ipv9%2Chttp%2F1.1#c%2Fd",
        );
    }
    #[test]
    fn test_encode_share_link_minimal() {
        let proxy = Proxy {
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
        };
        let leg = &proxy.legs[0];
        let trojan = match &leg.protocol {
            ProxyProtocolType::Trojan(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let url = trojan.encode_share_link(leg, &proxy).unwrap();
        assert_eq!(url, "trojan://a%2Fb@a.co:10443#c%2Fd",);
    }
    #[test]
    fn test_encode_share_link_too_many_legs() {
        let proxy = Proxy {
            name: "c/d".into(),
            legs: vec![
                ProxyLeg {
                    protocol: ProxyProtocolType::Trojan(TrojanProxy {
                        password: ByteBuf::new(),
                    }),
                    dest: DestinationAddr {
                        host: HostName::DomainName("a.co".into()),
                        port: 10443,
                    },
                    obfs: None,
                    tls: Some(Default::default()),
                },
                ProxyLeg {
                    protocol: ProxyProtocolType::Trojan(TrojanProxy {
                        password: ByteBuf::new(),
                    }),
                    dest: DestinationAddr {
                        host: HostName::DomainName("a.co".into()),
                        port: 10443,
                    },
                    obfs: None,
                    tls: Some(Default::default()),
                },
            ],
            udp_supported: false,
        };
        let leg = &proxy.legs[0];
        let trojan = match &leg.protocol {
            ProxyProtocolType::Trojan(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let url = trojan.encode_share_link(leg, &proxy);
        assert_eq!(url.unwrap_err(), EncodeError::TooManyLegs);
    }
    #[test]
    fn test_encode_share_link_obfs() {
        let proxy = Proxy {
            name: "c/d".into(),
            legs: vec![ProxyLeg {
                protocol: ProxyProtocolType::Trojan(TrojanProxy {
                    password: ByteBuf::new(),
                }),
                dest: DestinationAddr {
                    host: HostName::DomainName("a.co".into()),
                    port: 1080,
                },
                obfs: Some(ProxyObfsType::WebSocket(Default::default())),
                tls: Some(Default::default()),
            }],
            udp_supported: false,
        };
        let leg = &proxy.legs[0];
        let trojan = match &leg.protocol {
            ProxyProtocolType::Trojan(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let res = trojan.encode_share_link(leg, &proxy);
        assert_eq!(res.unwrap_err(), EncodeError::UnsupportedComponent("obfs"));
    }
}
