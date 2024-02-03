use percent_encoding::{percent_decode_str, percent_encode, NON_ALPHANUMERIC};
use serde_bytes::ByteBuf;
use url::Url;

use ytflow::flow::DestinationAddr;

use super::decode::{extract_name_from_frag, map_host_name, DecodeError, DecodeResult, QueryMap};
use super::encode::{url_encode_host, EncodeError, EncodeResult};
use crate::proxy::protocol::http::HttpProxy;
use crate::proxy::protocol::ProxyProtocolType;
use crate::proxy::tls::ProxyTlsLayer;
use crate::proxy::{Proxy, ProxyLeg};

impl HttpProxy {
    pub(super) fn decode_share_link(url: &Url, _queries: &mut QueryMap) -> DecodeResult<Proxy> {
        let user = percent_decode_str(url.username())
            .decode_utf8()
            .map_err(|_| DecodeError::InvalidEncoding)?
            .into_owned()
            .into_bytes();
        let pass = percent_decode_str(url.password().unwrap_or_default())
            .decode_utf8()
            .map_err(|_| DecodeError::InvalidEncoding)?
            .into_owned()
            .into_bytes();

        let host = map_host_name(url.host().expect("http or https URLs must have a host"));
        let port = url
            .port_or_known_default()
            .expect("http or https URLs must have a port or a default port");
        let dest = DestinationAddr { host, port };

        Ok(Proxy {
            name: extract_name_from_frag(url, &dest)?,
            legs: vec![ProxyLeg {
                protocol: ProxyProtocolType::Http(HttpProxy {
                    username: ByteBuf::from(user),
                    password: ByteBuf::from(pass),
                }),
                dest,
                obfs: None,
                tls: (url.scheme() == "https").then_some(ProxyTlsLayer::default()),
            }],
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
        let host = url_encode_host(&leg.dest.host);
        let mut url = Url::parse(&format!(
            "{}://{}:{}#{}",
            if leg.tls.is_some() { "https" } else { "http" },
            host,
            leg.dest.port,
            percent_encode(proxy.name.as_bytes(), NON_ALPHANUMERIC),
        ))
        .expect("host name should be valid");

        if !self.username.is_empty() {
            url.set_username(&percent_encode(&self.username, NON_ALPHANUMERIC).to_string())
                .expect("cannot set username");
        }
        if !self.password.is_empty() {
            url.set_password(Some(
                &percent_encode(&self.password, NON_ALPHANUMERIC).to_string(),
            ))
            .expect("cannot set password");
        }

        Ok(url.to_string())
    }
}

#[cfg(test)]
mod tests {
    use ytflow::flow::HostName;

    use super::*;
    use crate::proxy::{obfs::ProxyObfsType, tls::ProxyTlsLayer};

    #[test]
    fn test_decode_share_link() {
        let url = Url::parse(&format!("http://a%2fb:p%2fd@a.co:1080#c/d",)).unwrap();
        let mut queries = url.query_pairs().collect::<QueryMap>();
        let proxy = HttpProxy::decode_share_link(&url, &mut queries).unwrap();
        assert_eq!(
            proxy,
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
                udp_supported: false
            },
        );
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_share_link_default_http_port() {
        let url = Url::parse("http://a.com").unwrap();
        let mut queries = QueryMap::new();
        let proxy = HttpProxy::decode_share_link(&url, &mut queries).unwrap();
        assert_eq!(proxy.legs[0].dest.port, 80);
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_share_link_https() {
        let url = Url::parse("https://a.com:10443").unwrap();
        let mut queries = QueryMap::new();
        let proxy = HttpProxy::decode_share_link(&url, &mut queries).unwrap();
        assert_eq!(proxy.legs[0].tls, Some(ProxyTlsLayer::default()));
        assert_eq!(proxy.legs[0].dest.port, 10443);
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_share_link_https_default_port() {
        let url = Url::parse("https://a.com").unwrap();
        let mut queries = QueryMap::new();
        let proxy = HttpProxy::decode_share_link(&url, &mut queries).unwrap();
        assert_eq!(proxy.legs[0].dest.port, 443);
        assert!(queries.is_empty());
    }

    #[test]
    fn test_encode_share_link() {
        let proxy = Proxy {
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
        };
        let leg = &proxy.legs[0];
        let http = match &leg.protocol {
            ProxyProtocolType::Http(p) => p,
            _ => panic!("unexpected protocol"),
        };
        assert_eq!(
            http.encode_share_link(leg, &proxy).unwrap(),
            "http://a%2Fb:p%2Fd@a.co:1080/#c%2Fd"
        );
    }
    #[test]
    fn test_encode_share_link_https() {
        let proxy = Proxy {
            name: "c/d".into(),
            legs: vec![ProxyLeg {
                protocol: ProxyProtocolType::Http(Default::default()),
                dest: DestinationAddr {
                    host: HostName::DomainName("a.co".into()),
                    port: 1080,
                },
                obfs: None,
                tls: Some(Default::default()),
            }],
            udp_supported: false,
        };
        let leg = &proxy.legs[0];
        let http = match &leg.protocol {
            ProxyProtocolType::Http(p) => p,
            _ => panic!("unexpected protocol"),
        };
        assert_eq!(
            http.encode_share_link(leg, &proxy).unwrap(),
            "https://a.co:1080/#c%2Fd"
        );
    }
    #[test]
    fn test_encode_share_link_too_many_legs() {
        let proxy = Proxy {
            name: "c/d".into(),
            legs: vec![
                ProxyLeg {
                    protocol: ProxyProtocolType::Http(Default::default()),
                    dest: DestinationAddr {
                        host: HostName::DomainName("a.co".into()),
                        port: 1080,
                    },
                    obfs: None,
                    tls: Some(Default::default()),
                },
                ProxyLeg {
                    protocol: ProxyProtocolType::Http(Default::default()),
                    dest: DestinationAddr {
                        host: HostName::DomainName("b.co".into()),
                        port: 1080,
                    },
                    obfs: None,
                    tls: Some(Default::default()),
                },
            ],
            udp_supported: false,
        };
        let leg = &proxy.legs[0];
        let http = match &leg.protocol {
            ProxyProtocolType::Http(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let res = http.encode_share_link(leg, &proxy);
        assert_eq!(res.unwrap_err(), EncodeError::TooManyLegs);
    }
    #[test]
    fn test_encode_share_link_obfs() {
        let proxy = Proxy {
            name: "c/d".into(),
            legs: vec![ProxyLeg {
                protocol: ProxyProtocolType::Http(Default::default()),
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
        let http = match &leg.protocol {
            ProxyProtocolType::Http(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let res = http.encode_share_link(leg, &proxy);
        assert_eq!(res.unwrap_err(), EncodeError::UnsupportedComponent("obfs"));
    }
}
