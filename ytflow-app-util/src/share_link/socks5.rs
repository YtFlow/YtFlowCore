use percent_encoding::{percent_decode_str, percent_encode, NON_ALPHANUMERIC};
use serde_bytes::ByteBuf;
use url::Url;

use ytflow::flow::DestinationAddr;

use super::decode::{
    extract_name_from_frag, parse_host_transparent, DecodeError, DecodeResult, QueryMap,
};
use super::encode::{url_encode_host, EncodeError, EncodeResult};
use crate::proxy::protocol::socks5::Socks5Proxy;
use crate::proxy::protocol::ProxyProtocolType;
use crate::proxy::{Proxy, ProxyLeg};

impl Socks5Proxy {
    pub(super) fn decode_share_link(url: &Url, queries: &mut QueryMap) -> DecodeResult<Proxy> {
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

        let host = parse_host_transparent(url)?;
        let port = url.port().ok_or(DecodeError::MissingInfo("port"))?;
        let dest = DestinationAddr { host, port };

        let name = queries
            .remove("remarks")
            .map(|s| Ok(s.into_owned()))
            .unwrap_or_else(|| extract_name_from_frag(url, &dest))?;

        Ok(Proxy {
            name,
            legs: vec![ProxyLeg {
                protocol: ProxyProtocolType::Socks5(Socks5Proxy {
                    username: ByteBuf::from(user),
                    password: ByteBuf::from(pass),
                }),
                dest,
                obfs: None,
                tls: None,
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
        if leg.tls.is_some() {
            return Err(EncodeError::UnsupportedComponent("tls"));
        }
        let host = url_encode_host(&leg.dest.host);
        let mut url = Url::parse(&format!(
            "socks5://{}:{}#{}",
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

    use crate::proxy::obfs::ProxyObfsType;

    use super::*;

    #[test]
    fn test_decode_share_link_hosts() {
        let url = Url::parse(&format!("socks5://a%2fb:p%2fd@a.co:1080#name%2f")).unwrap();
        let proxy = Socks5Proxy::decode_share_link(&url, &mut QueryMap::new()).unwrap();
        assert_eq!(
            proxy,
            Proxy {
                name: "name/".into(),
                legs: vec![ProxyLeg {
                    protocol: ProxyProtocolType::Socks5(Socks5Proxy {
                        username: ByteBuf::from(b"a/b"),
                        password: ByteBuf::from(b"p/d"),
                    }),
                    dest: DestinationAddr {
                        host: HostName::from_domain_name("a.co".into()).unwrap(),
                        port: 1080,
                    },
                    obfs: None,
                    tls: None,
                }],
                udp_supported: false,
            }
        );
    }
    #[test]
    fn test_decode_share_link_names() {
        let cases = [
            "socks5://a.co:1080?remarks=name.com:2333#name.frag",
            "socks5://a.co:1080?#name.com:2333",
            "socks5://name.com:2333",
        ];
        for raw_url in cases {
            let url = Url::parse(raw_url).unwrap();
            let mut queries = url.query_pairs().collect::<QueryMap>();
            let proxy = Socks5Proxy::decode_share_link(&url, &mut queries).unwrap();
            assert_eq!(proxy.name, "name.com:2333", "{raw_url}");
        }
    }
    #[test]
    fn test_decode_share_link_missing_port() {
        let url = Url::parse("socks5://a.co").unwrap();
        let proxy = Socks5Proxy::decode_share_link(&url, &mut QueryMap::new());
        assert_eq!(proxy.unwrap_err(), DecodeError::MissingInfo("port"));
    }
    #[test]
    fn test_decode_share_link_invalid_encoding() {
        let cases = ["socks5://%ff:a@a.com:1080", "socks5://a:%ff@a.com:1080"];
        for raw_url in cases {
            let url = Url::parse(raw_url).unwrap();
            let proxy = Socks5Proxy::decode_share_link(&url, &mut QueryMap::new());
            assert_eq!(proxy.unwrap_err(), DecodeError::InvalidEncoding);
        }
    }

    #[test]
    fn test_encode_share_link() {
        let proxy = Proxy {
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
        };
        let leg = &proxy.legs[0];
        let socks5 = match &leg.protocol {
            ProxyProtocolType::Socks5(p) => p,
            _ => panic!("unexpected protocol"),
        };
        assert_eq!(
            socks5.encode_share_link(leg, &proxy).unwrap(),
            "socks5://a%2Fb:p%2Fd@a.co:1080#c%2Fd"
        );
    }
    #[test]
    fn test_encode_share_link_too_many_legs() {
        let proxy = Proxy {
            name: "c/d".into(),
            legs: vec![
                ProxyLeg {
                    protocol: ProxyProtocolType::Socks5(Default::default()),
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
        let socks5 = match &leg.protocol {
            ProxyProtocolType::Socks5(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let res = socks5.encode_share_link(leg, &proxy);
        assert_eq!(res.unwrap_err(), EncodeError::TooManyLegs);
    }
    #[test]
    fn test_encode_share_link_obfs() {
        let proxy = Proxy {
            name: "c/d".into(),
            legs: vec![ProxyLeg {
                protocol: ProxyProtocolType::Socks5(Default::default()),
                dest: DestinationAddr {
                    host: HostName::DomainName("a.co".into()),
                    port: 1080,
                },
                obfs: Some(ProxyObfsType::WebSocket(Default::default())),
                tls: None,
            }],
            udp_supported: false,
        };
        let leg = &proxy.legs[0];
        let socks5 = match &leg.protocol {
            ProxyProtocolType::Socks5(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let res = socks5.encode_share_link(leg, &proxy);
        assert_eq!(res.unwrap_err(), EncodeError::UnsupportedComponent("obfs"));
    }
    #[test]
    fn test_encode_share_link_tls() {
        let proxy = Proxy {
            name: "c/d".into(),
            legs: vec![ProxyLeg {
                protocol: ProxyProtocolType::Socks5(Default::default()),
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
        let socks5 = match &leg.protocol {
            ProxyProtocolType::Socks5(p) => p,
            _ => panic!("unexpected protocol"),
        };
        let res = socks5.encode_share_link(leg, &proxy);
        assert_eq!(res.unwrap_err(), EncodeError::UnsupportedComponent("tls"));
    }
}
