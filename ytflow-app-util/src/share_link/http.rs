use percent_encoding::percent_decode_str;
use serde_bytes::ByteBuf;
use url::Url;

use ytflow::flow::DestinationAddr;

use super::decode::{extract_name_from_frag, map_host_name, DecodeError, DecodeResult, QueryMap};
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
}

#[cfg(test)]
mod tests {
    use ytflow::flow::HostName;

    use super::*;
    use crate::proxy::tls::ProxyTlsLayer;

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
}
