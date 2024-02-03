use percent_encoding::percent_decode_str;
use serde_bytes::ByteBuf;
use url::Url;

use ytflow::flow::DestinationAddr;

use super::decode::{
    extract_name_from_frag, parse_host_transparent, DecodeError, DecodeResult, QueryMap,
};
use crate::proxy::protocol::trojan::TrojanProxy;
use crate::proxy::protocol::ProxyProtocolType;
use crate::proxy::tls::ProxyTlsLayer;
use crate::proxy::{Proxy, ProxyLeg};

impl TrojanProxy {
    pub(super) fn decode_share_link(url: &Url, queries: &mut QueryMap) -> DecodeResult<Proxy> {
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
}

#[cfg(test)]
mod tests {
    use ytflow::flow::HostName;

    use super::*;
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
}
