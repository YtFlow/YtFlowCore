use percent_encoding::percent_decode_str;
use serde_bytes::ByteBuf;
use url::Url;

use ytflow::flow::DestinationAddr;

use super::decode::{
    extract_name_from_frag, parse_host_transparent, DecodeError, DecodeResult, QueryMap,
};
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
}

#[cfg(test)]
mod tests {
    use ytflow::flow::HostName;

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
}
