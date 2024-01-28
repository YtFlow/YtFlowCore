use std::collections::BTreeMap;

use base64::Engine;
use percent_encoding::percent_decode_str;
use url::{Host, Url};
use ytflow::{
    config::plugin::parse_supported_cipher,
    flow::{DestinationAddr, HostName},
};

use super::decode::{extract_name_from_frag, DecodeError, DecodeResult, QueryMap, BASE64_ENGINE};
use crate::proxy::obfs::{http_obfs::HttpObfsObfs, tls_obfs::TlsObfsObfs, ProxyObfsType};
use crate::proxy::protocol::{shadowsocks::ShadowsocksProxy, ProxyProtocolType};
use crate::proxy::{Proxy, ProxyLeg};

fn decode_legacy(url: &Url, _queries: &mut QueryMap) -> DecodeResult<ProxyLeg> {
    let b64 = {
        let b64str = percent_decode_str(url.host_str().ok_or(DecodeError::InvalidUrl)?)
            .decode_utf8()
            .map_err(|_| DecodeError::InvalidEncoding)?;
        BASE64_ENGINE
            .decode(&*b64str)
            .map_err(|_| DecodeError::InvalidEncoding)?
    };
    let mut split = b64.rsplitn(2, |&b| b == b'@');
    let dest = {
        let host_port = split.next().unwrap();
        let host_port = std::str::from_utf8(host_port).map_err(|_| DecodeError::InvalidEncoding)?;
        let mut split = host_port.rsplitn(2, ':');
        let port = split.next().unwrap();
        let host = Host::parse(split.next().ok_or(DecodeError::InvalidEncoding)?)
            .map_err(|_| DecodeError::InvalidEncoding)?;
        DestinationAddr {
            host: match host {
                Host::Domain(domain) => {
                    HostName::from_domain_name(domain).map_err(|_| DecodeError::InvalidEncoding)?
                }
                Host::Ipv4(ip) => HostName::Ip(ip.into()),
                Host::Ipv6(ip) => HostName::Ip(ip.into()),
            },
            port: port.parse().map_err(|_| DecodeError::InvalidEncoding)?,
        }
    };
    let (cipher, password) = {
        let method_pass = split.next().ok_or(DecodeError::InvalidEncoding)?;
        let mut split = method_pass.splitn(2, |&b| b == b':');
        let method = split.next().unwrap();
        let cipher = parse_supported_cipher(method).ok_or(DecodeError::InvalidValue)?;
        let pass = split.next().ok_or(DecodeError::InvalidEncoding)?;
        (cipher, pass.into())
    };

    Ok(ProxyLeg {
        protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy { cipher, password }),
        dest,
        obfs: None,
        tls: None,
    })
}

fn decode_sip002(url: &Url, queries: &mut QueryMap) -> DecodeResult<ProxyLeg> {
    let b64 = {
        let b64str = percent_decode_str(url.username())
            .decode_utf8()
            .map_err(|_| DecodeError::InvalidEncoding)?;
        BASE64_ENGINE
            .decode(&*b64str)
            .map_err(|_| DecodeError::InvalidEncoding)?
    };
    let (cipher, password) = {
        let mut split = b64.splitn(2, |&b| b == b':');
        let method = split.next().ok_or(DecodeError::InvalidEncoding)?;
        let cipher = parse_supported_cipher(method).ok_or(DecodeError::InvalidValue)?;
        let pass = split.next().ok_or(DecodeError::InvalidEncoding)?;
        (cipher, pass)
    };

    let host = match Host::parse(url.host_str().unwrap_or_default())
        .map_err(|_| DecodeError::InvalidUrl)?
    {
        Host::Domain(domain) => {
            HostName::from_domain_name(domain.into()).map_err(|_| DecodeError::InvalidEncoding)?
        }
        Host::Ipv4(ip) => HostName::Ip(ip.into()),
        Host::Ipv6(ip) => HostName::Ip(ip.into()),
    };
    let port = url.port().ok_or(DecodeError::InvalidUrl)?;

    let plugin_param = queries.remove("plugin").unwrap_or_default();
    let mut obfs_split = plugin_param.split(";");
    let obfs = match obfs_split.next().unwrap() {
        "obfs-local" => {
            let mut obfs_params = obfs_split
                .map(|kv| {
                    let mut split = kv.splitn(2, '=');
                    let k = split.next().unwrap();
                    let v = split.next().unwrap_or_default();
                    (k, v)
                })
                .collect::<BTreeMap<&str, &str>>();

            let host = obfs_params
                .remove("obfs-host")
                .filter(|s| !s.is_empty())
                .unwrap_or(url.host_str().unwrap())
                .into();
            let r#type = obfs_params
                .remove("obfs")
                .filter(|s| !s.is_empty())
                .ok_or(DecodeError::InvalidUrl)?;
            let obfs = match r#type {
                "http" => {
                    let path = obfs_params
                        .remove("obfs-uri")
                        .filter(|s| !s.is_empty())
                        .unwrap_or("/")
                        .into();
                    ProxyObfsType::HttpObfs(HttpObfsObfs { host, path })
                }
                "tls" => ProxyObfsType::TlsObfs(TlsObfsObfs { host }),
                _ => return Err(DecodeError::InvalidValue),
            };

            if let Some((first_extra_key, _)) = obfs_params.pop_first() {
                return Err(DecodeError::ExtraParameters(first_extra_key.into()));
            }
            Some(obfs)
        }
        "" => None,
        _ => return Err(DecodeError::InvalidValue),
    };

    Ok(ProxyLeg {
        protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
            cipher,
            password: password.into(),
        }),
        dest: DestinationAddr { host, port },
        obfs,
        tls: None,
    })
}

impl ShadowsocksProxy {
    pub(super) fn decode_share_link(url: &Url, queries: &mut QueryMap) -> DecodeResult<Proxy> {
        let leg = if url.username().is_empty() {
            decode_legacy(url, queries)
        } else {
            decode_sip002(url, queries)
        }?;

        Ok(Proxy {
            name: extract_name_from_frag(url, &leg.dest)?,
            legs: vec![leg],
            udp_supported: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use base64::engine::general_purpose::STANDARD;
    use ytflow::plugin::shadowsocks::SupportedCipher;

    use super::*;

    #[test]
    fn test_decode_legacy_hosts() {
        let hosts = [
            ("3.187.225.7", HostName::Ip([3, 187, 225, 7].into())),
            ("a.co", HostName::DomainName("a.co".into())),
            ("[::1]", HostName::Ip(Ipv6Addr::LOCALHOST.into())),
        ];

        for (host_part, expected_host) in hosts {
            let url = Url::parse(&format!(
                "ss://{}",
                STANDARD.encode(format!("aes-256-cfb:UYL1EvkfI0cT6NOY@{host_part}:34187"))
            ))
            .unwrap();
            let mut queries = QueryMap::new();
            let leg = decode_legacy(&url, &mut queries).unwrap();
            assert_eq!(
                leg,
                ProxyLeg {
                    protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                        cipher: SupportedCipher::Aes256Cfb,
                        password: "UYL1EvkfI0cT6NOY".into(),
                    }),
                    dest: DestinationAddr {
                        host: expected_host,
                        port: 34187,
                    },
                    obfs: None,
                    tls: None,
                }
            );
            assert!(queries.is_empty());
        }
    }
    #[test]
    fn test_decode_legacy_no_padding() {
        let url = Url::parse("ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWUAzLjE4Ny4yMjUuNzozNDE4Nw")
            .unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_legacy(&url, &mut queries).unwrap();
        assert_eq!(leg.dest.port, 34187);
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_legacy_invalid_cipher() {
        let url = Url::parse(&format!(
            "ss://{}",
            STANDARD.encode("114514:UYL1EvkfI0cT6NOY@3.187.225.7:34187")
        ))
        .unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_legacy(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::InvalidValue);
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_legacy_invalid_url() {
        let url = Url::parse("ss://").unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_legacy(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::InvalidUrl);
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_legacy_invalid_base64() {
        let raw_urls = ["ss://%ff%ff", "ss://あ"];
        for raw_url in raw_urls {
            let url = Url::parse(raw_url).unwrap();
            let mut queries = QueryMap::new();
            let leg = decode_legacy(&url, &mut queries);
            assert_eq!(leg.unwrap_err(), DecodeError::InvalidEncoding);
            assert!(queries.is_empty());
        }
    }
    #[test]
    fn test_decode_legacy_invalid_encoding() {
        let raw_values: [&[u8]; 8] = [
            b"rc4:a@",
            b"rc4:a@a",
            b"rc4:a@:114",
            b"rc4:a@\xff\xff:114",
            b"rc4:a@ :114",
            b"rc4:a@a.co:cc",
            b"a.co:114",
            b"rc4@a.co:114",
        ];
        for raw_value in raw_values {
            let url = Url::parse(&format!("ss://{}", STANDARD.encode(raw_value))).unwrap();
            let mut queries = QueryMap::new();
            let leg = decode_legacy(&url, &mut queries);
            assert_eq!(leg.unwrap_err(), DecodeError::InvalidEncoding);
            assert!(queries.is_empty());
        }
    }
    #[test]
    fn test_decode_sip002_hosts() {
        let hosts = [
            ("3.187.225.7", HostName::Ip([3, 187, 225, 7].into())),
            ("a.co", HostName::DomainName("a.co".into())),
            ("[::1]", HostName::Ip(Ipv6Addr::LOCALHOST.into())),
        ];
        for (host_part, expected_host) in hosts {
            let url = Url::parse(&format!(
                "ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ==@{host_part}:34187"
            ))
            .unwrap();
            let mut queries = QueryMap::new();
            let leg = decode_sip002(&url, &mut queries).unwrap();
            assert_eq!(
                leg,
                ProxyLeg {
                    protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                        cipher: SupportedCipher::Aes256Cfb,
                        password: "UYL1EvkfI0cT6NOY".into(),
                    }),
                    dest: DestinationAddr {
                        host: expected_host,
                        port: 34187,
                    },
                    obfs: None,
                    tls: None,
                }
            );
            assert!(queries.is_empty());
        }
    }
    #[test]
    fn test_decode_sip002_no_padding() {
        let url =
            Url::parse("ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ@3.187.225.7:34187").unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_sip002(&url, &mut queries).unwrap();
        let ss = match leg.protocol {
            ProxyProtocolType::Shadowsocks(ss) => ss,
            p => panic!("unexpected protocol type {:?}", p),
        };
        assert_eq!(&ss.password, b"UYL1EvkfI0cT6NOY");
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_sip002_obfs() {
        let cases = [
            (
                "obfs=tls",
                ProxyObfsType::TlsObfs(TlsObfsObfs {
                    host: "3.187.225.7".into(),
                }),
            ),
            (
                "obfs=tls;obfs-host=a.co",
                ProxyObfsType::TlsObfs(TlsObfsObfs {
                    host: "a.co".into(),
                }),
            ),
            (
                "obfs=http",
                ProxyObfsType::HttpObfs(HttpObfsObfs {
                    host: "3.187.225.7".into(),
                    path: "/".into(),
                }),
            ),
            (
                "obfs=http;obfs-host=a.co",
                ProxyObfsType::HttpObfs(HttpObfsObfs {
                    host: "a.co".into(),
                    path: "/".into(),
                }),
            ),
            (
                "obfs=http;obfs-host=",
                ProxyObfsType::HttpObfs(HttpObfsObfs {
                    host: "3.187.225.7".into(),
                    path: "/".into(),
                }),
            ),
            (
                "obfs=http;obfs-host=a.co;obfs-uri=/bb",
                ProxyObfsType::HttpObfs(HttpObfsObfs {
                    host: "a.co".into(),
                    path: "/bb".into(),
                }),
            ),
            (
                "obfs=http;obfs-host=a.co;obfs-uri=",
                ProxyObfsType::HttpObfs(HttpObfsObfs {
                    host: "a.co".into(),
                    path: "/".into(),
                }),
            ),
        ];
        for (obfs_param, expected_obfs) in cases {
            let url =
            Url::parse(&format!("ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ==@3.187.225.7:34187?plugin=obfs-local;{}", obfs_param))
                .unwrap();
            let mut queries = url.query_pairs().collect::<QueryMap>();
            let leg = decode_sip002(&url, &mut queries).unwrap();
            assert_eq!(leg.obfs.unwrap(), expected_obfs);
            assert!(queries.is_empty());
        }
    }
    #[test]
    fn test_decode_sip002_invalid_cipher() {
        let url = Url::parse(&format!(
            "ss://{}@3.187.225.7:34187",
            STANDARD.encode("114514:UYL1EvkfI0cT6NOY")
        ))
        .unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_sip002(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::InvalidValue);
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_sip002_invalid_plugin() {
        let url =
            Url::parse("ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ==@3.187.225.7:34187?plugin=aa")
                .unwrap();
        let mut queries = url.query_pairs().collect::<QueryMap>();
        let leg = decode_sip002(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::InvalidValue);
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_sip002_no_obfs() {
        let url = Url::parse(
            "ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ==@3.187.225.7:34187?plugin=obfs-local;",
        )
        .unwrap();
        let mut queries = url.query_pairs().collect::<QueryMap>();
        let leg = decode_sip002(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::InvalidUrl);
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_sip002_invalid_obfs() {
        let url =
            Url::parse("ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ==@3.187.225.7:34187?plugin=obfs-local;obfs=aa")
                .unwrap();
        let mut queries = url.query_pairs().collect::<QueryMap>();
        let leg = decode_sip002(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::InvalidValue);
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_sip002_obfs_extra_params() {
        let url =
            Url::parse("ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ==@3.187.225.7:34187?plugin=obfs-local;obfs=http;aa=bb")
                .unwrap();
        let mut queries = url.query_pairs().collect::<QueryMap>();
        let leg = decode_sip002(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::ExtraParameters("aa".into()));
        assert!(queries.is_empty());
    }
}
