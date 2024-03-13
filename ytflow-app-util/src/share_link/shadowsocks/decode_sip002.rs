use std::collections::BTreeMap;

use base64::Engine;
use percent_encoding::percent_decode_str;
use serde_bytes::ByteBuf;
use url::Url;

use ytflow::{config::plugin::parse_supported_cipher, flow::DestinationAddr};

use crate::proxy::obfs::{HttpObfsObfs, ProxyObfsType, TlsObfsObfs};
use crate::proxy::protocol::{ProxyProtocolType, ShadowsocksProxy};
use crate::proxy::ProxyLeg;
use crate::share_link::decode::parse_host_transparent;
use crate::share_link::decode::{DecodeError, DecodeResult, QueryMap, BASE64_ENGINE};

pub fn decode_shadowsocks_plugin_opts(
    plugin: &str,
    opts: &str,
    leg: &mut ProxyLeg,
) -> DecodeResult<()> {
    match plugin {
        "" => return Ok(()),
        "obfs-local" => {}
        _ => return Err(DecodeError::UnknownValue("plugin")),
    };
    let mut obfs_params = opts
        .split(';')
        .map(|kv| {
            let mut split = kv.splitn(2, '=');
            let k = split.next().expect("first split must exist");
            let v = split.next().unwrap_or_default();
            (k, v)
        })
        .collect::<BTreeMap<&str, &str>>();

    let host = obfs_params
        .remove("obfs-host")
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| leg.dest.host.to_string());
    let r#type = obfs_params
        .remove("obfs")
        .filter(|s| !s.is_empty())
        .ok_or(DecodeError::MissingInfo("obfs"))?;

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
        _ => return Err(DecodeError::UnknownValue("obfs")),
    };

    if let Some((first_extra_key, _)) = obfs_params.pop_first() {
        return Err(DecodeError::ExtraParameters(first_extra_key.into()));
    }

    leg.obfs = Some(obfs);
    Ok(())
}

pub fn decode_sip002(url: &Url, queries: &mut QueryMap) -> DecodeResult<ProxyLeg> {
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
        let method = split.next().expect("first split must exist");
        let cipher = parse_supported_cipher(method).ok_or(DecodeError::UnknownValue("method"))?;
        let pass = split.next().ok_or(DecodeError::MissingInfo("password"))?;
        (cipher, pass)
    };

    let host = parse_host_transparent(url)?;
    let port = url.port().ok_or(DecodeError::InvalidUrl)?;

    let mut leg = ProxyLeg {
        protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
            cipher,
            password: ByteBuf::from(password),
        }),
        dest: DestinationAddr { host, port },
        obfs: None,
        tls: None,
    };

    let plugin_param = queries.remove("plugin").unwrap_or_default();
    let (obfs_plugin, obfs_opts) = plugin_param.split_once(";").unwrap_or((&plugin_param, ""));
    decode_shadowsocks_plugin_opts(obfs_plugin, obfs_opts, &mut leg)?;

    queries.remove("group");
    Ok(leg)
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

    use ytflow::flow::HostName;
    use ytflow::plugin::shadowsocks::SupportedCipher;

    use super::*;

    #[test]
    fn test_decode_sip002() {
        let url = Url::parse(&format!(
            "ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ==@a.co:34187"
        ))
        .unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_sip002(&url, &mut queries).unwrap();
        assert_eq!(
            leg,
            ProxyLeg {
                protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                    cipher: SupportedCipher::Aes256Cfb,
                    password: ByteBuf::from("UYL1EvkfI0cT6NOY"),
                }),
                dest: DestinationAddr {
                    host: HostName::DomainName("a.co".into()),
                    port: 34187,
                },
                obfs: None,
                tls: None,
            },
        );
        assert!(queries.is_empty());
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
    fn test_decode_sip002_binary_password() {
        let url = Url::parse(&format!(
            "ss://{}@3.187.225.7:34187",
            utf8_percent_encode(&STANDARD.encode(b"aes-128-cfb:\xff\xff"), NON_ALPHANUMERIC)
        ))
        .unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_sip002(&url, &mut queries).unwrap();
        let ss = match leg.protocol {
            ProxyProtocolType::Shadowsocks(ss) => ss,
            p => panic!("unexpected protocol type {:?}", p),
        };
        assert_eq!(&ss.password, b"\xff\xff");
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
            assert_eq!(leg.obfs.unwrap(), expected_obfs, "{obfs_param}");
            assert!(queries.is_empty());
        }
    }
    #[test]
    fn test_decode_sip002_unknown_cipher() {
        let url = Url::parse(&format!(
            "ss://{}@3.187.225.7:34187",
            STANDARD.encode("114514:UYL1EvkfI0cT6NOY")
        ))
        .unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_sip002(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::UnknownValue("method"));
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_sip002_unknown_plugin() {
        let url =
            Url::parse("ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ==@3.187.225.7:34187?plugin=aa")
                .unwrap();
        let mut queries = url.query_pairs().collect::<QueryMap>();
        let leg = decode_sip002(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::UnknownValue("plugin"));
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
        assert_eq!(leg.unwrap_err(), DecodeError::MissingInfo("obfs"));
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_sip002_invalid_obfs() {
        let url =
            Url::parse("ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ==@3.187.225.7:34187?plugin=obfs-local;obfs=aa")
                .unwrap();
        let mut queries = url.query_pairs().collect::<QueryMap>();
        let leg = decode_sip002(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::UnknownValue("obfs"));
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
    #[test]
    fn test_decode_sip002_invalid_url() {
        let raw_urls = ["ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ==@a.co"];
        for raw_url in raw_urls {
            let url = Url::parse(raw_url).unwrap();
            let mut queries = QueryMap::new();
            let leg = decode_sip002(&url, &mut queries);
            assert_eq!(leg.unwrap_err(), DecodeError::InvalidUrl, "{raw_url}");
            assert!(queries.is_empty());
        }
    }
    #[test]
    fn test_decode_sip002_missing_password() {
        let url = Url::parse(&format!(
            "ss://{}@3.187.225.7:34187",
            STANDARD.encode("aes-128-gcm")
        ))
        .unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_sip002(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::MissingInfo("password"));
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_sip002_invalid_encoding() {
        let cases: [&str; 2] = ["ss://%ff%ff@a.com:114", "ss://あ@a.com:514"];
        for raw_url in cases {
            let url = Url::parse(raw_url).unwrap();
            let mut queries = QueryMap::new();
            let leg = decode_sip002(&url, &mut queries);
            assert_eq!(leg.unwrap_err(), DecodeError::InvalidEncoding, "{raw_url}",);
            assert!(queries.is_empty());
        }
    }
}
