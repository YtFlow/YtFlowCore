use std::borrow::Cow;
use std::fmt::Display;
use std::str::FromStr;

use base64::Engine;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Deserializer};
use url::Url;

use ytflow::config::plugin::parse_supported_security;
use ytflow::flow::{DestinationAddr, HostName};
use ytflow::plugin::vmess::SupportedSecurity;

use crate::proxy::obfs::ws::WebSocketObfs;
use crate::proxy::obfs::ProxyObfsType;
use crate::proxy::protocol::vmess::VMessProxy;
use crate::proxy::protocol::ProxyProtocolType;
use crate::proxy::tls::ProxyTlsLayer;
use crate::proxy::{Proxy, ProxyLeg};
use crate::share_link::decode::{DecodeError, DecodeResult, QueryMap, BASE64_ENGINE};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StupidValue<T>(T);

impl<'de, T> Deserialize<'de> for StupidValue<T>
where
    T: FromStr + Deserialize<'de>,
    T::Err: Display,
{
    fn deserialize<D>(deserializer: D) -> Result<StupidValue<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StrOrValue<'a, T> {
            Str(Cow<'a, str>),
            Value(T),
        }

        let str_or_val = StrOrValue::<T>::deserialize(deserializer)?;
        Ok(StupidValue(match str_or_val {
            StrOrValue::Value(val) => val,
            StrOrValue::Str(s) => s.parse().map_err(serde::de::Error::custom)?,
        }))
    }
}

#[derive(Deserialize)]
struct V2raynDoc<'a> {
    #[serde(rename = "v")]
    version: StupidValue<u8>,
    #[serde(rename = "ps")]
    name: String,
    enable_vless: Option<StupidValue<bool>>,
    #[serde(rename = "aid")]
    alter_id: StupidValue<u16>,
    #[serde(rename = "id")]
    user_id: uuid::Uuid,
    #[serde(default)]
    #[serde(rename = "scy")]
    security: &'a str,
    #[serde(rename = "add")]
    host: HostName,
    port: StupidValue<u16>,
    #[serde(default)]
    #[serde(rename = "type")]
    proxy_type: &'a str,
    #[serde(rename = "net")]
    obfs_type: &'a str,
    #[serde(rename = "host")]
    obfs_host: Option<String>,
    #[serde(rename = "path")]
    obfs_path: Option<String>,
    #[serde(default)]
    tls: &'a str,
    sni: Option<String>,
    #[serde(default)]
    alpn: &'a str,
}

pub fn decode_v2rayn(url: &Url, queries: &mut QueryMap) -> DecodeResult<Proxy> {
    if !queries.is_empty() {
        return Err(DecodeError::InvalidUrl);
    }

    let b64 = url.host_str().unwrap_or_default().to_owned() + url.path();
    let b64 = percent_decode_str(b64.strip_suffix('/').unwrap_or(&b64))
        .decode_utf8()
        .map_err(|_| DecodeError::InvalidUrl)?;
    let doc = BASE64_ENGINE
        .decode(&*b64)
        .map_err(|_| DecodeError::InvalidEncoding)?;
    let V2raynDoc {
        version: StupidValue(version),
        name,
        enable_vless,
        alter_id: StupidValue(alter_id),
        user_id,
        security,
        host,
        port: StupidValue(port),
        proxy_type,
        obfs_type,
        obfs_host,
        obfs_path,
        tls,
        sni,
        alpn,
    } = serde_json::from_slice(&doc).map_err(|_| DecodeError::InvalidEncoding)?;

    if version != 2 {
        return Err(DecodeError::UnknownValue("version"));
    }
    if let Some(StupidValue(true)) = enable_vless {
        return Err(DecodeError::UnknownValue("enable_vless"));
    }
    let security = if security == "" {
        SupportedSecurity::Auto
    } else {
        parse_supported_security(security.as_bytes())
            .ok_or(DecodeError::UnknownValue("security"))?
    };

    if !matches!(proxy_type, "" | "none" | "vmess") {
        return Err(DecodeError::UnknownValue("protocol_type"));
    }

    let mut is_ws = false;
    let obfs = match obfs_type {
        "tcp" => None,
        "ws" => {
            is_ws = true;
            Some(ProxyObfsType::WebSocket(WebSocketObfs {
                host: obfs_host,
                path: obfs_path
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "/".into()),
            }))
        }
        _ => return Err(DecodeError::UnknownValue("obfs_type")),
    };

    let tls = if tls == "tls" {
        let sni = sni.filter(|s| !s.is_empty());
        let alpns = alpn.split(',');
        let alpn = if is_ws && alpns.clone().eq(["h2", "http/1.1"]) {
            // websocket-client is ALPN-aware. Omit alpn to enable h2 probe.
            vec![]
        } else {
            alpns
                .filter(|s| !s.is_empty())
                .map(|s| s.into())
                .collect::<Vec<_>>()
        };
        Some(ProxyTlsLayer {
            alpn,
            sni,
            skip_cert_check: Some(true),
        })
    } else {
        None
    };

    Ok(Proxy {
        name,
        legs: vec![ProxyLeg {
            dest: DestinationAddr { host, port },
            protocol: ProxyProtocolType::VMess(VMessProxy {
                user_id,
                alter_id,
                security,
            }),
            obfs,
            tls,
        }],
        udp_supported: false,
    })
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use base64::prelude::*;
    use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
    use serde_json::{json, to_string as to_json};
    use uuid::uuid;

    use super::*;

    #[test]
    fn test_decode_v2rayn_minimal() {
        let doc = json!({
            "v": 2,
            "ps": "test",
            "aid": "1",
            "id": "22222222-3333-4444-5555-666666666666",
            "add": "a.co",
            "port": 11451,
            "net": "tcp",
        });
        let b64 = STANDARD.encode(to_json(&doc).unwrap().as_bytes());
        let b64 = percent_encode(b64.as_bytes(), NON_ALPHANUMERIC);
        let url = Url::parse(&format!("vmess://{}", b64)).unwrap();
        let proxy = decode_v2rayn(&url, &mut Default::default()).unwrap();
        assert_eq!(
            proxy,
            Proxy {
                name: "test".to_string(),
                legs: vec![ProxyLeg {
                    dest: DestinationAddr {
                        host: HostName::from_domain_name("a.co".into()).unwrap(),
                        port: 11451,
                    },
                    protocol: ProxyProtocolType::VMess(VMessProxy {
                        user_id: uuid!("22222222-3333-4444-5555-666666666666"),
                        alter_id: 1,
                        security: SupportedSecurity::Auto,
                    }),
                    obfs: None,
                    tls: None,
                }],
                udp_supported: false,
            }
        );
    }
    #[test]
    fn test_decode_v2rayn_invalid_url() {
        let urls = ["vmess://%ff%ff", "vmess://?a=1"];
        for raw_url in urls {
            let url = Url::parse(raw_url).unwrap();
            let mut queries = url.query_pairs().collect::<QueryMap>();
            let proxy = decode_v2rayn(&url, &mut queries);
            assert_eq!(proxy, Err(DecodeError::InvalidUrl), "{raw_url}");
        }
    }
    #[test]
    fn test_decode_v2rayn_invalid_encoding() {
        let urls = ["vmess://%3D%3D%3D", "vmess://ew=="];
        for raw_url in urls {
            let url = Url::parse(raw_url).unwrap();
            let proxy = decode_v2rayn(&url, &mut Default::default());
            assert_eq!(proxy, Err(DecodeError::InvalidEncoding), "{raw_url}");
        }
    }
    #[test]
    fn test_decode_v2rayn_unknown_value() {
        let cases = [
            ("v", json!(3), "version"),
            ("enable_vless", json!(true), "enable_vless"),
            ("enable_vless", json!("true"), "enable_vless"),
            ("scy", json!("abcd"), "security"),
            ("type", json!("vmess2"), "protocol_type"),
            ("net", json!("udp"), "obfs_type"),
        ];
        for (field, value, expected_field) in cases {
            let doc = json!({
                "v": 2,
                "ps": "test",
                "aid": "1",
                "id": "22222222-3333-4444-5555-666666666666",
                "add": "a.co",
                "port": 11451,
                "net": "tcp",
                field: value,
            });
            let b64 = STANDARD.encode(to_json(&doc).unwrap().as_bytes());
            let b64 = percent_encode(b64.as_bytes(), NON_ALPHANUMERIC);
            let url = Url::parse(&format!("vmess://{}", b64)).unwrap();
            let proxy = decode_v2rayn(&url, &mut Default::default());
            assert_eq!(
                proxy,
                Err(DecodeError::UnknownValue(expected_field)),
                "{field}={value:?} {expected_field}"
            );
        }
    }
    #[test]
    fn test_decode_v2rayn_security() {
        let cases = [
            ("none", SupportedSecurity::None),
            ("auto", SupportedSecurity::Auto),
            ("aes-128-cfb", SupportedSecurity::Aes128Cfb),
            ("aes-128-gcm", SupportedSecurity::Aes128Gcm),
            ("chacha20-poly1305", SupportedSecurity::Chacha20Poly1305),
        ];
        for (scy, expected) in cases {
            let doc = json!({
                "v": 2,
                "ps": "test",
                "aid": "1",
                "id": "22222222-3333-4444-5555-666666666666",
                "add": "a.co",
                "port": 11451,
                "net": "tcp",
                "scy": scy,
            });
            let b64 = STANDARD.encode(to_json(&doc).unwrap().as_bytes());
            let b64 = percent_encode(b64.as_bytes(), NON_ALPHANUMERIC);
            let url = Url::parse(&format!("vmess://{}", b64)).unwrap();
            let mut proxy = decode_v2rayn(&url, &mut Default::default()).unwrap();
            let vmess = match proxy.legs.pop().unwrap().protocol {
                ProxyProtocolType::VMess(vmess) => vmess,
                p => panic!("unexpected protocol type {:?}", p),
            };
            assert_eq!(vmess.security, expected, "{scy}");
        }
    }
    #[test]
    fn test_decode_v2ray_proxy_type() {
        let cases = ["", "none", "vmess"];
        for proxy_type in cases {
            let doc = json!({
                "v": 2,
                "ps": "test",
                "aid": "1",
                "id": "22222222-3333-4444-5555-666666666666",
                "add": "a.co",
                "port": 11451,
                "net": "tcp",
                "type": proxy_type,
            });
            let b64 = STANDARD.encode(to_json(&doc).unwrap().as_bytes());
            let b64 = percent_encode(b64.as_bytes(), NON_ALPHANUMERIC);
            let url = Url::parse(&format!("vmess://{}", b64)).unwrap();
            let proxy = decode_v2rayn(&url, &mut Default::default());
            assert!(proxy.is_ok(), "{proxy_type}");
        }
    }
    #[test]
    fn test_decode_v2rayn_ws() {
        let doc = json!({
            "v": 2,
            "ps": "test",
            "aid": "1",
            "id": "22222222-3333-4444-5555-666666666666",
            "add": "a.co",
            "port": 11451,
            "net": "ws",
            "host": "b.co",
            "path": "/path",
        });
        let b64 = STANDARD.encode(to_json(&doc).unwrap().as_bytes());
        let b64 = percent_encode(b64.as_bytes(), NON_ALPHANUMERIC);
        let url = Url::parse(&format!("vmess://{}", b64)).unwrap();
        let mut proxy = decode_v2rayn(&url, &mut Default::default()).unwrap();
        let leg = proxy.legs.pop().unwrap();
        let (dest, ws) = match leg {
            ProxyLeg {
                dest,
                obfs: Some(ProxyObfsType::WebSocket(ws)),
                ..
            } => (dest, ws),
            p => panic!("unexpected leg {:?}", p),
        };
        assert_eq!(
            dest.host,
            HostName::from_domain_name("a.co".into()).unwrap()
        );
        assert_eq!(
            ws,
            WebSocketObfs {
                host: Some("b.co".into()),
                path: "/path".into()
            }
        );
    }
    #[test]
    fn test_decode_v2rayn_ws_no_path() {
        let doc = json!({
            "v": 2,
            "ps": "test",
            "aid": "1",
            "id": "22222222-3333-4444-5555-666666666666",
            "add": "a.co",
            "port": 11451,
            "net": "ws",
        });
        let b64 = STANDARD.encode(to_json(&doc).unwrap().as_bytes());
        let b64 = percent_encode(b64.as_bytes(), NON_ALPHANUMERIC);
        let url = Url::parse(&format!("vmess://{}", b64)).unwrap();
        let mut proxy = decode_v2rayn(&url, &mut Default::default()).unwrap();
        let leg = proxy.legs.pop().unwrap();
        let ws = match leg.obfs {
            Some(ProxyObfsType::WebSocket(ws)) => ws,
            p => panic!("unexpected obfs {:?}", p),
        };
        assert_eq!(
            ws,
            WebSocketObfs {
                host: None,
                path: "/".into()
            }
        );
    }
    #[test]
    fn test_decode_v2rayn_tls_alpn() {
        let cases = [
            ("tcp", "h2,http/0.0", vec!["h2".into(), "http/0.0".into()]),
            ("ws", "h2,http/0.0", vec!["h2".into(), "http/0.0".into()]),
            ("ws", "h2,http/1.1", vec![]),
        ];
        for (obfs_type, alpn, expected_alpn) in cases {
            let doc = json!({
                "v": 2,
                "ps": "test",
                "aid": "1",
                "id": "22222222-3333-4444-5555-666666666666",
                "add": "a.co",
                "port": 11451,
                "net": obfs_type,
                "tls": "tls",
                "sni": "b.co",
                "alpn": alpn,
            });
            let b64 = STANDARD.encode(to_json(&doc).unwrap().as_bytes());
            let b64 = percent_encode(b64.as_bytes(), NON_ALPHANUMERIC);
            let url = Url::parse(&format!("vmess://{}", b64)).unwrap();
            let mut proxy = decode_v2rayn(&url, &mut Default::default()).unwrap();
            let ProxyLeg { dest, tls, .. } = proxy.legs.pop().unwrap();
            assert_eq!(
                dest.host,
                HostName::from_domain_name("a.co".into()).unwrap(),
                "{obfs_type} {alpn}"
            );
            assert_eq!(
                tls,
                Some(ProxyTlsLayer {
                    alpn: expected_alpn,
                    sni: Some("b.co".into()),
                    skip_cert_check: Some(true),
                }),
                "{obfs_type} {alpn}"
            );
        }
    }
    #[test]
    fn test_decode_v2rayn_tls_no_sni() {
        let doc = json!({
            "v": 2,
            "ps": "test",
            "aid": "1",
            "id": "22222222-3333-4444-5555-666666666666",
            "add": "a.co",
            "port": 11451,
            "net": "tcp",
            "tls": "tls",
            "sni": ""
        });
        let b64 = STANDARD.encode(to_json(&doc).unwrap().as_bytes());
        let b64 = percent_encode(b64.as_bytes(), NON_ALPHANUMERIC);
        let url = Url::parse(&format!("vmess://{}", b64)).unwrap();
        let mut proxy = decode_v2rayn(&url, &mut Default::default()).unwrap();
        assert_eq!(proxy.legs.pop().unwrap().tls.unwrap().sni, None);
    }
}
