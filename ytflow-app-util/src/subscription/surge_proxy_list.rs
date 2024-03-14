use std::collections::BTreeMap;

use serde_bytes::ByteBuf;

use ytflow::config::plugin::{parse_supported_cipher, parse_supported_security};
use ytflow::flow::{DestinationAddr, HostName};
use ytflow::plugin::vmess::SupportedSecurity;

use super::decode::DecodeResult;
use crate::proxy::obfs::{HttpObfsObfs, ProxyObfsType, TlsObfsObfs, WebSocketObfs};
use crate::proxy::protocol::{
    HttpProxy, ProxyProtocolType, ShadowsocksProxy, Socks5Proxy, TrojanProxy, VMessProxy,
};
use crate::proxy::tls::ProxyTlsLayer;
use crate::proxy::{Proxy, ProxyLeg};
use crate::subscription::{Subscription, SubscriptionFormat};

impl SubscriptionFormat<'static> {
    pub const SURGE_PROXY_LIST: Self = SubscriptionFormat(b"surge-proxy-list\0");
}

fn decode_surge_proxy_line(line: &str, parents: &mut BTreeMap<String, String>) -> Option<Proxy> {
    let line = line
        .trim()
        .split('#')
        .next()
        .expect("first split must exist");

    let (mut name, args) = line.split_once('=')?;
    name = name.trim();
    let mut args = args.split(',').map(str::trim).fuse();

    let protocol = args.next()?;
    let server = args.next()?;
    let port: u16 = args.next()?.parse().ok()?;
    let dest = DestinationAddr {
        host: HostName::from_domain_name(server.into()).ok()?,
        port,
    };
    let (mut username, mut password) = ("", "");
    let mut kv_args = BTreeMap::new();
    if let Some(maybe_username) = args.next() {
        if let Some((k, v)) = maybe_username.split_once('=') {
            kv_args.insert(k.trim(), v.trim());
        } else {
            username = maybe_username;
            if let Some(maybe_password) = args.next() {
                if let Some((k, v)) = maybe_password.split_once('=') {
                    kv_args.insert(k.trim(), v.trim());
                } else {
                    password = maybe_password;
                }
            }
        }
    }
    let (username, password) = (
        ByteBuf::from(username.as_bytes()),
        ByteBuf::from(password.as_bytes()),
    );
    kv_args.extend(args.filter_map(|arg| {
        let (k, v) = arg.split_once('=')?;
        Some((k.trim(), Some(v.trim()).filter(|s| !s.is_empty())?))
    }));
    kv_args.remove("group");
    kv_args.remove("no-error-alert");

    let sni = kv_args.remove("sni").filter(|&sni| sni != "off");
    let tls = if kv_args.remove("tls") == Some("true")
        || ["https", "trojan", "socks5-tls"].contains(&protocol)
    {
        Some(ProxyTlsLayer {
            alpn: vec![],
            sni: sni.map(String::from),
            skip_cert_check: kv_args.remove("skip-cert-verify").map(|v| v == "true"),
        })
    } else {
        None
    };

    let ws = kv_args.remove("ws");
    let obfs = kv_args.remove("obfs");
    let obfs_host = kv_args.remove("obfs-host").unwrap_or(server);
    let obfs_uri = kv_args.remove("obfs-uri").unwrap_or("/");
    let ws_path = kv_args.remove("ws-path").unwrap_or("/");
    let ws_headers = kv_args
        .remove("ws-headers")
        .unwrap_or_default()
        .split('|')
        .filter_map(|kv| kv.split_once(':').map(|(k, v)| (k.trim(), v.trim())))
        .map(|(k, v)| (k.into(), v.into()));
    let obfs = if ws == Some("true") {
        Some(ProxyObfsType::WebSocket(WebSocketObfs {
            host: None,
            path: ws_path.into(),
            headers: ws_headers.collect(),
        }))
    } else if obfs == Some("http") {
        Some(ProxyObfsType::HttpObfs(HttpObfsObfs {
            host: obfs_host.into(),
            path: obfs_uri.into(),
        }))
    } else if obfs == Some("tls") {
        Some(ProxyObfsType::TlsObfs(TlsObfsObfs {
            host: obfs_host.into(),
        }))
    } else {
        None
    };

    let mut udp_supported = false;
    let encrypt_method = kv_args.remove("encrypt-method");
    let protocol_username = kv_args.remove("username").unwrap_or_default();
    let protocol_password = ByteBuf::from(kv_args.remove("password").unwrap_or_default());
    let udp_relay = kv_args.remove("udp-relay").unwrap_or_default();
    let vmess_aead = kv_args.remove("vmess-aead").unwrap_or_default();
    let protocol = match protocol {
        "http" | "https" => {
            kv_args.remove("always-use-connect");
            ProxyProtocolType::Http(HttpProxy { username, password })
        }
        "socks5" | "socks5-tls" => ProxyProtocolType::Socks5(Socks5Proxy { username, password }),
        "ss" => {
            udp_supported = udp_relay == "true";
            ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                cipher: parse_supported_cipher(encrypt_method?.as_bytes())?,
                password: protocol_password,
            })
        }
        "trojan" => ProxyProtocolType::Trojan(TrojanProxy {
            password: protocol_password,
        }),
        "vmess" => ProxyProtocolType::VMess(VMessProxy {
            user_id: protocol_username.parse().ok()?,
            security: encrypt_method
                .map(|s| parse_supported_security(s.as_bytes()))
                .unwrap_or(Some(SupportedSecurity::Auto))?,
            alter_id: if vmess_aead == "true" { 0 } else { 1 },
        }),
        _ => return None,
    };

    if let Some(underlying_proxy) = kv_args.remove("underlying-proxy") {
        parents.insert(name.into(), underlying_proxy.into());
    }

    if !kv_args.is_empty() {
        return None;
    }

    Some(Proxy {
        name: name.into(),
        legs: vec![ProxyLeg {
            protocol,
            dest,
            obfs,
            tls,
        }],
        udp_supported,
    })
}

pub fn decode_surge_proxy_list(data: &[u8]) -> DecodeResult<Subscription> {
    let mut parents = BTreeMap::new();
    let mut proxies = String::from_utf8_lossy(data)
        .lines()
        .filter_map(|l| decode_surge_proxy_line(l, &mut parents))
        .collect::<Vec<_>>();
    while let Some((leaf, mut node)) = parents.pop_first() {
        let mut chain = vec![leaf];
        while let Some(parent) = parents.remove(&node) {
            chain.push(node);
            node = parent;
        }
        let mut parent = node;
        while let Some(child_name) = chain.pop() {
            let Some(parent_proxy) = proxies.iter().find(|p| p.name == parent) else {
                proxies.retain(|p| p.name != child_name);
                continue;
            };
            let mut parent_legs = parent_proxy.legs.clone();
            let child = proxies
                .iter_mut()
                .find(|p| p.name == child_name)
                .expect("child must have been decoded");
            parent_legs.extend(child.legs.drain(..));
            child.legs = parent_legs;
            parent = child_name;
        }
    }
    Ok(Subscription { proxies })
}

#[cfg(test)]
mod tests {
    use uuid::uuid;

    use ytflow::plugin::shadowsocks::SupportedCipher;

    use super::*;

    #[test]
    fn test_decode_surge_proxy_list() {
        let data = b"
            // # aa = ss , a.com , 11451 , group = g , no-error-alert = t , encrypt-method = aes-256-cfb , password = abc , udp-relay = true 
            aa = ss , a.com , 11451 , group = g , no-error-alert = t , encrypt-method = aes-256-cfb , password = abc , udp-relay = true , kk
        ";
        let sub = decode_surge_proxy_list(data).unwrap();
        assert_eq!(
            sub,
            Subscription {
                proxies: vec![Proxy {
                    name: "aa".into(),
                    legs: vec![ProxyLeg {
                        protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                            cipher: SupportedCipher::Aes256Cfb,
                            password: ByteBuf::from(b"abc"),
                        }),
                        dest: DestinationAddr {
                            host: HostName::from_domain_name("a.com".into()).unwrap(),
                            port: 11451,
                        },
                        obfs: None,
                        tls: None,
                    }],
                    udp_supported: true,
                }]
            }
        );
    }

    #[test]
    fn test_decode_surge_proxy_list_tls() {
        let cases = [
            (
                "aa = ss, a.com, 114, encrypt-method=aes-256-cfb, password=abc, tls=true, sni=b.com, skip-cert-verify=false",
                ProxyTlsLayer {
                    alpn: vec![],
                    sni: Some("b.com".into()),
                    skip_cert_check: Some(false),
                },
            ),
            ("aa = https, a.com, 114", Default::default()),
            ("aa = trojan, a.com, 114, password=abc", Default::default()),
            ("aa = socks5-tls, a.com, 114", Default::default()),
        ];
        for (data, expected_tls) in cases {
            let mut sub = decode_surge_proxy_list(data.as_bytes()).unwrap();
            let proxy = sub.proxies.pop().unwrap().legs.pop().unwrap().tls.unwrap();
            assert_eq!(proxy, expected_tls, "{data}");
        }
    }

    #[test]
    fn test_decode_surge_proxy_list_obfs() {
        let cases = [
            (
                "aa = ss, a.com, 114, encrypt-method=aes-256-cfb, password=abc, ws=true",
                ProxyObfsType::WebSocket(Default::default()),
            ),
            (
                "aa = ss, a.com, 114, encrypt-method=aes-256-cfb, password=abc, ws=true, ws-path=/path, ws-headers=H1:V1|H2:V2|HH",
                ProxyObfsType::WebSocket(WebSocketObfs {
                    host: None,
                    path: "/path".into(),
                    headers: [("H1".into(), "V1".into()), ("H2".into(), "V2".into())]
                        .into_iter()
                        .collect(),
                }),
            ),
            (
                "aa = ss, a.com, 114, encrypt-method=aes-256-cfb, password=abc, obfs=http, obfs-host=b.com, obfs-uri=/path",
                ProxyObfsType::HttpObfs(HttpObfsObfs {
                    host: "b.com".into(),
                    path: "/path".into(),
                }),
            ),
            (
                "aa = ss, a.com, 114, encrypt-method=aes-256-cfb, password=abc, obfs=http",
                ProxyObfsType::HttpObfs(HttpObfsObfs {
                    host: "a.com".into(),
                    path: "/".into(),
                }),
            ),
            (
                "aa = ss, a.com, 114, encrypt-method=aes-256-cfb, password=abc, obfs=tls, obfs-host=b.com",
                ProxyObfsType::TlsObfs(TlsObfsObfs {
                    host: "b.com".into(),
                }),
            ),
            (
                "aa = ss, a.com, 114, encrypt-method=aes-256-cfb, password=abc, obfs=tls",
                ProxyObfsType::TlsObfs(TlsObfsObfs {
                    host: "a.com".into(),
                }),
            ),
        ];
        for (data, expected_obfs) in cases {
            let mut sub = decode_surge_proxy_list(data.as_bytes()).unwrap();
            let proxy = sub.proxies.pop().unwrap().legs.pop().unwrap().obfs.unwrap();
            assert_eq!(proxy, expected_obfs, "{data}");
        }
    }

    #[test]
    fn test_decode_surge_proxy_list_protocol() {
        let cases = [
            (
                "aa = http, a.com, 114, always-use-connect=true",
                ProxyProtocolType::Http(HttpProxy {
                    username: ByteBuf::default(),
                    password: ByteBuf::default(),
                }),
            ),
            (
                "aa = https, a.com, 114, user, pass",
                ProxyProtocolType::Http(HttpProxy {
                    username: ByteBuf::from("user"),
                    password: ByteBuf::from("pass"),
                }),
            ),
            (
                "aa = socks5, a.com, 114, user, pass",
                ProxyProtocolType::Socks5(Socks5Proxy {
                    username: ByteBuf::from("user"),
                    password: ByteBuf::from("pass"),
                }),
            ),
            (
                "aa = socks5-tls, a.com, 114",
                ProxyProtocolType::Socks5(Socks5Proxy {
                    username: ByteBuf::default(),
                    password: ByteBuf::default(),
                }),
            ),
            (
                "aa = ss, a.com, 114, encrypt-method=aes-256-cfb, password=abc",
                ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                    cipher: SupportedCipher::Aes256Cfb,
                    password: ByteBuf::from("abc"),
                }),
            ),
            (
                "aa = trojan, a.com, 114, password=abc",
                ProxyProtocolType::Trojan(TrojanProxy {
                    password: ByteBuf::from("abc"),
                }),
            ),
            (
                "aa = vmess, a.com, 114, username=22222222-3333-4444-5555-666666666666, password=def",
                ProxyProtocolType::VMess(VMessProxy {
                    user_id: uuid!("22222222-3333-4444-5555-666666666666"),
                    security: SupportedSecurity::Auto,
                    alter_id: 1,
                }),
            ),
            (
                "aa = vmess, a.com, 114, username=22222222-3333-4444-5555-666666666666, password=def, vmess-aead=true, encrypt-method=aes-128-gcm",
                ProxyProtocolType::VMess(VMessProxy {
                    user_id: uuid!("22222222-3333-4444-5555-666666666666"),
                    security: SupportedSecurity::Aes128Gcm,
                    alter_id: 0,
                }),
            )
        ];
        for (data, expected_protocol) in cases {
            let mut sub = decode_surge_proxy_list(data.as_bytes()).unwrap();
            let proxy = sub.proxies.pop().expect(data).legs.pop().unwrap().protocol;
            assert_eq!(proxy, expected_protocol, "{data}");
        }
    }

    #[test]
    fn test_decode_surge_proxy_list_invalid() {
        let cases = [
            "aa = ss",
            "aa = ss, a.com",
            "aa = ss, a.com, 114514",
            "aa = ss, a.com, 114, encrypt-method=aes-nya, password=abc",
            "aa = vmess, a.com, 114, username=22222222-3333-4444-5555-666666666666, password=def, encrypt-method=aes-nya",
            "aa = vmess, a.com, 114, username=not-a-uuid, password=def",
            "aa = ??",
            "aa = http, a.com, 114, extra=param",
        ];
        for data in cases {
            let sub = decode_surge_proxy_list(data.as_bytes()).unwrap();
            assert!(sub.proxies.is_empty(), "{data}");
        }
    }

    #[test]
    fn test_decode_surge_proxy_list_chain() {
        let data = b"
            aa = http, a.com, 114, underlying-proxy=bb
            bb = http, b.com, 114, underlying-proxy=cc
            cc = http, c.com, 114
            dd = http, d.com, 114, underlying-proxy=ee
            ee = http, d.com, 114, underlying-proxy=??
        ";
        let sub = decode_surge_proxy_list(data).unwrap();
        let protocol = ProxyProtocolType::Http(HttpProxy::default());
        let aa_dest = DestinationAddr {
            host: HostName::from_domain_name("a.com".into()).unwrap(),
            port: 114,
        };
        let bb_dest = DestinationAddr {
            host: HostName::from_domain_name("b.com".into()).unwrap(),
            port: 114,
        };
        let cc_dest = DestinationAddr {
            host: HostName::from_domain_name("c.com".into()).unwrap(),
            port: 114,
        };
        assert_eq!(
            sub,
            Subscription {
                proxies: vec![
                    Proxy {
                        name: "aa".into(),
                        legs: vec![
                            ProxyLeg {
                                protocol: protocol.clone(),
                                dest: cc_dest.clone(),
                                obfs: None,
                                tls: None,
                            },
                            ProxyLeg {
                                protocol: protocol.clone(),
                                dest: bb_dest.clone(),
                                obfs: None,
                                tls: None,
                            },
                            ProxyLeg {
                                protocol: protocol.clone(),
                                dest: aa_dest,
                                obfs: None,
                                tls: None,
                            }
                        ],
                        udp_supported: false,
                    },
                    Proxy {
                        name: "bb".into(),
                        legs: vec![
                            ProxyLeg {
                                protocol: protocol.clone(),
                                dest: cc_dest.clone(),
                                obfs: None,
                                tls: None,
                            },
                            ProxyLeg {
                                protocol: protocol.clone(),
                                dest: bb_dest,
                                obfs: None,
                                tls: None,
                            }
                        ],
                        udp_supported: false,
                    },
                    Proxy {
                        name: "cc".into(),
                        legs: vec![ProxyLeg {
                            protocol,
                            dest: cc_dest,
                            obfs: None,
                            tls: None,
                        }],
                        udp_supported: false,
                    }
                ]
            }
        );
    }
}
