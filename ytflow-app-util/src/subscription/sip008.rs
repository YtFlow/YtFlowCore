use std::borrow::Cow;

use serde::Deserialize;
use serde_bytes::ByteBuf;

use ytflow::config::plugin::parse_supported_cipher;
use ytflow::flow::{DestinationAddr, HostName};

use super::decode::{DecodeError, DecodeResult};
use crate::proxy::protocol::{ProxyProtocolType, ShadowsocksProxy};
use crate::proxy::{Proxy, ProxyLeg};
use crate::share_link::shadowsocks::decode_shadowsocks_plugin_opts;
use crate::subscription::{Subscription, SubscriptionFormat};

#[derive(Debug, Clone, Deserialize)]
struct Sip008Extended<'a> {
    version: u8,
    #[serde(borrow)]
    servers: Vec<Sip008Server<'a>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum Sip008<'a> {
    FullFormat(#[serde(borrow)] Sip008Extended<'a>),
    BasicFormat(#[serde(borrow)] Vec<Sip008Server<'a>>),
}

#[derive(Debug, Clone, Deserialize)]
struct Sip008Server<'a> {
    remarks: Option<String>,
    server: String,
    server_port: u16,
    method: &'a str,
    password: String,
    #[serde(default)]
    plugin: &'a str,
    #[serde(default)]
    plugin_opts: Cow<'a, str>,
    // Custom fields are allowed.
    // https://shadowsocks.org/doc/sip008.html
}

impl SubscriptionFormat<'static> {
    pub const SIP008: Self = SubscriptionFormat(b"sip008\0");
}

pub fn decode_sip008(data: &[u8]) -> DecodeResult<Subscription> {
    let sip008: Sip008 = serde_json::from_slice(data).map_err(|_| DecodeError::InvalidEncoding)?;
    let servers = match sip008 {
        Sip008::FullFormat(Sip008Extended { version, servers }) => {
            if version != 1 {
                return Err(DecodeError::UnknownValue("version"));
            }
            servers
        }
        Sip008::BasicFormat(servers) => servers,
    };

    let servers = servers
        .into_iter()
        .filter_map(|s| {
            let dest = DestinationAddr {
                host: HostName::from_domain_name(s.server).ok()?,
                port: s.server_port,
            };
            let name = s.remarks.unwrap_or_else(|| dest.to_string());
            let mut leg = ProxyLeg {
                protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                    cipher: parse_supported_cipher(s.method.as_bytes())?,
                    password: ByteBuf::from(s.password),
                }),
                dest,
                obfs: None,
                tls: None,
            };
            decode_shadowsocks_plugin_opts(s.plugin, &s.plugin_opts, &mut leg).ok()?;
            Some(Proxy {
                name,
                legs: vec![leg],
                udp_supported: true,
            })
        })
        .collect();

    Ok(Subscription { proxies: servers })
}

#[cfg(test)]
mod tests {
    use ytflow::plugin::shadowsocks::SupportedCipher;

    use crate::proxy::obfs::{ProxyObfsType, TlsObfsObfs};

    use super::*;

    #[test]
    fn test_decode_sip008_server_only() {
        let data = r#"[
            {
                "remarks": "server1",
                "server": "example.com",
                "server_port": 443,
                "method": "aes-256-gcm",
                "password": "password1"
            },
            {
                "remarks": "server2",
                "server": "example.net",
                "server_port": 443,
                "method": "chacha20-ietf-poly1305",
                "password": "password2"
            }
        ]"#;
        let sub = decode_sip008(data.as_bytes()).unwrap();
        assert_eq!(
            sub.proxies,
            vec![
                Proxy {
                    name: "server1".into(),
                    legs: vec![ProxyLeg {
                        protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                            cipher: SupportedCipher::Aes256Gcm,
                            password: ByteBuf::from("password1"),
                        }),
                        dest: DestinationAddr {
                            host: HostName::from_domain_name("example.com".into()).unwrap(),
                            port: 443,
                        },
                        obfs: None,
                        tls: None,
                    }],
                    udp_supported: true,
                },
                Proxy {
                    name: "server2".into(),
                    legs: vec![ProxyLeg {
                        protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                            cipher: SupportedCipher::Chacha20IetfPoly1305,
                            password: ByteBuf::from("password2"),
                        }),
                        dest: DestinationAddr {
                            host: HostName::from_domain_name("example.net".into()).unwrap(),
                            port: 443,
                        },
                        obfs: None,
                        tls: None,
                    }],
                    udp_supported: true,
                },
            ]
        );
    }

    #[test]
    fn test_decode_sip008_extended() {
        let data = r#"{
            "version": 1,
            "servers": [
                {
                    "remarks": "server1",
                    "server": "example.com",
                    "server_port": 443,
                    "method": "aes-256-gcm",
                    "password": "password1"
                },
                {
                    "remarks": "server2🔞",
                    "server": "example.net",
                    "server_port": 443,
                    "method": "chacha20-ietf-poly1305",
                    "password": "password2",
                    "plugin": "obfs-local",
                    "plugin_opts": "obfs=tls"
                }
            ]
        }"#;
        let sub = decode_sip008(data.as_bytes()).unwrap();
        assert_eq!(
            sub.proxies,
            vec![
                Proxy {
                    name: "server1".into(),
                    legs: vec![ProxyLeg {
                        protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                            cipher: SupportedCipher::Aes256Gcm,
                            password: ByteBuf::from("password1"),
                        }),
                        dest: DestinationAddr {
                            host: HostName::from_domain_name("example.com".into()).unwrap(),
                            port: 443,
                        },
                        obfs: None,
                        tls: None,
                    }],
                    udp_supported: true,
                },
                Proxy {
                    name: "server2🔞".into(),
                    legs: vec![ProxyLeg {
                        protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                            cipher: SupportedCipher::Chacha20IetfPoly1305,
                            password: ByteBuf::from("password2"),
                        }),
                        dest: DestinationAddr {
                            host: HostName::from_domain_name("example.net".into()).unwrap(),
                            port: 443,
                        },
                        obfs: Some(ProxyObfsType::TlsObfs(TlsObfsObfs {
                            host: "example.net".into()
                        })),
                        tls: None
                    }],
                    udp_supported: true,
                },
            ]
        );
    }

    #[test]
    fn test_decode_sip008_unknown_version() {
        let data = r#"{
            "version": 2,
            "servers": []
        }"#;
        let result = decode_sip008(data.as_bytes());
        assert_eq!(result.unwrap_err(), DecodeError::UnknownValue("version"));
    }

    #[test]
    fn test_decode_sip008_ignore_invalid_server() {
        let data = r#"[
            {
                "remarks": "InvalidServer",
                "server": "...",
                "server_port": 443,
                "method": "chacha20-ietf-poly1305",
                "password": "password2"
            },
            {
                "remarks": "InvalidPluginOpts",
                "server": "example.org",
                "server_port": 443,
                "method": "chacha20-ietf-poly1305",
                "password": "password3",
                "plugin": "obfs-nya",
                "plugin_opts": "obfs=tls"
            },
            {
                "remarks": "InvalidCipher",
                "server": "example.net",
                "server_port": 443,
                "method": "aes-114514-ctr",
                "password": "password4"
            },
            {
                "remarks": "Ok",
                "server": "example.com",
                "server_port": 443,
                "method": "aes-256-gcm",
                "password": "password1"
            }
        ]"#;
        let sub = decode_sip008(data.as_bytes()).unwrap();
        assert_eq!(sub.proxies.len(), 1);
        assert_eq!(sub.proxies[0].name, "Ok");
    }
}
