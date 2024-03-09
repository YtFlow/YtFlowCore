use ciborium::cbor;
use serde_bytes::ByteBuf;
use thiserror::Error;

use ytflow::flow::DestinationAddr;
use ytflow::plugin::dyn_outbound::config::v1::{
    Plugin as DynOutboundV1Plugin, Proxy as DynOutboundV1Proxy,
};

use crate::proxy::obfs::ProxyObfsType;
use crate::proxy::protocol::ProxyProtocolType;
use crate::proxy::tls::ProxyTlsLayer;
use crate::proxy::{Proxy, ProxyLeg};

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ComposeError {
    #[error("proxy contains no leg")]
    NoLeg,
}

pub type ComposeResult<T> = Result<T, ComposeError>;

fn to_cbor(value: Result<ciborium::Value, ciborium::value::Error>) -> ByteBuf {
    let buf = Vec::with_capacity(128);
    let value = value.expect("cannot encode cbor");
    let buf = cbor4ii::serde::to_vec(buf, &value).expect("cannot serialize cbor");
    ByteBuf::from(buf)
}

fn encode_tls(
    tls: &ProxyTlsLayer,
    plugin_name: impl Into<String>,
    next: &str,
) -> DynOutboundV1Plugin {
    DynOutboundV1Plugin {
        name: plugin_name.into(),
        plugin: "tls-client".into(),
        plugin_version: 0,
        param: to_cbor(cbor!({
            "sni" => tls.sni.as_deref(),
            "alpn" => &*tls.alpn,
            "skip_cert_check" => tls.skip_cert_check,
            "next" => next,
        })),
    }
}

fn encode_obfs(
    obfs: &ProxyObfsType,
    plugin_name: impl Into<String>,
    next: &str,
) -> DynOutboundV1Plugin {
    match obfs {
        ProxyObfsType::HttpObfs(http) => DynOutboundV1Plugin {
            name: plugin_name.into(),
            plugin: "http-obfs-client".into(),
            plugin_version: 0,
            param: to_cbor(cbor!({
                "host" => &*http.host,
                "path" => &*http.path,
                "next" => next,
            })),
        },
        ProxyObfsType::TlsObfs(tls) => DynOutboundV1Plugin {
            name: plugin_name.into(),
            plugin: "tls-obfs-client".into(),
            plugin_version: 0,
            param: to_cbor(cbor!({
                "host" => &*tls.host,
                "next" => next,
            })),
        },
        ProxyObfsType::WebSocket(ws) => DynOutboundV1Plugin {
            name: plugin_name.into(),
            plugin: "ws-client".into(),
            plugin_version: 0,
            param: to_cbor(cbor!({
                "host" => ws.host.as_deref(),
                "path" => &*ws.path,
                "headers" => &ws.headers,
                "next" => next,
            })),
        },
    }
}

fn encode_redir(
    dest: &DestinationAddr,
    plugin_name: impl Into<String>,
    tcp_next: &str,
    udp_next: &str,
) -> DynOutboundV1Plugin {
    DynOutboundV1Plugin {
        name: plugin_name.into(),
        plugin: "redirect".into(),
        plugin_version: 0,
        param: to_cbor(cbor!({
            "dest" => dest,
            "tcp_next" => tcp_next,
            "udp_next" => udp_next,
        })),
    }
}

fn encode_protocol(
    protocol: &ProxyProtocolType,
    plugin_name: impl Into<String>,
    tcp_next: &str,
    udp_next: &str,
) -> DynOutboundV1Plugin {
    match protocol {
        ProxyProtocolType::Shadowsocks(ss) => DynOutboundV1Plugin {
            name: plugin_name.into(),
            plugin: "shadowsocks-client".into(),
            plugin_version: 0,
            param: to_cbor(cbor!({
                "cipher" => ss.cipher,
                "password" => &ss.password,
                "tcp_next" => tcp_next,
                "udp_next" => udp_next,
            })),
        },
        ProxyProtocolType::Trojan(trojan) => DynOutboundV1Plugin {
            name: plugin_name.into(),
            plugin: "trojan-client".into(),
            plugin_version: 0,
            param: to_cbor(cbor!({
                "password" => &trojan.password,
                "tls_next" => tcp_next,
            })),
        },
        ProxyProtocolType::Http(http) => DynOutboundV1Plugin {
            name: plugin_name.into(),
            plugin: "http-proxy-client".into(),
            plugin_version: 0,
            param: to_cbor(cbor!({
                "user" => &http.username,
                "pass" => &http.password,
                "tcp_next" => tcp_next,
            })),
        },
        ProxyProtocolType::Socks5(socks5) => DynOutboundV1Plugin {
            name: plugin_name.into(),
            plugin: "socks5-client".into(),
            plugin_version: 0,
            param: to_cbor(cbor!({
                "user" => &socks5.username,
                "pass" => &socks5.password,
                "tcp_next" => tcp_next,
                "udp_next" => udp_next,
            })),
        },
        ProxyProtocolType::VMess(vmess) => DynOutboundV1Plugin {
            name: plugin_name.into(),
            plugin: "vmess-client".into(),
            plugin_version: 0,
            param: to_cbor(cbor!({
                "user_id" => vmess.user_id,
                "alter_id" => vmess.alter_id,
                "security" => vmess.security,
                "tcp_next" => tcp_next,
            })),
        },
    }
}

fn compose_single_leg(leg: &ProxyLeg) -> DynOutboundV1Proxy {
    let mut tcp_outbound = "$out.tcp";
    let tls = leg.tls.as_ref().map(|tls| {
        let p = encode_tls(tls, "t", tcp_outbound);
        tcp_outbound = "t.tcp";
        p
    });
    let obfs = leg.obfs.as_ref().map(|obfs| {
        let p = encode_obfs(obfs, "o", tcp_outbound);
        tcp_outbound = "o.tcp";
        p
    });
    let redir = encode_redir(&leg.dest, "r", tcp_outbound, "$out.udp");
    tcp_outbound = "r.tcp";
    let main_protocol = encode_protocol(&leg.protocol, "p", tcp_outbound, "r.udp");
    tcp_outbound = "p.tcp";

    DynOutboundV1Proxy {
        tcp_entry: tcp_outbound.into(),
        udp_entry: leg.protocol.provide_udp().then(|| "p.udp".into()),
        plugins: tls
            .into_iter()
            .chain(obfs)
            .chain(Some(redir))
            .chain(Some(main_protocol))
            .collect(),
    }
}

fn compose_multiple_legs(legs: &[ProxyLeg]) -> DynOutboundV1Proxy {
    let (mut tcp_outbound, mut udp_outbound) = ("$out.tcp".to_string(), "$out.udp".to_string());
    let plugins = legs
        .into_iter()
        .enumerate()
        .map(|(idx, leg)| (idx + 1, leg))
        .flat_map(|(idx, leg)| {
            let tls = leg.tls.as_ref().map(|tls| {
                let plugin_name = format!("t{}", idx);
                let p = encode_tls(tls, &plugin_name, &tcp_outbound);
                tcp_outbound = plugin_name + ".tcp";
                p
            });
            let obfs = leg.obfs.as_ref().map(|obfs| {
                let plugin_name = format!("o{}", idx);
                let p = encode_obfs(obfs, &plugin_name, &tcp_outbound);
                tcp_outbound = plugin_name + ".tcp";
                p
            });
            let mut plugin_name = format!("r{}", idx);
            let redir = encode_redir(&leg.dest, &plugin_name, &tcp_outbound, &udp_outbound);
            tcp_outbound = plugin_name.clone() + ".tcp";
            let main_protocol = encode_protocol(
                &leg.protocol,
                format!("p{}", idx),
                &tcp_outbound,
                &(plugin_name + ".udp"),
            );
            plugin_name = format!("p{}", idx);
            udp_outbound = if leg.protocol.provide_udp() {
                plugin_name.clone() + ".udp"
            } else {
                "$null.udp".into()
            };
            tcp_outbound = plugin_name + ".tcp";
            tls.into_iter()
                .chain(obfs)
                .chain(Some(redir))
                .chain(Some(main_protocol))
        })
        .collect();
    DynOutboundV1Proxy {
        tcp_entry: tcp_outbound,
        udp_entry: Some(udp_outbound).filter(|u| u != "$null.udp"),
        plugins,
    }
}

pub fn compose_data_proxy(proxy: &Proxy) -> ComposeResult<Vec<u8>> {
    let mut composed = match &*proxy.legs {
        [] => return Err(ComposeError::NoLeg),
        [leg] => compose_single_leg(leg),
        legs => compose_multiple_legs(legs),
    };
    if !proxy.udp_supported {
        composed.udp_entry = None;
    }
    let buf =
        cbor4ii::serde::to_vec(Vec::with_capacity(512), &composed).expect("Cannot serialize proxy");
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ciborium::Value;
    use ytflow::{flow::HostName, plugin::shadowsocks::SupportedCipher};

    use crate::proxy::{obfs::HttpObfsObfs, protocol::ShadowsocksProxy};

    use super::*;

    fn deserialize_plugin_param(data: &[u8]) -> BTreeMap<String, Value> {
        cbor4ii::serde::from_slice(data).unwrap()
    }
    fn find_plugin_param(proxy: &DynOutboundV1Proxy, plugin_name: &str) -> BTreeMap<String, Value> {
        let plugin = proxy
            .plugins
            .iter()
            .find(|p| p.name == plugin_name)
            .expect(&format!("{} not found", plugin_name));
        deserialize_plugin_param(&plugin.param)
    }
    fn assert_plugin(
        actual_plugin: &DynOutboundV1Plugin,
        expected_plugin: &DynOutboundV1Plugin,
        expected_data: Result<Value, ciborium::value::Error>,
        desc: &str,
    ) {
        assert_eq!(actual_plugin.name, expected_plugin.name);
        assert_eq!(
            actual_plugin.plugin, expected_plugin.plugin,
            "{} {}",
            &expected_plugin.name, desc
        );
        assert_eq!(
            actual_plugin.plugin_version, expected_plugin.plugin_version,
            "{} {}",
            &expected_plugin.name, desc
        );
        assert_eq!(
            cbor4ii::serde::from_slice::<Value>(&actual_plugin.param).unwrap(),
            expected_data.unwrap(),
            "{} {}",
            &expected_plugin.name,
            desc
        );
    }

    #[test]
    fn test_compose_data_proxy_no_leg() {
        let proxy = Proxy {
            name: "test".into(),
            legs: vec![],
            udp_supported: false,
        };
        assert_eq!(compose_data_proxy(&proxy), Err(ComposeError::NoLeg));
    }

    #[test]
    fn test_compose_data_proxy_one_leg_only_protocol() {
        let proxy = Proxy {
            name: "test".into(),
            legs: vec![ProxyLeg {
                protocol: ProxyProtocolType::Http(Default::default()),
                dest: DestinationAddr {
                    host: HostName::from_domain_name("example.com".into()).unwrap(),
                    port: 443,
                },
                obfs: None,
                tls: None,
            }],
            udp_supported: true,
        };
        let data = compose_data_proxy(&proxy).unwrap();
        let proxy: DynOutboundV1Proxy = cbor4ii::serde::from_slice(&data).unwrap();
        assert_eq!(proxy.tcp_entry, "p.tcp");
        assert_eq!(proxy.udp_entry, None);
        assert_eq!(proxy.plugins.len(), 2);
        let redir = proxy.plugins.iter().find(|p| p.name == "r").unwrap();
        let protocol = proxy.plugins.iter().find(|p| p.name == "p").unwrap();
        assert_plugin(
            redir,
            &DynOutboundV1Plugin {
                name: "r".into(),
                plugin: "redirect".into(),
                plugin_version: 0,
                param: Default::default(),
            },
            cbor!({
              "dest" => DestinationAddr {
                   host: HostName::from_domain_name("example.com".into()).unwrap(),
                   port: 443,
              },
              "tcp_next" => "$out.tcp",
              "udp_next" => "$out.udp",
            }),
            "redir",
        );
        assert_plugin(
            protocol,
            &DynOutboundV1Plugin {
                name: "p".into(),
                plugin: "http-proxy-client".into(),
                plugin_version: 0,
                param: Default::default(),
            },
            cbor!({
              "user" => ByteBuf::default(),
              "pass" => ByteBuf::default(),
              "tcp_next" => "r.tcp",
            }),
            "protocol",
        );
    }

    #[test]
    fn test_compose_data_proxy_one_leg_protocol_tls() {
        let proxy = Proxy {
            name: "test".into(),
            legs: vec![ProxyLeg {
                protocol: ProxyProtocolType::Http(Default::default()),
                dest: DestinationAddr {
                    host: HostName::from_domain_name("example.com".into()).unwrap(),
                    port: 443,
                },
                obfs: None,
                tls: Some(Default::default()),
            }],
            udp_supported: false,
        };
        let data = compose_data_proxy(&proxy).unwrap();
        let proxy: DynOutboundV1Proxy = cbor4ii::serde::from_slice(&data).unwrap();
        assert_eq!(proxy.plugins.len(), 3);
        let tls = find_plugin_param(&proxy, "t");
        let redir = find_plugin_param(&proxy, "r");
        let protocol = find_plugin_param(&proxy, "p");

        assert_eq!(tls["next"], cbor!("$out.tcp").unwrap(), "tls");
        assert_eq!(redir["tcp_next"], cbor!("t.tcp").unwrap(), "redir");
        assert_eq!(protocol["tcp_next"], cbor!("r.tcp").unwrap(), "protocol");
    }
    #[test]
    fn test_compose_data_proxy_one_leg_protocol_obfs() {
        let proxy = Proxy {
            name: "test".into(),
            legs: vec![ProxyLeg {
                protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                    cipher: SupportedCipher::Aes128Gcm,
                    password: ByteBuf::from("password"),
                }),
                dest: DestinationAddr {
                    host: HostName::from_domain_name("example.com".into()).unwrap(),
                    port: 443,
                },
                obfs: Some(ProxyObfsType::HttpObfs(HttpObfsObfs {
                    host: "obfs.example.com".into(),
                    path: "/obfs".into(),
                })),
                tls: None,
            }],
            udp_supported: false,
        };
        let data = compose_data_proxy(&proxy).unwrap();
        let proxy: DynOutboundV1Proxy = cbor4ii::serde::from_slice(&data).unwrap();
        assert_eq!(proxy.plugins.len(), 3);
        assert_eq!(proxy.udp_entry, None);
        let obfs = find_plugin_param(&proxy, "o");
        let redir = find_plugin_param(&proxy, "r");
        let protocol = find_plugin_param(&proxy, "p");

        assert_eq!(obfs["next"], cbor!("$out.tcp").unwrap(), "obfs");
        assert_eq!(redir["tcp_next"], cbor!("o.tcp").unwrap(), "redir");
        assert_eq!(redir["udp_next"], cbor!("$out.udp").unwrap(), "redir");
        assert_eq!(protocol["tcp_next"], cbor!("r.tcp").unwrap(), "protocol");
        assert_eq!(protocol["udp_next"], cbor!("r.udp").unwrap(), "protocol");
    }
    #[test]
    fn test_compose_data_proxy_one_leg_protocol_obfs_tls() {
        let proxy = Proxy {
            name: "test".into(),
            legs: vec![ProxyLeg {
                protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                    cipher: SupportedCipher::Aes128Gcm,
                    password: ByteBuf::from("password"),
                }),
                dest: DestinationAddr {
                    host: HostName::from_domain_name("example.com".into()).unwrap(),
                    port: 443,
                },
                obfs: Some(ProxyObfsType::HttpObfs(HttpObfsObfs {
                    host: "obfs.example.com".into(),
                    path: "/obfs".into(),
                })),
                tls: Some(Default::default()),
            }],
            udp_supported: false,
        };
        let data = compose_data_proxy(&proxy).unwrap();
        let proxy: DynOutboundV1Proxy = cbor4ii::serde::from_slice(&data).unwrap();
        assert_eq!(proxy.plugins.len(), 4);
        let tls = find_plugin_param(&proxy, "t");
        let obfs = find_plugin_param(&proxy, "o");
        let redir = find_plugin_param(&proxy, "r");
        let protocol = find_plugin_param(&proxy, "p");

        assert_eq!(tls["next"], cbor!("$out.tcp").unwrap(), "tls");
        assert_eq!(obfs["next"], cbor!("t.tcp").unwrap(), "obfs");
        assert_eq!(redir["tcp_next"], cbor!("o.tcp").unwrap(), "redir");
        assert_eq!(redir["udp_next"], cbor!("$out.udp").unwrap(), "redir");
        assert_eq!(protocol["tcp_next"], cbor!("r.tcp").unwrap(), "protocol");
        assert_eq!(protocol["udp_next"], cbor!("r.udp").unwrap(), "protocol");
    }
    #[test]
    fn test_compose_data_proxy_4legs() {
        let proxy = Proxy {
            name: "test".into(),
            legs: vec![
                ProxyLeg {
                    protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                        cipher: SupportedCipher::Aes128Gcm,
                        password: ByteBuf::from("password"),
                    }),
                    dest: DestinationAddr {
                        host: HostName::from_domain_name("example.com".into()).unwrap(),
                        port: 443,
                    },
                    obfs: Some(ProxyObfsType::HttpObfs(HttpObfsObfs {
                        host: "obfs.example.com".into(),
                        path: "/obfs".into(),
                    })),
                    tls: Some(Default::default()),
                },
                ProxyLeg {
                    protocol: ProxyProtocolType::Http(Default::default()),
                    dest: DestinationAddr {
                        host: HostName::from_domain_name("example.com".into()).unwrap(),
                        port: 443,
                    },
                    obfs: None,
                    tls: Some(Default::default()),
                },
                ProxyLeg {
                    protocol: ProxyProtocolType::Http(Default::default()),
                    dest: DestinationAddr {
                        host: HostName::from_domain_name("example.com".into()).unwrap(),
                        port: 443,
                    },
                    obfs: Some(ProxyObfsType::HttpObfs(HttpObfsObfs {
                        host: "obfs.example.com".into(),
                        path: "/obfs".into(),
                    })),
                    tls: None,
                },
                ProxyLeg {
                    protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                        cipher: SupportedCipher::Aes128Gcm,
                        password: ByteBuf::from("password"),
                    }),
                    dest: DestinationAddr {
                        host: HostName::from_domain_name("example.com".into()).unwrap(),
                        port: 443,
                    },
                    obfs: None,
                    tls: None,
                },
            ],
            udp_supported: true,
        };
        let data = compose_data_proxy(&proxy).unwrap();
        let proxy: DynOutboundV1Proxy = cbor4ii::serde::from_slice(&data).unwrap();
        assert_eq!(proxy.tcp_entry, "p4.tcp");
        assert_eq!(proxy.udp_entry, Some("p4.udp".into()));
        assert_eq!(proxy.plugins.len(), 12);
        let tls1 = find_plugin_param(&proxy, "t1");
        let obfs1 = find_plugin_param(&proxy, "o1");
        let redir1 = find_plugin_param(&proxy, "r1");
        let protocol1 = find_plugin_param(&proxy, "p1");
        assert_eq!(tls1["next"], cbor!("$out.tcp").unwrap(), "tls1");
        assert_eq!(obfs1["next"], cbor!("t1.tcp").unwrap(), "obfs1");
        assert_eq!(redir1["tcp_next"], cbor!("o1.tcp").unwrap(), "redir1");
        assert_eq!(redir1["udp_next"], cbor!("$out.udp").unwrap(), "redir1");
        assert_eq!(protocol1["tcp_next"], cbor!("r1.tcp").unwrap(), "protocol1");
        assert_eq!(protocol1["udp_next"], cbor!("r1.udp").unwrap(), "protocol1");
        let tls2 = find_plugin_param(&proxy, "t2");
        let redir2 = find_plugin_param(&proxy, "r2");
        let protocol2 = find_plugin_param(&proxy, "p2");
        assert_eq!(tls2["next"], cbor!("p1.tcp").unwrap(), "tls2");
        assert_eq!(redir2["tcp_next"], cbor!("t2.tcp").unwrap(), "redir2");
        assert_eq!(protocol2["tcp_next"], cbor!("r2.tcp").unwrap(), "protocol2");
        let obfs3 = find_plugin_param(&proxy, "o3");
        let redir3 = find_plugin_param(&proxy, "r3");
        let protocol3 = find_plugin_param(&proxy, "p3");
        assert_eq!(obfs3["next"], cbor!("p2.tcp").unwrap(), "obfs3");
        assert_eq!(redir3["tcp_next"], cbor!("o3.tcp").unwrap(), "redir3");
        assert_eq!(protocol3["tcp_next"], cbor!("r3.tcp").unwrap(), "protocol3");
        let redir4 = find_plugin_param(&proxy, "r4");
        let protocol4 = find_plugin_param(&proxy, "p4");
        assert_eq!(redir4["tcp_next"], cbor!("p3.tcp").unwrap(), "redir4");
        assert_eq!(redir4["udp_next"], cbor!("$null.udp").unwrap(), "redir4");
        assert_eq!(protocol4["tcp_next"], cbor!("r4.tcp").unwrap(), "protocol4");
    }
}
