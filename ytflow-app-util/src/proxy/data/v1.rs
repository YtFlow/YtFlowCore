pub(super) mod analyzer;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ciborium::{cbor, Value};
    use serde_bytes::ByteBuf;
    use uuid::uuid;

    use ytflow::flow::DestinationAddr;
    use ytflow::plugin::dyn_outbound::config::v1::{
        Plugin as DynOutboundV1Plugin, Proxy as DynOutboundV1Proxy,
    };
    use ytflow::plugin::vmess::SupportedSecurity;
    use ytflow::{flow::HostName, plugin::shadowsocks::SupportedCipher};

    use super::super::analyze_data_proxy;
    use super::super::compose_data_proxy_v1 as compose_data_proxy;
    use crate::proxy::data::ComposeError;
    use crate::proxy::obfs::{HttpObfsObfs, ProxyObfsType, TlsObfsObfs, WebSocketObfs};
    use crate::proxy::protocol::{
        ProxyProtocolType, ShadowsocksProxy, Socks5Proxy, TrojanProxy, VMessProxy,
    };
    use crate::proxy::{Proxy, ProxyLeg};

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
            "{} {desc}",
            &expected_plugin.name
        );
        assert_eq!(
            actual_plugin.plugin_version, expected_plugin.plugin_version,
            "{} {desc}",
            &expected_plugin.name
        );
        assert_eq!(
            cbor4ii::serde::from_slice::<Value>(&actual_plugin.param).unwrap(),
            expected_data.unwrap(),
            "{} {desc}",
            &expected_plugin.name
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
    fn test_roundtrip_data_proxy_one_leg_only_protocol() {
        let mut proxy = Proxy {
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
        let composed: DynOutboundV1Proxy = cbor4ii::serde::from_slice(&data).unwrap();
        assert_eq!(composed.tcp_entry, "p.tcp");
        assert_eq!(composed.udp_entry, None);
        assert_eq!(composed.plugins.len(), 2);
        let redir = composed.plugins.iter().find(|p| p.name == "r").unwrap();
        let protocol = composed.plugins.iter().find(|p| p.name == "p").unwrap();
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
        let analyzed = analyze_data_proxy("test".into(), &data, 0).unwrap();
        proxy.udp_supported = false;
        assert_eq!(analyzed, proxy);
    }

    #[test]
    fn test_roundtrip_data_proxy_one_leg_protocol_tls() {
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
        let composed: DynOutboundV1Proxy = cbor4ii::serde::from_slice(&data).unwrap();
        assert_eq!(composed.plugins.len(), 3);
        let tls = find_plugin_param(&composed, "t");
        let redir = find_plugin_param(&composed, "r");
        let protocol = find_plugin_param(&composed, "p");

        assert_eq!(tls["next"], cbor!("$out.tcp").unwrap(), "tls");
        assert_eq!(redir["tcp_next"], cbor!("t.tcp").unwrap(), "redir");
        assert_eq!(protocol["tcp_next"], cbor!("r.tcp").unwrap(), "protocol");
        let analyzed = analyze_data_proxy("test".into(), &data, 0).unwrap();
        assert_eq!(analyzed, proxy);
    }
    #[test]
    fn test_roundtrip_data_proxy_one_leg_protocol_obfs() {
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
        let composed: DynOutboundV1Proxy = cbor4ii::serde::from_slice(&data).unwrap();
        assert_eq!(composed.plugins.len(), 3);
        assert_eq!(composed.udp_entry, None);
        let obfs = find_plugin_param(&composed, "o");
        let redir = find_plugin_param(&composed, "r");
        let protocol = find_plugin_param(&composed, "p");

        assert_eq!(obfs["next"], cbor!("$out.tcp").unwrap(), "obfs");
        assert_eq!(redir["tcp_next"], cbor!("o.tcp").unwrap(), "redir");
        assert_eq!(redir["udp_next"], cbor!("$out.udp").unwrap(), "redir");
        assert_eq!(protocol["tcp_next"], cbor!("r.tcp").unwrap(), "protocol");
        assert_eq!(protocol["udp_next"], cbor!("r.udp").unwrap(), "protocol");
        let analyzed = analyze_data_proxy("test".into(), &data, 0).unwrap();
        assert_eq!(analyzed, proxy);
    }
    #[test]
    fn test_roundtrip_data_proxy_one_leg_protocol_obfs_tls() {
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
        let composed: DynOutboundV1Proxy = cbor4ii::serde::from_slice(&data).unwrap();
        assert_eq!(composed.plugins.len(), 4);
        let tls = find_plugin_param(&composed, "t");
        let obfs = find_plugin_param(&composed, "o");
        let redir = find_plugin_param(&composed, "r");
        let protocol = find_plugin_param(&composed, "p");

        assert_eq!(tls["next"], cbor!("$out.tcp").unwrap(), "tls");
        assert_eq!(obfs["next"], cbor!("t.tcp").unwrap(), "obfs");
        assert_eq!(redir["tcp_next"], cbor!("o.tcp").unwrap(), "redir");
        assert_eq!(redir["udp_next"], cbor!("$out.udp").unwrap(), "redir");
        assert_eq!(protocol["tcp_next"], cbor!("r.tcp").unwrap(), "protocol");
        assert_eq!(protocol["udp_next"], cbor!("r.udp").unwrap(), "protocol");
        let analyzed = analyze_data_proxy("test".into(), &data, 0).unwrap();
        assert_eq!(analyzed, proxy);
    }
    #[test]
    fn test_roundtrip_data_proxy_4legs() {
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
        let composed: DynOutboundV1Proxy = cbor4ii::serde::from_slice(&data).unwrap();
        assert_eq!(composed.tcp_entry, "p4.tcp");
        assert_eq!(composed.udp_entry, Some("p4.udp".into()));
        assert_eq!(composed.plugins.len(), 12);
        let tls1 = find_plugin_param(&composed, "t1");
        let obfs1 = find_plugin_param(&composed, "o1");
        let redir1 = find_plugin_param(&composed, "r1");
        let protocol1 = find_plugin_param(&composed, "p1");
        assert_eq!(tls1["next"], cbor!("$out.tcp").unwrap(), "tls1");
        assert_eq!(obfs1["next"], cbor!("t1.tcp").unwrap(), "obfs1");
        assert_eq!(redir1["tcp_next"], cbor!("o1.tcp").unwrap(), "redir1");
        assert_eq!(redir1["udp_next"], cbor!("$out.udp").unwrap(), "redir1");
        assert_eq!(protocol1["tcp_next"], cbor!("r1.tcp").unwrap(), "protocol1");
        assert_eq!(protocol1["udp_next"], cbor!("r1.udp").unwrap(), "protocol1");
        let tls2 = find_plugin_param(&composed, "t2");
        let redir2 = find_plugin_param(&composed, "r2");
        let protocol2 = find_plugin_param(&composed, "p2");
        assert_eq!(tls2["next"], cbor!("p1.tcp").unwrap(), "tls2");
        assert_eq!(redir2["tcp_next"], cbor!("t2.tcp").unwrap(), "redir2");
        assert_eq!(protocol2["tcp_next"], cbor!("r2.tcp").unwrap(), "protocol2");
        let obfs3 = find_plugin_param(&composed, "o3");
        let redir3 = find_plugin_param(&composed, "r3");
        let protocol3 = find_plugin_param(&composed, "p3");
        assert_eq!(obfs3["next"], cbor!("p2.tcp").unwrap(), "obfs3");
        assert_eq!(redir3["tcp_next"], cbor!("o3.tcp").unwrap(), "redir3");
        assert_eq!(protocol3["tcp_next"], cbor!("r3.tcp").unwrap(), "protocol3");
        let redir4 = find_plugin_param(&composed, "r4");
        let protocol4 = find_plugin_param(&composed, "p4");
        assert_eq!(redir4["tcp_next"], cbor!("p3.tcp").unwrap(), "redir4");
        assert_eq!(redir4["udp_next"], cbor!("$null.udp").unwrap(), "redir4");
        assert_eq!(protocol4["tcp_next"], cbor!("r4.tcp").unwrap(), "protocol4");
        let analyzed = analyze_data_proxy("test".into(), &data, 0).unwrap();
        assert_eq!(analyzed, proxy);
    }

    #[test]
    fn test_roundtrip_data_proxy_protocols_obfses() {
        let dest = DestinationAddr {
            host: HostName::from_domain_name("example.com".into()).unwrap(),
            port: 443,
        };
        let proxy = Proxy {
            name: "test".into(),
            legs: vec![
                ProxyLeg {
                    protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                        cipher: SupportedCipher::Aes128Gcm,
                        password: ByteBuf::from("password"),
                    }),
                    dest: dest.clone(),
                    obfs: Some(ProxyObfsType::HttpObfs(HttpObfsObfs {
                        host: "obfs.example.com".into(),
                        path: "/obfs".into(),
                    })),
                    tls: None,
                },
                ProxyLeg {
                    protocol: ProxyProtocolType::Trojan(TrojanProxy {
                        password: ByteBuf::from("password"),
                    }),
                    dest: dest.clone(),
                    obfs: Some(ProxyObfsType::TlsObfs(TlsObfsObfs {
                        host: "obfs.example.com".into(),
                    })),
                    tls: Some(Default::default()),
                },
                ProxyLeg {
                    protocol: ProxyProtocolType::Http(Default::default()),
                    dest: dest.clone(),
                    obfs: Some(ProxyObfsType::WebSocket(WebSocketObfs {
                        host: None,
                        path: "/path".into(),
                        headers: [("X-Header".into(), "value".into())].into_iter().collect(),
                    })),
                    tls: None,
                },
                ProxyLeg {
                    protocol: ProxyProtocolType::Socks5(Socks5Proxy {
                        username: ByteBuf::from("username"),
                        password: ByteBuf::from("password"),
                    }),
                    dest: dest.clone(),
                    obfs: None,
                    tls: None,
                },
                ProxyLeg {
                    protocol: ProxyProtocolType::VMess(VMessProxy {
                        user_id: uuid!("b831381d-6324-4d53-ad4f-8cda48b30811"),
                        alter_id: 0,
                        security: SupportedSecurity::Aes128Gcm,
                    }),
                    dest: dest.clone(),
                    obfs: Some(ProxyObfsType::WebSocket(Default::default())),
                    tls: None,
                },
            ],
            udp_supported: true,
        };
        let data = compose_data_proxy(&proxy).unwrap();
        let analyzed = analyze_data_proxy("test".into(), &data, 0).unwrap();
        assert_eq!(analyzed, proxy);
    }
}
