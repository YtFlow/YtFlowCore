use ciborium::{cbor, value::Value as CborValue};
use serde_bytes::{ByteBuf, Bytes};
use strum_macros::{Display, EnumIter};

use super::serialize_cbor;
use ytflow::{
    flow::{DestinationAddr, HostName},
    plugin::dyn_outbound::config::v1::{Plugin, Proxy},
};

const PLUGIN_NAME_MAIN_PROTOCOL: &str = "p";
const PLUGIN_NAME_REDIR: &str = "r";
const PLUGIN_NAME_OBFS: &str = "o";
const PLUGIN_NAME_TLS: &str = "t";
const ACCESS_POINT_MAIN_PROTOCOL_TCP: &str = "p.tcp";
const ACCESS_POINT_MAIN_PROTOCOL_UDP: &str = "p.udp";
const ACCESS_POINT_REDIR_TCP: &str = "r.tcp";
const ACCESS_POINT_REDIR_UDP: &str = "r.udp";
const ACCESS_POINT_OBFS_TCP: &str = "o.tcp";
const ACCESS_POINT_TLS_TCP: &str = "t.tcp";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, EnumIter)]
pub enum ProxyType {
    #[strum(serialize = "Shadowsocks")]
    Shadowsocks,
    #[strum(serialize = "Shadowsocks + HTTP obfs")]
    ShadowsocksHttpObfs,
    #[strum(serialize = "Shadowsocks + TLS obfs")]
    ShadowsocksTlsObfs,
    #[strum(serialize = "Trojan (via TLS)")]
    TrojanTls,
    #[strum(serialize = "HTTP (CONNECT)")]
    HttpConnect,
    #[strum(serialize = "SOCKS5")]
    Socks5,
}

fn gen_redirect(tcp_next: CborValue, udp_next: CborValue) -> Plugin {
    Plugin {
        name: PLUGIN_NAME_REDIR.into(),
        plugin: "redirect".into(),
        plugin_version: 0,
        param: ByteBuf::from(serialize_cbor(
            cbor!({
                "dest" => DestinationAddr {
                    host: HostName::DomainName("my.proxy.server.com.".into()),
                    port: 8388,
                },
                "tcp_next" => tcp_next,
                "udp_next" => udp_next,
            })
            .unwrap(),
        )),
    }
}

impl ProxyType {
    fn gen_main_protocol(self, tcp_next: CborValue, udp_next: CborValue) -> Plugin {
        match self {
            ProxyType::Shadowsocks
            | ProxyType::ShadowsocksHttpObfs
            | ProxyType::ShadowsocksTlsObfs => Plugin {
                name: PLUGIN_NAME_MAIN_PROTOCOL.into(),
                plugin: "shadowsocks-client".into(),
                plugin_version: 0,
                param: ByteBuf::from(serialize_cbor(
                    cbor!({
                        "method" => "aes-256-gcm",
                        "password" => Bytes::new(b"password"),
                        "tcp_next" => tcp_next,
                        "udp_next" => udp_next,
                    })
                    .unwrap(),
                )),
            },
            ProxyType::TrojanTls => Plugin {
                name: PLUGIN_NAME_MAIN_PROTOCOL.into(),
                plugin: "trojan-client".into(),
                plugin_version: 0,
                param: ByteBuf::from(serialize_cbor(
                    cbor!({
                        "password" => Bytes::new(b"password"),
                        "tls_next" => tcp_next,
                    })
                    .unwrap(),
                )),
            },
            ProxyType::HttpConnect => Plugin {
                name: PLUGIN_NAME_MAIN_PROTOCOL.into(),
                plugin: "http-proxy-client".into(),
                plugin_version: 0,
                param: ByteBuf::from(serialize_cbor(
                    cbor!({
                        "tcp_next" => tcp_next,
                    })
                    .unwrap(),
                )),
            },
            ProxyType::Socks5 => Plugin {
                name: PLUGIN_NAME_MAIN_PROTOCOL.into(),
                plugin: "socks5-client".into(),
                plugin_version: 0,
                param: ByteBuf::from(serialize_cbor(
                    cbor!({
                        "tcp_next" => tcp_next,
                        "udp_next" => udp_next,
                    })
                    .unwrap(),
                )),
            },
        }
    }
    fn gen_obfs(self, tcp_next: CborValue) -> Option<Plugin> {
        match self {
            ProxyType::ShadowsocksHttpObfs => Some(Plugin {
                name: PLUGIN_NAME_OBFS.into(),
                plugin: "http-obfs-client".into(),
                plugin_version: 0,
                param: ByteBuf::from(serialize_cbor(
                    cbor!({
                        "host" => "windowsupdate.microsoft.com",
                        "path" => "/",
                        "next" => tcp_next,
                    })
                    .unwrap(),
                )),
            }),
            ProxyType::ShadowsocksTlsObfs => Some(Plugin {
                name: PLUGIN_NAME_OBFS.into(),
                plugin: "tls-obfs-client".into(),
                plugin_version: 0,
                param: ByteBuf::from(serialize_cbor(
                    cbor!({
                        "host" => "windowsupdate.microsoft.com",
                        "next" => tcp_next,
                    })
                    .unwrap(),
                )),
            }),
            _ => None,
        }
    }
    fn gen_tls(self, tcp_next: CborValue) -> Option<Plugin> {
        match self {
            ProxyType::TrojanTls => Some(Plugin {
                name: PLUGIN_NAME_TLS.into(),
                plugin: "tls-client".into(),
                plugin_version: 0,
                param: ByteBuf::from(serialize_cbor(
                    cbor!({
                        "next" => tcp_next,
                    })
                    .unwrap(),
                )),
            }),
            _ => None,
        }
    }
    fn has_udp(&self) -> bool {
        !matches!(self, ProxyType::HttpConnect)
    }
    pub fn gen_default_proxy(self) -> Vec<u8> {
        let mut tcp_outbound = "$out.tcp";
        let mut udp_outbound = "$out.udp";
        let tls = self.gen_tls(tcp_outbound.into());
        if tls.is_some() {
            tcp_outbound = ACCESS_POINT_TLS_TCP;
        }
        let obfs = self.gen_obfs(tcp_outbound.into());
        if obfs.is_some() {
            tcp_outbound = ACCESS_POINT_OBFS_TCP;
        }
        let redir = gen_redirect(tcp_outbound.into(), udp_outbound.into());
        tcp_outbound = ACCESS_POINT_REDIR_TCP;
        udp_outbound = ACCESS_POINT_REDIR_UDP;
        let main_protocol = self.gen_main_protocol(tcp_outbound.into(), udp_outbound.into());
        let proxy = Proxy {
            tcp_entry: ACCESS_POINT_MAIN_PROTOCOL_TCP.into(),
            udp_entry: self
                .has_udp()
                .then(|| ACCESS_POINT_MAIN_PROTOCOL_UDP.into()),
            plugins: tls
                .into_iter()
                .chain(obfs)
                .chain(Some(redir))
                .chain(Some(main_protocol))
                .collect(),
        };
        let mut v = Vec::with_capacity(512);
        ciborium::ser::into_writer(&proxy, &mut v).expect("Cannot serialize proxy");
        v
    }
}
