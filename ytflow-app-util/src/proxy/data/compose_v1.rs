use ciborium::cbor;
use thiserror::Error;

use ytflow::flow::DestinationAddr;
use ytflow::plugin::dyn_outbound::config::v1::{
    Plugin as DynOutboundV1Plugin, Proxy as DynOutboundV1Proxy,
};

use crate::cbor::to_cbor;
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
                "method" => ss.cipher,
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
                "user_id" => vmess.user_id.to_string(),
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
