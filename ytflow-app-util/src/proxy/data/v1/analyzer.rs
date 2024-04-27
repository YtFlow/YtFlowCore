use std::collections::{BTreeMap, HashMap};
use std::ops::{Deref, DerefMut};

use serde::Deserialize;
use serde_bytes::ByteBuf;
use ytflow::config::plugin::parse_supported_security;
use ytflow::config::HumanRepr;
use ytflow::flow::DestinationAddr;
use ytflow::plugin::dyn_outbound::config::v1::{
    Plugin as DynOutboundV1Plugin, Proxy as DynOutboundV1Proxy,
};
use ytflow::plugin::shadowsocks::SupportedCipher;

use crate::proxy::data::{AnalyzeError, AnalyzeResult};
use crate::proxy::obfs::{HttpObfsObfs, ProxyObfsType, TlsObfsObfs, WebSocketObfs};
use crate::proxy::protocol::{
    HttpProxy, ProxyProtocolType, ShadowsocksProxy, Socks5Proxy, TrojanProxy, VMessProxy,
};
use crate::proxy::tls::ProxyTlsLayer;
use crate::proxy::{Proxy, ProxyLeg};

#[derive(Debug)]
struct PluginMap<'p>(BTreeMap<&'p str, Option<&'p DynOutboundV1Plugin>>);

#[derive(Debug)]
struct Analyzer<'p> {
    name: String,
    is_udp_supported: bool,
    plugins: PluginMap<'p>,
    current_plugin: Option<&'p DynOutboundV1Plugin>,
    expect_next_udp: Option<bool>,
}

impl<'p> Deref for PluginMap<'p> {
    type Target = BTreeMap<&'p str, Option<&'p DynOutboundV1Plugin>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'p> DerefMut for PluginMap<'p> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'p> PluginMap<'p> {
    fn take_plugin(
        &mut self,
        name: &str,
        initiator: &str,
    ) -> AnalyzeResult<Option<&'p DynOutboundV1Plugin>> {
        if name == "$out" {
            return Ok(None);
        }
        let ret = self
            .get_mut(name)
            .ok_or_else(|| AnalyzeError::PluginNotFound(name.into(), initiator.into()))?
            .take()
            .ok_or(AnalyzeError::TooComplicated)?;
        if ret.plugin_version != 0 {
            return Err(AnalyzeError::InvalidPlugin(name.into()));
        }
        Ok(Some(ret))
    }
}

impl<'p> Analyzer<'p> {
    pub fn new(name: String, proxy: &'p DynOutboundV1Proxy) -> AnalyzeResult<Self> {
        let mut plugins = PluginMap(proxy.plugins.iter().map(|p| (&*p.name, Some(p))).collect());
        if plugins.len() != proxy.plugins.len() {
            for p in &proxy.plugins {
                if plugins.remove(&*p.name).is_none() {
                    return Err(AnalyzeError::DuplicateName(p.name.clone()));
                }
            }
            unreachable!("cannot find duplicated plugin name");
        }

        let entry_plugin = get_plugin_name_from_tcp_ap(&proxy.tcp_entry)?;
        if entry_plugin == "$null" {
            return Err(AnalyzeError::TooComplicated);
        }
        let udp_supported = if let Some(udp_ap) = &proxy.udp_entry {
            if get_plugin_name_from_udp_ap(&udp_ap)? != entry_plugin {
                return Err(AnalyzeError::TooComplicated);
            }
            true
        } else {
            false
        };
        let entry_plugin = plugins.take_plugin(entry_plugin, "$entry")?;

        Ok(Self {
            name,
            is_udp_supported: udp_supported,
            plugins,
            current_plugin: entry_plugin,
            expect_next_udp: udp_supported.then_some(true),
        })
    }

    pub fn analyze(mut self) -> AnalyzeResult<Proxy> {
        let mut legs = vec![];
        while let Some(leg) = self.extract_leg()? {
            legs.push(leg);
        }
        legs.reverse();

        if let Some(plugin) = self.plugins.values().find_map(|p| p.clone()) {
            return Err(AnalyzeError::UnusedPlugin(plugin.name.clone()));
        }

        Ok(Proxy {
            name: self.name,
            udp_supported: self.is_udp_supported,
            legs,
        })
    }

    fn extract_leg(&mut self) -> AnalyzeResult<Option<ProxyLeg>> {
        let Some(current_plugin) = self.current_plugin.clone() else {
            return Ok(None);
        };
        let (protocol, next_plugin_name) = Self::analyze_protocol(current_plugin)?;
        if let Some(expect_next_udp) = self.expect_next_udp {
            // TODO: too strict?
            if expect_next_udp != protocol.provide_udp() {
                return Err(AnalyzeError::UnexpectedUdpAccessPoint(
                    current_plugin.name.clone(),
                    expect_next_udp,
                ));
            }
        }
        let redir_plugin = self
            .plugins
            .take_plugin(&next_plugin_name, &current_plugin.name)?
            .ok_or(AnalyzeError::TooComplicated)?;
        let (dest, next_tcp_plugin_name, next_udp_plugin_name) =
            Self::analyze_redirect(redir_plugin)?;

        self.current_plugin = self
            .plugins
            .take_plugin(&next_tcp_plugin_name, &redir_plugin.name)?;
        let obfs = self.analyze_obfs()?;
        let tls = self.analyze_tls()?;

        if next_udp_plugin_name == "$null" {
            self.expect_next_udp = Some(false);
        } else {
            let next_plugin_name = self
                .current_plugin
                .as_ref()
                .map(|p| &*p.name)
                .unwrap_or("$out");
            if next_plugin_name != next_udp_plugin_name {
                return Err(AnalyzeError::TooComplicated);
            }
            self.expect_next_udp = Some(true);
        }
        Ok(Some(ProxyLeg {
            protocol,
            dest,
            obfs,
            tls,
        }))
    }

    fn analyze_protocol(
        plugin: &DynOutboundV1Plugin,
    ) -> AnalyzeResult<(ProxyProtocolType, String)> {
        let (protocol, tcp_dep, udp_dep) = match &*plugin.plugin {
            "socks5-client" => {
                #[derive(Deserialize)]
                struct Socks5ClientConfig<'a> {
                    tcp_next: &'a str,
                    udp_next: &'a str,
                    user: ByteBuf,
                    pass: ByteBuf,
                }
                let socks5: Socks5ClientConfig = deserialize_plugin_param(plugin)?;
                (
                    ProxyProtocolType::Socks5(Socks5Proxy {
                        username: socks5.user,
                        password: socks5.pass,
                    }),
                    socks5.tcp_next,
                    Some(socks5.udp_next),
                )
            }
            "http-proxy-client" => {
                #[derive(Deserialize)]
                struct HttpProxyConfig<'a> {
                    user: ByteBuf,
                    pass: ByteBuf,
                    tcp_next: &'a str,
                }
                let http_proxy: HttpProxyConfig = deserialize_plugin_param(plugin)?;
                (
                    ProxyProtocolType::Http(HttpProxy {
                        username: http_proxy.user,
                        password: http_proxy.pass,
                    }),
                    http_proxy.tcp_next,
                    None,
                )
            }
            "shadowsocks-client" => {
                #[derive(Deserialize)]
                struct ShadowsocksConfig<'a> {
                    method: SupportedCipher,
                    password: ByteBuf,
                    tcp_next: &'a str,
                    udp_next: &'a str,
                }
                let ss: ShadowsocksConfig = deserialize_plugin_param(plugin)?;
                (
                    ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                        cipher: ss.method,
                        password: ss.password,
                    }),
                    ss.tcp_next,
                    Some(ss.udp_next),
                )
            }
            "trojan-client" => {
                #[derive(Deserialize)]
                struct TrojanConfig<'a> {
                    password: ByteBuf,
                    tls_next: &'a str,
                }
                let trojan: TrojanConfig = deserialize_plugin_param(plugin)?;
                (
                    ProxyProtocolType::Trojan(TrojanProxy {
                        password: trojan.password,
                    }),
                    trojan.tls_next,
                    None,
                )
            }
            "vmess-client" => {
                #[derive(Deserialize)]
                struct VMessConfig<'a> {
                    user_id: HumanRepr<uuid::Uuid>,
                    #[serde(default)]
                    alter_id: u16,
                    #[serde(default = "default_security")]
                    security: &'a str,
                    tcp_next: &'a str,
                }
                fn default_security() -> &'static str {
                    "auto"
                }
                let vmess: VMessConfig = deserialize_plugin_param(plugin)?;
                (
                    ProxyProtocolType::VMess(VMessProxy {
                        user_id: vmess.user_id.inner,
                        alter_id: vmess.alter_id,
                        security: parse_supported_security(vmess.security.as_bytes())
                            .ok_or_else(|| AnalyzeError::InvalidPlugin(plugin.name.clone()))?,
                    }),
                    vmess.tcp_next,
                    None,
                )
            }
            _ => return Err(AnalyzeError::TooComplicated),
        };
        let tcp_dep_plugin = get_plugin_name_from_tcp_ap(&tcp_dep)?;
        ensure_non_special_plugin_name(tcp_dep)?;
        if let Some(udp_dep) = udp_dep {
            let udp_dep_plugin = get_plugin_name_from_udp_ap(&udp_dep)?;
            if tcp_dep_plugin != udp_dep_plugin {
                return Err(AnalyzeError::TooComplicated);
            }
        }
        Ok((protocol, tcp_dep_plugin.into()))
    }
    fn analyze_redirect(
        plugin: &DynOutboundV1Plugin,
    ) -> AnalyzeResult<(DestinationAddr, &str, &str)> {
        if plugin.plugin != "redirect" {
            return Err(AnalyzeError::TooComplicated);
        }
        #[derive(Debug, Clone, Deserialize)]
        struct Redirect<'a> {
            dest: DestinationAddr,
            tcp_next: &'a str,
            udp_next: &'a str,
        }
        let redirect: Redirect = deserialize_plugin_param(plugin)?;
        let tcp_next_plugin_name = get_plugin_name_from_tcp_ap(redirect.tcp_next)?;
        let udp_next_plugin_name = get_plugin_name_from_udp_ap(redirect.udp_next)?;
        Ok((redirect.dest, tcp_next_plugin_name, udp_next_plugin_name))
    }
    fn analyze_obfs(&mut self) -> AnalyzeResult<Option<ProxyObfsType>> {
        let Some(plugin) = self.current_plugin.clone() else {
            return Ok(None);
        };
        let next_tcp;
        let ret = match &*plugin.plugin {
            "http-obfs-client" => {
                #[derive(Deserialize)]
                struct HttpObfsClientConfig<'a> {
                    host: String,
                    path: String,
                    next: &'a str,
                }
                let obfs: HttpObfsClientConfig = deserialize_plugin_param(plugin)?;
                next_tcp = obfs.next;
                ProxyObfsType::HttpObfs(HttpObfsObfs {
                    host: obfs.host,
                    path: obfs.path,
                })
            }
            "tls-obfs-client" => {
                #[derive(Deserialize)]
                struct TlsObfsClientConfig<'a> {
                    host: String,
                    next: &'a str,
                }
                let obfs: TlsObfsClientConfig = deserialize_plugin_param(plugin)?;
                next_tcp = obfs.next;
                ProxyObfsType::TlsObfs(TlsObfsObfs { host: obfs.host })
            }
            "ws-client" => {
                #[derive(Deserialize)]
                struct WsClientFactory<'a> {
                    host: Option<String>,
                    #[serde(default = "default_path")]
                    path: String,
                    headers: HashMap<String, String>,
                    next: &'a str,
                }
                fn default_path() -> String {
                    "/".into()
                }
                let obfs: WsClientFactory = deserialize_plugin_param(plugin)?;
                next_tcp = obfs.next;
                ProxyObfsType::WebSocket(WebSocketObfs {
                    host: obfs.host,
                    path: obfs.path,
                    headers: obfs.headers,
                })
            }
            _ => return Ok(None),
        };
        let next_plugin_name = get_plugin_name_from_tcp_ap(next_tcp)?;
        self.current_plugin = self.plugins.take_plugin(next_plugin_name, &plugin.name)?;
        Ok(Some(ret))
    }
    fn analyze_tls(&mut self) -> AnalyzeResult<Option<ProxyTlsLayer>> {
        let Some(plugin) = self.current_plugin.clone() else {
            return Ok(None);
        };
        if &*plugin.plugin != "tls-client" {
            return Ok(None);
        }
        #[derive(Deserialize)]
        struct TlsConfig<'a> {
            sni: Option<String>,
            #[serde(default)]
            alpn: Vec<String>,
            skip_cert_check: Option<bool>,
            next: &'a str,
        }
        let tls: TlsConfig = deserialize_plugin_param(plugin)?;
        let next_plugin_name = get_plugin_name_from_tcp_ap(tls.next)?;
        self.current_plugin = self.plugins.take_plugin(&next_plugin_name, &plugin.name)?;
        Ok(Some(ProxyTlsLayer {
            sni: tls.sni,
            alpn: tls.alpn,
            skip_cert_check: tls.skip_cert_check,
        }))
    }
}

fn get_plugin_name_from_tcp_ap(ap: &str) -> AnalyzeResult<&str> {
    let (plugin_name, _) = ap
        .rsplit_once('.')
        .filter(|(_, ty)| *ty == "tcp")
        .ok_or_else(|| AnalyzeError::UnknownAccessPoint(ap.into()))?;
    Ok(plugin_name)
}

fn get_plugin_name_from_udp_ap(ap: &str) -> AnalyzeResult<&str> {
    let (plugin_name, _) = ap
        .rsplit_once('.')
        .filter(|(_, ty)| *ty == "udp")
        .ok_or_else(|| AnalyzeError::UnknownAccessPoint(ap.into()))?;
    Ok(plugin_name)
}

fn ensure_non_special_plugin_name(name: impl AsRef<str>) -> AnalyzeResult<()> {
    let name = name.as_ref();
    if name == "$out" || name == "$null" {
        return Err(AnalyzeError::TooComplicated);
    }
    Ok(())
}

fn deserialize_plugin_param<'a, T: Deserialize<'a>>(
    plugin: &'a DynOutboundV1Plugin,
) -> AnalyzeResult<T> {
    cbor4ii::serde::from_slice(&plugin.param)
        .map_err(|_| AnalyzeError::InvalidPlugin(plugin.name.clone()))
}

pub fn analyze(name: String, proxy: &[u8]) -> AnalyzeResult<Proxy> {
    let proxy: DynOutboundV1Proxy =
        cbor4ii::serde::from_slice(proxy).map_err(|_| AnalyzeError::InvalidEncoding)?;
    Analyzer::new(name, &proxy)?.analyze()
}

#[cfg(test)]
mod tests {
    use super::*;

    use ciborium::cbor;
    use ytflow::flow::HostName;
    use ytflow::plugin::shadowsocks::SupportedCipher;

    use crate::cbor::to_cbor;
    use crate::proxy::Proxy;

    #[test]
    fn test_analyze_invalid_proxy_cbor() {
        assert_eq!(
            analyze("test".into(), &[]).unwrap_err(),
            AnalyzeError::InvalidEncoding
        );
    }
    #[test]
    fn test_analyze_duplicate_plugins() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![
                DynOutboundV1Plugin {
                    name: "a".into(),
                    plugin: "socks5-client".into(),
                    plugin_version: 0,
                    param: ByteBuf::new(),
                },
                DynOutboundV1Plugin {
                    name: "a".into(),
                    plugin: "http-proxy-client".into(),
                    plugin_version: 0,
                    param: ByteBuf::new(),
                },
            ],
            tcp_entry: "a.tcp".into(),
            udp_entry: None,
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy).unwrap_err(),
            AnalyzeError::DuplicateName("a".into())
        );
    }
    #[test]
    fn test_analyze_invalid_entry_tcp() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![],
            tcp_entry: "aa.fcp".into(),
            udp_entry: None,
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy).unwrap_err(),
            AnalyzeError::UnknownAccessPoint("aa.fcp".into())
        );
    }
    #[test]
    fn test_analyze_invalid_entry_udp() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![],
            tcp_entry: "$out.tcp".into(),
            udp_entry: Some("aa.fcp".into()),
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy).unwrap_err(),
            AnalyzeError::UnknownAccessPoint("aa.fcp".into())
        );
    }
    #[test]
    fn test_analyze_entry_tcp_null() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![],
            tcp_entry: "$null.tcp".into(),
            udp_entry: None,
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy).unwrap_err(),
            AnalyzeError::TooComplicated
        );
    }
    #[test]
    fn test_analyze_entry_tcp_out() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![],
            tcp_entry: "$out.tcp".into(),
            udp_entry: None,
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy)
                .unwrap()
                .analyze()
                .unwrap(),
            Proxy {
                name: "test".into(),
                udp_supported: false,
                legs: vec![]
            }
        );
    }
    #[test]
    fn test_analyze_entry_has_udp() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![],
            tcp_entry: "$out.tcp".into(),
            udp_entry: Some("$out.udp".into()),
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy)
                .unwrap()
                .analyze()
                .unwrap(),
            Proxy {
                name: "test".into(),
                udp_supported: true,
                legs: vec![]
            }
        );
    }
    #[test]
    fn test_analyze_entry_tcp_udp_mismatch() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![],
            tcp_entry: "a.tcp".into(),
            udp_entry: Some("b.udp".into()),
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy).unwrap_err(),
            AnalyzeError::TooComplicated
        );
    }

    #[test]
    fn test_analyze_entry_not_found() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![],
            tcp_entry: "a.tcp".into(),
            udp_entry: None,
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy).unwrap_err(),
            AnalyzeError::PluginNotFound("a".into(), "$entry".into())
        );
    }
    #[test]
    fn test_analyze_extra_plugin() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![DynOutboundV1Plugin {
                name: "a".into(),
                plugin: "socks5-client".into(),
                plugin_version: 0,
                param: ByteBuf::new(),
            }],
            tcp_entry: "$out.tcp".into(),
            udp_entry: None,
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy)
                .unwrap()
                .analyze()
                .unwrap_err(),
            AnalyzeError::UnusedPlugin("a".into())
        );
    }
    #[test]
    fn test_analyze_entry_plugin_is_not_protocol() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![DynOutboundV1Plugin {
                name: "a".into(),
                plugin: "tls-client".into(),
                plugin_version: 0,
                param: ByteBuf::new(),
            }],
            tcp_entry: "a.tcp".into(),
            udp_entry: None,
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy)
                .unwrap()
                .analyze()
                .unwrap_err(),
            AnalyzeError::TooComplicated
        );
    }
    #[test]
    fn test_analyze_only_protocol() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![DynOutboundV1Plugin {
                name: "a".into(),
                plugin: "trojan-client".into(),
                plugin_version: 0,
                param: to_cbor(cbor!({
                    "password" => ByteBuf::new(),
                    "tls_next" => "$out.tcp",
                })),
            }],
            tcp_entry: "a.tcp".into(),
            udp_entry: None,
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy)
                .unwrap()
                .analyze()
                .unwrap_err(),
            AnalyzeError::TooComplicated
        );
    }
    #[test]
    fn test_analyze_protocol_tcp_udp_next_mismatch() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![DynOutboundV1Plugin {
                name: "a".into(),
                plugin: "shadowsocks-client".into(),
                plugin_version: 0,
                param: to_cbor(cbor!({
                    "method" => SupportedCipher::Aes128Gcm,
                    "password" => ByteBuf::new(),
                    "tcp_next" => "b.tcp",
                    "udp_next" => "c.udp",
                })),
            }],
            tcp_entry: "a.tcp".into(),
            udp_entry: Some("a.udp".into()),
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy)
                .unwrap()
                .analyze()
                .unwrap_err(),
            AnalyzeError::TooComplicated
        );
    }
    #[test]
    fn test_analyze_protocol_point_to_self() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![DynOutboundV1Plugin {
                name: "a".into(),
                plugin: "trojan-client".into(),
                plugin_version: 0,
                param: to_cbor(cbor!({
                    "password" => ByteBuf::new(),
                    "tls_next" => "a.tcp",
                })),
            }],
            tcp_entry: "a.tcp".into(),
            udp_entry: None,
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy)
                .unwrap()
                .analyze()
                .unwrap_err(),
            AnalyzeError::TooComplicated
        );
    }
    #[test]
    fn test_analyze_expect_http_udp() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![DynOutboundV1Plugin {
                name: "a".into(),
                plugin: "http-proxy-client".into(),
                plugin_version: 0,
                param: to_cbor(cbor!({
                    "user" => ByteBuf::new(),
                    "pass" => ByteBuf::new(),
                    "tcp_next" => "b.tcp",
                })),
            }],
            tcp_entry: "a.tcp".into(),
            udp_entry: Some("a.udp".into()),
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy)
                .unwrap()
                .analyze()
                .unwrap_err(),
            AnalyzeError::UnexpectedUdpAccessPoint("a".into(), true)
        );
    }
    #[test]
    fn test_analyze_expect_ss_no_udp() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![
                DynOutboundV1Plugin {
                    name: "a".into(),
                    plugin: "shadowsocks-client".into(),
                    plugin_version: 0,
                    param: to_cbor(cbor!({
                        "method" => SupportedCipher::Aes128Gcm,
                        "password" => ByteBuf::new(),
                        "tcp_next" => "b.tcp",
                        "udp_next" => "b.udp",
                    })),
                },
                DynOutboundV1Plugin {
                    name: "b".into(),
                    plugin: "redirect".into(),
                    plugin_version: 0,
                    param: to_cbor(cbor!({
                        "dest" => DestinationAddr {
                            host: HostName::from_domain_name("example.com".into()).unwrap(),
                            port: 443,
                        },
                        "tcp_next" => "c.tcp",
                        "udp_next" => "$null.udp",
                    })),
                },
                DynOutboundV1Plugin {
                    name: "c".into(),
                    plugin: "shadowsocks-client".into(),
                    plugin_version: 0,
                    param: to_cbor(cbor!({
                        "method" => SupportedCipher::Aes128Gcm,
                        "password" => ByteBuf::new(),
                        "tcp_next" => "d.tcp",
                        "udp_next" => "d.udp",
                    })),
                },
                DynOutboundV1Plugin {
                    name: "d".into(),
                    plugin: "redirect".into(),
                    plugin_version: 0,
                    param: to_cbor(cbor!({
                        "dest" => DestinationAddr {
                            host: HostName::from_domain_name("example.com".into()).unwrap(),
                            port: 443,
                        },
                        "tcp_next" => "$out.tcp",
                        "udp_next" => "$out.udp",
                    })),
                },
            ],
            tcp_entry: "a.tcp".into(),
            udp_entry: Some("a.udp".into()),
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy)
                .unwrap()
                .analyze()
                .unwrap_err(),
            AnalyzeError::UnexpectedUdpAccessPoint("c".into(), false)
        );
    }
    #[test]
    fn test_analyze_redirect_next_tcp_udp_mismatch() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![
                DynOutboundV1Plugin {
                    name: "a".into(),
                    plugin: "shadowsocks-client".into(),
                    plugin_version: 0,
                    param: to_cbor(cbor!({
                        "method" => SupportedCipher::Aes128Gcm,
                        "password" => ByteBuf::new(),
                        "tcp_next" => "b.tcp",
                        "udp_next" => "b.udp",
                    })),
                },
                DynOutboundV1Plugin {
                    name: "b".into(),
                    plugin: "redirect".into(),
                    plugin_version: 0,
                    param: to_cbor(cbor!({
                        "dest" => DestinationAddr {
                            host: HostName::from_domain_name("example.com".into()).unwrap(),
                            port: 443,
                        },
                        "tcp_next" => "c.tcp",
                        "udp_next" => "d.udp",
                    })),
                },
                DynOutboundV1Plugin {
                    name: "c".into(),
                    plugin: "shadowsocks-client".into(),
                    plugin_version: 0,
                    param: to_cbor(cbor!({
                        "method" => SupportedCipher::Aes128Gcm,
                        "password" => ByteBuf::new(),
                        "tcp_next" => "$out.tcp",
                        "udp_next" => "$out.udp",
                    })),
                },
            ],
            tcp_entry: "a.tcp".into(),
            udp_entry: Some("a.udp".into()),
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy)
                .unwrap()
                .analyze()
                .unwrap_err(),
            AnalyzeError::TooComplicated
        );
    }
    #[test]
    fn test_analyze_invalid_plugin_version() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![DynOutboundV1Plugin {
                name: "a".into(),
                plugin: "trojan-client".into(),
                plugin_version: 114,
                param: ByteBuf::new(),
            }],
            tcp_entry: "a.tcp".into(),
            udp_entry: None,
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy).unwrap_err(),
            AnalyzeError::InvalidPlugin("a".into())
        );
    }
    #[test]
    fn test_analyze_invalid_plugin_param() {
        let proxy = DynOutboundV1Proxy {
            plugins: vec![DynOutboundV1Plugin {
                name: "a".into(),
                plugin: "trojan-client".into(),
                plugin_version: 0,
                param: ByteBuf::from(vec![0x80]),
            }],
            tcp_entry: "a.tcp".into(),
            udp_entry: None,
        };
        assert_eq!(
            Analyzer::new("test".into(), &proxy)
                .unwrap()
                .analyze()
                .unwrap_err(),
            AnalyzeError::InvalidPlugin("a".into())
        );
    }
}
