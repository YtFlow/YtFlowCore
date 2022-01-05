use std::net::{IpAddr, Ipv4Addr};

use ciborium::{cbor, value::Value::Null};
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use serde_bytes::Bytes;
use strum::{EnumMessage, EnumProperty};
use strum_macros::{Display, EnumIter, EnumMessage, EnumProperty};

use super::{serialize_cbor, DUMMY_PLUGIN_ID, MIN_DATETIME};
use ytflow::{
    config::plugin::NetifFactory,
    data::Plugin,
    flow::{Destination, DestinationAddr},
    plugin::netif::{FamilyPreference, SelectionMode},
};

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, EnumIter, EnumProperty, EnumMessage)]
pub enum PluginType {
    #[strum(
        props(prefix = "reject"),
        detailed_message = "Silently reject any incoming requests."
    )]
    Reject,
    #[strum(
        props(prefix = "null"),
        detailed_message = "Silently drop any outgoing requests."
    )]
    Null,
    #[strum(
        props(prefix = "ip-stack"),
        detailed_message = "Handle TCP or UDP connections from a TUN."
    )]
    IpStack,
    #[strum(
        props(prefix = "socket-listener"),
        detailed_message = "Bind a socket to a specified port and listen for connections or datagrams."
    )]
    SocketListener,
    #[strum(
        props(prefix = "vpn-tun"),
        detailed_message = "An instance to be instantiated by a VPN system service, such as UWP VPN Plugin on Windows."
    )]
    VpnTun,
    #[strum(
        props(prefix = "host-resolver"),
        detailed_message = "Resolve real IP addresses by querying DNS servers."
    )]
    HostResolver,
    #[strum(
        props(prefix = "fake-ip"),
        detailed_message = "Assign a fake IP address for each domain name. This is useful for TUN inbounds where incoming connections carry no information about domain names. By using a Fake IP resolver, destination IP addresses can be mapped back to a domain name that the client is connecting to."
    )]
    FakeIp,
    #[strum(
        props(prefix = "system-resolver"),
        detailed_message = "Resolve real IP addresses by calling system functions. This is the recommended resolver for simple proxy scenarios for both client and server."
    )]
    SystemResolver,
    #[strum(
        props(prefix = "dns-server"),
        detailed_message = "Respond to DNS request messages using results returned by the specified resolver."
    )]
    DnsServer,
    #[strum(props(prefix = "socks5-server"), detailed_message = "SOCKS5 server.")]
    Socks5Server,
    #[strum(
        props(prefix = "resolve-dest"),
        detailed_message = "Resolve domain names in flow destinations from/to IP addresses."
    )]
    ResolveDest,
    #[strum(
        props(prefix = "simple-dispatcher"),
        detailed_message = "Match the source/dest address against a list of simple rules, and use the corresponding handler or fallback handler if there is no match."
    )]
    SimpleDispatcher,
    #[strum(
        props(prefix = "forward"),
        detailed_message = "Establish a new connection for each incoming connection, and forward data between them."
    )]
    Forward,
    #[strum(
        props(prefix = "shadowsocks-client"),
        detailed_message = "Shadowsocks client."
    )]
    ShadowsocksClient,
    #[strum(props(prefix = "socks5-client"), detailed_message = "SOCKS5 client.")]
    Socks5Client,
    #[strum(
        props(prefix = "http-proxy-client"),
        detailed_message = "HTTP Proxy client. Use HTTP CONNECT to connect to the proxy server."
    )]
    HttpProxyClient,
    #[strum(props(prefix = "tls-client"), detailed_message = "TLS client stream.")]
    TlsClient,
    #[strum(
        props(prefix = "trojan-client"),
        detailed_message = "Trojan client. Note that TLS is not included. You will likely need to connect this plugin to a TLS plugin."
    )]
    TrojanClient,
    #[strum(
        props(prefix = "redirect"),
        detailed_message = "Change the destination of connections or datagrams."
    )]
    Redirect,
    #[strum(
        props(prefix = "socket"),
        detailed_message = "Represents a system socket connection."
    )]
    Socket,
    #[strum(
        props(prefix = "netif"),
        detailed_message = "A dynamic network interface."
    )]
    Netif,
}

impl PluginType {
    pub fn gen_default(self) -> Plugin {
        let plugin = self.get_str("prefix").unwrap().to_string();
        let name = format!("{}-{}", &plugin, nanoid::nanoid!(5));
        let desc = self.get_detailed_message().unwrap().to_string();
        let param = serialize_cbor(
            match self {
                PluginType::Reject => Ok(Null),
                PluginType::Null => Ok(Null),
                PluginType::IpStack => cbor!({
                    "tun" => name.clone() + "-tun.tun",
                    "tcp_next" => name.clone() + "-reverse-resolver.tcp",
                    "udp_next" => name.clone() + "-reject.udp",
                }),
                PluginType::SocketListener => cbor!({
                    "tcp_listen" => ["127.0.0.1:9080"],
                    "udp_listen" => [],
                    "tcp_next" => name.clone() + "-socks5.tcp",
                    "udp_next" => name.clone() + "-reject.udp",
                }),
                PluginType::VpnTun => cbor!({
                    "ipv4" => Ipv4Addr::new(192, 168, 3, 1),
                    "ipv6" => Null,
                    "ipv4_route" => [Ipv4Cidr::new([11, 17, 0, 0].into(), 16).unwrap()],
                    "ipv6_route" => Vec::<Ipv6Cidr>::new(),
                    "dns" => [IpAddr::V4([11, 16, 1, 1].into())],
                    "web_proxy" => Null,
                }),
                PluginType::HostResolver => cbor!({
                    "udp" => ["8.8.8.8", "8.8.4.4"],
                    "tcp" => ["8.8.8.8", "4.4.4.4"],
                }),
                PluginType::FakeIp => cbor!({
                    "prefix_v4" => [11u8, 17],
                    "prefix_v6" => [0x26u8, 0x0c, 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    "fallback" => name.clone() + "-host-resolver.resolver",
                }),
                PluginType::SystemResolver => Ok(Null),
                PluginType::DnsServer => cbor!({
                    "concurrency_limit" => 64u8,
                    "resolver" => name.clone() + "-fake-ip.resolver",
                    "ttl" => 60u8,
                }),
                PluginType::Socks5Server => cbor!({
                    "tcp_next" => name.clone() + "-forward.tcp",
                    "udp_next" => name.clone() + "-reject.udp",
                    "user" => Bytes::new(b"remove_if_no_cred"),
                    "pass" => Bytes::new(b"remove_if_no_cred"),
                }),
                PluginType::ResolveDest => cbor!({
                    "resolver" => name.clone() + "-fake-ip.resolver",
                    "reverse" => true,
                    "tcp_next" => name.clone() + "-forward.resolver",
                }),
                PluginType::SimpleDispatcher => cbor!({
                    "rules" => [cbor!({
                        "src" => cbor!({
                            "ip_ranges" => [IpCidr::new([11, 16, 1, 1].into(), 32).unwrap()],
                            "port_ranges" => [53u8..=53],
                        }).unwrap(),
                        "dst" => (),
                        "is_udp" => true,
                        "next" => name.clone() + "-dns-server.udp",
                    }).unwrap()],
                    "fallback_tcp" => name.clone() + "-forward.tcp",
                    "fallback_udp" => name.clone() + "-reject.udp",
                }),
                PluginType::Forward => cbor!({
                    "tcp_next" => name.clone() + "-shadowsocks-client.tcp",
                    "udp_next" => name.clone() + "-socket.udp",
                }),
                PluginType::ShadowsocksClient => cbor!({
                    "method" => Bytes::new(b"aes-256-gcm"),
                    "password" => Bytes::new(b"password"),
                    "tcp_next" => name.clone() + "-redirect.tcp",
                    "udp_next" => name.clone() + "-reject.tcp",
                }),
                PluginType::Socks5Client => cbor!({
                    "tcp_next" => name.clone() + "-redirect.tcp",
                    "udp_next" => name.clone() + "-reject.udp",
                    "user" => Bytes::new(b"remove_if_no_cred"),
                    "pass" => Bytes::new(b"remove_if_no_cred"),
                }),
                PluginType::HttpProxyClient => cbor!({
                    "tcp_next" => name.clone() + "-redirect.tcp",
                    "user" => Bytes::new(b""),
                    "pass" => Bytes::new(b""),
                }),
                PluginType::TlsClient => cbor!({
                    "sni" => "remove.for.auto.sni.detection.com",
                    "next" => name.clone() + "-redirect.tls",
                }),
                PluginType::TrojanClient => cbor!({
                    "password" => Bytes::new(b"password"),
                    "tls_next" => name.clone() + "-tls.tcp",
                }),
                PluginType::Redirect => cbor!({
                    "dest" => DestinationAddr {
                        dest: Destination::DomainName("my.proxy.server.com".into()),
                        port: 8388,
                    },
                    "tcp_next" => name.clone() + "-socket",
                    "udp_next" => name.clone() + "-socket",
                }),
                PluginType::Socket => cbor!({
                    "resolver" => name.clone() + "-system-resolver.resolver",
                    "netif" => name.clone() + "-main-netif.netif",
                }),
                PluginType::Netif => cbor!(NetifFactory {
                    family_preference: FamilyPreference::PreferIpv4,
                    selection: SelectionMode::Manual("eth0".into())
                }),
            }
            .unwrap(),
        );
        Plugin {
            id: DUMMY_PLUGIN_ID,
            name,
            desc,
            plugin,
            plugin_version: 0,
            param,
            updated_at: MIN_DATETIME,
        }
    }
}
