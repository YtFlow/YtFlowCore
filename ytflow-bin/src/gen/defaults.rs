use ciborium::cbor;
use strum::EnumProperty;
use strum_macros::{Display, EnumIter, EnumMessage, EnumProperty};

use super::{serialize_cbor, DUMMY_PLUGIN_ID, MIN_DATETIME};
use ytflow::data::Plugin;

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, EnumIter, EnumProperty, EnumMessage)]
pub enum PluginType {
    #[strum(
        props(prefix = "socket_listener"),
        detailed_message = "Bind a socket to a specified port and listen for connections or datagrams."
    )]
    SocketListener,
}

impl PluginType {
    pub fn gen_default(self) -> Plugin {
        let prefix = format!("{}_{}", self.get_str("prefix").unwrap(), nanoid::nanoid!(5));
        match self {
            PluginType::SocketListener => Plugin {
                id: DUMMY_PLUGIN_ID,
                name: prefix.clone(),
                desc: String::from("Listen for incoming SOCKS5 connections"),
                plugin: String::from("socket-listener"),
                plugin_version: 0,
                param: serialize_cbor(
                    cbor!({
                        "tcp_listen" => ["127.0.0.1:9080"],
                        "udp_listen" => [],
                        "tcp_next" => prefix.clone() + "_socks5.tcp",
                        "udp_next" => prefix + "_reject.udp",
                    })
                    .expect("Cannot generate SOCKS5 listener params"),
                ),
                updated_at: MIN_DATETIME,
            },
        }
    }
}
