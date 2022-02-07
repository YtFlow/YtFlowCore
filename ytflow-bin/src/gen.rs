use chrono::naive::MIN_DATETIME;
use ciborium::cbor;

pub mod defaults;
use ytflow::{
    data::{Connection, DataResult, Id, Plugin, PluginId, ProfileId},
    flow::{Destination, DestinationAddr},
};

#[derive(Debug)]
pub struct GeneratedPlugin {
    is_entry: bool,
    plugin: Plugin,
}

const DUMMY_PLUGIN_ID: PluginId = Id::new(0);

fn serialize_cbor(val: ciborium::value::Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&val, &mut buf).expect("Cannot serialize CBOR");
    buf
}

fn generate_common_plugins(prefix: &str, plugins: &mut Vec<GeneratedPlugin>) {
    let reject = Plugin {
        id: DUMMY_PLUGIN_ID,
        name: prefix.to_string() + "-reject",
        desc: String::from("Reject any incoming requests"),
        plugin: String::from("reject"),
        plugin_version: 0,
        param: serialize_cbor(ciborium::value::Value::Null),
        updated_at: MIN_DATETIME,
    };
    let null = Plugin {
        id: DUMMY_PLUGIN_ID,
        name: prefix.to_string() + "-null",
        desc: String::from("Return an error for any incoming requests"),
        plugin: String::from("null"),
        plugin_version: 0,
        param: serialize_cbor(ciborium::value::Value::Null),
        updated_at: MIN_DATETIME,
    };
    plugins.push(GeneratedPlugin {
        plugin: reject,
        is_entry: false,
    });
    plugins.push(GeneratedPlugin {
        plugin: null,
        is_entry: false,
    });
}

fn generate_socks5_forward(
    prefix: &str,
    tcp_next_plugin: String,
    plugins: &mut Vec<GeneratedPlugin>,
) {
    let listener = Plugin {
        id: DUMMY_PLUGIN_ID,
        name: String::from(prefix.to_string() + "-listener"),
        desc: String::from("Listen for incoming SOCKS5 connections"),
        plugin: String::from("socket-listener"),
        plugin_version: 0,
        param: serialize_cbor(
            cbor!({
                "tcp_listen" => ["127.0.0.1:9080"],
                "udp_listen" => [],
                "tcp_next" => prefix.to_string() + "-socks5.tcp",
                "udp_next" => prefix.to_string() + "-reject.udp",
            })
            .expect("Cannot generate SOCKS5 listener params"),
        ),
        updated_at: MIN_DATETIME,
    };
    let socks5 = Plugin {
        id: DUMMY_PLUGIN_ID,
        name: String::from(prefix.to_string() + "-socks5"),
        desc: String::from("SOCKS5 server"),
        plugin: String::from("socks5-server"),
        plugin_version: 0,
        param: serialize_cbor(
            cbor!({
                "tcp_next" => prefix.to_string() + "-forward.tcp",
                "udp_next" => prefix.to_string() + "-reject.udp",
            })
            .expect("Cannot generate SOCKS5 params"),
        ),
        updated_at: MIN_DATETIME,
    };
    let forward = Plugin {
        id: DUMMY_PLUGIN_ID,
        name: String::from(prefix.to_string() + "-forward"),
        desc: String::from("Main forwarder"),
        plugin: String::from("forward"),
        plugin_version: 0,
        param: serialize_cbor(
            cbor!({
                "tcp_next" => tcp_next_plugin + ".tcp",
                "udp_next" => prefix.to_string() + "-null.udp",
            })
            .expect("Cannot generate SOCKS5 forwarder params"),
        ),
        updated_at: MIN_DATETIME,
    };
    plugins.push(GeneratedPlugin {
        plugin: listener,
        is_entry: true,
    });
    plugins.push(GeneratedPlugin {
        plugin: socks5,
        is_entry: false,
    });
    plugins.push(GeneratedPlugin {
        plugin: forward,
        is_entry: false,
    });
}

fn generate_socket_outbound(prefix: &str, plugins: &mut Vec<GeneratedPlugin>) {
    let sys_resolver = Plugin {
        id: DUMMY_PLUGIN_ID,
        name: String::from(prefix.to_string() + "-sys-resolver"),
        desc: String::from("System resolver"),
        plugin: String::from("system-resolver"),
        plugin_version: 0,
        param: serialize_cbor(
            cbor!({
                "concurrency_limit" => 64u8
            })
            .expect("Cannot generate system resolver params"),
        ),
        updated_at: MIN_DATETIME,
    };
    let netif = Plugin {
        id: DUMMY_PLUGIN_ID,
        name: String::from(prefix.to_string() + "-netif"),
        desc: String::from("Dummy network interface"),
        plugin: String::from("netif"),
        plugin_version: 0,
        param: serialize_cbor(
            cbor!({
                "family_preference" => "NoPreference",
                "type" => "Virtual",
                "netif" => {
                    "name" => "DummyInterface",
                    "ipv4_addr" => "0.0.0.0:0",
                    "ipv6_addr" => "[::]:0",
                    "dns_servers" => []
                }
            })
            .expect("Cannot generate netif params"),
        ),
        updated_at: MIN_DATETIME,
    };
    let socket = Plugin {
        id: DUMMY_PLUGIN_ID,
        name: String::from(prefix.to_string() + "-socket"),
        desc: String::from("Socket outbound"),
        plugin: String::from("socket"),
        plugin_version: 0,
        param: serialize_cbor(
            cbor!({
                "resolver" => prefix.to_string() + "-sys-resolver.resolver",
                "netif" => prefix.to_string() + "-netif.netif"
            })
            .expect("Cannot generate socket params"),
        ),
        updated_at: MIN_DATETIME,
    };
    plugins.push(GeneratedPlugin {
        plugin: sys_resolver,
        is_entry: false,
    });
    plugins.push(GeneratedPlugin {
        plugin: netif,
        is_entry: false,
    });
    plugins.push(GeneratedPlugin {
        plugin: socket,
        is_entry: false,
    });
}

pub fn generate_shadowsocks_plugins() -> Vec<GeneratedPlugin> {
    // TODO: null, reject
    let mut plugins = Vec::with_capacity(10);
    let prefix = "default";
    generate_common_plugins(prefix, &mut plugins);
    generate_socket_outbound(prefix, &mut plugins);

    let ss = Plugin {
        id: DUMMY_PLUGIN_ID,
        name: String::from(prefix.to_string() + "-ss"),
        desc: String::from("Shadowsocks Client"),
        plugin: String::from("shadowsocks-client"),
        plugin_version: 0,
        param: serialize_cbor(
            cbor!({
                "method" => "aes-256-gcm",
                "password" => serde_bytes::Bytes::new(&b"password"[..]),
                "tcp_next" => prefix.to_string() + "-redir.tcp",
                "udp_next" => prefix.to_string() + "-null.udp",
            })
            .expect("Cannot generate Shadowsocks params"),
        ),
        updated_at: MIN_DATETIME,
    };
    let redir = Plugin {
        id: DUMMY_PLUGIN_ID,
        name: String::from(prefix.to_string() + "-redir"),
        desc: String::from("Redirect to Shadowsocks server"),
        plugin: String::from("redirect"),
        plugin_version: 0,
        param: serialize_cbor(
            cbor!({
                "dest" => DestinationAddr {
                    dest: Destination::DomainName("example.com.".into()),
                    port: 8388,
                },
                "tcp_next" => prefix.to_string() + "-socket",
                "udp_next" => prefix.to_string() + "-null.udp",
            })
            .expect("Cannot generate Shadowsocks redir params"),
        ),
        updated_at: MIN_DATETIME,
    };
    plugins.push(GeneratedPlugin {
        plugin: ss,
        is_entry: false,
    });
    plugins.push(GeneratedPlugin {
        plugin: redir,
        is_entry: false,
    });

    generate_socks5_forward(prefix, prefix.to_string() + "-ss", &mut plugins);
    plugins
}

pub fn create_profile(conn: &Connection) -> DataResult<ProfileId> {
    let id = ytflow::data::Profile::create(
        format!("new_profile_{}", nanoid::nanoid!(5)),
        String::from("en-US"),
        conn,
    )?;
    Ok(Id::new(id))
}

pub fn save_plugins(
    plugins: Vec<GeneratedPlugin>,
    profile_id: ProfileId,
    conn: &Connection,
) -> DataResult<()> {
    for GeneratedPlugin { plugin, is_entry } in plugins {
        let id = ytflow::data::Plugin::create(
            profile_id,
            plugin.name,
            plugin.desc,
            plugin.plugin,
            plugin.plugin_version,
            plugin.param,
            conn,
        )?;
        if is_entry {
            ytflow::data::Plugin::set_as_entry(profile_id, id.into(), conn)?;
        }
    }
    Ok(())
}
