use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

pub const BUILTIN_PLUGIN_OUT: &str = "$out";
pub const BUILTIN_PLUGIN_NULL: &str = "$null";
pub const BUILTIN_PLUGIN_NAMES: [&str; 2] = [BUILTIN_PLUGIN_OUT, BUILTIN_PLUGIN_NULL];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plugin {
    pub name: String,
    pub plugin: String,
    pub plugin_version: u16,
    pub param: ByteBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    pub tcp_entry: String,
    pub udp_entry: Option<String>,
    pub plugins: Vec<Plugin>,
}

impl From<Plugin> for crate::config::Plugin {
    fn from(plugin: Plugin) -> Self {
        Self {
            id: None,
            name: plugin.name,
            plugin: plugin.plugin,
            plugin_version: plugin.plugin_version,
            param: plugin.param.into_vec(),
        }
    }
}
