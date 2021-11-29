use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::forward;
use crate::plugin::null::Null;

#[derive(Clone, Deserialize)]
pub struct ForwardFactory<'a> {
    tcp_next: &'a str,
    udp_next: &'a str,
}

impl<'de> ForwardFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self =
            parse_param(param).ok_or_else(|| ConfigError::ParseParam(name.to_string()))?;
        Ok(ParsedPlugin {
            factory: config.clone(),
            requires: vec![
                Descriptor {
                    descriptor: config.tcp_next,
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                },
                Descriptor {
                    descriptor: config.udp_next,
                    r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                },
            ],
            provides: vec![
                Descriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::STREAM_HANDLER,
                },
                Descriptor {
                    descriptor: name.to_string() + ".udp",
                    r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
                },
            ],
        })
    }
}

impl<'de> Factory for ForwardFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let tcp_factory = Arc::new_cyclic(|weak| {
            set.stream_handlers
                .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
            let tcp_next =
                match set.get_or_create_stream_outbound(plugin_name.clone(), self.tcp_next) {
                    Ok(t) => t,
                    Err(e) => {
                        set.errors.push(e);
                        Arc::downgrade(&(Arc::new(Null)))
                    }
                };
            forward::StreamForwardHandler { outbound: tcp_next }
        });
        let udp_factory = Arc::new_cyclic(|weak| {
            set.datagram_handlers
                .insert(plugin_name.clone() + ".udp", weak.clone() as _);
            let udp_next =
                match set.get_or_create_datagram_outbound(plugin_name.clone(), self.udp_next) {
                    Ok(u) => u,
                    Err(e) => {
                        set.errors.push(e);
                        Arc::downgrade(&(Arc::new(Null)))
                    }
                };
            forward::DatagramForwardHandler { outbound: udp_next }
        });
        set.fully_constructed
            .stream_handlers
            .insert(plugin_name.clone() + ".tcp", tcp_factory);
        set.fully_constructed
            .datagram_handlers
            .insert(plugin_name.clone() + ".udp", udp_factory);
        Ok(())
    }
}
