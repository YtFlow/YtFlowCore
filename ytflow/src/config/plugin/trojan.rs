use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::null::Null;
use crate::plugin::trojan;

#[derive(Clone, Deserialize)]
pub struct TrojanFactory<'a> {
    pass: &'a [u8],
    tcp_next: &'a str,
    udp_next: &'a str,
}

impl<'de> TrojanFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self =
            parse_param(param).ok_or_else(|| ConfigError::ParseParam(name.to_string()))?;
        Ok(ParsedPlugin {
            factory: config.clone(),
            requires: vec![
                Descriptor {
                    descriptor: config.tcp_next,
                    r#type: AccessPointType::StreamOutboundFactory,
                },
                Descriptor {
                    descriptor: config.udp_next,
                    r#type: AccessPointType::DatagramSessionFactory,
                },
            ],
            provides: vec![
                Descriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::StreamOutboundFactory,
                },
                // TODO:
                // Descriptor {
                //     descriptor: name.to_string() + ".udp",
                //     r#type: AccessPointType::DatagramSessionFactory,
                // },
            ],
        })
    }
}

impl<'de> Factory for TrojanFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let factory = Arc::new_cyclic(|weak| {
            set.stream_outbounds
                .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
            let tcp_next =
                match set.get_or_create_stream_outbound(plugin_name.clone(), self.tcp_next) {
                    Ok(t) => t,
                    Err(e) => {
                        set.errors.push(e);
                        Arc::downgrade(&(Arc::new(Null) as _))
                    }
                };
            trojan::TrojanStreamOutboundFactory::new(self.pass, tcp_next)
        });
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name, factory);
        Ok(())
    }
}
