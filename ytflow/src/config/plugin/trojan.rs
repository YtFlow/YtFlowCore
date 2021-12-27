use serde::Deserialize;
use serde_bytes::Bytes;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::null::Null;
use crate::plugin::trojan;

#[derive(Clone, Deserialize)]
pub struct TrojanFactory<'a> {
    password: &'a Bytes,
    tcp_next: &'a str,
    udp_next: &'a str,
}

impl<'de> TrojanFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
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
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
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
            trojan::TrojanStreamOutboundFactory::new(self.password, tcp_next)
        });
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name, factory);
        Ok(())
    }
}
