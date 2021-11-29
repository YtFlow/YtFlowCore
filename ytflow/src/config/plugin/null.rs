use crate::config::factory::*;
use crate::config::*;
use crate::plugin::null;

pub struct NullFactory {}

impl NullFactory {
    pub(in super::super) fn parse(plugin: &Plugin) -> ConfigResult<ParsedPlugin<'static, Self>> {
        let name = plugin.name.clone();
        Ok(ParsedPlugin {
            factory: NullFactory {},
            requires: vec![],
            provides: vec![
                Descriptor {
                    descriptor: name.clone() + ".tcp",
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                },
                Descriptor {
                    descriptor: name.clone() + ".udp",
                    r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                },
                Descriptor {
                    descriptor: name + ".resolver",
                    r#type: AccessPointType::RESOLVER,
                },
            ],
        })
    }
}

impl Factory for NullFactory {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name.clone() + ".tcp", Arc::new(null::Null));
        set.fully_constructed
            .datagram_outbounds
            .insert(plugin_name.clone() + ".udp", Arc::new(null::Null));
        set.fully_constructed
            .resolver
            .insert(plugin_name + ".resolver", Arc::new(null::Null));
        Ok(())
    }
}
