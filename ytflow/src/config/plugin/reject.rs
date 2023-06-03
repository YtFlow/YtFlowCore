use crate::config::factory::*;
use crate::config::*;
use crate::plugin::reject;

pub struct RejectFactory {}

impl RejectFactory {
    pub(in super::super) fn parse(plugin: &Plugin) -> ConfigResult<ParsedPlugin<'static, Self>> {
        let name = plugin.name.clone();
        Ok(ParsedPlugin {
            factory: RejectFactory {},
            requires: vec![],
            provides: vec![
                Descriptor {
                    descriptor: name.clone() + ".tcp",
                    r#type: AccessPointType::STREAM_HANDLER,
                },
                Descriptor {
                    descriptor: name + ".udp",
                    r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
                },
            ],
            resources: vec![],
        })
    }
}

impl Factory for RejectFactory {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        set.fully_constructed.stream_handlers.insert(
            plugin_name.clone() + ".tcp",
            Arc::new(reject::RejectHandler),
        );
        set.fully_constructed
            .datagram_handlers
            .insert(plugin_name + ".udp", Arc::new(reject::RejectHandler));
        Ok(())
    }
}
