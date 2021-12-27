use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::system_resolver::SystemResolver;

#[derive(Clone, Deserialize)]
pub struct SystemResolverFactory {
    concurrency_limit: u32,
}

impl SystemResolverFactory {
    pub(in super::super) fn parse(plugin: &Plugin) -> ConfigResult<ParsedPlugin<'_, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        Ok(ParsedPlugin {
            factory: config.clone(),
            requires: vec![],
            provides: vec![Descriptor {
                descriptor: name.to_string() + ".resolver",
                r#type: AccessPointType::RESOLVER,
            }],
        })
    }
}

impl Factory for SystemResolverFactory {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let resolver = Arc::new(SystemResolver::new(self.concurrency_limit as usize));
        set.fully_constructed
            .resolver
            .insert(plugin_name + ".resolver", resolver);
        Ok(())
    }
}
