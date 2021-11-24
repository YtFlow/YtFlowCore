use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::fakeip;

#[derive(Clone, Deserialize)]
pub struct FakeIpFactory<'a> {
    prefix_v4: [u8; 2],
    prefix_v6: [u8; 14],
    // Reserved for CNAME, TXT and SRV support
    fallback: &'a str,
}

impl<'de> FakeIpFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self =
            parse_param(param).ok_or_else(|| ConfigError::ParseParam(name.to_string()))?;
        Ok(ParsedPlugin {
            factory: config.clone(),
            requires: vec![Descriptor {
                descriptor: config.fallback,
                r#type: AccessPointType::Resolver,
            }],
            provides: vec![Descriptor {
                descriptor: name.to_string() + ".resolver",
                r#type: AccessPointType::Resolver,
            }],
        })
    }
}

impl<'de> Factory for FakeIpFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let resolver = Arc::new(fakeip::FakeIp::new(self.prefix_v4, self.prefix_v6));
        set.fully_constructed
            .resolver
            .insert(plugin_name + ".resolver", resolver);
        Ok(())
    }
}
