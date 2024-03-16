use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::data::PluginId;

#[cfg_attr(not(feature = "plugins"), allow(dead_code))]
#[derive(Clone, Deserialize)]
pub struct FakeIpFactory<'a> {
    prefix_v4: [u8; 2],
    prefix_v6: [u8; 14],
    // Reserved for CNAME, TXT and SRV support
    fallback: &'a str,
    #[serde(skip)]
    plugin_id: Option<PluginId>,
}

impl<'de> FakeIpFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin {
            name, param, id, ..
        } = plugin;
        let mut config: Self = parse_param(name, param)?;
        config.plugin_id = *id;
        Ok(ParsedPlugin {
            factory: config.clone(),
            requires: vec![Descriptor {
                descriptor: config.fallback,
                r#type: AccessPointType::RESOLVER,
            }],
            provides: vec![Descriptor {
                descriptor: name.to_string() + ".resolver",
                r#type: AccessPointType::RESOLVER,
            }],
            resources: vec![],
        })
    }
}

impl<'de> Factory for FakeIpFactory<'de> {
    #[cfg(feature = "plugins")]
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        use crate::{data::PluginCache, plugin::fakeip};

        let db = set
            .db
            .ok_or_else(|| LoadError::DatabaseRequired {
                plugin: plugin_name.clone(),
            })?
            .clone();
        let cache = PluginCache::new(
            self.plugin_id.ok_or_else(|| LoadError::DatabaseRequired {
                plugin: plugin_name.clone(),
            })?,
            Some(db.clone()),
        );
        let plugin = Arc::new(fakeip::FakeIp::new(self.prefix_v4, self.prefix_v6, cache));
        set.fully_constructed
            .long_running_tasks
            .push(tokio::spawn(fakeip::cache_writer(plugin.clone())));
        set.fully_constructed
            .resolver
            .insert(plugin_name + ".resolver", plugin);
        Ok(())
    }
}
