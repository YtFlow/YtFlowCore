use serde::{Deserialize, Serialize};

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::netif;

#[derive(Serialize, Deserialize)]
pub struct NetifFactory {
    pub family_preference: netif::FamilyPreference,
    #[serde(flatten)]
    pub selection: netif::SelectionMode,
}

impl NetifFactory {
    pub(in super::super) fn parse(plugin: &Plugin) -> ConfigResult<ParsedPlugin<'static, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        Ok(ParsedPlugin {
            factory: config,
            requires: vec![],
            provides: vec![
                Descriptor {
                    descriptor: name.to_string() + ".netif",
                    r#type: AccessPointType::NETIF,
                },
                Descriptor {
                    descriptor: name.to_string() + ".resolver",
                    r#type: AccessPointType::RESOLVER,
                },
            ],
        })
    }
}

impl Factory for NetifFactory {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let netif = netif::NetifSelector::new(self.selection.clone(), self.family_preference)
            .ok_or_else(|| LoadError::NoUseableNetif(plugin_name.clone()))?;
        set.fully_constructed.resolver.insert(
            plugin_name.clone() + ".resolver",
            Arc::new(netif::NetifHostResolver::new(netif.clone())),
        );
        set.fully_constructed
            .netif
            .insert(plugin_name + ".netif", netif);
        Ok(())
    }
}
