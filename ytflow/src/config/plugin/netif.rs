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
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                },
                Descriptor {
                    descriptor: name.to_string() + ".udp",
                    r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                },
                Descriptor {
                    descriptor: name.to_string() + ".resolver",
                    r#type: AccessPointType::RESOLVER,
                },
            ],
            resources: vec![],
        })
    }
}

impl Factory for NetifFactory {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let netif = netif::NetifSelector::new(self.selection.clone(), self.family_preference);
        set.control_hub.create_plugin_control(
            plugin_name.clone(),
            "netif",
            netif::Responder::new(netif.clone()),
        );
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name.clone() + ".tcp", netif.clone());
        set.fully_constructed
            .datagram_outbounds
            .insert(plugin_name.clone() + ".udp", netif.clone());
        set.fully_constructed
            .resolver
            .insert(plugin_name + ".resolver", netif);
        Ok(())
    }
}
