use serde::{Deserialize, Serialize};

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::netif;

#[derive(Serialize, Deserialize)]
pub struct NetifFactory<'a> {
    pub family_preference: netif::FamilyPreference,
    #[serde(flatten)]
    pub selection: netif::SelectionMode,
    pub outbound_resolver: Option<&'a str>,
}

impl<'de> NetifFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        Ok(ParsedPlugin {
            requires: config
                .outbound_resolver
                .iter()
                .map(|r| Descriptor {
                    descriptor: *r,
                    r#type: AccessPointType::RESOLVER,
                })
                .collect(),
            factory: config,
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

impl<'a> Factory for NetifFactory<'a> {
    #[cfg(feature = "plugins")]
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        use crate::plugin::null::Null;

        let mut err = None;
        let netif =
            netif::NetifSelector::new(self.selection.clone(), self.family_preference, |weak| {
                set.stream_outbounds
                    .insert(plugin_name.clone() + ".tcp", weak.clone());
                set.datagram_outbounds
                    .insert(plugin_name.clone() + ".udp", weak.clone());
                set.resolver
                    .insert(plugin_name.clone() + ".resolver", weak.clone());

                self.outbound_resolver.map(|outbound_resolver| {
                    set.get_or_create_resolver(plugin_name.clone(), outbound_resolver)
                        .unwrap_or_else(|e| {
                            err = Some(e);
                            Arc::downgrade(&(Arc::new(Null) as _))
                        })
                })
            });
        if let Some(err) = err {
            set.errors.push(err);
        }
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
