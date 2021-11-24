use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::netif::{FamilyPreference, NetifSelector, SelectionMode};
use crate::plugin::null::Null;
use crate::plugin::socket;

#[derive(Clone, Deserialize)]
pub struct SocketFactory<'a> {
    resolver: &'a str,
    netif: &'a str,
}

impl<'de> SocketFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self =
            parse_param(param).ok_or_else(|| ConfigError::ParseParam(name.to_string()))?;
        Ok(ParsedPlugin {
            factory: config.clone(),
            requires: vec![
                Descriptor {
                    descriptor: config.resolver,
                    r#type: AccessPointType::Resolver,
                },
                Descriptor {
                    descriptor: config.netif,
                    r#type: AccessPointType::Netif,
                },
            ],
            provides: vec![Descriptor {
                descriptor: name.clone(),
                r#type: AccessPointType::StreamOutboundFactory
                    | AccessPointType::DatagramSessionFactory,
            }],
        })
    }
}

impl<'de> Factory for SocketFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let factory = Arc::new_cyclic(|weak| {
            set.stream_outbounds
                .insert(plugin_name.clone(), weak.clone() as _);
            set.datagram_outbounds
                .insert(plugin_name.clone(), weak.clone() as _);
            let resolver = match set.get_or_create_resolver(plugin_name.clone(), self.resolver) {
                Ok(resolver) => resolver,
                Err(e) => {
                    set.errors.push(e);
                    Arc::downgrade(&(Arc::new(Null) as _))
                }
            };
            let netif_selector = match set.get_or_create_netif(plugin_name.clone(), self.netif) {
                Ok(netif) => netif,
                Err(e) => {
                    set.errors.push(e);
                    NetifSelector::new(
                        SelectionMode::Virtual(Default::default()),
                        FamilyPreference::NoPreference,
                    )
                    .expect("Creating a NULL virtual netif should not fail")
                }
            };
            socket::SocketOutboundFactory {
                resolver,
                netif_selector,
            }
        });
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name.clone() + ".tcp", factory.clone());
        set.fully_constructed
            .datagram_outbounds
            .insert(plugin_name + ".udp", factory);
        Ok(())
    }
}
