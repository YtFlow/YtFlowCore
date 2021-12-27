use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::host_resolver;

#[derive(Deserialize)]
pub struct HostResolverFactory<'a> {
    #[serde(borrow)]
    udp: Vec<&'a str>,
    #[serde(borrow)]
    tcp: Vec<&'a str>,
}

impl<'de> HostResolverFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        let mut requires = Vec::with_capacity(config.udp.len() + config.tcp.len());
        requires.extend(config.udp.iter().map(|c| Descriptor {
            descriptor: *c,
            r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
        }));
        requires.extend(config.tcp.iter().map(|c| Descriptor {
            descriptor: *c,
            r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
        }));
        Ok(ParsedPlugin {
            factory: config,
            requires,
            provides: vec![Descriptor {
                descriptor: name.to_string() + ".resolver",
                r#type: AccessPointType::RESOLVER,
            }],
        })
    }
}

impl<'de> Factory for HostResolverFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let mut errors = vec![];
        let factory = Arc::new_cyclic(|weak| {
            set.resolver
                .insert(plugin_name.to_string() + ".resolver", weak.clone() as _);
            let udp = self
                .udp
                .iter()
                .map(|c| set.get_or_create_datagram_outbound(plugin_name.clone(), *c))
                .filter_map(|d| match d {
                    Ok(d) => Some(d),
                    Err(e) => {
                        errors.push(e);
                        None
                    }
                });
            host_resolver::HostResolver::new(udp)
        });
        set.errors.extend(errors);
        set.fully_constructed.resolver.insert(plugin_name, factory);
        Ok(())
    }
}
