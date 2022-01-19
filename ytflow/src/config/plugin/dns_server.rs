use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::dns_server;
use crate::plugin::null::Null;

#[derive(Deserialize)]
pub struct DnsServerFactory<'a> {
    /// For cross-platform consistency, use a fixed-width type
    concurrency_limit: u32,
    resolver: &'a str,
    ttl: u32,
}

impl<'de> DnsServerFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        let resolver = config.resolver;
        Ok(ParsedPlugin {
            factory: config,
            requires: vec![Descriptor {
                descriptor: resolver,
                r#type: AccessPointType::RESOLVER,
            }],
            provides: vec![Descriptor {
                descriptor: name.to_string() + ".udp",
                r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
            }],
        })
    }
}

impl<'de> Factory for DnsServerFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let mut err = None;
        let factory = Arc::new_cyclic(|weak| {
            set.datagram_handlers
                .insert(plugin_name.clone() + ".udp", weak.clone() as _);
            let resolver = set
                .get_or_create_resolver(plugin_name.clone(), self.resolver)
                .unwrap_or_else(|e| {
                    err = Some(e);
                    Arc::downgrade(&(Arc::new(Null) as _))
                });
            dns_server::DnsDatagramHandler::new(self.concurrency_limit as usize, resolver, self.ttl)
        });
        if let Some(e) = err {
            set.errors.push(e);
        }
        set.fully_constructed
            .datagram_handlers
            .insert(plugin_name + ".udp", factory);
        Ok(())
    }
}
