use std::collections::HashSet;

use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::data::PluginId;

#[cfg_attr(not(feature = "plugins"), allow(dead_code))]
#[derive(Deserialize)]
pub struct DnsServerFactory<'a> {
    /// For cross-platform consistency, use a fixed-width type
    concurrency_limit: u32,
    resolver: &'a str,
    ttl: u32,
    #[serde(borrow)]
    tcp_map_back: HashSet<&'a str>,
    #[serde(borrow)]
    udp_map_back: HashSet<&'a str>,
    #[serde(skip)]
    plugin_id: Option<PluginId>,
}

impl<'de> DnsServerFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin {
            name, param, id, ..
        } = plugin;
        let mut config: Self = parse_param(name, param)?;
        config.plugin_id = *id;
        let resolver = config.resolver;
        Ok(ParsedPlugin {
            requires: [Descriptor {
                descriptor: resolver,
                r#type: AccessPointType::RESOLVER,
            }]
            .into_iter()
            .chain(config.tcp_map_back.iter().map(|next| Descriptor {
                descriptor: *next,
                r#type: AccessPointType::STREAM_HANDLER,
            }))
            .chain(config.udp_map_back.iter().map(|next| Descriptor {
                descriptor: *next,
                r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
            }))
            .collect(),
            provides: [Descriptor {
                descriptor: name.to_string() + ".udp",
                r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
            }]
            .into_iter()
            .chain(config.tcp_map_back.iter().map(|next| Descriptor {
                descriptor: name.to_string() + ".tcp_map_back." + next,
                r#type: AccessPointType::STREAM_HANDLER,
            }))
            .chain(config.udp_map_back.iter().map(|next| Descriptor {
                descriptor: name.to_string() + ".udp_map_back." + next,
                r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
            }))
            .collect(),
            factory: config,
            resources: vec![],
        })
    }
}

impl<'de> Factory for DnsServerFactory<'de> {
    #[cfg(feature = "plugins")]
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        use crate::data::PluginCache;
        use crate::plugin::dns_server;
        use crate::plugin::null::Null;
        use crate::plugin::reject::RejectHandler;

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
            dns_server::DnsServer::new(self.concurrency_limit as usize, resolver, self.ttl, cache)
        });
        if let Some(e) = err {
            set.errors.push(e);
        }
        for next in self.tcp_map_back.iter() {
            let tcp_map_back = Arc::new_cyclic(|weak| {
                set.stream_handlers.insert(
                    plugin_name.clone() + ".tcp_map_back." + next,
                    weak.clone() as _,
                );
                let mut err = None;
                let next = set
                    .get_or_create_stream_handler(plugin_name.clone(), next)
                    .unwrap_or_else(|e| {
                        err = Some(e);
                        Arc::downgrade(&(Arc::new(RejectHandler) as _))
                    });
                if let Some(e) = err {
                    set.errors.push(e);
                }
                dns_server::MapBackStreamHandler::new(&factory, next)
            });
            set.fully_constructed
                .stream_handlers
                .insert(plugin_name.clone() + ".tcp_map_back." + next, tcp_map_back);
        }
        for next in self.udp_map_back.iter() {
            let udp_map_back = Arc::new_cyclic(|weak| {
                set.datagram_handlers.insert(
                    plugin_name.clone() + ".udp_map_back." + next,
                    weak.clone() as _,
                );
                let mut err = None;
                let next = set
                    .get_or_create_datagram_handler(plugin_name.clone(), next)
                    .unwrap_or_else(|e| {
                        err = Some(e);
                        Arc::downgrade(&(Arc::new(RejectHandler) as _))
                    });
                if let Some(e) = err {
                    set.errors.push(e);
                }
                dns_server::MapBackDatagramSessionHandler::new(&factory, next)
            });
            set.fully_constructed
                .datagram_handlers
                .insert(plugin_name.clone() + ".udp_map_back." + next, udp_map_back);
        }

        set.fully_constructed
            .datagram_handlers
            .insert(plugin_name + ".udp", factory.clone());
        set.fully_constructed
            .long_running_tasks
            .push(tokio::spawn(dns_server::cache_writer(factory)));
        Ok(())
    }
}
