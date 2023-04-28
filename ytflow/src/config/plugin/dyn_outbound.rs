use crate::config::factory::*;
use crate::config::*;
use crate::data::{DataResult, PluginCache, PluginId};
use crate::plugin::{dyn_outbound, null::Null};

pub struct DynOutboundFactory<'a> {
    config: DynOutboundConfig<'a>,
    plugin_id: Option<PluginId>,
}

#[derive(Deserialize)]
struct DynOutboundConfig<'a> {
    tcp_next: &'a str,
    udp_next: &'a str,
}

impl<'de> DynOutboundFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin {
            name, param, id, ..
        } = plugin;
        let config: DynOutboundConfig = parse_param(name, param)?;
        Ok(ParsedPlugin {
            requires: vec![
                Descriptor {
                    descriptor: config.tcp_next,
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                },
                Descriptor {
                    descriptor: config.udp_next,
                    r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                },
            ],
            provides: vec![
                Descriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                },
                Descriptor {
                    descriptor: name.to_string() + ".udp",
                    r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                },
            ],
            factory: DynOutboundFactory {
                config,
                plugin_id: *id,
            },
        })
    }
}

fn init_plugin(plugin: &dyn_outbound::DynOutbound, cache: &PluginCache) -> DataResult<()> {
    plugin.load_proxies()?;
    let last_selection = cache
        .get(dyn_outbound::PLUGIN_CACHE_KEY_LAST_SELECT)?
        .unwrap_or_default();
    // TODO: return errors
    let _ = plugin.manual_select(last_selection);
    Ok(())
}

impl<'de> Factory for DynOutboundFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let db = set
            .db
            .as_deref()
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
        let factory = Arc::new_cyclic(|weak| {
            set.stream_outbounds
                .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
            set.datagram_outbounds
                .insert(plugin_name.clone() + ".udp", weak.clone() as _);
            let tcp_next = match set
                .get_or_create_stream_outbound(plugin_name.clone(), self.config.tcp_next)
            {
                Ok(t) => t,
                Err(e) => {
                    set.errors.push(e);
                    Arc::downgrade(&(Arc::new(Null) as _))
                }
            };
            let udp_next = match set
                .get_or_create_datagram_outbound(plugin_name.clone(), self.config.udp_next)
            {
                Ok(u) => u,
                Err(e) => {
                    set.errors.push(e);
                    Arc::downgrade(&(Arc::new(Null) as _))
                }
            };

            // TOO: fixed outbounds
            dyn_outbound::DynOutbound::new(db, cache.clone(), vec![], tcp_next, udp_next)
        });

        // TODO: return errors
        let _ = init_plugin(&factory, &cache);

        set.control_hub.create_plugin_control(
            plugin_name.clone(),
            "dyn-outbound",
            dyn_outbound::Responder::new(factory.clone()),
        );
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name.clone() + ".tcp", factory.clone());
        set.fully_constructed
            .datagram_outbounds
            .insert(plugin_name + ".udp", factory);

        Ok(())
    }
}
