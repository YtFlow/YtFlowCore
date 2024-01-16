use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::data::PluginId;

#[cfg_attr(not(feature = "plugins"), allow(dead_code))]
#[derive(Deserialize)]
struct Choice<'a> {
    name: String,
    description: String,
    tcp_next: &'a str,
    udp_next: &'a str,
}

#[derive(Deserialize)]
struct SwitchConfig<'a> {
    #[serde(borrow)]
    choices: Vec<Choice<'a>>,
}

#[cfg_attr(not(feature = "plugins"), allow(dead_code))]
pub struct SwitchFactory<'a> {
    config: SwitchConfig<'a>,
    plugin_id: Option<PluginId>,
}

impl<'de> SwitchFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin {
            name, param, id, ..
        } = plugin;
        let config: SwitchConfig = parse_param(name, param)?;
        if config.choices.is_empty() || config.choices.len() > u32::MAX as usize {
            return Err(ConfigError::InvalidParam {
                plugin: name.clone(),
                field: "choices",
            });
        }
        Ok(ParsedPlugin {
            requires: config
                .choices
                .iter()
                .flat_map(|c| {
                    [
                        DemandDescriptor {
                            descriptor: c.tcp_next,
                            r#type: AccessPointType::STREAM_HANDLER,
                        },
                        DemandDescriptor {
                            descriptor: c.udp_next,
                            r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
                        },
                    ]
                })
                .collect(),
            provides: vec![
                ProvideDescriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::STREAM_HANDLER,
                },
                ProvideDescriptor {
                    descriptor: name.to_string() + ".udp",
                    r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
                },
            ],
            factory: SwitchFactory {
                config,
                plugin_id: *id,
            },
            resources: vec![],
        })
    }
}

impl<'de> Factory for SwitchFactory<'de> {
    #[cfg(feature = "plugins")]
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        use arc_swap::ArcSwap;

        use crate::data::PluginCache;
        use crate::plugin::reject::RejectHandler;
        use crate::plugin::switch;
        use crate::plugin::switch::responder::PLUGIN_CACHE_KEY_LAST_SELECT;

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
        let last_choice_idx: u32 = cache
            .get(PLUGIN_CACHE_KEY_LAST_SELECT)
            .unwrap_or_default()
            .unwrap_or_default();
        let mut choices = vec![];

        let switch = Arc::new_cyclic(|weak| {
            set.stream_handlers
                .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
            set.datagram_handlers
                .insert(plugin_name.clone() + ".udp", weak.clone() as _);

            choices = self
                .config
                .choices
                .iter()
                .map(|c| {
                    let tcp_next =
                        match set.get_or_create_stream_handler(plugin_name.clone(), c.tcp_next) {
                            Ok(t) => t,
                            Err(e) => {
                                set.errors.push(e);
                                Arc::downgrade(&(Arc::new(RejectHandler)))
                            }
                        };
                    let udp_next =
                        match set.get_or_create_datagram_handler(plugin_name.clone(), c.udp_next) {
                            Ok(u) => u,
                            Err(e) => {
                                set.errors.push(e);
                                Arc::downgrade(&(Arc::new(RejectHandler)))
                            }
                        };

                    switch::Choice {
                        name: c.name.clone(),
                        description: c.description.clone(),
                        tcp_next,
                        udp_next,
                    }
                })
                .collect();

            // `parse` ensures that there is at least one choice
            let (last_choice_idx, last_choice) = match choices.get(last_choice_idx as usize) {
                Some(last_choice) => (last_choice_idx, last_choice),
                None => (0, &choices[0]),
            };

            switch::Switch {
                current_choice: ArcSwap::new(Arc::new(switch::CurrentChoice {
                    idx: last_choice_idx,
                    tcp_next: last_choice.tcp_next.clone(),
                    udp_next: last_choice.udp_next.clone(),
                })),
            }
        });

        let responder = switch::Responder {
            choices,
            switch: switch.clone(),
            cache,
        };

        set.fully_constructed
            .stream_handlers
            .insert(plugin_name.clone() + ".tcp", switch.clone());
        set.fully_constructed
            .datagram_handlers
            .insert(plugin_name.clone() + ".udp", switch);
        set.control_hub
            .create_plugin_control(plugin_name, "switch", responder);

        Ok(())
    }
}
