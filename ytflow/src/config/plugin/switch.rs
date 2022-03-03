use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::reject::RejectHandler;
use crate::plugin::switch;

#[derive(Deserialize)]
struct Choice<'a> {
    name: String,
    description: String,
    tcp_next: &'a str,
    udp_next: &'a str,
}

#[derive(Deserialize)]
pub struct SwitchFactory<'a> {
    #[serde(borrow)]
    choices: Vec<Choice<'a>>,
}

impl<'de> SwitchFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
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
            factory: config,
        })
    }
}

impl<'de> Factory for SwitchFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let switch = Arc::new_cyclic(|weak| {
            set.stream_handlers
                .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
            set.datagram_handlers
                .insert(plugin_name.clone() + ".udp", weak.clone() as _);

            switch::Switch {
                // TODO: read last choice from DB
                current_choice: ArcSwap::new(Arc::new(switch::CurrentChoice {
                    idx: 0,
                    tcp_next: Arc::new(RejectHandler),
                    udp_next: Arc::new(RejectHandler),
                })),
            }
        });

        let choices: Vec<_> = self
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

        // TODO: read last choice from DB
        let first_choice = (choices[0].tcp_next.clone(), choices[0].udp_next.clone()); // `parse` ensures that there is at least one choice

        tokio::spawn({
            let switch = switch.clone();
            async move {
                let first_choice = switch::CurrentChoice {
                    idx: 0,
                    tcp_next: match first_choice.0.upgrade() {
                        Some(next) => next,
                        None => return,
                    },
                    udp_next: match first_choice.1.upgrade() {
                        Some(next) => next,
                        None => return,
                    },
                };
                switch.current_choice.store(Arc::new(first_choice));
            }
        });

        let responder = switch::Responder {
            choices,
            switch: switch.clone(),
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
