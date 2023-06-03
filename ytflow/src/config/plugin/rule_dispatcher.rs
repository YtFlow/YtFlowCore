use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Weak;

use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::flow::*;
use crate::plugin::null::Null;
use crate::plugin::reject::RejectHandler;
use crate::plugin::rule_dispatcher as rd;
use crate::resource::{ResourceError, RESOURCE_TYPE_GEOIP_COUNTRY};

static RULE_DISPATCHER_ALLOWED_RESOURCE_TYPES: [&str; 1] = [RESOURCE_TYPE_GEOIP_COUNTRY];

#[derive(Clone, Deserialize)]
pub struct Action<'a> {
    pub(super) tcp: Option<&'a str>,
    pub(super) udp: Option<&'a str>,
    pub(super) resolver: Option<&'a str>,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub enum ResourceSource<'a> {
    Key(&'a str),
    Literal { format: &'a str, text: Cow<'a, str> },
}

#[derive(Clone, Deserialize)]
pub struct RuleDispatcherConfig<'a> {
    pub(super) resolver: Option<&'a str>,
    pub(super) source: ResourceSource<'a>,
    // TODO: pub(super) geoip: ResourceSource<'a>,
    pub(super) actions: BTreeMap<&'a str, Action<'a>>,
    pub(super) rules: BTreeMap<&'a str, &'a str>,
    pub(super) fallback: Action<'a>,
}

pub struct RuleDispatcherFactory<'a> {
    config: RuleDispatcherConfig<'a>,
}

fn chain_requirements_from_action<'a, 'b>(
    a: &'b Action<'a>,
) -> impl Iterator<Item = DemandDescriptor<'a>> + 'b {
    a.tcp
        .iter()
        .map(|t| Descriptor {
            descriptor: *t,
            r#type: AccessPointType::STREAM_HANDLER,
        })
        .chain(a.udp.iter().map(|u| Descriptor {
            descriptor: *u,
            r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
        }))
        .chain(a.resolver.iter().map(|r| Descriptor {
            descriptor: *r,
            r#type: AccessPointType::RESOLVER,
        }))
}

impl<'de> RuleDispatcherFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: RuleDispatcherConfig = parse_param(name, param)?;

        if config.actions.len() > rd::ACTION_LIMIT {
            return Err(ConfigError::InvalidParam {
                plugin: name.to_string(),
                field: "actions",
            });
        }
        for rule_action in config.rules.values() {
            if !config.actions.contains_key(rule_action) {
                return Err(ConfigError::InvalidParam {
                    plugin: name.to_string(),
                    field: "rules",
                });
            }
        }

        let requires: Vec<_> = config
            .resolver
            .iter()
            .map(|r| Descriptor {
                descriptor: *r,
                r#type: AccessPointType::RESOLVER,
            })
            .chain(
                config
                    .actions
                    .values()
                    .flat_map(chain_requirements_from_action),
            )
            .chain(chain_requirements_from_action(&config.fallback))
            .collect();
        Ok(ParsedPlugin {
            resources: match config.source {
                ResourceSource::Key(key) => Some(RequiredResource {
                    key,
                    allowed_types: &RULE_DISPATCHER_ALLOWED_RESOURCE_TYPES,
                }),
                ResourceSource::Literal { .. } => None,
            }
            .into_iter()
            .collect(),
            factory: Self { config },
            requires,
            provides: vec![
                Descriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::STREAM_HANDLER,
                },
                Descriptor {
                    descriptor: name.to_string() + ".udp",
                    r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
                },
                Descriptor {
                    descriptor: name.to_string() + ".resolver",
                    r#type: AccessPointType::RESOLVER,
                },
            ],
        })
    }
}

fn load_resolver(
    resolver: &str,
    set: &mut PartialPluginSet,
    plugin_name: &str,
) -> Weak<dyn Resolver> {
    match set.get_or_create_resolver(plugin_name.to_string(), resolver) {
        Ok(resolver) => resolver,
        Err(e) => {
            set.errors.push(e);
            Arc::downgrade(&(Arc::new(Null) as _))
        }
    }
}

fn load_action(action: &Action, set: &mut PartialPluginSet, plugin_name: &str) -> rd::Action {
    let Action { tcp, udp, resolver } = action;
    let tcp_next = tcp
        .as_ref()
        .map(
            |tcp| match set.get_or_create_stream_handler(plugin_name.to_string(), tcp) {
                Ok(tcp_next) => tcp_next,
                Err(e) => {
                    set.errors.push(e);
                    Arc::downgrade(&(Arc::new(RejectHandler) as _))
                }
            },
        )
        .unwrap_or_else(|| Arc::downgrade(&(Arc::new(RejectHandler) as _)));
    let udp_next = udp
        .as_ref()
        .map(
            |udp| match set.get_or_create_datagram_handler(plugin_name.to_string(), udp) {
                Ok(udp_next) => udp_next,
                Err(e) => {
                    set.errors.push(e);
                    Arc::downgrade(&(Arc::new(RejectHandler) as _))
                }
            },
        )
        .unwrap_or_else(|| Arc::downgrade(&(Arc::new(RejectHandler) as _)));
    let resolver = resolver
        .as_ref()
        .map(|resolver| load_resolver(resolver, set, plugin_name))
        .unwrap_or_else(|| Arc::downgrade(&(Arc::new(Null) as _)));
    rd::Action {
        tcp_next,
        udp_next,
        resolver,
    }
}

impl<'de> Factory for RuleDispatcherFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let mut resource_type;
        let resource_key;
        let resource_bytes = match std::mem::replace(
            &mut self.config.source,
            ResourceSource::Literal {
                format: "",
                text: "".into(),
            },
        ) {
            ResourceSource::Key(key) => {
                resource_key = key;
                let metadata =
                    set.resource_registry
                        .query_metadata(key)
                        .map_err(|e| LoadError::Resource {
                            plugin: plugin_name.clone(),
                            error: e,
                        })?;
                let bytes = set
                    .resource_registry
                    .query_bytes(&metadata.handle)
                    .map_err(|e| LoadError::Resource {
                        plugin: plugin_name.clone(),
                        error: e,
                    })?;
                resource_type = metadata.r#type.as_str();
                bytes
            }
            ResourceSource::Literal { format, text } => {
                resource_key = "<literal>";
                resource_type = format;
                match text {
                    Cow::Borrowed(text) => text.as_bytes().into(),
                    Cow::Owned(text) => text.into_bytes().into(),
                }
            }
        };
        // TODO: more resource types
        let mut builder = rd::RuleDispatcherBuilder::default();
        match resource_type {
            RESOURCE_TYPE_GEOIP_COUNTRY => {
                builder
                    .load_dst_geoip(resource_bytes)
                    .map_err(|_| LoadError::Resource {
                        plugin: plugin_name.clone(),
                        error: ResourceError::InvalidData,
                    })?;
                resource_type = &RESOURCE_TYPE_GEOIP_COUNTRY;
            }
            resource_type => {
                return Err(LoadError::ResourceTypeMismatch {
                    plugin: plugin_name.clone(),
                    resource_key: resource_key.to_string(),
                    expected: &RULE_DISPATCHER_ALLOWED_RESOURCE_TYPES,
                    actual: resource_type.to_string(),
                })
            }
        }
        let plugin = Arc::new_cyclic(|weak| {
            set.stream_handlers
                .insert(plugin_name.clone(), weak.clone() as _);
            set.datagram_handlers
                .insert(plugin_name.clone(), weak.clone() as _);
            set.resolver.insert(plugin_name.clone(), weak.clone() as _);

            let mut action_map = BTreeMap::new();
            for (action_key, action_desc) in &self.config.actions {
                action_map.insert(
                    *action_key,
                    builder
                        .add_action(load_action(action_desc, set, &plugin_name))
                        // We have checked in the parse stage. Hopefully it will not panic.
                        .unwrap(),
                );
            }
            match resource_type {
                RESOURCE_TYPE_GEOIP_COUNTRY => {
                    for (code, action) in &self.config.rules {
                        builder.add_dst_geoip_rule(code.to_string(), action_map[action], true);
                    }
                }
                _ => unreachable!(),
            }
            builder.build(
                self.config
                    .resolver
                    .as_ref()
                    .map(|resolver| load_resolver(resolver, set, &plugin_name)),
                load_action(&self.config.fallback, set, &plugin_name),
                weak.clone(),
            )
        });
        set.fully_constructed
            .stream_handlers
            .insert(plugin_name.clone() + ".tcp", plugin.clone());
        set.fully_constructed
            .datagram_handlers
            .insert(plugin_name.clone() + ".udp", plugin.clone());
        set.fully_constructed
            .resolver
            .insert(plugin_name + ".resolver", plugin);
        Ok(())
    }
}
