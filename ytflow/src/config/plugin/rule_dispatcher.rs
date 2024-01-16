use std::borrow::Cow;
use std::collections::BTreeMap;
#[cfg(feature = "plugins")]
use std::sync::Weak;

use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
#[cfg(feature = "plugins")]
use crate::flow::*;
use crate::plugin::rule_dispatcher as rd;
#[cfg(feature = "plugins")]
use crate::resource::ResourceError;
use crate::resource::{RESOURCE_TYPE_GEOIP_COUNTRY, RESOURCE_TYPE_QUANX_FILTER};

static RULE_DISPATCHER_ALLOWED_RESOURCE_TYPES: [&str; 2] =
    [RESOURCE_TYPE_GEOIP_COUNTRY, RESOURCE_TYPE_QUANX_FILTER];
static RULE_DISPATCHER_ALLOWED_LITERAL_RESOURCE_TYPES: [&str; 1] = [RESOURCE_TYPE_QUANX_FILTER];

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
    Literal {
        format: &'a str,
        text: Vec<Cow<'a, str>>,
    },
}

#[derive(Clone, Deserialize)]
pub struct RuleDispatcherConfig<'a> {
    pub(super) resolver: Option<&'a str>,
    pub(super) source: ResourceSource<'a>,
    pub(super) geoip: Option<ResourceSource<'a>>,
    pub(super) actions: BTreeMap<&'a str, Action<'a>>,
    pub(super) rules: BTreeMap<&'a str, &'a str>,
    pub(super) fallback: Action<'a>,
}

#[cfg_attr(not(feature = "plugins"), allow(dead_code))]
pub struct RuleDispatcherFactory<'a> {
    config: RuleDispatcherConfig<'a>,
}

pub(super) fn chain_requirements_from_action<'a, 'b>(
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

        if let ResourceSource::Literal { format, .. } = config.source {
            if RULE_DISPATCHER_ALLOWED_LITERAL_RESOURCE_TYPES
                .iter()
                .all(|&t| format != t)
            {
                return Err(ConfigError::InvalidParam {
                    plugin: name.to_string(),
                    field: "source",
                });
            }
        }

        if let Some(ResourceSource::Literal { .. }) = &config.geoip {
            return Err(ConfigError::InvalidParam {
                plugin: name.to_string(),
                field: "geoip",
            });
        }

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

#[cfg(feature = "plugins")]
pub(super) fn load_resolver(
    resolver: &str,
    set: &mut PartialPluginSet,
    plugin_name: &str,
) -> Weak<dyn Resolver> {
    use crate::plugin::null::Null;

    match set.get_or_create_resolver(plugin_name.to_string(), resolver) {
        Ok(resolver) => resolver,
        Err(e) => {
            set.errors.push(e);
            Arc::downgrade(&(Arc::new(Null) as _))
        }
    }
}

#[cfg(feature = "plugins")]
pub(super) fn load_action(
    action: &Action,
    set: &mut PartialPluginSet,
    plugin_name: &str,
) -> rd::Action {
    use crate::plugin::null::Null;
    use crate::plugin::reject::RejectHandler;

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

#[cfg(feature = "plugins")]
pub(super) fn validate_text<'t>(
    bytes: &'t [u8],
    plugin_name: &str,
    set: &mut PartialPluginSet<'_>,
) -> Cow<'t, str> {
    let ret = String::from_utf8_lossy(bytes);
    if let Cow::Owned(_) = ret {
        set.errors.push(LoadError::Resource {
            plugin: plugin_name.to_owned(),
            error: ResourceError::InvalidData,
        });
    }
    ret
}

#[cfg(feature = "plugins")]
fn load_additional_geoip_db(
    source: &ResourceSource<'_>,
    plugin_name: &str,
    set: &mut PartialPluginSet,
) -> Option<Arc<[u8]>> {
    let key = match source {
        ResourceSource::Key(key) => *key,
        ResourceSource::Literal { .. } => {
            set.errors.push(LoadError::ResourceTypeMismatch {
                plugin: plugin_name.into(),
                resource_key: "<literal>".into(),
                expected: &[RESOURCE_TYPE_GEOIP_COUNTRY],
                actual: "<literal>".into(),
            });
            return None;
        }
    };
    let metadata = match set.resource_registry.query_metadata(key) {
        Ok(metadata) => metadata,
        Err(e) => {
            set.errors.push(LoadError::Resource {
                plugin: plugin_name.into(),
                error: e,
            });
            return None;
        }
    };
    if metadata.r#type != RESOURCE_TYPE_GEOIP_COUNTRY {
        set.errors.push(LoadError::ResourceTypeMismatch {
            plugin: plugin_name.into(),
            resource_key: key.into(),
            expected: &[RESOURCE_TYPE_GEOIP_COUNTRY],
            actual: metadata.r#type.clone(),
        });
        return None;
    }
    match set.resource_registry.query_bytes(&metadata.handle) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            set.errors.push(LoadError::Resource {
                plugin: plugin_name.into(),
                error: e,
            });
            None
        }
    }
}

#[cfg(feature = "plugins")]
fn load_rule_set(
    source: ResourceSource<'_>,
    additional_geoip_db: Option<&ResourceSource<'_>>,
    action_map: &BTreeMap<&str, rd::ActionHandle>,
    rules: &BTreeMap<&str, &str>,
    plugin_name: &str,
    set: &mut PartialPluginSet,
) -> rd::RuleSet {
    let rule_action_map = rules
        .iter()
        .map(|(rule, action)| (*rule, action_map[*action]))
        .collect();
    let resource_key;
    let resource_type;
    match source {
        // TODO: more resource types
        ResourceSource::Key(key) => {
            resource_key = key;
            let metadata = match set.resource_registry.query_metadata(key) {
                Ok(metadata) => metadata,
                Err(e) => {
                    set.errors.push(LoadError::Resource {
                        plugin: plugin_name.into(),
                        error: e,
                    });
                    return Default::default();
                }
            };
            let bytes = match set.resource_registry.query_bytes(&metadata.handle) {
                Ok(bytes) => bytes,
                Err(e) => {
                    set.errors.push(LoadError::Resource {
                        plugin: plugin_name.into(),
                        error: e,
                    });
                    return Default::default();
                }
            };
            match metadata.r#type.as_str() {
                RESOURCE_TYPE_GEOIP_COUNTRY => {
                    match rd::RuleSet::build_dst_geoip_rule(
                        rules
                            .iter()
                            .map(|(rule, action)| (rule.to_string(), action_map[action])),
                        bytes,
                    ) {
                        Some(ruleset) => return ruleset,
                        // TODO: log ruleset build error
                        None => {
                            set.errors.push(LoadError::Resource {
                                plugin: plugin_name.into(),
                                error: ResourceError::InvalidData,
                            });
                            return Default::default();
                        }
                    }
                }
                RESOURCE_TYPE_QUANX_FILTER => {
                    let text = validate_text(&bytes, plugin_name, set);
                    match rd::RuleSet::load_quanx_filter(
                        text.lines(),
                        &rule_action_map,
                        additional_geoip_db
                            .and_then(|source| load_additional_geoip_db(source, plugin_name, set)),
                    ) {
                        Some(ruleset) => return ruleset,
                        // TODO: log ruleset build error
                        None => {
                            set.errors.push(LoadError::Resource {
                                plugin: plugin_name.into(),
                                error: ResourceError::InvalidData,
                            });
                            return Default::default();
                        }
                    }
                }
                format => resource_type = format,
            }
        }
        ResourceSource::Literal { format, text } => {
            resource_key = "<literal>";
            resource_type = format;
            match format {
                RESOURCE_TYPE_QUANX_FILTER => {
                    match rd::RuleSet::load_quanx_filter(
                        text.iter().flat_map(|t| t.lines()),
                        &rule_action_map,
                        additional_geoip_db
                            .and_then(|source| load_additional_geoip_db(source, plugin_name, set)),
                    ) {
                        Some(ruleset) => return ruleset,
                        // TODO: log ruleset build error
                        None => {
                            set.errors.push(LoadError::Resource {
                                plugin: plugin_name.into(),
                                error: ResourceError::InvalidData,
                            });
                            return Default::default();
                        }
                    }
                }
                _ => {}
            }
            // TODO: process text based rule literals here
        }
    }
    set.errors.push(LoadError::ResourceTypeMismatch {
        plugin: plugin_name.into(),
        resource_key: resource_key.to_string(),
        expected: &RULE_DISPATCHER_ALLOWED_RESOURCE_TYPES,
        actual: resource_type.to_string(),
    });
    Default::default()
}

impl<'de> Factory for RuleDispatcherFactory<'de> {
    #[cfg(feature = "plugins")]
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let mut builder = rd::RuleDispatcherBuilder::default();
        let plugin = Arc::new_cyclic(|weak| {
            set.stream_handlers
                .insert(plugin_name.clone(), weak.clone() as _);
            set.datagram_handlers
                .insert(plugin_name.clone(), weak.clone() as _);
            set.resolver.insert(plugin_name.clone(), weak.clone() as _);

            let action_map: BTreeMap<_, _> = self
                .config
                .actions
                .iter()
                .map(|(action_key, action_desc)| {
                    (
                        *action_key,
                        builder
                            .add_action(load_action(action_desc, set, &plugin_name))
                            // We have checked in the parse stage. Hopefully it will not panic.
                            .unwrap(),
                    )
                })
                .collect();

            let rule_set = load_rule_set(
                std::mem::replace(
                    &mut self.config.source,
                    ResourceSource::Literal {
                        format: Default::default(),
                        text: Default::default(),
                    },
                ),
                self.config.geoip.as_ref(),
                &action_map,
                &self.config.rules,
                &plugin_name,
                set,
            );

            let resolver = self
                .config
                .resolver
                .map(|resolver| load_resolver(resolver, set, &plugin_name));
            let fallback = load_action(&self.config.fallback, set, &plugin_name);
            let me = weak.clone();
            builder.set_resolver(resolver);
            builder.build(rule_set, fallback, me)
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
