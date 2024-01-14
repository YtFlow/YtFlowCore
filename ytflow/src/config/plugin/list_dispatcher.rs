use super::rule_dispatcher::*;
use crate::config::factory::*;
use crate::config::*;
#[cfg(feature = "plugins")]
use crate::plugin::rule_dispatcher as rd;
use crate::resource::RESOURCE_TYPE_SURGE_DOMAINSET;

static LIST_DISPATCHER_ALLOWED_RESOURCE_TYPES: [&str; 1] = [RESOURCE_TYPE_SURGE_DOMAINSET];

#[derive(Clone, Deserialize)]
pub struct ListDispatcherConfig<'a> {
    pub(super) resolver: Option<&'a str>,
    pub(super) source: ResourceSource<'a>,
    // TODO: pub(super) geoip: ResourceSource<'a>,
    pub(super) action: Action<'a>,
    pub(super) fallback: Action<'a>,
}

#[cfg_attr(not(feature = "plugins"), allow(dead_code))]
pub struct ListDispatcherFactory<'a> {
    config: ListDispatcherConfig<'a>,
}

impl<'de> ListDispatcherFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: ListDispatcherConfig = parse_param(name, param)?;

        if let ResourceSource::Literal { format, .. } = config.source {
            if LIST_DISPATCHER_ALLOWED_RESOURCE_TYPES
                .iter()
                .all(|&t| format != t)
            {
                return Err(ConfigError::InvalidParam {
                    plugin: name.to_string(),
                    field: "source",
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
            .chain(chain_requirements_from_action(&config.action))
            .chain(chain_requirements_from_action(&config.fallback))
            .collect();
        Ok(ParsedPlugin {
            resources: match config.source {
                ResourceSource::Key(key) => Some(RequiredResource {
                    key,
                    allowed_types: &LIST_DISPATCHER_ALLOWED_RESOURCE_TYPES,
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
fn load_rule_set(
    source: ResourceSource<'_>,
    action: rd::ActionHandle,
    plugin_name: &str,
    set: &mut PartialPluginSet,
) -> rd::RuleSet {
    use crate::resource::ResourceError;

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
                RESOURCE_TYPE_SURGE_DOMAINSET => {
                    let text = validate_text(&bytes, &plugin_name, set);
                    match rd::RuleSet::build_surge_domainset(text.lines(), action) {
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
                RESOURCE_TYPE_SURGE_DOMAINSET => {
                    match rd::RuleSet::build_surge_domainset(
                        text.iter().flat_map(|s| s.lines()),
                        action,
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
        expected: &LIST_DISPATCHER_ALLOWED_RESOURCE_TYPES,
        actual: resource_type.to_string(),
    });
    Default::default()
}

impl<'de> Factory for ListDispatcherFactory<'de> {
    #[cfg(feature = "plugins")]
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let mut builder = rd::RuleDispatcherBuilder::default();
        let plugin = Arc::new_cyclic(|weak| {
            set.stream_handlers
                .insert(plugin_name.clone(), weak.clone() as _);
            set.datagram_handlers
                .insert(plugin_name.clone(), weak.clone() as _);
            set.resolver.insert(plugin_name.clone(), weak.clone() as _);

            let action = builder
                .add_action(load_action(&self.config.action, set, &plugin_name))
                .expect("one action for list dispatcher should not exceed the limit");

            let rule_set = load_rule_set(
                std::mem::replace(
                    &mut self.config.source,
                    ResourceSource::Literal {
                        format: Default::default(),
                        text: Default::default(),
                    },
                ),
                action,
                &plugin_name,
                set,
            );

            let fallback = load_action(&self.config.fallback, set, &plugin_name);
            let resolver = self
                .config
                .resolver
                .clone()
                .map(|resolver| load_resolver(resolver, set, &plugin_name));
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
