use std::sync::Weak;

use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::flow::*;
use crate::plugin::null::Null;
use crate::plugin::reject::RejectHandler;
use crate::plugin::resolve_dest;

#[derive(Clone, Deserialize)]
pub struct ResolveDestFactory<'a> {
    resolver: &'a str,
    reverse: bool,
    tcp_next: Option<&'a str>,
    udp_next: Option<&'a str>,
}

impl<'de> ResolveDestFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        if let (None, None) = (&config.tcp_next, &config.udp_next) {
            return Err(ConfigError::InvalidParam {
                plugin: name.to_string(),
                field: "tcp or udp",
            });
        }
        Ok(ParsedPlugin {
            factory: config.clone(),
            requires: config
                .tcp_next
                .iter()
                .map(|t| Descriptor {
                    descriptor: *t,
                    r#type: AccessPointType::STREAM_HANDLER,
                })
                .chain(config.udp_next.iter().map(|u| Descriptor {
                    descriptor: *u,
                    r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
                }))
                .collect(),
            provides: config
                .tcp_next
                .iter()
                .map(|_| Descriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::STREAM_HANDLER,
                })
                .chain(config.udp_next.iter().map(|_| Descriptor {
                    descriptor: name.to_string() + ".udp",
                    r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
                }))
                .collect(),
        })
    }
}

fn create_tcp<
    T: StreamHandler + 'static,
    C: FnOnce(Weak<dyn StreamHandler>, Weak<dyn Resolver>) -> T,
    A: FnOnce(&mut PartialPluginSet),
>(
    resolver: &str,
    tcp_next: Option<&str>,
    plugin_name: String,
    set: &mut PartialPluginSet,
    create_val: C,
    after_weak: A,
) {
    let tcp_next = match tcp_next {
        Some(tcp_next) => tcp_next,
        None => {
            after_weak(set);
            return;
        }
    };
    let factory = Arc::new_cyclic(|weak| {
        set.stream_handlers
            .insert(plugin_name.clone() + ".tcp", weak.clone() as _);

        after_weak(set);

        let tcp_next = match set.get_or_create_stream_handler(plugin_name.clone(), tcp_next) {
            Ok(tcp_next) => tcp_next,
            Err(e) => {
                set.errors.push(e);
                Arc::downgrade(&(Arc::new(RejectHandler) as _))
            }
        };
        let resolver = match set.get_or_create_resolver(plugin_name.clone(), resolver) {
            Ok(resolver) => resolver,
            Err(e) => {
                set.errors.push(e);
                Arc::downgrade(&(Arc::new(Null) as _))
            }
        };
        create_val(tcp_next, resolver)
    });
    set.fully_constructed
        .stream_handlers
        .insert(plugin_name + ".tcp", factory as _);
}

fn create_udp<
    T: DatagramSessionHandler + 'static,
    C: FnOnce(Weak<dyn DatagramSessionHandler>, Weak<dyn Resolver>) -> T,
    A: FnOnce(&mut PartialPluginSet),
>(
    resolver: &str,
    udp_next: Option<&str>,
    plugin_name: String,
    set: &mut PartialPluginSet,
    create_val: C,
    after_weak: A,
) {
    let udp_next = match udp_next {
        Some(udp_next) => udp_next,
        None => {
            after_weak(set);
            return;
        }
    };

    let factory = Arc::new_cyclic(|weak| {
        set.datagram_handlers
            .insert(plugin_name.clone() + ".udp", weak.clone() as _);

        after_weak(set);

        let udp_next = match set.get_or_create_datagram_handler(plugin_name.clone(), udp_next) {
            Ok(udp_next) => udp_next,
            Err(e) => {
                set.errors.push(e);
                Arc::downgrade(&(Arc::new(RejectHandler) as _))
            }
        };
        let resolver = match set.get_or_create_resolver(plugin_name.clone(), resolver) {
            Ok(resolver) => resolver,
            Err(e) => {
                set.errors.push(e);
                Arc::downgrade(&(Arc::new(Null) as _))
            }
        };
        create_val(udp_next, resolver)
    });
    set.fully_constructed
        .datagram_handlers
        .insert(plugin_name.clone() + ".udp", factory as _);
}

impl<'de> Factory for ResolveDestFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        if self.reverse {
            create_tcp(
                self.resolver,
                self.tcp_next,
                plugin_name.clone(),
                set,
                |next, resolver| resolve_dest::StreamReverseResolver { resolver, next },
                |set| {
                    create_udp(
                        self.resolver,
                        self.udp_next,
                        plugin_name.clone(),
                        set,
                        |next, resolver| resolve_dest::DatagramReverseResolver { resolver, next },
                        |_| {},
                    );
                },
            );
        } else {
            create_tcp(
                self.resolver,
                self.tcp_next,
                plugin_name.clone(),
                set,
                |next, resolver| resolve_dest::StreamForwardResolver { resolver, next },
                |set| {
                    create_udp(
                        self.resolver,
                        self.udp_next,
                        plugin_name.clone(),
                        set,
                        |next, resolver| resolve_dest::DatagramForwardResolver { resolver, next },
                        |_| {},
                    );
                },
            );
        }

        Ok(())
    }
}
