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
        let config: Self =
            parse_param(param).ok_or_else(|| ConfigError::ParseParam(name.to_string()))?;
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
                    r#type: AccessPointType::StreamHandler,
                })
                .chain(config.udp_next.iter().map(|u| Descriptor {
                    descriptor: *u,
                    r#type: AccessPointType::DatagramSessionHandler,
                }))
                .collect(),
            provides: config
                .tcp_next
                .iter()
                .map(|_| Descriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::StreamHandler,
                })
                .chain(config.udp_next.iter().map(|_| Descriptor {
                    descriptor: name.to_string() + ".udp",
                    r#type: AccessPointType::DatagramSessionHandler,
                }))
                .collect(),
        })
    }
}

fn create_tcp<
    T: StreamHandler + 'static,
    C: FnOnce(Weak<dyn StreamHandler>, Weak<dyn Resolver>) -> T,
>(
    resolver: &str,
    tcp_next: &str,
    plugin_name: String,
    set: &mut PartialPluginSet,
    callback: C,
) {
    let factory = Arc::new_cyclic(|weak| {
        set.stream_handlers
            .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
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
        callback(tcp_next, resolver)
    });
    set.fully_constructed
        .stream_handlers
        .insert(plugin_name.clone() + ".tcp", factory as _);
}

fn create_udp<
    T: DatagramSessionHandler + 'static,
    C: FnOnce(Weak<dyn DatagramSessionHandler>, Weak<dyn Resolver>) -> T,
>(
    resolver: &str,
    udp_next: &str,
    plugin_name: String,
    set: &mut PartialPluginSet,
    callback: C,
) {
    let factory = Arc::new_cyclic(|weak| {
        set.datagram_handlers
            .insert(plugin_name.clone() + ".udp", weak.clone() as _);
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
        callback(udp_next, resolver)
    });
    set.fully_constructed
        .datagram_handlers
        .insert(plugin_name.clone() + ".udp", factory as _);
}

impl<'de> Factory for ResolveDestFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        if let (Some(tcp_next), false) = (self.tcp_next, self.reverse) {
            create_tcp(
                self.resolver,
                tcp_next,
                plugin_name.clone(),
                set,
                |next, resolver| resolve_dest::StreamForwardResolver { resolver, next },
            );
        }
        if let (Some(tcp_next), true) = (self.tcp_next, self.reverse) {
            create_tcp(
                self.resolver,
                tcp_next,
                plugin_name.clone(),
                set,
                |next, resolver| resolve_dest::StreamReverseResolver { resolver, next },
            );
        }
        if let (Some(udp_next), false) = (self.udp_next, self.reverse) {
            create_udp(
                self.resolver,
                udp_next,
                plugin_name.clone(),
                set,
                |next, resolver| resolve_dest::DatagramForwardResolver { resolver, next },
            );
        }
        if let (Some(udp_next), true) = (self.udp_next, self.reverse) {
            create_udp(
                self.resolver,
                udp_next,
                plugin_name.clone(),
                set,
                |next, resolver| resolve_dest::DatagramReverseResolver { resolver, next },
            );
        }
        Ok(())
    }
}
