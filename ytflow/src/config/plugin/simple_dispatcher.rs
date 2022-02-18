use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::reject::RejectHandler;
use crate::plugin::simple_dispatcher as sd;

#[derive(Clone, Deserialize)]
pub struct Rule<'a> {
    src: sd::Condition,
    dst: sd::Condition,
    is_udp: bool,
    next: &'a str,
}

#[derive(Clone, Deserialize)]
pub struct SimpleDispatcherFactory<'a> {
    rules: Vec<Rule<'a>>,
    fallback_tcp: &'a str,
    fallback_udp: &'a str,
}

impl<'de> SimpleDispatcherFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        let mut requires = Vec::with_capacity(config.rules.len() + 2);
        requires.push(Descriptor {
            descriptor: config.fallback_tcp,
            r#type: AccessPointType::STREAM_HANDLER,
        });
        requires.push(Descriptor {
            descriptor: config.fallback_udp,
            r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
        });
        requires.extend(config.rules.iter().map(|r| {
            if r.is_udp {
                Descriptor {
                    descriptor: r.next,
                    r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
                }
            } else {
                Descriptor {
                    descriptor: r.next,
                    r#type: AccessPointType::STREAM_HANDLER,
                }
            }
        }));
        Ok(ParsedPlugin {
            factory: config,
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
            ],
        })
    }
}

impl<'de> Factory for SimpleDispatcherFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let udp_factory = Arc::new_cyclic(|weak| {
            set.datagram_handlers
                .insert(plugin_name.clone() + ".udp", weak.clone() as _);

            let tcp_factory = Arc::new_cyclic(|weak| {
                set.stream_handlers
                    .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
                let fallback = match set
                    .get_or_create_stream_handler(plugin_name.clone(), self.fallback_tcp)
                {
                    Ok(t) => t,
                    Err(e) => {
                        set.errors.push(e);
                        Arc::downgrade(&(Arc::new(RejectHandler) as _))
                    }
                };
                let mut ret = sd::SimpleStreamDispatcher {
                    rules: Vec::with_capacity(self.rules.iter().filter(|r| !r.is_udp).count()),
                    fallback,
                };
                for rule in self.rules.iter().filter(|r| !r.is_udp) {
                    let next =
                        match set.get_or_create_stream_handler(plugin_name.clone(), rule.next) {
                            Ok(t) => t,
                            Err(e) => {
                                set.errors.push(e);
                                Arc::downgrade(&(Arc::new(RejectHandler) as _))
                            }
                        };
                    ret.rules.push(sd::Rule {
                        src_cond: rule.src.clone(),
                        dst_cond: rule.dst.clone(),
                        next,
                    });
                }
                ret
            });
            set.fully_constructed
                .stream_handlers
                .insert(plugin_name.clone() + ".tcp", tcp_factory);

            let fallback =
                match set.get_or_create_datagram_handler(plugin_name.clone(), self.fallback_udp) {
                    Ok(u) => u,
                    Err(e) => {
                        set.errors.push(e);
                        Arc::downgrade(&(Arc::new(RejectHandler) as _))
                    }
                };
            let mut ret = sd::SimpleDatagramDispatcher {
                rules: Vec::with_capacity(self.rules.iter().filter(|r| r.is_udp).count()),
                fallback,
            };
            for rule in self.rules.iter().filter(|r| r.is_udp) {
                let next = match set.get_or_create_datagram_handler(plugin_name.clone(), rule.next)
                {
                    Ok(t) => t,
                    Err(e) => {
                        set.errors.push(e);
                        Arc::downgrade(&(Arc::new(RejectHandler) as _))
                    }
                };
                ret.rules.push(sd::Rule {
                    src_cond: rule.src.clone(),
                    dst_cond: rule.dst.clone(),
                    next,
                });
            }
            ret
        });

        set.fully_constructed
            .datagram_handlers
            .insert(plugin_name + ".udp", udp_factory);
        Ok(())
    }
}
