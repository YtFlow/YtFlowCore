use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::flow::*;
use crate::plugin::null::Null;
use crate::plugin::redirect;

#[derive(Clone, Deserialize)]
pub struct RedirectFactory<'a> {
    dest: DestinationAddr,

    tcp_next: Option<&'a str>,
    udp_next: Option<&'a str>,
}

impl<'de> RedirectFactory<'de> {
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
                    r#type: AccessPointType::StreamOutboundFactory,
                })
                .chain(config.udp_next.iter().map(|u| Descriptor {
                    descriptor: *u,
                    r#type: AccessPointType::DatagramSessionFactory,
                }))
                .collect(),
            provides: config
                .tcp_next
                .iter()
                .map(|_| Descriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::StreamOutboundFactory,
                })
                .chain(config.udp_next.iter().map(|_| Descriptor {
                    descriptor: name.to_string() + ".udp",
                    r#type: AccessPointType::DatagramSessionFactory,
                }))
                .collect(),
        })
    }
}

impl<'de> Factory for RedirectFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        if let Some(tcp_next) = &self.tcp_next {
            let factory = Arc::new_cyclic(|weak| {
                set.stream_outbounds
                    .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
                let next = match set.get_or_create_stream_outbound(plugin_name.clone(), tcp_next) {
                    Ok(t) => t,
                    Err(e) => {
                        set.errors.push(e);
                        Arc::downgrade(&(Arc::new(Null)))
                    }
                };
                let dest = self.dest.clone();
                redirect::StreamRedirectOutboundFactory {
                    remote_peer: move || dest.clone(),
                    next,
                }
            });
            set.fully_constructed
                .stream_outbounds
                .insert(plugin_name.clone() + ".tcp", factory);
        }
        if let Some(udp_next) = &self.udp_next {
            let factory = Arc::new_cyclic(|weak| {
                set.datagram_outbounds
                    .insert(plugin_name.clone() + ".udp", weak.clone() as _);
                let next = match set.get_or_create_datagram_outbound(plugin_name.clone(), udp_next)
                {
                    Ok(t) => t,
                    Err(e) => {
                        set.errors.push(e);
                        Arc::downgrade(&(Arc::new(Null)))
                    }
                };
                let dest = self.dest.clone();
                redirect::DatagramSessionRedirectFactory {
                    remote_peer: move || dest.clone(),
                    next,
                }
            });
            set.fully_constructed
                .datagram_outbounds
                .insert(plugin_name.clone() + ".udp", factory);
        }
        Ok(())
    }
}
