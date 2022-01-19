use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::flow::*;
use crate::plugin::null::Null;
use crate::plugin::redirect;

#[derive(Clone, Deserialize)]
pub struct RedirectFactory<'a> {
    dest: DestinationAddr,

    tcp_next: &'a str,
    udp_next: &'a str,
}

impl<'de> RedirectFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;

        Ok(ParsedPlugin {
            requires: vec![
                Descriptor {
                    descriptor: &config.tcp_next,
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                },
                Descriptor {
                    descriptor: &config.udp_next,
                    r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                },
            ],
            provides: vec![
                Descriptor {
                    descriptor: name.clone() + ".tcp",
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                },
                Descriptor {
                    descriptor: name.clone() + ".udp",
                    r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                },
            ],
            factory: config,
        })
    }
}

impl<'de> Factory for RedirectFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let tcp_factory = Arc::new_cyclic(|tcp_weak| {
            set.stream_outbounds
                .insert(plugin_name.clone() + ".tcp", tcp_weak.clone() as _);

            // Make sure all weak references are inserted into the set before loading any plugins
            let udp_factory = Arc::new_cyclic(|udp_weak| {
                set.datagram_outbounds
                    .insert(plugin_name.clone() + ".udp", udp_weak.clone() as _);

                let next = match set
                    .get_or_create_datagram_outbound(plugin_name.clone(), &self.udp_next)
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
                .insert(plugin_name.clone() + ".udp", udp_factory);

            let next = match set.get_or_create_stream_outbound(plugin_name.clone(), &self.tcp_next)
            {
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
            .insert(plugin_name + ".tcp", tcp_factory);
        Ok(())
    }
}
