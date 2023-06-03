use serde::Deserialize;
use serde_bytes::Bytes;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::{null::Null, reject::RejectHandler, socks5};

#[derive(Clone, Deserialize)]
struct Socks5Info<'a> {
    #[serde(borrow)]
    user: &'a Bytes,
    #[serde(borrow)]
    pass: &'a Bytes,
}

#[derive(Deserialize)]
pub struct Socks5ServerFactory<'a> {
    tcp_next: &'a str,
    udp_next: &'a str,
    #[serde(flatten)]
    #[serde(borrow)]
    socks5: Option<Socks5Info<'a>>,
}

#[derive(Deserialize)]
pub struct Socks5ClientFactory<'a> {
    tcp_next: &'a str,
    udp_next: &'a str,
    #[serde(flatten)]
    #[serde(borrow)]
    socks5: Option<Socks5Info<'a>>,
}

impl<'de> Socks5ServerFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        Ok(ParsedPlugin {
            requires: vec![
                Descriptor {
                    descriptor: config.tcp_next,
                    r#type: AccessPointType::STREAM_HANDLER,
                },
                Descriptor {
                    descriptor: config.udp_next,
                    r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
                },
            ],
            provides: vec![
                Descriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::STREAM_HANDLER,
                },
                // TODO:
                // Descriptor {
                //     descriptor: name.to_string() + ".udp",
                //     r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
                // },
            ],
            factory: config,
            resources: vec![],
        })
    }
}

impl<'de> Socks5ClientFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        Ok(ParsedPlugin {
            requires: vec![
                Descriptor {
                    descriptor: config.tcp_next,
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                },
                Descriptor {
                    descriptor: config.udp_next,
                    r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                },
            ],
            provides: vec![
                Descriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                },
                // TODO:
                // Descriptor {
                //     descriptor: name.to_string() + ".udp",
                //     r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                // },
            ],
            factory: config,
            resources: vec![],
        })
    }
}

impl<'de> Factory for Socks5ServerFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let factory = Arc::new_cyclic(|weak| {
            set.stream_handlers
                .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
            let tcp_next =
                match set.get_or_create_stream_handler(plugin_name.clone(), self.tcp_next) {
                    Ok(t) => t,
                    Err(e) => {
                        set.errors.push(e);
                        Arc::downgrade(&(Arc::new(RejectHandler) as _))
                    }
                };
            socks5::Socks5Handler::new(
                self.socks5.as_ref().map(|s| (&**s.user, &**s.pass)),
                tcp_next,
            )
        });
        set.fully_constructed
            .stream_handlers
            .insert(plugin_name + ".tcp", factory);
        Ok(())
    }
}

impl<'de> Factory for Socks5ClientFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let factory = Arc::new_cyclic(|weak| {
            set.stream_outbounds
                .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
            let tcp_next =
                match set.get_or_create_stream_outbound(plugin_name.clone(), self.tcp_next) {
                    Ok(t) => t,
                    Err(e) => {
                        set.errors.push(e);
                        Arc::downgrade(&(Arc::new(Null) as _))
                    }
                };
            socks5::Socks5Outbound::new(
                self.socks5.as_ref().map(|s| (&**s.user, &**s.pass)),
                tcp_next,
            )
        });
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name + ".tcp", factory);
        Ok(())
    }
}
