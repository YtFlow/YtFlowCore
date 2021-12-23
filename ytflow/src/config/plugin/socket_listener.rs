use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::{reject::RejectHandler, socket};

#[derive(Deserialize)]
pub struct SocketListenerFactory<'a> {
    #[serde(borrow)]
    #[serde(default)]
    tcp_listen: Vec<&'a str>,
    #[serde(borrow)]
    #[serde(default)]
    udp_listen: Vec<&'a str>,
    tcp_next: &'a str,
    udp_next: &'a str,
}

impl<'de> SocketListenerFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { param, name, .. } = plugin;
        let config: Self =
            parse_param(param).ok_or_else(|| ConfigError::ParseParam(name.to_string()))?;
        Ok(ParsedPlugin {
            requires: (!config.tcp_listen.is_empty())
                .then(|| Descriptor {
                    descriptor: config.tcp_next,
                    r#type: AccessPointType::STREAM_HANDLER,
                })
                .into_iter()
                .chain((!config.udp_listen.is_empty()).then(|| Descriptor {
                    descriptor: config.udp_next,
                    r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
                }))
                .collect(),
            factory: config,
            provides: vec![],
        })
    }
}

impl<'de> Factory for SocketListenerFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        if !self.tcp_listen.is_empty() {
            let tcp_next = set
                .get_or_create_stream_handler(plugin_name.clone(), self.tcp_next)
                .unwrap_or_else(|e| {
                    set.errors.push(e);
                    Arc::downgrade(&(Arc::new(RejectHandler) as _))
                });
            for tcp_listen in &self.tcp_listen {
                socket::listen_tcp(tcp_next.clone(), (*tcp_listen).to_owned());
            }
        }
        if !self.udp_listen.is_empty() {
            let udp_next = set
                .get_or_create_datagram_handler(plugin_name, self.udp_next)
                .unwrap_or_else(|e| {
                    set.errors.push(e);
                    Arc::downgrade(&(Arc::new(RejectHandler) as _))
                });
            for udp_listen in &self.udp_listen {
                socket::listen_udp(udp_next.clone(), (*udp_listen).to_owned());
            }
        }
        Ok(())
    }
}
