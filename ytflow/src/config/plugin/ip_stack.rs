use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::ip_stack;
use crate::plugin::reject::RejectHandler;

#[derive(Clone, Deserialize)]
pub struct IpStackFactory<'a> {
    tun: &'a str,
    tcp_next: &'a str,
    udp_next: &'a str,
}

impl<'de> IpStackFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        Ok(ParsedPlugin {
            factory: config.clone(),
            requires: vec![
                Descriptor {
                    descriptor: config.tun,
                    r#type: AccessPointType::TUN,
                },
                Descriptor {
                    descriptor: config.tcp_next,
                    r#type: AccessPointType::STREAM_HANDLER,
                },
                Descriptor {
                    descriptor: config.udp_next,
                    r#type: AccessPointType::DATAGRAM_SESSION_HANDLER,
                },
            ],
            provides: vec![],
        })
    }
}

impl<'de> Factory for IpStackFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let tun = set.get_or_create_tun(plugin_name.clone(), self.tun)?;
        let tcp_next = set
            .get_or_create_stream_handler(plugin_name.clone(), self.tcp_next)
            .unwrap_or_else(|e| {
                set.errors.push(e);
                Arc::downgrade(&(Arc::new(RejectHandler) as _))
            });
        let udp_next = set
            .get_or_create_datagram_handler(plugin_name.clone(), self.udp_next)
            .unwrap_or_else(|e| {
                set.errors.push(e);
                Arc::downgrade(&(Arc::new(RejectHandler) as _))
            });
        let tun = match tun.upgrade() {
            Some(tun) => tun,
            None => {
                return Err(LoadError::UnsatisfiedStrongReference {
                    initiator: plugin_name,
                    descriptor: self.tun.to_string(),
                })
            }
        };
        ip_stack::run(tun, tcp_next, udp_next);
        Ok(())
    }
}
