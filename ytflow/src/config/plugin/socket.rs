use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;

fn default_bind_addr_v4() -> Option<HumanRepr<SocketAddrV4>> {
    Some(HumanRepr {
        inner: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    })
}

fn default_bind_addr_v6() -> Option<HumanRepr<SocketAddrV6>> {
    Some(HumanRepr {
        inner: SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0),
    })
}

#[cfg_attr(not(feature = "plugins"), allow(dead_code))]
#[derive(Clone, Deserialize)]
pub struct SocketFactory<'a> {
    resolver: &'a str,
    #[serde(default = "default_bind_addr_v4")]
    bind_addr_v4: Option<HumanRepr<SocketAddrV4>>,
    #[serde(default = "default_bind_addr_v6")]
    bind_addr_v6: Option<HumanRepr<SocketAddrV6>>,
}

impl<'de> SocketFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        Ok(ParsedPlugin {
            factory: config.clone(),
            requires: vec![Descriptor {
                descriptor: config.resolver,
                r#type: AccessPointType::RESOLVER,
            }],
            provides: vec![Descriptor {
                descriptor: name.clone(),
                r#type: AccessPointType::STREAM_OUTBOUND_FACTORY
                    | AccessPointType::DATAGRAM_SESSION_FACTORY,
            }],
            resources: vec![],
        })
    }
}

impl<'de> Factory for SocketFactory<'de> {
    #[cfg(feature = "plugins")]
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        use crate::plugin::null::Null;
        use crate::plugin::socket;

        let factory = Arc::new_cyclic(|weak| {
            set.stream_outbounds
                .insert(plugin_name.clone(), weak.clone() as _);
            set.datagram_outbounds
                .insert(plugin_name.clone(), weak.clone() as _);
            let resolver = match set.get_or_create_resolver(plugin_name.clone(), self.resolver) {
                Ok(resolver) => resolver,
                Err(e) => {
                    set.errors.push(e);
                    Arc::downgrade(&(Arc::new(Null) as _))
                }
            };
            socket::SocketOutboundFactory {
                resolver,
                bind_addr_v4: self.bind_addr_v4.clone().map(|h| h.inner),
                bind_addr_v6: self.bind_addr_v6.clone().map(|h| h.inner),
            }
        });
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name.clone() + ".tcp", factory.clone());
        set.fully_constructed
            .datagram_outbounds
            .insert(plugin_name + ".udp", factory);
        Ok(())
    }
}
