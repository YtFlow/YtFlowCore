use crate::config::factory::*;
use crate::config::*;
use crate::plugin::{null::Null, vmess};

#[derive(Clone, Deserialize)]
pub struct VMessClientFactory<'a> {
    user_id: HumanRepr<uuid::Uuid>,
    tcp_next: &'a str,
}

impl<'de> VMessClientFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        Ok(ParsedPlugin {
            requires: vec![Descriptor {
                descriptor: config.tcp_next,
                r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
            }],
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
        })
    }
}

impl<'de> Factory for VMessClientFactory<'de> {
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
            vmess::VMessStreamOutboundFactory::new(*self.user_id.inner.as_bytes(), tcp_next)
        });
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name + ".tcp", factory);
        Ok(())
    }
}
