use serde::Deserialize;
use serde_bytes::Bytes;

use crate::config::factory::*;
use crate::config::*;

#[cfg_attr(not(feature = "plugins"), allow(dead_code))]
#[derive(Deserialize)]
pub struct HttpProxyFactory<'a> {
    user: &'a Bytes,
    pass: &'a Bytes,
    tcp_next: &'a str,
}

impl<'de> HttpProxyFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        let tcp_next = config.tcp_next;
        Ok(ParsedPlugin {
            factory: config,
            requires: vec![Descriptor {
                descriptor: tcp_next,
                r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
            }],
            provides: vec![Descriptor {
                descriptor: name.to_string() + ".tcp",
                r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
            }],
            resources: vec![],
        })
    }
}

impl<'de> Factory for HttpProxyFactory<'de> {
    #[cfg(feature = "plugins")]
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        use crate::plugin::http_proxy;
        use crate::plugin::null::Null;

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
            http_proxy::HttpProxyOutboundFactory::new(
                Some((self.user, self.pass))
                    .filter(|(u, p)| !u.is_empty() && !p.is_empty())
                    .map(|(u, p)| (&**u, &**p)),
                tcp_next,
            )
        });
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name + ".tcp", factory);
        Ok(())
    }
}
