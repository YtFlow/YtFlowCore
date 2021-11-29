use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::null::Null;
use crate::plugin::tls;

#[derive(Deserialize)]
pub struct TlsFactory<'a> {
    sni: &'a str,
    next: &'a str,
}

impl<'de> TlsFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self =
            parse_param(param).ok_or_else(|| ConfigError::ParseParam(name.to_string()))?;
        let next = config.next;
        Ok(ParsedPlugin {
            factory: config,
            requires: vec![Descriptor {
                descriptor: next,
                r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
            }],
            provides: vec![Descriptor {
                descriptor: name.to_string() + ".tcp",
                r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
            }],
        })
    }
}

impl<'de> Factory for TlsFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let factory = Arc::new_cyclic(|weak| {
            set.stream_outbounds
                .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
            let next = match set.get_or_create_stream_outbound(plugin_name.clone(), self.next) {
                Ok(next) => next,
                Err(e) => {
                    set.errors.push(e);
                    Arc::downgrade(&(Arc::new(Null)))
                }
            };
            let _sni = self.sni;
            tls::SslStreamFactory::new(next)
        });
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name, factory);
        Ok(())
    }
}
