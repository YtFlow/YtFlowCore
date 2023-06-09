use http::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::null::Null;
use crate::plugin::ws;

fn default_path() -> &'static str {
    "/"
}

#[derive(Deserialize)]
pub struct WsClientConfig<'a> {
    host: Option<&'a str>,
    #[serde(default = "default_path")]
    path: &'a str,
    #[serde(borrow)]
    headers: HashMap<&'a str, &'a str>,
    next: &'a str,
}

pub struct WsClientFactory<'a> {
    host: Option<&'a str>,
    path: &'a str,
    headers: HeaderMap,
    next: &'a str,
}

impl<'de> WsClientFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: WsClientConfig = parse_param(name, param)?;
        let next = config.next;
        let mut headers = HeaderMap::with_capacity(config.headers.len());
        for (k, v) in config.headers {
            let Ok(header) = HeaderName::from_bytes(k.as_bytes()) else {
                return Err(ConfigError::InvalidParam { plugin: name.clone(), field: "headers_header" });
            };
            let Ok(value) = HeaderValue::from_str(v) else {
                return Err(ConfigError::InvalidParam { plugin: name.clone(), field: "headers_value" });
            };
            headers.insert(header, value);
        }
        Ok(ParsedPlugin {
            factory: WsClientFactory {
                host: config.host,
                path: config.path,
                headers,
                next,
            },
            requires: vec![Descriptor {
                descriptor: next,
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

impl<'de> Factory for WsClientFactory<'de> {
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

            ws::WebSocketStreamOutboundFactory::new(
                self.host.map(|s| s.to_owned()),
                self.path.to_string(),
                std::mem::take(&mut self.headers),
                next,
            )
        });
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name + ".tcp", factory);
        Ok(())
    }
}
