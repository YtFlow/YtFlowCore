use std::str::FromStr;

use http::uri::Scheme;
use http::Uri;
use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::host_resolver;

#[derive(Deserialize)]
struct DohSpecConfig<'a> {
    url: &'a str,
    next: &'a str,
}

struct DohSpec<'a> {
    url: Uri,
    next: &'a str,
}

#[derive(Deserialize)]
struct HostResolverConfig<'a> {
    #[serde(borrow)]
    doh: Vec<DohSpecConfig<'a>>,
    #[serde(borrow)]
    udp: Vec<&'a str>,
    #[serde(borrow)]
    tcp: Vec<&'a str>,
}

pub struct HostResolverFactory<'a> {
    doh: Vec<DohSpec<'a>>,
    udp: Vec<&'a str>,
    _tcp: Vec<&'a str>,
}

impl<'de> HostResolverFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: HostResolverConfig = parse_param(name, param)?;

        let doh = config
            .doh
            .iter()
            .map(|d| {
                Uri::from_str(d.url)
                    .ok()
                    .filter(|url| {
                        url.scheme() == Some(&Scheme::HTTPS) || url.scheme() == Some(&Scheme::HTTP)
                    })
                    .filter(|url| url.host().is_some())
                    .map(|url| DohSpec { url, next: d.next })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| ConfigError::InvalidParam {
                plugin: name.clone(),
                field: "doh.url",
            })?;

        let requires = config
            .udp
            .iter()
            .map(|c| Descriptor {
                descriptor: *c,
                r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
            })
            .chain(config.tcp.iter().map(|c| Descriptor {
                descriptor: *c,
                r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
            }))
            .chain(config.doh.iter().map(|c| Descriptor {
                descriptor: c.next,
                r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
            }))
            .collect();
        Ok(ParsedPlugin {
            factory: HostResolverFactory {
                doh,
                udp: config.udp,
                _tcp: config.tcp,
            },
            requires,
            provides: vec![Descriptor {
                descriptor: name.to_string() + ".resolver",
                r#type: AccessPointType::RESOLVER,
            }],
            resources: vec![],
        })
    }
}

impl<'de> Factory for HostResolverFactory<'de> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let mut errors = vec![];
        let factory = Arc::new_cyclic(|weak| {
            set.resolver
                .insert(plugin_name.to_string() + ".resolver", weak.clone() as _);
            let doh = self
                .doh
                .iter()
                .map(|d| {
                    let next = set.get_or_create_stream_outbound(plugin_name.clone(), d.next);
                    (d.url.clone(), next)
                })
                .filter_map(|(url, next)| match next {
                    Ok(next) => Some((url, next)),
                    Err(e) => {
                        errors.push(e);
                        None
                    }
                })
                .map(|(url, next)| {
                    host_resolver::doh_adapter::DohDatagramAdapterFactory::new(url, next)
                })
                .collect::<Vec<_>>();
            let udp = self
                .udp
                .iter()
                .map(|c| set.get_or_create_datagram_outbound(plugin_name.clone(), *c))
                .filter_map(|d| match d {
                    Ok(d) => Some(d),
                    Err(e) => {
                        errors.push(e);
                        None
                    }
                });
            host_resolver::HostResolver::new(udp, doh)
        });
        set.errors.extend(errors);
        set.fully_constructed
            .resolver
            .insert(plugin_name + ".resolver", factory);
        Ok(())
    }
}
