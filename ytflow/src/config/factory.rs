use std::collections::hash_map::{Entry, HashMap};
use std::ops::Deref;
pub(super) use std::sync::Arc;

use bitflags::bitflags;
pub(super) use serde::{Deserialize, Serialize};

pub(super) use super::param::*;
pub(super) use super::plugin::Plugin;
pub(super) use super::set::*;
use super::*;

bitflags! {
    #[derive(Deserialize, Serialize)]
    pub struct AccessPointType: u8 {
        const STREAM_HANDLER           = 0b00000001;
        const DATAGRAM_SESSION_HANDLER = 0b00000010;
        const STREAM_OUTBOUND_FACTORY  = 0b00000100;
        const DATAGRAM_SESSION_FACTORY = 0b00001000;
        const RESOLVER                 = 0b00010000;
        const TUN                      = 0b00100000;
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor<D: Deref<Target = str>> {
    pub descriptor: D,
    pub r#type: AccessPointType,
}

pub type DemandDescriptor<'de> = Descriptor<&'de str>;
pub type ProvideDescriptor = Descriptor<String>;

pub(super) struct ParsedPlugin<'de, F: Factory> {
    pub(super) factory: F,
    pub(super) requires: Vec<DemandDescriptor<'de>>,
    pub(super) provides: Vec<ProvideDescriptor>,
}

pub(super) trait Factory {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet<'_>) -> LoadResult<()>;
}

impl<'de, 'f> Factory for Box<dyn Factory + 'f> {
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        (&mut **self).load(plugin_name, set)
    }
}

pub(super) fn create_factory_from_plugin(
    plugin: &'_ Plugin,
) -> ConfigResult<ParsedPlugin<'_, Box<dyn Factory + '_>>> {
    let no_such_type_err = Err(ConfigError::NoPluginType {
        initiator: plugin.name.clone(),
        r#type: plugin.plugin.clone(),
        version: plugin.plugin_version,
    });
    // All plugins are using v0 config at this moment;
    if plugin.plugin_version != 0 {
        return no_such_type_err;
    }
    fn box_result<'de, 'f, F: Factory + 'f>(
        r: ConfigResult<ParsedPlugin<'de, F>>,
    ) -> ConfigResult<ParsedPlugin<'de, Box<dyn Factory + 'f>>> {
        let ParsedPlugin {
            factory,
            requires,
            provides,
        } = r?;
        Ok(ParsedPlugin {
            factory: Box::new(factory),
            requires,
            provides,
        })
    }

    use plugin::*;
    match &*plugin.plugin {
        "reject" => box_result(RejectFactory::parse(plugin)),
        "null" => box_result(NullFactory::parse(plugin)),
        "ip-stack" => box_result(IpStackFactory::parse(plugin)),
        "socket-listener" => box_result(SocketListenerFactory::parse(plugin)),
        "vpn-tun" => box_result(VpnTunFactory::parse(plugin)),
        "host-resolver" => box_result(HostResolverFactory::parse(plugin)),
        "fake-ip" => box_result(FakeIpFactory::parse(plugin)),
        "system-resolver" => box_result(SystemResolverFactory::parse(plugin)),
        "switch" => box_result(SwitchFactory::parse(plugin)),
        "dns-server" => box_result(DnsServerFactory::parse(plugin)),
        "socks5-server" => box_result(Socks5ServerFactory::parse(plugin)),
        "http-obfs-server" => box_result(HttpObfsServerFactory::parse(plugin)),
        "resolve-dest" => box_result(ResolveDestFactory::parse(plugin)),
        "simple-dispatcher" => box_result(SimpleDispatcherFactory::parse(plugin)),
        "forward" => box_result(ForwardFactory::parse(plugin)),
        "dyn-outbound" => box_result(DynOutboundFactory::parse(plugin)),
        "shadowsocks-client" => box_result(ShadowsocksFactory::parse(plugin)),
        "socks5-client" => box_result(Socks5ClientFactory::parse(plugin)),
        "http-proxy-client" => box_result(HttpProxyFactory::parse(plugin)),
        "tls-client" => box_result(TlsFactory::parse(plugin)),
        "trojan-client" => box_result(TrojanFactory::parse(plugin)),
        "http-obfs-client" => box_result(HttpObfsClientFactory::parse(plugin)),
        "tls-obfs-client" => box_result(TlsObfsClientFactory::parse(plugin)),
        "redirect" => box_result(RedirectFactory::parse(plugin)),
        "socket" => box_result(SocketFactory::parse(plugin)),
        "netif" => box_result(NetifFactory::parse(plugin)),
        _ => no_such_type_err,
    }
}

pub(super) struct Demand<'de> {
    pub(super) initiator: &'de str,
    pub(super) ap_type: AccessPointType,
}

#[derive(Default)]
pub(super) struct AccessPointResolver<'de> {
    demanding_aps: HashMap<&'de str, Vec<Demand<'de>>>,
    provided_aps: HashMap<String, AccessPointType>,
    pub(super) plugin_to_visit: HashMap<&'de str, Option<&'de Plugin>>,
    all_plugins: HashMap<&'de str, &'de Plugin>,
}

#[derive(Default)]
pub(super) struct ParseResultCollection<'f> {
    pub(super) factories: HashMap<String, Box<dyn Factory + 'f>>,
    pub(super) errors: Vec<ConfigError>,
}

impl<'de> AccessPointResolver<'de> {
    pub(super) fn provide(&mut self, desc: ProvideDescriptor, errors: &mut Vec<ConfigError>) {
        let demands = self
            .demanding_aps
            .remove(&*desc.descriptor)
            .unwrap_or_default();
        errors.extend(
            demands
                .into_iter()
                .filter(|d| !desc.r#type.contains(d.ap_type))
                .map(|d| ConfigError::BadAccessPointType {
                    initiator: d.initiator.to_owned(),
                    r#type: format!("{:?}", d.ap_type),
                    descriptor: desc.descriptor.to_string(),
                }),
        );
        self.provided_aps.insert(desc.descriptor, desc.r#type);
    }
    pub(super) fn insert_demand(&mut self, ap: &'de str, demand: Demand<'de>) -> ConfigResult<()> {
        let plugin_name = ap.split('.').next().unwrap_or("");
        let to_visit_entry = self.plugin_to_visit.entry(plugin_name);
        if let Entry::Vacant(e) = to_visit_entry {
            if let Some(&plugin) = self.all_plugins.get(&plugin_name) {
                e.insert(Some(plugin));
            } else {
                return Err(ConfigError::NoPlugin {
                    initiator: demand.initiator.to_owned(),
                    plugin: plugin_name.to_owned(),
                });
            }
        }
        if let Some(provided_type) = self.provided_aps.get(ap) {
            return provided_type
                .contains(demand.ap_type)
                .then_some(())
                .ok_or_else(|| ConfigError::BadAccessPointType {
                    initiator: demand.initiator.to_owned(),
                    r#type: format!("{:?}", demand.ap_type),
                    descriptor: ap.to_owned(),
                });
        }
        self.demanding_aps.entry(ap).or_insert(vec![]).push(demand);
        Ok(())
    }
    fn process_plugin(
        &mut self,
        plugin: &'de Plugin,
        parsed: ParsedPlugin<'de, Box<dyn Factory + 'de>>,
        result_col: &mut ParseResultCollection<'de>,
    ) {
        let ParsedPlugin {
            factory,
            requires,
            provides,
        } = parsed;
        provides
            .into_iter()
            .for_each(|p| self.provide(p, &mut result_col.errors));
        result_col
            .errors
            .extend(requires.into_iter().filter_map(|d| {
                self.insert_demand(
                    &*d.descriptor,
                    Demand {
                        initiator: &plugin.name,
                        ap_type: d.r#type,
                    },
                )
                .err()
            }));
        result_col
            .factories
            .insert(plugin.name.to_string(), factory);
    }

    fn create_factory_from_demand(&mut self, result_col: &mut ParseResultCollection<'de>) -> bool {
        let plugin_to_visit = match self.plugin_to_visit.values_mut().find_map(Option::take) {
            Some(p) => p,
            None => return false,
        };
        let parsed = match create_factory_from_plugin(plugin_to_visit) {
            Ok(r) => r,
            Err(e) => {
                result_col.errors.push(e);
                return true;
            }
        };
        self.process_plugin(plugin_to_visit, parsed, result_col);
        true
    }
}

pub(super) fn parse_plugins_recursively<'de>(
    with_resolver: impl FnOnce(&mut AccessPointResolver<'de>, &mut Vec<ConfigError>),
    all_plugins: &'de [Plugin],
) -> ParseResultCollection<'de> {
    let all_plugins: HashMap<_, _> = all_plugins.iter().map(|p| (&*p.name, p)).collect();
    let mut ret = ParseResultCollection::default();

    let mut resolver = AccessPointResolver {
        all_plugins,
        ..Default::default()
    };
    with_resolver(&mut resolver, &mut ret.errors);
    while resolver.create_factory_from_demand(&mut ret) {}
    // Remaining access points cannot be satisfied
    for (ap, d) in resolver
        .demanding_aps
        .into_iter()
        .flat_map(|(ap, demands)| demands.into_iter().map(move |d| (ap, d)))
    {
        ret.errors.push(ConfigError::NoAccessPoint {
            initiator: d.initiator.to_owned(),
            descriptor: ap.to_owned(),
        });
    }
    ret
}
