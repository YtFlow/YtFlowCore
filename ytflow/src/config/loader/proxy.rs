use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::config::{
    factory::{AccessPointType, Demand, Descriptor},
    *,
};
use crate::flow::*;
use crate::resource::EmptyResourceRegistry;

pub struct ProxyLoader<'f, I1, I2> {
    factories: BTreeMap<String, Box<dyn factory::Factory + 'f>>,
    preset_stream_outbounds: BTreeMap<&'static str, Arc<dyn StreamOutboundFactory>>,
    preset_datagram_outbounds: BTreeMap<&'static str, Arc<dyn DatagramSessionFactory>>,
    required_stream_outbounds: I1,
    required_datagram_outbounds: I2,
}

pub struct ProxyLoadResult<'f> {
    pub plugin_set: set::PluginSet,
    pub errors: Vec<LoadError>,
    pub required_stream_outbounds: BTreeMap<&'f str, Arc<dyn StreamOutboundFactory>>,
    pub required_datagram_outbounds: BTreeMap<&'f str, Arc<dyn DatagramSessionFactory>>,
}

impl<
        'f,
        I1: IntoIterator<Item = &'f str> + Clone + 'f,
        I2: IntoIterator<Item = &'f str> + Clone + 'f,
    > ProxyLoader<'f, I1, I2>
{
    pub fn parse_with_preset_outbounds(
        preset_stream_outbounds: BTreeMap<&'static str, Arc<dyn StreamOutboundFactory>>,
        preset_datagram_outbounds: BTreeMap<&'static str, Arc<dyn DatagramSessionFactory>>,
        required_stream_outbounds: I1,
        required_datagram_outbounds: I2,
        all_plugins: &'f [Plugin],
    ) -> (Self, Vec<ConfigError>) {
        let res = factory::parse_plugins_recursively(
            |resolver, errs| {
                for &name in preset_stream_outbounds.keys() {
                    resolver.provide(
                        Descriptor {
                            descriptor: name.into(),
                            r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                        },
                        errs,
                    );
                    let plugin_name = name
                        .split('.')
                        .next()
                        .expect("Invalid preset outbound tcp name");
                    resolver.plugin_to_visit.insert(plugin_name, None);
                }
                for &name in preset_datagram_outbounds.keys() {
                    resolver.provide(
                        Descriptor {
                            descriptor: name.into(),
                            r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                        },
                        errs,
                    );
                    let plugin_name = name
                        .split('.')
                        .next()
                        .expect("Invalid preset outbound udp name");
                    resolver.plugin_to_visit.insert(plugin_name, None);
                }
                for name in required_stream_outbounds.clone() {
                    if let Err(e) = resolver.insert_demand(
                        name,
                        Demand {
                            initiator: "$entry",
                            ap_type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                        },
                    ) {
                        errs.push(e);
                    }
                }
                for name in required_datagram_outbounds.clone() {
                    if let Err(e) = resolver.insert_demand(
                        name,
                        Demand {
                            initiator: "$entry",
                            ap_type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                        },
                    ) {
                        errs.push(e);
                    }
                }
            },
            all_plugins,
        );
        (
            Self {
                factories: res.factories,
                preset_stream_outbounds,
                preset_datagram_outbounds,
                required_stream_outbounds,
                required_datagram_outbounds,
            },
            res.errors,
        )
    }
}

#[cfg(feature = "plugins")]
impl<'f, I1: IntoIterator<Item = &'f str> + 'f, I2: IntoIterator<Item = &'f str> + 'f>
    ProxyLoader<'f, I1, I2>
{
    pub fn load_all(
        self,
        rt_handle: &tokio::runtime::Handle,
        db: Option<&crate::data::Database>,
    ) -> ProxyLoadResult<'f> {
        use std::mem::ManuallyDrop;

        let Self {
            factories,
            preset_stream_outbounds,
            preset_datagram_outbounds,
            required_stream_outbounds,
            required_datagram_outbounds,
        } = self;

        let rt_handle_cloned = rt_handle.clone();
        let _enter_guard = rt_handle.enter();
        let mut partial_set = set::PartialPluginSet::new(
            factories.into_iter().map(|(k, v)| (k, Some(v))).collect(),
            Box::new(EmptyResourceRegistry),
            db,
            set::PluginSet {
                rt_handle: rt_handle_cloned,
                long_running_tasks: vec![],
                stream_handlers: ManuallyDrop::new(HashMap::new()),
                stream_outbounds: ManuallyDrop::new(
                    preset_stream_outbounds
                        .into_iter()
                        .map(|(k, v)| (k.into(), v))
                        .collect(),
                ),
                datagram_handlers: ManuallyDrop::new(HashMap::new()),
                datagram_outbounds: ManuallyDrop::new(
                    preset_datagram_outbounds
                        .into_iter()
                        .map(|(k, v)| (k.into(), v))
                        .collect(),
                ),
                resolver: ManuallyDrop::new(HashMap::new()),
                tun: ManuallyDrop::new(HashMap::new()),
            },
        );
        partial_set.load_all();

        let mut plugin_set = partial_set.fully_constructed;
        let required_stream_outbounds = required_stream_outbounds
            .into_iter()
            .map(|name| (name, plugin_set.stream_outbounds.remove(name).unwrap()))
            .collect();
        let required_datagram_outbounds = required_datagram_outbounds
            .into_iter()
            .map(|name| (name, plugin_set.datagram_outbounds.remove(name).unwrap()))
            .collect();

        ProxyLoadResult {
            plugin_set,
            errors: partial_set.errors,
            required_stream_outbounds,
            required_datagram_outbounds,
        }
    }
}
