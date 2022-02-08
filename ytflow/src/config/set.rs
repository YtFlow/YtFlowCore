use std::collections::HashMap;
use std::mem::ManuallyDrop;
use std::sync::{Arc, Weak};

use super::*;
use crate::flow::*;
use crate::plugin::netif::NetifSelector;

pub struct PluginSet {
    pub(super) rt_handle: tokio::runtime::Handle,
    pub(super) long_running_tasks: Vec<tokio::task::JoinHandle<()>>,
    pub(super) stream_handlers: ManuallyDrop<HashMap<String, Arc<dyn StreamHandler>>>,
    pub(super) stream_outbounds: ManuallyDrop<HashMap<String, Arc<dyn StreamOutboundFactory>>>,
    pub(super) datagram_handlers: ManuallyDrop<HashMap<String, Arc<dyn DatagramSessionHandler>>>,
    pub(super) datagram_outbounds: ManuallyDrop<HashMap<String, Arc<dyn DatagramSessionFactory>>>,
    pub(super) resolver: ManuallyDrop<HashMap<String, Arc<dyn Resolver>>>,
    pub(super) tun: ManuallyDrop<HashMap<String, Arc<dyn Tun>>>,
    pub(super) netif: ManuallyDrop<HashMap<String, Arc<NetifSelector>>>,
}

pub(super) struct PartialPluginSet<'f> {
    pub(super) plugins: HashMap<String, Option<Box<dyn super::factory::Factory + 'f>>>,
    pub(super) fully_constructed: PluginSet,
    pub(super) errors: Vec<LoadError>,
    pub(super) stream_handlers: HashMap<String, Weak<dyn StreamHandler>>,
    pub(super) stream_outbounds: HashMap<String, Weak<dyn StreamOutboundFactory>>,
    pub(super) datagram_handlers: HashMap<String, Weak<dyn DatagramSessionHandler>>,
    pub(super) datagram_outbounds: HashMap<String, Weak<dyn DatagramSessionFactory>>,
    pub(super) resolver: HashMap<String, Weak<dyn Resolver>>,
    pub(super) tun: HashMap<String, Weak<dyn Tun>>,
}

fn lookup<T: ?Sized>(
    descriptor: &str,
    strong_map: &HashMap<String, Arc<T>>,
    weak_map: &HashMap<String, Weak<T>>,
) -> Option<Weak<T>> {
    strong_map
        .get(descriptor)
        .map(Arc::downgrade)
        .or_else(|| weak_map.get(descriptor).map(Weak::clone))
}

macro_rules! impl_get_or_create {
    ($fn_name: ident, $dict_name: ident, $item_type: ident) => {
        pub(super) fn $fn_name(
            &mut self,
            initiator: String,
            descriptor: &str,
        ) -> LoadResult<Weak<dyn $item_type>> {
            loop {
                if let Some(next) = lookup(
                    descriptor,
                    &self.fully_constructed.$dict_name,
                    &self.$dict_name,
                ) {
                    return Ok(next);
                };
                self.load_plugin(initiator.clone(), descriptor)?;
            }
        }
    };
}

impl<'a> PartialPluginSet<'a> {
    pub(super) fn new(
        plugins: HashMap<String, Option<Box<dyn super::factory::Factory + 'a>>>,
        fully_constructed: PluginSet,
    ) -> Self {
        Self {
            fully_constructed,
            plugins,
            errors: vec![],
            stream_handlers: HashMap::new(),
            stream_outbounds: HashMap::new(),
            datagram_handlers: HashMap::new(),
            datagram_outbounds: HashMap::new(),
            resolver: HashMap::new(),
            tun: HashMap::new(),
        }
    }
    fn load_plugin(&mut self, initiator: String, descriptor: &str) -> LoadResult<()> {
        let plugin_name = descriptor.split('.').next().unwrap_or("").to_owned();
        let mut plugin = match self.plugins.get_mut(&plugin_name).map(Option::take) {
            Some(Some(plugin)) => plugin,
            Some(None) => {
                return Err(ConfigError::NoAccessPoint {
                    initiator,
                    descriptor: descriptor.to_owned(),
                }
                .into());
            }
            None => {
                return Err(ConfigError::NoPlugin {
                    initiator,
                    plugin: plugin_name,
                }
                .into());
            }
        };
        plugin.load(plugin_name, self)
    }
    impl_get_or_create!(get_or_create_stream_handler, stream_handlers, StreamHandler);
    impl_get_or_create!(
        get_or_create_stream_outbound,
        stream_outbounds,
        StreamOutboundFactory
    );
    impl_get_or_create!(
        get_or_create_datagram_handler,
        datagram_handlers,
        DatagramSessionHandler
    );
    impl_get_or_create!(
        get_or_create_datagram_outbound,
        datagram_outbounds,
        DatagramSessionFactory
    );
    impl_get_or_create!(get_or_create_resolver, resolver, Resolver);
    impl_get_or_create!(get_or_create_tun, tun, Tun);
    pub(super) fn get_or_create_netif(
        &mut self,
        initiator: String,
        descriptor: &str,
    ) -> LoadResult<Arc<NetifSelector>> {
        loop {
            if let Some(netif) = self.fully_constructed.netif.get(descriptor) {
                break Ok(netif.clone());
            }
            self.load_plugin(initiator.clone(), descriptor)?;
        }
    }

    pub(super) fn load_all(&mut self) {
        while let Some((plugin_name, _)) = self.plugins.iter_mut().find(|(_, v)| v.is_some()) {
            let plugin_name = &plugin_name.clone();
            if let Err(e) = self.load_plugin(String::from("#root"), plugin_name) {
                self.errors.push(e);
            }
        }
    }
}

impl Drop for PluginSet {
    fn drop(&mut self) {
        // In case some destructors need the async runtime to spawn new tasks
        let _enter_guard = self.rt_handle.enter();
        unsafe {
            // We must move ownership out from all the `ManuallyDrop`s at once,
            // and bind them to a named variable (not `_`), so that they will
            // be dropped even when a panic occurs in these destructors.
            let _stream_handlers = ManuallyDrop::take(&mut self.stream_handlers);
            let _stream_outbounds = ManuallyDrop::take(&mut self.stream_outbounds);
            let _datagram_handlers = ManuallyDrop::take(&mut self.datagram_handlers);
            let _datagram_outbounds = ManuallyDrop::take(&mut self.datagram_outbounds);
            let _resolver = ManuallyDrop::take(&mut self.resolver);
            let _tun = ManuallyDrop::take(&mut self.tun);
            let _netif = ManuallyDrop::take(&mut self.netif);

            for handle in &self.long_running_tasks {
                handle.abort()
            }
        }
    }
}
