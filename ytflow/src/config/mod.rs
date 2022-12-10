use std::collections::HashMap;

mod error;
pub mod factory;
mod human_repr;
mod param;
pub mod plugin;
mod set;
pub mod verify;

pub use error::*;
pub use human_repr::HumanRepr;
pub use set::PluginSet;

use crate::data::Plugin;

pub struct ProfilePluginFactory<'f>(HashMap<String, Box<dyn factory::Factory + 'f>>);

pub struct LoadPluginResult {
    pub plugin_set: set::PluginSet,
    pub errors: Vec<LoadError>,
    pub control_hub: crate::control::ControlHub,
}

impl<'f> ProfilePluginFactory<'f> {
    pub fn parse_profile(
        entry_plugins: impl Iterator<Item = &'f Plugin>,
        all_plugins: &'f [Plugin],
    ) -> (Self, Vec<ConfigError>) {
        let res = factory::parse_plugins_recursively(entry_plugins, all_plugins);
        (Self(res.factories), res.errors)
    }
    pub fn load_all(self, rt_handle: &tokio::runtime::Handle) -> LoadPluginResult {
        use std::mem::ManuallyDrop;

        let rt_handle_cloned = rt_handle.clone();
        let _enter_guard = rt_handle.enter();
        let mut partial_set = set::PartialPluginSet::new(
            self.0.into_iter().map(|(k, v)| (k, Some(v))).collect(),
            set::PluginSet {
                rt_handle: rt_handle_cloned,
                long_running_tasks: vec![],
                stream_handlers: ManuallyDrop::new(HashMap::new()),
                stream_outbounds: ManuallyDrop::new(HashMap::new()),
                datagram_handlers: ManuallyDrop::new(HashMap::new()),
                datagram_outbounds: ManuallyDrop::new(HashMap::new()),
                resolver: ManuallyDrop::new(HashMap::new()),
                tun: ManuallyDrop::new(HashMap::new()),
            },
        );
        partial_set.load_all();
        LoadPluginResult {
            plugin_set: partial_set.fully_constructed,
            errors: partial_set.errors,
            control_hub: partial_set.control_hub,
        }
    }
}
