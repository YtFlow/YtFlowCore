use std::collections::{BTreeMap, HashMap};

use crate::config::factory::RequiredResource;
use crate::config::*;
use crate::resource::ResourceRegistry;

pub struct ProfileLoader<'f>(BTreeMap<String, Box<dyn factory::Factory + 'f>>);

pub struct ProfileLoadResult {
    pub plugin_set: set::PluginSet,
    pub errors: Vec<LoadError>,
    pub control_hub: crate::control::ControlHub,
}

impl<'f> ProfileLoader<'f> {
    pub fn parse_profile(
        entry_plugins: impl Iterator<Item = &'f Plugin>,
        all_plugins: &'f [Plugin],
    ) -> (Self, Vec<RequiredResource>, Vec<ConfigError>) {
        let res = factory::parse_plugins_recursively(
            |resolver, _| {
                for entry_plugin in entry_plugins {
                    resolver
                        .plugin_to_visit
                        .insert(&entry_plugin.name, Some(entry_plugin));
                }
            },
            all_plugins,
        );
        (Self(res.factories), res.resources, res.errors)
    }
    pub fn load_all(
        self,
        rt_handle: &tokio::runtime::Handle,
        resource_registry: Box<dyn ResourceRegistry>,
        db: Option<&crate::data::Database>,
    ) -> ProfileLoadResult {
        use std::mem::ManuallyDrop;

        let rt_handle_cloned = rt_handle.clone();
        let _enter_guard = rt_handle.enter();
        let mut partial_set = set::PartialPluginSet::new(
            self.0.into_iter().map(|(k, v)| (k, Some(v))).collect(),
            resource_registry,
            db,
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
        ProfileLoadResult {
            plugin_set: partial_set.fully_constructed,
            errors: partial_set.errors,
            control_hub: partial_set.control_hub,
        }
    }
}
