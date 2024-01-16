use std::collections::BTreeMap;
use std::sync::Arc;

use itertools::Itertools;
use thiserror::Error;

use super::config::v1;
use super::PLUGIN_CACHE_KEY_LAST_SELECT;
use crate::config::PluginSet;
use crate::flow::{DatagramSessionFactory, StreamOutboundFactory};

pub(super) struct Selection {
    pub(super) idx: usize,
    pub(super) name: String,
    pub(super) tcp: Arc<dyn StreamOutboundFactory>,
    pub(super) udp: Arc<dyn DatagramSessionFactory>,
    _plugin_set: Option<PluginSet>, // Keep dependent plugins alive
}

#[derive(Debug, Error)]
pub enum SelectError {
    #[error("bad proxy version: {0}")]
    BadProxyVersion(u16),
    #[error("proxy not found")]
    ProxyNotFound,
    #[error("failed to parse proxy")]
    ProxyParseError,
    #[error("no outbound")]
    NoOutbound,
    #[error("error parsing proxy: {0:?}")]
    ConfigParseError(Vec<crate::config::ConfigError>),
    #[error("error loading plugins: {0:?}")]
    PluginLoadError(Vec<crate::config::LoadError>),
    #[error("tcp/udp entry point not found: {0}")]
    EntrypointNotFound(String),
}

impl super::DynOutbound {
    pub fn manual_select(&self, idx: usize) -> Result<(), SelectError> {
        let new_selection = if idx >= self.fixed_outbounds.len() {
            self.load_proxy(idx)?
        } else {
            self.load_fixed_outbound(idx)?
        };
        self.current.store(Arc::new(Some(new_selection)));
        // TODO: log error
        let _ = self.plugin_cache.set(PLUGIN_CACHE_KEY_LAST_SELECT, &idx);
        Ok(())
    }
    pub(super) fn load_fixed_outbound(&self, idx: usize) -> Result<Selection, SelectError> {
        let outbound = self
            .fixed_outbounds
            .get(idx)
            .ok_or(SelectError::ProxyNotFound)?;
        let tcp = outbound.tcp_next.upgrade().ok_or(SelectError::NoOutbound)?;
        let udp = outbound.udp_next.upgrade().ok_or(SelectError::NoOutbound)?;
        Ok(Selection {
            idx,
            name: outbound.name.to_owned(),
            tcp,
            udp,
            _plugin_set: None,
        })
    }
    pub(super) fn load_proxy(&self, idx: usize) -> Result<Selection, SelectError> {
        let (proxy, version, name) = self
            .proxy_list
            .load()
            .0
            .get(idx - self.fixed_outbounds.len())
            .map(|(p, _)| (p.proxy.clone(), p.proxy_version, p.name.clone()))
            .ok_or(SelectError::ProxyNotFound)?;
        if version != 0 {
            return Err(SelectError::BadProxyVersion(version));
        }
        let v1::Proxy {
            plugins,
            tcp_entry,
            udp_entry,
        } = cbor4ii::serde::from_slice(&proxy).map_err(|_| SelectError::ProxyParseError)?;
        let plugins = plugins.into_iter().map(|p| p.into()).collect_vec();

        let mut preset_stream_outbounds = BTreeMap::new();
        let mut preset_datagram_outbounds = BTreeMap::new();
        preset_stream_outbounds.insert(
            "$out.tcp",
            self.tcp_next.upgrade().ok_or(SelectError::NoOutbound)?,
        );
        let udp_next = self.udp_next.upgrade().ok_or(SelectError::NoOutbound)?;
        preset_datagram_outbounds.insert("$out.udp", udp_next.clone());
        let (loader, errs) = crate::config::loader::proxy::ProxyLoader::parse_with_preset_outbounds(
            preset_stream_outbounds,
            preset_datagram_outbounds,
            [tcp_entry.as_str()],
            udp_entry.as_deref(),
            &plugins,
        );
        if !errs.is_empty() {
            return Err(SelectError::ConfigParseError(errs));
        }

        let mut load_res = loader.load_all(&tokio::runtime::Handle::current(), Some(&self.db));
        if !load_res.errors.is_empty() {
            return Err(SelectError::PluginLoadError(load_res.errors));
        }
        let tcp = load_res
            .required_stream_outbounds
            .remove(&*tcp_entry)
            .ok_or_else(|| SelectError::EntrypointNotFound(tcp_entry.clone()))?;
        let udp = udp_entry
            .as_deref()
            .map(|udp_entry| {
                load_res
                    .required_datagram_outbounds
                    .remove(udp_entry)
                    .ok_or_else(|| SelectError::EntrypointNotFound(udp_entry.into()))
            })
            .transpose()?
            .unwrap_or(udp_next);

        Ok(Selection {
            idx,
            name,
            tcp,
            udp,
            _plugin_set: Some(load_res.plugin_set),
        })
    }
}
