use std::sync::Arc;

use cbor4ii::serde::{from_slice, to_vec};
use serde::Serialize;

use crate::control::{PluginRequestError, PluginRequestResult, PluginResponder};

pub struct Responder {
    dyn_outbound: Arc<super::DynOutbound>,
}

impl Responder {
    pub fn new(dyn_outbound: Arc<super::DynOutbound>) -> Self {
        Self { dyn_outbound }
    }
}

#[derive(Serialize)]
struct Info {
    current_proxy_idx: Option<u32>,
    current_proxy_name: Option<String>,
}
#[derive(Serialize)]
struct ProxyListItem<'a> {
    name: &'a str,
    idx: u32,
    id: u32,
    group_id: u32,
    group_name: &'a str,
}
#[derive(Serialize)]
struct FixedOutboundItem<'a> {
    name: &'a str,
    idx: u32,
}
#[derive(Serialize)]
struct ListProxiesRes<'a> {
    proxies: Vec<ProxyListItem<'a>>,
    fixed_outbounds: Vec<FixedOutboundItem<'a>>,
}

impl PluginResponder for Responder {
    fn collect_info(&self, _hashcode: &mut u32) -> Option<Vec<u8>> {
        let (current_proxy_idx, current_proxy_name) = (**self.dyn_outbound.current.load())
            .as_ref()
            .map(|c| (c.idx as u32, c.name.clone()))
            .unzip();
        let info = Info {
            current_proxy_idx,
            current_proxy_name,
        };
        Some(to_vec(vec![], &info).unwrap())
    }

    fn on_request(&self, func: &str, params: &[u8]) -> PluginRequestResult<Vec<u8>> {
        Ok(match func {
            "select" => {
                let idx: u32 = from_slice(params)?;
                let err = self
                    .dyn_outbound
                    .manual_select(idx as usize)
                    .err()
                    .map(|e| format!("{}", e));
                to_vec(vec![], &err).unwrap()
            }
            "list_proxies" => {
                // TODO: log errors
                let _ = self.dyn_outbound.load_proxies();
                let fixed_outbounds = self
                    .dyn_outbound
                    .fixed_outbounds
                    .iter()
                    .enumerate()
                    .map(|(idx, f)| FixedOutboundItem {
                        name: &f.name,
                        idx: idx as u32,
                    })
                    .collect::<Vec<_>>();
                let list = self.dyn_outbound.proxy_list.load_full();
                let (proxies, groups) = &*list;
                let proxies = proxies
                    .iter()
                    .enumerate()
                    .map(|(idx, (p, gid))| ProxyListItem {
                        name: &p.name,
                        idx: (idx + fixed_outbounds.len()) as u32,
                        id: p.id.0,
                        group_id: gid.0,
                        group_name: groups
                            .iter()
                            .find(|g| g.id == *gid)
                            .map(|g| &*g.name)
                            .unwrap_or_default(),
                    })
                    .collect::<Vec<_>>();
                to_vec(
                    vec![],
                    &ListProxiesRes {
                        proxies,
                        fixed_outbounds,
                    },
                )
                .unwrap()
            }
            _ => {
                return Err(PluginRequestError::NoSuchFunc);
            }
        })
    }
}
