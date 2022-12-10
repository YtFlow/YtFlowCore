use std::sync::Arc;

use cbor4ii::serde::{from_slice, to_vec};
use serde::{Deserialize, Serialize};

use crate::control::{PluginRequestError, PluginRequestResult, PluginResponder};

pub struct Responder {
    selector: Arc<super::NetifSelector>,
}

#[derive(Serialize)]
struct Info<'a> {
    selection: &'a super::SelectionMode,
    preference: super::FamilyPreference,
    netif: &'a super::sys::Netif,
}

#[derive(Deserialize)]
struct SelectRequest {
    selection: super::SelectionMode,
    preference: super::FamilyPreference,
}

impl Responder {
    pub fn new(selector: Arc<super::NetifSelector>) -> Self {
        Self { selector }
    }
}

impl PluginResponder for Responder {
    fn collect_info(&self, hashcode: &mut u32) -> Option<Vec<u8>> {
        let super::NetifSelector {
            selection,
            cached_netif,
            ..
        } = &*self.selector;
        let selection = selection.load();
        let netif = cached_netif.load();
        let new_hashcode = (Arc::as_ptr(&selection) as u32) << 16 | Arc::as_ptr(&netif) as u32;
        if std::mem::replace(hashcode, new_hashcode) == new_hashcode {
            return None;
        }
        let info = Info {
            selection: &selection.0,
            preference: selection.1,
            netif: &**netif,
        };
        Some(to_vec(vec![], &info).unwrap())
    }

    fn on_request(&self, func: &str, params: &[u8]) -> PluginRequestResult<Vec<u8>> {
        Ok(match func {
            "select" => {
                let info: SelectRequest = from_slice(params)?;
                self.selector
                    .selection
                    .store(Arc::new((info.selection, info.preference)));
                self.selector.update();
                vec![]
            }
            _ => return Err(PluginRequestError::NoSuchFunc),
        })
    }
}
