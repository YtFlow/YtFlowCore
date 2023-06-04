use serde::Serialize;

use super::*;
use crate::control::{PluginRequestError, PluginRequestResult, PluginResponder};
use crate::data::PluginCache;

pub const PLUGIN_CACHE_KEY_LAST_SELECT: &str = "last_select";

#[derive(Clone, Serialize)]
pub struct Choice {
    pub name: String,
    pub description: String,
    #[serde(skip)]
    pub tcp_next: Weak<dyn StreamHandler>,
    #[serde(skip)]
    pub udp_next: Weak<dyn DatagramSessionHandler>,
}

pub struct Responder {
    pub choices: Vec<Choice>,
    pub switch: Arc<Switch>,
    pub cache: PluginCache,
}

#[derive(Serialize)]
struct Info<'a> {
    choices: &'a [Choice],
    current: u32,
}

impl Responder {
    pub fn switch(&self, idx: u32) -> Option<u32> {
        let new_choice = self.choices.get(idx as usize)?;
        let new_choice = CurrentChoice {
            idx,
            tcp_next: new_choice.tcp_next.clone(),
            udp_next: new_choice.udp_next.clone(),
        };
        let old_choice = self.switch.current_choice.swap(Arc::new(new_choice));
        let _ = self.cache.set(PLUGIN_CACHE_KEY_LAST_SELECT, &idx).ok();
        Some(old_choice.idx)
    }
}

impl PluginResponder for Responder {
    fn collect_info(&self, hash: &mut u32) -> Option<Vec<u8>> {
        let guard = self.switch.current_choice.load();

        let ptr_hash = Arc::as_ptr(&guard) as u32;
        if std::mem::replace(hash, ptr_hash) == ptr_hash {
            return None;
        }

        let current = guard.idx;
        drop(guard);

        Some(
            cbor4ii::serde::to_vec(
                vec![],
                &Info {
                    choices: &self.choices,
                    current,
                },
            )
            .unwrap(),
        )
    }

    fn on_request(&self, func: &str, params: &[u8]) -> PluginRequestResult<Vec<u8>> {
        match func {
            "s" => {
                let choice_idx: u32 = cbor4ii::serde::from_slice(params)?;
                let ret = self.switch(choice_idx);
                Ok(cbor4ii::serde::to_vec(Vec::with_capacity(4), &ret).unwrap())
            }
            _ => Err(PluginRequestError::NoSuchFunc),
        }
    }
}
