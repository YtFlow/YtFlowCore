use std::borrow::Cow;
use std::convert::Infallible;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum PluginRequestError {
    #[error("No such plugin")]
    NoSuchPlugin,
    #[error("No such func")]
    NoSuchFunc,
    #[error("Bad param")]
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    BadParam(#[from] cbor4ii::core::dec::Error<Infallible>),
}

pub type PluginRequestResult<T> = Result<T, PluginRequestError>;

pub trait PluginResponder: Send + Sync + 'static {
    fn collect_info(&self, hash: &mut u32) -> Option<Vec<u8>>;
    fn on_request(&self, func: &str, params: &[u8]) -> PluginRequestResult<Vec<u8>>;
}

pub struct PluginControlHandle {
    // TODO: send notification
}

pub(super) struct PluginController {
    pub(super) id: u32,
    pub(super) name: String,
    pub(super) plugin: &'static str,
    pub(super) responder: Box<dyn PluginResponder>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PluginInfo<'a> {
    pub id: u32,
    pub name: Cow<'a, str>,
    pub plugin: Cow<'a, str>,
    pub info: ByteBuf,
    pub hashcode: u32,
}

impl PluginController {
    pub fn collect_info(&self, mut hashcode: u32) -> Option<PluginInfo> {
        self.responder
            .collect_info(&mut hashcode)
            .map(|info| PluginInfo {
                id: self.id,
                name: Cow::Borrowed(&self.name),
                plugin: Cow::Borrowed(&self.plugin),
                info: ByteBuf::from(info),
                hashcode,
            })
    }
}
