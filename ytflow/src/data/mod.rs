mod db;
mod error;
mod plugin;
mod plugin_cache;
mod profile;
mod proxy;
pub mod proxy_group;
mod resource;

use std::marker::PhantomData;

use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct Id<T>(pub u32, PhantomData<T>);

impl<T> Clone for Id<T> {
    fn clone(&self) -> Id<T> {
        Self(self.0, PhantomData)
    }
}
impl<T> Copy for Id<T> {}
impl<T> PartialEq for Id<T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.0.eq(&rhs.0)
    }
}
impl<T> Eq for Id<T> {}
impl<T> From<u32> for Id<T> {
    fn from(id: u32) -> Self {
        Self(id, PhantomData)
    }
}
impl<T> Default for Id<T> {
    fn default() -> Self {
        Self(u32::default(), PhantomData)
    }
}
impl<T> Id<T> {
    pub const fn new(id: u32) -> Self {
        Self(id, PhantomData)
    }
}

pub use db::Connection;
pub use db::Database;
pub use error::*;
pub use plugin::{Plugin, PluginId};
pub use plugin_cache::PluginCache;
pub use profile::{Profile, ProfileId};
pub use proxy::{Proxy, ProxyId, ProxyInput};
pub use proxy_group::{ProxyGroup, ProxyGroupId};
pub use resource::{
    Resource, ResourceGitHubRelease, ResourceGitHubReleaseId, ResourceId, ResourceUrl,
    ResourceUrlId,
};
