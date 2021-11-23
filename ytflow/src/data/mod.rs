mod db;
mod error;
mod plugin;
mod profile;

use std::marker::PhantomData;

#[derive(Debug)]
pub struct Id<T>(u32, PhantomData<T>);

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

pub use db::Connection;
pub use db::Database;
pub use error::*;
pub use plugin::{Plugin, PluginId};
pub use profile::{Profile, ProfileId};
