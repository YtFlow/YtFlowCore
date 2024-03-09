pub mod config;
#[cfg(feature = "plugins")]
mod dyn_outbound;
#[cfg(feature = "plugins")]
mod responder;
#[cfg(feature = "plugins")]
mod select;

#[cfg(feature = "plugins")]
pub use dyn_outbound::DynOutbound;
#[cfg(feature = "plugins")]
pub use responder::Responder;

pub const PLUGIN_CACHE_KEY_LAST_SELECT: &str = "last_select";
