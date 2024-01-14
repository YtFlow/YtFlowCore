// Windows does not provide per-link hostname resolution.
// On Linux, fallback to resolver when sytemd-resolved is not available.
#[cfg(all(feature = "plugins", any(windows, target_os = "linux")))]
mod resolver;
#[cfg(feature = "plugins")]
mod responder;
#[cfg(feature = "plugins")]
mod selector;
#[cfg(feature = "plugins")]
mod sys;

use serde::{Deserialize, Serialize};

#[cfg(feature = "plugins")]
pub use responder::Responder;
#[cfg(feature = "plugins")]
pub use selector::NetifSelector;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "netif")]
pub enum SelectionMode {
    Auto,
    Manual(String),
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum FamilyPreference {
    Both,
    Ipv4Only,
    Ipv6Only,
}
