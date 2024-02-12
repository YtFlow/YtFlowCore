use std::fmt::Display;

use serde::{Deserialize, Serialize};

#[cfg(feature = "plugins")]
mod client;
#[cfg(feature = "plugins")]
mod protocol;
#[cfg(feature = "plugins")]
mod stream;

#[cfg(feature = "plugins")]
pub use client::VMessStreamOutboundFactory;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupportedSecurity {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "aes-128-cfb")]
    Aes128Cfb,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305,
}

impl Display for SupportedSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SupportedSecurity::None => "none",
            SupportedSecurity::Auto => "auto",
            SupportedSecurity::Aes128Cfb => "aes-128-cfb",
            SupportedSecurity::Aes128Gcm => "aes-128-gcm",
            SupportedSecurity::Chacha20Poly1305 => "chacha20-poly1305",
        })
    }
}
