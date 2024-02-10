use std::fmt::Display;

#[cfg(feature = "plugins")]
mod client;
#[cfg(feature = "plugins")]
mod protocol;
#[cfg(feature = "plugins")]
mod stream;

#[cfg(feature = "plugins")]
pub use client::VMessStreamOutboundFactory;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedSecurity {
    None,
    Auto,
    Aes128Cfb,
    Aes128Gcm,
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
