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
