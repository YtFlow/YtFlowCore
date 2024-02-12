use std::fmt::Display;

use serde::{Deserialize, Serialize};

#[cfg(feature = "plugins")]
mod crypto;
#[cfg(feature = "plugins")]
mod datagram;
#[cfg(feature = "plugins")]
pub mod factory;
#[cfg(feature = "plugins")]
mod stream;
#[cfg(feature = "plugins")]
pub(crate) mod util;

#[rustfmt::skip]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupportedCipher {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "rc4")]
    Rc4,
    #[serde(rename = "rc4-md5")]
    Rc4Md5,
    #[serde(rename = "aes-128-cfb")]
    Aes128Cfb,
    #[serde(rename = "aes-192-cfb")]
    Aes192Cfb,
    #[serde(rename = "aes-256-cfb")]
    Aes256Cfb,
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr,
    #[serde(rename = "aes-192-ctr")]
    Aes192Ctr,
    #[serde(rename = "aes-256-ctr")]
    Aes256Ctr,
    #[serde(rename = "camellia-128-cfb")]
    Camellia128Cfb,
    #[serde(rename = "camellia-192-cfb")]
    Camellia192Cfb,
    #[serde(rename = "camellia-256-cfb")]
    Camellia256Cfb,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-ietf")]
    Chacha20Ietf,
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
    #[serde(rename = "xchacha20-ietf-poly1305")]
    XChacha20IetfPoly1305,
}

impl Display for SupportedCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SupportedCipher::None => "none",
            SupportedCipher::Rc4 => "rc4",
            SupportedCipher::Rc4Md5 => "rc4-md5",
            SupportedCipher::Aes128Cfb => "aes-128-cfb",
            SupportedCipher::Aes192Cfb => "aes-192-cfb",
            SupportedCipher::Aes256Cfb => "aes-256-cfb",
            SupportedCipher::Aes128Ctr => "aes-128-ctr",
            SupportedCipher::Aes192Ctr => "aes-192-ctr",
            SupportedCipher::Aes256Ctr => "aes-256-ctr",
            SupportedCipher::Camellia128Cfb => "camellia-128-cfb",
            SupportedCipher::Camellia192Cfb => "camellia-192-cfb",
            SupportedCipher::Camellia256Cfb => "camellia-256-cfb",
            SupportedCipher::Aes128Gcm => "aes-128-gcm",
            SupportedCipher::Aes256Gcm => "aes-256-gcm",
            SupportedCipher::Chacha20Ietf => "chacha20-ietf",
            SupportedCipher::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            SupportedCipher::XChacha20IetfPoly1305 => "xchacha20-ietf-poly1305",
        })
    }
}
