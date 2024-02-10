use std::fmt::Display;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedCipher {
    None, Rc4, Rc4Md5,
    Aes128Cfb, Aes192Cfb, Aes256Cfb,
    Aes128Ctr, Aes192Ctr, Aes256Ctr,
    Camellia128Cfb, Camellia192Cfb, Camellia256Cfb,
    Aes128Gcm, Aes256Gcm,
    Chacha20Ietf, Chacha20IetfPoly1305, XChacha20IetfPoly1305,
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
