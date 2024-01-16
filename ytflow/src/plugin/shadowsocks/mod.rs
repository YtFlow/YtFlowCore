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
#[derive(Clone, Copy)]
pub enum SupportedCipher {
    None, Rc4, Rc4Md5,
    Aes128Cfb, Aes192Cfb, Aes256Cfb,
    Aes128Ctr, Aes192Ctr, Aes256Ctr,
    Camellia128Cfb, Camellia192Cfb, Camellia256Cfb,
    Aes128Gcm, Aes256Gcm,
    Chacha20Ietf, Chacha20IetfPoly1305, XChacha20IetfPoly1305,
}
