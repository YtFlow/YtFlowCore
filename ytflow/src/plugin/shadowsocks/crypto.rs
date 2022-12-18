mod aead;
mod cfb128;
mod ctor;
mod plain;
mod stream;

use std::marker::PhantomData;
use std::num::NonZeroUsize;

use aes_gcm::aes::{Aes128, Aes192, Aes256};
use aes_gcm::{AeadCore, AeadInPlace};
use camellia::{Camellia128, Camellia192, Camellia256};
use cipher::generic_array::{
    typenum::{Unsigned, U12, U16},
    GenericArray,
};
use cipher::{KeyInit, KeyIvInit, KeySizeUser, StreamCipher};
use ctr::Ctr64BE;
use hkdf::Hkdf;
use sha1::Sha1;

use super::util::increase_num_buf;
use aead::RustCryptoAead;
use cfb128::RustCryptoCfb128;
use ctor::{KeyIvCtor, KeyOnlyCtor, Rc4Md5Ctor};
pub use plain::Plain;
use stream::RustCryptoStream;

pub trait ShadowCrypto: Send + Sync + Unpin + 'static {
    const KEY_LEN: usize;
    const IV_LEN: usize;
    const PRE_CHUNK_OVERHEAD: usize;
    const POST_CHUNK_OVERHEAD: usize;

    fn create_crypto(key: &[u8; Self::KEY_LEN], iv: &[u8; Self::IV_LEN]) -> Self;
    fn encrypt(
        &mut self,
        pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
        data: &mut [u8],
        post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
    );
    fn decrypt_size(
        &mut self,
        pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
    ) -> Option<NonZeroUsize>;
    #[must_use]
    fn decrypt(&mut self, data: &mut [u8], post_overhead: &[u8; Self::POST_CHUNK_OVERHEAD])
        -> bool;
}

pub type Aes128Gcm = RustCryptoAead<aes_gcm::AesGcm<Aes128, U12>, 32>;
pub type Aes256Gcm = RustCryptoAead<aes_gcm::AesGcm<Aes256, U12>, 32>;
pub type Chacha20IetfPoly1305 = RustCryptoAead<chacha20poly1305::ChaCha20Poly1305, 32>;
pub type XChacha20IetfPoly1305 = RustCryptoAead<chacha20poly1305::XChaCha20Poly1305, 32>;

pub type Rc4 = RustCryptoStream<KeyOnlyCtor<rc4::Rc4<U16>>, 0>;
pub type Rc4Md5 = RustCryptoStream<Rc4Md5Ctor<rc4::Rc4<U16>>, 16>;
pub type Chacha20Ietf = RustCryptoStream<KeyIvCtor<chacha20::ChaCha20>, 8>;
pub type Aes128Ctr = RustCryptoStream<KeyIvCtor<Ctr64BE<Aes128>>, 16>;
pub type Aes192Ctr = RustCryptoStream<KeyIvCtor<Ctr64BE<Aes192>>, 16>;
pub type Aes256Ctr = RustCryptoStream<KeyIvCtor<Ctr64BE<Aes256>>, 16>;

pub type Aes128Cfb = RustCryptoCfb128<Aes128, 16>;
pub type Aes192Cfb = RustCryptoCfb128<Aes192, 16>;
pub type Aes256Cfb = RustCryptoCfb128<Aes256, 16>;
pub type Camellia128Cfb = RustCryptoCfb128<Camellia128, 16>;
pub type Camellia192Cfb = RustCryptoCfb128<Camellia192, 16>;
pub type Camellia256Cfb = RustCryptoCfb128<Camellia256, 16>;
