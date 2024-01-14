use std::marker::PhantomData;
use std::sync::{Arc, Weak};

pub mod datagram;
pub mod stream;

use super::crypto::*;
use super::SupportedCipher;
use crate::flow::*;
use datagram::ShadowsocksDatagramSessionFactory;
use stream::ShadowsocksStreamOutboundFactory;

pub trait ReceiveFactory {
    fn receive_factory<F: CreateFactory>(self, factory: F);
}

pub trait CreateFactory {
    type StreamFactory: StreamOutboundFactory + 'static;
    type DatagramFactory: DatagramSessionFactory + 'static;
    fn create_stream_factory(&self, next: Weak<dyn StreamOutboundFactory>) -> Self::StreamFactory;
    fn create_datagram_session_factory(
        &self,
        next: Weak<dyn DatagramSessionFactory>,
    ) -> Self::DatagramFactory;
}

struct FactoryCreator<C: ShadowCrypto>
where
    [(); C::KEY_LEN]:,
{
    key: [u8; C::KEY_LEN],
    crypto_phantom: std::marker::PhantomData<C>,
}

impl<C: ShadowCrypto> CreateFactory for FactoryCreator<C>
where
    [(); C::KEY_LEN]:,
    [(); C::IV_LEN]:,
    [(); C::PRE_CHUNK_OVERHEAD]:,
    [(); C::POST_CHUNK_OVERHEAD]:,
{
    type StreamFactory = ShadowsocksStreamOutboundFactory<C>;
    type DatagramFactory = ShadowsocksDatagramSessionFactory<C>;
    fn create_stream_factory(&self, next: Weak<dyn StreamOutboundFactory>) -> Self::StreamFactory {
        ShadowsocksStreamOutboundFactory {
            key: self.key,
            crypto_phantom: PhantomData,
            next,
        }
    }
    fn create_datagram_session_factory(
        &self,
        next: Weak<dyn DatagramSessionFactory>,
    ) -> Self::DatagramFactory {
        ShadowsocksDatagramSessionFactory {
            key: Arc::new(self.key),
            next,
            crypto_phantom: PhantomData,
        }
    }
}

pub fn create_factory<R: ReceiveFactory>(method: SupportedCipher, password: &[u8], r: R) {
    use super::util::openssl_bytes_to_key as bk;

    let p = password;
    #[rustfmt::skip]
    match method {
        SupportedCipher::None => r.receive_factory(FactoryCreator::<Plain> { key: [], crypto_phantom: PhantomData }),
        SupportedCipher::Rc4 => r.receive_factory(FactoryCreator::<Rc4>{ key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Rc4Md5 => r.receive_factory(FactoryCreator::<Rc4Md5>{ key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes128Cfb => r.receive_factory(FactoryCreator::<Aes128Cfb> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes192Cfb => r.receive_factory(FactoryCreator::<Aes192Cfb> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes256Cfb => r.receive_factory(FactoryCreator::<Aes256Cfb> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes128Ctr => r.receive_factory(FactoryCreator::<Aes128Ctr> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes192Ctr => r.receive_factory(FactoryCreator::<Aes192Ctr> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes256Ctr => r.receive_factory(FactoryCreator::<Aes256Ctr> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Camellia128Cfb => r.receive_factory(FactoryCreator::<Camellia128Cfb> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Camellia192Cfb => r.receive_factory(FactoryCreator::<Camellia192Cfb> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Camellia256Cfb => r.receive_factory(FactoryCreator::<Camellia256Cfb> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes128Gcm => r.receive_factory(FactoryCreator::<Aes128Gcm> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes256Gcm => r.receive_factory(FactoryCreator::<Aes256Gcm> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Chacha20Ietf => r.receive_factory(FactoryCreator::<Chacha20Ietf> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Chacha20IetfPoly1305 => r.receive_factory(FactoryCreator::<Chacha20IetfPoly1305> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::XChacha20IetfPoly1305 => r.receive_factory(FactoryCreator::<XChacha20IetfPoly1305> { key: bk(p), crypto_phantom: PhantomData }),
    }
}
