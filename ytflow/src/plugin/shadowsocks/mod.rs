mod crypto;
mod stream;
pub(crate) mod util;
mod xchacha20;

use std::convert::TryInto;
use std::marker::PhantomData;
use std::sync::Weak;

use async_trait::async_trait;

use crate::flow::*;
use crypto::*;

struct ShadowsocksStreamOutboundFactory<C: ShadowCrypto>
where
    [(); C::KEY_LEN]:,
{
    key: [u8; C::KEY_LEN],
    next: Weak<dyn StreamOutboundFactory>,
    crypto_phantom: std::marker::PhantomData<C>,
}

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

pub trait ReceiveFactory {
    fn receive_factory<F: CreateFactory>(self, factory: F);
}

pub trait CreateFactory {
    type Factory: StreamOutboundFactory + 'static;
    fn create_factory(self, next: Weak<dyn StreamOutboundFactory>) -> Self::Factory;
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
    type Factory = ShadowsocksStreamOutboundFactory<C>;
    fn create_factory(self, next: Weak<dyn StreamOutboundFactory>) -> Self::Factory {
        let Self {
            key,
            crypto_phantom,
        } = self;
        ShadowsocksStreamOutboundFactory {
            key,
            crypto_phantom,
            next,
        }
    }
}

pub fn create_factory<R: ReceiveFactory>(method: SupportedCipher, password: &[u8], r: R) {
    use util::openssl_bytes_to_key as bk;

    let p = password;
    #[rustfmt::skip]
    match method {
        SupportedCipher::None => r.receive_factory(FactoryCreator::<Plain> { key: [], crypto_phantom: PhantomData }),
        SupportedCipher::Rc4=> r.receive_factory(FactoryCreator::<Rc4>{ key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Rc4Md5 => r.receive_factory(FactoryCreator::<Rc4Md5>{ key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes128Cfb => r.receive_factory(FactoryCreator::<Aes128Cfb> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes192Cfb => r.receive_factory(FactoryCreator::<Aes192Cfb> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes256Cfb => r.receive_factory(FactoryCreator::<Aes128Cfb> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes128Ctr => r.receive_factory(FactoryCreator::<Aes128Ctr> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes192Ctr => r.receive_factory(FactoryCreator::<Aes192Ctr> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes256Ctr => r.receive_factory(FactoryCreator::<Aes128Ctr> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Camellia128Cfb => r.receive_factory(FactoryCreator::<Camellia128Cfb> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Camellia192Cfb => r.receive_factory(FactoryCreator::<Camellia192Cfb> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Camellia256Cfb => r.receive_factory(FactoryCreator::<Camellia128Cfb> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes128Gcm => r.receive_factory(FactoryCreator::<Aes128Gcm> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Aes256Gcm => r.receive_factory(FactoryCreator::<Aes256Gcm> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Chacha20Ietf => r.receive_factory(FactoryCreator::<Chacha20Ietf> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::Chacha20IetfPoly1305 => r.receive_factory(FactoryCreator::<Chacha20IetfPoly1305> { key: bk(p), crypto_phantom: PhantomData }),
        SupportedCipher::XChacha20IetfPoly1305 => r.receive_factory(FactoryCreator::<XChacha20IetfPoly1305> { key: bk(p), crypto_phantom: PhantomData }),
    }
}

impl<C: ShadowCrypto> ShadowsocksStreamOutboundFactory<C>
where
    [(); C::KEY_LEN]:,
    [(); C::IV_LEN]:,
    [(); C::PRE_CHUNK_OVERHEAD]:,
    [(); C::POST_CHUNK_OVERHEAD]:,
{
    fn get_req(&self, context: &FlowContext, initial_data: &[u8]) -> (Vec<u8>, C) {
        let mut tx_handshake = Vec::with_capacity(259 + initial_data.len());
        util::write_dest(&mut tx_handshake, context);
        tx_handshake.extend_from_slice(initial_data);

        // TODO: Skip zero-fill tx_handshake part
        let mut req_buf =
            vec![
                0;
                C::IV_LEN + C::PRE_CHUNK_OVERHEAD + tx_handshake.len() + C::POST_CHUNK_OVERHEAD
            ];
        let (iv, whole_chunk) = req_buf.split_at_mut(C::IV_LEN);
        let (pre_overhead, remaining) = whole_chunk.split_at_mut(C::PRE_CHUNK_OVERHEAD);
        let (chunk, post_overhead) = remaining.split_at_mut(tx_handshake.len());

        getrandom::getrandom(iv).unwrap();
        chunk.copy_from_slice(&tx_handshake);

        let iv: &mut [u8; C::IV_LEN] = iv.try_into().unwrap();
        let pre_overhead: &mut [u8; C::PRE_CHUNK_OVERHEAD] = pre_overhead.try_into().unwrap();
        let post_overhead: &mut [u8; C::POST_CHUNK_OVERHEAD] = post_overhead.try_into().unwrap();
        let mut tx_crypto = C::create_crypto(&self.key, iv);
        tx_crypto.encrypt(pre_overhead, chunk, post_overhead);

        (req_buf, tx_crypto)
    }
}

#[async_trait]
impl<C: ShadowCrypto> StreamOutboundFactory for ShadowsocksStreamOutboundFactory<C>
where
    [(); C::KEY_LEN]:,
    [(); C::IV_LEN]:,
    [(); C::PRE_CHUNK_OVERHEAD]:,
    [(); C::POST_CHUNK_OVERHEAD]:,
{
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<Box<dyn Stream>> {
        let outbound_factory = self.next.upgrade().ok_or(FlowError::NoOutbound)?;
        let (next, tx_crypto) = {
            let (tx_buffer, tx_crypto) = self.get_req(&context, initial_data);
            (
                outbound_factory
                    .create_outbound(context, &tx_buffer)
                    .await?,
                tx_crypto,
            )
        };
        // Must specify C explicitly due to https://github.com/rust-lang/rust/issues/83249
        Ok(Box::new(stream::ShadowsocksStream::<C> {
            reader: StreamReader::new(4096),
            rx_buf: None,
            rx_chunk_size: std::num::NonZeroUsize::new(4096).unwrap(),
            lower: next,
            tx_offset: 0,
            rx_crypto: stream::RxCryptoState::ReadingIv { key: self.key },
            tx_crypto,
        }))
    }
}
