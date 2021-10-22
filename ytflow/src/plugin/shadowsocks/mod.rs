mod crypto;
mod stream;
pub(crate) mod util;
mod xchacha20;

use std::convert::TryInto;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use async_trait::async_trait;

use crate::flow::*;
use crypto::*;

struct ShadowsocksStreamOutboundFactory<C: ShadowCrypto>
where
    [(); C::KEY_LEN]: ,
{
    key: [u8; C::KEY_LEN],
    next: Weak<dyn StreamOutboundFactory>,
    crypto_phantom: std::marker::PhantomData<C>,
}

pub fn create_factory(
    method: &str,
    password: &str,
    next: Weak<dyn StreamOutboundFactory>,
) -> Option<Arc<dyn StreamOutboundFactory>> {
    use util::openssl_bytes_to_key as bk;

    let p = password.as_bytes();
    #[rustfmt::skip]
    Some(match method {
        "none" | "plain" => Arc::new(ShadowsocksStreamOutboundFactory::<Plain> { key: [], crypto_phantom: PhantomData, next }),
        "rc4" => Arc::new(ShadowsocksStreamOutboundFactory::<Rc4>{ key: bk(p), crypto_phantom: PhantomData, next}),
        "rc4-md5" => Arc::new(ShadowsocksStreamOutboundFactory::<Rc4Md5>{ key: bk(p), crypto_phantom: PhantomData, next}),
        "aes-128-cfb" => Arc::new(ShadowsocksStreamOutboundFactory::<Aes128Cfb> { key: bk(p), crypto_phantom: PhantomData, next }),
        "aes-192-cfb" => Arc::new(ShadowsocksStreamOutboundFactory::<Aes192Cfb> { key: bk(p), crypto_phantom: PhantomData, next }),
        "aes-256-cfb" => Arc::new(ShadowsocksStreamOutboundFactory::<Aes128Cfb> { key: bk(p), crypto_phantom: PhantomData, next }),
        "aes-128-ctr" => Arc::new(ShadowsocksStreamOutboundFactory::<Aes128Ctr> { key: bk(p), crypto_phantom: PhantomData, next }),
        "aes-192-ctr" => Arc::new(ShadowsocksStreamOutboundFactory::<Aes192Ctr> { key: bk(p), crypto_phantom: PhantomData, next }),
        "aes-256-ctr" => Arc::new(ShadowsocksStreamOutboundFactory::<Aes128Ctr> { key: bk(p), crypto_phantom: PhantomData, next }),
        "camellia-128-cfb" => Arc::new(ShadowsocksStreamOutboundFactory::<Camellia128Cfb> { key: bk(p), crypto_phantom: PhantomData, next }),
        "camellia-192-cfb" => Arc::new(ShadowsocksStreamOutboundFactory::<Camellia192Cfb> { key: bk(p), crypto_phantom: PhantomData, next }),
        "camellia-256-cfb" => Arc::new(ShadowsocksStreamOutboundFactory::<Camellia128Cfb> { key: bk(p), crypto_phantom: PhantomData, next }),
        "aes-128-gcm" => Arc::new(ShadowsocksStreamOutboundFactory::<Aes128Gcm> { key: bk(p), crypto_phantom: PhantomData, next }),
        "aes-256-gcm" => Arc::new(ShadowsocksStreamOutboundFactory::<Aes256Gcm> { key: bk(p), crypto_phantom: PhantomData, next }),
        "chacha20-ietf" => Arc::new(ShadowsocksStreamOutboundFactory::<Chacha20Ietf> { key: bk(p), crypto_phantom: PhantomData, next}),
        "chacha20-ietf-poly1305" => Arc::new(ShadowsocksStreamOutboundFactory::<Chacha20IetfPoly1305> { key: bk(p), crypto_phantom: PhantomData, next }),
        "xchacha20-ietf-poly1305" => Arc::new(ShadowsocksStreamOutboundFactory::<XChacha20IetfPoly1305> { key: bk(p), crypto_phantom: PhantomData, next }),
        _ => return None,
    })
}

impl<C: ShadowCrypto> ShadowsocksStreamOutboundFactory<C>
where
    [(); C::KEY_LEN]: ,
    [(); C::IV_LEN]: ,
    [(); C::PRE_CHUNK_OVERHEAD]: ,
    [(); C::POST_CHUNK_OVERHEAD]: ,
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
    [(); C::KEY_LEN]: ,
    [(); C::IV_LEN]: ,
    [(); C::PRE_CHUNK_OVERHEAD]: ,
    [(); C::POST_CHUNK_OVERHEAD]: ,
{
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<Pin<Box<dyn Stream>>> {
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
        Ok(Box::pin(stream::ShadowsocksStream::<C> {
            internal_rx_buf: Some(Vec::with_capacity(4096)),
            rx_buf: None,
            rx_chunk_size: std::num::NonZeroUsize::new(4096).unwrap(),
            lower: next,
            tx_offset: 0,
            rx_crypto: stream::RxCryptoState::ReadingIv { key: self.key },
            tx_crypto,
        }))
    }
}
