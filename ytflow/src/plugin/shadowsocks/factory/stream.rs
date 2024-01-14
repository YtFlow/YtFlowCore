use std::sync::Weak;

use async_trait::async_trait;

use super::super::{stream, util};
use super::ShadowCrypto;
use crate::flow::*;

pub struct ShadowsocksStreamOutboundFactory<C: ShadowCrypto>
where
    [(); C::KEY_LEN]:,
{
    pub(super) key: [u8; C::KEY_LEN],
    pub(super) next: Weak<dyn StreamOutboundFactory>,
    pub(super) crypto_phantom: std::marker::PhantomData<C>,
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
        util::write_dest(&mut tx_handshake, &context.remote_peer);
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
        context: &mut FlowContext,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let outbound_factory = self.next.upgrade().ok_or(FlowError::NoOutbound)?;
        let ((next, initial_res), tx_crypto) = {
            let (tx_buffer, tx_crypto) = self.get_req(&context, initial_data);
            (
                outbound_factory
                    .create_outbound(context, &tx_buffer)
                    .await?,
                tx_crypto,
            )
        };
        // Must specify C explicitly due to https://github.com/rust-lang/rust/issues/83249
        Ok((
            Box::new(stream::ShadowsocksStream::<C> {
                reader: StreamReader::new(4096, initial_res),
                rx_buf: None,
                rx_chunk_size: std::num::NonZeroUsize::new(4096).unwrap(),
                lower: next,
                tx_offset: 0,
                rx_crypto: stream::RxCryptoState::ReadingIv { key: self.key },
                tx_crypto,
            }),
            Buffer::new(),
        ))
    }
}
