use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::ready;

use super::crypto::*;
use super::util::{parse_dest, write_dest};
use crate::flow::*;

pub struct ShadowsocksDatagramSessionFactory<C: ShadowCrypto>
where
    [(); C::KEY_LEN]:,
{
    pub(super) key: Arc<[u8; C::KEY_LEN]>,
    pub(super) next: Weak<dyn DatagramSessionFactory>,
    pub(super) crypto_phantom: std::marker::PhantomData<C>,
}

struct ShadowsocksDatagramSession<C: ShadowCrypto>
where
    [(); C::KEY_LEN]:,
{
    key: Arc<[u8; C::KEY_LEN]>,
    lower: Box<dyn DatagramSession>,
    crypto_phantom: std::marker::PhantomData<C>,
}

#[async_trait]
impl<C: ShadowCrypto> DatagramSessionFactory for ShadowsocksDatagramSessionFactory<C>
where
    [(); C::KEY_LEN]:,
    [(); C::IV_LEN]:,
    [(); C::POST_CHUNK_OVERHEAD]:,
{
    async fn bind(&self, context: Box<FlowContext>) -> FlowResult<Box<dyn DatagramSession>> {
        let next = self.next.upgrade().ok_or(FlowError::NoOutbound)?;
        Ok(Box::new(ShadowsocksDatagramSession::<C> {
            key: self.key.clone(),
            lower: next.bind(context).await?,
            crypto_phantom: std::marker::PhantomData,
        }))
    }
}

impl<C: ShadowCrypto> DatagramSession for ShadowsocksDatagramSession<C>
where
    [(); C::KEY_LEN]:,
    [(); C::IV_LEN]:,
    [(); C::POST_CHUNK_OVERHEAD]:,
{
    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>> {
        let Some((_, mut buf)) = ready!(self.lower.poll_recv_from(cx)) else {
            return Poll::Ready(None);
        };
        if buf.len() <= C::IV_LEN + C::POST_CHUNK_OVERHEAD {
            return Poll::Ready(None);
        }
        let (iv, rem) = buf.split_at_mut(C::IV_LEN);
        let (payload, post_overhead) = rem.split_at_mut(rem.len() - C::POST_CHUNK_OVERHEAD);
        let mut crypto = C::create_crypto(&self.key, (&*iv).try_into().unwrap());
        if !crypto.decrypt(payload, (&*post_overhead).try_into().unwrap()) {
            return Poll::Ready(None);
        }
        let Some((dst, header_offset)) = parse_dest(payload) else {
            return Poll::Ready(None);
        };
        buf.drain(..C::IV_LEN + header_offset);
        buf.truncate(buf.len() - C::POST_CHUNK_OVERHEAD);
        Poll::Ready(Some((dst, buf)))
    }

    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.lower.poll_send_ready(cx)
    }

    fn send_to(&mut self, remote_peer: DestinationAddr, buf: Buffer) {
        let mut tx_handshake = Vec::with_capacity(259 + buf.len());
        write_dest(&mut tx_handshake, &remote_peer);
        tx_handshake.extend_from_slice(&buf);

        // TODO: Skip zero-fill tx_handshake part
        let mut req_buf = vec![0; C::IV_LEN + tx_handshake.len() + C::POST_CHUNK_OVERHEAD];
        let (iv, remaining) = req_buf.split_at_mut(C::IV_LEN);
        let (chunk, post_overhead) = remaining.split_at_mut(tx_handshake.len());

        getrandom::getrandom(iv).unwrap();
        chunk.copy_from_slice(&tx_handshake);

        let iv: &mut [u8; C::IV_LEN] = iv.try_into().unwrap();
        let post_overhead: &mut [u8; C::POST_CHUNK_OVERHEAD] = post_overhead.try_into().unwrap();
        let mut tx_crypto = C::create_crypto(&self.key, iv);
        tx_crypto.encrypt_all(chunk, post_overhead);
        self.lower.send_to(remote_peer, req_buf.into());
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.poll_shutdown(cx)
    }
}
