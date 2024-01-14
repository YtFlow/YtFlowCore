use std::sync::{Arc, Weak};

use async_trait::async_trait;

use super::super::datagram::ShadowsocksDatagramSession;
use super::ShadowCrypto;
use crate::flow::*;

pub struct ShadowsocksDatagramSessionFactory<C: ShadowCrypto>
where
    [(); C::KEY_LEN]:,
{
    pub(super) key: Arc<[u8; C::KEY_LEN]>,
    pub(super) next: Weak<dyn DatagramSessionFactory>,
    pub(super) crypto_phantom: std::marker::PhantomData<C>,
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
