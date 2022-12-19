use super::ctor::StreamCryptoCtor;
use super::*;

pub struct RustCryptoStream<Ctor: StreamCryptoCtor, const IV_LEN: usize> {
    inner: Ctor::Output,
    ctor: PhantomData<Ctor>,
}

impl<Ctor, const IV_LEN: usize> ShadowCrypto for RustCryptoStream<Ctor, IV_LEN>
where
    Ctor: Send + Sync + Unpin + 'static + StreamCryptoCtor,
    Ctor::Output: KeySizeUser + StreamCipher + Send + Sync + Unpin + 'static,
{
    const KEY_LEN: usize = <Ctor::Output as KeySizeUser>::KeySize::USIZE;
    const IV_LEN: usize = IV_LEN;
    const PRE_CHUNK_OVERHEAD: usize = 0;
    const POST_CHUNK_OVERHEAD: usize = 0;

    fn create_crypto(key: &[u8; Self::KEY_LEN], iv: &[u8; Self::IV_LEN]) -> Self {
        let inner = Ctor::create_crypto(key, iv);
        Self {
            inner,
            ctor: PhantomData,
        }
    }

    fn encrypt(
        &mut self,
        _pre_overhead: &mut [u8; 0],
        data: &mut [u8],
        _post_overhead: &mut [u8; 0],
    ) {
        self.inner.apply_keystream(data);
    }
    fn encrypt_all(
        &mut self,
        data: &mut [u8],
        _post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
    ) {
        self.inner.apply_keystream(data);
    }

    fn decrypt_size(&mut self, _pre_overhead: &mut [u8; 0]) -> Option<NonZeroUsize> {
        None
    }

    fn decrypt(&mut self, data: &mut [u8], _post_overhead: &[u8; 0]) -> bool {
        self.inner.apply_keystream(data);
        true
    }
}
