use cfb_mode::{BufDecryptor, BufEncryptor};
use cipher::{generic_array::ArrayLength, BlockCipher, BlockEncrypt, BlockSizeUser};

use super::*;

pub struct RustCryptoCfb128<C: BlockCipher + BlockEncrypt, const IV_LEN: usize> {
    enc: BufEncryptor<C>,
    dec: BufDecryptor<C>,
}

impl<C: BlockCipher + BlockEncrypt, const IV_LEN: usize> ShadowCrypto
    for RustCryptoCfb128<C, IV_LEN>
where
    C: KeyInit + Unpin + Send + Sync + 'static,
    <<C as BlockSizeUser>::BlockSize as ArrayLength<u8>>::ArrayType: Unpin,
{
    const KEY_LEN: usize = C::KeySize::USIZE;
    const IV_LEN: usize = IV_LEN;
    const PRE_CHUNK_OVERHEAD: usize = 0;
    const POST_CHUNK_OVERHEAD: usize = 0;

    fn create_crypto(key: &[u8; Self::KEY_LEN], iv: &[u8; Self::IV_LEN]) -> Self {
        Self {
            enc: BufEncryptor::new_from_slices(key, iv).unwrap(),
            dec: BufDecryptor::new_from_slices(key, iv).unwrap(),
        }
    }

    fn encrypt(
        &mut self,
        _pre_overhead: &mut [u8; 0],
        data: &mut [u8],
        _post_overhead: &mut [u8; 0],
    ) {
        self.enc.encrypt(data);
    }
    fn encrypt_all(
        &mut self,
        data: &mut [u8],
        _post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
    ) {
        self.enc.encrypt(data);
    }

    fn decrypt_size(
        &mut self,
        _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
    ) -> Option<NonZeroUsize> {
        None
    }

    fn decrypt(
        &mut self,
        data: &mut [u8],
        _post_overhead: &[u8; Self::POST_CHUNK_OVERHEAD],
    ) -> bool {
        self.dec.decrypt(data);
        true
    }
}
