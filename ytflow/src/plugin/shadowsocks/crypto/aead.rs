use super::*;

pub struct RustCryptoAead<Inner: AeadCore, const SALT_LEN: usize> {
    inner: Inner,
    nonce: GenericArray<u8, Inner::NonceSize>,
}

impl<Inner, const SALT_LEN: usize> ShadowCrypto for RustCryptoAead<Inner, SALT_LEN>
where
    Inner: AeadCore<TagSize = U16> + KeyInit + AeadInPlace + Send + Sync + Unpin + 'static,
    GenericArray<u8, Inner::NonceSize>: Send + Sync + Unpin + 'static,
{
    const KEY_LEN: usize = Inner::KeySize::USIZE;
    const IV_LEN: usize = SALT_LEN;
    const PRE_CHUNK_OVERHEAD: usize = 2 + 16;
    const POST_CHUNK_OVERHEAD: usize = 16;

    fn create_crypto(key: &[u8; Self::KEY_LEN], iv: &[u8; Self::IV_LEN]) -> Self {
        let mut subkey = [0u8; Self::KEY_LEN];
        Hkdf::<Sha1>::new(Some(b"ss-subkey"), key)
            .expand(iv, &mut subkey)
            .unwrap();

        Self {
            inner: Inner::new_from_slice(&subkey).unwrap(),
            nonce: Default::default(),
        }
    }

    fn encrypt(
        &mut self,
        pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
        data: &mut [u8],
        post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
    ) {
        pre_overhead[0..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
        let tag = self
            .inner
            .encrypt_in_place_detached(&self.nonce, &[], &mut pre_overhead[0..2])
            .unwrap();
        pre_overhead[2..].copy_from_slice(&tag);
        increase_num_buf(&mut self.nonce);
        let tag = self
            .inner
            .encrypt_in_place_detached(&self.nonce, &[], data)
            .unwrap();
        post_overhead.copy_from_slice(&tag);
        increase_num_buf(&mut self.nonce);
    }

    fn decrypt_size(
        &mut self,
        pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
    ) -> Option<NonZeroUsize> {
        let (size_buf, size_tag) = pre_overhead.split_at_mut(2);
        if self
            .inner
            .decrypt_in_place_detached(&self.nonce, &[], size_buf, (&*size_tag).into())
            .is_err()
        {
            return None;
        }
        increase_num_buf(&mut self.nonce);
        let size = u16::from_be_bytes((&size_buf[..]).try_into().unwrap()) & 0x3fff;
        NonZeroUsize::new(size as usize)
    }

    fn decrypt(
        &mut self,
        data: &mut [u8],
        post_overhead: &[u8; Self::POST_CHUNK_OVERHEAD],
    ) -> bool {
        let res = self
            .inner
            .decrypt_in_place_detached(&self.nonce, &[], data, (&*post_overhead).into())
            .is_ok();
        increase_num_buf(&mut self.nonce);
        res
    }
}
