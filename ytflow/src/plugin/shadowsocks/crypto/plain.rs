use super::*;

pub struct Plain {}

impl ShadowCrypto for Plain {
    const KEY_LEN: usize = 0;
    const IV_LEN: usize = 0;
    const PRE_CHUNK_OVERHEAD: usize = 0;
    const POST_CHUNK_OVERHEAD: usize = 0;

    fn create_crypto(_key: &[u8; Self::KEY_LEN], _iv: &[u8; Self::IV_LEN]) -> Self {
        Plain {}
    }

    fn encrypt(
        &mut self,
        _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
        _data: &mut [u8],
        _post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
    ) {
    }

    fn decrypt_size(
        &mut self,
        _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
    ) -> Option<NonZeroUsize> {
        None
    }

    #[must_use]
    fn decrypt(
        &mut self,
        _data: &mut [u8],
        _post_overhead: &[u8; Self::POST_CHUNK_OVERHEAD],
    ) -> bool {
        true
    }
}
