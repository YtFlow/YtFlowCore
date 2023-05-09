use super::super::header::{DATA_IV_LEN, DATA_KEY_LEN, VMESS_HEADER_ENC_NONE};
use super::{BodyCryptoFactory, RxCrypto, SizeCrypto, TxCrypto};
use crate::flow::{FlowError, FlowResult};

pub struct NoneClientCryptoTx<S> {
    size_crypto: S,
}

pub struct NoneClientCryptoRx<S> {
    size_crypto: S,
    expected_chunk_len: usize,
}

impl<S> NoneClientCryptoTx<S> {
    pub fn new(size_crypto: S) -> Self {
        Self { size_crypto }
    }
}

impl<S> NoneClientCryptoRx<S> {
    pub fn new(size_crypto: S) -> Self {
        Self {
            size_crypto,
            expected_chunk_len: 0,
        }
    }
}

impl<S: SizeCrypto> TxCrypto for NoneClientCryptoTx<S>
where
    [(); S::LEN]:,
{
    fn calculate_overhead(&mut self, _next_payload_len: usize) -> (usize, usize) {
        (S::LEN, 0)
    }

    fn seal(&mut self, pre_overhead: &mut [u8], payload: &mut [u8], _post_overhead: &mut [u8]) {
        pre_overhead.copy_from_slice(&self.size_crypto.encode_size(payload.len()));
    }
}

impl<S: SizeCrypto> RxCrypto for NoneClientCryptoRx<S>
where
    [(); S::LEN]:,
{
    fn expected_next_size_len(&mut self) -> usize {
        S::LEN
    }

    fn on_size(&mut self, size_bytes: &mut [u8]) -> FlowResult<usize> {
        let len = self
            .size_crypto
            .decode_size(&mut size_bytes[..].try_into().unwrap())?;
        if len == 0 {
            return Err(FlowError::Eof);
        }
        self.expected_chunk_len = len;
        Ok(len)
    }

    fn expected_next_chunk_len(&mut self) -> usize {
        self.expected_chunk_len
    }

    fn on_chunk<'c>(&mut self, chunk: &'c mut [u8]) -> FlowResult<&'c mut [u8]> {
        Ok(chunk)
    }
}

pub struct NoneCryptoFactory {}

impl BodyCryptoFactory for NoneCryptoFactory {
    type Rx<S: SizeCrypto> = NoneClientCryptoRx<S>
    where
        [(); S::LEN]:,;
    type Tx<S: SizeCrypto> = NoneClientCryptoTx<S>
    where
        [(); S::LEN]:,;
    const HEADER_SEC_TYPE: u8 = VMESS_HEADER_ENC_NONE;

    fn new_tx<S: SizeCrypto>(
        &self,
        _data_key: &[u8; DATA_KEY_LEN],
        _data_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
    ) -> Self::Tx<S>
    where
        [(); S::LEN]:,
    {
        NoneClientCryptoTx::new(size_crypto)
    }
    fn new_rx<S: SizeCrypto>(
        &self,
        _res_key: &[u8; DATA_KEY_LEN],
        _res_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
    ) -> Self::Rx<S>
    where
        [(); S::LEN]:,
    {
        NoneClientCryptoRx::new(size_crypto)
    }
}
