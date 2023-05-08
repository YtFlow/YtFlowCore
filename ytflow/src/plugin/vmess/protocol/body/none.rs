use super::super::header::{HeaderDecryptResult, ResponseHeaderDec};
use super::{RxCrypto, SizeCrypto, TxCrypto};
use crate::flow::{FlowError, FlowResult};

pub struct NoneClientCryptoTx<S> {
    size_crypto: S,
}

pub struct NoneClientCryptoRx<S, D> {
    header_dec: Option<D>,
    size_crypto: S,
    expected_chunk_len: usize,
}

impl<S> NoneClientCryptoTx<S> {
    pub fn new(size_crypto: S) -> Self {
        Self { size_crypto }
    }
}

impl<S, D> NoneClientCryptoRx<S, D> {
    pub fn new(size_crypto: S, header_dec: D) -> Self {
        Self {
            header_dec: Some(header_dec),
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

impl<S: SizeCrypto, D: ResponseHeaderDec> RxCrypto for NoneClientCryptoRx<S, D>
where
    [(); S::LEN]:,
{
    fn expected_next_size_len(&mut self) -> usize {
        match &mut self.header_dec {
            Some(header_dec) => match header_dec.decrypt_res(&mut []) {
                HeaderDecryptResult::Incomplete { total_required } => S::LEN + total_required,
                _ => unreachable!("header_dec should return Incomplete with empty data"),
            },
            None => S::LEN,
        }
    }

    fn on_size(&mut self, size_bytes: &mut [u8]) -> FlowResult<Option<usize>> {
        let offset = match self.header_dec.take() {
            Some(mut dec) => match dec.decrypt_res(size_bytes) {
                HeaderDecryptResult::Invalid => return Err(FlowError::UnexpectedData),
                HeaderDecryptResult::Incomplete { .. } => {
                    self.header_dec = Some(dec);
                    return Ok(None);
                }
                HeaderDecryptResult::Complete { res: _, len } => len,
            },
            None => 0,
        };
        let len = self
            .size_crypto
            .decode_size(&mut size_bytes[offset..].try_into().unwrap())?;
        self.expected_chunk_len = len;
        Ok(Some(len))
    }

    fn expected_next_chunk_len(&mut self) -> usize {
        self.expected_chunk_len
    }

    fn on_chunk<'c>(&mut self, chunk: &'c mut [u8]) -> FlowResult<&'c mut [u8]> {
        Ok(chunk)
    }
}
