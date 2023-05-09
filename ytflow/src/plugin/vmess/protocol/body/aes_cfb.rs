use aes_gcm::aes::Aes128;
use cfb_mode::{cipher::KeyIvInit, BufDecryptor, BufEncryptor};
use const_fnv1a_hash::fnv1a_hash_32;
use subtle::ConstantTimeEq;

use super::super::header::{DATA_IV_LEN, DATA_KEY_LEN, VMESS_HEADER_ENC_AES_CFB};
use super::{BodyCryptoFactory, RxCrypto, SizeCrypto, TxCrypto};
use crate::flow::{FlowError, FlowResult};

const HASH_LEN: usize = 4;

pub struct AesCfbClientCryptoTx<S> {
    size_crypto: S,
    enc: BufEncryptor<Aes128>,
}

pub struct AesCfbClientCryptoRx<S> {
    size_crypto: S,
    expected_chunk_len: usize,
    dec: BufDecryptor<Aes128>,
    process_header_ciphertext: bool,
}

impl<S> AesCfbClientCryptoTx<S> {
    pub fn new(data_key: &[u8; DATA_KEY_LEN], data_iv: &[u8; DATA_IV_LEN], size_crypto: S) -> Self {
        let enc = BufEncryptor::new_from_slices(&data_key[..], &data_iv[..]).unwrap();
        Self { size_crypto, enc }
    }
}

impl<S> AesCfbClientCryptoRx<S> {
    pub fn new(
        res_key: &[u8; DATA_KEY_LEN],
        res_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
        process_header_ciphertext: bool,
    ) -> Self {
        let dec = BufDecryptor::new_from_slices(&res_key[..], &res_iv[..]).unwrap();
        Self {
            size_crypto,
            expected_chunk_len: 0,
            dec,
            process_header_ciphertext,
        }
    }
}

impl<S: SizeCrypto> TxCrypto for AesCfbClientCryptoTx<S>
where
    [(); S::LEN]:,
{
    fn calculate_overhead(&mut self, _next_payload_len: usize) -> (usize, usize) {
        (S::LEN + HASH_LEN, 0)
    }

    fn seal(&mut self, pre_overhead: &mut [u8], payload: &mut [u8], _post_overhead: &mut [u8]) {
        let (size_buf, hash_buf) = pre_overhead.split_at_mut(S::LEN);
        size_buf.copy_from_slice(&self.size_crypto.encode_size(payload.len() + HASH_LEN));
        hash_buf.copy_from_slice(&fnv1a_hash_32(payload, None).to_be_bytes());
        self.enc.encrypt(pre_overhead);
        self.enc.encrypt(payload);
    }
}

impl<S: SizeCrypto> RxCrypto for AesCfbClientCryptoRx<S>
where
    [(); S::LEN]:,
{
    fn peek_header_ciphertext(&mut self, header_ciphertext: &mut [u8]) {
        if self.process_header_ciphertext {
            self.dec.decrypt(header_ciphertext);
        }
    }

    fn expected_next_size_len(&mut self) -> usize {
        S::LEN
    }

    fn on_size(&mut self, size_bytes: &mut [u8]) -> FlowResult<usize> {
        self.dec.decrypt(size_bytes);
        let len = self
            .size_crypto
            .decode_size(&mut size_bytes[..].try_into().unwrap())?;
        match len.cmp(&HASH_LEN) {
            std::cmp::Ordering::Less => Err(FlowError::UnexpectedData),
            std::cmp::Ordering::Equal => Err(FlowError::Eof),
            std::cmp::Ordering::Greater => {
                self.expected_chunk_len = len;
                Ok(len)
            }
        }
    }

    fn expected_next_chunk_len(&mut self) -> usize {
        self.expected_chunk_len
    }

    fn on_chunk<'c>(&mut self, chunk: &'c mut [u8]) -> FlowResult<&'c mut [u8]> {
        let hash_buf = chunk.get_mut(..HASH_LEN).unwrap(); // size checked at `on_size`
        self.dec.decrypt(hash_buf);
        let exp_hash = u32::from_be_bytes(hash_buf[..].try_into().unwrap());
        let payload = chunk.get_mut(HASH_LEN..).unwrap();
        self.dec.decrypt(payload);
        let cmp = fnv1a_hash_32(payload, None).ct_eq(&exp_hash);
        if !bool::from(cmp) {
            return Err(FlowError::UnexpectedData);
        }
        Ok(payload)
    }
}

pub struct AesCfbCryptoFactory {
    pub process_header_ciphertext: bool,
}

impl BodyCryptoFactory for AesCfbCryptoFactory {
    type Rx<S: SizeCrypto> = AesCfbClientCryptoRx<S>
    where
        [(); S::LEN]:,;
    type Tx<S: SizeCrypto> = AesCfbClientCryptoTx<S>
    where
        [(); S::LEN]:,;
    const HEADER_SEC_TYPE: u8 = VMESS_HEADER_ENC_AES_CFB;

    fn new_tx<S: SizeCrypto>(
        &self,
        data_key: &[u8; DATA_KEY_LEN],
        data_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
    ) -> Self::Tx<S>
    where
        [(); S::LEN]:,
    {
        AesCfbClientCryptoTx::new(data_key, data_iv, size_crypto)
    }
    fn new_rx<S: SizeCrypto>(
        &self,
        res_key: &[u8; DATA_KEY_LEN],
        res_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
    ) -> Self::Rx<S>
    where
        [(); S::LEN]:,
    {
        AesCfbClientCryptoRx::new(res_key, res_iv, size_crypto, self.process_header_ciphertext)
    }
}
