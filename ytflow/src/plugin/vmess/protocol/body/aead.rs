use aes_gcm::Aes128Gcm;
use aes_gcm::{aes::cipher::Unsigned, AeadCore, AeadInPlace};
use chacha20poly1305::ChaCha20Poly1305;
use cipher::KeyInit;
use md5::{Digest, Md5};

use super::super::header::{
    DATA_IV_LEN, DATA_KEY_LEN, VMESS_HEADER_ENC_AES_GCM, VMESS_HEADER_ENC_CHACHA_POLY,
};
use super::{BodyCryptoFactory, RxCrypto, SizeCrypto, TxCrypto};
use crate::flow::{FlowError, FlowResult};

pub struct AeadClientCryptoTx<S, C: AeadCore>
where
    [(); C::NonceSize::USIZE]:,
{
    size_crypto: S,
    enc: C,
    count: u16,
    nonce: [u8; C::NonceSize::USIZE],
}

pub struct AeadClientCryptoRx<S, C: AeadCore>
where
    [(); C::NonceSize::USIZE]:,
{
    size_crypto: S,
    expected_chunk_len: usize,
    dec: C,
    count: u16,
    nonce: [u8; C::NonceSize::USIZE],
}

impl<S> AeadClientCryptoTx<S, Aes128Gcm> {
    pub fn new_aes_gcm(
        data_key: &[u8; DATA_KEY_LEN],
        data_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
    ) -> Self {
        let enc = Aes128Gcm::new_from_slice(&data_key[..]).unwrap();
        let mut nonce = [0; 12];
        nonce.copy_from_slice(&data_iv[..12]);
        Self {
            size_crypto,
            enc,
            count: 0,
            nonce,
        }
    }
}

impl<S> AeadClientCryptoTx<S, ChaCha20Poly1305> {
    pub fn new_chacha_poly(
        data_key: &[u8; DATA_KEY_LEN],
        data_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
    ) -> Self {
        let key = {
            let hash1 = Md5::digest(data_key);
            let hash2 = Md5::digest(hash1);
            let mut key = [0; 32];
            key[..16].copy_from_slice(&hash1[..]);
            key[16..].copy_from_slice(&hash2[..]);
            key
        };
        let enc = ChaCha20Poly1305::new_from_slice(&key[..]).unwrap();

        let mut nonce = [0; 12];
        nonce.copy_from_slice(&data_iv[..12]);
        Self {
            size_crypto,
            enc,
            count: 0,
            nonce,
        }
    }
}

impl<S> AeadClientCryptoRx<S, Aes128Gcm> {
    pub fn new_aes_gcm(
        res_key: &[u8; DATA_KEY_LEN],
        res_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
    ) -> Self {
        let dec = Aes128Gcm::new_from_slice(&res_key[..]).unwrap();
        let mut nonce = [0; 12];
        nonce.copy_from_slice(&res_iv[..12]);
        Self {
            size_crypto,
            expected_chunk_len: 0,
            dec,
            count: 0,
            nonce,
        }
    }
}

impl<S> AeadClientCryptoRx<S, ChaCha20Poly1305> {
    pub fn new_chacha_poly(
        data_key: &[u8; DATA_KEY_LEN],
        data_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
    ) -> Self {
        let key = {
            let hash1 = Md5::digest(data_key);
            let hash2 = Md5::digest(hash1);
            let mut key = [0; 32];
            key[..16].copy_from_slice(&hash1[..]);
            key[16..].copy_from_slice(&hash2[..]);
            key
        };
        let dec = ChaCha20Poly1305::new_from_slice(&key[..]).unwrap();

        let mut nonce = [0; 12];
        nonce.copy_from_slice(&data_iv[..12]);
        Self {
            size_crypto,
            expected_chunk_len: 0,
            dec,
            count: 0,
            nonce,
        }
    }
}

impl<S: SizeCrypto, C: AeadCore + AeadInPlace> TxCrypto for AeadClientCryptoTx<S, C>
where
    [(); S::LEN]:,
    [(); C::NonceSize::USIZE]:,
{
    fn calculate_overhead(&mut self, _next_payload_len: usize) -> (usize, usize) {
        (S::LEN, C::TagSize::USIZE)
    }

    fn seal(&mut self, pre_overhead: &mut [u8], payload: &mut [u8], post_overhead: &mut [u8]) {
        pre_overhead.copy_from_slice(
            &self
                .size_crypto
                .encode_size(payload.len() + C::TagSize::USIZE),
        );

        let mut nonce = self.nonce;
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        let tag = self
            .enc
            .encrypt_in_place_detached((&nonce[..]).into(), &[], payload)
            .unwrap();
        post_overhead.copy_from_slice(&tag);

        self.count = self.count.wrapping_add(1);
    }
}

impl<S: SizeCrypto, C: AeadCore + AeadInPlace> RxCrypto for AeadClientCryptoRx<S, C>
where
    [(); S::LEN]:,
    [(); C::NonceSize::USIZE]:,
{
    fn expected_next_size_len(&mut self) -> usize {
        S::LEN
    }

    fn on_size(&mut self, size_bytes: &mut [u8]) -> FlowResult<usize> {
        let len = self
            .size_crypto
            .decode_size(&mut size_bytes[..].try_into().unwrap())?;
        match len.cmp(&C::TagSize::USIZE) {
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
        let (payload, tag) = chunk.split_at_mut(chunk.len() - C::TagSize::USIZE);
        let mut nonce = self.nonce;
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        self.dec
            .decrypt_in_place_detached((&nonce[..]).into(), &[], payload, (&*tag).into())
            .map_err(|_| FlowError::UnexpectedData)?;

        self.count = self.count.wrapping_add(1);
        Ok(payload)
    }
}

pub struct AesGcmCryptoFactory {}
pub struct ChachaPolyCryptoFactory {}

impl BodyCryptoFactory for AesGcmCryptoFactory {
    type Rx<S: SizeCrypto> = AeadClientCryptoRx<S, Aes128Gcm>
    where
        [(); S::LEN]:,;
    type Tx<S: SizeCrypto> = AeadClientCryptoTx<S, Aes128Gcm>
    where
        [(); S::LEN]:,;
    const HEADER_SEC_TYPE: u8 = VMESS_HEADER_ENC_AES_GCM;

    fn new_tx<S: SizeCrypto>(
        &self,
        data_key: &[u8; DATA_KEY_LEN],
        data_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
    ) -> Self::Tx<S>
    where
        [(); S::LEN]:,
    {
        AeadClientCryptoTx::new_aes_gcm(data_key, data_iv, size_crypto)
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
        AeadClientCryptoRx::new_aes_gcm(res_key, res_iv, size_crypto)
    }
}

impl BodyCryptoFactory for ChachaPolyCryptoFactory {
    type Rx<S: SizeCrypto> = AeadClientCryptoRx<S, ChaCha20Poly1305>
    where
        [(); S::LEN]:,;
    type Tx<S: SizeCrypto> = AeadClientCryptoTx<S, ChaCha20Poly1305>
    where
        [(); S::LEN]:,;
    const HEADER_SEC_TYPE: u8 = VMESS_HEADER_ENC_CHACHA_POLY;

    fn new_tx<S: SizeCrypto>(
        &self,
        data_key: &[u8; DATA_KEY_LEN],
        data_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
    ) -> Self::Tx<S>
    where
        [(); S::LEN]:,
    {
        AeadClientCryptoTx::new_chacha_poly(data_key, data_iv, size_crypto)
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
        AeadClientCryptoRx::new_chacha_poly(res_key, res_iv, size_crypto)
    }
}
