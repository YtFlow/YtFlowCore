use aes_gcm::aes::cipher::{
    generic_array::GenericArray, typenum::U12, BlockEncryptMut, BlockSizeUser, KeyInit,
    KeySizeUser, Unsigned,
};
use aes_gcm::{aes::Aes128, AeadCore, AeadInPlace, Aes128Gcm};
use getrandom::getrandom;
use sha2::{Digest, Sha256};

use super::super::USER_ID_LEN;
use super::{
    derive_cmd_key, hmac_hash, HeaderDecryptResult, RequestHeader, RequestHeaderEnc,
    ResponseHeader, ResponseHeaderDec, HEADER_IV_LEN, HEADER_KEY_LEN,
};

pub(super) const AUTH_ID_LEN: usize = 16;
const HEADER_SIZE_LEN: usize = 2;
pub(super) const NONCE_LEN: usize = 8;
const AEAD_KEY_LEN: usize = <Aes128 as KeySizeUser>::KeySize::USIZE;
const AEAD_TAG_LEN: usize = <Aes128Gcm as AeadCore>::TagSize::USIZE;
const AEAD_NONCE_LEN: usize = <Aes128Gcm as AeadCore>::NonceSize::USIZE;

pub struct AeadRequestEnc {
    auth_id: [u8; AUTH_ID_LEN],
    random_nonce: [u8; NONCE_LEN],
    header_size_enc: Aes128Gcm,
    header_size_nonce: GenericArray<u8, U12>,
    header_enc: Aes128Gcm,
    header_nonce: GenericArray<u8, U12>,
}

pub struct AeadRequestDec {
    res_auth: u8,
    anticipated_res_size: usize,
    header_size_dec: Aes128Gcm,
    header_size_nonce: GenericArray<u8, U12>,
    header_dec: Aes128Gcm,
    header_nonce: GenericArray<u8, U12>,
}

fn compose_eauid_plaintext(
    utc_timestamp: u64,
    rand: u32,
) -> [u8; <Aes128 as BlockSizeUser>::BlockSize::USIZE] {
    let mut plaintext = [0u8; <Aes128 as BlockSizeUser>::BlockSize::USIZE];
    plaintext[..8].copy_from_slice(&utc_timestamp.to_be_bytes());
    plaintext[8..12].copy_from_slice(&rand.to_be_bytes());
    let checksum = crc32fast::hash(&plaintext[..12]);
    plaintext[12..16].copy_from_slice(&checksum.to_be_bytes());
    plaintext
}

impl AeadRequestEnc {
    pub fn new(utc_timestamp: u64, user_id: &[u8; USER_ID_LEN], random: u32) -> Self {
        let cmd_key = derive_cmd_key(user_id);
        let auth_id = {
            let eauid = compose_eauid_plaintext(utc_timestamp, random);
            let auid_key = hmac_hash::derive_auth_id_key(&cmd_key);
            let mut aes = Aes128::new_from_slice(&auid_key[..AEAD_KEY_LEN]).unwrap();
            let mut auth_id = [0; AUTH_ID_LEN];
            aes.encrypt_block_b2b_mut((&eauid).into(), (&mut auth_id).into());
            auth_id
        };
        let mut random_nonce = [0; NONCE_LEN];
        getrandom(&mut random_nonce).unwrap();
        let header_size_enc = {
            let key = hmac_hash::derive_aead_header_size_key(&cmd_key, &auth_id, &random_nonce);
            Aes128Gcm::new_from_slice(&key[..AEAD_KEY_LEN]).unwrap()
        };
        let header_size_nonce = {
            let mut nonce = [0; AEAD_NONCE_LEN];
            let hash = hmac_hash::derive_aead_header_size_iv(&cmd_key, &auth_id, &random_nonce);
            nonce.copy_from_slice(&hash[..AEAD_NONCE_LEN]);
            nonce.into()
        };
        let header_enc = {
            let key = hmac_hash::derive_aead_header_key(&cmd_key, &auth_id, &random_nonce);
            Aes128Gcm::new_from_slice(&key[..AEAD_KEY_LEN]).unwrap()
        };
        let header_nonce = {
            let mut nonce = [0; AEAD_NONCE_LEN];
            let hash = hmac_hash::derive_aead_header_iv(&cmd_key, &auth_id, &random_nonce);
            nonce.copy_from_slice(&hash[..AEAD_NONCE_LEN]);
            nonce.into()
        };
        Self {
            auth_id,
            random_nonce,
            header_size_enc,
            header_size_nonce,
            header_enc,
            header_nonce,
        }
    }
}

impl RequestHeaderEnc for AeadRequestEnc {
    type Dec = AeadRequestDec;

    const REQUIRED_SIZE: usize = AUTH_ID_LEN
        + HEADER_SIZE_LEN + AEAD_TAG_LEN /* AEAD tag */
        + NONCE_LEN
        + std::mem::size_of::<RequestHeader>() + AEAD_TAG_LEN /* AEAD tag */;

    fn derive_res_iv(&self, header: &RequestHeader) -> [u8; HEADER_IV_LEN] {
        let mut res_iv = [0; HEADER_IV_LEN];
        let res = Sha256::digest(&header.data_iv);
        res_iv[..].copy_from_slice(&res[..HEADER_IV_LEN]);
        res_iv
    }

    fn derive_res_key(&self, header: &RequestHeader) -> [u8; HEADER_KEY_LEN] {
        let mut res_key = [0; HEADER_KEY_LEN];
        let res = Sha256::digest(&header.data_key);
        res_key[..].copy_from_slice(&res[..HEADER_KEY_LEN]);
        res_key
    }

    fn encrypt_req(self, header: &mut RequestHeader, buf: &mut [u8]) -> Option<(usize, Self::Dec)> {
        buf[..AUTH_ID_LEN].copy_from_slice(&self.auth_id[..]);
        let (size_buf, remaining) = buf[AUTH_ID_LEN..].split_at_mut(HEADER_SIZE_LEN);
        let (size_tag_buf, remaining) = remaining.split_at_mut(AEAD_TAG_LEN);
        let (nonce_buf, remaining) = remaining.split_at_mut(NONCE_LEN);

        nonce_buf.copy_from_slice(&self.random_nonce[..]);

        let header_size = header.encode_to(remaining)?;
        let (header_buf, remaining) = remaining.split_at_mut(header_size);
        let header_tag_buf = &mut remaining[..AEAD_TAG_LEN];

        size_buf[..HEADER_SIZE_LEN].copy_from_slice(&(header_size as u16).to_be_bytes());
        let size_tag = self
            .header_size_enc
            .encrypt_in_place_detached(&self.header_size_nonce, &self.auth_id, &mut size_buf[..])
            .unwrap();
        size_tag_buf[..AEAD_TAG_LEN].copy_from_slice(&size_tag[..]);
        let header_tag = self
            .header_enc
            .encrypt_in_place_detached(&self.header_nonce, &self.auth_id, header_buf)
            .unwrap();
        header_tag_buf.copy_from_slice(&header_tag[..]);

        let res_key = self.derive_res_key(header);
        let res_iv = self.derive_res_iv(header);
        let header_size_dec = {
            let key = hmac_hash::derive_aead_res_size_key(&res_key);
            Aes128Gcm::new_from_slice(&key[..AEAD_KEY_LEN]).unwrap()
        };
        let header_size_nonce = {
            let mut nonce = [0; AEAD_NONCE_LEN];
            let hash = hmac_hash::derive_aead_res_size_iv(&res_iv);
            nonce.copy_from_slice(&hash[..AEAD_NONCE_LEN]);
            nonce.into()
        };
        let header_dec = {
            let key = hmac_hash::derive_aead_res_key(&res_key);
            Aes128Gcm::new_from_slice(&key[..AEAD_KEY_LEN]).unwrap()
        };
        let header_nonce = {
            let mut nonce = [0; AEAD_NONCE_LEN];
            let hash = hmac_hash::derive_aead_res_iv(&res_iv);
            nonce.copy_from_slice(&hash[..AEAD_NONCE_LEN]);
            nonce.into()
        };

        Some((
            AUTH_ID_LEN + HEADER_SIZE_LEN + AEAD_TAG_LEN + NONCE_LEN + header_size + AEAD_TAG_LEN,
            AeadRequestDec {
                res_auth: header.res_auth,
                anticipated_res_size: Default::default(),
                header_size_dec,
                header_size_nonce,
                header_dec,
                header_nonce,
            },
        ))
    }
}

impl ResponseHeaderDec for AeadRequestDec {
    fn decrypt_res<'a>(&mut self, data: &'a mut [u8]) -> HeaderDecryptResult<ResponseHeader> {
        const RES_LEN: usize = 4;
        // TODO: const time?
        // TODO: cmd bytes
        let Some(size_chunk) = data.get_mut(..HEADER_SIZE_LEN + AEAD_TAG_LEN) else {
            return HeaderDecryptResult::Incomplete {
                total_required: HEADER_SIZE_LEN
                    + AEAD_TAG_LEN
                    + self.anticipated_res_size
                    + AEAD_TAG_LEN,
            };
        };
        let (chunk, chunk_tag) = size_chunk.split_at_mut(HEADER_SIZE_LEN);
        let mut chunk = <[u8; HEADER_SIZE_LEN]>::try_from(chunk).unwrap();
        if let Err(_) = self.header_size_dec.clone().decrypt_in_place_detached(
            &self.header_size_nonce,
            &[][..],
            &mut chunk,
            (&*chunk_tag).into(),
        ) {
            return HeaderDecryptResult::Invalid;
        }
        let size = u16::from_be_bytes([chunk[0], chunk[1]]) as usize;
        self.anticipated_res_size = size;

        let Some(chunk) = data[HEADER_SIZE_LEN + AEAD_TAG_LEN..].get_mut(..size + AEAD_TAG_LEN)
        else {
            return HeaderDecryptResult::Incomplete {
                total_required: HEADER_SIZE_LEN + AEAD_TAG_LEN + size + AEAD_TAG_LEN,
            };
        };
        let (chunk, chunk_tag) = chunk.split_at_mut(size);
        if let Err(_) = self.header_dec.clone().decrypt_in_place_detached(
            &self.header_nonce,
            &[][..],
            chunk,
            (&*chunk_tag).into(),
        ) {
            return HeaderDecryptResult::Invalid;
        }

        if chunk.len() != RES_LEN {
            return HeaderDecryptResult::Invalid;
        }
        let chunk = <[u8; RES_LEN]>::try_from(chunk).unwrap();
        let res = ResponseHeader {
            res_auth: chunk[0],
            opt: chunk[1],
            cmd: chunk[2],
            cmd_len: chunk[3],
        };
        if res.res_auth != self.res_auth || res.cmd != 0 || res.cmd_len != 0 {
            return HeaderDecryptResult::Invalid;
        }
        HeaderDecryptResult::Complete {
            res,
            len: HEADER_SIZE_LEN + AEAD_TAG_LEN + RES_LEN + AEAD_TAG_LEN,
        }
    }
}
