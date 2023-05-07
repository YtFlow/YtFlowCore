use aes_gcm::aes::Aes128;
use cfb_mode::{BufDecryptor, BufEncryptor};
use hmac::{Mac, SimpleHmac};
use md5::{Digest, Md5};

use super::header::{RequestHeader, ResponseHeader};

pub(crate) const VMESS_HEADER_KEY_LEN: usize = 16;
pub(crate) const VMESS_HEADER_IV_LEN: usize = 16;
pub(crate) const AES_CFB_HEADER_CERTIFICATION_LEN: usize = 16;

pub enum HeaderDecryptResult<T> {
    Invalid,
    Incomplete { total_required: usize },
    Complete { res: T, len: usize },
}

pub trait RequestHeaderEnc {
    type Dec: ResponseHeaderDec;

    const REQUIRED_SIZE: usize;

    fn encrypt_req(self, header: &mut RequestHeader, buf: &mut [u8]) -> Option<(usize, Self::Dec)>;
}

pub trait ResponseHeaderDec {
    #[must_use]
    fn decrypt_res<'a>(&mut self, data: &'a mut [u8]) -> HeaderDecryptResult<ResponseHeader>;
}

pub struct AesCfbRequestEnc {
    certification: [u8; AES_CFB_HEADER_CERTIFICATION_LEN],
    enc: BufEncryptor<Aes128>,
}

pub struct AesCfbResponseDec {
    res_auth: u8,
    dec: BufDecryptor<Aes128>,
}

impl AesCfbRequestEnc {
    pub fn new(utc_timestamp: u64, user_id: &[u8; super::USER_ID_LEN]) -> Self {
        let utc_timestamp = utc_timestamp.to_be_bytes();
        let certification = {
            let mut certification_hash = SimpleHmac::<md5::Md5>::new_from_slice(user_id).unwrap();
            // TODO: purturb timestamp
            certification_hash.update(&utc_timestamp);
            certification_hash.finalize().into_bytes()
        };

        let enc = {
            use cipher::KeyIvInit;
            let header_key = {
                let mut cmd_key = *b"????????????????c48619fe-8f02-49e0-b9e9-edf763e17e21";
                cmd_key[..super::USER_ID_LEN].copy_from_slice(user_id);
                let mut header_key_hash = Md5::new();
                header_key_hash.update(cmd_key);
                header_key_hash.finalize()
            };
            let header_iv = {
                let mut header_iv_hash = Md5::new();
                for _ in 0..4 {
                    header_iv_hash.update(utc_timestamp);
                }
                header_iv_hash.finalize()
            };
            BufEncryptor::new_from_slices(&header_key[..], &header_iv[..]).unwrap()
        };

        Self {
            certification: certification.into(),
            enc,
        }
    }
}

impl RequestHeaderEnc for AesCfbRequestEnc {
    type Dec = AesCfbResponseDec;

    const REQUIRED_SIZE: usize =
        AES_CFB_HEADER_CERTIFICATION_LEN + std::mem::size_of::<RequestHeader>();

    fn encrypt_req(
        mut self,
        header: &mut RequestHeader,
        buf: &mut [u8],
    ) -> Option<(usize, Self::Dec)> {
        let (auth_buf, buf) = buf.split_at_mut(AES_CFB_HEADER_CERTIFICATION_LEN);
        auth_buf.copy_from_slice(&self.certification);
        let offset = header.encode_to(buf)?;
        let buf = &mut buf[..offset];
        self.enc.encrypt(buf);

        let res_key = {
            let mut res_key_hash = Md5::new();
            res_key_hash.update(&header.data_key);
            res_key_hash.finalize()
        };
        let res_iv = {
            let mut res_iv_hash = Md5::new();
            res_iv_hash.update(&header.data_iv);
            res_iv_hash.finalize()
        };

        use cipher::KeyIvInit;
        Some((
            offset + AES_CFB_HEADER_CERTIFICATION_LEN,
            AesCfbResponseDec {
                res_auth: header.res_auth,
                dec: BufDecryptor::new_from_slices(&res_key, &res_iv).unwrap(),
            },
        ))
    }
}

impl ResponseHeaderDec for AesCfbResponseDec {
    fn decrypt_res<'a>(&mut self, data: &'a mut [u8]) -> HeaderDecryptResult<ResponseHeader> {
        const RES_LEN: usize = 4;
        // TODO: const time?
        // TODO: cmd bytes
        let Some(chunk) = data.get_mut(..RES_LEN) else {
            return HeaderDecryptResult::Incomplete {
                total_required: RES_LEN,
            };
        };
        self.dec.decrypt(chunk);
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
        HeaderDecryptResult::Complete { res, len: RES_LEN }
    }
}

/*
impl VMessRequestHeaderDec for AesCfbRequestDec {
    fn decrypt_res<'a>(&mut self, data: &'a mut [u8]) -> VMessHeaderDecryptResult<'a> {
        // TODO: const time?
        let Some(chunk) = data.get(..42) else {
            return VMessHeaderDecryptResult::Incomplete {
                total_required: 42,
            };
        };
        let mut dec = self.dec.clone();
        let mut chunk = <[u8; 42]>::try_from(chunk).unwrap();
        dec.decrypt(&mut chunk);
        let padding_len = (chunk[35] >> 4) as usize;
        let addr_len = match chunk[40] {
            1 => 4,
            2 => 1 + chunk[41] as usize,
            3 => 16,
            _ => return VMessHeaderDecryptResult::Invalid,
        };
        let total_len = 42 + padding_len + addr_len - 1 + 4;
        let Some(ret) = data.get_mut(..total_len) else {
            return VMessHeaderDecryptResult::Incomplete {
                total_required: total_len,
            };
        };
        self.dec.decrypt(ret);
        VMessHeaderDecryptResult::Complete(ret)
    }
}
*/
