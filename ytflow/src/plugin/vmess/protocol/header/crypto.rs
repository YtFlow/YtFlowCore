use md5::{Digest, Md5};

use super::super::USER_ID_LEN;
use super::{RequestHeader, ResponseHeader};

pub(crate) const HEADER_KEY_LEN: usize = 16;
pub(crate) const HEADER_IV_LEN: usize = 16;
pub(crate) const CMD_KEY_LEN: usize = 16;

pub enum HeaderDecryptResult<T> {
    Invalid,
    Incomplete { total_required: usize },
    Complete { res: T, len: usize },
}

pub trait RequestHeaderEnc {
    type Dec: ResponseHeaderDec;

    const REQUIRED_SIZE: usize;

    fn derive_res_iv(&self, header: &RequestHeader) -> [u8; HEADER_IV_LEN];
    fn derive_res_key(&self, header: &RequestHeader) -> [u8; HEADER_KEY_LEN];
    fn encrypt_req(self, header: &mut RequestHeader, buf: &mut [u8]) -> Option<(usize, Self::Dec)>;
}

pub trait ResponseHeaderDec {
    #[must_use]
    fn decrypt_res<'a>(&mut self, data: &'a mut [u8]) -> HeaderDecryptResult<ResponseHeader>;
}

pub fn derive_cmd_key(user_id: &[u8; USER_ID_LEN]) -> [u8; CMD_KEY_LEN] {
    let mut cmd_key = *b"????????????????c48619fe-8f02-49e0-b9e9-edf763e17e21";
    cmd_key[..USER_ID_LEN].copy_from_slice(user_id);
    let mut cmd_key_hash = Md5::new();
    cmd_key_hash.update(cmd_key);
    let mut cmd_key = [0; CMD_KEY_LEN];
    cmd_key[..].copy_from_slice(&cmd_key_hash.finalize()[..]);
    cmd_key
}
