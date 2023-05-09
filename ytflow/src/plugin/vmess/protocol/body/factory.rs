use super::{RxCrypto, SizeCrypto, TxCrypto};
use crate::plugin::vmess::protocol::header::{DATA_IV_LEN, DATA_KEY_LEN};

pub trait BodyCryptoFactory {
    type Rx<S: SizeCrypto>: RxCrypto
    where
        [(); S::LEN]:;
    type Tx<S: SizeCrypto>: TxCrypto
    where
        [(); S::LEN]:;
    const HEADER_SEC_TYPE: u8;

    fn new_tx<S: SizeCrypto>(
        &self,
        data_key: &[u8; DATA_KEY_LEN],
        data_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
    ) -> Self::Tx<S>
    where
        [(); S::LEN]:;
    fn new_rx<S: SizeCrypto>(
        &self,
        res_key: &[u8; DATA_KEY_LEN],
        res_iv: &[u8; DATA_IV_LEN],
        size_crypto: S,
    ) -> Self::Rx<S>
    where
        [(); S::LEN]:;
}
