use sha3::digest::{core_api::XofReaderCoreWrapper, ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128ReaderCore};

use super::SizeCrypto;
use crate::flow::FlowResult;

type Shake128Reader = XofReaderCoreWrapper<Shake128ReaderCore>;

pub struct ShakeSizeCrypto {
    reader: Shake128Reader,
}

impl ShakeSizeCrypto {
    pub fn new(iv: &[u8]) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(iv);
        let reader = hasher.finalize_xof();
        Self { reader }
    }
}

impl SizeCrypto for ShakeSizeCrypto {
    const LEN: usize = 2;

    fn encode_size(&mut self, size: usize) -> [u8; Self::LEN] {
        // TODO: exceed u16?
        let mut buf = [0, 0];
        self.reader.read(&mut buf);
        (u16::from_be_bytes(buf) ^ (size as u16)).to_be_bytes()
    }

    fn decode_size(&mut self, size_bytes: &mut [u8; Self::LEN]) -> FlowResult<usize> {
        let mut buf = [0, 0];
        self.reader.read(&mut buf);
        Ok((u16::from_be_bytes(buf) ^ u16::from_be_bytes(*size_bytes)) as usize)
    }
}
