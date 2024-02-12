use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use ytflow::plugin::shadowsocks::SupportedCipher;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksProxy {
    pub cipher: SupportedCipher,
    pub password: ByteBuf,
}
