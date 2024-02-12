use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5Proxy {
    pub username: ByteBuf,
    pub password: ByteBuf,
}
