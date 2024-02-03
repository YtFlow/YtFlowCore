use serde_bytes::ByteBuf;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Socks5Proxy {
    pub username: ByteBuf,
    pub password: ByteBuf,
}
