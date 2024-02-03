use serde_bytes::ByteBuf;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HttpProxy {
    pub username: ByteBuf,
    pub password: ByteBuf,
}
