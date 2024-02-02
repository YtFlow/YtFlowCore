use serde_bytes::ByteBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanProxy {
    pub password: ByteBuf,
}
