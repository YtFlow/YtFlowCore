use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProxy {
    pub username: ByteBuf,
    pub password: ByteBuf,
}
