use ytflow::plugin::shadowsocks::SupportedCipher;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowsocksProxy {
    pub cipher: SupportedCipher,
    pub password: Vec<u8>,
}
