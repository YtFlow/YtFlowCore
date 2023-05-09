pub(super) mod body;
pub(super) mod header;

pub(crate) const USER_ID_LEN: usize = 16;

#[derive(Debug, Clone, Copy)]
pub enum SupportedSecurity {
    None,
    Auto,
    Aes128Cfb,
    Aes128Gcm,
    Chacha20Poly1305,
}
