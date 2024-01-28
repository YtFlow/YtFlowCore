#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTlsLayer {
    pub name: String,
    pub alpn: Vec<String>,
    pub sni: Option<String>,
    pub skip_cert_check: Option<bool>,
}
