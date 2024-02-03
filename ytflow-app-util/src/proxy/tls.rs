#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProxyTlsLayer {
    pub alpn: Vec<String>,
    pub sni: Option<String>,
    pub skip_cert_check: Option<bool>,
}
