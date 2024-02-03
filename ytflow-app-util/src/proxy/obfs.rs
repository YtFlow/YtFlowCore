pub mod http_obfs;
pub mod tls_obfs;
pub mod ws;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyObfsType {
    HttpObfs(http_obfs::HttpObfsObfs),
    TlsObfs(tls_obfs::TlsObfsObfs),
    WebSocket(ws::WebSocketObfs),
}
