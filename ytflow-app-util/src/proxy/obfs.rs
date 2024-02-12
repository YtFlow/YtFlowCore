use serde::{Deserialize, Serialize};

mod http_obfs;
mod tls_obfs;
mod ws;

pub use http_obfs::HttpObfsObfs;
pub use tls_obfs::TlsObfsObfs;
pub use ws::WebSocketObfs;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyObfsType {
    HttpObfs(http_obfs::HttpObfsObfs),
    TlsObfs(tls_obfs::TlsObfsObfs),
    WebSocket(ws::WebSocketObfs),
}
