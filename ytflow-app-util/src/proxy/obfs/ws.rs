#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketObfs {
    pub host: Option<String>,
    pub path: String,
}
