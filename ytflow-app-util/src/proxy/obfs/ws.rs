use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocketObfs {
    pub host: Option<String>,
    pub path: String,
}

impl Default for WebSocketObfs {
    fn default() -> Self {
        Self {
            host: None,
            path: "/".into(),
        }
    }
}
