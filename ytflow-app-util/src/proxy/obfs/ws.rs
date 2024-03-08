use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocketObfs {
    pub host: Option<String>,
    pub path: String,
    pub headers: HashMap<String, String>,
}

impl Default for WebSocketObfs {
    fn default() -> Self {
        Self {
            host: None,
            path: "/".into(),
            headers: HashMap::new(),
        }
    }
}
