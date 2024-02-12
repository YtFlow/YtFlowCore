use serde::{Deserialize, Serialize};
use ytflow::plugin::vmess::SupportedSecurity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VMessProxy {
    pub user_id: uuid::Uuid,
    pub alter_id: u16,
    pub security: SupportedSecurity,
}
