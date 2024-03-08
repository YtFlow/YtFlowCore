mod decode;
mod sip008;
mod surge_proxy_list;
mod userinfo;

pub use decode::{decode_subscription, decode_subscription_with_format};
pub use userinfo::SubscriptionUserInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionFormat(pub(crate) &'static str);

impl AsRef<str> for SubscriptionFormat {
    fn as_ref(&self) -> &str {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub proxies: Vec<crate::proxy::Proxy>,
}
