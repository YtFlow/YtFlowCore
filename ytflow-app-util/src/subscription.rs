mod b64_links;
mod decode;
mod sip008;
mod surge_proxy_list;
mod userinfo;

use std::ffi::CStr;

pub use decode::{decode_subscription, decode_subscription_with_format, DecodeError, DecodeResult};
use serde::Serialize;
pub use userinfo::SubscriptionUserInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionFormat<'a>(pub(crate) &'a [u8]);

impl From<SubscriptionFormat<'static>> for &'static CStr {
    fn from(s: SubscriptionFormat<'static>) -> &'static CStr {
        CStr::from_bytes_with_nul(s.0).expect("format is not null-terminated")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Subscription {
    pub proxies: Vec<crate::proxy::Proxy>,
}
