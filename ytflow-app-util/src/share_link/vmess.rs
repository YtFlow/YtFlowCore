use url::Url;

mod v2rayn;

use super::decode::{DecodeResult, QueryMap};
use crate::proxy::protocol::vmess::VMessProxy;
use crate::proxy::Proxy;

impl VMessProxy {
    pub(super) fn decode_share_link(url: &Url, queries: &mut QueryMap) -> DecodeResult<Proxy> {
        v2rayn::decode_v2rayn(url, queries)
    }
}
