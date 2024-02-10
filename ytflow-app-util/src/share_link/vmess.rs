use url::Url;

mod v2rayn;

use super::decode::{DecodeResult, QueryMap};
use super::encode::EncodeResult;
use crate::proxy::protocol::vmess::VMessProxy;
use crate::proxy::{Proxy, ProxyLeg};

impl VMessProxy {
    pub(super) fn decode_share_link(url: &Url, queries: &mut QueryMap) -> DecodeResult<Proxy> {
        v2rayn::decode_v2rayn(url, queries)
    }
    pub(super) fn encode_share_link(&self, leg: &ProxyLeg, proxy: &Proxy) -> EncodeResult<String> {
        v2rayn::encode_v2rayn(self, leg, proxy)
    }
}
