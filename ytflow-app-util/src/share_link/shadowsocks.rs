use url::Url;

mod decode_legacy;
mod decode_sip002;
mod encode;

use super::decode::{extract_name_from_frag, DecodeResult, QueryMap};
use crate::proxy::protocol::ShadowsocksProxy;
use crate::proxy::Proxy;

impl ShadowsocksProxy {
    pub(super) fn decode_share_link(url: &Url, queries: &mut QueryMap) -> DecodeResult<Proxy> {
        let leg = if url.username().is_empty() {
            decode_legacy::decode_legacy(url, queries)
        } else {
            decode_sip002::decode_sip002(url, queries)
        }?;

        Ok(Proxy {
            name: extract_name_from_frag(url, &leg.dest)?,
            legs: vec![leg],
            udp_supported: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use crate::proxy::protocol::ProxyProtocolType;

    use super::*;

    #[test]
    fn test_decode_legacy() {
        let url = Url::parse("ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWUAzLjE4Ny4yMjUuNzozNDE4Nw")
            .unwrap();
        let mut queries = QueryMap::new();
        let proxy = ShadowsocksProxy::decode_share_link(&url, &mut queries).unwrap();
        assert_eq!(proxy.legs[0].dest.port, 34187);
        assert!(queries.is_empty());
    }

    #[test]
    fn test_decode_sip002() {
        let url =
            Url::parse("ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWQ@3.187.225.7:34187").unwrap();
        let mut queries = QueryMap::new();
        let mut proxy = ShadowsocksProxy::decode_share_link(&url, &mut queries).unwrap();
        let ss = match proxy.legs.pop().unwrap().protocol {
            ProxyProtocolType::Shadowsocks(ss) => ss,
            p => panic!("unexpected protocol type {:?}", p),
        };
        assert_eq!(&ss.password, b"UYL1EvkfI0cT6NOY");
        assert!(queries.is_empty());
    }
}
