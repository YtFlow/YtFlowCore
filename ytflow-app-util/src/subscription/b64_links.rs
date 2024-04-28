use std::str;

use base64::engine::general_purpose::STANDARD as base64;
use base64::prelude::*;

use super::decode::{DecodeError, DecodeResult};
use crate::share_link::decode_share_link;
use crate::subscription::{Subscription, SubscriptionFormat};

impl SubscriptionFormat<'static> {
    pub const B64_LINKS: Self = SubscriptionFormat(b"b64_links\0");
}

pub fn decode_b64_links(data: &[u8]) -> DecodeResult<Subscription> {
    let data = str::from_utf8(data).map_err(|_| DecodeError::InvalidEncoding)?;
    let proxies = data
        .lines()
        .filter_map(|l| base64.decode(l).ok())
        .map(|l| String::from_utf8(l).unwrap_or_default())
        .flat_map(|l| {
            l.lines()
                .filter_map(|l| decode_share_link(l).ok())
                .collect::<Vec<_>>()
        })
        .collect();
    Ok(Subscription { proxies })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_b64_links_invalid_utf8() {
        let res = decode_b64_links(b"\xff");
        assert_eq!(res, Err(DecodeError::InvalidEncoding));
    }
    #[test]
    fn test_decode_b64_links_invalid_utf8_b64() {
        let res = decode_b64_links(b"/w==");
        assert_eq!(res, Ok(Subscription { proxies: vec![] }));
    }
}
