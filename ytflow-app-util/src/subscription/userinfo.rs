use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionUserInfo {
    pub upload_bytes_used: Option<u64>,
    pub download_bytes_used: Option<u64>,
    pub bytes_total: Option<u64>,
    pub expires_at: Option<NaiveDateTime>,
}

impl SubscriptionUserInfo {
    pub fn decode_header(header: &str) -> SubscriptionUserInfo {
        let mut ret = Self::default();
        for kv in header.split(';') {
            let mut kv = kv.split('=');
            let key = kv.next().expect("first split must exist").trim();
            let Some(mut value) = kv.next() else {
                continue;
            };
            value = value.trim();

            match key {
                "upload" => {
                    ret.upload_bytes_used = value.parse().ok();
                }
                "download" => {
                    ret.download_bytes_used = value.parse().ok();
                }
                "total" => {
                    ret.bytes_total = value.parse().ok();
                }
                "expire" => {
                    ret.expires_at = value
                        .parse()
                        .ok()
                        .and_then(|s| NaiveDateTime::from_timestamp_opt(s, 0));
                }
                _ => {
                    continue;
                }
            }
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_header() {
        let header =
            "upload=455727941; download=6174315083; total=1073741824000; expire=1671815872;";
        let info = SubscriptionUserInfo::decode_header(header);
        assert_eq!(
            info,
            SubscriptionUserInfo {
                upload_bytes_used: Some(455727941),
                download_bytes_used: Some(6174315083),
                bytes_total: Some(1073741824000),
                expires_at: NaiveDateTime::from_timestamp_opt(1671815872, 0),
            }
        );
    }
    #[test]
    fn test_decode_header_empty() {
        let info = SubscriptionUserInfo::decode_header("");
        assert_eq!(info, SubscriptionUserInfo::default());
    }
    #[test]
    fn test_decode_header_no_expire() {
        let header = "upload=455727941; download=6174315083; total=1073741824000;";
        let info = SubscriptionUserInfo::decode_header(header);
        assert_eq!(
            info,
            SubscriptionUserInfo {
                upload_bytes_used: Some(455727941),
                download_bytes_used: Some(6174315083),
                bytes_total: Some(1073741824000),
                expires_at: None,
            }
        );
    }
}
