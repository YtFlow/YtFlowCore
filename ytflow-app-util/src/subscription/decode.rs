use thiserror::Error;

use super::b64_links::decode_b64_links;
use super::sip008::decode_sip008;
use super::surge_proxy_list::decode_surge_proxy_list;
use super::{Subscription, SubscriptionFormat};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DecodeError {
    #[error("unknown format")]
    UnknownFormat,
    #[error("invalid URL, UTF-8 or Base64 encoding")]
    InvalidEncoding,
    #[error("subscription contains no recognizable proxy")]
    NoProxy,
    #[error(r#"unknown value for field "{0}"#)]
    UnknownValue(&'static str),
}

pub type DecodeResult<T> = Result<T, DecodeError>;

impl Subscription {
    pub fn ensure_proxies(self) -> DecodeResult<Subscription> {
        if self.proxies.is_empty() {
            Err(DecodeError::NoProxy)
        } else {
            Ok(self)
        }
    }
}

pub fn decode_subscription(data: &[u8]) -> DecodeResult<(Subscription, SubscriptionFormat)> {
    decode_sip008(data)
        .and_then(Subscription::ensure_proxies)
        .map(|sub| (sub, SubscriptionFormat::SIP008))
        .or_else(|_| {
            decode_surge_proxy_list(data)
                .and_then(Subscription::ensure_proxies)
                .map(|sub| (sub, SubscriptionFormat::SURGE_PROXY_LIST))
        })
        .or_else(|_| {
            decode_b64_links(data)
                .and_then(Subscription::ensure_proxies)
                .map(|sub| (sub, SubscriptionFormat::B64_LINKS))
        })
}

pub fn decode_subscription_with_format(
    data: &[u8],
    format: SubscriptionFormat,
) -> DecodeResult<Subscription> {
    match format {
        SubscriptionFormat::SIP008 => decode_sip008(data),
        SubscriptionFormat::SURGE_PROXY_LIST => decode_surge_proxy_list(data),
        SubscriptionFormat::B64_LINKS => decode_b64_links(data),
        _ => return Err(DecodeError::UnknownFormat),
    }
    .and_then(Subscription::ensure_proxies)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBSCRIPTION_SIP008: &str = r#"{
        "version": 1,
        "servers": [
            {
                "remarks": "server 1",
                "server": "server1.example.com",
                "server_port": 12345,
                "method": "aes-256-gcm",
                "password": "password1"
            }
        ]
    }"#;
    const SUBSCRIPTION_SURGE_PROXY_LIST: &str = r#"aa = http, a.com, 114"#;
    const SUBSCRIPTION_B64_LINKS: &str = "c3M6Ly9ZV1Z6TFRFeU9DMW5ZMjA2WVdKalpBQGFhLmNvbTo4Mzg4Lz9ncm91cD1xdXEjYWEKc3M6Ly9ZV1Z6TFRFeU9DMW5ZMjA2WVdKalpBQGFiLmNvbTo4Mzg4Lz9ncm91cD1xdXEjYWI=\nc3M6Ly9ZV1Z6TFRFeU9DMW5ZMjA2WVdKalpBQGFjLmNvbTo4Mzg4Lz9ncm91cD1xdXEjYWM=";
    const SUBSCRIPTION_LIST: &[(&str, SubscriptionFormat)] = &[
        (SUBSCRIPTION_SIP008, SubscriptionFormat::SIP008),
        (
            SUBSCRIPTION_SURGE_PROXY_LIST,
            SubscriptionFormat::SURGE_PROXY_LIST,
        ),
        (SUBSCRIPTION_B64_LINKS, SubscriptionFormat::B64_LINKS),
    ];

    #[test]
    fn test_decode_subscription() {
        for (data, format) in SUBSCRIPTION_LIST {
            let (sub, fmt) = decode_subscription(data.as_bytes()).unwrap();
            assert_eq!(fmt, *format);
            assert!(sub.proxies.len() >= 1);
        }
    }

    #[test]
    fn test_decode_subscription_invalid() {
        let result = decode_subscription("invalid".as_bytes());
        assert_eq!(result.unwrap_err(), DecodeError::NoProxy);
    }

    #[test]
    fn test_decode_subscription_with_format() {
        for (data, format) in SUBSCRIPTION_LIST {
            let sub = decode_subscription_with_format(data.as_bytes(), *format).unwrap();
            assert!(sub.proxies.len() >= 1);
        }
    }

    #[test]
    fn test_decode_subscription_with_format_invalid_format() {
        let result = decode_subscription_with_format(
            SUBSCRIPTION_SURGE_PROXY_LIST.as_bytes(),
            SubscriptionFormat("??"),
        );
        assert_eq!(result.unwrap_err(), DecodeError::UnknownFormat);
    }

    #[test]
    fn test_decode_subscription_with_format_invalid() {
        let result = decode_subscription_with_format("[]".as_bytes(), SubscriptionFormat::SIP008);
        assert_eq!(result.unwrap_err(), DecodeError::NoProxy);
    }
}
