use std::borrow::Cow;
use std::collections::BTreeMap;

use percent_encoding::percent_decode_str;
use thiserror::Error;
use url::Url;
use ytflow::flow::DestinationAddr;

use crate::proxy::protocol::{shadowsocks::ShadowsocksProxy, trojan::TrojanProxy};
use crate::proxy::Proxy;

pub static BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::general_purpose::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DecodeError {
    #[error("invalid URL")]
    InvalidUrl,
    #[error("invalid URL, UTF-8 or Base64 encoding")]
    InvalidEncoding,
    #[error(r#""{0}" is required, but is missing"#)]
    MissingInfo(&'static str),
    #[error(r#"unknown value for field "{0}"#)]
    UnknownValue(&'static str),
    #[error("unknown URL scheme")]
    UnknownScheme,
    #[error(r#"extra parameter "{0}""#)]
    ExtraParameters(String),
}

pub type DecodeResult<T> = Result<T, DecodeError>;

pub(super) type QueryMap<'a> = BTreeMap<Cow<'a, str>, Cow<'a, str>>;

pub fn decode_share_link(link: &str) -> Result<Proxy, DecodeError> {
    let url = url::Url::parse(link.trim()).map_err(|_| DecodeError::InvalidUrl)?;
    let mut queries = url.query_pairs().collect::<QueryMap>();

    let proxy = match url.scheme() {
        "ss" => ShadowsocksProxy::decode_share_link(&url, &mut queries)?,
        "trojan" => TrojanProxy::decode_share_link(&url, &mut queries)?,
        _ => return Err(DecodeError::UnknownScheme),
    };

    if let Some((first_extra_key, _)) = queries.pop_first() {
        return Err(DecodeError::ExtraParameters(first_extra_key.into()));
    }

    Ok(proxy)
}

pub(super) fn extract_name_from_frag(url: &Url, dest: &DestinationAddr) -> DecodeResult<String> {
    Ok(url
        .fragment()
        .map(|s| percent_decode_str(s).decode_utf8())
        .transpose()
        .map_err(|_| DecodeError::InvalidEncoding)?
        .map(|s| s.into_owned())
        .unwrap_or_else(|| dest.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_name_from_frag() {
        let url = Url::parse("ss://test#cabc%2fabca").unwrap();
        let dest = DestinationAddr {
            host: ytflow::flow::HostName::from_domain_name("example.com".into()).unwrap(),
            port: 1234,
        };
        assert_eq!(
            extract_name_from_frag(&url, &dest).unwrap(),
            "cabc/abca".to_string()
        );
    }

    #[test]
    fn test_extract_name_from_frag_invalid() {
        let url = Url::parse("ss://test#cabc%ff%ffabca").unwrap();
        let dest = DestinationAddr {
            host: ytflow::flow::HostName::from_domain_name("example.com".into()).unwrap(),
            port: 1234,
        };
        assert_eq!(
            extract_name_from_frag(&url, &dest),
            Err(DecodeError::InvalidEncoding)
        );
    }
}
