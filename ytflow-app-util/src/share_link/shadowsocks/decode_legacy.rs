use base64::Engine;
use percent_encoding::percent_decode_str;
use serde_bytes::ByteBuf;
use url::{Host, Url};

use ytflow::{config::plugin::parse_supported_cipher, flow::DestinationAddr};

use crate::proxy::protocol::{shadowsocks::ShadowsocksProxy, ProxyProtocolType};
use crate::proxy::ProxyLeg;
use crate::share_link::decode::{
    map_host_name, DecodeError, DecodeResult, QueryMap, BASE64_ENGINE,
};

pub fn decode_legacy(url: &Url, _queries: &mut QueryMap) -> DecodeResult<ProxyLeg> {
    let b64 = {
        let b64str = percent_decode_str(url.host_str().ok_or(DecodeError::InvalidUrl)?)
            .decode_utf8()
            .map_err(|_| DecodeError::InvalidEncoding)?;
        BASE64_ENGINE
            .decode(&*b64str)
            .map_err(|_| DecodeError::InvalidEncoding)?
    };
    let mut split = b64.rsplitn(2, |&b| b == b'@');
    let dest = {
        let host_port = split.next().expect("first split must exist");
        let host_port = std::str::from_utf8(host_port).map_err(|_| DecodeError::InvalidEncoding)?;
        let mut split = host_port.rsplitn(2, ':');
        let port = split.next().expect("first split must exist");
        let host = Host::parse(split.next().ok_or(DecodeError::MissingInfo("port"))?)
            .map_err(|_| DecodeError::InvalidEncoding)?;
        DestinationAddr {
            host: map_host_name(host),
            port: port.parse().map_err(|_| DecodeError::InvalidEncoding)?,
        }
    };
    let (cipher, password) = {
        let method_pass = split.next().ok_or(DecodeError::MissingInfo("method"))?;
        let mut split = method_pass.splitn(2, |&b| b == b':');
        let method = split.next().expect("first split must exist");
        let cipher = parse_supported_cipher(method).ok_or(DecodeError::UnknownValue("method"))?;
        let pass = split.next().ok_or(DecodeError::MissingInfo("password"))?;
        (cipher, ByteBuf::from(pass))
    };

    Ok(ProxyLeg {
        protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy { cipher, password }),
        dest,
        obfs: None,
        tls: None,
    })
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use percent_encoding::{percent_encode, NON_ALPHANUMERIC};

    use ytflow::{flow::HostName, plugin::shadowsocks::SupportedCipher};

    use super::*;

    #[test]
    fn test_decode_legacy() {
        let url = Url::parse(&format!(
            "ss://{}",
            percent_encode(
                STANDARD
                    .encode(format!("aes-256-cfb:UYL1EvkfI0cT6NOY@a.co:34187"))
                    .as_bytes(),
                NON_ALPHANUMERIC
            )
        ))
        .unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_legacy(&url, &mut queries).unwrap();
        assert_eq!(
            leg,
            ProxyLeg {
                protocol: ProxyProtocolType::Shadowsocks(ShadowsocksProxy {
                    cipher: SupportedCipher::Aes256Cfb,
                    password: ByteBuf::from("UYL1EvkfI0cT6NOY"),
                }),
                dest: DestinationAddr {
                    host: HostName::DomainName("a.co".into()),
                    port: 34187,
                },
                obfs: None,
                tls: None,
            },
        );
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_legacy_no_padding() {
        let url = Url::parse("ss://YWVzLTI1Ni1jZmI6VVlMMUV2a2ZJMGNUNk5PWUAzLjE4Ny4yMjUuNzozNDE4Nw")
            .unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_legacy(&url, &mut queries).unwrap();
        assert_eq!(leg.dest.port, 34187);
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_legacy_unknown_cipher() {
        let url = Url::parse(&format!(
            "ss://{}",
            STANDARD.encode("114514:UYL1EvkfI0cT6NOY@3.187.225.7:34187")
        ))
        .unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_legacy(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::UnknownValue("method"));
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_legacy_invalid_url() {
        let url = Url::parse("ss://").unwrap();
        let mut queries = QueryMap::new();
        let leg = decode_legacy(&url, &mut queries);
        assert_eq!(leg.unwrap_err(), DecodeError::InvalidUrl);
        assert!(queries.is_empty());
    }
    #[test]
    fn test_decode_legacy_invalid_base64() {
        let raw_urls = ["ss://%ff%ff", "ss://あ"];
        for raw_url in raw_urls {
            let url = Url::parse(raw_url).unwrap();
            let mut queries = QueryMap::new();
            let leg = decode_legacy(&url, &mut queries);
            assert_eq!(leg.unwrap_err(), DecodeError::InvalidEncoding, "{raw_url}");
            assert!(queries.is_empty());
        }
    }
    #[test]
    fn test_decode_legacy_invalid_encoding() {
        let cases: [&[u8]; 4] = [
            b"rc4:a@:114",
            b"rc4:a@\xff\xff:114",
            b"rc4:a@ :114",
            b"rc4:a@a.co:cc",
        ];
        for raw_value in cases {
            let url = Url::parse(&format!(
                "ss://{}",
                percent_encode(STANDARD.encode(raw_value).as_bytes(), NON_ALPHANUMERIC).to_string()
            ))
            .unwrap();
            let mut queries = QueryMap::new();
            let leg = decode_legacy(&url, &mut queries);
            assert_eq!(
                leg.unwrap_err(),
                DecodeError::InvalidEncoding,
                "{}",
                String::from_utf8_lossy(raw_value)
            );
            assert!(queries.is_empty());
        }
    }
    #[test]
    fn test_decode_legacy_missing_info() {
        let cases: [(&str, &str); 4] = [
            ("rc4:a@", "port"),
            ("rc4:a@a", "port"),
            ("a.co:114", "method"),
            ("rc4@a.co:114", "password"),
        ];
        for (raw_value, expected_field) in cases {
            let url = Url::parse(&format!("ss://{}", STANDARD.encode(raw_value))).unwrap();
            let mut queries = QueryMap::new();
            let leg = decode_legacy(&url, &mut queries);
            assert_eq!(
                leg.unwrap_err(),
                DecodeError::MissingInfo(expected_field),
                "{raw_value}"
            );
            assert!(queries.is_empty());
        }
    }
}
