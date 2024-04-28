use base64::prelude::*;
use cbor4ii::core::Value as CborValue;

use super::{CborUtilError, CborUtilResult};

/// Map CBOR bytes to string or base64 encoded string for
/// later converting back.
pub fn escape_cbor_buf(val: &mut CborValue) {
    match val {
        CborValue::Bytes(bytes) => {
            let bytes = std::mem::take(bytes);
            *val = match String::from_utf8(bytes) {
                Ok(str) => CborValue::Map(vec![
                    (
                        CborValue::Text("__byte_repr".into()),
                        CborValue::Text("utf8".into()),
                    ),
                    (CborValue::Text("data".into()), CborValue::Text(str)),
                ]),
                Err(e) => CborValue::Map(vec![
                    (
                        CborValue::Text("__byte_repr".into()),
                        CborValue::Text("base64".into()),
                    ),
                    (
                        CborValue::Text("data".into()),
                        CborValue::Text(BASE64_STANDARD.encode(e.into_bytes())),
                    ),
                ]),
            };
        }
        CborValue::Array(v) => v.iter_mut().for_each(escape_cbor_buf),
        CborValue::Map(kvs) => kvs
            .iter_mut()
            .for_each(|(k, v)| (escape_cbor_buf(k), escape_cbor_buf(v), ()).2),
        _ => {}
    }
}

pub fn unescape_cbor_buf(val: &mut CborValue) -> CborUtilResult<()> {
    match val {
        CborValue::Array(v) => {
            v.iter_mut()
                .map(unescape_cbor_buf)
                .collect::<CborUtilResult<Vec<_>>>()?;
        }
        CborValue::Map(kvs) => {
            let mut byte_repr = None;
            let mut data = None;
            let mut unexpected_sibling = None;
            for kv in &mut *kvs {
                match kv {
                    (CborValue::Text(k), CborValue::Text(v)) => {
                        if k == "__byte_repr" {
                            byte_repr = Some(v);
                            continue;
                        }
                        if k == "data" {
                            data = Some(v);
                            continue;
                        }
                        unexpected_sibling = Some(&**k)
                    }
                    (CborValue::Text(k), _) => unexpected_sibling = Some(&**k),
                    _ => unexpected_sibling = Some(""),
                }
            }
            if let (Some(_), Some(sibling)) = (&byte_repr, unexpected_sibling) {
                return Err(CborUtilError::UnexpectedByteReprKey(sibling.into()));
            }
            let data = match (byte_repr, data) {
                (Some(repr), Some(buf)) if repr == "utf8" => std::mem::take(buf).into_bytes(),
                (Some(repr), Some(buf)) if repr == "base64" => BASE64_STANDARD
                    .decode(std::mem::take(buf).into_bytes())
                    .map_err(|_| CborUtilError::InvalidByteRepr("base64"))?,
                (Some(_), None) => return Err(CborUtilError::MissingData),
                (Some(repr), _) => return Err(CborUtilError::UnknownByteRepr(repr.clone())),
                (None, _) => {
                    for (k, v) in kvs {
                        unescape_cbor_buf(k)?;
                        unescape_cbor_buf(v)?;
                    }
                    return Ok(());
                }
            };

            *val = CborValue::Bytes(data);
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_cbor_buf_utf8() {
        use CborValue::*;
        let mut val = Map(vec![(
            Text("a".into()),
            Array(vec![Integer(114514), Bytes(b"bb".to_vec())]),
        )]);
        escape_cbor_buf(&mut val);
        assert_eq!(
            val,
            Map(vec![(
                Text("a".into()),
                Array(vec![
                    Integer(114514),
                    Map(vec![
                        (Text("__byte_repr".into()), Text("utf8".into())),
                        (Text("data".into()), Text("bb".into())),
                    ])
                ]),
            )])
        );
    }

    #[test]
    fn test_escape_cbor_buf_non_utf8() {
        use CborValue::*;
        let mut val = Map(vec![(
            Text("a".into()),
            Array(vec![Integer(114514), Bytes(b"\x80".to_vec())]),
        )]);
        escape_cbor_buf(&mut val);
        assert_eq!(
            val,
            Map(vec![(
                Text("a".into()),
                Array(vec![
                    Integer(114514),
                    Map(vec![
                        (Text("__byte_repr".into()), Text("base64".into())),
                        (Text("data".into()), Text("gA==".into())),
                    ])
                ]),
            )])
        );
    }

    #[test]
    fn test_unescape_cbor_buf_utf8() {
        use CborValue::*;
        let mut val = {
            Map(vec![(
                Text("a".into()),
                Map(vec![
                    (Text("__byte_repr".into()), Text("utf8".into())),
                    (Text("data".into()), Text("bb".into())),
                ]),
            )])
        };
        unescape_cbor_buf(&mut val).unwrap();
        assert_eq!(val, Map(vec![(Text("a".into()), Bytes(b"bb".to_vec()))]));
    }

    #[test]
    fn test_unescape_cbor_buf_non_utf8() {
        use CborValue::*;
        let mut val = {
            Map(vec![(
                Text("a".into()),
                Map(vec![
                    (Text("__byte_repr".into()), Text("base64".into())),
                    (Text("data".into()), Text("gA==".into())),
                ]),
            )])
        };
        unescape_cbor_buf(&mut val).unwrap();
        assert_eq!(val, Map(vec![(Text("a".into()), Bytes(b"\x80".to_vec()),)]));
    }

    #[test]
    fn test_unescape_cbor_buf_invalid_base64() {
        use CborValue::*;
        let mut val = {
            Map(vec![(
                Text("a".into()),
                Map(vec![
                    (Text("__byte_repr".into()), Text("base64".into())),
                    (Text("data".into()), Text("g?".into())),
                ]),
            )])
        };
        assert_eq!(
            unescape_cbor_buf(&mut val),
            Err(CborUtilError::InvalidByteRepr("base64"))
        );
    }

    #[test]
    fn test_unescape_cbor_buf_missing_data() {
        use CborValue::*;
        let mut val = {
            Map(vec![(
                Text("a".into()),
                Map(vec![(Text("__byte_repr".into()), Text("utf8".into()))]),
            )])
        };
        assert_eq!(unescape_cbor_buf(&mut val), Err(CborUtilError::MissingData));
    }

    #[test]
    fn test_unescape_cbor_buf_unknown_repr() {
        use CborValue::*;
        let mut val = {
            Map(vec![(
                Text("a".into()),
                Map(vec![
                    (Text("__byte_repr".into()), Text("unknown".into())),
                    (Text("data".into()), Text("bb".into())),
                ]),
            )])
        };
        assert_eq!(
            unescape_cbor_buf(&mut val),
            Err(CborUtilError::UnknownByteRepr("unknown".into()))
        );
    }

    #[test]
    fn test_unescape_cbor_buf_unexpected_sibling() {
        use CborValue::*;
        let mut val = {
            Map(vec![(
                Text("a".into()),
                Map(vec![
                    (Text("__byte_repr".into()), Text("utf8".into())),
                    (Text("data".into()), Text("bb".into())),
                    (Text("unexpected".into()), Text("sibling".into())),
                ]),
            )])
        };
        assert_eq!(
            unescape_cbor_buf(&mut val),
            Err(CborUtilError::UnexpectedByteReprKey("unexpected".into()))
        );
    }
}
