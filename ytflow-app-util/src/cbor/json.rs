use super::{escape_cbor_buf, unescape_cbor_buf, CborUtilError, CborUtilResult};

pub fn cbor_to_json(cbor: &[u8]) -> CborUtilResult<String> {
    let mut val = cbor4ii::serde::from_slice(cbor).map_err(|_| CborUtilError::InvalidEncoding)?;
    escape_cbor_buf(&mut val);
    serde_json::to_string_pretty(&val).map_err(|_| CborUtilError::InvalidEncoding)
}

pub fn json_to_cbor(json: &str) -> CborUtilResult<Vec<u8>> {
    let mut val = serde_json::from_str(json).map_err(|_| CborUtilError::InvalidEncoding)?;
    unescape_cbor_buf(&mut val)?;
    cbor4ii::serde::to_vec(vec![], &val).map_err(|_| CborUtilError::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor_to_json() {
        let cbor = b"\x42\x68\x68";
        let json = cbor_to_json(cbor).unwrap();
        assert_eq!(
            json,
            r#"{
  "__byte_repr": "utf8",
  "data": "hh"
}"#
        );
    }
    #[test]
    fn test_cbor_to_json_invalid_cbor() {
        let cbor = b"\x42\x68";
        let res = cbor_to_json(cbor);
        assert_eq!(res, Err(CborUtilError::InvalidEncoding));
    }

    #[test]
    fn test_json_to_cbor() {
        let json = r#"{ "__byte_repr": "utf8", "data": "hh" }"#;
        let cbor = json_to_cbor(json).unwrap();
        let expected_cbor = b"\x42\x68\x68";
        assert_eq!(cbor, expected_cbor);
    }
    #[test]
    fn test_json_to_cbor_invalid_json() {
        let json = "{ ";
        let res = json_to_cbor(json);
        assert_eq!(res, Err(CborUtilError::InvalidEncoding));
    }
}
