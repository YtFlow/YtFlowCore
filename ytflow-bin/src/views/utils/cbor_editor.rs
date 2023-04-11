use anyhow::{Context, Result};
use base64::prelude::*;
use cbor4ii::core::Value as CborValue;

/// Map CBOR bytes to string or base64 encoded string for
/// later converting back.
fn escape_cbor_buf(val: &mut CborValue) {
    match val {
        CborValue::Bytes(bytes) => {
            let bytes = std::mem::take(bytes);
            *val = match std::str::from_utf8(&bytes) {
                Ok(str) => CborValue::Map(vec![
                    (
                        CborValue::Text("__byte_repr".into()),
                        CborValue::Text("utf8".into()),
                    ),
                    (CborValue::Text("data".into()), CborValue::Text(str.into())),
                ]),
                Err(_) => CborValue::Map(vec![
                    (
                        CborValue::Text("__byte_repr".into()),
                        CborValue::Text("base64".into()),
                    ),
                    (
                        CborValue::Text("data".into()),
                        CborValue::Text(BASE64_STANDARD.encode(&bytes)),
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

fn unescape_cbor_buf(val: &mut CborValue) -> std::result::Result<(), String> {
    match val {
        CborValue::Array(v) => {
            for i in v {
                unescape_cbor_buf(i)?;
            }
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
                return Err(format!("Unexpected sibling {} of __byte_repr", sibling));
            }
            let data = match (byte_repr, data) {
                (Some(repr), Some(buf)) if repr == "utf8" => std::mem::take(buf).into_bytes(),
                (Some(repr), Some(buf)) if repr == "base64" => BASE64_STANDARD
                    .decode(std::mem::take(buf).into_bytes())
                    .map_err(|_| "Invalid base64 data")?,
                (Some(_), None) => return Err("Missing data field".into()),
                (Some(repr), _) => return Err(format!("Unknown representation {}", repr)),
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

pub fn open_editor_and_verify_for_cbor<T>(
    ctx: &mut crate::AppContext,
    mut val: CborValue,
    mut verify_fn: impl FnMut(CborValue) -> Result<T>,
) -> Result<Option<T>> {
    // Note: some editors will change line endings
    const CANCEL_SAFEWORD: &[u8] = b"//  === Remove this line to cancel editing ===\n";
    const BAD_JSON_MSG: &[u8] =
        b"//  === Remove this line and everything below after correcting the errors ===\n";

    escape_cbor_buf(&mut val);
    let json_buf = serde_json::to_vec_pretty(&val).context("Failed to convert into JSON")?;
    let mut edit_buf = CANCEL_SAFEWORD.to_vec();
    edit_buf.extend_from_slice(&json_buf);
    let ret = loop {
        let input_buf = edit::edit_bytes_with_builder(
            &edit_buf,
            edit::Builder::new()
                .prefix("ytflow-editor-param-")
                .suffix(".json"),
        )
        .context("Failed to edit")?;
        // Editor process output will mess up the terminal
        // Force a redraw
        ctx.term.clear().unwrap();

        if !input_buf.starts_with(CANCEL_SAFEWORD)
            || (input_buf.len() == edit_buf.len() && input_buf.as_slice() == edit_buf.as_slice())
        {
            return Ok(None);
        }

        // Leave a newline in the buffer for correct error messages
        match serde_json::from_slice(&input_buf[(CANCEL_SAFEWORD.len() - 1)..])
            .map_err(|e| e.to_string())
            .and_then(|mut v| unescape_cbor_buf(&mut v).map(|()| v))
            .and_then(|v| verify_fn(v).map_err(|e| format!("{:#?}", e)))
        {
            Ok(v) => break v,
            Err(err_str) => {
                edit_buf.clear();
                edit_buf.reserve(input_buf.len() + BAD_JSON_MSG.len() + err_str.len());
                edit_buf.extend_from_slice(&input_buf);
                edit_buf.extend_from_slice(BAD_JSON_MSG);
                edit_buf.extend_from_slice(err_str.as_bytes());
                continue;
            }
        };
    };
    Ok(Some(ret))
}

pub fn open_editor_for_cbor_bytes(
    ctx: &mut crate::AppContext,
    input_bytes: &[u8],
) -> Result<Option<Vec<u8>>> {
    let val: CborValue =
        cbor4ii::serde::from_slice(input_bytes).context("Failed to deserialize CBOR")?;
    open_editor_and_verify_for_cbor(ctx, val, |v| {
        cbor4ii::serde::to_vec(vec![], &v).context("Failed to serialize JSON into CBOR")
    })
}
