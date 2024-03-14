use ::edit::{edit_bytes_with_builder, Builder as EditorBuilder};
use anyhow::{Context, Result};
use cbor4ii::core::Value as CborValue;

use ytflow_app_util::cbor::{cbor_to_json, unescape_cbor_buf};

use crate::edit;

pub fn open_editor_for_cbor<T>(
    ctx: &mut edit::AppContext,
    val: &[u8],
    mut verify_fn: impl FnMut(CborValue) -> Result<T>,
) -> Result<Option<T>> {
    // Note: some editors will change line endings
    const CANCEL_SAFEWORD: &[u8] = b"//  === Remove this line to cancel editing ===\n";
    const BAD_JSON_MSG: &[u8] =
        b"//  === Remove this line and everything below after correcting the errors ===\n";

    let json_buf = cbor_to_json(val).context("Failed to convert into JSON")?;
    let mut edit_buf = CANCEL_SAFEWORD.to_vec();
    edit_buf.extend_from_slice(json_buf.as_bytes());
    let ret = loop {
        let input_buf = edit_bytes_with_builder(
            &edit_buf,
            EditorBuilder::new()
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
            .and_then(|mut v| {
                unescape_cbor_buf(&mut v)
                    .map(|()| v)
                    .map_err(|e| e.to_string())
            })
            .and_then(|v| verify_fn(v).map_err(|e| e.to_string()))
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
