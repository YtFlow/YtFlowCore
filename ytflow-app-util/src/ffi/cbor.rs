use std::ffi::CStr;
use std::os::raw::c_char;

use super::error::ytflow_result;
use super::interop::{serialize_byte_buffer, serialize_string_buffer};

#[no_mangle]
pub unsafe extern "C" fn ytflow_app_cbor_to_json(
    cbor: *const u8,
    cbor_len: usize,
) -> ytflow_result {
    ytflow_result::catch_result_unwind(move || {
        let cbor = std::slice::from_raw_parts(cbor, cbor_len);
        crate::cbor::cbor_to_json(cbor).map(|j| serialize_string_buffer(j))
    })
}

#[no_mangle]
pub unsafe extern "C" fn ytflow_app_cbor_from_json(json: *const c_char) -> ytflow_result {
    ytflow_result::catch_result_unwind(move || {
        let json = unsafe { CStr::from_ptr(json).to_string_lossy() };
        crate::cbor::json_to_cbor(&json).map(|c| serialize_byte_buffer(c))
    })
}
