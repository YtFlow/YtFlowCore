use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;

use super::error::{ytflow_result, InvalidCborError};
use super::interop::{serialize_buffer, serialize_byte_buffer};
use crate::proxy;

#[no_mangle]
pub unsafe extern "C" fn ytflow_app_proxy_data_proxy_analyze(
    name: *const c_char,
    data_proxy: *const u8,
    data_proxy_len: usize,
    version: u16,
) -> ytflow_result {
    ytflow_result::catch_result_unwind(AssertUnwindSafe(move || {
        let name = unsafe { CStr::from_ptr(name).to_string_lossy().into_owned() };
        proxy::data::analyze_data_proxy(
            name,
            std::slice::from_raw_parts(data_proxy, data_proxy_len),
            version,
        )
        .map(|p| serialize_buffer(&p))
    }))
}

pub(super) unsafe fn deserialize_proxy_cbor(
    data: *const u8,
    data_len: usize,
) -> Result<proxy::Proxy, InvalidCborError> {
    let data = std::slice::from_raw_parts(data, data_len);
    cbor4ii::serde::from_slice(data).map_err(|_| super::error::InvalidCborError)
}

#[no_mangle]
pub unsafe extern "C" fn ytflow_app_proxy_data_proxy_compose_v1(
    proxy: *const u8,
    proxy_len: usize,
) -> ytflow_result {
    ytflow_result::catch_result_unwind(AssertUnwindSafe(move || {
        let proxy = deserialize_proxy_cbor(proxy, proxy_len)?;
        proxy::data::compose_data_proxy_v1(&proxy)
            .map(|p| serialize_byte_buffer(p))
            .map_err(ytflow_result::from)
    }))
}
