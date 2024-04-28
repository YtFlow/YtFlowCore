use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;

use super::interop::serialize_buffer;
use super::{error::ytflow_result, interop::serialize_string_buffer};
use crate::share_link::{decode_share_link, encode_share_link};

#[no_mangle]
pub unsafe extern "C" fn ytflow_app_share_link_decode(link: *const c_char) -> ytflow_result {
    ytflow_result::catch_result_unwind(AssertUnwindSafe(move || {
        let link = unsafe { CStr::from_ptr(link).to_string_lossy() };
        decode_share_link(&link).map(|p| serialize_buffer(&p))
    }))
}

#[no_mangle]
pub unsafe extern "C" fn ytflow_app_share_link_encode(
    proxy: *const u8,
    proxy_len: usize,
) -> ytflow_result {
    ytflow_result::catch_result_unwind(AssertUnwindSafe(move || {
        let proxy = super::proxy::deserialize_proxy_cbor(proxy, proxy_len)?;
        encode_share_link(&proxy)
            .map(|l| serialize_string_buffer(l))
            .map_err(ytflow_result::from)
    }))
}
