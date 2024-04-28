use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;

use crate::subscription::{
    decode_subscription, decode_subscription_with_format, DecodeError, SubscriptionFormat,
    SubscriptionUserInfo,
};

use super::error::{ytflow_result, InvalidCborError};
use super::interop::serialize_buffer;

#[no_mangle]
pub unsafe extern "C" fn ytflow_app_subscription_userinfo_header_decode(
    header: *const c_char,
) -> ytflow_result {
    ytflow_result::catch_result_unwind(AssertUnwindSafe(move || {
        let header = unsafe { CStr::from_ptr(header).to_string_lossy() };
        let info = SubscriptionUserInfo::decode_header(&header);
        Ok::<_, InvalidCborError>(serialize_buffer(&info))
    }))
}

#[no_mangle]
pub unsafe extern "C" fn ytflow_app_subscription_decode(
    subscription: *const u8,
    subscription_len: usize,
    format: *mut *const c_char,
) -> ytflow_result {
    ytflow_result::catch_result_unwind(AssertUnwindSafe(move || {
        let subscription = std::slice::from_raw_parts(subscription, subscription_len);
        *format = std::ptr::null_mut();
        let (subscription, decoded_format) = decode_subscription(subscription)?;
        *format = <&'static CStr>::from(decoded_format).as_ptr();
        Ok::<_, DecodeError>(serialize_buffer(&subscription))
    }))
}

#[no_mangle]
pub unsafe extern "C" fn ytflow_app_subscription_decode_with_format(
    subscription: *const u8,
    subscription_len: usize,
    format: *const c_char,
) -> ytflow_result {
    ytflow_result::catch_result_unwind(AssertUnwindSafe(move || {
        let subscription = std::slice::from_raw_parts(subscription, subscription_len);
        let format = SubscriptionFormat(CStr::from_ptr(format).to_bytes_with_nul());
        decode_subscription_with_format(subscription, format).map(|s| serialize_buffer(&s))
    }))
}
