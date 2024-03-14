use std::os::raw::c_void;
use std::ptr::null_mut;

use serde::Serialize;

use super::error::ytflow_result;

#[no_mangle]
pub unsafe extern "C" fn ytflow_buffer_free(ptr: *mut c_void, metadata: usize) -> ytflow_result {
    ytflow_result::catch_ptr_unwind(|| {
        unsafe {
            drop(Box::from_raw(std::ptr::from_raw_parts_mut::<[u8]>(
                ptr as _, metadata,
            )));
        }
        (null_mut(), 0)
    })
}

pub(super) fn serialize_buffer<T: Serialize>(data: &T) -> (*mut c_void, usize) {
    let buf = cbor4ii::serde::to_vec(vec![], data).expect("Could not serialize buffer into CBOR");
    serialize_byte_buffer(buf.into_boxed_slice())
}

pub(super) fn serialize_byte_buffer(data: impl Into<Box<[u8]>>) -> (*mut c_void, usize) {
    let ptr = Box::into_raw(data.into());
    let (ptr, metadata) = ptr.to_raw_parts();
    (ptr as _, metadata)
}

pub(super) fn serialize_string_buffer(data: impl Into<String>) -> (*mut c_void, usize) {
    serialize_byte_buffer(data.into().into_bytes())
}
