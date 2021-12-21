use std::os::raw::c_void;
use std::ptr::null_mut;

use serde::Serialize;

use super::error::FfiResult;

#[no_mangle]
pub extern "C" fn ytflow_buffer_free(ptr: *mut c_void, metadata: usize) -> FfiResult {
    FfiResult::catch_ptr_unwind(|| {
        unsafe {
            drop(Box::from_raw(std::ptr::from_raw_parts_mut::<[u8]>(
                ptr as _, metadata,
            )));
        }
        (null_mut(), 0)
    })
}

pub(super) fn serialize_buffer<T: Serialize>(data: &T) -> (*mut c_void, usize) {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(data, &mut buf).unwrap();
    let ptr = Box::into_raw(buf.into_boxed_slice());
    let (ptr, metadata) = ptr.to_raw_parts();
    (ptr as _, metadata)
}
