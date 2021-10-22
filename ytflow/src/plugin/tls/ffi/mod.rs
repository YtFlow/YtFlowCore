// Credits to: https://github.com/sfackler/rust-openssl

pub(super) mod bio;
pub(super) mod ctx;
pub(super) mod ssl;

use std::os::raw::c_int;

const SSL_ERROR_WANT_READ: c_int = 2;
const SSL_ERROR_WANT_WRITE: c_int = 3;

#[macro_export]
macro_rules! opaque_ffi_struct {
    ($name: tt) => {
        #[repr(C)]
        pub(super) struct $name {
            _data: [u8; 0],
            _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
        }
    };
}
