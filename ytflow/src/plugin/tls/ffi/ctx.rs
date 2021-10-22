use std::os::raw::*;

crate::opaque_ffi_struct!(SSL_CTX);
crate::opaque_ffi_struct!(SSL_METHOD);

extern "C" {
    fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
    fn SSL_CTX_up_ref(ctx: *const SSL_CTX) -> c_int;
    fn SSL_CTX_free(ctx: *mut SSL_CTX);
    fn TLS_method() -> *const SSL_METHOD;
}

pub struct SslCtx {
    pub(super) inner: *mut SSL_CTX,
}

unsafe impl Send for SslCtx {}
unsafe impl Sync for SslCtx {}

impl SslCtx {
    pub fn new() -> Self {
        let ptr = unsafe { SSL_CTX_new(TLS_method()) };
        if ptr.is_null() {
            panic!("Failed to create SSL CTX");
        }
        // TODO: set SSL options
        Self { inner: ptr }
    }
}

impl Clone for SslCtx {
    fn clone(&self) -> Self {
        let ret = unsafe { SSL_CTX_up_ref(self.inner) };
        if ret != 1 {
            panic!("Cannot clone SSL CTX");
        }
        Self { inner: self.inner }
    }
}

impl Drop for SslCtx {
    fn drop(&mut self) {
        unsafe {
            SSL_CTX_free(self.inner);
        }
    }
}
