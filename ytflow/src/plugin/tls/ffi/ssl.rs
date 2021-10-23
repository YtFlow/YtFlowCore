use std::os::raw::*;

crate::opaque_ffi_struct!(SSL);

use super::bio::{Bio, BioData, BIO};
use super::ctx::SSL_CTX;
use crate::flow::Buffer;

extern "C" {
    fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;
    fn SSL_free(ssl: *mut SSL);
    fn SSL_set_bio(ssl: *mut SSL, rbio: *mut BIO, wbio: *mut BIO);
    fn SSL_get_error(ssl: *const SSL, ret: c_int) -> c_int;
    fn SSL_write(ssl: *mut SSL, buf: *const c_void, num: c_int) -> c_int;
    fn SSL_read(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int;
    fn SSL_do_handshake(ssl: *mut SSL) -> c_int;
    fn SSL_shutdown(ssl: *mut SSL) -> c_int;
}

#[derive(Clone, Copy)]
pub enum SslResult {
    Ok(c_int),
    WantRead,
    WantWrite,
    Fatal,
    // TODO: detailed errors
}

pub struct Ssl {
    inner: *mut SSL,
    bio: Bio,
}

unsafe impl Send for Ssl {}
unsafe impl Sync for Ssl {}

impl Ssl {
    pub fn new(ctx: &super::ctx::SslCtx, bio: super::bio::Bio) -> Self {
        let ptr = unsafe { SSL_new(ctx.inner) };
        if ptr.is_null() {
            panic!("Failed to create SSL");
        }
        let bio_ptr = bio.inner.clone().into_raw();
        // Safety: one reference of BIO will be consumed
        unsafe {
            SSL_set_bio(ptr, bio_ptr, bio_ptr);
        }
        Self { inner: ptr, bio }
    }

    fn ret_to_error(&self, ret: c_int) -> SslResult {
        if ret > 0 {
            return SslResult::Ok(ret);
        }
        let code = unsafe { SSL_get_error(self.inner, ret) };
        match code {
            super::SSL_ERROR_WANT_READ => SslResult::WantRead,
            super::SSL_ERROR_WANT_WRITE => SslResult::WantWrite,
            _ => SslResult::Fatal,
        }
    }

    pub fn do_handshake(&mut self) -> SslResult {
        self.ret_to_error(unsafe { SSL_do_handshake(self.inner) })
    }

    pub fn write(&mut self, data: &[u8]) -> SslResult {
        self.ret_to_error(unsafe {
            SSL_write(self.inner, data.as_ptr() as *const _, data.len() as _)
        })
    }

    pub fn read(&mut self, data: &mut [u8]) -> SslResult {
        self.ret_to_error(unsafe {
            SSL_write(self.inner, data.as_mut_ptr() as *mut _, data.len() as _)
        })
    }

    pub fn shutdown(&mut self) -> SslResult {
        self.ret_to_error(unsafe { SSL_shutdown(self.inner) })
    }

    pub fn inner_data_mut(&mut self) -> &mut BioData {
        self.bio.get_data_mut()
    }
}

impl Drop for Ssl {
    fn drop(&mut self) {
        unsafe {
            SSL_free(self.inner);
        }
    }
}
