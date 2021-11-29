use std::os::raw::*;

use libc::strlen;

crate::opaque_ffi_struct!(BIO);
crate::opaque_ffi_struct!(BIO_METHOD);

type BioCreateFn = extern "C" fn(*mut BIO) -> c_int;
type BioDestroyFn = extern "C" fn(*mut BIO) -> c_int;
type BioReadFn = extern "C" fn(*mut BIO, *mut c_char, c_int) -> c_int;
type BioWriteFn = extern "C" fn(*mut BIO, *const c_char, c_int) -> c_int;
type BioPutsFn = extern "C" fn(*mut BIO, *const c_char) -> c_int;
type BioCtrlFn = extern "C" fn(*mut BIO, c_int, c_long, *mut c_void) -> c_long;

const BIO_TYPE_NONE: c_int = 0;
const BIO_FLAGS_READ: c_int = 0x01;
const BIO_FLAGS_WRITE: c_int = 0x02;
const BIO_FLAGS_SHOULD_RETRY: c_int = 0x08;
const BIO_CTRL_EOF: c_int = 2;
const BIO_CTRL_FLUSH: c_int = 11;

use crate::flow::Buffer;

extern "C" {
    fn BIO_meth_new(r#type: c_int, name: *const c_char) -> *mut BIO_METHOD;
    fn BIO_meth_free(biom: *mut BIO_METHOD);
    fn BIO_meth_set_create(biom: *mut BIO_METHOD, cb: Option<BioCreateFn>) -> c_int;
    fn BIO_meth_set_destroy(biom: *mut BIO_METHOD, cb: Option<BioDestroyFn>) -> c_int;
    fn BIO_meth_set_read(biom: *mut BIO_METHOD, cb: Option<BioReadFn>) -> c_int;
    fn BIO_meth_set_write(biom: *mut BIO_METHOD, cb: Option<BioWriteFn>) -> c_int;
    fn BIO_meth_set_puts(biom: *mut BIO_METHOD, cb: Option<BioPutsFn>) -> c_int;
    fn BIO_meth_set_ctrl(biom: *mut BIO_METHOD, cb: Option<BioCtrlFn>) -> c_int;

    fn BIO_new(r#type: *const BIO_METHOD) -> *mut BIO;
    fn BIO_free(bio: *mut BIO) -> c_int;
    fn BIO_up_ref(a: *mut BIO) -> c_int;
    fn BIO_get_data(bio: *mut BIO) -> *mut c_void;
    fn BIO_set_data(bio: *mut BIO, ptr: *mut c_void);
    fn BIO_set_init(bio: *mut BIO, init: c_int);
    fn BIO_set_flags(bio: *mut BIO, flags: c_int);
}

pub(super) struct BioMethod {
    inner: *mut BIO_METHOD,
}

unsafe impl Send for BioMethod {}
unsafe impl Sync for BioMethod {}

impl Drop for BioMethod {
    fn drop(&mut self) {
        unsafe {
            BIO_meth_free(self.inner);
        }
    }
}

extern "C" fn bcreate(bio: *mut BIO) -> c_int {
    unsafe {
        BIO_set_data(
            bio,
            Box::into_raw(Box::new(BioData {
                rx_eof: false,
                rx_buf: None,
                rx_size_hint: None,
                tx_buf: None,
            })) as *mut _,
        );
        BIO_set_init(bio, 1);
    };
    1
}

extern "C" fn bdestroy(bio: *mut BIO) -> c_int {
    unsafe {
        drop(Box::<BioData>::from_raw(BIO_get_data(bio) as *mut _));
    }
    1
}

extern "C" fn bread(bio: *mut BIO, buf: *mut c_char, len: c_int) -> c_int {
    let bio_data: &mut BioData = unsafe { get_data_mut(bio) };
    if bio_data.rx_eof {
        return -1;
    }
    let (rx_buf, offset) = match bio_data.rx_buf.as_mut() {
        Some(buf) => buf,
        None => {
            bio_set_retry_read(bio);
            return -1;
        }
    };
    let to_read = (rx_buf.len() - *offset).min(len as usize);
    if to_read == 0 {
        bio_set_retry_read(bio);
        return -1;
    }
    let src = &mut rx_buf[*offset..(*offset + to_read)];
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_mut_ptr(), buf as *mut _, to_read);
    }
    *offset += to_read;
    to_read as _
}

extern "C" fn bwrite(bio: *mut BIO, buf: *const c_char, len: c_int) -> c_int {
    let bio_data: &mut BioData = unsafe { get_data_mut(bio) };
    let (tx_buf, offset) = match bio_data.tx_buf.as_mut() {
        Some(buf) => buf,
        None => {
            bio_set_retry_write(bio);
            return -1;
        }
    };
    let to_write = (tx_buf.len() - *offset).min(len as usize);
    if to_write == 0 {
        bio_set_retry_write(bio);
        return -1;
    }
    let src = unsafe { std::slice::from_raw_parts(buf as *const _, len as usize) };
    tx_buf[*offset..(*offset + to_write)].copy_from_slice(&src[..to_write]);
    *offset += to_write;
    to_write as _
}

extern "C" fn bputs(bio: *mut BIO, buf: *const c_char) -> c_int {
    bwrite(bio, buf, unsafe { strlen(buf) as c_int })
}

extern "C" fn bctrl(bio: *mut BIO, cmd: c_int, _larg: c_long, _parg: *mut c_void) -> c_long {
    match cmd {
        BIO_CTRL_EOF => {
            let bio_data = unsafe { get_data_mut(bio) };
            bio_data.rx_eof.into()
        }
        BIO_CTRL_FLUSH => 1,
        _ => 0,
    }
}

fn bio_set_retry_read(bio: *mut BIO) {
    unsafe { BIO_set_flags(bio, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY) }
}

fn bio_set_retry_write(bio: *mut BIO) {
    unsafe { BIO_set_flags(bio, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY) }
}

unsafe fn get_data_mut<'a>(bio: *mut BIO) -> &'a mut BioData {
    unsafe { &mut *(BIO_get_data(bio) as *mut _) }
}

impl BioMethod {
    fn new() -> BioMethod {
        let ptr = unsafe { BIO_meth_new(BIO_TYPE_NONE, b"YtFlowCore_Flow_Bio\0" as *const _ as _) };
        if ptr.is_null() {
            panic!("Failed to create BIO_METHOD");
        }
        // These functions are pure setters and should not fail in OpenSSL
        unsafe {
            BIO_meth_set_create(ptr, Some(bcreate));
            BIO_meth_set_destroy(ptr, Some(bdestroy));
            BIO_meth_set_read(ptr, Some(bread));
            BIO_meth_set_write(ptr, Some(bwrite));
            BIO_meth_set_puts(ptr, Some(bputs));
            BIO_meth_set_ctrl(ptr, Some(bctrl));
        }
        BioMethod { inner: ptr }
    }
}

pub(super) struct BioInner {
    inner: *mut BIO,
}

unsafe impl Send for BioInner {}
unsafe impl Sync for BioInner {}

impl BioInner {
    /// # Safety:
    /// Caller must ensure `meth` is valid and freed **after** BioInner.
    unsafe fn new(meth: *const BIO_METHOD) -> Self {
        let ptr = unsafe { BIO_new(meth) };
        if ptr.is_null() {
            panic!("Failed to create BIO");
        }
        Self { inner: ptr }
    }

    pub(super) fn into_raw(self) -> *mut BIO {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr
    }
}

impl Clone for BioInner {
    fn clone(&self) -> BioInner {
        let ret = unsafe { BIO_up_ref(self.inner) };
        if ret != 1 {
            panic!("Cannot clone BIO");
        }
        BioInner { inner: self.inner }
    }
}

impl Drop for BioInner {
    fn drop(&mut self) {
        let ret = unsafe { BIO_free(self.inner) };
        if ret != 1 {
            panic!("Cannot drop BIO");
        }
    }
}

pub struct Bio {
    pub(super) inner: BioInner,
    _meth: BioMethod,
}

impl Bio {
    pub fn new() -> Self {
        let meth = BioMethod::new();
        // Safety: Fields are dropped in declaration order so that
        // BIO is dropped before BIO_METHOD
        let inner = unsafe { BioInner::new(meth.inner) };
        Self { _meth: meth, inner }
    }

    pub(super) fn get_data_mut(&mut self) -> &mut BioData {
        unsafe { get_data_mut(self.inner.inner) }
    }
}

pub struct BioData {
    pub rx_eof: bool,
    pub rx_buf: Option<(Buffer, usize)>,
    pub rx_size_hint: Option<crate::flow::SizeHint>,
    pub tx_buf: Option<(Buffer, usize)>,
}
