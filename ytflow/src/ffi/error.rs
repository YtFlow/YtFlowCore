use std::any::Any;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::panic::{catch_unwind, UnwindSafe};
use std::ptr::null_mut;

use crate::config::ConfigError;
use crate::data::DataError;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiResultPtrType(*mut c_void, usize);
pub type FfiErrorFields = [*mut c_char; 3];

#[repr(C)]
pub union FfiResultUnion {
    pub res: FfiResultPtrType,
    pub err: FfiErrorFields,
}

#[repr(C)]
pub struct FfiResult {
    pub code: u32,
    pub data: FfiResultUnion,
}

fn string_to_c_ptr(s: &str) -> *mut c_char {
    if s.as_bytes().starts_with(&[0]) {
        return CString::new("")
            .expect("Converting an empty error message should not fail")
            .into_raw();
    }
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(e) => {
            let pos = e.nul_position();
            CString::new(&e.into_vec()[..pos])
                .expect("Cannot handle an error message with a NUL byte")
                .into_raw()
        }
    }
}

impl FfiResult {
    pub fn no_error(ptr: FfiResultPtrType) -> Self {
        Self {
            code: 0,
            data: FfiResultUnion { res: ptr },
        }
    }
    fn e0(code: u32) -> Self {
        Self {
            code,
            data: FfiResultUnion {
                err: [null_mut(); 3],
            },
        }
    }
    // FIXME: leak when panic?
    fn e1(code: u32, f1: String) -> Self {
        let mut e = Self::e0(code);
        unsafe { e.data.err[0] = string_to_c_ptr(&f1) };
        e
    }
    fn e2(code: u32, f1: String, f2: String) -> Self {
        let mut e = Self::e1(code, f1);
        unsafe { e.data.err[1] = string_to_c_ptr(&f2) };
        e
    }
    #[allow(unused)]
    fn e3(code: u32, f1: String, f2: String, f3: String) -> Self {
        let mut e = Self::e2(code, f1, f2);
        unsafe { e.data.err[2] = string_to_c_ptr(&f3) };
        e
    }
}

impl From<Box<dyn Any + Send + 'static>> for FfiResult {
    fn from(p: Box<dyn Any + Send + 'static>) -> Self {
        let msg = p
            .downcast::<String>()
            .map(|b| *b)
            .or_else(|p| p.downcast::<&'static str>().map(|s| s.to_string()))
            .unwrap_or_else(|_| String::from("Unknown panic"));
        Self::e1(0x0800_fffe, msg)
    }
}

impl From<DataError> for FfiResult {
    fn from(d: DataError) -> Self {
        match d {
            DataError::Migration(r) => Self::e1(0x0800_1001, r.to_string()),
            DataError::Database(r) => Self::e1(0x0800_1002, r.to_string()),
            DataError::InvalidData { domain, field } => {
                Self::e2(0x0800_1003, domain.to_string(), field.to_string())
            }
        }
    }
}

impl From<ConfigError> for FfiResult {
    fn from(c: ConfigError) -> Self {
        match c {
            ConfigError::ParseParam(p, inner) => Self::e2(0x0800_2001, p, inner.to_string()),
            ConfigError::InvalidParam { plugin, field } => {
                Self::e2(0x0800_2002, plugin, field.to_string())
            }
            ConfigError::NoAccessPoint {
                initiator,
                descriptor,
            } => Self::e2(0x0800_0003, initiator, descriptor),
            ConfigError::BadAccessPointType {
                initiator,
                r#type,
                descriptor,
            } => Self::e3(0x0800_0004, initiator, r#type, descriptor),
            ConfigError::NoPlugin { initiator, plugin } => Self::e2(0x0800_0005, initiator, plugin),
            ConfigError::NoPluginType {
                initiator,
                r#type,
                version,
            } => Self::e3(0x0800_0006, initiator, r#type, version.to_string()),
            ConfigError::RecursionLimitExceeded(p) => Self::e1(0x0800_0007, p),
            ConfigError::TooManyPlugin { plugin, r#type } => {
                Self::e2(0x0800_0008, plugin, r#type.to_string())
            }
        }
    }
}

impl FfiResult {
    pub fn catch_ptr_unwind(f: impl FnOnce() -> (*mut c_void, usize) + UnwindSafe) -> FfiResult {
        match catch_unwind(f) {
            Ok((ptr, metadata)) => Self::no_error(FfiResultPtrType(ptr, metadata)),
            Err(e) => e.into(),
        }
    }
    pub fn catch_result_unwind<
        F: FnOnce() -> Result<(*mut c_void, usize), R> + UnwindSafe,
        R: Into<Self>,
    >(
        f: F,
    ) -> FfiResult {
        match catch_unwind(f) {
            Ok(Ok((ptr, metadata))) => Self::no_error(FfiResultPtrType(ptr, metadata)),
            Ok(Err(e)) => e.into(),
            Err(e) => e.into(),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ytflow_result_free(result: *mut FfiResult) {
    let result = unsafe { &mut *result };
    if result.code == 0 {
        return;
    }
    unsafe {
        for ptr in &mut result.data.err {
            if !ptr.is_null() {
                drop(CString::from_raw(std::mem::replace(ptr, null_mut())));
            }
        }
    }
}
