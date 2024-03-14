use std::any::Any;
use std::ffi::CString;
use std::fmt::Display;
use std::os::raw::{c_char, c_void};
use std::panic::{catch_unwind, UnwindSafe};
use std::ptr::null_mut;

use ytflow::config::ConfigError;
use ytflow::data::DataError;

use crate::{cbor, proxy, share_link, subscription};

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct ytflow_result_content(*mut c_void, usize);
#[allow(non_camel_case_types)]
pub type ytflow_error_fields = [*mut c_char; 4];

#[repr(C)]
#[allow(non_camel_case_types)]
pub union ytflow_result_data {
    pub res: ytflow_result_content,
    pub err: ytflow_error_fields,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct ytflow_result {
    pub code: u32,
    pub data: ytflow_result_data,
}

pub struct ErrorDesc {
    code: u32,
    message: [*mut c_char; 3],
}

pub trait ToFfiError: ToString {
    fn from(self) -> ErrorDesc;
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

impl ytflow_result {
    pub fn no_error(ptr: ytflow_result_content) -> Self {
        Self {
            code: 0,
            data: ytflow_result_data { res: ptr },
        }
    }
}

impl ErrorDesc {
    fn e0(code: u32) -> Self {
        Self {
            code,
            message: [null_mut(); 3],
        }
    }
    // FIXME: leak when panic?
    fn e1(code: u32, f1: String) -> Self {
        let mut e = ErrorDesc::e0(code);
        e.message[0] = string_to_c_ptr(&f1);
        e
    }
    fn e2(code: u32, f1: String, f2: String) -> Self {
        let mut e = ErrorDesc::e1(code, f1);
        e.message[1] = string_to_c_ptr(&f2);
        e
    }
    #[allow(unused)]
    fn e3(code: u32, f1: String, f2: String, f3: String) -> Self {
        let mut e = ErrorDesc::e2(code, f1, f2);
        e.message[2] = string_to_c_ptr(&f3);
        e
    }
}

impl<T: ToFfiError> From<T> for ytflow_result {
    fn from(e: T) -> Self {
        let err_str = e.to_string();
        let ErrorDesc {
            code,
            message: [e1, e2, e3],
        } = e.from();
        Self {
            code,
            data: ytflow_result_data {
                err: [string_to_c_ptr(&err_str), e1, e2, e3],
            },
        }
    }
}

const INVALID_CBOR_ERROR_CODE: u32 = 0x8001_1601;

impl ToFfiError for DataError {
    fn from(self) -> ErrorDesc {
        use DataError::*;
        const BASE_CODE: u32 = 0x8000_1000;
        match self {
            Migration(r) => ErrorDesc::e1(BASE_CODE + 1, r.to_string()),
            Database(r) => ErrorDesc::e1(BASE_CODE + 2, r.to_string()),
            InvalidData { domain, field } => {
                ErrorDesc::e2(BASE_CODE + 3, domain.to_string(), field.to_string())
            }
        }
    }
}

impl ToFfiError for ConfigError {
    fn from(self) -> ErrorDesc {
        use ConfigError::*;
        const BASE_CODE: u32 = 0x8000_2000;
        match self {
            ParseParam(p, inner) => ErrorDesc::e2(BASE_CODE + 1, p, inner.to_string()),
            InvalidParam { plugin, field } => {
                ErrorDesc::e2(BASE_CODE + 2, plugin, field.to_string())
            }
            NoAccessPoint {
                initiator,
                descriptor,
            } => ErrorDesc::e2(BASE_CODE + 3, initiator, descriptor),
            BadAccessPointType {
                initiator,
                r#type,
                descriptor,
            } => ErrorDesc::e3(BASE_CODE + 4, initiator, r#type, descriptor),
            NoPlugin { initiator, plugin } => ErrorDesc::e2(BASE_CODE + 5, initiator, plugin),
            NoPluginType {
                initiator,
                r#type,
                version,
            } => ErrorDesc::e3(BASE_CODE + 6, initiator, r#type, version.to_string()),
            RecursionLimitExceeded(p) => ErrorDesc::e1(0x0800_0007, p),
            TooManyPlugin { plugin, r#type } => {
                ErrorDesc::e2(BASE_CODE + 7, plugin, r#type.to_string())
            }
        }
    }
}

impl ToFfiError for proxy::data::AnalyzeError {
    fn from(self) -> ErrorDesc {
        use proxy::data::AnalyzeError::*;
        const BASE_CODE: u32 = 0x8001_1100;
        match self {
            UnknownVersion => ErrorDesc::e0(BASE_CODE + 1),
            InvalidEncoding => ErrorDesc::e0(INVALID_CBOR_ERROR_CODE),
            DuplicateName(n) => ErrorDesc::e1(BASE_CODE + 3, n),
            PluginNotFound(n, v) => ErrorDesc::e2(BASE_CODE + 4, n, v),
            UnknownAccessPoint(n) => ErrorDesc::e1(BASE_CODE + 5, n),
            UnexpectedUdpAccessPoint(n, t) => ErrorDesc::e2(BASE_CODE + 6, n, t.to_string()),
            TooComplicated => ErrorDesc::e0(BASE_CODE + 7),
            InvalidPlugin(n) => ErrorDesc::e1(BASE_CODE + 8, n),
            UnusedPlugin(n) => ErrorDesc::e1(BASE_CODE + 9, n),
        }
    }
}

impl ToFfiError for proxy::data::ComposeError {
    fn from(self) -> ErrorDesc {
        use proxy::data::ComposeError::*;
        const BASE_CODE: u32 = 0x8001_1200;
        match self {
            NoLeg => ErrorDesc::e0(BASE_CODE + 1),
        }
    }
}

impl ToFfiError for share_link::DecodeError {
    fn from(self) -> ErrorDesc {
        use share_link::DecodeError::*;
        const BASE_CODE: u32 = 0x8001_1300;
        match self {
            InvalidUrl => ErrorDesc::e0(BASE_CODE + 1),
            InvalidEncoding => ErrorDesc::e0(INVALID_CBOR_ERROR_CODE),
            MissingInfo(i) => ErrorDesc::e1(BASE_CODE + 3, i.into()),
            UnknownValue(v) => ErrorDesc::e1(BASE_CODE + 4, v.into()),
            UnknownScheme => ErrorDesc::e0(BASE_CODE + 5),
            ExtraParameters(p) => ErrorDesc::e1(BASE_CODE + 6, p),
        }
    }
}

impl ToFfiError for share_link::EncodeError {
    fn from(self) -> ErrorDesc {
        use share_link::EncodeError::*;
        const BASE_CODE: u32 = 0x8001_1400;
        match self {
            TooManyLegs => ErrorDesc::e0(BASE_CODE + 1),
            InvalidEncoding(c) => ErrorDesc::e1(BASE_CODE + 2, c.into()),
            UnsupportedComponent(c) => ErrorDesc::e1(BASE_CODE + 3, c.into()),
        }
    }
}

impl ToFfiError for subscription::DecodeError {
    fn from(self) -> ErrorDesc {
        use subscription::DecodeError::*;
        const BASE_CODE: u32 = 0x8001_1500;
        match self {
            UnknownFormat => ErrorDesc::e0(BASE_CODE + 1),
            InvalidEncoding => ErrorDesc::e0(INVALID_CBOR_ERROR_CODE),
            NoProxy => ErrorDesc::e0(BASE_CODE + 3),
            UnknownValue(v) => ErrorDesc::e1(BASE_CODE + 4, v.into()),
        }
    }
}

impl ToFfiError for cbor::CborUtilError {
    fn from(self) -> ErrorDesc {
        use cbor::CborUtilError::*;
        const BASE_CODE: u32 = 0x8001_1600;
        match self {
            InvalidEncoding => ErrorDesc::e0(INVALID_CBOR_ERROR_CODE),
            UnexpectedByteReprKey(k) => ErrorDesc::e1(BASE_CODE + 2, k),
            InvalidByteRepr(r) => ErrorDesc::e1(BASE_CODE + 3, r.into()),
            MissingData => ErrorDesc::e0(BASE_CODE + 4),
            UnknownByteRepr(r) => ErrorDesc::e1(BASE_CODE + 5, r),
        }
    }
}

pub(super) struct InvalidCborError;

impl Display for InvalidCborError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid CBOR")
    }
}

impl ToFfiError for InvalidCborError {
    fn from(self) -> ErrorDesc {
        ErrorDesc::e0(INVALID_CBOR_ERROR_CODE)
    }
}

struct PanicError(String);

impl PanicError {
    fn new(e: Box<dyn Any + Send>) -> Self {
        let msg = e
            .downcast::<String>()
            .map(|b| *b)
            .or_else(|p| p.downcast::<&'static str>().map(|s| s.to_string()))
            .unwrap_or_else(|_| String::from("Unknown panic"));
        Self(msg)
    }
}

impl Display for PanicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl ToFfiError for PanicError {
    fn from(self) -> ErrorDesc {
        ErrorDesc::e1(0x0800_fffe, self.0)
    }
}

impl ytflow_result {
    pub fn catch_ptr_unwind(
        f: impl FnOnce() -> (*mut c_void, usize) + UnwindSafe,
    ) -> ytflow_result {
        match catch_unwind(f) {
            Ok((ptr, metadata)) => Self::no_error(ytflow_result_content(ptr, metadata)),
            Err(e) => PanicError::new(e).into(),
        }
    }
    pub fn catch_result_unwind<
        F: FnOnce() -> Result<(*mut c_void, usize), R> + UnwindSafe,
        R: Into<ytflow_result>,
    >(
        f: F,
    ) -> ytflow_result {
        match catch_unwind(f) {
            Ok(Ok((ptr, metadata))) => Self::no_error(ytflow_result_content(ptr, metadata)),
            Ok(Err(e)) => e.into(),
            Err(e) => PanicError::new(e).into(),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ytflow_result_free(result: *mut ytflow_result) {
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
