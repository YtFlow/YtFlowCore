use std::{panic::AssertUnwindSafe, ptr::null_mut};

use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime};

use super::error::FfiResult;

#[allow(unused)]
pub struct Runtime {
    pub(crate) rt: TokioRuntime,
}

#[no_mangle]
pub extern "C" fn ytflow_runtime_new() -> FfiResult {
    FfiResult::catch_ptr_unwind(|| {
        let rt = TokioRuntimeBuilder::new_multi_thread()
            .enable_all()
            .thread_name("ytflow-tokio-runtime-worker")
            .worker_threads(2)
            .build()
            .expect("Cannot build Tokio Runtime");
        (Box::into_raw(Box::new(Runtime { rt })) as _, 0)
    })
}

#[no_mangle]
pub extern "C" fn ytflow_runtime_free(runtime: *mut Runtime) -> FfiResult {
    FfiResult::catch_ptr_unwind(AssertUnwindSafe(|| {
        unsafe { drop(Box::from_raw(runtime)) };
        (null_mut(), 0)
    }))
}
