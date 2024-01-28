use std::{panic::AssertUnwindSafe, ptr::null_mut};

use ytflow::tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime};

use super::error::ytflow_result;

#[allow(unused, non_camel_case_types)]
pub struct ytflow_runtime {
    pub(crate) rt: TokioRuntime,
}

#[allow(unused, non_camel_case_types)]
pub(crate) type FfiRuntime = ytflow_runtime;

#[no_mangle]
pub extern "C" fn ytflow_runtime_new() -> ytflow_result {
    ytflow_result::catch_ptr_unwind(|| {
        let rt = TokioRuntimeBuilder::new_multi_thread()
            .enable_all()
            .thread_name("ytflow-tokio-runtime-worker")
            .worker_threads(2)
            .build()
            .expect("Cannot build Tokio Runtime");
        (Box::into_raw(Box::new(FfiRuntime { rt })) as _, 0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn ytflow_runtime_free(runtime: *mut ytflow_runtime) -> ytflow_result {
    ytflow_result::catch_ptr_unwind(AssertUnwindSafe(|| {
        unsafe { drop(Box::from_raw(runtime)) };
        (null_mut(), 0)
    }))
}
