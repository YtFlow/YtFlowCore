use std::ffi::CStr;
use std::os::raw::c_char;

use super::error::FfiResult;
use super::interop::serialize_buffer;
use crate::config::verify::verify_plugin;
use crate::config::Plugin;

#[no_mangle]
pub extern "C" fn ytflow_plugin_verify(
    plugin: *const c_char,
    plugin_version: u16,
    param: *const u8,
    param_len: usize,
) -> FfiResult {
    FfiResult::catch_result_unwind(move || {
        let plugin = unsafe { CStr::from_ptr(plugin) };
        let plugin = Plugin {
            name: String::from("test_plugin"),
            plugin: plugin.to_string_lossy().into_owned(),
            plugin_version,
            param: unsafe { std::slice::from_raw_parts(param, param_len).to_vec() },
        };
        verify_plugin(&plugin).map(|v| serialize_buffer(&v))
    })
}
