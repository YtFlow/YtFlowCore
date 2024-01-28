use std::ffi::CStr;
use std::os::raw::c_char;

use ytflow::config::verify::verify_plugin;
use ytflow::config::Plugin;

use super::error::ytflow_result;
use super::interop::serialize_buffer;

#[no_mangle]
pub unsafe extern "C" fn ytflow_plugin_verify(
    plugin: *const c_char,
    plugin_version: u16,
    param: *const u8,
    param_len: usize,
) -> ytflow_result {
    ytflow_result::catch_result_unwind(move || {
        let plugin = unsafe { CStr::from_ptr(plugin) };
        let plugin = Plugin {
            id: None,
            name: String::from("test_plugin"),
            plugin: plugin.to_string_lossy().into_owned(),
            plugin_version,
            param: unsafe { std::slice::from_raw_parts(param, param_len).to_vec() },
        };
        verify_plugin(&plugin).map(|v| serialize_buffer(&v))
    })
}
