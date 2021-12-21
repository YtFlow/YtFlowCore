use std::ffi::CStr;
use std::os::raw::c_char;

use chrono::NaiveDateTime;

use super::error::FfiResult;
use super::interop::serialize_buffer;
use crate::config::verify::verify_plugin;
use crate::data::{Id, Plugin};

#[no_mangle]
pub extern "C" fn ytflow_plugin_verify(
    plugin: *const c_char,
    plugin_version: u16,
    param: *const c_char,
) -> FfiResult {
    FfiResult::catch_result_unwind(move || {
        let plugin = unsafe { CStr::from_ptr(plugin) };
        let param = unsafe { CStr::from_ptr(param) };
        let plugin = Plugin {
            id: Id::default(),
            name: String::from("test_plugin"),
            desc: String::from("Plugin for verification"),
            plugin: plugin.to_string_lossy().into_owned(),
            plugin_version,
            param: param.to_string_lossy().into_owned(),
            updated_at: NaiveDateTime::from_timestamp(0, 0),
        };
        verify_plugin(&plugin).map(|v| serialize_buffer(&v))
    })
}
