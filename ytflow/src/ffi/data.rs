use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;
use std::ptr::null_mut;

use super::error::FfiResult;
use super::interop::serialize_buffer;
use crate::data::{Connection, Database, Plugin, Profile};

#[no_mangle]
#[cfg(windows)]
pub extern "C" fn ytflow_db_new_win32(path: *const u16, len: usize) -> FfiResult {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    FfiResult::catch_result_unwind(move || {
        let path = unsafe { OsString::from_wide(std::slice::from_raw_parts(path, len)) };
        Database::open(path).map(|db| (Box::into_raw(Box::new(db)) as *mut _, 0))
    })
}

#[no_mangle]
#[cfg(unix)]
pub extern "C" fn ytflow_db_new_unix(path: *const u8, len: usize) -> FfiResult {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    FfiResult::catch_result_unwind(move || {
        let path = unsafe { OsStr::from_bytes(std::slice::from_raw_parts(path, len)) };
        Database::open(path).map(|db| (Box::into_raw(Box::new(db)) as *mut _, 0))
    })
}

#[no_mangle]
pub extern "C" fn ytflow_db_free(db: *mut Database) -> FfiResult {
    FfiResult::catch_ptr_unwind(move || {
        unsafe { drop(Box::from_raw(db)) };
        (null_mut(), 0)
    })
}

#[no_mangle]
pub extern "C" fn ytflow_db_conn_new(db: *const Database) -> FfiResult {
    FfiResult::catch_result_unwind(move || {
        let db = unsafe { &*db };
        db.connect()
            .map(|conn| (Box::into_raw(Box::new(conn)) as *mut _, 0))
    })
}

#[no_mangle]
pub extern "C" fn ytflow_db_conn_free(conn: *mut Connection) -> FfiResult {
    FfiResult::catch_ptr_unwind(AssertUnwindSafe(move || {
        unsafe { drop(Box::from_raw(conn)) };
        (null_mut(), 0)
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_profiles_get_all(conn: *const Connection) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        Profile::query_all(conn).map(|p| serialize_buffer(&p))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_plugins_get_by_profile(
    profile_id: u32,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        Plugin::query_all_by_profile(profile_id.into(), conn).map(|p| serialize_buffer(&p))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_plugins_get_entry(profile_id: u32, conn: *const Connection) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        Plugin::query_entry_by_profile(profile_id.into(), conn).map(|p| serialize_buffer(&p))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_profile_create(
    name: *const c_char,
    locale: *const c_char,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let name = unsafe { CStr::from_ptr(name) };
        let locale = unsafe { CStr::from_ptr(locale) };
        let conn = unsafe { &*conn };
        Profile::create(
            name.to_string_lossy().into_owned(),
            locale.to_string_lossy().into_owned(),
            conn,
        )
        .map(|id| (id as _, 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_profile_update(
    profile_id: u32,
    name: *const c_char,
    locale: *const c_char,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let name = unsafe { CStr::from_ptr(name) };
        let locale = unsafe { CStr::from_ptr(locale) };
        let conn = unsafe { &*conn };
        Profile::update(
            profile_id.into(),
            name.to_string_lossy().into_owned(),
            locale.to_string_lossy().into_owned(),
            conn,
        )
        .map(|()| (null_mut(), 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_profile_delete(profile_id: u32, conn: *const Connection) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        Profile::delete(profile_id.into(), conn).map(|()| (null_mut(), 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_plugin_create(
    profile_id: u32,
    name: *const c_char,
    desc: *const c_char,
    plugin: *const c_char,
    plugin_version: u16,
    param: *const u8,
    param_len: usize,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let name = unsafe { CStr::from_ptr(name) };
        let desc = unsafe { CStr::from_ptr(desc) };
        let plugin = unsafe { CStr::from_ptr(plugin) };
        let conn = unsafe { &*conn };
        Plugin::create(
            profile_id.into(),
            name.to_string_lossy().into_owned(),
            desc.to_string_lossy().into_owned(),
            plugin.to_string_lossy().into_owned(),
            plugin_version,
            unsafe { std::slice::from_raw_parts(param, param_len).to_vec() },
            conn,
        )
        .map(|id| (id as _, 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_plugin_update(
    plugin_id: u32,
    profile_id: u32,
    name: *const c_char,
    desc: *const c_char,
    plugin: *const c_char,
    plugin_version: u16,
    param: *const u8,
    param_len: usize,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let name = unsafe { CStr::from_ptr(name) };
        let desc = unsafe { CStr::from_ptr(desc) };
        let plugin = unsafe { CStr::from_ptr(plugin) };
        let conn = unsafe { &*conn };
        Plugin::update(
            plugin_id.into(),
            profile_id.into(),
            name.to_string_lossy().into_owned(),
            desc.to_string_lossy().into_owned(),
            plugin.to_string_lossy().into_owned(),
            plugin_version,
            unsafe { std::slice::from_raw_parts(param, param_len).to_vec() },
            conn,
        )
        .map(|()| (null_mut(), 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_plugin_delete(plugin_id: u32, conn: *const Connection) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        Plugin::delete(plugin_id.into(), conn).map(|()| (null_mut(), 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_plugin_set_as_entry(
    plugin_id: u32,
    profile_id: u32,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        Plugin::set_as_entry(profile_id.into(), plugin_id.into(), conn).map(|()| (null_mut(), 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_plugin_unset_as_entry(
    plugin_id: u32,
    profile_id: u32,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        Plugin::unset_as_entry(profile_id.into(), plugin_id.into(), conn).map(|()| (null_mut(), 0))
    }))
}
