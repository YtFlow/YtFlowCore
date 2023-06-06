use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;
use std::ptr::null_mut;

use super::error::FfiResult;
use super::interop::serialize_buffer;
use crate::data::{
    Connection, Database, Plugin, Profile, Proxy, ProxyGroup, Resource, ResourceGitHubRelease,
    ResourceUrl,
};

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
            profile_id,
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
        Profile::delete(profile_id, conn).map(|()| (null_mut(), 0))
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
            plugin_id,
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
        Plugin::delete(plugin_id, conn).map(|()| (null_mut(), 0))
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

#[no_mangle]
pub extern "C" fn ytflow_proxy_group_get_all(conn: *const Connection) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        ProxyGroup::query_all(conn).map(|p| serialize_buffer(&p))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_proxy_group_get_by_id(
    proxy_group_id: u32,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        ProxyGroup::query_by_id(proxy_group_id as usize, conn).map(|p| serialize_buffer(&p))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_proxy_group_create(
    name: *const c_char,
    r#type: *const c_char,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let name = unsafe { CStr::from_ptr(name) };
        let r#type = unsafe { CStr::from_ptr(r#type) };
        let conn = unsafe { &*conn };
        ProxyGroup::create(
            name.to_string_lossy().into_owned(),
            r#type.to_string_lossy().into_owned(),
            conn,
        )
        .map(|id| (id as _, 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_proxy_group_rename(
    proxy_group_id: u32,
    name: *const c_char,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let name = unsafe { CStr::from_ptr(name) };
        let conn = unsafe { &*conn };
        ProxyGroup::rename(proxy_group_id, name.to_string_lossy().into_owned(), conn)
            .map(|()| (null_mut(), 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_proxy_group_delete(
    proxy_group_id: u32,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        ProxyGroup::delete(proxy_group_id, conn).map(|()| (null_mut(), 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_proxy_get_by_proxy_group(
    proxy_group_id: u32,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        Proxy::query_all_by_group(proxy_group_id.into(), conn).map(|p| serialize_buffer(&p))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_proxy_create(
    proxy_group_id: u32,
    name: *const c_char,
    proxy: *const u8,
    proxy_len: usize,
    proxy_version: u16,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let name = unsafe { CStr::from_ptr(name) };
        let conn = unsafe { &*conn };
        Proxy::create(
            proxy_group_id.into(),
            name.to_string_lossy().into_owned(),
            unsafe { std::slice::from_raw_parts(proxy, proxy_len).to_vec() },
            proxy_version,
            conn,
        )
        .map(|id| (id as _, 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_proxy_update(
    proxy_id: u32,
    name: *const c_char,
    proxy: *const u8,
    proxy_len: usize,
    proxy_version: u16,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let name = unsafe { CStr::from_ptr(name) };
        let conn = unsafe { &*conn };
        Proxy::update(
            proxy_id,
            name.to_string_lossy().into_owned(),
            unsafe { std::slice::from_raw_parts(proxy, proxy_len).to_vec() },
            proxy_version,
            conn,
        )
        .map(|()| (null_mut(), 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_proxy_delete(proxy_id: u32, conn: *const Connection) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        Proxy::delete(proxy_id, conn).map(|()| (null_mut(), 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_proxy_reorder(
    proxy_group_id: u32,
    range_start_order: i32,
    range_end_order: i32,
    moves: i32,
    conn: *mut Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &mut *conn };
        Proxy::reorder(
            proxy_group_id.into(),
            range_start_order,
            range_end_order,
            moves,
            conn,
        )
        .map(|()| (null_mut(), 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_resource_get_all(conn: *const Connection) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        Resource::query_all(conn).map(|r| serialize_buffer(&r))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_resource_delete(resource_id: u32, conn: *const Connection) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        Resource::delete(resource_id, conn).map(|()| (null_mut(), 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_resource_create_with_url(
    key: *const c_char,
    r#type: *const c_char,
    local_file: *const c_char,
    url: *const c_char,
    conn: *mut Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let key = unsafe { CStr::from_ptr(key) };
        let r#type = unsafe { CStr::from_ptr(r#type) };
        let local_file = unsafe { CStr::from_ptr(local_file) };
        let url = unsafe { CStr::from_ptr(url) };
        let conn = unsafe { &mut *conn };
        Resource::create_with_url(
            key.to_string_lossy().into_owned(),
            r#type.to_string_lossy().into_owned(),
            local_file.to_string_lossy().into_owned(),
            url.to_string_lossy().into_owned(),
            conn,
        )
        .map(|id| (id as _, 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_resource_create_with_github_release(
    key: *const c_char,
    r#type: *const c_char,
    local_file: *const c_char,
    github_username: *const c_char,
    github_repo: *const c_char,
    asset_name: *const c_char,
    conn: *mut Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let key = unsafe { CStr::from_ptr(key) };
        let r#type = unsafe { CStr::from_ptr(r#type) };
        let local_file = unsafe { CStr::from_ptr(local_file) };
        let github_username = unsafe { CStr::from_ptr(github_username) };
        let github_repo = unsafe { CStr::from_ptr(github_repo) };
        let asset_name = unsafe { CStr::from_ptr(asset_name) };
        let conn = unsafe { &mut *conn };
        Resource::create_with_github_release(
            key.to_string_lossy().into_owned(),
            r#type.to_string_lossy().into_owned(),
            local_file.to_string_lossy().into_owned(),
            github_username.to_string_lossy().into_owned(),
            github_repo.to_string_lossy().into_owned(),
            asset_name.to_string_lossy().into_owned(),
            conn,
        )
        .map(|id| (id as _, 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_resource_url_query_by_resource_id(
    resource_id: u32,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        ResourceUrl::query_by_resource_id(resource_id, conn).map(|r| serialize_buffer(&r))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_resource_url_update_retrieved_by_resource_id(
    resource_id: u32,
    etag: *const c_char,
    last_modified: *const c_char,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let etag = if etag.is_null() {
            None
        } else {
            Some(
                unsafe { CStr::from_ptr(etag) }
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        let last_modified = if last_modified.is_null() {
            None
        } else {
            Some({
                unsafe { CStr::from_ptr(last_modified) }
                    .to_string_lossy()
                    .into_owned()
            })
        };
        let conn = unsafe { &*conn };
        ResourceUrl::update_retrieved_by_resource_id(resource_id, etag, last_modified, conn)
            .map(|()| (null_mut(), 0))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_resource_github_release_query_by_resource_id(
    resource_id: u32,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let conn = unsafe { &*conn };
        ResourceGitHubRelease::query_by_resource_id(resource_id, conn).map(|r| serialize_buffer(&r))
    }))
}

#[no_mangle]
pub extern "C" fn ytflow_resource_github_release_update_retrieved_by_resource_id(
    resource_id: u32,
    git_tag: *const c_char,
    release_title: *const c_char,
    conn: *const Connection,
) -> FfiResult {
    FfiResult::catch_result_unwind(AssertUnwindSafe(move || {
        let git_tag = unsafe { CStr::from_ptr(git_tag) };
        let release_title = unsafe { CStr::from_ptr(release_title) };
        let conn = unsafe { &*conn };
        ResourceGitHubRelease::update_retrieved_by_resource_id(
            resource_id,
            git_tag.to_string_lossy().into_owned(),
            release_title.to_string_lossy().into_owned(),
            conn,
        )
        .map(|()| (null_mut(), 0))
    }))
}
