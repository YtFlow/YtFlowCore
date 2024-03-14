#![allow(clippy::missing_safety_doc)]
pub mod cbor;
pub mod config;
pub mod data;
pub mod error;
pub mod interop;
pub mod proxy;
pub mod runtime;
pub mod share_link;
pub mod subscription;

pub mod exports {
    pub use super::ytflow_get_version;
    use super::*;
    pub use cbor::{ytflow_app_cbor_from_json, ytflow_app_cbor_to_json};
    pub use config::ytflow_plugin_verify;
    #[cfg(unix)]
    pub use data::ytflow_db_new_unix;
    #[cfg(windows)]
    pub use data::ytflow_db_new_win32;
    pub use data::{
        ytflow_db_conn_free, ytflow_db_conn_new, ytflow_db_free, ytflow_plugin_create,
        ytflow_plugin_delete, ytflow_plugin_update, ytflow_plugins_get_by_profile,
        ytflow_plugins_get_entry, ytflow_profile_create, ytflow_profile_delete,
        ytflow_profile_update, ytflow_profiles_get_all, ytflow_proxy_create, ytflow_proxy_delete,
        ytflow_proxy_get_by_proxy_group, ytflow_proxy_group_create, ytflow_proxy_group_delete,
        ytflow_proxy_group_get_all, ytflow_proxy_group_get_by_id, ytflow_proxy_group_rename,
        ytflow_proxy_reorder, ytflow_proxy_update, ytflow_resource_create_with_github_release,
        ytflow_resource_create_with_url, ytflow_resource_delete, ytflow_resource_get_all,
        ytflow_resource_github_release_query_by_resource_id,
        ytflow_resource_github_release_update_retrieved_by_resource_id,
        ytflow_resource_url_query_by_resource_id,
        ytflow_resource_url_update_retrieved_by_resource_id,
    };
    pub use error::ytflow_result_free;
    pub use interop::ytflow_buffer_free;
    pub use proxy::{ytflow_app_proxy_data_proxy_analyze, ytflow_app_proxy_data_proxy_compose_v1};
    pub use runtime::{ytflow_runtime_free, ytflow_runtime_new};
    pub use share_link::{ytflow_app_share_link_decode, ytflow_app_share_link_encode};
    pub use subscription::{
        ytflow_app_subscription_decode, ytflow_app_subscription_decode_with_format,
        ytflow_app_subscription_userinfo_header_decode,
    };
}

#[no_mangle]
pub extern "C" fn ytflow_get_version() -> *const std::os::raw::c_char {
    use std::ffi::CString;
    use std::os::raw::c_char;
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicPtr, Ordering};
    static VERSION_CPTR: AtomicPtr<c_char> = AtomicPtr::new(null_mut());
    let cptr = VERSION_CPTR.load(Ordering::Acquire);
    if !cptr.is_null() {
        return cptr as _;
    }
    // Let it leak
    VERSION_CPTR.store(
        CString::new(env!("CARGO_PKG_VERSION")).unwrap().into_raw(),
        Ordering::Release,
    );
    ytflow_get_version()
}
