pub mod config;
pub mod data;
pub mod error;
pub mod interop;
pub mod runtime;

pub mod exports {
    use super::*;
    pub use config::ytflow_plugin_verify;
    #[cfg(unix)]
    pub use data::ytflow_db_new_unix;
    #[cfg(windows)]
    pub use data::ytflow_db_new_win32;
    pub use data::{
        ytflow_db_conn_free, ytflow_db_conn_new, ytflow_db_free, ytflow_plugin_create,
        ytflow_plugin_delete, ytflow_plugin_update, ytflow_plugins_get_by_profile,
        ytflow_plugins_get_entry, ytflow_profile_create, ytflow_profile_delete,
        ytflow_profile_update, ytflow_profiles_get_all,
    };
    pub use error::ytflow_result_free;
    pub use interop::ytflow_buffer_free;
    pub use runtime::{ytflow_runtime_free, ytflow_runtime_new};
}
