#![allow(unused_unsafe)]
#![feature(generic_const_exprs)]
#![feature(stmt_expr_attributes)]
#![feature(const_btree_new)]
#![feature(bool_to_option)]
#![feature(ptr_metadata)]

#[cfg(windows)]
mod bindings {
    windows::core::include_bindings!();
}

pub mod config;
pub mod control;
pub mod data;
pub mod ffi;
pub mod flow;
pub mod log;
pub mod plugin;

pub use tokio;
