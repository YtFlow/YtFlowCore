#![allow(unused_unsafe)]
#![feature(generic_const_exprs)]
#![feature(stmt_expr_attributes)]
#![feature(ptr_metadata)]
#![feature(once_cell)]
#![feature(let_chains)]
#![feature(ip)]
#![feature(const_option)]
#![feature(result_flattening)]

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
