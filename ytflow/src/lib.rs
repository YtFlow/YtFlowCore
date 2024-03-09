#![allow(unused_unsafe)]
#![feature(generic_const_exprs)]
#![feature(stmt_expr_attributes)]
#![feature(let_chains)]
#![feature(ip)]
#![feature(const_option)]
#![feature(result_flattening)]
#![feature(lazy_cell)]

pub mod config;
#[cfg(feature = "plugins")]
pub mod control;
pub mod data;
pub mod flow;
pub mod log;
pub mod plugin;
pub mod resource;

pub use tokio;
