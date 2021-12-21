#![allow(unused_unsafe)]
#![feature(generic_const_exprs)]
#![feature(stmt_expr_attributes)]
#![feature(const_btree_new)]
#![feature(arc_new_cyclic)]
#![feature(bool_to_option)]
#![feature(vec_spare_capacity)]
#![feature(ptr_metadata)]

pub mod config;
pub mod data;
pub mod ffi;
pub mod flow;
pub mod log;
pub mod plugin;

pub use tokio;
