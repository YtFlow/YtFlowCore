#![feature(generic_const_exprs)]
#![feature(stmt_expr_attributes)]
#![feature(const_btree_new)]
#![feature(arc_new_cyclic)]

mod bindings {
    windows::include_bindings!();
}
pub mod config;
pub mod flow;
pub mod log;
pub mod plugin;
