#![feature(exitcode_exit_method)]
#![feature(let_chains)]

use std::process::ExitCode;

pub mod core;
pub mod edit;

fn execute_main<E>(main: impl FnOnce() -> Result<(), E>) {
    match main() {
        Ok(_) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
    .exit_process()
}

#[no_mangle]
pub extern "C" fn ytflow_bin_exec_core() {
    execute_main(core::main)
}

#[no_mangle]
pub extern "C" fn ytflow_bin_exec_edit() {
    execute_main(edit::main)
}
