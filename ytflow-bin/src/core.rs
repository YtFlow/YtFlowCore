fn main() {
    extern "C" {
        fn ytflow_bin_exec_core();
    }
    unsafe {
        ytflow_bin_exec_core();
    }
}
