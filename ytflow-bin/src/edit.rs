fn main() {
    extern "C" {
        fn ytflow_bin_exec_edit();
    }
    unsafe {
        ytflow_bin_exec_edit();
    }
}
