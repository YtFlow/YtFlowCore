fn main() {
    #[cfg_attr(windows, link(name = "ytflow_shared_lib", kind = "raw-dylib"))]
    #[cfg_attr(not(windows), link(name = "ytflow_shared_lib", kind = "dylib"))]
    extern "C" {
        fn ytflow_bin_exec_main();
    }
    unsafe {
        ytflow_bin_exec_main();
    }
}
