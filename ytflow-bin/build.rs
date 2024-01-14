fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        println!("cargo:rustc-link-lib=dylib=ytflow_bin_shared.dll");
    } else {
        println!("cargo:rustc-link-lib=dylib=ytflow_bin_shared");
    }
    println!(
        "cargo:rustc-link-search={}",
        std::env::var("CARGO_CDYLIB_DIR_YTFLOW_BIN_SHARED").unwrap()
    );
    println!("cargo:rerun-if-changed=build.rs");
}
