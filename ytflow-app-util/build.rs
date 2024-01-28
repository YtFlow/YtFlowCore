use std::env;

fn main() {
    println!("cargo:rerun-if-changed=include/ytflow_core.h");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::generate(crate_dir)
        .expect("Unable to generate bindings")
        .write_to_file("include/ytflow_core.h");
}
