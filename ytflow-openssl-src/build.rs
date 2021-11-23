fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    openssl_src::Build::new().build().print_cargo_metadata();
}
