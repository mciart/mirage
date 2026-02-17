use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let output_file = PathBuf::from(&crate_dir)
        .join("include")
        .join("mirage_ffi.h");

    // Ensure the include directory exists
    std::fs::create_dir_all(PathBuf::from(&crate_dir).join("include"))
        .expect("Failed to create include directory");

    let config = cbindgen::Config::from_file("cbindgen.toml")
        .unwrap_or_else(|_| cbindgen::Config::default());

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(output_file);
}
