fn main() {
    // Ensure Cargo reruns this script when inputs change
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src");

    // Generate C header with cbindgen into include/tfhe_enc.h
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = std::path::Path::new(&crate_dir).join("include");
    std::fs::create_dir_all(&out_dir).unwrap();
    let header_path = out_dir.join("tfhe_enc.h");

    match cbindgen::generate(&crate_dir) {
        Ok(builder) => {
            builder.write_to_file(header_path);
        }
        Err(err) => {
            // Fail the build if header generation fails to avoid stale headers.
            panic!("cbindgen generate failed: {}", err);
        }
    }
}
