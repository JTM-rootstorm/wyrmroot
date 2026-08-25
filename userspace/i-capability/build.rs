use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest path"));
    let script = manifest.join("../../toolchain/native-user.ld");
    println!("cargo:rerun-if-changed={}", script.display());
    println!(
        "cargo:rustc-link-arg-bin=wyrmroot-i-capability=-T{}",
        script.display()
    );
    println!("cargo:rustc-link-arg-bin=wyrmroot-i-capability=--build-id=none");
}
