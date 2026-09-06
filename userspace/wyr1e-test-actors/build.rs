use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest path"));
    let script = manifest.join("../../toolchain/native-user.ld");
    println!("cargo:rerun-if-changed={}", script.display());
    for binary in ["wyrmroot-wyr1e-exit-nonzero", "wyrmroot-wyr1e-fault"] {
        println!("cargo:rustc-link-arg-bin={binary}=-T{}", script.display());
        println!("cargo:rustc-link-arg-bin={binary}=--build-id=none");
    }
}
