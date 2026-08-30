use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest path"));
    let script = manifest.join("../../toolchain/native-user.ld");
    for binary in [
        "wyrmroot-dw1d6-owner",
        "wyrmroot-dw1d6-trigger",
        "wyrmroot-dw1d6-replacement-owner",
    ] {
        println!("cargo:rustc-link-arg-bin={binary}=-T{}", script.display());
        println!("cargo:rustc-link-arg-bin={binary}=--build-id=none");
    }
    println!("cargo:rerun-if-env-changed=DEEPWYRM_DW1D6_BUILD_NONCE");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_DW1D6_BUILD_CHALLENGE");
}
