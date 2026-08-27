use std::path::PathBuf;
fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest path"));
    let script = manifest.join("../../toolchain/native-user.ld");
    for token in 1..=10 { println!("cargo:rustc-link-arg-bin=wyrmroot-dw1c-actor{token}=-T{}", script.display()); println!("cargo:rustc-link-arg-bin=wyrmroot-dw1c-actor{token}=--build-id=none"); }
}
