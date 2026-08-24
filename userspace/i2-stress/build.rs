fn main() {
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../toolchain/native-user.ld");
    println!(
        "cargo:rustc-link-arg-bin=wyrmroot-i2-stress=-T{}",
        script.display()
    );
    println!("cargo:rustc-link-arg-bin=wyrmroot-i2-stress=--build-id=none");
}
