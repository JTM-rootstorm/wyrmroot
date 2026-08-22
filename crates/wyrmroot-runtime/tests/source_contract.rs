use deepwyrm_syscall as _;
use wyrmroot_runtime as _;

const SOURCE: &str = concat!(
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/native.rs")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bootstrap.rs")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/startup.rs")),
);
const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));

#[test]
fn native_surface_uses_the_deepwyrm_owned_binding() {
    assert!(MANIFEST.contains("deepwyrm-syscall.workspace = true"));
    assert!(!MANIFEST.contains("deepwyrm-abi.workspace = true"));
    assert!(SOURCE.contains("deepwyrm_syscall::process_exit"));
    assert!(SOURCE.contains("deepwyrm_syscall::thread_exit"));
    assert!(SOURCE.contains("deepwyrm_syscall::channel_receive"));
    assert!(SOURCE.contains("deepwyrm_syscall::address_region_map"));
    assert!(!SOURCE.contains("DW_SYSCALL_"));
    assert!(!SOURCE.contains("global_asm!"));
    assert!(!SOURCE.contains("asm!"));
}

#[test]
fn guest_runtime_has_no_host_personality_dependency() {
    for forbidden in ["libc", "std::", "errno"] {
        assert!(
            !SOURCE.contains(forbidden),
            "found forbidden guest surface {forbidden}"
        );
        assert!(
            !MANIFEST.contains(forbidden),
            "found forbidden dependency {forbidden}"
        );
    }
}
