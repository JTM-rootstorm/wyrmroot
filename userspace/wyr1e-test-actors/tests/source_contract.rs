use std::fs;
use std::path::PathBuf;

use deepwyrm_syscall as _;
use wyrmroot_loader as _;
use wyrmroot_runtime as _;
use wyrmroot_wyr1e_test_actors as _;

#[test]
fn binaries_use_canonical_linker_and_exact_paths() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let build = fs::read_to_string(root.join("build.rs")).unwrap();
    assert!(build.contains("../../toolchain/native-user.ld"));
    assert!(build.contains("wyrmroot-wyr1e-exit-nonzero"));
    assert!(build.contains("wyrmroot-wyr1e-fault"));
    let library = fs::read_to_string(root.join("src/lib.rs")).unwrap();
    assert!(library.contains("test/wyr1-e/exit-nonzero"));
    assert!(library.contains("test/wyr1-e/fault"));
    assert!(library.contains("LaunchProfile::JobV2Streams"));
}

#[test]
fn fault_instruction_is_narrow_and_other_actor_sources_forbid_unsafe() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fault = fs::read_to_string(root.join("src/bin/fault.rs")).unwrap();
    let exit = fs::read_to_string(root.join("src/bin/exit_nonzero.rs")).unwrap();
    let library = fs::read_to_string(root.join("src/lib.rs")).unwrap();
    assert_eq!(fault.matches("unsafe {").count(), 1);
    assert!(fault.contains("core::arch::asm!(\"ud2\""));
    assert!(fault.contains("options(noreturn, nostack, nomem)"));
    assert!(!exit.contains("unsafe {"));
    assert!(library.contains("#![forbid(unsafe_code)]"));
}

#[test]
fn actors_have_no_privileged_or_test_evidence_calls() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for path in ["src/lib.rs", "src/bin/exit_nonzero.rs", "src/bin/fault.rs"] {
        let source = fs::read_to_string(root.join(path)).unwrap();
        for forbidden in [
            "submit_",
            "device_",
            "resource_domain",
            "SelfRoot",
            "PublicationAuthority",
            "DW_SYSCALL_TEST",
        ] {
            assert!(!source.contains(forbidden), "{path} contains {forbidden}");
        }
    }
}
