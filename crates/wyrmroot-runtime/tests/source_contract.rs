use deepwyrm_syscall as _;
use wyrmroot_loader as _;
use wyrmroot_runtime as _;

const SOURCE: &str = concat!(
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/native.rs")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/loader_native.rs")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bootstrap.rs")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/startup.rs")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/supervision.rs")),
);
const NATIVE_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/native.rs"));
const LOADER_NATIVE_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/loader_native.rs"));
const STARTUP_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/startup.rs"));
const ENTRY_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/entry.rs"));
const MEMORY_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/memory.rs"));
const TEST_SUPPORT_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/test_support.rs"));
const SUPERVISION_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/supervision.rs"));
const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));

#[test]
fn native_surface_uses_the_deepwyrm_owned_binding() {
    assert!(MANIFEST.contains("deepwyrm-syscall.workspace = true"));
    assert!(!MANIFEST.contains("deepwyrm-abi.workspace = true"));
    assert!(SOURCE.contains("deepwyrm_syscall::process_exit"));
    assert!(SOURCE.contains("deepwyrm_syscall::thread_exit"));
    assert!(SOURCE.contains("deepwyrm_syscall::channel_receive"));
    assert!(SOURCE.contains("deepwyrm_syscall::wait_many"));
    assert!(SOURCE.contains("deepwyrm_syscall::object_get_task_state_v1"));
    assert!(SOURCE.contains("deepwyrm_syscall::address_region_map"));
    assert!(NATIVE_SOURCE.contains("DW_SYSCALL_CLOCK_GET"));
    assert!(!NATIVE_SOURCE.contains("DW_SYSCALL_WAIT_"));
    assert!(!SOURCE.contains("global_asm!"));
    assert!(!SOURCE.contains("asm!"));
}

#[test]
fn supervision_stays_bounded_and_uses_structured_process_exit() {
    assert!(SUPERVISION_SOURCE.contains("DW_DEADLINE_INFINITE"));
    assert!(SUPERVISION_SOURCE.contains("DW_SIGNAL_READABLE"));
    assert!(SUPERVISION_SOURCE.contains("DW_SIGNAL_PEER_CLOSED"));
    assert!(SUPERVISION_SOURCE.contains("DW_SIGNAL_EXITED"));
    assert!(SUPERVISION_SOURCE.contains("validate_successful_exit"));
    assert!(SUPERVISION_SOURCE.contains("DW_TERMINATION_NORMAL_EXIT"));
    assert!(!SUPERVISION_SOURCE.contains("DW_SYSCALL_"));
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

#[test]
fn runtime_unsafe_is_confined_to_the_validated_bootfs_slice_and_clock_boundaries() {
    assert_eq!(NATIVE_SOURCE.matches("unsafe {").count(), 2);
    assert!(NATIVE_SOURCE.contains("core::slice::from_raw_parts"));
    assert!(NATIVE_SOURCE.contains("fn raw_clock_get"));
    assert!(NATIVE_SOURCE.contains("fn dw_syscall6("));
    assert!(!NATIVE_SOURCE.contains("unsafe fn"));
    assert!(!NATIVE_SOURCE.contains("from_raw_parts_mut"));
}

#[test]
fn loader_unsafe_is_confined_to_the_temporary_writable_mapping() {
    assert_eq!(LOADER_NATIVE_SOURCE.matches("unsafe {").count(), 1);
    assert!(LOADER_NATIVE_SOURCE.contains("core::slice::from_raw_parts_mut"));
    assert!(LOADER_NATIVE_SOURCE.contains("address_region_unmap"));
    assert!(!LOADER_NATIVE_SOURCE.contains("unsafe fn"));
}

#[test]
fn startup_unsafe_is_confined_to_the_initial_stack_slice_boundary() {
    assert_eq!(STARTUP_SOURCE.matches("unsafe {").count(), 2);
    assert!(STARTUP_SOURCE.contains("pub unsafe fn with_native_startup"));
    assert!(STARTUP_SOURCE.contains("core::slice::from_raw_parts"));
    assert!(!STARTUP_SOURCE.contains("from_raw_parts_mut"));
}

#[test]
fn freestanding_memory_symbols_are_target_only_and_do_not_delegate_to_libc() {
    for symbol in ["memcpy", "memmove", "memset", "memcmp"] {
        assert!(MEMORY_SOURCE.contains(&format!("fn {symbol}(")));
    }
    assert!(SOURCE.contains("cfg(target_os = \"wyrmroot\")"));
    assert!(!MEMORY_SOURCE.contains("extern \"C\" {"));
    assert!(!MEMORY_SOURCE.contains("libc"));
    assert!(!MEMORY_SOURCE.contains("copy_nonoverlapping"));
    assert!(!MEMORY_SOURCE.contains("ptr::copy("));
    assert!(!MEMORY_SOURCE.contains("write_bytes"));
}

#[test]
fn shared_native_entry_owns_startup_assembly_but_not_syscall_assembly() {
    assert!(ENTRY_SOURCE.contains("global_asm!"));
    assert!(ENTRY_SOURCE.contains("movq %rsp, %rdx"));
    assert!(ENTRY_SOURCE.contains("with_native_startup"));
    assert!(!ENTRY_SOURCE.contains("syscall"));
    assert!(!ENTRY_SOURCE.contains("DW_SYSCALL_"));
}

#[test]
fn primordial_test_support_uses_generated_ids_and_is_feature_isolated() {
    assert!(MANIFEST.contains("primordial-test-support = []"));
    for generated_id in [
        "DW_SYSCALL_CLOCK_GET",
        "DW_SYSCALL_WAIT_ONE",
        "DW_SYSCALL_ATOMIC_WAIT32",
    ] {
        assert!(TEST_SUPPORT_SOURCE.contains(generated_id));
    }
    assert!(TEST_SUPPORT_SOURCE.contains("fn dw_syscall6("));
    assert!(TEST_SUPPORT_SOURCE.contains("DwSyscallId(u32::MAX)"));
    assert!(TEST_SUPPORT_SOURCE.contains("\"xor rsp, rsp\""));
    assert!(TEST_SUPPORT_SOURCE.contains("\"syscall\""));
    assert!(!TEST_SUPPORT_SOURCE.contains("0x000400"));
    assert!(!TEST_SUPPORT_SOURCE.contains("libc"));
    assert!(!TEST_SUPPORT_SOURCE.contains("std::"));
}
