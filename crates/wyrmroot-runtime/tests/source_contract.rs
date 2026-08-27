use deepwyrm_syscall as _;
use wyrmroot_loader as _;
use wyrmroot_runtime as _;

const SOURCE: &str = concat!(
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/native.rs")),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/capability_native.rs"
    )),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/loader_native.rs")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bootstrap.rs")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/startup.rs")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/supervision.rs")),
);
const NATIVE_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/native.rs"));
const CAPABILITY_NATIVE_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/capability_native.rs"
));
const LOADER_NATIVE_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/loader_native.rs"));
const STARTUP_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/startup.rs"));
const ENTRY_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/entry.rs"));
const MEMORY_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/memory.rs"));
const TEST_SUPPORT_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/test_support.rs"));
const SUPERVISION_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/supervision.rs"));
const RESTART_SUPERVISION_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/supervision/restart.rs"
));
const BOUNDED_ACCOUNTING_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bounded_accounting.rs"
));
const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
const PRIMORDIAL_STARTUP_CONTRACT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../Plans/WYR0_D0_PRIMORDIAL_STARTUP_CONTRACT.md"
));
const CHILD_LOADING_CONTRACT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../Plans/WYR0_E0_USERSPACE_PROCESS_LOADING_CONTRACT.md"
));
const WYR1B_CONTRACT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../Plans/WYR1_B_REGISTRY_LAUNCH_CONTRACT.md"
));

#[test]
fn coordinated_primordial_and_child_stack_targets_remain_separately_owned() {
    assert!(PRIMORDIAL_STARTUP_CONTRACT.contains("Deepwyrm maps 128 KiB RW/NX"));
    assert!(PRIMORDIAL_STARTUP_CONTRACT.contains("leaving 124 KiB"));
    assert!(!PRIMORDIAL_STARTUP_CONTRACT.contains("Deepwyrm maps 64 KiB RW/NX"));
    assert!(CHILD_LOADING_CONTRACT.contains("primordial stack target is also 128 KiB"));
    assert!(WYR1B_CONTRACT.contains("production primordial stack\ntarget is also 128 KiB"));
    assert!(CHILD_LOADING_CONTRACT.contains("implementation ownership"));
    assert!(WYR1B_CONTRACT.contains("ownership remains separate"));
}

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
    assert!(SOURCE.contains("deepwyrm_syscall::clock_get"));
    assert!(!NATIVE_SOURCE.contains("DW_SYSCALL_CLOCK_GET"));
    assert!(!NATIVE_SOURCE.contains("DW_SYSCALL_WAIT_"));
    assert!(!SOURCE.contains("global_asm!"));
    assert!(!SOURCE.contains("asm!"));
}

#[test]
fn capability_wrappers_use_generated_ids_at_one_audited_raw_boundary() {
    for required in [
        "DW_SYSCALL_TASK_GROUP_CREATE",
        "DW_SYSCALL_EVENT_CREATE",
        "DW_SYSCALL_EVENT_SIGNAL",
        "DW_SYSCALL_TIMER_CREATE",
        "DW_SYSCALL_TIMER_SET",
        "DW_SYSCALL_TIMER_CANCEL",
        "mod raw",
        "SAFETY:",
    ] {
        assert!(
            CAPABILITY_NATIVE_SOURCE.contains(required),
            "missing native capability-wrapper boundary marker {required}"
        );
    }
    for forbidden in [
        "0x0001_0001",
        "0x0001_0002",
        "0x0004_0010",
        "0x0004_0011",
        "0x0005_0010",
        "0x0005_0011",
        "0x0005_0012",
        "global_asm!",
        "asm!",
        "std::",
        "libc",
    ] {
        assert!(
            !CAPABILITY_NATIVE_SOURCE.contains(forbidden),
            "capability wrapper copied or imported forbidden boundary {forbidden}"
        );
    }
}

#[test]
fn mapped_byte_views_require_explicit_unsafe_acknowledgement() {
    for required in [
        "pub unsafe fn with_bytes_mut",
        "pub unsafe fn with_bytes",
        "impl for<'bytes> FnOnce(&'bytes mut [u8])",
        "impl for<'bytes> FnOnce(&'bytes [u8])",
        "Deepwyrm permits multiple virtual mappings",
        "```compile_fail",
    ] {
        assert!(
            CAPABILITY_NATIVE_SOURCE.contains(required),
            "missing mapped-view safety contract {required}"
        );
    }
    assert!(!CAPABILITY_NATIVE_SOURCE.contains("pub fn with_bytes_mut"));
    assert!(!CAPABILITY_NATIVE_SOURCE.contains("pub fn with_bytes<R>"));
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
fn restart_supervision_is_finite_generation_safe_native_policy() {
    for required in [
        "WYR0_I_SUPERVISION_POLICY",
        "max_attempts: 4",
        "backoff_ns: 25_000_000",
        "restart_window_ns: 2_000_000_000",
        "ready_timeout_ns: 1_000_000_000",
        "cleanup_timeout_ns: 1_000_000_000",
        "RestartState::PermanentFailure",
        "CleanupAction::TerminateTaskGroup",
        "checked_add",
    ] {
        assert!(
            RESTART_SUPERVISION_SOURCE.contains(required),
            "missing restart-supervision contract marker {required}"
        );
    }
    for forbidden in ["std::", "libc", "signal(", "filesystem", "service registry"] {
        assert!(
            !RESTART_SUPERVISION_SOURCE.contains(forbidden),
            "restart supervision imported forbidden service-manager surface {forbidden}"
        );
    }
}

#[test]
fn readiness_accounting_is_fixed_generated_and_truthfully_scoped() {
    for required in [
        "DW_CHANNEL_MAX_PAYLOAD",
        "DW_CHANNEL_MAX_HANDLES",
        "EnforcementClass::Kernel",
        "EnforcementClass::Wyrmroot",
        "EnforcementClass::Future",
        "CleanupDisposition::Complete",
        "TerminalRecordMissing",
        "OutstandingGenerationResource",
        "checked_add",
        "checked_sub",
        "[PeerAccounting; MAX_ACCOUNTED_PEERS]",
        "[u64; MAX_LIVE_TRANSACTIONS_PER_PEER]",
        "[u64; MAX_REPLAY_ENTRIES_PER_PEER]",
    ] {
        assert!(
            BOUNDED_ACCOUNTING_SOURCE.contains(required),
            "missing bounded-accounting contract marker {required}"
        );
    }
    for forbidden in [
        "Vec<", "VecDeque", "HashMap", "BTreeMap", "alloc::", "std::",
    ] {
        assert!(
            !BOUNDED_ACCOUNTING_SOURCE.contains(forbidden),
            "bounded accounting imported dynamic surface {forbidden}"
        );
    }
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
fn runtime_unsafe_is_confined_to_the_validated_bootfs_slice_boundary() {
    assert_eq!(NATIVE_SOURCE.matches("unsafe {").count(), 1);
    assert!(NATIVE_SOURCE.contains("core::slice::from_raw_parts"));
    assert!(!NATIVE_SOURCE.contains("fn raw_clock_get"));
    assert!(!NATIVE_SOURCE.contains("fn dw_syscall6("));
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

#[test]
fn wyr1b_evidence_raw_call_is_exact_and_feature_isolated() {
    assert!(MANIFEST.contains("wyr1b-test-evidence = []"));
    for required in [
        "#[cfg(feature = \"wyr1b-test-evidence\")]",
        "DwSyscallId(0xffff_ff1b)",
        "pub const WYR1B_EVIDENCE_RECORD_BYTES: usize = 96",
        "pub fn submit_wyr1b_evidence",
        "record.as_ptr() as u64",
        "WYR1B_EVIDENCE_RECORD_BYTES as u64",
    ] {
        assert!(
            CAPABILITY_NATIVE_SOURCE.contains(required),
            "missing selector-27 evidence boundary marker {required}"
        );
    }
    assert!(SOURCE.contains("submit_wyr1b_evidence"));
    assert!(CAPABILITY_NATIVE_SOURCE.contains("DwSyscallId(0xffff_ff19)"));
    assert!(CAPABILITY_NATIVE_SOURCE.contains("DwSyscallId(0xFFFF_FF1A)"));
}

#[test]
fn dw1c_private_veneer_has_only_the_three_frozen_operation_shapes() {
    assert!(MANIFEST.contains("dw1c-test-evidence = []"));
    for required in [
        "DwSyscallId(0xFFFF_FF1C)",
        "pub const DW1C_ACTOR_COUNT: usize = 10",
        "bindings.as_ptr() as u64",
        "DW1C_ACTOR_COUNT as u64",
        "240,",
        "[2, token, count, digest, 0, 0]",
        "[3, 0x1f, digest, 0, 0, 0]",
    ] {
        assert!(
            CAPABILITY_NATIVE_SOURCE.contains(required),
            "missing DW1-C marker {required}"
        );
    }
    assert!(SOURCE.contains("submit_dw1c_workload_complete"));
    assert!(!NATIVE_SOURCE.contains("FFFF_FF1C"));
}
