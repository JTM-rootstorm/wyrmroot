use deepwyrm_syscall as _;
use wyrmroot_bootfs as _;
use wyrmroot_bootstrap as _;
use wyrmroot_bootstrap_proto as _;
#[cfg(feature = "dw1d6-synthetic")]
use wyrmroot_dw1d6_device_test as _;
use wyrmroot_loader as _;
use wyrmroot_runtime as _;

const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
const MAIN_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
const LIB_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
const WYR0_COMPAT_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/wyr0_compat.rs"));
const NATIVE_ARTIFACT_INSPECTOR: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../toolchain/inspect-native-artifact.sh"
));

#[test]
fn primordial_variants_are_explicit_mutually_exclusive_test_features() {
    assert!(MANIFEST.contains("default = []"));
    for variant in [
        "primordial-blocking-cleanup",
        "primordial-user-exception",
        "primordial-invalid-return",
    ] {
        assert!(MANIFEST.contains(&format!(
            "{variant} = [\"native-bootstrap\", \"primordial-test-support\"]"
        )));
        assert!(MAIN_SOURCE.contains(&format!("feature = \"{variant}\"")));
    }
    assert!(LIB_SOURCE.contains("primordial bootstrap behavior variants are mutually exclusive"));
    assert!(
        LIB_SOURCE.contains("the WYR0-E loader-smoke integration is mutually exclusive with primordial behavior variants")
    );
    assert!(MANIFEST.contains("loader-smoke-integration = []"));
    assert!(MANIFEST.contains(
        "native-loader-smoke-integration = [\"native-bootstrap\", \"loader-smoke-integration\"]"
    ));
    for variant in [
        "i0-negative-malformed-elf",
        "i0-negative-malformed-startup",
        "i0-negative-capability-count",
        "i0-negative-capability-type",
        "i0-negative-capability-rights",
    ] {
        assert!(MANIFEST.contains(&format!("{variant} = [\"native-bootstrap\"]")));
        assert!(MAIN_SOURCE.contains(&format!("feature = \"{variant}\"")));
    }
    assert!(LIB_SOURCE.contains("I0 negative bootstrap variants are mutually exclusive"));
}

#[test]
fn production_path_stays_separate_from_test_only_hook_and_terminal_behaviors() {
    assert!(LIB_SOURCE.contains("#[cfg(feature = \"primordial-test-support\")]"));
    assert!(LIB_SOURCE.contains("pub fn run_bootstrap_with_before_ready"));
    assert!(MAIN_SOURCE.contains("run_init0_bootstrap("));
    assert!(MAIN_SOURCE.contains("run_init0_bootstrap_with_fault("));
    assert!(WYR0_COMPAT_SOURCE.contains("LoadFault::None"));
    assert!(MAIN_SOURCE.contains("primordial_blocking_cleanup(channel)"));
    assert!(MAIN_SOURCE.contains("trigger_user_exception()"));
    assert!(MAIN_SOURCE.contains("trigger_invalid_syscall_return()"));
    assert!(!MAIN_SOURCE.contains("DW_SYSCALL_"));
    assert!(!MAIN_SOURCE.contains("0x000400"));
}

#[test]
fn dw1c_bootstrap_watchdog_contains_the_selector_transaction() {
    assert!(MANIFEST.contains("dw1c-bootstrap-supervision = [\"wyr0-init0-integration\"]"));
    assert!(MAIN_SOURCE.contains("cfg!(feature = \"dw1c-bootstrap-supervision\")"));
    assert!(MAIN_SOURCE.contains("270_000_000_000"));
    assert!(MAIN_SOURCE.contains("240-second workload"));
    assert!(MAIN_SOURCE.contains("5_000_000_000"));
}

#[test]
fn d6_bootstrap_is_feature_gated_v3_and_keeps_actors_out_of_production_init() {
    assert!(MANIFEST.contains("dw1d6-synthetic = [\"native-bootstrap\""));
    assert!(MAIN_SOURCE.contains("#[cfg(feature = \"dw1d6-synthetic\")]"));
    assert!(LIB_SOURCE.contains("terminate_d6_replacement(system, replacement.process)"));
    assert!(LIB_SOURCE.contains("status == DW_STATUS_WOULD_BLOCK"));
    assert!(LIB_SOURCE.contains("D6_TERMINATE_REGISTRATION_RETRIES"));
    assert!(LIB_SOURCE.contains("BootstrapMessage::InitV3"));
    assert!(LIB_SOURCE.contains("validate_init_capabilities_v3"));
    assert!(LIB_SOURCE.contains("load_d6_resource_owner_process"));
    assert!(LIB_SOURCE.contains("LaunchProfile::Hello"));
    assert!(!LIB_SOURCE.contains("continue_system_init_product"));
}

#[test]
fn blocking_variant_does_not_import_the_ordinary_bootstrap_entry() {
    assert!(MAIN_SOURCE.contains("#[cfg(not(any("));
    assert!(MAIN_SOURCE.contains("feature = \"native-loader-smoke-integration\""));
    assert!(MAIN_SOURCE.contains("use wyrmroot_bootstrap::run_init0_bootstrap;"));
    assert!(WYR0_COMPAT_SOURCE.contains("pub fn run_init0_bootstrap"));
    assert!(WYR0_COMPAT_SOURCE.contains("profile: LaunchProfile::Init0"));
    assert!(
        !WYR0_COMPAT_SOURCE
            .contains("LaunchProfile::Hello,\n            transaction_id: INIT0_TRANSACTION_ID")
    );
}

#[test]
fn artifact_oracle_has_one_exact_invalid_return_test_tail_exception() {
    assert!(NATIVE_ARTIFACT_INSPECTOR.contains("--primordial-invalid-return-test"));
    assert!(NATIVE_ARTIFACT_INSPECTOR.contains("if [ \"$syscall_count\" -ne 1 ]"));
    assert!(NATIVE_ARTIFACT_INSPECTOR.contains("if [ \"$syscall_count\" -ne 2 ]"));
    for instruction in [
        "$0xffffffff, %eax",
        "%rdi, %rdi",
        "%rsi, %rsi",
        "%rdx, %rdx",
        "%r10, %r10",
        "%r8, %r8",
        "%r9, %r9",
        "%rsp, %rsp",
        "test_only_invalid_return_tails\":1",
    ] {
        assert!(NATIVE_ARTIFACT_INSPECTOR.contains(instruction));
    }
}
