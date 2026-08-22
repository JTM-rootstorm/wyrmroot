use deepwyrm_syscall as _;
use wyrmroot_bootfs as _;
use wyrmroot_bootstrap as _;
use wyrmroot_bootstrap_proto as _;
use wyrmroot_runtime as _;

const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
const MAIN_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
const LIB_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
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
    assert!(LIB_SOURCE.contains("primordial bootstrap test variants are mutually exclusive"));
}

#[test]
fn production_path_stays_separate_from_test_only_hook_and_terminal_behaviors() {
    assert!(LIB_SOURCE.contains("#[cfg(feature = \"primordial-test-support\")]"));
    assert!(LIB_SOURCE.contains("pub fn run_bootstrap_with_before_ready"));
    assert!(MAIN_SOURCE.contains("run_bootstrap(&mut system"));
    assert!(MAIN_SOURCE.contains("primordial_blocking_cleanup(channel)"));
    assert!(MAIN_SOURCE.contains("trigger_user_exception()"));
    assert!(MAIN_SOURCE.contains("trigger_invalid_syscall_return()"));
    assert!(!MAIN_SOURCE.contains("DW_SYSCALL_"));
    assert!(!MAIN_SOURCE.contains("0x000400"));
}

#[test]
fn blocking_variant_does_not_import_the_ordinary_bootstrap_entry() {
    assert!(MAIN_SOURCE.contains("#[cfg(not(feature = \"primordial-blocking-cleanup\"))]"));
    assert!(MAIN_SOURCE.contains("use wyrmroot_bootstrap::run_bootstrap;"));
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
