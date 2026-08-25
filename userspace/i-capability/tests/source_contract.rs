use deepwyrm_syscall as _;
use wyrmroot_bootfs as _;
use wyrmroot_i_capability as _;
use wyrmroot_loader as _;
use wyrmroot_runtime as _;

const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
const CONTENT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/content.rs"));
const EVIDENCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/evidence.rs"));
const NATIVE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/native.rs"));

#[test]
fn payload_remains_freestanding_generated_abi_only_and_profile_bound() {
    assert!(MANIFEST.contains("license = \"GPL-3.0-or-later\""));
    for required in [
        "BOOTSTRAP_CHANNEL_EXPECTATION",
        "validate_bootstrap_channel",
        "LaunchProfile::CapabilityController",
        "LaunchProfile::ProbeChild",
        "encode_ready_for_profile(LaunchProfile::ProbeChild",
        "parse_ready_for_profile(profile",
        "wyrmroot_runtime::PAGE_SIZE",
        "DW_STATUS_WOULD_BLOCK",
        "DW_STATUS_PEER_CLOSED",
        "DW_TERMINATION_AUTHORIZED",
    ] {
        assert!(
            NATIVE.contains(required),
            "missing native proof marker {required}"
        );
    }
    for forbidden in [
        "std::",
        "alloc::",
        "libc",
        "DW_SYSCALL_",
        "dw_syscall6",
        "unsafe {",
        "asm!",
        "global_asm!",
    ] {
        assert!(
            !NATIVE.contains(forbidden),
            "payload imported forbidden native boundary {forbidden}"
        );
    }
}

#[test]
fn selector_content_and_wrcap1_framing_are_exactly_owned() {
    for required in [
        "test/wyr0-i/config.toml",
        "test/wyr0-i/asset.bin",
        "schema_version = 1",
        r#"selector = \"native-userspace-capability\""#,
        "test_id = 24",
        r#"evidence_protocol = \"wrcap1\""#,
    ] {
        assert!(
            CONTENT.contains(required),
            "missing content contract {required}"
        );
    }
    for required in [
        "WRCAP1|01|",
        "WRCAP1_RECORD_BYTES: usize = 117",
        "WRCAP1_EVENT_COUNT: usize = 15",
        "REQUIRED_CAPABILITY_MASK: u16 = (1 << 10) - 1",
        "fnv1a32(&output[..108])",
        "EvidenceKind::CleanupBaseline",
    ] {
        assert!(
            EVIDENCE.contains(required),
            "missing evidence contract {required}"
        );
    }
}
