use wyrmroot_loader::launch::{MAX_CAPABILITIES, WYRMSH_BYTES};

const LIB_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
const LAUNCH_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/launch.rs"));
const PROCESS_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/process.rs"));

#[test]
fn wyrmsh_capacity_is_widened_at_every_loader_owned_storage_site() {
    assert_eq!(MAX_CAPABILITIES, 6);
    assert_eq!(WYRMSH_BYTES, 160);
    for required in [
        "delegated_channels: [Option<DwHandle>; launch::MAX_CAPABILITIES]",
        "delegated_channels: [None; launch::MAX_CAPABILITIES]",
        "let mut init = [0_u8; launch::WYRMSH_BYTES]",
        "[DwHandleTransferV1::default(); launch::MAX_CAPABILITIES]",
        "for slot in &mut self.delegated_channels",
    ] {
        assert!(
            PROCESS_SOURCE.contains(required),
            "missing six-role loader capacity marker {required}"
        );
    }
    for stale in [
        "delegated_channels: [Option<DwHandle>; 3]",
        "delegated_channels: [None; 3]",
        "let mut init = [0_u8; launch::CONSOLED_BYTES]",
        "let mut transfers = [DwHandleTransferV1::default(); 4]",
        "self.delegated_channels[0].take()",
        "self.delegated_channels[1].take()",
        "self.delegated_channels[2].take()",
    ] {
        assert!(
            !PROCESS_SOURCE.contains(stale),
            "stale bounded-loader capacity remains: {stale}"
        );
    }
}

#[test]
fn wyrmsh_uses_a_dedicated_request_and_all_six_custody_fields() {
    for required in [
        "pub struct WyrmshLoadRequest<'a>",
        "pub struct WyrmshLoadError<PlatformError>",
        "pub fn load_wyrmsh_process<P: LoaderPlatform>",
        "stdin_consumed",
        "stdout_consumed",
        "stderr_consumed",
        "console_status_consumed",
        "registry_client_consumed",
        "launch_session_consumed",
        "profile: LaunchProfile::Wyrmsh",
        "path: PATH",
        "argv: &argv",
        "environment: &[]",
    ] {
        assert!(
            PROCESS_SOURCE.contains(required),
            "missing dedicated Wyrmsh loader marker {required}"
        );
    }
    assert!(LAUNCH_SOURCE.contains("Self::Wyrmsh => MINOR_V1_11"));
    assert!(LAUNCH_SOURCE.contains("Self::Wyrmsh => 6"));
    assert!(LIB_SOURCE.contains("#![no_std]"));
    assert!(LIB_SOURCE.contains("#![forbid(unsafe_code)]"));
}
