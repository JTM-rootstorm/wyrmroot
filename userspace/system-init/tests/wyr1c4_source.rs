use deepwyrm_syscall as _;
use wyrmroot_bootfs as _;
#[cfg(feature = "wyr1e-production")]
use wyrmroot_consoled as _;
use wyrmroot_device_proto as _;
use wyrmroot_devmgr as _;
use wyrmroot_launch_proto as _;
use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_registryd as _;
use wyrmroot_rrc_manifest as _;
use wyrmroot_runtime as _;
use wyrmroot_system_init as _;
use wyrmroot_uart16550d as _;
use wyrmroot_wyr1b_gate_proto as _;

const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
const MAIN_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
const NATIVE_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/wyr1c_native.rs"));
const RETAINED_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/wyr1b_native.rs"));

#[test]
fn native_wait_until_accepts_only_a_clock_verified_timeout_fallback() {
    let wait_until = &MAIN_SOURCE[MAIN_SOURCE.find("fn wait_until(").unwrap()
        ..MAIN_SOURCE
            .find("impl Wyr1BPlatform for NativeSystem")
            .unwrap()];
    assert!(wait_until.contains("DW_STATUS_TIMED_OUT"));
    assert!(wait_until.contains("monotonic_active_now()?"));
    assert!(wait_until.contains("validate_wait_until_completion("));
}

/// Every devmgr generation's TaskGroup is created under the retained
/// resource-domain custody, and the replacement loop passes that custody on.
///
/// Source text because no host fake creates an attempt TaskGroup (both
/// `RebindPlatform` and `ControlInputPlatform` refuse it), so `launch_devmgr`
/// never reaches its parentage on the host. Scoped to `launch_devmgr` and
/// `launch_devmgr_replacement`.
#[test]
fn every_c4_devmgr_generation_is_parented_under_retained_custody() {
    let launch = native_fn("launch_devmgr<");
    let parent = launch
        .find(
            "let task_group_parent = resource_domain\n        .map(ResourceDomainCustody::handle)",
        )
        .unwrap();
    let create = launch
        .find(".create_attempt_task_group(task_group_parent)")
        .unwrap();
    assert!(parent < create);
    let claim = launch
        .find("ResourceDomainMembership::DevmgrGenerationDescendant")
        .unwrap();
    let load = launch
        .find("load_device_coordinator_resource_process(")
        .unwrap();
    assert!(create < claim && claim < load);
    assert!(launch.contains("LaunchProfile::DeviceCoordinatorResourceDomain"));
    assert!(launch.contains("StatusCode::OperationalResourceOwned"));

    let replacement = native_fn("launch_devmgr_replacement<");
    let custody = replacement.find("let resource_domain = resident").unwrap();
    let call = replacement.find("launch_devmgr(").unwrap();
    assert!(custody < call);
    assert!(replacement[call..].contains("resource_domain,"));
}

/// The device manifest is materialized with transfer rights so the move can
/// stage, and the child receives it without delegation.
///
/// Source text: the rights constants and `transfer()` live in
/// wyrmroot-loader, outside this lane's paths, so their host test belongs to
/// that crate; init's own use is in `launch_devmgr`, which no host fake
/// reaches (it refuses the TaskGroup). Scoped to `launch_devmgr`.
#[test]
fn c4_manifest_move_stages_transfer_without_delegating_it() {
    assert!(
        native_fn("launch_devmgr<")
            .contains("manifest_bytes,\n            DEVICE_MANIFEST_TRANSFER_RIGHTS,")
    );
    let launch = include_str!("../../../crates/wyrmroot-loader/src/launch.rs");
    assert!(launch.contains("DwRights(DEVICE_MANIFEST_RIGHTS.0 | DW_RIGHT_TRANSFER.0)"));
    let process = include_str!("../../../crates/wyrmroot-loader/src/process.rs");
    assert!(process.contains("transfers[2] = transfer(manifest, launch::DEVICE_MANIFEST_RIGHTS);"));
}

/// Reversed by `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.3 item 2. The driver's
/// attempt TaskGroup used to be a child of the devmgr generation that
/// requested it, so tearing that generation down took the driver with it --
/// which contradicts [B] §5.4's promise that the recovery console stays usable
/// exactly when automatic reconstruction has failed. It is now parented under
/// init's own authority, and only `reap_driver`'s explicit termination by
/// handle stops it. It moves up one level, to the resource domain itself, not
/// out to init's bootstrap group: `WYR1_C_DEVICE_HANDOFF_CONTRACT.md` §4 makes
/// domain teardown terminal recovery for the boot, and a driver holding a
/// DeviceResource outside the domain would survive it.
///
/// Source text because no host fake creates an attempt TaskGroup, so
/// `construct_driver` never reaches its parentage on the host. Scoped to
/// `construct_driver`'s body.
#[test]
fn c5_driver_attempt_is_parented_under_init_not_the_devmgr_generation() {
    assert!(MANIFEST.contains("wyr1c5-production = [\"native-init\"]"));
    let construct = native_fn("construct_driver<");
    let parent = construct
        .find(".and_then(|state| state.resource_domain)")
        .unwrap();
    let create = construct
        .find("create_attempt_task_group(driver_parent)")
        .unwrap();
    let load = construct.find("load_device_driver_process(").unwrap();
    assert!(parent < create && create < load);
    // The domain's own handle, falling back to init's group only when the
    // build has no domain.
    assert!(
        construct[parent..create]
            .contains(".map_or(resident.authority.task_group, ResourceDomainCustody::handle);")
    );
    assert!(!construct[..create].contains("driver_parent = devmgr.task_group"));
}

/// The WRDM UART identity is joined to the one the retained WRRM validation
/// produced. The comparison itself is host-tested by
/// `wrdm_uart_identity_must_match_the_independent_wrrm_identity`
/// (wyr1c_native.rs); this holds which value reaches it.
///
/// Source text because `activate_in_place` is reached only from the product
/// entry, which no host fake drives. Scoped to `validate_retained_bootfs_c1`
/// and `activate_in_place`.
#[test]
fn c6_joins_wrdm_to_the_validated_retained_uart_identity() {
    let start = RETAINED_SOURCE
        .find("pub(crate) fn validate_retained_bootfs_c1(")
        .unwrap();
    let end = RETAINED_SOURCE[start..].find("\n}\n").unwrap() + start;
    let retained = &RETAINED_SOURCE[start..end];
    let identity = retained.find("let uart_identity = *manifest").unwrap();
    assert!(
        retained[identity..]
            .starts_with("let uart_identity = *manifest\n        .role(RoleId::Uart16550d)")
    );
    assert!(retained.ends_with("Ok((controller, uart_identity))"));
    let activate = native_fn("activate_in_place<");
    let validated = activate
        .find(
            "let (manifest, uart_identity) = crate::wyr1b_native::validate_retained_bootfs_c1(bootfs)?;",
        )
        .unwrap();
    let joined = activate
        .find("validate_device_identity(device_manifest, uart_identity)?;")
        .unwrap();
    assert!(validated < joined);
    assert!(!activate.contains("executable_identity(RoleId::Uart16550d)"));
}

/// The text of `fn name`, up to its closing brace at column 0.
fn native_fn(name: &str) -> &'static str {
    let start = NATIVE_SOURCE
        .find(&format!("fn {name}"))
        .unwrap_or_else(|| panic!("missing fn {name}"));
    let end = NATIVE_SOURCE[start..].find("\n}\n").unwrap() + start;
    &NATIVE_SOURCE[start..end]
}
