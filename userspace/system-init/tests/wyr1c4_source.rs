use deepwyrm_syscall as _;
use wyrmroot_bootfs as _;
use wyrmroot_device_proto as _;
use wyrmroot_launch_proto as _;
use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_rrc_manifest as _;
use wyrmroot_runtime as _;
use wyrmroot_system_init as _;
use wyrmroot_wyr1b_gate_proto as _;

const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
const LIB_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
const MAIN_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
const NATIVE_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/wyr1c_native.rs"));
const RETAINED_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/wyr1b_native.rs"));

#[test]
fn c4_product_selects_only_the_four_capability_resource_profile() {
    assert!(MANIFEST.contains("wyr1c4-production = [\"native-init\"]"));
    assert!(MAIN_SOURCE.contains("continue_system_init_resource_product"));
    assert!(LIB_SOURCE.contains("pub fn continue_system_init_resource_product"));
    assert!(LIB_SOURCE.contains("let mut handles = [DwReceivedHandleInfoV1::default(); 4]"));
    assert!(LIB_SOURCE.contains("LaunchProfile::SupervisorResourceDomain"));
    assert!(LIB_SOURCE.contains("ResourceDomainCustody::new(handles[3].handle)"));
    assert!(LIB_SOURCE.contains("LaunchProfile::Supervisor,"));
}

#[test]
fn c6_feature_composition_keeps_selector_29_on_the_resource_profile() {
    assert!(MANIFEST.contains("wyr1c6-production = [\"wyr1c5-production\"]"));
    assert!(
        MANIFEST.contains("wyr1c6-selector29 = [\"wyr1c6-production\", \"wyr1c6-test-evidence\"]")
    );
    assert!(
        MAIN_SOURCE.contains(
            "#[cfg(any(feature = \"wyr1c4-production\", feature = \"wyr1c5-production\"))]"
        )
    );
    assert!(MAIN_SOURCE.contains("continue_system_init_resource_product("));
}

#[test]
fn every_c4_devmgr_generation_is_parented_under_retained_custody() {
    assert!(NATIVE_SOURCE.contains(".map(ResourceDomainCustody::handle)"));
    assert!(NATIVE_SOURCE.contains(".create_attempt_task_group(task_group_parent)"));
    assert!(NATIVE_SOURCE.contains("load_device_coordinator_resource_process("));
    assert!(NATIVE_SOURCE.contains("ResourceDomainMembership::DevmgrGenerationDescendant"));
    assert!(NATIVE_SOURCE.contains("LaunchProfile::DeviceCoordinatorResourceDomain"));
    assert!(NATIVE_SOURCE.contains("StatusCode::OperationalResourceOwned"));

    let replacement = NATIVE_SOURCE
        .split("fn launch_devmgr_replacement")
        .nth(1)
        .expect("devmgr replacement loop");
    assert!(replacement.contains("let resource_domain = resident"));
    assert!(replacement.contains("launch_devmgr("));
    assert!(replacement.contains("resource_domain,"));
}

#[test]
fn c4_manifest_move_stages_transfer_without_delegating_it() {
    assert!(NATIVE_SOURCE.contains("DEVICE_MANIFEST_TRANSFER_RIGHTS"));
    assert!(
        NATIVE_SOURCE.contains("manifest_bytes,\n            DEVICE_MANIFEST_TRANSFER_RIGHTS,")
    );
    let launch = include_str!("../../../crates/wyrmroot-loader/src/launch.rs");
    assert!(launch.contains("DwRights(DEVICE_MANIFEST_RIGHTS.0 | DW_RIGHT_TRANSFER.0)"));
    let process = include_str!("../../../crates/wyrmroot-loader/src/process.rs");
    assert!(process.contains("transfers[2] = transfer(manifest, launch::DEVICE_MANIFEST_RIGHTS);"));
}

#[test]
fn c5_driver_attempt_is_parented_under_the_current_devmgr_generation() {
    assert!(MANIFEST.contains("wyr1c5-production = [\"native-init\"]"));
    let construct = &NATIVE_SOURCE[NATIVE_SOURCE.find("fn construct_driver").unwrap()..];
    let parent = construct
        .find("let driver_parent = devmgr.task_group")
        .unwrap();
    let create = construct
        .find("create_attempt_task_group(driver_parent)")
        .unwrap();
    let load = construct.find("load_device_driver_process(").unwrap();
    assert!(parent < create && create < load);
    assert!(construct.contains("#[cfg(feature = \"wyr1c5-production\")]"));
}

#[test]
fn c6_terminal_facts_are_init_owned_and_bound_to_real_predicates() {
    let devmgr = include_str!("../../devmgr/src/main.rs");
    assert!(NATIVE_SOURCE.contains("emit_c6_terminal_facts(resident)"));
    assert!(!devmgr.contains("emit_selector29_final_facts"));
    assert!(NATIVE_SOURCE.contains("c6_startup_profiles_exclude_direct_device_authority"));
    assert!(NATIVE_SOURCE.contains("ResourceDomainMembership::InitOutsideDomain"));
    assert!(NATIVE_SOURCE.contains("physical_io_not_performed"));
    assert!(NATIVE_SOURCE.contains("role_failure_count(RoleId::Devmgr)"));
    assert!(NATIVE_SOURCE.contains("WYR0_I_SUPERVISION_POLICY.max_attempts"));
    assert!(NATIVE_SOURCE.contains("WYR0_I_SUPERVISION_POLICY.backoff_ns"));
}

#[test]
fn c6_joins_wrdm_to_the_validated_retained_uart_identity() {
    assert!(RETAINED_SOURCE.contains("let uart_identity = *manifest"));
    assert!(RETAINED_SOURCE.contains(".role(RoleId::Uart16550d)"));
    assert!(RETAINED_SOURCE.contains("Ok((controller, uart_identity))"));
    assert!(NATIVE_SOURCE.contains(
        "let (manifest, uart_identity) = crate::wyr1b_native::validate_retained_bootfs_c1(bootfs)?;"
    ));
    assert!(NATIVE_SOURCE.contains("validate_device_identity(device_manifest, uart_identity)?;"));
    assert!(!NATIVE_SOURCE.contains("manifest.executable_identity(RoleId::Uart16550d)"));
}
