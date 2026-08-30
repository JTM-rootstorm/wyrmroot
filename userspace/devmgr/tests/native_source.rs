use {wyrmroot_device_proto as _, wyrmroot_devmgr as _};

use deepwyrm_syscall as _;

const NATIVE: &str = include_str!("../src/main.rs");

#[test]
fn native_path_validates_manifest_before_ready_then_enters_bounded_controller_loop() {
    let run = &NATIVE[NATIVE.find("fn run(").unwrap()..];
    let parse = run.find("parse_device_coordinator_init").unwrap();
    let map = run.find("map_bootfs_read_only").unwrap();
    let prepare = run.find("prepare_operational").unwrap();
    let resident = run.find("ResidentController::new").unwrap();
    let ready = run.find("encode_ready_for_profile").unwrap();
    let wait = run.find("wait_many(&waits[..wait_count]").unwrap();
    assert!(parse < map);
    assert!(map < prepare);
    assert!(prepare < resident);
    assert!(resident < ready);
    assert!(ready < wait);
}

#[test]
fn native_path_keeps_the_c3_launch_surface_hardware_free() {
    assert!(NATIVE.contains("LaunchProfile::DeviceCoordinator"));
    assert!(NATIVE.contains("DEVICE_MANIFEST_RIGHTS"));
    assert!(NATIVE.contains("DW_OBJECT_TYPE_MEMORY_OBJECT"));
    assert!(NATIVE.contains("send_channel(bootstrap, &ready[..ready_len], &[])"));
    assert!(NATIVE.contains("issue_driver_launch"));
    assert!(NATIVE.contains("parse_constructed"));
    assert!(NATIVE.contains("accept_driver_control_ready"));
    assert!(NATIVE.contains("requested_rights: CHILD_CHANNEL_RIGHTS"));
    assert!(!NATIVE.contains("DW_OBJECT_TYPE_INTERRUPT"));
    assert!(!NATIVE.contains("pio_"));
}

#[test]
fn c4_claim_path_is_feature_gated_exact_and_stops_before_interrupt_creation() {
    assert!(NATIVE.contains("#[cfg(feature = \"wyr1c4-production\")]"));
    assert!(NATIVE.contains("parse_device_coordinator_resource_init"));
    assert!(NATIVE.contains("RESOURCE_DOMAIN_CLAIM_RIGHTS"));
    assert!(NATIVE.contains("require_device_resource_interrupt_feature"));
    assert!(NATIVE.contains("claim_device_resource("));
    assert!(NATIVE.contains("DEVICE_RESOURCE_CUSTODY_RIGHTS"));
    assert!(NATIVE.contains("device_resource_info(resource)"));
    assert!(NATIVE.contains("admit_device_resource(info)"));
    assert!(NATIVE.contains("StatusCode::OperationalResourceOwned"));
    let c4 = &NATIVE[NATIVE
        .find("if action == ControllerAction::InitialPublicationBound")
        .expect("C4 initial binding")..];
    let feature = c4
        .find("require_device_resource_interrupt_feature")
        .expect("ABI feature gate");
    let claim = c4.find("claim_device_resource(").expect("resource claim");
    let owned = c4
        .find("_device_resource = Some(resource)")
        .expect("tracked ownership");
    let metadata = c4
        .find("device_resource_info(resource)")
        .expect("typed resource metadata");
    let retire_domain = c4
        .find("if close_handle(domain).is_err()")
        .expect("domain retirement");
    let status = c4
        .find("send_resident_status(bootstrap, &resident, status)")
        .expect("resource-owned status");
    assert!(feature < claim && claim < owned && owned < metadata);
    assert!(metadata < retire_domain && retire_domain < status);
    assert!(c4.contains("close_optional(_device_resource.take())"));
    assert!(NATIVE.contains(
        "#[cfg(not(feature = \"wyr1c4-production\"))]\n            if action == ControllerAction::InitialPublicationBound"
    ));
    assert!(!NATIVE.contains("create_interrupt("));
    assert!(!NATIVE.contains("DW_OBJECT_TYPE_INTERRUPT"));
}

#[test]
fn c3_construction_and_control_ready_share_one_finite_deadline() {
    let launch = &NATIVE[NATIVE.find("fn launch_driver(").unwrap()..];
    let launch = &launch[..launch.find("fn wait_readable(").unwrap()];
    let deadline = launch.find("monotonic_deadline_after").unwrap();
    let ack_wait = launch.find("wait_readable(bootstrap, deadline").unwrap();
    let direct_wait = launch.find("wait_readable(retained, deadline").unwrap();
    assert!(deadline < ack_wait);
    assert!(ack_wait < direct_wait);
    assert!(launch.contains("WYR0_I_SUPERVISION_POLICY.ready_timeout_ns"));
    assert!(!launch.contains("DW_DEADLINE_INFINITE"));
}

#[test]
fn registry_peer_close_preserves_generation_and_uses_explicit_rebind() {
    let replacement = NATIVE
        .find("Registry replacement closes only the old publication binding")
        .unwrap();
    let tail = &NATIVE[replacement..];
    let close_publication = tail.find("close_handle(old)").unwrap();
    let peer_closed = tail.find("publication_peer_closed").unwrap();
    let report = tail.find("OperationalWaitingForRegistry").unwrap();
    assert!(close_publication < peer_closed);
    assert!(peer_closed < report);
    assert!(NATIVE.contains("parse_controller"));
    assert!(NATIVE.contains("RebindPublication"));
    assert!(NATIVE.contains("validate_fresh(\n                    handles[0].handle,"));
    assert!(NATIVE.contains(
        "close_optional(publication);\n                    close_optional(driver_control);\n                    let _ = close_handle(bootstrap);"
    ));
}
