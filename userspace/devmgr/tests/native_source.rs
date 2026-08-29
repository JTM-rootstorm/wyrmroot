use {wyrmroot_device_proto as _, wyrmroot_devmgr as _};

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
    assert!(!NATIVE.contains("DW_OBJECT_TYPE_DEVICE_RESOURCE"));
    assert!(!NATIVE.contains("DW_OBJECT_TYPE_INTERRUPT"));
    assert!(!NATIVE.contains("pio_"));
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
