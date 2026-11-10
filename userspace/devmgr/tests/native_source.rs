#[cfg(feature = "native-devmgr")]
use {wyrmroot_loader as _, wyrmroot_registry_proto as _, wyrmroot_runtime as _};

use {wyrmroot_device_proto as _, wyrmroot_devmgr as _};

use deepwyrm_syscall as _;

/// devmgr's role logic, in its original order: the binary's entry file, then
/// `role.rs`, which holds everything `main.rs` held before S2U step 3. Source
/// text because the role's decisions are not yet driven by host tests through
/// the platform seam; S3 converts these rows.
const NATIVE: &str = concat!(
    include_str!("../src/main.rs"),
    include_str!("../src/role.rs")
);

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
#[test]
fn native_path_validates_manifest_before_ready_then_enters_bounded_controller_loop() {
    let run = &NATIVE[NATIVE.find("fn run<").unwrap()..];
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

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
#[test]
fn native_path_keeps_the_c3_launch_surface_hardware_free() {
    assert!(NATIVE.contains("LaunchProfile::DeviceCoordinator"));
    assert!(NATIVE.contains("DEVICE_MANIFEST_RIGHTS"));
    assert!(NATIVE.contains("DW_OBJECT_TYPE_MEMORY_OBJECT"));
    assert!(
        NATIVE
            .contains("send_bootstrap_channel(platform, bootstrap, &ready[..ready_len], &[], 15)")
    );
    assert!(NATIVE.contains("issue_driver_launch"));
    assert!(NATIVE.contains("parse_constructed"));
    assert!(NATIVE.contains("accept_driver_control_ready"));
    assert!(NATIVE.contains("requested_rights: CHILD_CHANNEL_RIGHTS"));
    let c3 = &NATIVE[NATIVE.find("fn launch_driver<").unwrap()
        ..NATIVE.find("fn launch_driver_with_bundle<").unwrap()];
    assert!(!c3.contains("DW_OBJECT_TYPE_INTERRUPT"));
    assert!(!c3.contains("pio_"));
}

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
#[test]
fn c5_moves_exact_reduced_bundle_then_requires_ready_before_publish() {
    let historical = NATIVE
        .find("fn launch_driver_with_historical_bundle<")
        .unwrap();
    let c5 = &NATIVE[historical..];
    let duplicate = c5.find("duplicate_handle(parent_resource").unwrap();
    let interrupt = c5.find("create_interrupt(parent_resource").unwrap();
    let bundle = c5.find("resource_bundle_message()").unwrap();
    let move_bundle = c5
        .find("send_channel(retained, &bundle_bytes, &transfers)")
        .unwrap();
    let ready = c5.find("accept_driver_ready(ready)").unwrap();
    let publish = c5
        .find("publish_driver(platform, publication, request, resident)")
        .unwrap();
    assert!(duplicate < interrupt && interrupt < bundle && bundle < move_bundle);
    assert!(move_bundle < ready && ready < publish);
    assert!(c5.contains("duplicate_handle(parent_resource, DEVICE_RESOURCE_TRANSFER_RIGHTS)"));
    assert!(c5.contains("requested_rights: CHILD_CHANNEL_TRANSFER_RIGHTS"));
    assert!(NATIVE.contains("DwRights(DEVICE_RESOURCE_DRIVER_RIGHTS.0 | DW_RIGHT_TRANSFER.0)"));
    assert!(c5.contains("requested_rights: DEVICE_RESOURCE_DRIVER_RIGHTS"));
    assert!(c5.contains("requested_rights: INTERRUPT_DRIVER_RIGHTS"));
    assert!(c5.contains("DW_HANDLE_TRANSFER_MOVE"));
    assert!(!c5.contains("device_pio_read"));
    assert!(!c5.contains("device_pio_write"));
    assert!(!c5.contains("interrupt_ack"));
}

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
#[test]
fn c6_inline_publication_rebind_is_acknowledged_before_driver_backoff() {
    let cleanup = &NATIVE[NATIVE
        .find("send_driver_retired(platform, bootstrap, request)?")
        .expect("driver retirement notification")..];
    let receive = cleanup
        .find("let received = receive_controller")
        .expect("inline rebind receive");
    let install = cleanup
        .find("publication.replace(replacement)")
        .expect("replacement publication install");
    let acknowledge = cleanup
        .find("send_publication_acknowledgement(platform, bootstrap, &resident)")
        .expect("rebind acknowledgement status");
    let acknowledge_failure = cleanup
        .find("if let Err(code) = acknowledged")
        .expect("failed acknowledgement cleanup");
    let close_resource = cleanup
        .find("close_optional(platform, device_resource.take())")
        .expect("failed acknowledgement closes the retained resource");
    let close_publication = cleanup
        .find("close_optional(platform, publication.take())")
        .expect("failed acknowledgement closes the replacement publication");
    let close_bootstrap = cleanup
        .find("let _ = platform.close_handle(bootstrap)")
        .expect("failed acknowledgement closes the bootstrap channel");
    let cleanup_complete = cleanup
        .find("complete_driver_failure_cleanup(now)")
        .expect("cleanup completion");
    let retry = cleanup
        .find("resident.driver_retry_ready(now)")
        .expect("bounded retry transition");
    assert!(receive < install);
    assert!(install < acknowledge);
    assert!(acknowledge < acknowledge_failure);
    assert!(acknowledge_failure < close_resource);
    assert!(close_resource < close_publication);
    assert!(close_publication < close_bootstrap);
    assert!(close_bootstrap < cleanup_complete);
    assert!(acknowledge < cleanup_complete);
    assert!(cleanup_complete < retry);
}

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
#[test]
fn publication_acknowledgements_use_the_shared_lifecycle_producer_and_failure_stages() {
    let sender = &NATIVE[NATIVE.find("fn send_publication_acknowledgement<").unwrap()
        ..NATIVE.find("fn send_resident_status<").unwrap()];
    assert!(sender.contains(".publication_acknowledgement()"));
    assert!(sender.contains("PublicationAcknowledgementError::Lifecycle(_) => failure(35)"));
    assert!(sender.contains("PublicationAcknowledgementError::Encoding(_) => failure(36)"));
    assert!(sender.contains("send_bootstrap_channel(platform, bootstrap, &bytes, &[], 37)"));
    assert_eq!(
        NATIVE
            .matches("send_publication_acknowledgement(platform, bootstrap, &resident)")
            .count(),
        2
    );
}

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
#[test]
fn c3_construction_and_control_ready_share_one_finite_deadline() {
    let launch = &NATIVE[NATIVE.find("fn launch_driver<").unwrap()..];
    let launch = &launch[..launch.find("fn wait_readable<").unwrap()];
    let deadline = launch.find("monotonic_deadline_after").unwrap();
    let ack_wait = launch
        .find("wait_readable(platform, bootstrap, deadline")
        .unwrap();
    let direct_wait = launch
        .find("wait_readable(platform, retained, deadline")
        .unwrap();
    assert!(deadline < ack_wait);
    assert!(ack_wait < direct_wait);
    assert!(launch.contains("WYR0_I_SUPERVISION_POLICY.ready_timeout_ns"));
    assert!(!launch.contains("DW_DEADLINE_INFINITE"));
}

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
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
    assert!(NATIVE.contains(
        "validate_fresh(\n                    platform,\n                    handles[0].handle,"
    ));
    assert!(NATIVE.contains(
        "close_optional(platform, publication);\n                    close_optional(platform, driver_control);\n                    let _ = platform.close_handle(bootstrap);"
    ));
}
