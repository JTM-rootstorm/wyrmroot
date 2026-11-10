#[cfg(feature = "native-devmgr")]
use {wyrmroot_loader as _, wyrmroot_registry_proto as _, wyrmroot_runtime as _};

use {wyrmroot_device_proto as _, wyrmroot_devmgr as _};

use deepwyrm_syscall as _;
use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_runtime as _;

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
