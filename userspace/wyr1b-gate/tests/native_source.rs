use {
    wyrmroot_launch_proto as _, wyrmroot_registry_proto as _, wyrmroot_wyr1b_gate as _,
    wyrmroot_wyr1b_gate_proto as _,
};

#[test]
fn publisher_revalidates_authority_and_offer_capabilities() {
    let source = include_str!("../src/publisher.rs");
    assert!(source.contains("validate_fresh(handles[0]"));
    assert!(source.contains("validate_fresh(handles[1]"));
    assert!(source.contains("validate_fresh(offered[0]"));
    assert!(source.contains("CHILD_CHANNEL_RIGHTS"));
    assert!(source.contains("let mut reply = [0u8; 72]"));
    assert!(source.contains("Message::Error { .. }"));
    assert!(source.contains("send_failure"));
    assert!(source.contains("FailureTracker"));
    assert!(source.contains("mark_ready"));
}

#[test]
fn client_moves_broad_endpoint_and_has_failure_atomic_cleanup() {
    let source = include_str!("../src/client.rs");
    assert!(source.contains("create_channel(BROAD_CHANNEL_RIGHTS)"));
    assert!(source.contains("requested_rights: BROAD_CHANNEL_RIGHTS"));
    assert!(source.contains("operation: DW_HANDLE_TRANSFER_MOVE"));
    assert!(source.contains("let first = close_handle(service)"));
    assert!(source.contains("let second = close_handle(direct)"));
    assert!(source.contains("let mut connected_bytes = [0u8; 72]"));
    assert!(source.contains("validate_fresh(handles[0]"));
    assert!(source.contains("validate_fresh(handles[1]"));
    assert!(source.contains("send_failure"));
    assert!(source.contains("FailureTracker"));
    assert!(source.contains("mark_ready"));
}

#[test]
fn client_uses_typed_wrlj_for_gate_job_reports_without_evidence_authority() {
    let source = include_str!("../src/client.rs");
    assert!(source.contains("encode_launch("));
    assert!(source.contains("LaunchType::Wait"));
    assert!(source.contains("LaunchType::Query"));
    assert!(source.contains("LaunchErrorCode::ForeignOrUnknownJob"));
    assert!(source.contains("Message::LaunchAccepted"));
    assert!(source.contains("Message::JobResult"));
    assert!(source.contains("ClientAction::Report(record)"));
    assert!(source.contains("ClientAction::Disconnect(record)"));
    assert!(source.contains("let mut handles = [DwReceivedHandleInfoV1::default(); 16]"));
}
