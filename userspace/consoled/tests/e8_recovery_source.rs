use {wyrmroot_console_proto as _, wyrmroot_consoled as _};

const MANIFEST: &str = include_str!("../Cargo.toml");
const NATIVE: &str = include_str!("../src/main.rs");

#[test]
fn e8_ready_facts_precede_each_shell_v1_request_and_use_live_serial_identity() {
    assert!(MANIFEST.contains("wyr1e8-recovery = [\"wyr1e-wyrmsh\"]"));
    let launch = &NATIVE[NATIVE.find("fn launch_child_once(").unwrap()
        ..NATIVE.find("fn finish_launch_abort(").unwrap()];
    let reserve = launch.find("model.begin_child_launch(").unwrap();
    let facts = launch
        .find("wyrmroot_consoled::e8_control::ReadyFacts {")
        .unwrap();
    let live_attach = launch
        .find("serial.identity.attach_transaction_id")
        .unwrap();
    let live_stream = launch.find("serial.identity.stream_generation").unwrap();
    let live_bundle = launch.find("serial.identity.bundle_generation").unwrap();
    let send_facts = launch
        .find("send_channel(authorities.recovery_control, &bytes, &[])")
        .unwrap();
    let shell_request = launch
        .find("ChildPolicy::Wyrmsh => encode_shell_v1_request(")
        .unwrap();
    assert!(reserve < facts);
    assert!(facts < live_attach && live_attach < live_stream && live_stream < live_bundle);
    assert!(live_bundle < send_facts && send_facts < shell_request);
}

#[test]
fn e8_quiescence_stops_input_and_waits_for_every_owned_output_queue() {
    let loop_body = &NATIVE[NATIVE.find("fn event_loop(").unwrap()
        ..NATIVE.find("fn drain_clean_terminal_output(").unwrap()];
    assert!(loop_body.contains("let accepting_raw_input = recovery_request.is_none();"));
    assert!(
        loop_body.contains("input_pending.is_empty()\n            && output_pending.is_empty()")
    );
    assert!(loop_body.contains("snapshot.input_queued == 0"));
    assert!(loop_body.contains("snapshot.stdout_queued == 0"));
    assert!(loop_body.contains("snapshot.stderr_queued == 0"));
    let quiet_poll = loop_body
        .find("if !streams_freshly_quiet(&mut streams, child, model)?")
        .unwrap();
    let acknowledge = loop_body.find("Message::Quiesced(identity)").unwrap();
    assert!(quiet_poll < acknowledge);
    assert!(loop_body[quiet_poll..acknowledge].contains("continue;"));
    assert!(loop_body.contains("if let Some(identity) = recovery_request"));
    assert!(
        loop_body
            .contains("recovery_request = Some(receive_recovery_request(authorities, child)?);")
    );
    assert!(loop_body.contains("Message::Quiesced(identity)"));
    assert!(loop_body.contains("recovery_acknowledged = true"));

    let quiet = &NATIVE[NATIVE.find("fn streams_freshly_quiet(").unwrap()
        ..NATIVE.find("fn selector_configure(").unwrap()];
    assert!(quiet.contains("&mut child.stdout"));
    assert!(quiet.contains("&mut child.stderr"));
    assert!(quiet.contains(".poll_output_quiescence(child.event, |source, payload|"));
    assert!(quiet.contains("input.read(streams, payload)"));
    assert!(quiet.contains("Ok(count) => Ok(Some(count))"));
    assert!(quiet.contains("Err(StreamError::WouldBlock) => Ok(None)"));
    assert!(quiet.contains("Err(_) => Err(wyrmroot_consoled::ModelError::ChildDisconnected)"));
    assert!(!quiet.contains("wait_many"));
    assert!(!quiet.contains("DW_STATUS_TIMED_OUT"));
}

#[test]
fn clean_terminal_result_drains_child_output_before_reap_and_relaunch() {
    let branch = &NATIVE[NATIVE.find("2 => {").unwrap()..NATIVE.find("3 => {").unwrap()];
    let drain = branch.find("drain_clean_terminal_output(").unwrap();
    let recover = branch.find("recover_terminal_child(").unwrap();
    assert!(drain < recover);

    let drain_body = &NATIVE[NATIVE.find("fn drain_clean_terminal_output(").unwrap()
        ..NATIVE.find("fn receive_recovery_request(").unwrap()];
    let job_result = drain_body
        .find("LaunchReply::JobResult(child.job_id)")
        .unwrap();
    let deadline = drain_body.find("TERMINAL_DRAIN_TIMEOUT_NS").unwrap();
    let stdout = drain_body.find("child.stdout.endpoint().handle()").unwrap();
    let stderr = drain_body.find("child.stderr.endpoint().handle()").unwrap();
    let commit = drain_body
        .find("commit_output(model, output_pending)?")
        .unwrap();
    assert!(deadline < job_result && job_result < stdout && stdout < stderr && stderr < commit);

    let bounded_receive = &NATIVE[NATIVE.find("fn receive_launch_before(").unwrap()
        ..NATIVE.find("fn receive_initial_launch(").unwrap()];
    assert!(bounded_receive.contains("DwDeadline(deadline)"));
    assert!(bounded_receive.contains("DW_SIGNAL_READABLE"));
    assert!(bounded_receive.contains("DW_SIGNAL_PEER_CLOSED"));
    assert!(bounded_receive.contains("receive_launch_ready(channel)?"));

    let recover_body = &NATIVE[NATIVE.find("fn recover_terminal_child(").unwrap()
        ..NATIVE.find("fn recover_child(").unwrap()];
    assert!(recover_body.contains("#[cfg(not(feature = \"wyr1e-wyrmsh\"))]"));
    assert!(recover_body.contains("model.child_terminal"));
    assert!(recover_body.contains("close_reaped_job"));
    assert!(recover_body.contains("*child = launch_child"));
}

#[test]
fn role_peer_close_with_pending_wait_uses_terminal_precursor_before_fault_retirement() {
    let loop_body = &NATIVE[NATIVE.find("fn event_loop(").unwrap()
        ..NATIVE.find("fn drain_clean_terminal_output(").unwrap()];
    assert_eq!(loop_body.matches("recover_terminal_precursor(").count(), 3);
    assert!(loop_body.contains("signals & DW_SIGNAL_PEER_CLOSED.0 != 0 && child.wait.is_some()"));
    assert!(loop_body.contains("4 | 5 => {"));
    assert!(loop_body.contains("6 if child.status.is_some() => {"));

    let precursor = &NATIVE[NATIVE.find("fn recover_terminal_precursor(").unwrap()
        ..NATIVE.find("fn receive_recovery_request(").unwrap()];
    let observe = precursor.find("model.child_terminal_precursor").unwrap();
    let drain = precursor.find("drain_clean_terminal_output(").unwrap();
    let recover = precursor.find("recover_terminal_child(").unwrap();
    assert!(observe < drain && drain < recover);
    assert!(!precursor.contains("recover_child("));
    assert!(!precursor.contains("clear_volatile"));
}
