use {
    deepwyrm_syscall as _, wyrmroot_bootfs as _, wyrmroot_device_proto as _,
    wyrmroot_launch_proto as _, wyrmroot_loader as _, wyrmroot_registry_proto as _,
    wyrmroot_rrc_manifest as _, wyrmroot_runtime as _, wyrmroot_system_init as _,
    wyrmroot_wyr1b_gate_proto as _,
};

const MANIFEST: &str = include_str!("../Cargo.toml");
const CONSOLED: &str = include_str!("../../consoled/src/main.rs");
const NATIVE: &str = include_str!("../src/wyr1e_native.rs");
const JOBS: &str = include_str!("../src/wyr1b_native.rs");
const DISPATCH: &str = include_str!("../src/wyr1b_job.rs");

#[test]
fn e8_profile_is_additive_and_keeps_e7_feature_separate() {
    assert!(MANIFEST.contains("wyr1e8-selector33 = ["));
    assert!(MANIFEST.contains("\"wyr1e-production\""));
    assert!(MANIFEST.contains("\"dep:wyrmroot-wyr1e-test-actors\""));
    assert!(MANIFEST.contains("\"wyrmroot-consoled/wyr1e8-recovery\""));
    assert!(MANIFEST.contains("\"wyrmroot-runtime/wyr1e8-test-evidence\""));
    assert!(
        include_str!("../src/lib.rs")
            .contains("WYR1-E7 and E8 selector profiles are mutually exclusive")
    );
}

#[test]
fn e8_actor_admission_uses_the_product_owned_paths() {
    assert!(DISPATCH.contains("wyrmroot_wyr1e_test_actors::RECOVERY_TRIGGER_PATH"));
    assert!(DISPATCH.contains("wyrmroot_wyr1e_test_actors::STDOUT_PRESSURE_PATH"));
    assert!(!DISPATCH.contains("| \"test/wyr1-e/recovery-trigger\""));
    assert!(!DISPATCH.contains("| \"test/wyr1-e/stdout-pressure\""));
}

#[test]
fn e8_shell_ready_requires_matching_tuple_and_authenticated_serial_facts() {
    let poll = &NATIVE[NATIVE.find("pub(super) fn poll").unwrap()
        ..NATIVE.find("pub(super) fn retire_dependents").unwrap()];
    let facts = poll.find("Message::ReadyFacts(facts)").unwrap();
    let observe = poll.find("observe_e8_serial_ready(").unwrap();
    assert!(facts < observe);
    assert!(poll.contains("bundle_generation: facts.bundle_generation"));
    assert!(poll.contains("e8_tuple_waiting_for_serial()"));

    let launch = &JOBS[JOBS.find("fn dispatch_one_job_request_inner").unwrap()
        ..JOBS.find("pub(crate) fn poll_job_dispatcher").unwrap()];
    assert!(launch.contains("stage_e8_shell_ready"));
    assert!(launch.contains("ShellTuple"));
    assert!(CONSOLED.contains("Message::ReadyFacts(facts)"));
}

#[test]
fn e8_holds_the_real_terminal_wait_until_exact_quiescence_and_cleanup() {
    let service = &JOBS[JOBS.find("fn service_pending_wait_inner").unwrap()
        ..JOBS.find("fn cleanup_session_owner").unwrap()];
    let terminal = service.find("result_for_owner").unwrap();
    let held = service
        .find("state.hold_e8_wait(system, pending, result)?")
        .unwrap();
    let send = service
        .find("system.send_channel(session, &response[..size])")
        .unwrap();
    assert!(terminal < held && held < send);

    let state = &JOBS
        [JOBS.find("fn hold_e8_wait").unwrap()..JOBS.find("pub(crate) const fn health").unwrap()];
    assert!(state.contains("TerminationClassification::NormalExit.as_u32()"));
    assert!(state.contains(".launch_transaction\n            .checked_add(1)"));
    assert!(state.contains("pending.reservation.transaction_id != expected_wait_transaction"));
    assert!(state.contains("Message::Quiesce(identity)"));
    assert!(state.contains("now >= held.deadline"));
    assert!(state.contains("identity != held.identity || held.acknowledged"));
}

#[test]
fn e8_trigger_token_is_derived_per_recovery_stage() {
    assert!(JOBS.contains("const E8_DRIVER_TRIGGER_TOKEN_INDEX: u64 = 0x0102;"));
    assert!(JOBS.contains("const E8_REGISTRY_TRIGGER_TOKEN_INDEX: u64 = 0x0202;"));
    assert!(JOBS.contains("let expected_token = nonce ^ token_index;"));
    assert!(JOBS.contains(
        "expected_token == 0 || launch.arg(2).and_then(parse_e8_nonce) != Some(expected_token)"
    ));
}

#[test]
fn driver_retire_uses_all_six_current_d5_identity_fields() {
    let identity = &JOBS[JOBS.find("pub(crate) fn e8_driver_identity").unwrap()
        ..JOBS.find("pub(crate) fn record_e8_forced_retired").unwrap()];
    for field in [
        "request.role_id.0",
        "request.attempt_generation.0",
        "request.endpoint.id.0",
        "request.endpoint.generation.0",
        "request.transaction_id",
        "request.supervisor_generation.0",
        "bundle_generation: bundle",
    ] {
        assert!(
            identity.contains(field),
            "missing current identity join: {field}"
        );
    }
    let poll = &NATIVE[NATIVE.find("Message::Quiesced(identity)").unwrap()
        ..NATIVE
            .find("if wyrmroot_loader::launch::parse_ready_for_profile")
            .unwrap()];
    assert!(poll.contains("D5ControllerMessage::RequestRetire("));
    assert!(poll.contains("identity,"));
    assert!(poll.contains(".send_channel(devmgr.loaded.launch_channel, &request_bytes)"));
}

#[test]
fn forced_retirement_disconnects_then_removes_only_the_held_barrier_result() {
    let retire = &NATIVE[NATIVE.find("pub(super) fn retire_dependents").unwrap()
        ..NATIVE
            .find("pub(super) fn reserve_registry_replacement")
            .unwrap()];
    let disconnect = retire.find("retire_console_product_with_result(").unwrap();
    let held = retire.find("take_e8_held(expected_action)?").unwrap();
    let remove = retire
        .find("remove_barrier_result(held.pending, held.result)")
        .unwrap();
    let evidence = retire
        .find("record_e8_forced_retired(system, held, result)")
        .unwrap();
    assert!(disconnect < held && held < remove && remove < evidence);

    let remove_body = &DISPATCH[DISPATCH
        .find("pub(crate) fn remove_barrier_result")
        .unwrap()..DISPATCH.find("fn drop_session_waits").unwrap()];
    assert!(remove_body.contains("remove_invisible_completed"));
    assert!(remove_body.contains("pending.grant.endpoint_id"));
    assert!(remove_body.contains("pending.grant.endpoint_generation"));
    assert!(remove_body.contains("pending.job_id"));
}
