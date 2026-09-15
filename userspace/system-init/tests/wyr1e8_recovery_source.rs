#[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))]
use wyrmroot_consoled as _;
#[cfg(feature = "wyr1e8-selector33")]
use wyrmroot_wyr1e_test_actors as _;
use {
    deepwyrm_syscall as _, wyrmroot_bootfs as _, wyrmroot_device_proto as _, wyrmroot_devmgr as _,
    wyrmroot_launch_proto as _, wyrmroot_loader as _, wyrmroot_registry_proto as _,
    wyrmroot_rrc_manifest as _, wyrmroot_runtime as _, wyrmroot_system_init as _,
    wyrmroot_uart16550d as _, wyrmroot_wyr1b_gate_proto as _,
};

const MANIFEST: &str = include_str!("../Cargo.toml");
const CONSOLED: &str = include_str!("../../consoled/src/main.rs");
const DEVMGR: &str = include_str!("../../devmgr/src/main.rs");
const UART: &str = include_str!("../../uart16550d/src/main.rs");
const NATIVE: &str = include_str!("../src/wyr1e_native.rs");
const RESIDENT: &str = include_str!("../src/wyr1c_native.rs");
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
    // Match the path in any position: as the first alternative of an
    // or-pattern it carries no leading `|`, so requiring one let a hard-coded
    // literal through.
    assert!(!DISPATCH.contains("\"test/wyr1-e/recovery-trigger\""));
    assert!(!DISPATCH.contains("\"test/wyr1-e/stdout-pressure\""));
}

#[test]
fn e8_shell_ready_requires_matching_tuple_and_authenticated_serial_facts() {
    let poll = &NATIVE[NATIVE.find("pub(super) fn poll").unwrap()
        ..NATIVE.find("pub(super) fn retire_dependents").unwrap()];
    let facts = poll.find("Message::ReadyFacts(facts)").unwrap();
    let observe = poll.find("observe_e8_serial_ready(").unwrap();
    assert!(facts < observe);
    assert!(poll.contains("bundle_generation: facts.bundle_generation"));
    assert!(poll.contains("e6.shell.job_dispatcher_poll_allowed()"));
    let admission = &JOBS[JOBS
        .find("pub(crate) const fn job_dispatcher_poll_allowed")
        .unwrap()
        ..JOBS
            .find("pub(crate) const fn routine_console_relaunch_allowed")
            .unwrap()];
    assert!(
        admission
            .contains("self.e8_held.is_none() && !self.e8_evidence.tuple_waiting_for_serial()")
    );

    let launch = &JOBS[JOBS.find("fn dispatch_one_job_request_inner").unwrap()
        ..JOBS.find("pub(crate) fn poll_job_dispatcher").unwrap()];
    assert!(launch.contains("stage_e8_shell_ready"));
    assert!(launch.contains("ShellTuple"));
    assert!(CONSOLED.contains("Message::ReadyFacts(facts)"));
    let attach = &CONSOLED[CONSOLED.find("fn attach_serial(").unwrap()
        ..CONSOLED.find("fn finish_connect_abort(").unwrap()];
    assert!(attach.contains("connector_client_transaction: connector_transaction"));
    assert!(attach.contains(
        "valid_connector_identity(identity, publication_generation, connector_transaction)"
    ));
    assert!(attach.contains("let correlation = serial_correlation(authorities, identity);"));
    let correlation = &CONSOLED[CONSOLED.find("fn serial_correlation(").unwrap()
        ..CONSOLED.find("fn serial_correlates(").unwrap()];
    assert!(correlation.contains("connector_client_transaction: identity.client_transaction_id"));
}

#[test]
fn e8_holds_the_real_terminal_wait_until_exact_quiescence_and_cleanup() {
    let service = &JOBS[JOBS.find("fn service_pending_wait_inner").unwrap()
        ..JOBS.find("fn cleanup_session_owner").unwrap()];
    let terminal = service.find("result_for_owner").unwrap();
    let held = service
        .find("state.hold_e8_wait(system, pending, result)")
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
    let held = retire.find("e8_held_for_action(expected_action)?").unwrap();
    let disconnect = retire
        .find("retire_console_product_with_result_before(")
        .unwrap();
    let finalize = retire
        .find("finish_e8_dependent_retirement(system")
        .unwrap();
    assert!(held < disconnect && disconnect < finalize);

    let finalizer = &JOBS[JOBS
        .find("pub(crate) fn finish_e8_dependent_retirement")
        .unwrap()..JOBS.find("fn retire_console_product_inner").unwrap()];
    let remove = finalizer
        .find("remove_barrier_result(held.pending, held.result)")
        .unwrap();
    let evidence = finalizer
        .find("record_e8_forced_retired(system, held, result)")
        .unwrap();
    let consume = finalizer.find("consume_e8_held(held)").unwrap();
    assert!(remove < evidence && evidence < consume);

    let remove_body = &DISPATCH[DISPATCH
        .find("pub(crate) fn remove_barrier_result")
        .unwrap()..DISPATCH.find("fn drop_session_waits").unwrap()];
    assert!(remove_body.contains("remove_invisible_completed"));
    assert!(remove_body.contains("pending.grant.endpoint_id"));
    assert!(remove_body.contains("pending.grant.endpoint_generation"));
    assert!(remove_body.contains("pending.job_id"));
}

#[test]
fn driver_exit_uses_the_reached_production_owner_order() {
    let driver_exit = &RESIDENT[RESIDENT.find("ResidentPollEvent::DriverExited =>").unwrap()..];
    let driver_exit = &driver_exit[..driver_exit
        .find("ResidentPollEvent::ProbeControlReadable =>")
        .unwrap()];
    let dependents = driver_exit.find("wyr1e::retire_dependents(").unwrap();
    let reap = driver_exit.find("reap_driver_before(").unwrap();
    let acknowledge = driver_exit.find("acknowledge_driver_reaped(").unwrap();
    assert!(dependents < reap && reap < acknowledge);

    for reached_uart_step in [
        "GracefulRetireDrain::new",
        "observe_stream_empty",
        "temt_probe_due",
        "observe_temt",
    ] {
        assert!(UART.contains(reached_uart_step));
    }
    for reached_broker_step in [
        ".retire_current()",
        ".driver_attempt_reaped(",
        ".replace_published_driver(",
    ] {
        assert!(DEVMGR.contains(reached_broker_step));
    }
}

#[test]
fn supervision_discriminator_stays_at_the_three_existing_failure_sources() {
    let guard = &NATIVE[NATIVE.find("pub(super) fn ensure_e8_action_live(").unwrap()
        ..NATIVE.find("fn retire_current_console<").unwrap()];
    assert!(guard.contains("E8FailureOperation::ActionDeadline"));
    assert!(guard.contains("state.shell.require_e8_action_live_at(now)"));
    assert!(!guard.contains("E8FailureOperation::Quiesced"));

    let late_ready_start = NATIVE.find("if validated_at >= e6.ready_deadline").unwrap();
    let late_ready = &NATIVE[late_ready_start..];
    let late_ready = &late_ready[..late_ready.find("e6.awaiting_ready = false;").unwrap()];
    assert!(late_ready.contains("e6.shell.e8_action_expired(validated_at)"));
    assert!(late_ready.contains("E8FailureOperation::ActionDeadline"));
    assert!(!late_ready.contains("E8FailureOperation::Quiesced"));

    let response = &NATIVE[NATIVE
        .find("if bytes[..counts.bytes].starts_with(b\"WRC8\")")
        .unwrap()
        ..NATIVE
            .find("if wyrmroot_loader::launch::parse_ready_for_profile")
            .unwrap()];
    assert_eq!(response.matches("E8FailureOperation::Quiesced").count(), 4);
    assert!(response.contains("e6.shell.require_e8_action_live_at(quiesced_at)"));
    assert!(response.contains("e6.shell.accept_e8_quiesced(identity, quiesced_at)"));
    assert!(!response.contains("E8FailureOperation::ActionDeadline"));
    assert!(!response.contains("E8FailureOperation::RecoveryFallback"));

    let fallback_start = RESIDENT.find("let outcome = wyr1e::poll(").unwrap();
    let fallback = &RESIDENT[fallback_start..];
    let fallback = &fallback[..fallback.find("let size = system").unwrap()];
    assert!(fallback.contains("#[cfg(feature = \"wyr1e8-selector33\")]"));
    assert!(
        fallback
            .contains("wyr1e::PollOutcome::RecoverDevmgr | wyr1e::PollOutcome::RecoverRegistry")
    );
    assert!(fallback.contains("wyr1e::e8_action_deadline(resident)?.is_some()"));
    assert!(fallback.contains("E8FailureOperation::RecoveryFallback"));
    assert!(fallback.contains("Err(InitError::Supervision)"));
    assert!(!fallback.contains("E8FailureOperation::Quiesced"));
}

#[test]
fn registry_recovery_phase_failures_are_wrapped_at_existing_boundaries() {
    let recovery = &RESIDENT[RESIDENT.find("fn recover_registry<").unwrap()
        ..RESIDENT
            .find("pub(crate) const E8_REGISTRY_FIXTURE_DEVMGR_CONTROL")
            .unwrap()];
    let dependents = &recovery[recovery.find("let dependent_cleanup_error =").unwrap()
        ..recovery.find("let registry = resident").unwrap()];
    assert!(dependents.contains("E8FailureOperation::RetireDependents"));
    assert!(dependents.contains("wyr1e::retire_dependents(resident, system, waits, true)"));
    for (binding, operation) in [
        ("exhausted", "RetireRegistry"),
        ("replacement", "LaunchRegistry"),
        ("reserved", "CommitRegistry"),
        ("replacement", "CommitRegistry"),
        ("committed", "CommitRegistry"),
        ("waiting", "RebindPublication"),
        ("rebound", "RebindPublication"),
        ("started", "StartConsole"),
    ] {
        assert!(recovery.contains(&format!(
            "e8_operation(E8FailureOperation::{operation}, {binding})"
        )));
    }
    assert_eq!(recovery.matches("wyr1e::ensure_e8_action_live(").count(), 3);
    let console_start = &RESIDENT[RESIDENT
        .find("wyr1e::PollOutcome::LaunchConsole =>")
        .unwrap()
        ..RESIDENT
            .find("wyr1e::PollOutcome::RecoverDevmgr =>")
            .unwrap()];
    assert!(console_start.contains("wyr1e::launch_after_publication_observed("));
    assert!(console_start.contains("e8_operation(E8FailureOperation::StartConsole, launched)"));
    let publication = &NATIVE[NATIVE.find("pub(super) fn poll<").unwrap()
        ..NATIVE.find("fn retire_current_console<").unwrap()];
    assert!(
        publication
            .contains("let publication = poll_publication_observer(resident, system, waits, now)")
    );
    assert!(
        publication.contains("e8_operation(E8FailureOperation::RebindPublication, publication)")
    );
}

#[test]
fn registry_episode_admission_is_only_for_live_quiesced_coordinated_recovery() {
    let recovery = &RESIDENT[RESIDENT.find("fn recover_registry<").unwrap()
        ..RESIDENT
            .find("pub(crate) const E8_REGISTRY_FIXTURE_DEVMGR_CONTROL")
            .unwrap()];
    let quiesced = recovery
        .find("action_deadline.is_some() && !_e8_quiesced")
        .unwrap();
    let live = recovery.find("wyr1e::ensure_e8_action_live(").unwrap();
    let dependents = recovery.find("wyr1e::retire_dependents(").unwrap();
    let admission = recovery
        .find("retire_registry_for_recovery_before(")
        .unwrap();
    assert!(quiesced < live && live < dependents && dependents < admission);
    assert!(recovery.contains("let exhausted = if let Some(deadline) = action_deadline"));
    assert!(recovery.contains("&& dependent_cleanup_error.is_none()"));
    assert_eq!(
        RESIDENT
            .matches("retire_registry_for_recovery_before(")
            .count(),
        1
    );
    assert!(JOBS.contains("RegistryRetirement::Failure => controller.fail("));
    assert!(JOBS.contains("if deadline_cap.is_some_and(|deadline| now < deadline)"));
    let retirement = &JOBS[JOBS.find("fn retire_registry_generation<").unwrap()
        ..JOBS
            .find("pub(crate) fn restart_topology_or_poison<")
            .unwrap()];
    assert_eq!(retirement.matches("controller.admit_recovery(").count(), 1);
}

#[test]
fn e8_failure_detail_is_bound_to_each_actual_transition_join() {
    let main = include_str!("../src/main.rs");
    let lib = include_str!("../src/lib.rs");
    let jobs = include_str!("../src/wyr1b_native.rs");
    let console = include_str!("../src/wyr1e_native.rs");
    let driver = include_str!("../src/wyr1c_native.rs");

    assert!(main.contains("resident_tick_failure_application_status(&error)"));
    assert!(lib.contains("0xAF18_0000 | (operation as u32) << 8 | kind as u32"));
    let held_wait_start = jobs
        .find("if scope == LaunchSessionScope::ShellJobs")
        .unwrap();
    let held_wait_end = held_wait_start
        + jobs[held_wait_start..]
            .find("let terminal = controller_result_to_wire(result)")
            .unwrap();
    let held_wait = &jobs[held_wait_start..held_wait_end];
    assert_eq!(
        held_wait.matches("E8FailureOperation::TriggerWait").count(),
        2
    );

    let quiesced = &console[console.find("Message::Quiesced(identity)").unwrap()
        ..console.find("Message::Quiesce(_)").unwrap()];
    for operation in [
        "E8FailureOperation::Quiesced",
        "E8FailureOperation::RequestRetire",
    ] {
        assert!(quiesced.contains(operation));
    }

    let driver_retired_start = driver
        .find("Ok(DevmgrControlInput::DriverRetired { bytes })")
        .unwrap();
    let driver_retired_end = driver_retired_start
        + driver[driver_retired_start..]
            .find("ResidentPollEvent::RegistryLost")
            .unwrap();
    let driver_retired = &driver[driver_retired_start..driver_retired_end];
    for operation in [
        "E8FailureOperation::DriverRetired",
        "E8FailureOperation::RebindPublication",
    ] {
        assert!(driver_retired.contains(operation));
    }

    let driver_exited_start = driver.find("ResidentPollEvent::DriverExited =>").unwrap();
    let driver_exited_end = driver_exited_start
        + driver[driver_exited_start..]
            .find("ResidentPollEvent::ProbeControlReadable")
            .unwrap();
    let driver_exited = &driver[driver_exited_start..driver_exited_end];
    for operation in [
        "E8FailureOperation::RetireDependents",
        "E8FailureOperation::ReapDriver",
        "E8FailureOperation::AcknowledgeReaped",
    ] {
        assert!(driver_exited.contains(operation));
    }
}

#[test]
fn publication_rebind_joins_use_exact_lifecycle_postconditions_and_a_real_producer() {
    let production = &RESIDENT[..RESIDENT.find("#[cfg(test)]\nmod tests {").unwrap()];
    assert_eq!(
        production
            .matches("PublicationRebindContext::DriverRetirement")
            .count(),
        2
    );
    assert_eq!(
        production
            .matches("PublicationRebindContext::RegistryRecovery")
            .count(),
        1
    );
    let rebind = &production[production.find("fn rebind_publication<").unwrap()..];
    assert!(rebind.contains("context.expected_status("));
    assert!(rebind.contains("state.resource_domain"));
    assert!(rebind.contains("state.last_reaped_driver"));
    assert!(rebind.contains("expected_status,"));
    assert!(rebind.contains("deadline_cap,"));
    let fixture = include_str!("../src/wyr1e8_producer_fixture.rs");
    assert!(fixture.contains("producer.publication_acknowledgement().unwrap()"));
    assert!(!fixture.contains("OperationalWaitingForDeviceBundle"));
}
