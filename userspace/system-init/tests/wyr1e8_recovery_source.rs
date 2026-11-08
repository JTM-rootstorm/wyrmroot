#[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))]
use wyrmroot_consoled as _;
#[cfg(feature = "dw1e3-selector31")]
use wyrmroot_dw1e3_com2_test as _;
#[cfg(feature = "wyr1e8-selector33")]
use wyrmroot_wyr1e_test_actors as _;
use {
    deepwyrm_syscall as _, wyrmroot_bootfs as _, wyrmroot_device_proto as _, wyrmroot_devmgr as _,
    wyrmroot_launch_proto as _, wyrmroot_loader as _, wyrmroot_registry_proto as _,
    wyrmroot_registryd as _, wyrmroot_rrc_manifest as _, wyrmroot_runtime as _,
    wyrmroot_system_init as _, wyrmroot_uart16550d as _, wyrmroot_wyr1b_gate_proto as _,
};

/// consoled's role, in its original order: the binary's entry file, then
/// `role.rs`, which holds everything consoled's `main.rs` held before S2U step
/// 3. Source text because no host test drives the role yet; each test below
/// names the property it reads.
const CONSOLED: &str = concat!(
    include_str!("../../consoled/src/main.rs"),
    include_str!("../../consoled/src/role.rs")
);
/// devmgr's role, in its original order: the binary's entry file, then
/// `role.rs`, which holds everything devmgr's `main.rs` held before S2U step 3.
/// Source text for the reason each test below gives.
const DEVMGR: &str = concat!(
    include_str!("../../devmgr/src/main.rs"),
    include_str!("../../devmgr/src/role.rs")
);
/// uart16550d's role, in its original order: the binary's entry file, then
/// `role.rs`, which holds everything its `main.rs` held before S2U step 3.
/// Source text for the reason each test below gives.
const UART: &str = concat!(
    include_str!("../../uart16550d/src/main.rs"),
    include_str!("../../uart16550d/src/role.rs")
);
const NATIVE: &str = include_str!("../src/wyr1e_native.rs");
const RESIDENT: &str = include_str!("../src/wyr1c_native.rs");
const JOBS: &str = include_str!("../src/wyr1b_native.rs");
const DISPATCH: &str = include_str!("../src/wyr1b_job.rs");

/// The source span of the one top-level item beginning at `anchor`. rustfmt
/// closes a top-level item with `}` in column zero, so ending the span there
/// rather than at a named later function keeps an anchor that has left the
/// item from quietly matching somewhere further down the file. Top-level items
/// only: a method inside an `impl` does not close in column zero.
fn item<'a>(source: &'a str, anchor: &str) -> &'a str {
    let start = source.find(anchor).unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    &source[start..end]
}

#[test]
fn e8_shell_ready_requires_matching_tuple_and_authenticated_serial_facts() {
    let poll = item(NATIVE, "fn poll_observations<");
    let facts = poll.find("Message::ReadyFacts(facts)").unwrap();
    let observe = poll.find("observe_e8_serial_ready(").unwrap();
    assert!(facts < observe);
    assert!(poll.contains("bundle_generation: facts.bundle_generation"));
    assert!(poll.contains("!e6.shell.e8_tuple_waiting_for_serial()"));
    // R7B-4 class D1b. The dispatcher asks the policy which launch may open an
    // episode; it does not know the path. Assert the negative too, since
    // reintroducing the comparison would not change how the call site reads.
    assert!(JOBS.contains("policy.opens_recovery_episode(request.path)"));
    let classify = &JOBS[JOBS.find("fn e8_trigger_from_launch").unwrap()
        ..JOBS.find("fn e8_trigger_from_request").unwrap()];
    assert!(classify.contains("if !opens_episode {"));
    assert!(!classify.contains("RECOVERY_TRIGGER_PATH"));
    assert!(classify.contains("launch.arg(0) != Some(launch.path)"));
    // R7B-4 class D1e. The dispatcher admission carries one reason, evidence
    // adjacency, and the held WAIT is no longer one of them. Assert the
    // negative too: re-adding `e8_held` here would restore the bundling
    // without changing how the call site reads.
    let admission = &JOBS[JOBS
        .find("pub(crate) const fn e8_tuple_waiting_for_serial")
        .unwrap()
        ..JOBS
            .find("pub(crate) const fn routine_console_relaunch_allowed")
            .unwrap()];
    assert!(admission.contains("self.e8_evidence.tuple_waiting_for_serial()"));
    assert!(!admission.contains("self.e8_held"));

    let launch = &JOBS[JOBS.find("fn dispatch_one_job_request_inner").unwrap()
        ..JOBS.find("pub(crate) fn poll_job_dispatcher").unwrap()];
    assert!(launch.contains("stage_e8_shell_ready"));
    assert!(launch.contains("ShellTuple"));
    assert!(CONSOLED.contains("Message::ReadyFacts(facts)"));
    // Source text: no host test drives consoled's role yet. The anchor ends in
    // `<` because attach_serial now opens with its platform parameter list.
    let attach = item(CONSOLED, "fn attach_serial<");
    assert!(attach.contains("connector_client_transaction: connector_transaction"));
    assert!(attach.contains(
        "valid_connector_identity(identity, publication_generation, connector_transaction)"
    ));
    assert!(attach.contains("let correlation = serial_correlation(authorities, identity);"));
    let correlation = &CONSOLED[CONSOLED.find("fn serial_correlation(").unwrap()
        ..CONSOLED.find("fn serial_correlates(").unwrap()];
    assert!(correlation.contains("connector_client_transaction: identity.client_transaction_id"));
}

/// The resident sends the D5 retire with the identity `e8_driver_identity`
/// built, which `e8_driver_identity_joins_every_current_d5_identity_field`
/// (wyr1b_native.rs) holds field by field. Source text for the send because
/// it is inline in `poll_observations`, which no host fake drives; scoped to
/// the `Quiesced` arm.
#[test]
fn driver_retire_uses_all_six_current_d5_identity_fields() {
    let poll = item(NATIVE, "fn poll_observations<");
    let poll = &poll[poll.find("Message::Quiesced(identity)").unwrap()
        ..poll.find("Message::Quiesce(_)").unwrap()];
    let identity = poll
        .find("let identity = e6.shell.e8_driver_identity(request)?;")
        .unwrap();
    let encode = poll.find("D5ControllerMessage::RequestRetire(\n").unwrap();
    let send = poll
        .find(".send_channel(devmgr.loaded.launch_channel, &request_bytes)")
        .unwrap();
    assert!(identity < encode && encode < send);
    assert!(poll[encode..send].contains("identity,"));
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
        .find("remove_barrier_result(held.pending, E8_HELD_WAIT_RESULT)")
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
    let guard = &NATIVE[NATIVE.find("pub(super) fn ensure_recovery_live(").unwrap()
        ..NATIVE.find("fn retire_current_console<").unwrap()];
    assert!(guard.contains("RecoveryOperation::ActionDeadline"));
    assert!(guard.contains("state.shell.require_recovery_live_at(now)"));
    assert!(!guard.contains("RecoveryOperation::Quiesced"));

    let late_ready_start = NATIVE.find("if validated_at >= e6.ready_deadline").unwrap();
    let late_ready = &NATIVE[late_ready_start..];
    let late_ready = &late_ready[..late_ready.find("e6.awaiting_ready = false;").unwrap()];
    assert!(late_ready.contains("e6.shell.recovery_deadline_expired(validated_at)"));
    assert!(late_ready.contains("RecoveryOperation::ActionDeadline"));
    assert!(!late_ready.contains("RecoveryOperation::Quiesced"));

    let response = &NATIVE[NATIVE
        .find("if bytes[..counts.bytes].starts_with(b\"WRC8\")")
        .unwrap()
        ..NATIVE
            .find("if wyrmroot_loader::launch::parse_ready_for_profile")
            .unwrap()];
    assert_eq!(response.matches("RecoveryOperation::Quiesced").count(), 4);
    assert!(response.contains("e6.shell.require_recovery_live_at(quiesced_at)"));
    assert!(response.contains("e6.shell.accept_e8_quiesced(identity, quiesced_at)"));
    assert!(!response.contains("RecoveryOperation::ActionDeadline"));
    assert!(!response.contains("RecoveryOperation::RecoveryFallback"));

    let fallback_start = RESIDENT.find("let outcome = wyr1e::poll(").unwrap();
    let fallback = &RESIDENT[fallback_start..];
    let fallback = &fallback[..fallback.find("let size = system").unwrap()];
    // R7B-2: the fallback is no longer the selector's. It is reached only when
    // an episode is open, and a product build opens none, so removing the gate
    // changed which builds compile it and not which builds take it. Pin that
    // the gate is gone, so putting it back has to argue with this line.
    assert!(!fallback.contains("#[cfg(feature = \"wyr1e8-selector33\")]"));
    assert!(
        fallback
            .contains("wyr1e::PollOutcome::RecoverDevmgr | wyr1e::PollOutcome::RecoverRegistry")
    );
    assert!(fallback.contains("wyr1e::recovery_deadline(resident)?.is_some()"));
    assert!(fallback.contains("RecoveryOperation::RecoveryFallback"));
    assert!(fallback.contains("Err(InitError::Supervision)"));
    assert!(!fallback.contains("RecoveryOperation::Quiesced"));
}

#[test]
fn registry_recovery_phase_failures_are_wrapped_at_existing_boundaries() {
    let recovery = &RESIDENT[RESIDENT.find("fn recover_registry<").unwrap()
        ..RESIDENT
            .find("pub(crate) const E8_REGISTRY_FIXTURE_DEVMGR_CONTROL")
            .unwrap()];
    let dependents = &recovery[recovery.find("let dependent_cleanup_error =").unwrap()
        ..recovery.find("let registry = resident").unwrap()];
    assert!(dependents.contains("RecoveryOperation::RetireDependents"));
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
            "attribute_failure(RecoveryOperation::{operation}, {binding})"
        )));
    }
    assert_eq!(recovery.matches("wyr1e::ensure_recovery_live(").count(), 3);
    let console_start = &RESIDENT[RESIDENT
        .find("wyr1e::PollOutcome::LaunchConsole =>")
        .unwrap()
        ..RESIDENT
            .find("wyr1e::PollOutcome::RecoverDevmgr =>")
            .unwrap()];
    assert!(console_start.contains("wyr1e::launch_after_publication_observed("));
    assert!(console_start.contains("attribute_failure(RecoveryOperation::StartConsole, launched)"));
    let publication = &NATIVE[NATIVE.find("pub(super) fn poll<").unwrap()
        ..NATIVE.find("fn retire_current_console<").unwrap()];
    assert!(
        publication
            .contains("let publication = poll_publication_observer(resident, system, waits, now)")
    );
    assert!(
        publication
            .contains("attribute_failure(RecoveryOperation::RebindPublication, publication)")
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
    let live = recovery.find("wyr1e::ensure_recovery_live(").unwrap();
    let dependents = recovery.find("wyr1e::retire_dependents(").unwrap();
    let admission = recovery
        .find("retire_registry_for_recovery_before(")
        .unwrap();
    assert!(quiesced < live && live < dependents && dependents < admission);
    // R7B-4 made the episode-capped retirement take `Option<u64>` like the
    // rest of the `_before` family, so the condition reads as a test on the
    // episode rather than a destructuring of it. The property is unchanged:
    // admission needs a live episode and a clean dependent retirement.
    assert!(recovery.contains(
        "let exhausted = if action_deadline.is_some() && dependent_cleanup_error.is_none()"
    ));
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

/// Each E8 transition join names its own `RecoveryOperation`. The status
/// word's layout is not checked here; it is pinned by value, in
/// `a_payload_free_tick_failure_status_is_unchanged_by_the_widening` below and
/// by the attributed-status tests in lib.rs.
///
/// Source text because the `Quiesced`, `DriverRetired` and `DriverExited`
/// arms are inline in `poll_observations` and `control_tick`, which no host
/// fake drives; each span is scoped to its fn body or arm.
#[test]
fn e8_failure_detail_is_bound_to_each_actual_transition_join() {
    // The resident loop, which reports a tick failure, moved out of `main.rs`.
    let resident_loop = item(
        include_str!("../src/resident_loop.rs"),
        "pub fn continue_resident<",
    );
    let jobs = item(JOBS, "fn service_pending_wait_inner<");
    let driver = item(RESIDENT, "pub(crate) fn control_tick<");

    assert!(resident_loop.contains("resident_tick_failure_application_status(&error)"));
    let held_wait_start = jobs
        .find("if scope == LaunchSessionScope::ShellJobs")
        .unwrap();
    let held_wait_end = held_wait_start
        + jobs[held_wait_start..]
            .find("let terminal = controller_result_to_wire(result)")
            .unwrap();
    let held_wait = &jobs[held_wait_start..held_wait_end];
    assert_eq!(
        held_wait.matches("RecoveryOperation::TriggerWait").count(),
        2
    );

    let console = item(NATIVE, "fn poll_observations<");
    let quiesced = &console[console.find("Message::Quiesced(identity)").unwrap()
        ..console.find("Message::Quiesce(_)").unwrap()];
    for operation in [
        "RecoveryOperation::Quiesced",
        "RecoveryOperation::RequestRetire",
    ] {
        assert!(quiesced.contains(operation));
    }

    let driver_retired_start = driver
        .find("Ok(DevmgrControlInput::DriverRetired { bytes })")
        .unwrap();
    let driver_retired_end = driver_retired_start
        + driver[driver_retired_start..]
            // F3A.6h split `RegistryLost` in two; this is a span delimiter,
            // so it tracks whichever arm now comes first.
            .find("ResidentPollEvent::RegistryControlLost")
            .unwrap();
    let driver_retired = &driver[driver_retired_start..driver_retired_end];
    for operation in [
        "RecoveryOperation::DriverRetired",
        "RecoveryOperation::RebindPublication",
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
        "RecoveryOperation::RetireDependents",
        "RecoveryOperation::ReapDriver",
        "RecoveryOperation::AcknowledgeReaped",
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

/// R7B-1's invariant: a recovery episode's budget never outlives the trigger
/// that opened it.
///
/// The deadline became ordinary supervision state while the trigger stayed
/// selector-gated, which put the two in separate fields. Clearing only the
/// trigger would leave a deadline nothing owns, and `recovery_deadline_expired`
/// would then start failing ordinary legs against a window that had already
/// closed. During the split one abandon site -- the rollback taken when the
/// ACCEPTED reply cannot be sent -- did exactly that, and no test caught it.
/// So pin the shape instead of the symptom: both fields are written in exactly
/// one place each outside construction, and that place is the helper.
#[test]
fn a_recovery_episodes_budget_is_cleared_with_the_trigger_that_opened_it() {
    assert_eq!(JOBS.matches("self.e8_trigger = None;").count(), 1);
    assert_eq!(JOBS.matches("self.recovery_deadline = None;").count(), 1);
    let close = JOBS
        .find("fn close_recovery_episode(&mut self) {")
        .expect("the episode still ends in one helper");
    let body = &JOBS[close..close + JOBS[close..].find("\n    }\n").unwrap()];
    assert!(body.contains("self.e8_trigger = None;"));
    assert!(body.contains("self.recovery_deadline = None;"));

    // No other site may clear either half on its own.
    for stray in [".e8_trigger = None", ".recovery_deadline = None"] {
        assert_eq!(
            JOBS.matches(stray).count(),
            1,
            "an abandon site clears {stray} outside close_recovery_episode"
        );
    }
}

/// F3A.6c: widening the tick-failure word must not move any existing status.
///
/// Every error that carries no payload has to encode exactly what it encoded
/// before the payload nibbles existed, because
/// `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` requires E8's failure statuses to stay
/// identical to the A27 baseline. This asserts that by value rather than by
/// reading the expression, which is what the substring check above could not
/// do.
#[test]
fn a_payload_free_tick_failure_status_is_unchanged_by_the_widening() {
    use wyrmroot_system_init::{
        InitError, decode_tick_failure, resident_tick_failure_application_status as status,
    };

    // The four baseline kinds the A27/E8 table pins, unattributed.
    for (error, expected) in [
        (InitError::WrongActivationOrder, 0xAF18_0F01_u32),
        (InitError::Accounting, 0xAF18_0F02),
        (InitError::Supervision, 0xAF18_0F03),
        (InitError::Cleanup, 0xAF18_0F04),
    ] {
        assert_eq!(status(&error), expected);
        let decoded = decode_tick_failure(expected).expect("a baseline status decodes");
        assert_eq!(decoded.instance, 0);
        assert_eq!(
            (decoded.operation, decoded.kind),
            (0x0f, expected as u8 & 0x0f)
        );
    }
}
