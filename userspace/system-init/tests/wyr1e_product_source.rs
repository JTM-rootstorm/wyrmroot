use {
    deepwyrm_syscall as _, wyrmroot_bootfs as _, wyrmroot_device_proto as _, wyrmroot_devmgr as _,
    wyrmroot_launch_proto as _, wyrmroot_loader as _, wyrmroot_registry_proto as _,
    wyrmroot_registryd as _, wyrmroot_rrc_manifest as _, wyrmroot_runtime as _,
    wyrmroot_system_init as _, wyrmroot_uart16550d as _, wyrmroot_wyr1b_gate_proto as _,
};

const MANIFEST: &str = include_str!("../Cargo.toml");
const LIB: &str = include_str!("../src/lib.rs");
const MAIN: &str = include_str!("../src/main.rs");
const NATIVE: &str = include_str!("../src/wyr1c_native.rs");
const E6: &str = include_str!("../src/wyr1e_native.rs");
const SELECTOR32: &str = include_str!("../src/wyr1d_native.rs");
const JOBS: &str = include_str!("../src/wyr1b_native.rs");

/// Source assertions on call shape must survive rustfmt wrapping an argument
/// list, so compare calls with their layout removed.
fn without_whitespace(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

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
fn e6_feature_selects_the_shell_controller_without_selecting_selector32() {
    assert!(MANIFEST.contains(
        "wyr1e-production = [\"wyr1c6-production\", \"wyr1e-shell-controller\", \"dep:wyrmroot-consoled\", \"wyrmroot-consoled/wyr1e-wyrmsh\"]"
    ));
    assert!(
        LIB.contains("WYR1-E production and selector-only init policies are mutually exclusive")
    );
    assert!(MAIN.contains("feature = \"wyr1e-production\""));
    assert!(
        !MANIFEST
            .split("wyr1e-production = ")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .contains("wyr1d-selector32")
    );
}

#[test]
fn e6_manifest_admission_is_additive_and_historical_profiles_stay_retained() {
    let historical = &LIB[LIB.find("pub(crate) fn from_wyr1c_manifest").unwrap()
        ..LIB.find("fn from_manifest_with_profiles").unwrap()];
    assert!(historical.contains("StartupProfile::Retained"));
    assert!(historical.contains("pub(crate) fn from_wyr1e_manifest"));
    assert!(historical.contains("StartupProfile::Wyrmsh"));
    assert!(JOBS.contains("SystemInit::from_wyr1e_manifest(manifest)"));
    assert!(JOBS.contains("SystemInit::from_wyr1c_manifest(manifest)"));
}

#[test]
fn production_publication_sender_uses_v1_1_without_selecting_d5_control() {
    let imports = &NATIVE[..NATIVE.find("pub(crate) const MARKER_BYTES").unwrap()];
    assert!(imports.contains(
        "#[cfg(any(\n    test,\n    not(any(feature = \"wyr1d-selector32\", feature = \"wyr1e-production\"))\n))]\nuse wyrmroot_device_proto::controller::encode as encode_controller;"
    ));

    let selected = "#[cfg(any(feature = \"wyr1d-selector32\", feature = \"wyr1e-production\"))]";
    let legacy = "#[cfg(not(any(feature = \"wyr1d-selector32\", feature = \"wyr1e-production\")))]";
    let encode_start = NATIVE
        .find(&format!("{selected}\nconst PUBLICATION_REQUEST_BYTES"))
        .unwrap();
    let encode = &NATIVE[encode_start..NATIVE.find("fn install_publication").unwrap()];
    assert!(encode.contains(&format!(
        "{selected}\nconst PUBLICATION_REQUEST_BYTES: usize = wyrmroot_device_proto::controller_v1_1::RECORD_BYTES;"
    )));
    assert!(encode.contains(&format!(
        "{legacy}\nconst PUBLICATION_REQUEST_BYTES: usize = wyrmroot_device_proto::controller::INSTALL_BYTES;"
    )));
    assert!(encode.contains(&format!(
        "{selected}\n    wyrmroot_device_proto::controller_v1_1::encode(\n        wyrmroot_device_proto::controller_v1_1::PublicationMessage {{\n            controller,\n            service_generation,"
    )));
    assert!(encode.contains(&format!(
        "{legacy}\n    {{\n        let _ = service_generation;\n        encode_controller(controller, &mut bytes)"
    )));
    assert!(!encode.contains("d5_controller"));

    assert!(
        NATIVE.contains("#[cfg(feature = \"wyr1d-selector32\")]\n#[path = \"wyr1d_native.rs\"]")
    );
}

#[test]
fn console_launcher_is_installed_before_consoled_can_send_shell_v1() {
    let launch = &E6
        [E6.find("fn launch_console").unwrap()..E6.find("fn clear_publication_observer").unwrap()];
    let install = launch.find("LaunchSessionScope::ConsoleLauncher").unwrap();
    let load = launch.find("load_consoled_process(").unwrap();
    let owner = launch.find("attach_session_owner(").unwrap();
    assert!(install < load && load < owner);
    assert!(launch.contains("ConsoledLoadRequest"));
    assert!(!launch.contains("wyr1d-selector32"));
}

#[test]
fn selector33_observes_only_the_validated_current_serial_publication() {
    let observer = &E6[E6.find("fn poll_publication_observer_state").unwrap()
        ..E6.find("fn poll_publication_observer<S, W>").unwrap()];
    let datagram = observer.find("validate_publication_datagram(").unwrap();
    let current = observer
        .find("current.request != observer.expected_driver")
        .unwrap();
    let hook = observer.find("e6.shell.observe_serial_for_e7(").unwrap();
    let cleanup = observer.rfind("clear_publication_observer(").unwrap();
    assert!(datagram < current && current < hook && hook < cleanup);
    assert!(
        observer.contains(
            "#[cfg(feature = \"wyr1e-selector33\")]\n    e6.shell.observe_serial_for_e7("
        )
    );
    assert_eq!(E6.matches("observe_serial_for_e7(").count(), 1);
}

#[test]
fn resident_services_shell_v1_before_waiting_for_consoled_ready() {
    // The console readiness/exit wait admission now lives in
    // `poll_console_event`. The property is that the resident services the
    // shell-v1 dispatcher before it admits that wait, not that the wait is
    // written inline in `poll`.
    let console_event =
        &E6[E6.find("fn poll_console_event").unwrap()..E6.find("pub(super) fn poll<").unwrap()];
    assert!(console_event.contains("system.wait_many("));

    let poll = item(E6, "pub(super) fn poll<");
    // A re-inlined console wait could sit ahead of the dispatcher without
    // disturbing the ordering below, so `poll` must keep delegating it.
    assert!(!poll.contains("system.wait_many("));
    let dispatch = poll.find("poll_job_dispatcher_with_shell(").unwrap();
    let wait = poll.find("poll_console_event(").unwrap();
    assert!(dispatch < wait);

    // The publication gate is the only step `poll` runs before the dispatcher.
    // Its wait carries a zero deadline, so it cannot stall a queued shell-v1
    // request either.
    let gate = &E6[E6.find("fn poll_publication_observer_state").unwrap()
        ..E6.find("fn poll_publication_observer<S, W>").unwrap()];
    assert!(poll.find("poll_publication_observer(").unwrap() < dispatch);
    assert!(gate.contains("system.wait_many(core::slice::from_ref(&item), DwDeadline(now))"));

    assert!(poll.contains("ShellLaunchContext"));
    assert!(poll.contains("LaunchProfile::Consoled"));
    assert!(poll.contains("bootstrap_released = true"));
    assert!(poll.contains("now >= e6.ready_deadline"));
    assert!(poll.contains("validated_at >= e6.ready_deadline"));
}

#[test]
fn registry_and_devmgr_recovery_retire_dependents_before_replacement() {
    let registry = item(NATIVE, "fn recover_registry");
    let retire = registry.find("wyr1e::retire_dependents").unwrap();
    // The `_before` variants are the same retirement and the same topology
    // restart, carrying the E8 action deadline as a cap.
    let poison = registry.find("poison_registry_generation_before(").unwrap();
    let reserve = registry
        .find("wyr1e::reserve_registry_replacement")
        .unwrap();
    let restart = registry.find("restart_topology_or_poison_before(").unwrap();
    let commit = registry.find("wyr1e::commit_registry_replacement").unwrap();
    let relaunch = registry.find("start_wyr1e_or_recover_registry(").unwrap();
    assert!(retire < poison && poison < reserve && reserve < restart);
    assert!(restart < commit && commit < relaunch);
    // The E8 wyr1e8-recovery branch retires the same generation from the
    // same position, after dependent retirement and before any replacement.
    let e8_retire = registry
        .find("retire_registry_for_recovery_before(")
        .unwrap();
    assert!(retire < e8_retire && e8_retire < reserve);
    // Relaunch is one hop away: the helper starts the console and re-enters
    // registry recovery only when that start fails.
    let relaunch_helper = item(NATIVE, "fn start_wyr1e_or_recover_registry<S");
    assert!(relaunch_helper.contains("wyr1e::start_after_driver_constructed"));

    // The devmgr path keeps that ordering, but both halves are now conditional
    // on the retention introduced by `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md`
    // §5.3.1 item 4: a coordinator change leaves the device topology beneath it
    // alone while anything still consumes the stream it established.
    let devmgr = &NATIVE[NATIVE.find("fn recover_devmgr<S").unwrap()
        ..NATIVE.find("fn retire_retained_device_topology").unwrap()];
    let retained = devmgr
        .find("let retained_device_topology = wyr1e::console_depends_on_driver(resident);")
        .unwrap();
    let retire = devmgr.find("wyr1e::retire_dependents").unwrap();
    // `reap_driver` is a prefix of `reap_driver_before`; anchor on the call.
    let reap = devmgr.find("reap_driver(").unwrap();
    assert!(retained < retire && retire < reap);
    // Neither half may run unconditionally any more.
    assert!(devmgr[..retire].ends_with(
        "if !retained_device_topology
        && "
    ));
    assert!(devmgr[..reap].contains(
        "if !retained_device_topology
        && resident"
    ));

    // What was retained is torn down when a replacement generation is READY,
    // not skipped: ordinary devmgr recovery ends where it always did.
    let deferred = item(NATIVE, "fn retire_retained_device_topology<S, W>");
    assert!(deferred.contains("if !wyr1e::console_depends_on_driver(resident)"));
    assert!(deferred.contains("wyr1e::retire_dependents(resident, system, waits, false)"));
    assert!(deferred.contains("reap_driver(resident, system, waits, true)"));
    let replacement = item(NATIVE, "fn launch_devmgr_replacement<S, L, W>");
    let teardown = replacement
        .find("retire_retained_device_topology(resident, system, waits)?;")
        .unwrap();
    let install = replacement
        .find("state.devmgr = Some(attempt.active);")
        .unwrap();
    assert!(teardown < install);
}

#[test]
fn targeted_console_retirement_preserves_the_dispatcher_for_orphan_reaping() {
    // `retire_console_product` only delegates now. Assert the entry point and
    // the body that does the work against their own spans, so neither is
    // proven by a slice that runs past the function it names.
    let entry = &JOBS[JOBS
        .find("pub(crate) fn retire_console_product<S, W>")
        .unwrap()
        ..JOBS
            .find("pub(crate) fn retire_console_product_with_result<S, W>")
            .unwrap()];
    assert!(entry.contains("retire_console_product_inner("));

    let inner = &JOBS[JOBS.find("fn retire_console_product_inner<S, W>").unwrap()
        ..JOBS.find("fn drain_job_dispatcher").unwrap()];
    assert!(inner.contains("loaded_job_for_owner"));
    assert!(inner.contains("disconnect_owned_session"));
    // `cleanup_shell_before_publication` is a prefix of the deadline-capped
    // variant this path actually calls.
    assert!(inner.contains("cleanup_shell_before_publication_before("));

    // The shared drain reaps orphans owned by other sessions, so no entry point
    // in the retirement family may reach it.
    let family = &JOBS[JOBS
        .find("pub(crate) fn retire_console_product<S, W>")
        .unwrap()..JOBS.find("fn drain_job_dispatcher").unwrap()];
    assert!(!family.contains("drain_job_dispatcher("));
}

#[test]
fn console_relaunch_is_finite_and_registry_replacement_is_the_only_budget_reset() {
    assert!(E6.contains("console_launch_attempts"));
    assert!(E6.contains("WYR0_I_SUPERVISION_POLICY.max_attempts"));
    let transaction = &E6[E6.find("fn take_console_transaction").unwrap()
        ..E6.find("fn commit_registry_replacement").unwrap()];
    assert!(!transaction.contains("console_launch_attempts = 0"));
    let replacement = &E6[E6.find("fn commit_registry_replacement").unwrap()
        ..E6.find("pub(super) fn start_after_driver_constructed")
            .unwrap()];
    assert!(replacement.contains("console_launch_attempts = 0"));

    assert!(NATIVE.contains("let outcome = wyr1e::poll(resident"));
    assert!(NATIVE.contains("wyr1e::PollOutcome::RecoverRegistry =>"));
    // `recover_registry` gained an E8-quiescence argument and the call is now
    // wrapped, so compare the call shape instead of one formatted line.
    // Ordinary recovery passes `status_already_consumed = false`, so the
    // replacement still awaits WRCS status, and `_e8_quiesced = false`.
    let native = without_whitespace(NATIVE);
    assert!(native.contains(
        "wyr1e::PollOutcome::RecoverRegistry=>recover_registry(resident,system,loader,waits,bootfs,false,false"
    ));
    assert!(native.contains(
        "wyr1e::PollOutcome::RecoverRegistryForE8=>recover_registry(resident,system,loader,waits,bootfs,false,true"
    ));
}

#[test]
fn selector32_resident_remains_on_historical_launch_and_gate_paths() {
    assert!(SELECTOR32.contains("d5.jobs.install_session(launch_grant, launch_endpoint)"));
    assert!(SELECTOR32.contains("poll_job_dispatcher(system, loader, waits"));
    assert!(SELECTOR32.contains("Status::configure(d5.gate.nonce())"));
    assert!(!SELECTOR32.contains("poll_job_dispatcher_with_shell"));
    assert!(!SELECTOR32.contains("LaunchSessionScope::ConsoleLauncher"));
}

/// Contract §11 item 4, the dispatcher half: ordinary `exit` and fresh-shell
/// construction keep working under DEGRADED.
///
/// The console/shell supervisor consults the supervisor's mode nowhere. That
/// is the whole reason shell continuity survives a degraded episode, and it is
/// exactly the kind of property that regresses silently when someone adds a
/// well-meaning mode gate -- so it is pinned by absence, deliberately.
/// `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.4 also forbids the converse: a
/// replacement shell must not restore NORMAL, which no code here could do
/// because none of it can reach the mode.
#[test]
fn the_console_and_shell_supervisor_never_reads_or_writes_the_supervisor_mode() {
    for (name, source) in [
        ("wyr1e_native.rs", E6),
        ("wyr1b_job.rs", include_str!("../src/wyr1b_job.rs")),
    ] {
        assert!(
            !source.contains("SystemMode"),
            "{name} must not reach the supervisor mode: shell continuity under \
             DEGRADED depends on the job dispatcher and the shell launch path \
             being mode-blind, and a replacement shell must not be able to \
             restore NORMAL"
        );
    }

    // The dispatcher leg of `poll` is unconditional apart from the E8
    // evidence-adjacency gate, which is a selector's and is not the mode.
    let poll = item(E6, "pub(super) fn poll<S, L, W>");
    assert!(poll.contains("let poll_shell_jobs = true;"));
    let gate = poll.find("if poll_shell_jobs {").unwrap();
    let dispatch = poll.find("poll_job_dispatcher_with_shell(").unwrap();
    assert!(gate < dispatch);
}

/// F3A.6: a fatally failed bring-up must not discard its own evidence.
///
/// The ordinary drain is gated on `evidence_finalized()`, and a tick that
/// returns an error never finalizes, so before this every record produced
/// before a fatal failure was thrown away and COM1 carried one error class and
/// nothing else. The first three F3A boots were diagnosed from that alone.
///
/// The assertion is positional rather than a bare substring. A substring test
/// would stay green if the drain were moved out of the failure arm, or if a
/// `return` were inserted above it -- which is exactly how this guard would be
/// lost.
#[test]
fn a_fatal_control_tick_submits_its_evidence_before_reporting_the_failure() {
    let arm_start = MAIN
        .find("if let Err(error) = resident.control_tick_product(system, loader, waits, now) {")
        .expect("the resident tick failure arm");
    let report = "return resident_tick_failure_application_status(&error);";
    let report_offset = MAIN[arm_start..]
        .find(report)
        .map(|offset| arm_start + offset)
        .expect("the tick failure status report");
    let arm = &MAIN[arm_start..report_offset];

    // The drain sits inside the failure arm, ahead of the status report.
    assert!(arm.contains("#[cfg(feature = \"wyr1-test-evidence\")]"));
    assert!(arm.contains("if !evidence_submitted {"));
    assert!(arm.contains("resident.controller().evidence_line(index)"));
    assert!(arm.contains("wyrmroot_runtime::submit_wyr1_evidence(record)"));
    assert!(arm.contains("evidence_submitted = true;"));

    // Nothing may return before the drain runs, or the arm is dead code.
    assert!(
        !arm.contains("return "),
        "a return above the fatal evidence drain makes it unreachable"
    );

    // A submission failure must not replace the status that explains the run.
    assert!(arm.contains("let _ = wyrmroot_runtime::submit_wyr1_evidence(record);"));

    // The ordinary finalized drain still exists, after the failure arm.
    let ordinary = &MAIN[report_offset..];
    assert!(ordinary.contains("if resident.evidence_finalized() && !evidence_submitted {"));
}
