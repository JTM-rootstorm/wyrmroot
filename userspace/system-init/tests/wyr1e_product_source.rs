use {
    deepwyrm_syscall as _, wyrmroot_bootfs as _, wyrmroot_device_proto as _,
    wyrmroot_launch_proto as _, wyrmroot_loader as _, wyrmroot_registry_proto as _,
    wyrmroot_rrc_manifest as _, wyrmroot_runtime as _, wyrmroot_system_init as _,
    wyrmroot_wyr1b_gate_proto as _,
};

const MANIFEST: &str = include_str!("../Cargo.toml");
const LIB: &str = include_str!("../src/lib.rs");
const MAIN: &str = include_str!("../src/main.rs");
const NATIVE: &str = include_str!("../src/wyr1c_native.rs");
const E6: &str = include_str!("../src/wyr1e_native.rs");
const SELECTOR32: &str = include_str!("../src/wyr1d_native.rs");
const JOBS: &str = include_str!("../src/wyr1b_native.rs");

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
    let poll = &E6[E6.find("pub(super) fn poll").unwrap()
        ..E6.find("pub(super) fn retire_dependents").unwrap()];
    let dispatch = poll.find("poll_job_dispatcher_with_shell(").unwrap();
    let wait = poll.find("system.wait_many(").unwrap();
    assert!(dispatch < wait);
    assert!(poll.contains("ShellLaunchContext"));
    assert!(poll.contains("LaunchProfile::Consoled"));
    assert!(poll.contains("bootstrap_released = true"));
    assert!(poll.contains("now >= e6.ready_deadline"));
    assert!(poll.contains("validated_at >= e6.ready_deadline"));
}

#[test]
fn registry_and_devmgr_recovery_retire_dependents_before_replacement() {
    let registry = &NATIVE[NATIVE.find("fn recover_registry").unwrap()
        ..NATIVE.find("fn recover_devmgr_after_error").unwrap()];
    let retire = registry.find("wyr1e::retire_dependents").unwrap();
    let poison = registry.find("poison_registry_generation(").unwrap();
    let reserve = registry
        .find("wyr1e::reserve_registry_replacement")
        .unwrap();
    let restart = registry.find("restart_topology_or_poison(").unwrap();
    let commit = registry.find("wyr1e::commit_registry_replacement").unwrap();
    let relaunch = registry
        .rfind("wyr1e::start_after_driver_constructed")
        .unwrap();
    assert!(retire < poison && poison < reserve && reserve < restart);
    assert!(restart < commit && commit < relaunch);

    let devmgr = &NATIVE[NATIVE.find("fn recover_devmgr<S").unwrap()
        ..NATIVE.find("fn launch_devmgr_replacement").unwrap()];
    assert!(devmgr.find("wyr1e::retire_dependents").unwrap() < devmgr.find("reap_driver").unwrap());
}

#[test]
fn targeted_console_retirement_preserves_the_dispatcher_for_orphan_reaping() {
    let retire = &JOBS[JOBS.find("pub(crate) fn retire_console_product").unwrap()
        ..JOBS.find("fn drain_job_dispatcher").unwrap()];
    assert!(retire.contains("loaded_job_for_owner"));
    assert!(retire.contains("disconnect_owned_session"));
    assert!(retire.contains("cleanup_shell_before_publication"));
    assert!(!retire.contains("drain_job_dispatcher("));
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
    assert!(NATIVE.contains("recover_registry(resident, system, loader, waits, bootfs, false)"));
}

#[test]
fn selector32_resident_remains_on_historical_launch_and_gate_paths() {
    assert!(SELECTOR32.contains("d5.jobs.install_session(launch_grant, launch_endpoint)"));
    assert!(SELECTOR32.contains("poll_job_dispatcher(system, loader, waits"));
    assert!(SELECTOR32.contains("Status::configure(d5.gate.nonce())"));
    assert!(!SELECTOR32.contains("poll_job_dispatcher_with_shell"));
    assert!(!SELECTOR32.contains("LaunchSessionScope::ConsoleLauncher"));
}
