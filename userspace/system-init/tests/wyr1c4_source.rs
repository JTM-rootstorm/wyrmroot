use deepwyrm_syscall as _;
use wyrmroot_bootfs as _;
use wyrmroot_device_proto as _;
use wyrmroot_launch_proto as _;
use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_rrc_manifest as _;
use wyrmroot_runtime as _;
use wyrmroot_system_init as _;
use wyrmroot_wyr1b_gate_proto as _;

const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
const LIB_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
const MAIN_SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
const NATIVE_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/wyr1c_native.rs"));
const RETAINED_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/wyr1b_native.rs"));

#[test]
fn c4_product_selects_only_the_four_capability_resource_profile() {
    assert!(MANIFEST.contains("wyr1c4-production = [\"native-init\"]"));
    assert!(MAIN_SOURCE.contains("continue_system_init_resource_product"));
    assert!(LIB_SOURCE.contains("pub fn continue_system_init_resource_product"));
    assert!(LIB_SOURCE.contains("let mut handles = [DwReceivedHandleInfoV1::default(); 4]"));
    assert!(LIB_SOURCE.contains("LaunchProfile::SupervisorResourceDomain"));
    assert!(LIB_SOURCE.contains("ResourceDomainCustody::new(handles[3].handle)"));
    assert!(LIB_SOURCE.contains("LaunchProfile::Supervisor,"));
}

#[test]
fn c6_feature_composition_keeps_selector_29_on_the_resource_profile() {
    assert!(MANIFEST.contains("wyr1c6-production = [\"wyr1c5-production\"]"));
    assert!(
        MANIFEST.contains("wyr1c6-selector29 = [\"wyr1c6-production\", \"wyr1c6-test-evidence\"]")
    );
    assert!(
        MAIN_SOURCE.contains(
            "#[cfg(any(feature = \"wyr1c4-production\", feature = \"wyr1c5-production\"))]"
        )
    );
    assert!(MAIN_SOURCE.contains("continue_system_init_resource_product("));
}

#[test]
fn c6_resident_tick_leaves_time_for_the_ready_handshake() {
    let resident = &MAIN_SOURCE[MAIN_SOURCE.find("fn continue_resident(").unwrap()..];
    assert!(resident.contains("#[cfg(feature = \"wyr1c6-selector29\")]"));
    assert!(resident.contains("let tick_ns = WYR0_I_SUPERVISION_POLICY.backoff_ns;"));
    assert!(resident.contains("let tick_ns = 1_000_000_000;"));
    assert!(resident.contains("now.checked_add(tick_ns)"));
}

#[test]
fn native_wait_until_accepts_only_a_clock_verified_timeout_fallback() {
    let wait_until = &MAIN_SOURCE[MAIN_SOURCE.find("fn wait_until(").unwrap()
        ..MAIN_SOURCE
            .find("impl Wyr1BPlatform for NativeSystem")
            .unwrap()];
    assert!(wait_until.contains("DW_STATUS_TIMED_OUT"));
    assert!(wait_until.contains("monotonic_active_now()?"));
    assert!(wait_until.contains("validate_wait_until_completion("));
}

#[test]
fn every_c4_devmgr_generation_is_parented_under_retained_custody() {
    assert!(NATIVE_SOURCE.contains(".map(ResourceDomainCustody::handle)"));
    assert!(NATIVE_SOURCE.contains(".create_attempt_task_group(task_group_parent)"));
    assert!(NATIVE_SOURCE.contains("load_device_coordinator_resource_process("));
    assert!(NATIVE_SOURCE.contains("ResourceDomainMembership::DevmgrGenerationDescendant"));
    assert!(NATIVE_SOURCE.contains("LaunchProfile::DeviceCoordinatorResourceDomain"));
    assert!(NATIVE_SOURCE.contains("StatusCode::OperationalResourceOwned"));

    let replacement = NATIVE_SOURCE
        .split("fn launch_devmgr_replacement")
        .nth(1)
        .expect("devmgr replacement loop");
    assert!(replacement.contains("let resource_domain = resident"));
    assert!(replacement.contains("launch_devmgr("));
    assert!(replacement.contains("resource_domain,"));
}

#[test]
fn c4_manifest_move_stages_transfer_without_delegating_it() {
    assert!(NATIVE_SOURCE.contains("DEVICE_MANIFEST_TRANSFER_RIGHTS"));
    assert!(
        NATIVE_SOURCE.contains("manifest_bytes,\n            DEVICE_MANIFEST_TRANSFER_RIGHTS,")
    );
    let launch = include_str!("../../../crates/wyrmroot-loader/src/launch.rs");
    assert!(launch.contains("DwRights(DEVICE_MANIFEST_RIGHTS.0 | DW_RIGHT_TRANSFER.0)"));
    let process = include_str!("../../../crates/wyrmroot-loader/src/process.rs");
    assert!(process.contains("transfers[2] = transfer(manifest, launch::DEVICE_MANIFEST_RIGHTS);"));
}

#[test]
fn c5_driver_attempt_is_parented_under_the_current_devmgr_generation() {
    assert!(MANIFEST.contains("wyr1c5-production = [\"native-init\"]"));
    let construct = &NATIVE_SOURCE[NATIVE_SOURCE.find("fn construct_driver").unwrap()..];
    let parent = construct
        .find("let driver_parent = devmgr.task_group")
        .unwrap();
    let create = construct
        .find("create_attempt_task_group(driver_parent)")
        .unwrap();
    let load = construct.find("load_device_driver_process(").unwrap();
    assert!(parent < create && create < load);
    assert!(construct.contains("#[cfg(feature = \"wyr1c5-production\")]"));
}

#[test]
fn c6_terminal_facts_are_init_owned_and_bound_to_real_predicates() {
    let devmgr = include_str!("../../devmgr/src/main.rs");
    assert!(NATIVE_SOURCE.contains("emit_c6_terminal_facts(resident)"));
    assert!(!devmgr.contains("emit_selector29_final_facts"));
    assert!(NATIVE_SOURCE.contains("c6_startup_profiles_exclude_direct_device_authority"));
    assert!(NATIVE_SOURCE.contains("ResourceDomainMembership::InitOutsideDomain"));
    assert!(NATIVE_SOURCE.contains("physical_io_not_performed"));
    assert!(NATIVE_SOURCE.contains("role_failure_count(RoleId::Devmgr)"));
    assert!(NATIVE_SOURCE.contains("WYR0_I_SUPERVISION_POLICY.max_attempts"));
    assert!(NATIVE_SOURCE.contains("WYR0_I_SUPERVISION_POLICY.backoff_ns"));
}

#[test]
fn c6_joins_wrdm_to_the_validated_retained_uart_identity() {
    assert!(RETAINED_SOURCE.contains("let uart_identity = *manifest"));
    assert!(RETAINED_SOURCE.contains(".role(RoleId::Uart16550d)"));
    assert!(RETAINED_SOURCE.contains("Ok((controller, uart_identity))"));
    assert!(NATIVE_SOURCE.contains(
        "let (manifest, uart_identity) = crate::wyr1b_native::validate_retained_bootfs_c1(bootfs)?;"
    ));
    assert!(NATIVE_SOURCE.contains("validate_device_identity(device_manifest, uart_identity)?;"));
    assert!(!NATIVE_SOURCE.contains("manifest.executable_identity(RoleId::Uart16550d)"));
}

#[test]
fn selector31_controller_rejoins_response_temt_then_retires_u1_before_fresh_u2() {
    let response = NATIVE_SOURCE
        .find("E3AControllerMessage::ResponseCommitted")
        .unwrap();
    let temt = NATIVE_SOURCE
        .find("DevmgrControlInput::TransportEmpty(fact)")
        .unwrap();
    let begin = NATIVE_SOURCE.find("fn maybe_begin_e3a_retire").unwrap();
    let stage1 = NATIVE_SOURCE[temt..]
        .find("DevmgrControlInput::RetireStage1Ready")
        .unwrap()
        + temt;
    let closed = NATIVE_SOURCE
        .find("E3AControllerMessage::StreamPeerClosed")
        .unwrap();
    let report = NATIVE_SOURCE
        .find("Dw1e3ReportEvent::Driver1PeerClosed")
        .unwrap();
    let finalize = NATIVE_SOURCE.find("fn send_e3a_finalize_retire").unwrap();
    assert!(begin < temt && begin < response);
    assert!(temt < stage1 && stage1 < closed && closed < report);
    assert!(finalize < closed);
    assert!(NATIVE_SOURCE.contains("reap_e3a_probe(resident, system, waits, true)?"));
    assert!(NATIVE_SOURCE.contains("if !admit_u2 {"));
    assert!(NATIVE_SOURCE.contains("state.e3a_next_challenge_generation = 0;"));
    assert!(NATIVE_SOURCE.contains("} else if retired_generation == 1 {"));
    assert!(NATIVE_SOURCE.contains("state.e3a_next_challenge_generation = 2;"));
}

#[test]
fn selector31_u1_exit_requires_complete_finalize_state_and_zero_normal_exit() {
    let validate = NATIVE_SOURCE
        .find("fn validate_e3a_u1_finalize_exit")
        .unwrap();
    let body = &NATIVE_SOURCE[validate..];
    for requirement in [
        "!state.e3a_response_committed",
        "!state.e3a_begin_retire_sent",
        "!state.e3a_stage1_ready",
        "!state.e3a_peer_closed",
        "!state.e3a_finalize_retire_sent",
        "validate_successful_exit(&exit)",
    ] {
        assert!(body.contains(requirement), "missing {requirement}");
    }
    let exit = NATIVE_SOURCE
        .find("ResidentPollEvent::DriverExited =>")
        .unwrap();
    let gate = NATIVE_SOURCE[exit..]
        .find("validate_e3a_u1_finalize_exit(resident, waits)")
        .unwrap()
        + exit;
    let reap = NATIVE_SOURCE[exit..]
        .find("let _request = reap_driver")
        .unwrap()
        + exit;
    assert!(gate < reap);
}

#[test]
fn selector31_supervises_probe_channel_and_process_failure_without_advancement() {
    // The probe can die before C1 response, after stage1 but before its close
    // proof, or during U2.  All three paths share the same exact cleanup
    // fence: no lifecycle edge may turn such a death into a new admission.
    for required in [
        "ProbeControlLost",
        "ProbeExited",
        "DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0)",
        "handle: probe.loaded.process",
        "signals: DW_SIGNAL_EXITED",
        "fn fail_e3a_probe_supervision",
        "fn reap_e3a_u2_probe_after_response",
        "fn e3a_u2_probe_may_exit",
        "validate_successful_exit(&exit)",
        "reap_e3a_probe(resident, system, waits, false)",
        "reap_driver(resident, system, waits, true)",
        "state.e3a_next_challenge_generation = 0;",
    ] {
        assert!(NATIVE_SOURCE.contains(required), "missing {required}");
    }
    let lost = NATIVE_SOURCE
        .find("ResidentPollEvent::ProbeControlLost")
        .unwrap();
    let exited = NATIVE_SOURCE
        .find("ResidentPollEvent::ProbeExited")
        .unwrap();
    let failed = NATIVE_SOURCE.find("fail_e3a_probe_supervision").unwrap();
    let u2 = NATIVE_SOURCE
        .find("start_e3a_probe(resident, system, loader, waits, bootfs)")
        .unwrap();
    assert!(lost < u2 && exited < u2 && failed < u2);
    let u2_reap = NATIVE_SOURCE
        .find("reap_e3a_u2_probe_after_response(resident, system, waits)")
        .unwrap();
    let u2_failure = NATIVE_SOURCE[u2_reap..]
        .find("fail_e3a_probe_supervision(resident, system, waits")
        .unwrap()
        + u2_reap;
    assert!(u2_reap < u2_failure);
}

#[test]
fn selector31_drains_queued_u2_response_before_a_combined_peer_close_is_classified() {
    let classifier = NATIVE_SOURCE.find("fn classify_resident_poll").unwrap();
    let readable = NATIVE_SOURCE[classifier..]
        .find("Ok(ResidentPollEvent::ProbeControlReadable)")
        .unwrap()
        + classifier;
    let closed = NATIVE_SOURCE[classifier..]
        .find("Ok(ResidentPollEvent::ProbeControlLost)")
        .unwrap()
        + classifier;
    assert!(readable < closed);
    let response = NATIVE_SOURCE
        .find("E3AControllerMessage::ResponseCommitted")
        .unwrap();
    let u2_exit = NATIVE_SOURCE
        .find("e3a_u2_probe_may_exit(resident)")
        .unwrap();
    assert!(response < u2_exit);
    assert!(NATIVE_SOURCE.contains("combined READABLE|PEER_CLOSED wake"));
}

#[test]
fn selector31_u2_temt_join_is_the_only_terminal_claim_path() {
    let terminal = NATIVE_SOURCE
        .find("dw1e3_terminal_claim(binding.nonce)")
        .unwrap();
    let join = NATIVE_SOURCE[..terminal]
        .rfind("exact_transport_empty(")
        .unwrap();
    let response = NATIVE_SOURCE[..terminal]
        .rfind("if !response_committed || transport_empty.is_none()")
        .unwrap();
    assert!(response < join && join < terminal);
}
