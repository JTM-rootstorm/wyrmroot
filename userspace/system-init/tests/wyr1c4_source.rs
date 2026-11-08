use deepwyrm_syscall as _;
use wyrmroot_bootfs as _;
use wyrmroot_device_proto as _;
use wyrmroot_devmgr as _;
#[cfg(feature = "dw1e3-selector31")]
use wyrmroot_dw1e3_com2_test as _;
use wyrmroot_launch_proto as _;
use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_registryd as _;
use wyrmroot_rrc_manifest as _;
use wyrmroot_runtime as _;
use wyrmroot_system_init as _;
use wyrmroot_uart16550d as _;
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

/// Reversed by `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.3 item 2. The driver's
/// attempt TaskGroup used to be a child of the devmgr generation that
/// requested it, so tearing that generation down took the driver with it --
/// which contradicts [B] §5.4's promise that the recovery console stays usable
/// exactly when automatic reconstruction has failed. It is now parented under
/// init's own authority, and only `reap_driver`'s explicit termination by
/// handle stops it. It moves up one level, to the resource domain itself, not
/// out to init's bootstrap group: `WYR1_C_DEVICE_HANDOFF_CONTRACT.md` §4 makes
/// domain teardown terminal recovery for the boot, and a driver holding a
/// DeviceResource outside the domain would survive it.
#[test]
fn c5_driver_attempt_is_parented_under_init_not_the_devmgr_generation() {
    assert!(MANIFEST.contains("wyr1c5-production = [\"native-init\"]"));
    let construct = &NATIVE_SOURCE[NATIVE_SOURCE.find("fn construct_driver").unwrap()..];
    let parent = construct
        .find(".and_then(|state| state.resource_domain)")
        .unwrap();
    let create = construct
        .find("create_attempt_task_group(driver_parent)")
        .unwrap();
    let load = construct.find("load_device_driver_process(").unwrap();
    assert!(parent < create && create < load);
    assert!(!construct[..create].contains("driver_parent = devmgr.task_group"));
}

#[test]
fn c6_terminal_facts_are_init_owned_and_bound_to_real_predicates() {
    // devmgr's role moved from `main.rs` to `role.rs` in S2U step 3; read both.
    let devmgr = concat!(
        include_str!("../../devmgr/src/main.rs"),
        include_str!("../../devmgr/src/role.rs")
    );
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

/// The text of `fn name`, up to its closing brace at column 0.
fn native_fn(name: &str) -> &'static str {
    let start = NATIVE_SOURCE
        .find(&format!("fn {name}"))
        .unwrap_or_else(|| panic!("missing fn {name}"));
    let end = NATIVE_SOURCE[start..].find("\n}\n").unwrap() + start;
    &NATIVE_SOURCE[start..end]
}

/// The text of one match arm of `body`, from `start` to the next `end`.
fn arm<'a>(body: &'a str, start: &str, end: &str) -> &'a str {
    let from = body
        .find(start)
        .unwrap_or_else(|| panic!("missing arm {start}"));
    let to = body[from..]
        .find(end)
        .unwrap_or_else(|| panic!("missing end {end}"))
        + from;
    &body[from..to]
}

fn in_order(text: &str, needles: &[&str]) {
    let mut at = 0;
    for needle in needles {
        at += text[at..]
            .find(needle)
            .unwrap_or_else(|| panic!("missing {needle} in order"))
            + needle.len();
    }
}

/// Selector 31's resident dispatch routes each probe and driver event to the
/// join that owns it. Source text, because the arms are inline in
/// `control_tick`, which no host fake drives in the selector-31 shape (it needs
/// a scripted multi-handle wait and receive); the joins themselves are
/// host-tested in `wyr1c_native::tests::selector31` (S3 rows 201-207).
#[test]
fn selector31_resident_dispatch_routes_each_probe_and_driver_event_to_its_join() {
    let tick = native_fn("control_tick<");
    in_order(
        tick,
        &[
            "if let Some(probe) = state.e3a_probe",
            "handle: probe.loaded.launch_channel",
            "DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0",
            "handle: probe.loaded.process",
            "signals: DW_SIGNAL_EXITED",
            "system.wait_many(",
        ],
    );
    in_order(
        arm(
            tick,
            "Ok(DevmgrControlInput::TransportEmpty(fact)) =>",
            "Ok(DevmgrControlInput::BindingReady",
        ),
        &[
            "exact_transport_empty(binding, fact)?",
            ".e3a_transport_empty = Some(fact);",
            "maybe_begin_e3a_retire(resident, system)",
        ],
    );
    in_order(
        arm(
            tick,
            "Ok(DevmgrControlInput::RetireStage1Ready(binding)) =>",
            "Ok(DevmgrControlInput::C6Fact",
        ),
        &[
            "!state.e3a_begin_retire_sent",
            "state.e3a_stage1_ready = true;",
            "send_e3a_finalize_retire(resident, system)",
        ],
    );
    in_order(
        arm(
            tick,
            "ResidentPollEvent::DriverExited =>",
            "ResidentPollEvent::ProbeControlReadable =>",
        ),
        &[
            "validate_e3a_u1_finalize_exit(resident, waits)",
            "let _request = reap_driver(resident, system, waits, false);",
            "reap_e3a_probe(resident, system, waits, true)?",
            "acknowledge_driver_reaped(",
        ],
    );
    let readable = arm(
        tick,
        "ResidentPollEvent::ProbeControlReadable =>",
        "ResidentPollEvent::ProbeControlLost =>",
    );
    in_order(
        readable,
        &[
            "E3AControllerMessage::ResponseCommitted",
            "state.e3a_response_committed = true;",
            "maybe_begin_e3a_retire(resident, system)",
            "E3AControllerMessage::StreamPeerClosed",
            "!state.e3a_response_committed",
            "Dw1e3ReportEvent::Driver1PeerClosed",
            ".e3a_peer_closed = true;",
            "send_e3a_finalize_retire(resident, system)",
        ],
    );
    for (event, end, validate) in [
        (
            "ResidentPollEvent::ProbeControlLost =>",
            "ResidentPollEvent::ProbeExited =>",
            "false",
        ),
        (
            "ResidentPollEvent::ProbeExited =>",
            "selector32::poll(",
            "true",
        ),
    ] {
        in_order(
            arm(tick, event, end),
            &[
                "if e3a_u2_probe_may_exit(resident)",
                "reap_e3a_u2_probe_after_response(resident, system, waits)",
                "fail_e3a_u2_probe_exit(resident, system, waits, error)",
                &format!("fail_e3a_probe_supervision(resident, system, waits, {validate})"),
            ],
        );
    }
    for recovery in ["recover_registry<", "recover_devmgr<"] {
        in_order(
            native_fn(recovery),
            &[
                "if let Some(child_cleanup_failed) = fail_closed_e3a_recovery(resident, system, waits)",
                "return finish_e3a_fatal_recovery(resident, system, waits, child_cleanup_failed);",
            ],
        );
    }
}
