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

/// The C4 product receives four capabilities under the resource-domain
/// profile and keeps the fourth as the domain's custody; the historical
/// product stays on the three-capability profile.
///
/// Source text because both product entries start with the bootstrap
/// receive and capability checks, and no host fake passes them (`MockNative`
/// fails the first query). Scoped to each activation fn's body.
#[test]
fn c4_product_selects_only_the_four_capability_resource_profile() {
    assert!(MANIFEST.contains("wyr1c4-production = [\"native-init\"]"));
    assert!(MAIN_SOURCE.contains("continue_system_init_resource_product"));
    let receive = lib_fn("receive_and_activate_resource_product_in_place<");
    assert!(receive.contains("let mut handles = [DwReceivedHandleInfoV1::default(); 4]"));
    let resource = lib_fn("activate_received_resource_product_in_place<");
    assert!(
        resource
            .contains("parse_init(LaunchProfile::SupervisorResourceDomain, init_bytes, handles)")
    );
    assert!(resource.contains("let custody = ResourceDomainCustody::new(handles[3].handle);"));
    assert!(
        resource.contains(
            "Some(custody),\n                    LaunchProfile::SupervisorResourceDomain,"
        )
    );
    let historical = lib_fn("activate_received_product_in_place<");
    assert!(historical.contains("parse_init(LaunchProfile::Supervisor, init_bytes, handles)"));
    assert!(!historical.contains("SupervisorResourceDomain"));
}

/// The text of lib.rs's `fn name`, up to its closing brace at column 0.
fn lib_fn(name: &str) -> &'static str {
    let start = LIB_SOURCE
        .find(&format!("fn {name}"))
        .unwrap_or_else(|| panic!("missing fn {name}"));
    let end = LIB_SOURCE[start..].find("\n}\n").unwrap() + start;
    &LIB_SOURCE[start..end]
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

/// Every devmgr generation's TaskGroup is created under the retained
/// resource-domain custody, and the replacement loop passes that custody on.
///
/// Source text because no host fake creates an attempt TaskGroup (both
/// `RebindPlatform` and `ControlInputPlatform` refuse it), so `launch_devmgr`
/// never reaches its parentage on the host. Scoped to `launch_devmgr` and
/// `launch_devmgr_replacement`.
#[test]
fn every_c4_devmgr_generation_is_parented_under_retained_custody() {
    let launch = native_fn("launch_devmgr<");
    let parent = launch
        .find(
            "let task_group_parent = resource_domain\n        .map(ResourceDomainCustody::handle)",
        )
        .unwrap();
    let create = launch
        .find(".create_attempt_task_group(task_group_parent)")
        .unwrap();
    assert!(parent < create);
    let claim = launch
        .find("ResourceDomainMembership::DevmgrGenerationDescendant")
        .unwrap();
    let load = launch
        .find("load_device_coordinator_resource_process(")
        .unwrap();
    assert!(create < claim && claim < load);
    assert!(launch.contains("LaunchProfile::DeviceCoordinatorResourceDomain"));
    assert!(launch.contains("StatusCode::OperationalResourceOwned"));

    let replacement = native_fn("launch_devmgr_replacement<");
    let custody = replacement.find("let resource_domain = resident").unwrap();
    let call = replacement.find("launch_devmgr(").unwrap();
    assert!(custody < call);
    assert!(replacement[call..].contains("resource_domain,"));
}

/// The device manifest is materialized with transfer rights so the move can
/// stage, and the child receives it without delegation.
///
/// Source text: the rights constants and `transfer()` live in
/// wyrmroot-loader, outside this lane's paths, so their host test belongs to
/// that crate; init's own use is in `launch_devmgr`, which no host fake
/// reaches (it refuses the TaskGroup). Scoped to `launch_devmgr`.
#[test]
fn c4_manifest_move_stages_transfer_without_delegating_it() {
    assert!(
        native_fn("launch_devmgr<")
            .contains("manifest_bytes,\n            DEVICE_MANIFEST_TRANSFER_RIGHTS,")
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
///
/// Source text because no host fake creates an attempt TaskGroup, so
/// `construct_driver` never reaches its parentage on the host. Scoped to
/// `construct_driver`'s body.
#[test]
fn c5_driver_attempt_is_parented_under_init_not_the_devmgr_generation() {
    assert!(MANIFEST.contains("wyr1c5-production = [\"native-init\"]"));
    let construct = native_fn("construct_driver<");
    let parent = construct
        .find(".and_then(|state| state.resource_domain)")
        .unwrap();
    let create = construct
        .find("create_attempt_task_group(driver_parent)")
        .unwrap();
    let load = construct.find("load_device_driver_process(").unwrap();
    assert!(parent < create && create < load);
    // The domain's own handle, falling back to init's group only when the
    // build has no domain.
    assert!(
        construct[parent..create]
            .contains(".map_or(resident.authority.task_group, ResourceDomainCustody::handle);")
    );
    assert!(!construct[..create].contains("driver_parent = devmgr.task_group"));
}

/// Selector 29's terminal facts are emitted by init, from its own predicates.
///
/// Source text because `emit_c6_terminal_facts` runs only from
/// `accept_c6_fact`'s event 22, and no host fixture builds a selector-29
/// resident holding a D2 lease and a C6 evidence log. Scoped to the two fns.
#[test]
fn c6_terminal_facts_are_init_owned_and_bound_to_real_predicates() {
    // devmgr's role moved from `main.rs` to `role.rs` in S2U step 3; read both.
    let devmgr = concat!(
        include_str!("../../devmgr/src/main.rs"),
        include_str!("../../devmgr/src/role.rs")
    );
    let accept = native_fn("accept_c6_fact(");
    assert!(accept.contains("if fact.event == 22 {\n        emit_c6_terminal_facts(resident)?;"));
    assert!(!devmgr.contains("emit_selector29_final_facts"));
    let emit = native_fn("emit_c6_terminal_facts(");
    for predicate in [
        "c6_startup_profiles_exclude_direct_device_authority()",
        ".devmgr_claim_authority(ResourceDomainMembership::InitOutsideDomain)",
        "|| !state.c6_gate_config.physical_io_not_performed",
        ".role_failure_count(RoleId::Devmgr)",
        "WYR0_I_SUPERVISION_POLICY.max_attempts",
        "WYR0_I_SUPERVISION_POLICY.backoff_ns",
    ] {
        assert!(emit.contains(predicate), "{predicate}");
    }
}

/// The WRDM UART identity is joined to the one the retained WRRM validation
/// produced. The comparison itself is host-tested by
/// `wrdm_uart_identity_must_match_the_independent_wrrm_identity`
/// (wyr1c_native.rs); this holds which value reaches it.
///
/// Source text because `activate_in_place` is reached only from the product
/// entry, which no host fake drives. Scoped to `validate_retained_bootfs_c1`
/// and `activate_in_place`.
#[test]
fn c6_joins_wrdm_to_the_validated_retained_uart_identity() {
    let start = RETAINED_SOURCE
        .find("pub(crate) fn validate_retained_bootfs_c1(")
        .unwrap();
    let end = RETAINED_SOURCE[start..].find("\n}\n").unwrap() + start;
    let retained = &RETAINED_SOURCE[start..end];
    let identity = retained.find("let uart_identity = *manifest").unwrap();
    assert!(
        retained[identity..]
            .starts_with("let uart_identity = *manifest\n        .role(RoleId::Uart16550d)")
    );
    assert!(retained.ends_with("Ok((controller, uart_identity))"));
    let activate = native_fn("activate_in_place<");
    let validated = activate
        .find(
            "let (manifest, uart_identity) = crate::wyr1b_native::validate_retained_bootfs_c1(bootfs)?;",
        )
        .unwrap();
    let joined = activate
        .find("validate_device_identity(device_manifest, uart_identity)?;")
        .unwrap();
    assert!(validated < joined);
    assert!(!activate.contains("executable_identity(RoleId::Uart16550d)"));
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
