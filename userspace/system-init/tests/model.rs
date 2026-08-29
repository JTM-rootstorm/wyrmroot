use deepwyrm_syscall::DwHandle;
use wyrmroot_bootfs::builder::{Builder as BootfsBuilder, FileMode};
use wyrmroot_device_proto as _;
use wyrmroot_launch_proto as _;
use wyrmroot_loader::launch::{self, HEADER_BYTES, LaunchProfile};
use wyrmroot_registry_proto as _;
use wyrmroot_rrc_manifest::{
    Activation, DependencyKind, Manifest, RoleId, StartupProfile,
    builder::{Builder, DependencySpec, RoleSpec},
};
use wyrmroot_runtime::{AttemptFailure, RestartState, TerminalDisposition};
use wyrmroot_system_init::{
    AttemptResources, InitError, REAP_CLASS_AUTHORIZED_TERMINATION, REAP_CLASS_NORMAL_EXIT,
    REAP_CLASS_TASK_GROUP_TEARDOWN, REAP_CLASS_UNHANDLED_EXCEPTION, RecoveryResult, SystemInit,
    SystemMode, observe_ready, reap_evidence_value,
};
use wyrmroot_wyr1b_gate_proto as _;

const BOOT: [u8; 32] = [0x42; 32];

fn manifest_bytes() -> Vec<u8> {
    manifest_bytes_with_early_paths("system/registryd", "system/devmgr")
}

fn manifest_bytes_with_early_paths(registry_path: &str, devmgr_path: &str) -> Vec<u8> {
    let mut builder = Builder::new(BOOT);
    for (id, path, activation, profile) in [
        (
            RoleId::Registryd,
            registry_path,
            Activation::Early,
            StartupProfile::EarlyBootStub,
        ),
        (
            RoleId::Devmgr,
            devmgr_path,
            Activation::Early,
            StartupProfile::EarlyBootStub,
        ),
        (
            RoleId::Uart16550d,
            "system/uart16550d",
            Activation::DeviceBound,
            StartupProfile::Retained,
        ),
        (
            RoleId::Consoled,
            "system/consoled",
            Activation::ConsoleBound,
            StartupProfile::Retained,
        ),
        (
            RoleId::Wyrmsh,
            "system/wyrmsh",
            Activation::ConsoleBound,
            StartupProfile::Retained,
        ),
    ] {
        builder
            .add_role(RoleSpec {
                id,
                required: true,
                requires_ready: true,
                activation,
                startup_profile: profile,
                path,
                justification: "fixed retained recovery closure",
                executable_identity: [id as u8; 32],
            })
            .unwrap();
    }
    for (owner, target) in [
        (RoleId::Devmgr, RoleId::Registryd),
        (RoleId::Uart16550d, RoleId::Devmgr),
        (RoleId::Consoled, RoleId::Uart16550d),
        (RoleId::Wyrmsh, RoleId::Consoled),
    ] {
        builder
            .add_dependency(DependencySpec {
                owner,
                kind: DependencyKind::RoleReady,
                target_role: Some(target),
                target_path: None,
            })
            .unwrap();
    }
    builder.build_structural().unwrap()
}

#[test]
fn manifest_role_path_drift_is_rejected_before_activation() {
    let bytes = manifest_bytes_with_early_paths("system/registryd-v2", "system/devmgr");
    let manifest = Manifest::parse_structural(&bytes, &BOOT).unwrap();
    assert_eq!(
        SystemInit::from_manifest(manifest),
        Err(InitError::WrongManifestProfile)
    );
}

#[test]
fn manifest_role_path_substitution_is_rejected_before_activation() {
    let bytes = manifest_bytes_with_early_paths("system/devmgr", "system/registryd");
    let manifest = Manifest::parse_structural(&bytes, &BOOT).unwrap();
    assert_eq!(
        SystemInit::from_manifest(manifest),
        Err(InitError::WrongManifestProfile)
    );
}

fn system() -> SystemInit {
    let bytes = manifest_bytes();
    let manifest = Manifest::parse_structural(&bytes, &BOOT).unwrap();
    SystemInit::from_manifest(manifest).unwrap()
}

fn resources(
    init: &mut SystemInit,
    role: RoleId,
    generation: u64,
    transaction: u64,
) -> AttemptResources {
    AttemptResources {
        role,
        generation,
        transaction_id: transaction,
        executable_identity: [role as u8; 32],
        startup_profile: StartupProfile::EarlyBootStub,
        task_group: DwHandle(100 + generation),
        process: DwHandle(200 + generation),
        launch_channel: DwHandle(300 + generation),
        mappings: 3,
        reservation: init.reserve_attempt(role, generation, transaction).unwrap(),
    }
}

fn start_role(init: &mut SystemInit, role: RoleId, generation: u64, transaction: u64, now: u64) {
    let resources = resources(init, role, generation, transaction);
    init.install_attempt(resources).unwrap();
    init.child_started(role, generation, transaction, now + 1)
        .unwrap();
}

#[test]
fn exact_registry_then_devmgr_ready_reaches_normal_without_activating_retained_roles() {
    let mut init = system();
    init.become_operational().unwrap();
    assert_eq!(init.mode(), SystemMode::SupervisorOperational);
    init.begin_registry(0, 1, 10).unwrap();
    start_role(&mut init, RoleId::Registryd, 1, 10, 0);
    init.ready(RoleId::Registryd, 1, 10, 2).unwrap();
    assert!(matches!(
        init.role_state(RoleId::Devmgr),
        Some(RestartState::Starting {
            generation: 1,
            transaction_id: 11,
            ..
        })
    ));
    assert_eq!(init.role_state(RoleId::Uart16550d), None);
    assert_eq!(
        init.reserve_attempt(RoleId::Wyrmsh, 1, 1),
        Err(InitError::UnlaunchableRole)
    );
    start_role(&mut init, RoleId::Devmgr, 1, 11, 2);
    init.ready(RoleId::Devmgr, 1, 11, 5).unwrap();
    assert_eq!(init.mode(), SystemMode::Normal);
    init.terminal(
        RoleId::Registryd,
        1,
        10,
        6,
        TerminalDisposition::NormalExit(0),
    )
    .unwrap();
    init.cleanup_complete(RoleId::Registryd, 1, 10, 7).unwrap();
    init.terminal(RoleId::Devmgr, 1, 11, 6, TerminalDisposition::NormalExit(0))
        .unwrap();
    assert_eq!(init.mode(), SystemMode::Normal);
    init.cleanup_complete(RoleId::Devmgr, 1, 11, 7).unwrap();
    assert_eq!(init.mode(), SystemMode::Normal);
    assert_eq!(init.result(), Some(RecoveryResult::Recovered));
}

#[test]
fn registry_retry_admits_devmgr_only_after_replacement_ready() {
    let mut init = system();
    init.become_operational().unwrap();
    init.begin_registry(0, 1, 10).unwrap();
    start_role(&mut init, RoleId::Registryd, 1, 10, 0);
    init.terminal(
        RoleId::Registryd,
        1,
        10,
        3,
        TerminalDisposition::NormalExit(7),
    )
    .unwrap();
    init.cleanup_complete(RoleId::Registryd, 1, 10, 4).unwrap();
    let RestartState::Backoff { deadline_ns, .. } = init.role_state(RoleId::Registryd).unwrap()
    else {
        panic!("expected registry retry backoff")
    };
    init.start_replacement(RoleId::Registryd, deadline_ns, 2, 11)
        .unwrap();
    start_role(&mut init, RoleId::Registryd, 2, 11, deadline_ns);
    assert_eq!(init.role_state(RoleId::Devmgr), Some(RestartState::Stopped));
    init.ready(RoleId::Registryd, 2, 11, deadline_ns + 2)
        .unwrap();
    assert!(matches!(
        init.role_state(RoleId::Devmgr),
        Some(RestartState::Starting {
            generation: 2,
            transaction_id: 12,
            ..
        })
    ));
}

#[test]
fn process_existence_never_substitutes_for_exact_profile_ready() {
    let mut init = system();
    init.become_operational().unwrap();
    init.begin_registry(0, 1, 10).unwrap();
    start_role(&mut init, RoleId::Registryd, 1, 10, 0);
    assert_eq!(init.mode(), SystemMode::ActivatingEarlyRoles);
    let mut ready = [0; HEADER_BYTES];
    launch::encode_ready_for_profile(LaunchProfile::EarlyBootStub, 10, &mut ready).unwrap();
    assert_eq!(observe_ready(&ready, 0, 10), Ok(()));
    assert_eq!(
        observe_ready(&ready, 0, 11),
        Err(AttemptFailure::WrongTransactionReady)
    );
    ready[6] = 1;
    assert_eq!(
        observe_ready(&ready, 0, 10),
        Err(AttemptFailure::MalformedReady)
    );
    assert_eq!(
        observe_ready(&ready, 1, 10),
        Err(AttemptFailure::MalformedReady)
    );
}

#[test]
fn four_failed_attempts_reap_exact_resources_and_degrade_once() {
    let mut init = system();
    init.become_operational().unwrap();
    init.begin_registry(0, 1, 10).unwrap();
    let mut now = 0;
    for attempt in 0..4_u64 {
        let generation = attempt + 1;
        let transaction = 10 + attempt;
        start_role(&mut init, RoleId::Registryd, generation, transaction, now);
        now += 2;
        init.fail(
            RoleId::Registryd,
            generation,
            transaction,
            now,
            AttemptFailure::MalformedReady,
        )
        .unwrap();
        assert!(init.resources(RoleId::Registryd).is_some());
        now += 1;
        init.cleanup_complete(RoleId::Registryd, generation, transaction, now)
            .unwrap();
        assert!(init.resources(RoleId::Registryd).is_none());
        assert_eq!(init.outstanding_reservations(), 0);
        if attempt != 3 {
            let RestartState::Backoff {
                deadline_ns,
                next_generation,
                ..
            } = init.role_state(RoleId::Registryd).unwrap()
            else {
                panic!("expected backoff")
            };
            assert_eq!(next_generation, generation + 1);
            now = deadline_ns;
            init.start_replacement(RoleId::Registryd, now, generation + 1, transaction + 1)
                .unwrap();
        }
    }
    assert!(matches!(
        init.role_state(RoleId::Registryd),
        Some(RestartState::PermanentFailure { .. })
    ));
    assert_eq!(init.mode(), SystemMode::Degraded);
    assert_eq!(init.degraded_transitions(), 1);
    assert_eq!(
        init.start_replacement(RoleId::Registryd, now, 5, 14),
        Err(InitError::Restart(
            wyrmroot_runtime::RestartTransitionError::InvalidState
        ))
    );
    assert_eq!(init.degraded_transitions(), 1);
}

#[test]
fn four_after_ready_nonzero_exits_degrade_once() {
    let mut init = system();
    init.become_operational().unwrap();
    init.begin_registry(0, 1, 10).unwrap();
    let mut now = 0;
    for attempt in 0..4_u64 {
        let generation = attempt + 1;
        let transaction = 10 + attempt;
        start_role(&mut init, RoleId::Registryd, generation, transaction, now);
        now += 2;
        init.ready(RoleId::Registryd, generation, transaction, now)
            .unwrap();
        if attempt == 0 {
            start_role(&mut init, RoleId::Devmgr, 1, 11, now);
            now += 2;
            init.ready(RoleId::Devmgr, 1, 11, now).unwrap();
        }
        now += 1;
        init.terminal(
            RoleId::Registryd,
            generation,
            transaction,
            now,
            TerminalDisposition::NormalExit(0xA101_F001),
        )
        .unwrap();
        now += 1;
        init.cleanup_complete(RoleId::Registryd, generation, transaction, now)
            .unwrap();
        if attempt != 3 {
            let RestartState::Backoff {
                deadline_ns,
                next_generation,
                ..
            } = init.role_state(RoleId::Registryd).unwrap()
            else {
                panic!("expected backoff")
            };
            assert_eq!(next_generation, generation + 1);
            now = deadline_ns;
            init.start_replacement(RoleId::Registryd, now, generation + 1, transaction + 1)
                .unwrap();
        }
    }
    assert!(matches!(
        init.role_state(RoleId::Registryd),
        Some(RestartState::PermanentFailure { .. })
    ));
    assert_eq!(init.mode(), SystemMode::Degraded);
    assert_eq!(init.degraded_transitions(), 1);
}

#[test]
fn four_exit_before_ready_records_degrade_once() {
    let mut init = system();
    init.become_operational().unwrap();
    init.begin_registry(0, 1, 10).unwrap();
    let mut now = 0;
    for attempt in 0..4_u64 {
        let generation = attempt + 1;
        let transaction = 10 + attempt;
        start_role(&mut init, RoleId::Registryd, generation, transaction, now);
        now += 2;
        init.terminal(
            RoleId::Registryd,
            generation,
            transaction,
            now,
            TerminalDisposition::NormalExit(0xA101_F001),
        )
        .unwrap();
        now += 1;
        init.cleanup_complete(RoleId::Registryd, generation, transaction, now)
            .unwrap();
        if attempt != 3 {
            let RestartState::Backoff {
                deadline_ns,
                next_generation,
                ..
            } = init.role_state(RoleId::Registryd).unwrap()
            else {
                panic!("expected backoff")
            };
            assert_eq!(next_generation, generation + 1);
            now = deadline_ns;
            init.start_replacement(RoleId::Registryd, now, generation + 1, transaction + 1)
                .unwrap();
        }
    }
    assert!(matches!(
        init.role_state(RoleId::Registryd),
        Some(RestartState::PermanentFailure { .. })
    ));
    assert_eq!(init.mode(), SystemMode::Degraded);
    assert_eq!(init.degraded_transitions(), 1);
}

#[test]
fn failed_cleanup_retains_generation_reservation_and_blocks_replacement() {
    let mut init = system();
    init.become_operational().unwrap();
    init.begin_registry(0, 1, 10).unwrap();
    start_role(&mut init, RoleId::Registryd, 1, 10, 0);
    init.fail(RoleId::Registryd, 1, 10, 2, AttemptFailure::MalformedReady)
        .unwrap();
    init.cleanup_failed(RoleId::Registryd, 1, 10, 3).unwrap();
    assert_eq!(init.outstanding_reservations(), 1);
    assert!(init.resources(RoleId::Registryd).is_some());
    assert!(matches!(
        init.role_state(RoleId::Registryd),
        Some(RestartState::PermanentFailure { .. })
    ));
    assert!(
        init.start_replacement(RoleId::Registryd, 30_000_000, 2, 11)
            .is_err()
    );
}

#[test]
fn ready_timeout_equality_uses_deadline_transition() {
    let mut init = system();
    init.become_operational().unwrap();
    init.begin_registry(0, 1, 10).unwrap();
    start_role(&mut init, RoleId::Registryd, 1, 10, 0);
    let RestartState::AwaitingReady { deadline_ns, .. } =
        init.role_state(RoleId::Registryd).unwrap()
    else {
        panic!("expected READY wait")
    };
    init.ready_wait_failed(
        RoleId::Registryd,
        1,
        10,
        deadline_ns,
        AttemptFailure::WaitFailed,
    )
    .unwrap();
    assert!(matches!(
        init.role_state(RoleId::Registryd),
        Some(RestartState::CleaningUp {
            failure: AttemptFailure::ReadyTimeout,
            ..
        })
    ));
}

#[test]
fn reap_evidence_value_encodes_terminal_class_and_application_code() {
    assert_eq!(
        reap_evidence_value(AttemptFailure::ExitAfterReady(
            TerminalDisposition::NormalExit(0)
        )),
        (REAP_CLASS_NORMAL_EXIT as u64) << 32
    );
    assert_eq!(
        reap_evidence_value(AttemptFailure::ExitBeforeReady(
            TerminalDisposition::NormalExit(0xA101_F001)
        )),
        ((REAP_CLASS_NORMAL_EXIT as u64) << 32) | 0xA101_F001
    );
    assert_eq!(
        reap_evidence_value(AttemptFailure::ExitAfterReady(
            TerminalDisposition::AuthorizedTermination
        )),
        (REAP_CLASS_AUTHORIZED_TERMINATION as u64) << 32
    );
    assert_eq!(
        reap_evidence_value(AttemptFailure::StartFailed),
        (REAP_CLASS_AUTHORIZED_TERMINATION as u64) << 32
    );
    assert_eq!(
        reap_evidence_value(AttemptFailure::DuplicateReady),
        (REAP_CLASS_TASK_GROUP_TEARDOWN as u64) << 32
    );
    assert_eq!(
        reap_evidence_value(AttemptFailure::ExitQueryFailed),
        (REAP_CLASS_UNHANDLED_EXCEPTION as u64) << 32
    );
}

#[test]
fn stale_ready_exit_and_cleanup_cannot_mutate_a_replacement() {
    let mut init = system();
    init.become_operational().unwrap();
    init.begin_registry(0, 1, 10).unwrap();
    start_role(&mut init, RoleId::Registryd, 1, 10, 0);
    init.terminal(
        RoleId::Registryd,
        1,
        10,
        2,
        TerminalDisposition::NormalExit(7),
    )
    .unwrap();
    init.cleanup_complete(RoleId::Registryd, 1, 10, 3).unwrap();
    let RestartState::Backoff { deadline_ns, .. } = init.role_state(RoleId::Registryd).unwrap()
    else {
        panic!()
    };
    init.start_replacement(RoleId::Registryd, deadline_ns, 2, 11)
        .unwrap();
    start_role(&mut init, RoleId::Registryd, 2, 11, deadline_ns);
    assert!(
        init.ready(RoleId::Registryd, 1, 10, deadline_ns + 2)
            .is_err()
    );
    assert!(
        init.terminal(
            RoleId::Registryd,
            1,
            10,
            deadline_ns + 2,
            TerminalDisposition::NormalExit(0)
        )
        .is_err()
    );
    assert!(
        init.cleanup_complete(RoleId::Registryd, 1, 10, deadline_ns + 2)
            .is_err()
    );
    assert!(matches!(
        init.role_state(RoleId::Registryd),
        Some(RestartState::AwaitingReady { generation: 2, .. })
    ));
}

#[test]
fn capability_and_profile_mismatch_fail_before_publication() {
    let mut init = system();
    init.become_operational().unwrap();
    init.begin_registry(0, 1, 10).unwrap();
    let mut wrong = resources(&mut init, RoleId::Registryd, 1, 10);
    wrong.startup_profile = StartupProfile::Retained;
    assert_eq!(
        init.install_attempt(wrong),
        Err(InitError::ResourceIdentityMismatch)
    );
    assert_eq!(init.outstanding_reservations(), 0);

    let mut init = system();
    init.become_operational().unwrap();
    init.begin_registry(0, 1, 10).unwrap();
    let mut wrong = resources(&mut init, RoleId::Registryd, 1, 10);
    wrong.task_group = DwHandle(0);
    assert_eq!(
        init.install_attempt(wrong),
        Err(InitError::InvalidResourceHandle)
    );
    assert_eq!(init.outstanding_reservations(), 0);

    let mut init = system();
    init.become_operational().unwrap();
    init.begin_registry(0, 1, 10).unwrap();
    let wrong = resources(&mut init, RoleId::Registryd, 1, 99);
    assert_eq!(
        init.install_attempt(wrong),
        Err(InitError::ResourceIdentityMismatch)
    );
    assert_eq!(init.outstanding_reservations(), 0);
}

#[test]
fn retained_bootfs_validation_hashes_exact_role_artifacts_and_rejects_mutation() {
    let artifacts: [(RoleId, &str, &[u8]); 5] = [
        (RoleId::Registryd, "system/registryd", b"registryd"),
        (RoleId::Devmgr, "system/devmgr", b"devmgr"),
        (RoleId::Uart16550d, "system/uart16550d", b"uart"),
        (RoleId::Consoled, "system/consoled", b"console"),
        (RoleId::Wyrmsh, "system/wyrmsh", b"shell"),
    ];
    let mut manifest = Builder::new(BOOT);
    for (id, path, bytes) in artifacts {
        let (activation, profile) = match id {
            RoleId::Registryd | RoleId::Devmgr => {
                (Activation::Early, StartupProfile::EarlyBootStub)
            }
            RoleId::Uart16550d => (Activation::DeviceBound, StartupProfile::Retained),
            _ => (Activation::ConsoleBound, StartupProfile::Retained),
        };
        manifest
            .add_role(RoleSpec {
                id,
                required: true,
                requires_ready: true,
                activation,
                startup_profile: profile,
                path,
                justification: "retained recovery closure",
                executable_identity: wyrmroot_runtime::sha256::digest(bytes),
            })
            .unwrap();
    }
    for (owner, target) in [
        (RoleId::Devmgr, RoleId::Registryd),
        (RoleId::Uart16550d, RoleId::Devmgr),
        (RoleId::Consoled, RoleId::Uart16550d),
        (RoleId::Wyrmsh, RoleId::Consoled),
    ] {
        manifest
            .add_dependency(DependencySpec {
                owner,
                kind: DependencyKind::RoleReady,
                target_role: Some(target),
                target_path: None,
            })
            .unwrap();
    }
    manifest
        .add_dependency(DependencySpec {
            owner: RoleId::Registryd,
            kind: DependencyKind::Config,
            target_role: None,
            target_path: Some("system/config/registryd"),
        })
        .unwrap();
    let manifest = manifest.build_structural().unwrap();
    let build = |registry: &[u8], init: Option<(&[u8], FileMode)>, include_config: bool| {
        let mut bootfs = BootfsBuilder::new();
        bootfs
            .add(b"system/bootstrap/rrc-a-v1", &manifest, FileMode::ReadOnly)
            .unwrap();
        if let Some((bytes, mode)) = init {
            bootfs.add(b"system/init", bytes, mode).unwrap();
        }
        for (_, path, bytes) in artifacts {
            let bytes = if path == "system/registryd" {
                registry
            } else {
                bytes
            };
            bootfs
                .add(path.as_bytes(), bytes, FileMode::Executable)
                .unwrap();
        }
        if include_config {
            bootfs
                .add(
                    b"system/config/registryd",
                    b"registry-config",
                    FileMode::ReadOnly,
                )
                .unwrap();
        }
        bootfs.build().unwrap()
    };
    let valid_init = Some((b"init".as_slice(), FileMode::Executable));
    assert!(
        wyrmroot_system_init::validate_retained_bootfs(&build(b"registryd", valid_init, true))
            .is_ok()
    );
    assert_eq!(
        wyrmroot_system_init::validate_retained_bootfs(&build(b"mutated", valid_init, true)),
        Err(InitError::ArtifactIdentityMismatch(RoleId::Registryd))
    );
    assert_eq!(
        wyrmroot_system_init::validate_retained_bootfs(&build(b"registryd", None, true)),
        Err(InitError::MissingRetainedMaterial)
    );
    assert_eq!(
        wyrmroot_system_init::validate_retained_bootfs(&build(
            b"registryd",
            Some((b"init".as_slice(), FileMode::ReadOnly)),
            true,
        )),
        Err(InitError::NonExecutableRole)
    );
    assert_eq!(
        wyrmroot_system_init::validate_retained_bootfs(&build(b"registryd", valid_init, false)),
        Err(InitError::MissingRetainedMaterial)
    );
}
