use super::*;
extern crate std;
use alloc::{format, string::String};
use core::fmt::Write;
use wyrmroot_bootfs::launch_policy::JOB_V2_PROFILE_ID;
use wyrmroot_device_proto::connector::{ConnectorMessage, ConnectorIdentity};
use wyrmroot_device_proto::control::ControlEndpoint;
use wyrmroot_device_proto::control_v1_1::{ControlIdentityV1_1, ControlMessageV1_1};
use wyrmroot_device_proto::coordinator::{
    AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId,
};
use wyrmroot_device_proto::manifest::RoleId;
use wyrmroot_devmgr::connector::{
    AttachCorrelation, ConnectorAction, ConnectorBroker, ConnectorSlot, PublishedDriver,
};
use wyrmroot_uart16550d::GracefulRetireDrain;

const NONCE: u64 = 0x1122_3344_5566_7788;

fn transaction(grant: EndpointGrant, transaction_id: u64) -> LaunchReservation {
    LaunchReservation {
        connection_id: grant.endpoint_id,
        generation: grant.endpoint_generation,
        transaction_id,
    }
}

fn stream_handles() -> [DwReceivedHandleInfoV1; 3] {
    [DwHandle(701), DwHandle(702), DwHandle(703)].map(|handle| DwReceivedHandleInfoV1 {
        handle,
        object_type: DW_OBJECT_TYPE_CHANNEL,
        rights: CONTROLLER_CHANNEL_RIGHTS,
        ..DwReceivedHandleInfoV1::default()
    })
}

fn record(
    state: &mut ShellControllerState,
    platform: &mut ShellPlatform,
    request: &[u8],
    response: &[u8],
    handles: &[DwReceivedHandleInfoV1],
) {
    state
        .record_e8_shell_jobs(platform, request, response, handles, None)
        .unwrap();
}

fn record_list(
    state: &mut ShellControllerState,
    platform: &mut ShellPlatform,
    grant: EndpointGrant,
    transaction_id: u64,
    jobs: &[u64],
) {
    let reservation = transaction(grant, transaction_id);
    let mut request = [0u8; wyrmroot_launch_proto::HEADER_BYTES];
    let request_len = wyrmroot_launch_proto::encode_list_jobs(reservation, &mut request).unwrap();
    let mut response = [0u8; 96];
    let response_len = encode_job_list(reservation, jobs, &mut response).unwrap();
    record(
        state,
        platform,
        &request[..request_len],
        &response[..response_len],
        &[],
    );
}

#[allow(clippy::too_many_arguments)]
fn record_launch(
    state: &mut ShellControllerState,
    platform: &mut ShellPlatform,
    grant: EndpointGrant,
    transaction_id: u64,
    path: &str,
    argv: &[&str],
    streams: bool,
    result: Result<u64, LaunchErrorCode>,
) {
    let reservation = transaction(grant, transaction_id);
    let mut request = [0u8; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
    let request_len =
        wyrmroot_launch_proto::encode_launch(reservation, path, argv, &[], streams, &mut request)
            .unwrap();
    let mut response = [0u8; 88];
    let response_len = match result {
        Ok(job_id) => encode_job_message(
            reservation,
            LaunchMessageType::LaunchAccepted,
            job_id,
            &mut response,
        )
        .unwrap(),
        Err(error) => encode_launch_error(reservation, error, &mut response).unwrap(),
    };
    let handles = stream_handles();
    record(
        state,
        platform,
        &request[..request_len],
        &response[..response_len],
        if streams { &handles } else { &[] },
    );
}

fn record_job_message(
    state: &mut ShellControllerState,
    platform: &mut ShellPlatform,
    grant: EndpointGrant,
    transaction_id: u64,
    request_kind: LaunchMessageType,
    response_kind: LaunchMessageType,
    job_id: u64,
) {
    let reservation = transaction(grant, transaction_id);
    let mut request = [0u8; 56];
    let request_len = encode_job_message(reservation, request_kind, job_id, &mut request).unwrap();
    let mut response = [0u8; 56];
    let response_len =
        encode_job_message(reservation, response_kind, job_id, &mut response).unwrap();
    record(
        state,
        platform,
        &request[..request_len],
        &response[..response_len],
        &[],
    );
}

fn record_wait(
    state: &mut ShellControllerState,
    platform: &mut ShellPlatform,
    grant: EndpointGrant,
    transaction_id: u64,
    job_id: u64,
    result: TerminationResult,
) {
    let reservation = transaction(grant, transaction_id);
    let mut request = [0u8; 56];
    let request_len =
        encode_job_message(reservation, LaunchMessageType::Wait, job_id, &mut request).unwrap();
    let mut response = [0u8; 88];
    let response_len = encode_job_result(reservation, job_id, result, &mut response).unwrap();
    record(
        state,
        platform,
        &request[..request_len],
        &response[..response_len],
        &[],
    );
}

const fn result(
    classification: TerminationClassification,
    application_code: u32,
    exception_class: u32,
    exception_detail: u32,
) -> TerminationResult {
    TerminationResult {
        classification,
        application_code,
        exception_class,
        exception_detail,
        exception_address: 0,
        cleanup_result: 0,
    }
}

fn record_modeled_s1(
    state: &mut ShellControllerState,
    platform: &mut ShellPlatform,
    tuple: crate::wyr1e8_evidence::ShellTuple,
) {
    let grant = EndpointGrant {
        registry_generation: tuple.registry_generation,
        endpoint_id: tuple.shell_jobs_connection_id,
        endpoint_generation: tuple.shell_jobs_generation,
        role_generation: 1,
        kind: EndpointKind::LaunchSession,
    };
    let token = format!("{:016X}", NONCE ^ 5);
    let hello = 1_001;
    let nonzero = 1_002;
    let fault = 1_003;
    let hog = 1_004;

    record_list(state, platform, grant, 1, &[]);
    record_launch(
        state,
        platform,
        grant,
        2,
        "bin/hello",
        &["bin/hello", token.as_str()],
        true,
        Ok(hello),
    );
    record_wait(
        state,
        platform,
        grant,
        3,
        hello,
        result(TerminationClassification::NormalExit, 0, 0, 0),
    );
    record_job_message(
        state,
        platform,
        grant,
        4,
        LaunchMessageType::CloseJob,
        LaunchMessageType::Closed,
        hello,
    );
    record_launch(
        state,
        platform,
        grant,
        5,
        "test/wyr1-e/not-admitted",
        &["test/wyr1-e/not-admitted"],
        true,
        Err(LaunchErrorCode::PolicyRejected),
    );
    record_launch(
        state,
        platform,
        grant,
        6,
        "test/wyr1-e/malformed-elf",
        &["test/wyr1-e/malformed-elf"],
        true,
        Err(LaunchErrorCode::LoaderFailure),
    );
    record_launch(
        state,
        platform,
        grant,
        7,
        "test/wyr1-e/exit-nonzero",
        &["test/wyr1-e/exit-nonzero"],
        true,
        Ok(nonzero),
    );
    record_wait(
        state,
        platform,
        grant,
        8,
        nonzero,
        result(TerminationClassification::NormalExit, 37, 0, 0),
    );
    record_job_message(
        state,
        platform,
        grant,
        9,
        LaunchMessageType::CloseJob,
        LaunchMessageType::Closed,
        nonzero,
    );
    record_launch(
        state,
        platform,
        grant,
        10,
        "test/wyr1-e/fault",
        &["test/wyr1-e/fault"],
        true,
        Ok(fault),
    );
    record_wait(
        state,
        platform,
        grant,
        11,
        fault,
        result(TerminationClassification::UnhandledException, 0, 2, 6),
    );
    record_job_message(
        state,
        platform,
        grant,
        12,
        LaunchMessageType::CloseJob,
        LaunchMessageType::Closed,
        fault,
    );
    record_launch(
        state,
        platform,
        grant,
        13,
        "bin/cpu-hog",
        &["bin/cpu-hog"],
        false,
        Ok(hog),
    );
    record_list(state, platform, grant, 14, &[hog]);
    record_job_message(
        state,
        platform,
        grant,
        15,
        LaunchMessageType::Terminate,
        LaunchMessageType::TerminationAccepted,
        hog,
    );
    record_wait(
        state,
        platform,
        grant,
        16,
        hog,
        result(TerminationClassification::TaskGroupTeardown, 0, 0, 0),
    );
    record_job_message(
        state,
        platform,
        grant,
        17,
        LaunchMessageType::CloseJob,
        LaunchMessageType::Closed,
        hog,
    );
    record_list(state, platform, grant, 18, &[]);
}

fn finish_modeled_s1(
    state: &mut ShellControllerState,
    platform: &mut ShellPlatform,
    outer_job: u64,
) {
    let outer_grant = EndpointGrant {
        registry_generation: 15,
        endpoint_id: 300,
        endpoint_generation: 4,
        role_generation: 1,
        kind: EndpointKind::LaunchSession,
    };
    let wait = transaction(outer_grant, 501);
    let mut wait_request = [0u8; 56];
    let wait_request_len =
        encode_job_message(wait, LaunchMessageType::Wait, outer_job, &mut wait_request).unwrap();
    let mut wait_response = [0u8; 88];
    let wait_response_len = encode_job_result(
        wait,
        outer_job,
        result(TerminationClassification::NormalExit, 0, 0, 0),
        &mut wait_response,
    )
    .unwrap();
    state
        .record_e8_outer_response(
            platform,
            &wait_request[..wait_request_len],
            &wait_response[..wait_response_len],
        )
        .unwrap();

    let close = transaction(outer_grant, 502);
    let mut close_request = [0u8; 56];
    let close_request_len = encode_job_message(
        close,
        LaunchMessageType::CloseJob,
        outer_job,
        &mut close_request,
    )
    .unwrap();
    let mut close_response = [0u8; 56];
    let close_response_len = encode_job_message(
        close,
        LaunchMessageType::Closed,
        outer_job,
        &mut close_response,
    )
    .unwrap();
    state
        .record_e8_outer_response(
            platform,
            &close_request[..close_request_len],
            &close_response[..close_response_len],
        )
        .unwrap();
}

fn recovery_policy_bootfs(image: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let generation = [0x46; 32];
    let mut manifest = [0u8; 80];
    manifest[48..80].copy_from_slice(&generation);
    let path = wyrmroot_wyr1e_test_actors::RECOVERY_TRIGGER_PATH;
    let entry = LaunchPolicyEntry {
        path,
        content_sha256: wyrmroot_runtime::sha256::digest(image),
        startup_abi: 2,
        profile_id: JOB_V2_PROFILE_ID,
        allow_no_streams: false,
        allow_three_streams: true,
    };
    let mut policy = [0u8; 512];
    let policy_len = encode_launch_policy(generation, &[entry], &mut policy).unwrap();
    let mut builder = BootfsBuilder::new();
    builder
        .add(path.as_bytes(), image, FileMode::Executable)
        .unwrap();
    builder
        .add(b"system/registryd", image, FileMode::Executable)
        .unwrap();
    builder
        .add(
            LAUNCH_POLICY_PATH.as_bytes(),
            &policy[..policy_len],
            FileMode::ReadOnly,
        )
        .unwrap();
    builder
        .add(MANIFEST_PATH.as_bytes(), &manifest, FileMode::ReadOnly)
        .unwrap();
    (builder.build().unwrap(), generation)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn published_driver(
    serial: crate::wyr1e8_evidence::SerialFacts,
    bundle_generation: u64,
) -> PublishedDriver {
    PublishedDriver {
        publication_generation: serial.publication_generation,
        control: ControlIdentityV1_1 {
            role_id: RoleId(serial.device_role_id),
            bundle_generation: BundleGeneration(bundle_generation),
            attempt_generation: AttemptGeneration(serial.driver_attempt_generation),
            endpoint: ControlEndpoint {
                id: EndpointId(serial.driver_control_endpoint_id),
                generation: EndpointGeneration(serial.driver_control_endpoint_generation),
            },
            transaction_id: serial.driver_launch_transaction,
        },
    }
}

fn attach_serial(
    broker: &mut ConnectorBroker,
    publication_generation: u64,
    client_transaction_id: u64,
) -> AttachCorrelation {
    let ConnectorAction::AllocatePair { attach, .. } = broker
        .begin_connect(ConnectorMessage::ConnectStream {
            publication_generation,
            client_transaction_id,
        })
        .unwrap()
    else {
        panic!("connector must allocate the fresh raw pair")
    };
    broker.driver_endpoint_moved(attach).unwrap();
    broker
        .accept_stream_ready(ControlMessageV1_1::StreamReady {
            identity: ControlIdentityV1_1 {
                transaction_id: attach.attach_transaction_id,
                ..attach.driver.control
            },
            stream_generation: attach.stream_generation,
            publication_generation: attach.driver.publication_generation,
        })
        .unwrap();
    assert_eq!(
        broker.connected_response(),
        Ok(ConnectorMessage::Connected {
            identity: ConnectorIdentity {
                publication_generation: attach.driver.publication_generation,
                client_transaction_id,
                device_role_id: attach.driver.control.role_id.0,
                bundle_generation: attach.driver.control.bundle_generation.0,
                driver_attempt_generation: attach.driver.control.attempt_generation.0,
                driver_control_endpoint_id: attach.driver.control.endpoint.id.0,
                driver_control_endpoint_generation: attach.driver.control.endpoint.generation.0,
                attach_transaction_id: attach.attach_transaction_id,
                stream_generation: attach.stream_generation,
            },
        })
    );
    broker.client_endpoint_moved().unwrap();
    attach
}

fn detach_serial(attach: AttachCorrelation) -> ControlMessageV1_1 {
    ControlMessageV1_1::StreamDetached {
        identity: ControlIdentityV1_1 {
            transaction_id: attach.attach_transaction_id,
            ..attach.driver.control
        },
        stream_generation: attach.stream_generation,
        publication_generation: attach.driver.publication_generation,
    }
}

#[test]
fn actual_driver_and_registry_recovery_compose_through_s4_ready() {
    let serial = crate::wyr1e8_evidence::SerialFacts {
        publication_generation: 20,
        device_role_id: 21,
        driver_attempt_generation: 22,
        driver_control_endpoint_id: 23,
        driver_control_endpoint_generation: 24,
        driver_launch_transaction: 25,
        supervisor_generation: 26,
    };
    let s1 = crate::wyr1e8_evidence::ShellTuple {
        console_generation: 10,
        status_generation: 11,
        shell_generation: 12,
        outer_launch_transaction: 13,
        outer_job_id: 14,
        registry_generation: 15,
        registry_endpoint_id: 16,
        registry_endpoint_generation: 17,
        shell_jobs_connection_id: 100,
        shell_jobs_generation: 1,
    };
    let s1_ready = crate::wyr1e8_evidence::SerialReady {
        console_generation: s1.console_generation,
        status_generation: s1.status_generation,
        shell_generation: s1.shell_generation,
        attach_transaction: 30,
        stream_generation: 31,
        bundle_generation: 32,
    };
    let mut platform = ShellPlatform::new();
    let mut state = ShellControllerState::new(s1.registry_generation).unwrap();
    state.e8_evidence.observe_serial(serial).unwrap();
    state.stage_e8_shell_ready(&mut platform, s1).unwrap();
    state
        .observe_e8_serial_ready(&mut platform, s1_ready)
        .unwrap();
    record_modeled_s1(&mut state, &mut platform, s1);
    finish_modeled_s1(&mut state, &mut platform, s1.outer_job_id);
    assert_eq!(platform.e8_evidence.len(), 20);

    let s2_grant = EndpointGrant {
        registry_generation: s1.registry_generation,
        endpoint_id: 200,
        endpoint_generation: 3,
        role_generation: 112,
        kind: EndpointKind::LaunchSession,
    };
    let console_grant = EndpointGrant {
        registry_generation: s1.registry_generation,
        endpoint_id: 180,
        endpoint_generation: 2,
        role_generation: 110,
        kind: EndpointKind::LaunchSession,
    };
    let console_session = DwHandle(89);
    let session = DwHandle(90);
    let console_owner = SessionOwner {
        process: DwHandle(801),
        launch_channel: DwHandle(802),
        task_group: DwHandle(803),
    };
    let mut jobs = JobDispatcher::new();
    jobs
        .install_scoped_session(
            console_grant,
            console_session,
            LaunchSessionScope::ConsoleLauncher,
        )
        .unwrap();
    jobs.attach_session_owner(console_grant, console_owner).unwrap();
    let outer_reservation = transaction(console_grant, 113);
    let outer = jobs.jobs.begin_launch(outer_reservation).unwrap();
    let outer_process = DwHandle(811);
    let outer_task_group = DwHandle(812);
    let outer_launch_channel = DwHandle(813);
    jobs
        .jobs
        .commit_launch(
            outer,
            outer_process.0,
            outer_task_group.0,
            outer_launch_channel.0,
        )
        .unwrap();
    jobs
        .install_scoped_session(s2_grant, session, LaunchSessionScope::ShellJobs)
        .unwrap();
    jobs.attach_outer_job(s2_grant, outer.job_id).unwrap();
    let console_peer = InstalledPeer {
        grant: console_grant,
        loaded: LoadedProcess {
            process: console_owner.process,
            launch_channel: console_owner.launch_channel,
        },
        task_group: console_owner.task_group,
    };
    let s2 = crate::wyr1e8_evidence::ShellTuple {
        console_generation: s1.console_generation,
        status_generation: 111,
        shell_generation: 112,
        outer_launch_transaction: outer_reservation.transaction_id,
        outer_job_id: outer.job_id,
        registry_generation: s1.registry_generation,
        registry_endpoint_id: 116,
        registry_endpoint_generation: 117,
        shell_jobs_connection_id: s2_grant.endpoint_id,
        shell_jobs_generation: s2_grant.endpoint_generation,
    };
    let s2_ready = crate::wyr1e8_evidence::SerialReady {
        console_generation: s2.console_generation,
        status_generation: s2.status_generation,
        shell_generation: s2.shell_generation,
        ..s1_ready
    };
    state.stage_e8_shell_ready(&mut platform, s2).unwrap();
    state
        .observe_e8_serial_ready(&mut platform, s2_ready)
        .unwrap();
    assert_eq!(platform.e8_evidence.len(), 21);
    state
        .set_e8_console_control(console_owner.launch_channel)
        .unwrap();

    let old_driver = published_driver(serial, s2_ready.bundle_generation);
    let mut broker = ConnectorBroker::new(
        Some(old_driver),
        s2_ready.attach_transaction,
        s2_ready.stream_generation,
    )
    .unwrap();
    let old_attach = attach_serial(&mut broker, serial.publication_generation, 40);
    assert_eq!(old_attach.attach_transaction_id, s2_ready.attach_transaction);
    assert_eq!(old_attach.stream_generation, s2_ready.stream_generation);

    let image = executable();
    let (bootfs, generation) = recovery_policy_bootfs(&image);
    let archive = Archive::new(&bootfs).unwrap();
    let policy = PolicyView::from_bootfs(archive, generation).unwrap();
    let reservation = transaction(s2_grant, 1);
    let token = format!("{:016X}", NONCE ^ E8_DRIVER_TRIGGER_TOKEN_INDEX);
    let path = wyrmroot_wyr1e_test_actors::RECOVERY_TRIGGER_PATH;
    let mut request = [0u8; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
    let request_len = wyrmroot_launch_proto::encode_launch(
        reservation,
        path,
        &[
            path,
            wyrmroot_wyr1e_test_actors::RECOVERY_DRIVER_ACTION,
            token.as_str(),
        ],
        &[],
        true,
        &mut request,
    )
    .unwrap();
    let handles = stream_handles();
    platform.push(
        session,
        request[..request_len].to_vec(),
        &handles.map(|info| info.handle),
    );
    let captured_handles = platform.inbound[0].2.clone();
    let mut loader = InitSendLoader::new();
    loader.fail_init = false;
    let mut waits = AcceptedJobV2Waits {
        transaction_id: reservation.transaction_id,
        profile: LaunchProfile::JobV2Streams,
        exited: false,
        console_status_lost_process: Some(outer_process),
        running_process: None,
    };
    let mut topology = RegistryTopology::new(s2.registry_generation).unwrap();
    let mut context = ShellLaunchContext {
        registry_control: DwHandle(80),
        topology: &mut topology,
        state: &mut state,
    };
    let outcome = dispatch_one_job_request_with_shell(
        &mut platform,
        &mut loader,
        &mut waits,
        LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        },
        Some(&policy),
        &mut jobs,
        session,
        s2_grant,
        &mut context,
    )
    .unwrap();
    let JobDispatchOutcome::Launched(loaded) = outcome else {
        panic!("the real dispatcher must accept the S2 recovery trigger")
    };
    assert_eq!(platform.e8_evidence.len(), 22);
    assert_eq!(
        context.state.e8_trigger,
        Some(E8Trigger {
            identity: E8TriggerIdentity {
                launch_transaction: reservation.transaction_id,
                job_id: loaded.job_id,
                action: E8RecoveryAction::Driver,
            },
            deadline: 10 + WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns,
        })
    );

    let accepted_request = request[..request_len].to_vec();
    let accepted_response = platform.sent.last().unwrap().1.clone();
    let response = accepted_response.as_slice();
    assert!(matches!(
        parse_launch_message(response, 0).unwrap().message,
        LaunchMessage::LaunchAccepted { job_id } if job_id == loaded.job_id
    ));
    let actual = &platform.e8_evidence[21];
    assert_eq!(&actual[32..112], &platform.e8_evidence[20][32..112]);
    assert_eq!(u16::from_le_bytes(actual[6..8].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(actual[8..12].try_into().unwrap()), 2);
    assert_eq!(u64::from_le_bytes(actual[16..24].try_into().unwrap()), 22);
    assert_eq!(
        u64::from_le_bytes(actual[24..32].try_into().unwrap()),
        NONCE
    );
    assert_eq!(u64::from_le_bytes(actual[112..120].try_into().unwrap()), 1);
    assert_eq!(
        u64::from_le_bytes(actual[120..128].try_into().unwrap()),
        loaded.job_id
    );
    assert_eq!(
        u32::from_le_bytes(actual[128..132].try_into().unwrap()),
        LaunchMessageType::Launch as u32
    );
    assert_eq!(
        u32::from_le_bytes(actual[132..136].try_into().unwrap()),
        LaunchMessageType::LaunchAccepted as u32
    );
    assert!(actual[160..].iter().any(|byte| *byte != 0));

    // The exact LAUNCH-successor WAIT is installed while the actor is still
    // running. Only the later real terminal/reap observation may hold it.
    let wait = transaction(s2_grant, 2);
    let mut wait_request = [0u8; 56];
    let wait_request_len = encode_job_message(
        wait,
        LaunchMessageType::Wait,
        loaded.job_id,
        &mut wait_request,
    )
    .unwrap();
    platform.push(session, wait_request[..wait_request_len].to_vec(), &[]);
    assert_eq!(
        dispatch_one_job_request_with_shell(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            Some(&policy),
            &mut jobs,
            session,
            s2_grant,
            &mut context,
        ),
        Ok(JobDispatchOutcome::Responded)
    );
    let sent_before_terminal = platform.sent.len();
    waits.exited = true;
    let released_actor = jobs.jobs.loaded_job(loaded.job_id).unwrap();
    assert_eq!(released_actor.loaded.launch_channel, DwHandle(0));
    let actor_result = reap_job(&mut platform, &mut waits, &mut jobs, released_actor).unwrap();
    assert_eq!(actor_result, result(TerminationClassification::NormalExit, 0, 0, 0));
    service_pending_wait_inner(
        &mut platform,
        &mut waits,
        &mut jobs,
        Some(&mut *context.state),
    )
    .unwrap();
    assert_eq!(platform.sent.len(), sent_before_terminal + 1);
    let quiesce = wyrmroot_consoled::e8_control::parse(&platform.sent.last().unwrap().1).unwrap();
    let wyrmroot_consoled::e8_control::Message::Quiesce(quiesce_identity) = quiesce else {
        panic!("the held WAIT must emit the exact WRC8 quiescence request")
    };
    let held = context.state.e8_held.unwrap();
    assert_eq!(held.identity, quiesce_identity);
    assert_eq!(held.identity.trigger_wait_transaction, 2);
    assert_eq!(context.state.accept_e8_quiesced(quiesce_identity, platform.now), Ok(E8RecoveryAction::Driver));

    // The reached UART drain needs a fresh empty receive, empty software ring,
    // and a paced TEMT observation before the old driver may be released.
    let mut drain = GracefulRetireDrain::new(platform.now, false).unwrap();
    assert!(!drain.temt_probe_due(platform.now, true).unwrap());
    drain.observe_stream_empty();
    assert!(drain.temt_probe_due(platform.now, true).unwrap());
    assert!(drain.observe_temt(platform.now, true, true).unwrap());

    // Ordinary UART retirement invalidates the raw/publication path first.
    // Replacement must remain impossible while the dependent console product
    // and its exact held result are still owned.
    assert_eq!(broker.retire_current(), None);
    assert!(matches!(broker.slot(), ConnectorSlot::RetiringActive { .. }));

    let new_serial = crate::wyr1e8_evidence::SerialFacts {
        publication_generation: 36,
        device_role_id: serial.device_role_id,
        driver_attempt_generation: 37,
        driver_control_endpoint_id: 38,
        driver_control_endpoint_generation: 39,
        driver_launch_transaction: 40,
        supervisor_generation: serial.supervisor_generation,
    };
    let new_driver = published_driver(new_serial, s2_ready.bundle_generation);
    assert!(broker.replace_published_driver(new_driver).is_err());

    // Use the same product-retirement and held-result finalizer as the reached
    // production DriverExited path. The console/shell owners must be gone and
    // cause-2 retirement emitted before exact driver reap acknowledgement.
    let held = context
        .state
        .e8_held_for_action(E8RecoveryAction::Driver)
        .unwrap();
    context
        .state
        .clear_e8_console_control(console_owner.launch_channel)
        .unwrap();
    let retired = retire_console_product_with_result_before(
        &mut platform,
        &mut waits,
        &mut jobs,
        console_peer,
        false,
        held.deadline,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        retired,
        result(
            TerminationClassification::NormalExit,
            WYRMSH_CONSOLE_STATUS_LOST,
            0,
            0,
        )
    );
    assert!(!platform
        .terminated_task_groups
        .contains(&console_owner.task_group));
    assert!(platform.terminated_task_groups.contains(&outer_task_group));
    crate::wyr1b_native::finish_e8_dependent_retirement(
        &mut platform,
        &mut jobs,
        context.state,
        held,
        retired,
    )
        .unwrap();
    assert_eq!(jobs.session_count(), 0);
    assert_eq!(jobs.jobs.live_jobs(), 0);
    assert_eq!(platform.e8_evidence.len(), 23);

    // STREAM_DETACHED is not used as reap evidence. Exact supervisor/reaper
    // proof moves the broker toward Empty, but client-witness release remains
    // independently required before the fresh publication can be installed.
    assert_eq!(broker.driver_attempt_reaped(old_driver), Ok(None));
    assert!(matches!(
        broker.slot(),
        ConnectorSlot::RetiringActive { .. }
    ));
    assert!(broker.replace_published_driver(new_driver).is_err());
    broker.client_release_observed(old_attach).unwrap();
    assert_eq!(broker.slot(), ConnectorSlot::Empty);
    broker.replace_published_driver(new_driver).unwrap();
    // Connector transactions are local to the replacement consoled process;
    // numeric reuse is valid only because the authenticated client owner is new.
    let new_attach = attach_serial(&mut broker, new_serial.publication_generation, 40);
    assert!(new_attach.attach_transaction_id > old_attach.attach_transaction_id);
    assert!(new_attach.stream_generation > old_attach.stream_generation);

    // Reissue the S3 console, registry-client, and ShellJobs authorities. The
    // local generation counters may restart only because all owning endpoints
    // and processes are new.
    let s3_console_grant = context
        .topology
        .issue(310, EndpointKind::LaunchSession)
        .unwrap();
    let s3_grant = context
        .topology
        .issue(312, EndpointKind::LaunchSession)
        .unwrap();
    let s3_registry_client = context
        .topology
        .issue(312, EndpointKind::RegistryClient)
        .unwrap();
    let s3_console_session = DwHandle(189);
    let s3_session = DwHandle(190);
    let s3_console_owner = SessionOwner {
        process: DwHandle(901),
        launch_channel: DwHandle(902),
        task_group: DwHandle(903),
    };
    jobs
        .install_scoped_session(
            s3_console_grant,
            s3_console_session,
            LaunchSessionScope::ConsoleLauncher,
        )
        .unwrap();
    jobs
        .attach_session_owner(s3_console_grant, s3_console_owner)
        .unwrap();
    let s3_outer_reservation = transaction(s3_console_grant, 313);
    let s3_outer = jobs.jobs.begin_launch(s3_outer_reservation).unwrap();
    let s3_outer_process = DwHandle(911);
    let s3_outer_task_group = DwHandle(912);
    let s3_outer_launch_channel = DwHandle(913);
    jobs
        .jobs
        .commit_launch(
            s3_outer,
            s3_outer_process.0,
            s3_outer_task_group.0,
            s3_outer_launch_channel.0,
        )
        .unwrap();
    jobs
        .install_scoped_session(s3_grant, s3_session, LaunchSessionScope::ShellJobs)
        .unwrap();
    jobs.attach_outer_job(s3_grant, s3_outer.job_id).unwrap();
    let s3_console_peer = InstalledPeer {
        grant: s3_console_grant,
        loaded: LoadedProcess {
            process: s3_console_owner.process,
            launch_channel: s3_console_owner.launch_channel,
        },
        task_group: s3_console_owner.task_group,
    };
    let s3 = crate::wyr1e8_evidence::ShellTuple {
        console_generation: 1,
        status_generation: 1,
        shell_generation: 1,
        outer_launch_transaction: s3_outer_reservation.transaction_id,
        outer_job_id: s3_outer.job_id,
        registry_generation: s2.registry_generation,
        registry_endpoint_id: s3_registry_client.endpoint_id,
        registry_endpoint_generation: s3_registry_client.endpoint_generation,
        shell_jobs_connection_id: s3_grant.endpoint_id,
        shell_jobs_generation: s3_grant.endpoint_generation,
    };
    let s3_ready = crate::wyr1e8_evidence::SerialReady {
        console_generation: s3.console_generation,
        status_generation: s3.status_generation,
        shell_generation: s3.shell_generation,
        attach_transaction: new_attach.attach_transaction_id,
        stream_generation: new_attach.stream_generation,
        bundle_generation: new_attach.driver.control.bundle_generation.0,
    };
    context.state.e8_evidence.observe_serial(new_serial).unwrap();
    context.state.stage_e8_shell_ready(&mut platform, s3).unwrap();
    context
        .state
        .observe_e8_serial_ready(&mut platform, s3_ready)
        .unwrap();
    assert_eq!(context.state.e8_stage(), 3);
    assert!(context.state.e8_shell_ready());
    assert_eq!(context.state.e8_trigger, None);
    assert_eq!(platform.e8_evidence.len(), 24);
    context
        .state
        .set_e8_console_control(s3_console_owner.launch_channel)
        .unwrap();

    // Drive the S3 registry trigger through the same production dispatcher and
    // held-WAIT barrier used by the driver leg.
    let registry_reservation = transaction(s3_grant, 1);
    let registry_token = format!("{:016X}", NONCE ^ E8_REGISTRY_TRIGGER_TOKEN_INDEX);
    let mut registry_request = [0u8; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
    let registry_request_len = wyrmroot_launch_proto::encode_launch(
        registry_reservation,
        path,
        &[
            path,
            wyrmroot_wyr1e_test_actors::RECOVERY_REGISTRY_ACTION,
            registry_token.as_str(),
        ],
        &[],
        true,
        &mut registry_request,
    )
    .unwrap();
    platform.push(
        s3_session,
        registry_request[..registry_request_len].to_vec(),
        &handles.map(|info| info.handle),
    );
    waits.transaction_id = registry_reservation.transaction_id;
    waits.exited = false;
    waits.console_status_lost_process = Some(s3_outer_process);
    let registry_outcome = dispatch_one_job_request_with_shell(
        &mut platform,
        &mut loader,
        &mut waits,
        LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        },
        Some(&policy),
        &mut jobs,
        s3_session,
        s3_grant,
        &mut context,
    )
    .unwrap();
    let JobDispatchOutcome::Launched(registry_actor) = registry_outcome else {
        panic!("the real dispatcher must accept the S3 registry trigger")
    };
    assert_eq!(platform.e8_evidence.len(), 25);
    assert!(matches!(
        context.state.e8_trigger,
        Some(E8Trigger {
            identity: E8TriggerIdentity {
                launch_transaction: 1,
                job_id,
                action: E8RecoveryAction::Registry,
            },
            ..
        }) if job_id == registry_actor.job_id
    ));

    let registry_wait = transaction(s3_grant, 2);
    let mut registry_wait_request = [0u8; 56];
    let registry_wait_len = encode_job_message(
        registry_wait,
        LaunchMessageType::Wait,
        registry_actor.job_id,
        &mut registry_wait_request,
    )
    .unwrap();
    platform.push(
        s3_session,
        registry_wait_request[..registry_wait_len].to_vec(),
        &[],
    );
    assert_eq!(
        dispatch_one_job_request_with_shell(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            Some(&policy),
            &mut jobs,
            s3_session,
            s3_grant,
            &mut context,
        ),
        Ok(JobDispatchOutcome::Responded)
    );
    waits.exited = true;
    let released_registry_actor = jobs.jobs.loaded_job(registry_actor.job_id).unwrap();
    assert_eq!(released_registry_actor.loaded.launch_channel, DwHandle(0));
    assert_eq!(
        reap_job(&mut platform, &mut waits, &mut jobs, released_registry_actor),
        Ok(result(TerminationClassification::NormalExit, 0, 0, 0))
    );
    service_pending_wait_inner(
        &mut platform,
        &mut waits,
        &mut jobs,
        Some(&mut *context.state),
    )
    .unwrap();
    let registry_quiesce =
        wyrmroot_consoled::e8_control::parse(&platform.sent.last().unwrap().1).unwrap();
    let wyrmroot_consoled::e8_control::Message::Quiesce(registry_identity) = registry_quiesce
    else {
        panic!("the registry held WAIT must emit its exact WRC8 request")
    };
    assert_eq!(registry_identity.trigger_wait_transaction, 2);
    assert_eq!(
        context
            .state
            .accept_e8_quiesced(registry_identity, platform.now),
        Ok(E8RecoveryAction::Registry)
    );

    // The old consoled-side connector must become empty before its replacement
    // can publish. This independent broker model preserves the nonempty and
    // stale-correlation negatives while production init owns root recovery.
    assert_eq!(broker.retire_current(), None);
    assert!(matches!(broker.slot(), ConnectorSlot::RetiringActive { .. }));
    let proposed_rebound_serial = crate::wyr1e8_evidence::SerialFacts {
        publication_generation: 46,
        ..new_serial
    };
    let proposed_rebound_driver =
        published_driver(proposed_rebound_serial, s3_ready.bundle_generation);
    assert!(broker
        .replace_published_driver(proposed_rebound_driver)
        .is_err());
    broker.client_release_observed(new_attach).unwrap();
    assert!(matches!(broker.slot(), ConnectorSlot::RetiringActive { .. }));
    broker.driver_detached(detach_serial(new_attach)).unwrap();
    assert_eq!(broker.slot(), ConnectorSlot::Empty);

    // Cross the actual system-init recovery wrapper. It consumes the held WAIT,
    // retires the old consoled and registry owners, launches the replacement
    // registry, observes devmgr's exact WAIT, rebinds its publication, installs
    // the current-driver watch, and consumes the matching generation event.
    drop(context);
    let driver_request = DriverLaunchRequest {
        supervisor_generation: wyrmroot_device_proto::coordinator::SupervisorGeneration(
            new_serial.supervisor_generation,
        ),
        role_id: RoleId(new_serial.device_role_id),
        attempt_generation: AttemptGeneration(new_serial.driver_attempt_generation),
        launch_session: wyrmroot_device_proto::coordinator::LaunchSessionGeneration(39),
        endpoint: ControlEndpoint {
            id: EndpointId(new_serial.driver_control_endpoint_id),
            generation: EndpointGeneration(new_serial.driver_control_endpoint_generation),
        },
        transaction_id: new_serial.driver_launch_transaction,
        driver_path: wyrmroot_device_proto::DEVICE_DRIVER_PATH,
        actor_identity: wyrmroot_device_proto::manifest::ContentIdentity([0x5a; 32]),
        child_is_channel: true,
        child_rights: wyrmroot_device_proto::DirectControlRights::ExactReduced,
    };
    let devmgr_control = crate::wyr1c_native::E8_REGISTRY_FIXTURE_DEVMGR_CONTROL;
    let mut waiting_status = [0u8; wyrmroot_device_proto::controller::STATUS_BYTES];
    wyrmroot_device_proto::controller::encode(
        wyrmroot_device_proto::controller::ControllerMessage::Status {
            supervisor_generation: wyrmroot_device_proto::coordinator::SupervisorGeneration(
                s3.registry_generation,
            ),
            binding: None,
            transaction_id: 9,
            status: wyrmroot_device_proto::controller::StatusCode::OperationalWaitingForRegistry,
            attempt_generation: None,
        },
        &mut waiting_status,
    )
    .unwrap();
    platform.push(devmgr_control, waiting_status.to_vec(), &[]);
    let expected_rebound_binding = wyrmroot_device_proto::RegistryBinding {
        generation: wyrmroot_device_proto::coordinator::RegistryGeneration(
            s3.registry_generation + 1,
        ),
        endpoint: wyrmroot_device_proto::coordinator::RegistryEndpoint {
            id: wyrmroot_device_proto::coordinator::RegistryEndpointId(4),
            generation: wyrmroot_device_proto::coordinator::RegistryEndpointGeneration(1),
        },
    };
    let mut rebound_status = [0u8; wyrmroot_device_proto::controller::STATUS_BYTES];
    wyrmroot_device_proto::controller::encode(
        wyrmroot_device_proto::controller::ControllerMessage::Status {
            supervisor_generation: wyrmroot_device_proto::coordinator::SupervisorGeneration(
                s3.registry_generation,
            ),
            binding: Some(expected_rebound_binding),
            transaction_id: 10,
            status:
                wyrmroot_device_proto::controller::StatusCode::OperationalWaitingForDeviceBundle,
            attempt_generation: None,
        },
        &mut rebound_status,
    )
    .unwrap();
    platform.push(devmgr_control, rebound_status.to_vec(), &[]);
    platform.allow_wait_until = true;
    waits.transaction_id = 0xE8B5_0002;
    waits.profile = LaunchProfile::BootstrapRegistry;
    waits.exited = true;
    waits.console_status_lost_process = Some(s3_outer_process);
    waits.running_process = Some(crate::wyr1c_native::E8_REGISTRY_FIXTURE_DRIVER_PROCESS);
    let recovered = crate::wyr1c_native::exercise_e8_registry_recovery_orchestrator(
        &mut platform,
        &mut loader,
        &mut waits,
        &bootfs,
        wyrmroot_runtime::sha256::digest(&image),
        s3.registry_generation,
        state,
        jobs,
        s3_console_peer,
        topology,
        driver_request,
        |platform, channel, bytes| {
            platform.push(channel, bytes.to_vec(), &[]);
            Ok(())
        },
    )
    .unwrap_or_else(|error| {
        panic!(
            "production registry recovery failed: {error:?}; evidence={}, inbound={}/{}, moved={}, sent={}, closed={}, now={}",
            platform.e8_evidence.len(),
            platform.inbound_cursor,
            platform.inbound.len(),
            platform.moved.len(),
            platform.sent.len(),
            platform.closed.len(),
            platform.now,
        )
    });
    let replacement_registry_generation = recovered.registry_generation;
    assert!(replacement_registry_generation > s3.registry_generation);
    let rebound_serial = crate::wyr1e8_evidence::SerialFacts {
        publication_generation: recovered.publication_generation,
        ..new_serial
    };
    let rebound_driver = published_driver(rebound_serial, s3_ready.bundle_generation);
    broker.replace_published_driver(rebound_driver).unwrap();
    let rebound_attach = attach_serial(&mut broker, rebound_serial.publication_generation, 40);
    assert!(rebound_attach.attach_transaction_id > new_attach.attach_transaction_id);
    assert!(rebound_attach.stream_generation > new_attach.stream_generation);

    let mut state = recovered.shell;
    let mut jobs = recovered.jobs;
    let mut topology = recovered.topology;
    let context = ShellLaunchContext {
        registry_control: DwHandle(0xE8B5_0010),
        topology: &mut topology,
        state: &mut state,
    };
    assert_eq!(platform.e8_evidence.len(), 26);
    assert_eq!(jobs.session_count(), 0);
    assert_eq!(jobs.jobs.live_jobs(), 0);

    let s4_console_grant = context
        .topology
        .issue(410, EndpointKind::LaunchSession)
        .unwrap();
    let s4_registry_client = context
        .topology
        .issue(412, EndpointKind::RegistryClient)
        .unwrap();
    let s4_shell_jobs = context
        .topology
        .issue(412, EndpointKind::LaunchSession)
        .unwrap();
    let s4_console_session = DwHandle(192);
    let s4_session = DwHandle(193);
    let s4_console_owner = SessionOwner {
        process: DwHandle(904),
        launch_channel: DwHandle(905),
        task_group: DwHandle(906),
    };
    jobs
        .install_scoped_session(
            s4_console_grant,
            s4_console_session,
            LaunchSessionScope::ConsoleLauncher,
        )
        .unwrap();
    jobs
        .attach_session_owner(s4_console_grant, s4_console_owner)
        .unwrap();
    let s4_outer_reservation = transaction(s4_console_grant, 413);
    let s4_outer = jobs.jobs.begin_launch(s4_outer_reservation).unwrap();
    jobs
        .jobs
        .commit_launch(
            s4_outer,
            s4_console_owner.process.0,
            s4_console_owner.task_group.0,
            s4_console_owner.launch_channel.0,
        )
        .unwrap();
    jobs
        .install_scoped_session(s4_shell_jobs, s4_session, LaunchSessionScope::ShellJobs)
        .unwrap();
    jobs
        .attach_outer_job(s4_shell_jobs, s4_outer.job_id)
        .unwrap();
    let s4 = crate::wyr1e8_evidence::ShellTuple {
        console_generation: 1,
        status_generation: 1,
        shell_generation: 1,
        outer_launch_transaction: s4_outer_reservation.transaction_id,
        outer_job_id: s4_outer.job_id,
        registry_generation: replacement_registry_generation,
        registry_endpoint_id: s4_registry_client.endpoint_id,
        registry_endpoint_generation: s4_registry_client.endpoint_generation,
        shell_jobs_connection_id: s4_shell_jobs.endpoint_id,
        shell_jobs_generation: s4_shell_jobs.endpoint_generation,
    };
    let s4_ready = crate::wyr1e8_evidence::SerialReady {
        console_generation: s4.console_generation,
        status_generation: s4.status_generation,
        shell_generation: s4.shell_generation,
        attach_transaction: rebound_attach.attach_transaction_id,
        stream_generation: rebound_attach.stream_generation,
        bundle_generation: rebound_attach.driver.control.bundle_generation.0,
    };
    assert_ne!(s4_console_grant, s3_console_grant);

    // Stale publication ownership and a duplicate old READY are terminal
    // relation failures; neither may mutate the accepted observer.
    let mut stale_publication_observer = context.state.e8_evidence;
    let stale_before = stale_publication_observer;
    assert_eq!(
        stale_publication_observer.observe_serial(new_serial),
        Err(InitError::Accounting)
    );
    assert_eq!(stale_publication_observer, stale_before);

    context.state.stage_e8_shell_ready(&mut platform, s4).unwrap();
    context
        .state
        .observe_e8_serial_ready(&mut platform, s4_ready)
        .unwrap();
    assert_eq!(context.state.e8_stage(), 4);
    assert!(context.state.e8_shell_ready());
    assert_eq!(context.state.e8_trigger, None);
    assert_eq!(jobs.session_count(), 2);
    assert_eq!(jobs.jobs.live_jobs(), 1);
    assert_eq!(platform.e8_evidence.len(), 27);
    assert_eq!(
        context.state.stage_e8_shell_ready(&mut platform, s4),
        Err(InitError::Accounting)
    );
    assert_eq!(
        context
            .state
            .observe_e8_serial_ready(&mut platform, s4_ready),
        Err(InitError::Accounting)
    );
    assert_eq!(platform.e8_evidence.len(), 27);

    std::println!();
    for record in &platform.e8_evidence {
        std::println!("E8FIXTURE_RECORD={}", lowercase_hex(record));
    }
    std::println!(
        "E8FIXTURE_REQUEST={}",
        lowercase_hex(&accepted_request)
    );
    std::println!("E8FIXTURE_RESPONSE={}", lowercase_hex(&accepted_response));
    let mut handle_shape = String::new();
    for (index, info) in captured_handles.iter().enumerate() {
        if index != 0 {
            handle_shape.push(',');
        }
        write!(
            &mut handle_shape,
            "{}:{:016x}:{}",
            info.object_type.0,
            info.rights.0,
            index + 1
        )
        .unwrap();
    }
    std::println!("E8FIXTURE_HANDLES={handle_shape}");
}
