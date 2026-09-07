use super::*;
extern crate std;
use alloc::{format, string::String};
use core::fmt::Write;
use wyrmroot_bootfs::launch_policy::JOB_V2_PROFILE_ID;

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
        .record_e8_shell_jobs(platform, request, response, handles)
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

#[test]
fn actual_dispatcher_emits_s2_driver_trigger_record_after_accepted_prefix() {
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
    let s2 = crate::wyr1e8_evidence::ShellTuple {
        console_generation: s1.console_generation,
        status_generation: 111,
        shell_generation: 112,
        outer_launch_transaction: 113,
        outer_job_id: 114,
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
    state.e8_evidence.observe_serial(serial).unwrap();
    state.stage_e8_shell_ready(&mut platform, s2).unwrap();
    state
        .observe_e8_serial_ready(&mut platform, s2_ready)
        .unwrap();
    assert_eq!(platform.e8_evidence.len(), 21);

    let image = executable();
    let (bootfs, generation) = recovery_policy_bootfs(&image);
    let archive = Archive::new(&bootfs).unwrap();
    let policy = PolicyView::from_bootfs(archive, generation).unwrap();
    let session = DwHandle(90);
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
    let mut jobs = JobDispatcher::new();
    jobs.install_scoped_session(s2_grant, session, LaunchSessionScope::ShellJobs)
        .unwrap();
    let mut loader = InitSendLoader::new();
    loader.fail_init = false;
    let mut waits = AcceptedJobV2Waits {
        transaction_id: reservation.transaction_id,
        profile: LaunchProfile::JobV2Streams,
        exited: false,
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
            launch_transaction: reservation.transaction_id,
            job_id: loaded.job_id,
            action: E8RecoveryAction::Driver,
        })
    );

    let response = platform.sent.last().unwrap().1.as_slice();
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

    std::println!();
    for record in &platform.e8_evidence {
        std::println!("E8FIXTURE_RECORD={}", lowercase_hex(record));
    }
    std::println!(
        "E8FIXTURE_REQUEST={}",
        lowercase_hex(&request[..request_len])
    );
    std::println!("E8FIXTURE_RESPONSE={}", lowercase_hex(response));
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
