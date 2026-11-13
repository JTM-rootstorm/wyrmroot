//! consoled's role driven through the runtime's recording platform.
//!
//! These run the role's real code with scripted kernel replies and check the
//! exact syscall sequence and the failure step it stops with. They cover the
//! stream adapter's bounded wait and the bootstrap stages, which need no
//! registry, connector or launcher peer.

use std::vec;
use std::vec::Vec;

use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_READ, DW_SIGNAL_PEER_CLOSED,
    DW_SIGNAL_READABLE, DW_STATUS_PEER_CLOSED, DwDeadline, DwHandle, DwReceivedHandleInfoV1,
    DwSignals, DwWaitResultV1,
};
use wyrmroot_loader::launch::{CHILD_CHANNEL_RIGHTS, CONSOLED_BYTES, SELF_ROOT_RIGHTS};
use wyrmroot_runtime::platform::recording::{Call, Datagram, RecordingPlatform, Reply};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, NativeError, NativeOutputError, StreamSystem,
    WYR0_I_SUPERVISION_POLICY,
};

use wyrmroot_launch_proto::{
    MAX_LAUNCH_MESSAGE_BYTES, Message as LaunchMessage, Reservation as LaunchReservation,
    parse_message,
};

use super::{ConsoledStreams, encode_console_echo_launch, run};

const BOOTSTRAP: DwHandle = DwHandle(0x10);
const ENDPOINT: DwHandle = DwHandle(0x40);

fn peer_closed() -> NativeError {
    NativeError::Status(DW_STATUS_PEER_CLOSED)
}

/// A stream wait is bounded at the supervision ready timeout past the active
/// clock, and returns the full observed snapshot. This is the property that
/// keeps consoled off the runtime's blanket adapter, which waits forever.
#[test]
fn a_stream_wait_is_bounded_by_the_ready_timeout() {
    let observed = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
    let mut platform = RecordingPlatform::scripted([
        Reply::Value(Ok(5_000)),
        Reply::Wait(Ok(DwWaitResultV1 {
            observed,
            ..DwWaitResultV1::default()
        })),
    ]);
    let signals = DW_SIGNAL_READABLE;
    assert_eq!(
        ConsoledStreams::new(&mut platform).wait(ENDPOINT, signals),
        Ok(observed)
    );
    assert_eq!(
        platform.calls(),
        [
            Call::MonotonicActiveNow,
            Call::WaitOne {
                handle: ENDPOINT,
                signals,
                deadline: DwDeadline(5_000 + WYR0_I_SUPERVISION_POLICY.ready_timeout_ns),
            },
        ]
    );
    platform.assert_script_consumed();
}

/// A deadline that would overflow is refused before any wait is made.
#[test]
fn a_stream_wait_deadline_overflow_waits_for_nothing() {
    let mut platform = RecordingPlatform::scripted([Reply::Value(Ok(u64::MAX))]);
    assert_eq!(
        ConsoledStreams::new(&mut platform).wait(ENDPOINT, DW_SIGNAL_READABLE),
        Err(NativeError::Output(NativeOutputError::DeadlineOverflow))
    );
    assert_eq!(platform.calls(), [Call::MonotonicActiveNow]);
    platform.assert_script_consumed();
}

/// The adapter sends data records with no handle transfer and closes through
/// the platform.
#[test]
fn a_stream_send_moves_no_handles_and_close_reaches_the_platform() {
    let mut platform = RecordingPlatform::scripted([Reply::Unit(Ok(())), Reply::Unit(Ok(()))]);
    let mut streams = ConsoledStreams::new(&mut platform);
    assert_eq!(streams.send(ENDPOINT, b"hi"), Ok(()));
    assert_eq!(streams.close(ENDPOINT), Ok(()));
    assert_eq!(
        platform.calls(),
        [
            Call::SendChannel {
                channel: ENDPOINT,
                bytes: b"hi".to_vec(),
                transfers: Vec::new(),
            },
            Call::CloseHandle { handle: ENDPOINT },
        ]
    );
    platform.assert_script_consumed();
}

fn valid_bootstrap() -> Reply {
    Reply::CapabilityInfo(Ok(CapabilityInfo {
        object_type: BOOTSTRAP_CHANNEL_EXPECTATION.object_type,
        rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
    }))
}

fn query_then_receive() -> [Call; 2] {
    [
        Call::QueryCapabilityInfo { handle: BOOTSTRAP },
        Call::ReceiveChannel {
            channel: BOOTSTRAP,
            byte_capacity: CONSOLED_BYTES,
            handle_capacity: 3,
        },
    ]
}

/// INIT's three handles as the loader sends them: the self root, then the
/// registry client and launch session Channels.
fn init_handles() -> Vec<DwReceivedHandleInfoV1> {
    [
        (0x20, DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS),
        (0x21, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS),
        (0x22, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS),
    ]
    .into_iter()
    .map(|(handle, object_type, rights)| DwReceivedHandleInfoV1 {
        handle: DwHandle(handle),
        object_type,
        rights,
        ..DwReceivedHandleInfoV1::default()
    })
    .collect()
}

fn closes(handles: &[u64]) -> Vec<Call> {
    handles
        .iter()
        .map(|&handle| Call::CloseHandle {
            handle: DwHandle(handle),
        })
        .collect()
}

/// The bootstrap query is the first syscall, and its failure stops at step 3
/// with nothing else run.
#[test]
fn a_failed_bootstrap_query_stops_at_step_3() {
    let mut platform = RecordingPlatform::scripted([Reply::CapabilityInfo(Err(peer_closed()))]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(3));
    assert_eq!(
        platform.calls(),
        [Call::QueryCapabilityInfo { handle: BOOTSTRAP }]
    );
    platform.assert_script_consumed();
}

/// A bootstrap Channel with the wrong rights stops at step 4, before INIT is
/// received.
#[test]
fn a_wrong_bootstrap_channel_stops_at_step_4() {
    let mut platform = RecordingPlatform::scripted([Reply::CapabilityInfo(Ok(CapabilityInfo {
        object_type: BOOTSTRAP_CHANNEL_EXPECTATION.object_type,
        rights: DW_RIGHT_READ,
    }))]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(4));
    assert_eq!(
        platform.calls(),
        [Call::QueryCapabilityInfo { handle: BOOTSTRAP }]
    );
    platform.assert_script_consumed();
}

/// INIT is received into a consoled-profile buffer with room for three
/// handles; a failed receive stops at step 5.
#[test]
fn a_failed_init_receive_stops_at_step_5() {
    let mut platform =
        RecordingPlatform::scripted([valid_bootstrap(), Reply::Receive(Err(peer_closed()))]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(5));
    assert_eq!(platform.calls(), query_then_receive());
    platform.assert_script_consumed();
}

/// Too few handles closes every handle that arrived, last first, then the
/// bootstrap Channel, and stops at step 6.
#[test]
fn a_short_handle_set_closes_what_arrived_then_the_bootstrap() {
    let handles = init_handles()[..2].to_vec();
    let mut platform = RecordingPlatform::scripted([
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: vec![0; CONSOLED_BYTES],
            handles,
        })),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(6));
    let mut expected = query_then_receive().to_vec();
    expected.extend(closes(&[0x21, 0x20, BOOTSTRAP.0]));
    assert_eq!(platform.calls(), expected);
    platform.assert_script_consumed();
}

/// A malformed INIT closes all three handles, last first, then the bootstrap
/// Channel, and stops at step 7. A failed close does not stop the rest.
#[test]
fn a_malformed_init_closes_every_handle_then_the_bootstrap() {
    let mut platform = RecordingPlatform::scripted([
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: vec![0; CONSOLED_BYTES],
            handles: init_handles(),
        })),
        Reply::Unit(Err(peer_closed())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(7));
    let mut expected = query_then_receive().to_vec();
    expected.extend(closes(&[0x22, 0x21, 0x20, BOOTSTRAP.0]));
    assert_eq!(platform.calls(), expected);
    platform.assert_script_consumed();
}

/// A valid INIT whose self-root close fails releases the launch session, the
/// registry client and the bootstrap Channel, in that order, and stops at
/// step 8. Selector 32 reads its configuration off the bootstrap Channel
/// before this close, so the sequence is this build's only without it.
#[test]
fn a_failed_self_root_close_releases_the_authorities_then_the_bootstrap() {
    use wyrmroot_loader::launch::encode_consoled_init;

    let mut init = [0u8; CONSOLED_BYTES];
    assert_eq!(
        encode_consoled_init(7, 1, 2, 3, 4, 5, &mut init),
        Ok(CONSOLED_BYTES)
    );
    let mut platform = RecordingPlatform::scripted([
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: init.to_vec(),
            handles: init_handles(),
        })),
        Reply::Unit(Err(peer_closed())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(8));
    let mut expected = query_then_receive().to_vec();
    expected.extend(closes(&[0x20, 0x22, 0x21, BOOTSTRAP.0]));
    assert_eq!(platform.calls(), expected);
    platform.assert_script_consumed();
}

/// The historical console-echo child stays an explicit launch of its own
/// path: argv0 only, no environment, and the three stream handles, under the
/// caller's reservation.
#[test]
fn historical_policy_remains_an_explicit_three_stream_launch() {
    let reservation = LaunchReservation {
        connection_id: 3,
        generation: 4,
        transaction_id: 5,
    };
    let mut bytes = [0u8; MAX_LAUNCH_MESSAGE_BYTES];
    let size = encode_console_echo_launch(reservation, &mut bytes).unwrap();
    let parsed = parse_message(&bytes[..size], 3).unwrap();
    assert_eq!(parsed.reservation, reservation);
    let LaunchMessage::Launch(request) = parsed.message else {
        panic!("console-echo is not a plain launch: {:?}", parsed.message);
    };
    assert_eq!(request.path, "bin/console-echo");
    assert_eq!(
        (request.argc(), request.arg(0)),
        (1, Some("bin/console-echo"))
    );
    assert_eq!(request.environment_count(), 0);
    assert_eq!(request.stream_count, 3);
}

// A shell that ends the session with Ctrl-D exits with
// `SHELL_SESSION_SHUTDOWN_STATUS` and its streams close as it exits. When the
// stream close reaches the data pump before the WAIT result, the pump calls
// `recover_child`, which used to relaunch the shell regardless, so Ctrl-D
// would leave a fresh prompt and the system would never power off. (Found
// while chasing the 2026-11-12 dev-boot hang, which turned out to be wyrmsh
// closing SHELL_JOBS before exit.) These drive `recover_child` through both
// orders the launch replies can arrive in.

const LAUNCH: DwHandle = DwHandle(0x50);
const SHELL_JOB: u64 = 200;
const NOW_NS: u64 = 7_000_000_000;

fn launch_authorities() -> super::StartupAuthorities {
    super::StartupAuthorities {
        registry: DwHandle(0x51),
        launch: LAUNCH,
        registry_generation: 1,
        registry_endpoint_id: 1,
        registry_endpoint_generation: 1,
        launch_connection_id: 7,
        launch_connection_generation: 8,
        startup_transaction: 10,
    }
}

fn launch_reservation(transaction_id: u64) -> LaunchReservation {
    LaunchReservation {
        connection_id: 7,
        generation: 8,
        transaction_id,
    }
}

fn endpoint(handle: u64) -> wyrmroot_runtime::StreamEndpoint {
    wyrmroot_runtime::StreamEndpoint::from_validated_handle(DwHandle(handle)).unwrap()
}

/// A model with one live shell (job 200) on serial generation 1, and the
/// role's matching child session whose WAIT is transaction 5.
fn live_shell() -> (wyrmroot_consoled::ConsoleModel, super::ChildSession) {
    use wyrmroot_consoled::{ConnectRequest, ConsoleModel, SerialCorrelation, StreamKind};
    let mut model = ConsoleModel::new();
    model
        .begin_connect(ConnectRequest {
            registry_generation: 1,
            registry_endpoint_id: 1,
            registry_endpoint_generation: 1,
            requested_publication_generation: 1,
            connector_client_transaction: 1,
        })
        .unwrap();
    model
        .attach_connected(
            SerialCorrelation {
                registry_generation: 1,
                registry_endpoint_id: 1,
                registry_endpoint_generation: 1,
                publication_generation: 1,
                connector_client_transaction: 1,
                device_role: 1,
                device_bundle: 1,
                driver_attempt: 1,
                driver_control_endpoint_id: 1,
                driver_control_endpoint_generation: 1,
                attach_transaction: 1,
                stream_generation: 1,
            },
            0,
        )
        .unwrap();
    let mut launch = model.begin_child_launch(100).unwrap();
    for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
        launch.move_child_peer(kind).unwrap();
    }
    let event = model
        .commit_child_launch(&mut launch, SHELL_JOB)
        .unwrap()
        .ids
        .into();
    let child = super::ChildSession {
        job_id: SHELL_JOB,
        event,
        wait: Some(launch_reservation(5)),
        session_shutdown: false,
        stdin: wyrmroot_runtime::NativeOutput::new(endpoint(0x61)),
        stdout: wyrmroot_runtime::NativeInput::new(endpoint(0x62)),
        stderr: wyrmroot_runtime::NativeInput::new(endpoint(0x63)),
        status: None,
    };
    (model, child)
}

fn idle_serial() -> super::SerialSession {
    super::SerialSession {
        identity: wyrmroot_device_proto::connector::ConnectorIdentity {
            publication_generation: 1,
            client_transaction_id: 1,
            device_role_id: 1,
            bundle_generation: 1,
            driver_attempt_generation: 1,
            driver_control_endpoint_id: 1,
            driver_control_endpoint_generation: 1,
            attach_transaction_id: 1,
            stream_generation: 1,
        },
        watch: None,
        raw_owned: true,
        release_witness: None,
        input: wyrmroot_runtime::NativeInput::new(endpoint(0x70)),
        output: wyrmroot_runtime::NativeOutput::new(endpoint(0x70)),
    }
}

fn now() -> Reply {
    Reply::Value(Ok(NOW_NS))
}

/// One launch-channel reply as `receive_launch_any` reads it: the clock for
/// its deadline, a readable wait, then the datagram.
fn launch_reply(bytes: Vec<u8>) -> [Reply; 3] {
    [
        now(),
        Reply::Wait(Ok(DwWaitResultV1 {
            observed: DW_SIGNAL_READABLE,
            ..DwWaitResultV1::default()
        })),
        Reply::Receive(Ok(Datagram {
            bytes,
            handles: Vec::new(),
        })),
    ]
}

fn shutdown_result(transaction_id: u64) -> Vec<u8> {
    let mut bytes = [0u8; MAX_LAUNCH_MESSAGE_BYTES];
    let size = wyrmroot_launch_proto::encode_job_result(
        launch_reservation(transaction_id),
        SHELL_JOB,
        wyrmroot_launch_proto::TerminationResult {
            classification: wyrmroot_launch_proto::TerminationClassification::NormalExit,
            application_code: wyrmroot_launch_proto::SHELL_SESSION_SHUTDOWN_STATUS,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        },
        &mut bytes,
    )
    .unwrap();
    bytes[..size].to_vec()
}

fn launch_error(transaction_id: u64, code: wyrmroot_launch_proto::ErrorCode) -> Vec<u8> {
    let mut bytes = [0u8; MAX_LAUNCH_MESSAGE_BYTES];
    let size =
        wyrmroot_launch_proto::encode_error(launch_reservation(transaction_id), code, &mut bytes)
            .unwrap();
    bytes[..size].to_vec()
}

fn job_message(
    transaction_id: u64,
    kind: wyrmroot_launch_proto::MessageType,
    value: u64,
) -> Vec<u8> {
    let mut bytes = [0u8; MAX_LAUNCH_MESSAGE_BYTES];
    let size = wyrmroot_launch_proto::encode_job_message(
        launch_reservation(transaction_id),
        kind,
        value,
        &mut bytes,
    )
    .unwrap();
    bytes[..size].to_vec()
}

fn recover_from_stdout_close(
    script: Vec<Reply>,
) -> (Result<super::TerminalOutcome, u32>, RecordingPlatform) {
    let (mut model, mut child) = live_shell();
    let mut serial = idle_serial();
    let mut transactions = super::TransactionIds::after(10).unwrap();
    let mut input = super::Pending::new();
    let mut output = super::Pending::new();
    let mut platform = RecordingPlatform::scripted(script);
    let outcome = super::recover_child(
        &mut platform,
        launch_authorities(),
        &mut transactions,
        &mut model,
        &mut serial,
        &mut child,
        &mut input,
        &mut output,
        super::ChildFault::Peer(wyrmroot_consoled::StreamKind::Stdout),
    );
    (outcome, platform)
}

/// The WAIT result is already queued when the cancel goes out: it carries
/// the shutdown status, and the cancel is refused as too late.
#[test]
fn a_shutdown_exit_seen_first_as_a_stream_close_ends_the_session() {
    use wyrmroot_launch_proto::{ErrorCode, MessageType};
    let mut script = vec![now(), Reply::Unit(Ok(()))];
    script.extend(launch_reply(shutdown_result(5)));
    script.extend(launch_reply(launch_error(
        11,
        ErrorCode::CancellationUnavailable,
    )));
    script.extend([
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    script.extend([now(), now(), Reply::Unit(Ok(()))]);
    script.extend(launch_reply(job_message(
        12,
        MessageType::Closed,
        SHELL_JOB,
    )));
    script.push(now());

    let (outcome, platform) = recover_from_stdout_close(script);

    assert_eq!(outcome, Ok(super::TerminalOutcome::SessionEnded));
    platform.assert_script_consumed();
}

/// The cancel wins: the launcher had not yet recorded the exit. Termination
/// is then refused because the shell already exited, and the WAIT that
/// follows still reports the shutdown status.
#[test]
fn a_shutdown_exit_whose_wait_was_cancelled_still_ends_the_session() {
    use wyrmroot_launch_proto::{ErrorCode, MessageType};
    let mut script = vec![now(), Reply::Unit(Ok(()))];
    script.extend(launch_reply(job_message(11, MessageType::Cancelled, 5)));
    script.extend([
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    script.push(now());
    script.push(Reply::Unit(Ok(())));
    script.extend(launch_reply(launch_error(12, ErrorCode::InvalidState)));
    script.push(Reply::Unit(Ok(())));
    script.extend(launch_reply(shutdown_result(13)));
    script.extend([now(), Reply::Unit(Ok(()))]);
    script.extend(launch_reply(job_message(
        14,
        MessageType::Closed,
        SHELL_JOB,
    )));
    script.push(now());

    let (outcome, platform) = recover_from_stdout_close(script);

    assert_eq!(outcome, Ok(super::TerminalOutcome::SessionEnded));
    platform.assert_script_consumed();
}

/// The serial connection drops just as the shell exits with the shutdown
/// status: the session still ends, instead of reattaching serial and
/// launching a new shell.
#[test]
fn a_shutdown_exit_that_races_serial_loss_ends_the_session() {
    use wyrmroot_launch_proto::{ErrorCode, MessageType};
    let (mut model, mut child) = live_shell();
    let mut serial = idle_serial();
    let mut transactions = super::TransactionIds::after(10).unwrap();
    let mut input = super::Pending::new();
    let mut output = super::Pending::new();
    // Serial loss is noticed, then the raw endpoint is closed.
    let mut script = vec![now(), Reply::Unit(Ok(()))];
    // The cancel finds the shell's WAIT result already queued.
    script.push(Reply::Unit(Ok(())));
    script.extend(launch_reply(shutdown_result(5)));
    script.extend(launch_reply(launch_error(
        11,
        ErrorCode::CancellationUnavailable,
    )));
    script.extend([
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    script.extend([now(), now(), Reply::Unit(Ok(()))]);
    script.extend(launch_reply(job_message(
        12,
        MessageType::Closed,
        SHELL_JOB,
    )));
    script.push(now());
    let mut platform = RecordingPlatform::scripted(script);

    let outcome = super::recover_serial(
        &mut platform,
        launch_authorities(),
        &mut transactions,
        &mut model,
        &mut serial,
        &mut child,
        &mut input,
        &mut output,
    );

    assert_eq!(outcome, Ok(super::TerminalOutcome::SessionEnded));
    platform.assert_script_consumed();
}
