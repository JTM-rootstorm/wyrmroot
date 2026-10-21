//! registryd's role driven through the runtime's recording platform.
//!
//! These drive [`run`] with scripted kernel replies and check the exact
//! syscall sequence and the failure code it stops with. They cover the
//! bootstrap stages, which need no publication or client, and the first pass
//! through the resident service loop, on the one platform instance `run`
//! shares with the loop's transport.

use std::vec;
use std::vec::Vec;

use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_SIGNAL_PEER_CLOSED,
    DW_SIGNAL_READABLE, DW_STATUS_PEER_CLOSED, DwHandle, DwReceivedHandleInfoV1, DwRights,
    DwSignals, DwWaitResultV1,
};
use wyrmroot_loader::launch::{CHILD_CHANNEL_RIGHTS, LaunchProfile, SELF_ROOT_RIGHTS, encode_init};
use wyrmroot_runtime::platform::recording::{Call, Datagram, RecordingPlatform, Reply};
use wyrmroot_runtime::{BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, NativeError};

use super::{registry_error_code, run, step_outcome};
use crate::RegistryError;
use crate::service::ServiceError;

const BOOTSTRAP: DwHandle = DwHandle(0x10);
const SELF_ROOT: DwHandle = DwHandle(0x20);
const CONTROL: DwHandle = DwHandle(0x21);

/// registryd's failure codes are `0xB101_0000 | stage`.
const fn failure(stage: u32) -> u32 {
    0xB101_0000 | stage
}

fn status(status: deepwyrm_syscall::DwStatus) -> NativeError {
    NativeError::Status(status)
}

fn valid_bootstrap() -> Reply {
    Reply::CapabilityInfo(Ok(CapabilityInfo {
        object_type: BOOTSTRAP_CHANNEL_EXPECTATION.object_type,
        rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
    }))
}

fn startup_handles() -> [DwReceivedHandleInfoV1; 2] {
    [
        DwReceivedHandleInfoV1 {
            handle: SELF_ROOT,
            object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
            rights: SELF_ROOT_RIGHTS,
            ..DwReceivedHandleInfoV1::default()
        },
        DwReceivedHandleInfoV1 {
            handle: CONTROL,
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: CHILD_CHANNEL_RIGHTS,
            ..DwReceivedHandleInfoV1::default()
        },
    ]
}

fn valid_init() -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    let size = encode_init(LaunchProfile::BootstrapRegistry, 7, &mut bytes).unwrap();
    bytes.truncate(size);
    bytes
}

#[test]
fn failed_bootstrap_query_stops_after_one_call() {
    let mut platform = RecordingPlatform::scripted([Reply::CapabilityInfo(Err(status(
        DW_STATUS_PEER_CLOSED,
    )))]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(1)));
    assert_eq!(
        platform.calls(),
        &[Call::QueryCapabilityInfo { handle: BOOTSTRAP }]
    );
    platform.assert_script_consumed();
}

#[test]
fn wrong_bootstrap_rights_stop_before_the_receive() {
    let mut platform = RecordingPlatform::scripted([Reply::CapabilityInfo(Ok(CapabilityInfo {
        object_type: BOOTSTRAP_CHANNEL_EXPECTATION.object_type,
        rights: DwRights(0),
    }))]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(2)));
    assert_eq!(
        platform.calls(),
        &[Call::QueryCapabilityInfo { handle: BOOTSTRAP }]
    );
    platform.assert_script_consumed();
}

#[test]
fn failed_startup_receive_stops_there() {
    let mut platform = RecordingPlatform::scripted([
        valid_bootstrap(),
        Reply::Receive(Err(status(DW_STATUS_PEER_CLOSED))),
    ]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(3)));
    platform.assert_script_consumed();
}

#[test]
fn a_short_handle_count_stops_without_parsing() {
    let mut platform = RecordingPlatform::scripted([
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: valid_init(),
            handles: vec![startup_handles()[0]],
        })),
    ]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(4)));
    platform.assert_script_consumed();
}

#[test]
fn a_malformed_init_stops_before_validating_handles() {
    let mut platform = RecordingPlatform::scripted([
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: vec![0xFFu8; 56],
            handles: Vec::from(startup_handles()),
        })),
    ]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(5)));
    platform.assert_script_consumed();
}

/// The metadata parse admits, but a fresh query disagrees with it: registryd
/// re-checks each received handle with the kernel instead of trusting the
/// receive-time metadata alone.
#[test]
fn a_self_root_the_fresh_query_disowns_is_rejected() {
    let mut platform = RecordingPlatform::scripted([
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: valid_init(),
            handles: Vec::from(startup_handles()),
        })),
        Reply::CapabilityInfo(Ok(CapabilityInfo {
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: SELF_ROOT_RIGHTS,
        })),
    ]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(6)));
    assert_eq!(
        platform.calls().last(),
        Some(&Call::QueryCapabilityInfo { handle: SELF_ROOT })
    );
    platform.assert_script_consumed();
}

#[test]
fn a_control_channel_the_fresh_query_disowns_is_rejected() {
    let mut platform = RecordingPlatform::scripted([
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: valid_init(),
            handles: Vec::from(startup_handles()),
        })),
        Reply::CapabilityInfo(Ok(CapabilityInfo {
            object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
            rights: SELF_ROOT_RIGHTS,
        })),
        Reply::CapabilityInfo(Err(status(DW_STATUS_PEER_CLOSED))),
    ]);
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(7)));
    assert_eq!(
        platform.calls().last(),
        Some(&Call::QueryCapabilityInfo { handle: CONTROL })
    );
    platform.assert_script_consumed();
}

/// The full bootstrap sequence, then one pass through the resident loop, all
/// on the one `RecordingPlatform` `run` shares with `NativeTransport`: proof
/// that the bootstrap stage and the service loop are one continuous syscall
/// sequence over the caller's platform, not two separately constructed ones.
#[test]
fn a_valid_bootstrap_sends_ready_closes_both_handles_and_enters_the_loop_on_one_platform() {
    let mut platform = RecordingPlatform::scripted([
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: valid_init(),
            handles: Vec::from(startup_handles()),
        })),
        Reply::CapabilityInfo(Ok(CapabilityInfo {
            object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
            rights: SELF_ROOT_RIGHTS,
        })),
        Reply::CapabilityInfo(Ok(CapabilityInfo {
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: CHILD_CHANNEL_RIGHTS,
        })),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Wait(Err(status(DW_STATUS_PEER_CLOSED))),
    ]);
    let mut ready = vec![0u8; 40];
    let ready_size = wyrmroot_loader::launch::encode_ready_for_profile(
        LaunchProfile::BootstrapRegistry,
        7,
        &mut ready,
    )
    .unwrap();
    ready.truncate(ready_size);

    // A failed wait stops the generation with the wait's own transport code.
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(0x11)));
    assert_eq!(
        platform.calls(),
        &[
            Call::QueryCapabilityInfo { handle: BOOTSTRAP },
            Call::ReceiveChannel {
                channel: BOOTSTRAP,
                byte_capacity: 64,
                handle_capacity: 2,
            },
            Call::QueryCapabilityInfo { handle: SELF_ROOT },
            Call::QueryCapabilityInfo { handle: CONTROL },
            Call::SendChannel {
                channel: BOOTSTRAP,
                bytes: ready,
                transfers: Vec::new(),
            },
            Call::CloseHandle { handle: BOOTSTRAP },
            Call::CloseHandle { handle: SELF_ROOT },
            // The resident loop's first wait: no endpoint is installed yet
            // (the service has no state until the first InstallPublication or
            // InstallClient), so the control handle is the only wait item.
            // This call, on the same recorder as the bootstrap stage above,
            // is the proof that `run` and `NativeTransport` share one
            // platform instead of each starting a fresh one.
            Call::WaitMany {
                items: vec![super::wait_item(CONTROL)],
                deadline: deepwyrm_syscall::DW_DEADLINE_INFINITE,
            },
        ]
    );
    platform.assert_script_consumed();
}

/// A resident wait that selects the control item (index 0) carries no
/// endpoint index; computing one must not underflow. A readable control
/// datagram is received, then the next wait's failure ends the generation.
#[test]
fn a_control_wait_selects_no_endpoint() {
    let mut platform = RecordingPlatform::scripted([
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: valid_init(),
            handles: Vec::from(startup_handles()),
        })),
        Reply::CapabilityInfo(Ok(CapabilityInfo {
            object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
            rights: SELF_ROOT_RIGHTS,
        })),
        Reply::CapabilityInfo(Ok(CapabilityInfo {
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: CHILD_CHANNEL_RIGHTS,
        })),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Wait(Ok(DwWaitResultV1 {
            observed: DW_SIGNAL_READABLE,
            ..DwWaitResultV1::default()
        })),
        Reply::Receive(Ok(Datagram {
            bytes: vec![0u8; 4],
            handles: Vec::new(),
        })),
        Reply::Wait(Err(status(DW_STATUS_PEER_CLOSED))),
    ]);
    // A failed wait stops the generation with the wait's own transport code.
    assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(0x11)));
    assert!(matches!(
        platform.calls()[8],
        Call::ReceiveChannel {
            channel: CONTROL,
            ..
        }
    ));
    platform.assert_script_consumed();
}

/// The replies that take `run` through bootstrap to its first resident wait.
fn bootstrap_replies() -> Vec<Reply> {
    vec![
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: valid_init(),
            handles: Vec::from(startup_handles()),
        })),
        Reply::CapabilityInfo(Ok(CapabilityInfo {
            object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
            rights: SELF_ROOT_RIGHTS,
        })),
        Reply::CapabilityInfo(Ok(CapabilityInfo {
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: CHILD_CHANNEL_RIGHTS,
        })),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]
}

/// A resident wait that observed `signals` on the control item (index 0).
fn control_wait(signals: DwSignals) -> Reply {
    Reply::Wait(Ok(DwWaitResultV1 {
        observed: signals,
        ..DwWaitResultV1::default()
    }))
}

const BOOTSTRAP_CALLS: usize = 7;

/// System-init's session shutdown closes registryd's supervisor control before
/// it terminates the task group. A control `PEER_CLOSED` with nothing readable
/// is that orderly end: the generation returns `Ok`, so registryd exits 0.
#[test]
fn a_control_peer_close_alone_ends_the_generation_in_order() {
    let mut replies = bootstrap_replies();
    replies.push(control_wait(DW_SIGNAL_PEER_CLOSED));
    let mut platform = RecordingPlatform::scripted(replies);
    assert_eq!(run(&mut platform, BOOTSTRAP), Ok(()));
    assert_eq!(platform.calls().len(), BOOTSTRAP_CALLS + 1);
    assert!(matches!(
        platform.calls().last(),
        Some(Call::WaitMany { .. })
    ));
    platform.assert_script_consumed();
}

/// WYR1-B §8: when `READABLE` and `PEER_CLOSED` arrive together, the committed
/// datagram is received and dispatched first; the orderly end needs a fresh
/// wait that sees the close with nothing readable.
#[test]
fn a_control_datagram_beside_the_peer_close_is_dispatched_before_the_orderly_end() {
    let mut replies = bootstrap_replies();
    replies.push(control_wait(DwSignals(
        DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0,
    )));
    // A malformed control datagram with no handles: dispatched and dropped.
    replies.push(Reply::Receive(Ok(Datagram {
        bytes: vec![0u8; 4],
        handles: Vec::new(),
    })));
    replies.push(control_wait(DW_SIGNAL_PEER_CLOSED));
    let mut platform = RecordingPlatform::scripted(replies);
    assert_eq!(run(&mut platform, BOOTSTRAP), Ok(()));
    let resident = &platform.calls()[BOOTSTRAP_CALLS..];
    assert_eq!(resident.len(), 3);
    assert!(matches!(resident[0], Call::WaitMany { .. }));
    assert!(matches!(
        resident[1],
        Call::ReceiveChannel {
            channel: CONTROL,
            ..
        }
    ));
    assert!(matches!(resident[2], Call::WaitMany { .. }));
    platform.assert_script_consumed();
}

/// Every step failure other than the orderly close stops the generation with
/// its own code: a transport error keeps its operation's, and each service
/// error has one written out. None is the old catch-all `0xB101_0010`, and
/// none repeats a bootstrap or transport code.
#[test]
fn every_other_step_failure_has_its_own_code() {
    assert_eq!(step_outcome(Ok(())), None);
    assert_eq!(
        step_outcome(Err(ServiceError::ControlPeerClosed)),
        Some(Ok(()))
    );
    assert_eq!(
        step_outcome(Err(ServiceError::Transport(failure(0x13)))),
        Some(Err(failure(0x13)))
    );
    let states = [
        RegistryError::ZeroIdentity,
        RegistryError::WrongRegistryGeneration,
        RegistryError::DuplicateEndpoint,
        RegistryError::DuplicatePublication,
        RegistryError::DuplicateClient,
        RegistryError::DuplicateService,
        RegistryError::StaleServiceGeneration,
        RegistryError::Capacity,
        RegistryError::UnknownEndpoint,
        RegistryError::WrongEndpointGeneration,
        RegistryError::NotPublished,
        RegistryError::UnsupportedVersion,
        RegistryError::EnumerationDenied,
        RegistryError::TransactionLive,
        RegistryError::TransactionReplay,
        RegistryError::OutstandingLimit,
        RegistryError::WrongEndpointKind,
        RegistryError::UnknownTransaction,
        RegistryError::InvalidState,
    ];
    let mut codes = vec![match step_outcome(Err(ServiceError::InvalidWaitEvent)) {
        Some(Err(code)) => code,
        other => panic!("an invalid wait event must fail, got {other:?}"),
    }];
    for state in states {
        let code = registry_error_code(state);
        assert_eq!(
            step_outcome(Err(ServiceError::State(state))),
            Some(Err(code))
        );
        codes.push(code);
    }
    assert_eq!(codes[0], failure(0x1B));
    for (index, code) in codes.iter().enumerate() {
        assert_eq!(
            code & 0xFFFF_0000,
            failure(0),
            "{code:#X} left registryd's range"
        );
        // 0x01..=0x0B bootstrap, 0x10 the old catch-all, 0x11..=0x1A transport.
        assert!(
            code & 0xFFFF > 0x1A,
            "{code:#X} collides with an earlier code"
        );
        assert!(!codes[..index].contains(code), "{code:#X} is not distinct");
    }
}
