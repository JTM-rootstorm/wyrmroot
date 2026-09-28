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

use super::{ConsoledStreams, run};

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
#[cfg(not(feature = "wyr1d-selector32"))]
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
