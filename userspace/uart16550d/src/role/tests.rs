//! uart16550d's role driven through the runtime's recording platform.
//!
//! Each test gives the role a [`RecordingPlatform`] with scripted kernel
//! replies and checks the exact syscall sequence and the result. The startup
//! tests run [`run`] through the bootstrap stages that need no device. The
//! stream and control-loss tests build a driver on a fake register window
//! and call the loop helpers directly; they cover F3A.7l's detach-cause
//! recording and the orphaned driver's shutdown.

use std::vec;
use std::vec::Vec;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_READ,
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_STATUS_BAD_STATE, DW_STATUS_PEER_CLOSED,
    DwHandle, DwReceivedHandleInfoV1, DwSignals, DwStatus, DwWaitItemV1, DwWaitResultV1,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS, encode_device_driver_init,
};
use wyrmroot_runtime::platform::recording::{Call, Datagram, RecordingPlatform, Reply};
use wyrmroot_runtime::{BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, NativeError};

use super::run;

const BOOTSTRAP: DwHandle = DwHandle(0x10);
const SELF_ROOT: DwHandle = DwHandle(0x20);
const CONTROL: DwHandle = DwHandle(0x21);

fn status(status: DwStatus) -> NativeError {
    NativeError::Status(status)
}

fn valid_bootstrap() -> Reply {
    Reply::CapabilityInfo(Ok(CapabilityInfo {
        object_type: BOOTSTRAP_CHANNEL_EXPECTATION.object_type,
        rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
    }))
}

fn startup_handles() -> Vec<DwReceivedHandleInfoV1> {
    vec![
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
    let mut bytes = vec![0; DEVICE_DRIVER_BYTES];
    let size = encode_device_driver_init(1, 2, 3, 4, 5, 6, 7, &mut bytes).unwrap();
    assert_eq!(size, DEVICE_DRIVER_BYTES);
    bytes
}

fn query_then_receive() -> [Call; 2] {
    [
        Call::QueryCapabilityInfo { handle: BOOTSTRAP },
        Call::ReceiveChannel {
            channel: BOOTSTRAP,
            byte_capacity: DEVICE_DRIVER_BYTES,
            handle_capacity: 2,
        },
    ]
}

fn close(handle: DwHandle) -> Call {
    Call::CloseHandle { handle }
}

/// Runs the role with `script` and returns its result and its calls. The
/// port-I/O platform must stay untouched: no stage here reaches the device.
fn run_scripted(script: Vec<Reply>) -> (Result<u32, u32>, Vec<Call>) {
    let mut platform = RecordingPlatform::scripted(script);
    let mut pio = RecordingPlatform::new();
    let result = run(&mut platform, &mut pio, BOOTSTRAP);
    platform.assert_script_consumed();
    assert_eq!(pio.calls(), [], "no port I/O before the device stage");
    (result, platform.take_calls())
}

/// The bootstrap query is the first syscall. Its status stops the role at
/// step 1, and nothing else runs.
#[test]
fn a_failed_bootstrap_query_stops_at_step_1() {
    let (result, calls) = run_scripted(vec![Reply::CapabilityInfo(Err(status(
        DW_STATUS_PEER_CLOSED,
    )))]);
    assert_eq!(result, Err(1));
    assert_eq!(calls, [Call::QueryCapabilityInfo { handle: BOOTSTRAP }]);
}

/// A bootstrap Channel with the wrong rights is refused before the startup
/// record is received.
#[test]
fn a_wrong_bootstrap_channel_stops_at_step_2() {
    let (result, calls) = run_scripted(vec![Reply::CapabilityInfo(Ok(CapabilityInfo {
        object_type: BOOTSTRAP_CHANNEL_EXPECTATION.object_type,
        rights: DW_RIGHT_READ,
    }))]);
    assert_eq!(result, Err(2));
    assert_eq!(calls, [Call::QueryCapabilityInfo { handle: BOOTSTRAP }]);
}

/// The startup record is received into a device-driver-sized buffer with
/// room for exactly two handles.
#[test]
fn a_failed_startup_receive_stops_at_step_3() {
    let (result, calls) = run_scripted(vec![
        valid_bootstrap(),
        Reply::Receive(Err(status(DW_STATUS_PEER_CLOSED))),
    ]);
    assert_eq!(result, Err(3));
    assert_eq!(calls, query_then_receive());
}

/// A startup record with one handle closes the handle that did arrive, and
/// leaves the bootstrap Channel open, before stopping at step 4.
#[test]
fn a_short_handle_set_closes_what_arrived_then_stops_at_step_4() {
    let handles = startup_handles()[..1].to_vec();
    let (result, calls) = run_scripted(vec![
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: valid_init(),
            handles,
        })),
        Reply::Unit(Ok(())),
    ]);
    assert_eq!(result, Err(4));
    let mut expected = query_then_receive().to_vec();
    expected.push(close(SELF_ROOT));
    assert_eq!(calls, expected);
}

/// A malformed startup record with two valid handles closes both, then the
/// bootstrap Channel, before stopping at step 5. A failed close does not
/// stop the others.
#[test]
fn a_malformed_startup_record_closes_every_handle_then_stops_at_step_5() {
    let (result, calls) = run_scripted(vec![
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: vec![0xff; DEVICE_DRIVER_BYTES],
            handles: startup_handles(),
        })),
        Reply::Unit(Err(status(DW_STATUS_BAD_STATE))),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    assert_eq!(result, Err(5));
    let mut expected = query_then_receive().to_vec();
    expected.extend([close(SELF_ROOT), close(CONTROL), close(BOOTSTRAP)]);
    assert_eq!(calls, expected);
}

/// A valid startup record drops the self-root first. If that close fails,
/// control and the bootstrap Channel are closed and the role stops at step 6.
#[test]
fn a_failed_self_root_close_releases_control_and_bootstrap_then_stops_at_step_6() {
    let (result, calls) = run_scripted(vec![
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: valid_init(),
            handles: startup_handles(),
        })),
        Reply::Unit(Err(status(DW_STATUS_BAD_STATE))),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    assert_eq!(result, Err(6));
    let mut expected = query_then_receive().to_vec();
    expected.extend([close(SELF_ROOT), close(CONTROL), close(BOOTSTRAP)]);
    assert_eq!(calls, expected);
}

/// After the startup handles are settled, the role waits for the first
/// control stage. A control peer that has already closed is refused even if
/// a stage is queued: control is closed and the role stops at step 10.
#[test]
fn a_closed_control_peer_at_the_first_stage_stops_at_step_10() {
    let (result, calls) = run_scripted(vec![
        valid_bootstrap(),
        Reply::Receive(Ok(Datagram {
            bytes: valid_init(),
            handles: startup_handles(),
        })),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Wait(Ok(DwWaitResultV1 {
            index: 0,
            observed: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            ..DwWaitResultV1::default()
        })),
        Reply::Unit(Ok(())),
    ]);
    assert_eq!(result, Err(10));
    let mut expected = query_then_receive().to_vec();
    expected.extend([
        close(SELF_ROOT),
        close(BOOTSTRAP),
        Call::WaitMany {
            items: vec![control_wait_item()],
            deadline: DW_DEADLINE_INFINITE,
        },
        close(CONTROL),
    ]);
    assert_eq!(calls, expected);
}

/// The control wait item every control wait uses: readable or peer-closed.
fn control_wait_item() -> DwWaitItemV1 {
    DwWaitItemV1 {
        handle: CONTROL,
        signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    }
}

/// The resident loop's helpers in the production shape, whose signatures
/// carry no selector state.
mod resident {
    use std::vec;
    use std::vec::Vec;

    use deepwyrm_syscall::{
        DW_DEADLINE_INFINITE, DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_DEVICE_RESOURCE_INFO_V1_VERSION,
        DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DW_INTERRUPT_INFO_V1_SIZE,
        DW_INTERRUPT_INFO_V1_VERSION, DW_INTERRUPT_STATE_ARMED, DW_OBJECT_TYPE_CHANNEL,
        DW_OBJECT_TYPE_DEVICE_RESOURCE, DW_OBJECT_TYPE_INTERRUPT, DW_SIGNAL_PEER_CLOSED,
        DW_STATUS_BAD_STATE, DW_STATUS_PEER_CLOSED, DwDeviceResourceInfoV1, DwHandle,
        DwInterruptInfoV1, DwWaitResultV1,
    };
    use wyrmroot_device_proto::control::ControlEndpoint;
    use wyrmroot_device_proto::control_v1_1::{ControlIdentityV1_1, ControlMessageV1_1};
    use wyrmroot_device_proto::coordinator::{
        AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId,
    };
    use wyrmroot_device_proto::manifest::RoleId;
    use wyrmroot_runtime::native_error_code;
    use wyrmroot_runtime::platform::recording::{Call, RecordingPlatform, Reply};
    use wyrmroot_stream_proto::MAX_RECORD_BYTES;
    use wyrmroot_uart16550_core::ByteRegisterIo;

    use super::super::{StreamReadOutcome, run_event_loop, service_stream_read};
    use super::{CONTROL, close, status};
    use crate::{
        COM2_INTERRUPT_SOURCE, COM2_PIO_BASE, COM2_PIO_LENGTH, COM2_RESOURCE_ID,
        DEVICE_RESOURCE_RIGHTS, DeviceStage, INTERRUPT_RIGHTS, ProductionDriver, RAW_STREAM_RIGHTS,
        ReceivedDeviceResource, ReceivedInterrupt, ReceivedStreamEndpoint,
    };

    const RESOURCE: DwHandle = DwHandle(9);
    const INTERRUPT: DwHandle = DwHandle(12);
    const STREAM: DwHandle = DwHandle(20);

    /// A register window that reports an idle 16550: no interrupt pending.
    struct IdleIo;

    impl ByteRegisterIo for IdleIo {
        fn read(&mut self, offset: u8) -> u8 {
            if offset == 2 { 1 } else { 0 }
        }

        fn write(&mut self, _: u8, _: u8) {}
    }

    fn identity(transaction: u64) -> ControlIdentityV1_1 {
        ControlIdentityV1_1 {
            role_id: RoleId(1),
            bundle_generation: BundleGeneration(2),
            attempt_generation: AttemptGeneration(3),
            endpoint: ControlEndpoint {
                id: EndpointId(4),
                generation: EndpointGeneration(5),
            },
            transaction_id: transaction,
        }
    }

    /// An active driver, as `run` hands it to the loop, with or without an
    /// attached stream.
    fn driver(stream: bool) -> ProductionDriver<IdleIo> {
        let stage = ControlMessageV1_1::DeviceStage {
            identity: identity(6),
            stage_generation: 7,
            resource_id: COM2_RESOURCE_ID,
            pio_base: COM2_PIO_BASE,
            pio_length: COM2_PIO_LENGTH,
            source: COM2_INTERRUPT_SOURCE,
        };
        let resource = ReceivedDeviceResource {
            handle: RESOURCE,
            object_type: DW_OBJECT_TYPE_DEVICE_RESOURCE,
            rights: DEVICE_RESOURCE_RIGHTS,
            reserved0: 0,
            reserved: [0; 2],
            info: DwDeviceResourceInfoV1 {
                size: DW_DEVICE_RESOURCE_INFO_V1_SIZE,
                version: DW_DEVICE_RESOURCE_INFO_V1_VERSION,
                kind: DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
                flags: 0,
                resource_id: COM2_RESOURCE_ID,
                lease_generation: 2,
                pio_base: COM2_PIO_BASE,
                pio_length: COM2_PIO_LENGTH,
                interrupt_source: COM2_INTERRUPT_SOURCE,
                reserved: 0,
            },
        };
        let mut stage = DeviceStage::validate(identity(99), stage, resource, IdleIo).unwrap();
        stage.initialize_quiesced().unwrap();
        let interrupt = ReceivedInterrupt {
            handle: INTERRUPT,
            object_type: DW_OBJECT_TYPE_INTERRUPT,
            rights: INTERRUPT_RIGHTS,
            reserved0: 0,
            reserved: [0; 2],
            info: DwInterruptInfoV1 {
                size: DW_INTERRUPT_INFO_V1_SIZE,
                version: DW_INTERRUPT_INFO_V1_VERSION,
                source: COM2_INTERRUPT_SOURCE,
                state: DW_INTERRUPT_STATE_ARMED,
                object_generation: 10,
                binding_generation: 11,
                parent_resource_id: COM2_RESOURCE_ID,
                parent_lease_generation: 2,
                ..DwInterruptInfoV1::default()
            },
        };
        let mut driver = stage
            .validate_interrupt(
                ControlMessageV1_1::InterruptStage {
                    identity: identity(8),
                    stage_generation: 7,
                    parent_resource_id: COM2_RESOURCE_ID,
                    source: COM2_INTERRUPT_SOURCE,
                },
                interrupt,
            )
            .unwrap();
        driver.activate().unwrap();
        if stream {
            driver
                .attach_stream(
                    ControlMessageV1_1::AttachStream {
                        identity: identity(21),
                        stream_generation: 22,
                        publication_generation: 23,
                    },
                    ReceivedStreamEndpoint {
                        handle: STREAM,
                        object_type: DW_OBJECT_TYPE_CHANNEL,
                        rights: RAW_STREAM_RIGHTS,
                        reserved0: 0,
                        reserved: [0; 2],
                    },
                )
                .unwrap();
        }
        driver
    }

    fn stream_receive() -> Call {
        Call::ReceiveChannel {
            channel: STREAM,
            byte_capacity: MAX_RECORD_BYTES,
            handle_capacity: 16,
        }
    }

    fn is_detach_report(call: &Call) -> bool {
        matches!(call, Call::SendChannel { channel, transfers, .. }
            if *channel == CONTROL && transfers.is_empty())
    }

    /// F3A.7l: a native receive failure records its exact cause, then
    /// isolates the stream (close, then report the detach to devmgr).
    #[test]
    fn a_native_stream_receive_failure_records_its_cause_then_isolates() {
        let mut driver = driver(true);
        let mut platform = RecordingPlatform::scripted([
            Reply::Receive(Err(status(DW_STATUS_BAD_STATE))),
            Reply::Unit(Ok(())),
            Reply::Unit(Ok(())),
        ]);
        let pio_failed = core::cell::Cell::new(false);
        let outcome = service_stream_read(&mut platform, &mut driver, CONTROL, &pio_failed);
        assert!(matches!(outcome, Ok(StreamReadOutcome::Detached)));
        let causes = driver.counters().detach_causes;
        assert_eq!(causes.native, 1);
        assert_eq!(
            causes.last_native,
            native_error_code(status(DW_STATUS_BAD_STATE))
        );
        let calls = platform.take_calls();
        assert_eq!(calls[..2], [stream_receive(), close(STREAM)]);
        assert_eq!(calls.len(), 3);
        assert!(is_detach_report(&calls[2]));
        assert!(driver.stream_endpoint().is_none());
        platform.assert_script_consumed();
    }

    /// F3A.7l: the cause is recorded before isolation, so a detach report
    /// that fails still leaves the instance in the driver's counters.
    #[test]
    fn the_detach_cause_survives_a_failed_isolation() {
        let mut driver = driver(true);
        let mut platform = RecordingPlatform::scripted([
            Reply::Receive(Err(status(DW_STATUS_BAD_STATE))),
            Reply::Unit(Ok(())),
            Reply::Unit(Err(status(DW_STATUS_BAD_STATE))),
        ]);
        let pio_failed = core::cell::Cell::new(false);
        let outcome = service_stream_read(&mut platform, &mut driver, CONTROL, &pio_failed);
        assert!(outcome.is_err());
        assert_eq!(driver.counters().detach_causes.native, 1);
        platform.assert_script_consumed();
    }

    /// A detach report to a control peer that has closed is dropped, not a
    /// driver failure: the orphaned driver keeps running.
    #[test]
    fn a_detach_report_to_a_closed_control_peer_is_dropped() {
        let mut driver = driver(true);
        let mut platform = RecordingPlatform::scripted([
            Reply::Receive(Err(status(DW_STATUS_BAD_STATE))),
            Reply::Unit(Ok(())),
            Reply::Unit(Err(status(DW_STATUS_PEER_CLOSED))),
        ]);
        let pio_failed = core::cell::Cell::new(false);
        let outcome = service_stream_read(&mut platform, &mut driver, CONTROL, &pio_failed);
        assert!(matches!(outcome, Ok(StreamReadOutcome::Detached)));
        platform.assert_script_consumed();
    }

    fn peer_closed_at(index: u32) -> Reply {
        Reply::Wait(Ok(DwWaitResultV1 {
            index,
            observed: DW_SIGNAL_PEER_CLOSED,
            ..DwWaitResultV1::default()
        }))
    }

    fn control_probe() -> Call {
        Call::WaitMany {
            items: vec![super::control_wait_item()],
            deadline: deepwyrm_syscall::DwDeadline(0),
        }
    }

    /// The teardown order after the IER-zero write: Interrupt, DeviceResource,
    /// control, with any stream closed first.
    fn teardown(stream: bool) -> Vec<Call> {
        let mut calls = vec![Call::DevicePioWrite {
            resource: RESOURCE,
            offset: 1,
            width: 1,
            value: 0,
        }];
        if stream {
            calls.push(close(STREAM));
        }
        calls.extend([close(INTERRUPT), close(RESOURCE), close(CONTROL)]);
        calls
    }

    /// `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.3 item 1: a lost control peer
    /// orphans the driver. With no stream left there is nothing to serve, so
    /// it shuts down gracefully -- exit 0, no report to the dead peer.
    #[test]
    fn an_orphaned_driver_with_no_stream_shuts_down_without_reporting() {
        let mut driver = driver(false);
        let mut platform = RecordingPlatform::scripted([
            peer_closed_at(0),
            peer_closed_at(0),
            Reply::Unit(Ok(())),
            Reply::Unit(Ok(())),
            Reply::Unit(Ok(())),
            Reply::Unit(Ok(())),
        ]);
        let pio_failed = core::cell::Cell::new(false);
        let result = run_event_loop(&mut platform, &mut driver, CONTROL, &pio_failed);
        assert_eq!(result, Ok(0));
        let calls = platform.take_calls();
        let Call::WaitMany { items, deadline } = &calls[0] else {
            panic!("the loop waits first: {calls:?}");
        };
        assert_eq!(*deadline, DW_DEADLINE_INFINITE);
        assert_eq!(items[0], super::control_wait_item());
        assert_eq!(calls[1], control_probe());
        assert_eq!(calls[2..], teardown(false));
        assert!(
            !calls
                .iter()
                .any(|call| matches!(call, Call::SendChannel { .. }))
        );
        platform.assert_script_consumed();
    }

    /// With a stream still attached, the orphaned driver keeps serving and
    /// never waits on control again. A later wait failure then fails the
    /// driver (code 35) through the one teardown order.
    #[test]
    fn an_orphaned_driver_with_a_stream_keeps_serving_without_control() {
        let mut driver = driver(true);
        let mut platform = RecordingPlatform::scripted([
            peer_closed_at(0),
            peer_closed_at(0),
            Reply::Wait(Err(status(DW_STATUS_BAD_STATE))),
            Reply::Unit(Ok(())),
            Reply::Unit(Ok(())),
            Reply::Unit(Ok(())),
            Reply::Unit(Ok(())),
            Reply::Unit(Ok(())),
        ]);
        let pio_failed = core::cell::Cell::new(false);
        let result = run_event_loop(&mut platform, &mut driver, CONTROL, &pio_failed);
        assert_eq!(result, Err(35));
        let calls = platform.take_calls();
        assert_eq!(calls[1], control_probe());
        let Call::WaitMany { items, .. } = &calls[2] else {
            panic!("the orphaned loop waits again: {calls:?}");
        };
        assert!(items.iter().all(|item| item.handle != CONTROL));
        assert!(items.iter().any(|item| item.handle == STREAM));
        assert_eq!(
            items
                .iter()
                .find(|item| item.handle == INTERRUPT)
                .map(|item| item.signals),
            Some(deepwyrm_syscall::DW_SIGNAL_SIGNALED)
        );
        assert_eq!(calls[3..], teardown(true));
        platform.assert_script_consumed();
    }
}
