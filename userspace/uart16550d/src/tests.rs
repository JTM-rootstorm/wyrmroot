use super::*;
use deepwyrm_syscall::{DwObjectType, DwRights};
use std::{cell::RefCell, collections::VecDeque, rc::Rc, vec::Vec};
use wyrmroot_device_proto::control::ControlEndpoint;
use wyrmroot_device_proto::coordinator::{
    AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId,
};
use wyrmroot_device_proto::manifest::RoleId;

#[derive(Debug)]
struct FakeIo {
    writes: [(u8, u8); 16],
    write_len: usize,
}

impl FakeIo {
    const fn new() -> Self {
        Self {
            writes: [(0, 0); 16],
            write_len: 0,
        }
    }
}

impl ByteRegisterIo for FakeIo {
    fn read(&mut self, offset: u8) -> u8 {
        if offset == 2 { 1 } else { 0 }
    }

    fn write(&mut self, offset: u8, value: u8) {
        self.writes[self.write_len] = (offset, value);
        self.write_len += 1;
    }
}

#[derive(Debug)]
struct ScriptedIo {
    reads: [VecDeque<u8>; 8],
    writes: Vec<(u8, u8)>,
    trace: Rc<RefCell<Vec<&'static str>>>,
}

impl ScriptedIo {
    fn new(trace: Rc<RefCell<Vec<&'static str>>>) -> Self {
        Self {
            reads: core::array::from_fn(|_| VecDeque::new()),
            writes: Vec::new(),
            trace,
        }
    }

    fn push_reads(&mut self, offset: u8, values: impl IntoIterator<Item = u8>) {
        self.reads[usize::from(offset)].extend(values);
    }
}

impl ByteRegisterIo for ScriptedIo {
    fn read(&mut self, offset: u8) -> u8 {
        self.trace.borrow_mut().push("read");
        self.reads[usize::from(offset)]
            .pop_front()
            .unwrap_or(if offset == 2 { 1 } else { 0 })
    }

    fn write(&mut self, offset: u8, value: u8) {
        self.trace.borrow_mut().push("write");
        self.writes.push((offset, value));
    }
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

fn message() -> ControlMessageV1_1 {
    ControlMessageV1_1::DeviceStage {
        identity: identity(6),
        stage_generation: 7,
        resource_id: COM2_RESOURCE_ID,
        pio_base: COM2_PIO_BASE,
        pio_length: COM2_PIO_LENGTH,
        source: COM2_INTERRUPT_SOURCE,
    }
}

fn resource() -> ReceivedDeviceResource {
    ReceivedDeviceResource {
        handle: DwHandle(9),
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
    }
}

fn interrupt(transaction: u64) -> (ControlMessageV1_1, ReceivedInterrupt) {
    let info = DwInterruptInfoV1 {
        size: DW_INTERRUPT_INFO_V1_SIZE,
        version: DW_INTERRUPT_INFO_V1_VERSION,
        source: COM2_INTERRUPT_SOURCE,
        state: DW_INTERRUPT_STATE_ARMED,
        object_generation: 10,
        binding_generation: 11,
        parent_resource_id: COM2_RESOURCE_ID,
        parent_lease_generation: 2,
        ..DwInterruptInfoV1::default()
    };
    (
        ControlMessageV1_1::InterruptStage {
            identity: identity(transaction),
            stage_generation: 7,
            parent_resource_id: COM2_RESOURCE_ID,
            source: COM2_INTERRUPT_SOURCE,
        },
        ReceivedInterrupt {
            handle: DwHandle(12),
            object_type: DW_OBJECT_TYPE_INTERRUPT,
            rights: INTERRUPT_RIGHTS,
            reserved0: 0,
            reserved: [0; 2],
            info,
        },
    )
}

fn production<I: ByteRegisterIo>(io: I) -> ProductionDriver<I> {
    let mut stage = DeviceStage::validate(identity(99), message(), resource(), io).unwrap();
    stage.initialize_quiesced().unwrap();
    let (interrupt_message, interrupt) = interrupt(8);
    stage
        .validate_interrupt(interrupt_message, interrupt)
        .unwrap()
}

#[test]
fn exact_stage_reaches_quiesced_gate_with_ier_zero_first() {
    let mut stage =
        DeviceStage::validate(identity(99), message(), resource(), FakeIo::new()).unwrap();
    assert_eq!(stage.uart().state(), CoreState::Reset);
    assert_eq!(
        stage.initialize_quiesced().unwrap(),
        ControlMessageV1_1::DeviceQuiesced {
            identity: identity(6),
            stage_generation: 7
        }
    );
    let (_, uart) = stage.into_parts();
    let io = uart.into_io();
    assert_eq!(io.writes[0], (1, 0));
    assert_eq!(io.writes[io.write_len - 1], (4, 0x0b));
    assert!(!io.writes[..io.write_len].contains(&(1, 0x05)));
}

#[test]
fn rights_resource_and_generation_mismatches_precede_io() {
    let mut bad_rights = resource();
    bad_rights.rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_INSPECT.0);
    assert!(matches!(
        DeviceStage::validate(identity(99), message(), bad_rights, FakeIo::new()),
        Err(StageError::WrongHandle)
    ));

    let mut bad_info = resource();
    bad_info.info.lease_generation = 3;
    assert!(matches!(
        DeviceStage::validate(identity(99), message(), bad_info, FakeIo::new()),
        Err(StageError::WrongResource)
    ));

    let mut wrong_type = resource();
    wrong_type.object_type = DwObjectType(0);
    assert!(matches!(
        DeviceStage::validate(identity(99), message(), wrong_type, FakeIo::new()),
        Err(StageError::WrongHandle)
    ));

    let mut reserved_metadata = resource();
    reserved_metadata.reserved[1] = 1;
    assert!(matches!(
        DeviceStage::validate(identity(99), message(), reserved_metadata, FakeIo::new()),
        Err(StageError::WrongHandle)
    ));
}

#[test]
fn one_stream_endpoint_attaches_ready_detaches_and_reconnects() {
    let mut streams = StreamAttachment::new(identity(6));
    let endpoint = ReceivedStreamEndpoint {
        handle: DwHandle(10),
        object_type: DW_OBJECT_TYPE_CHANNEL,
        rights: RAW_STREAM_RIGHTS,
        reserved0: 0,
        reserved: [0; 2],
    };
    let attach = ControlMessageV1_1::AttachStream {
        identity: identity(11),
        stream_generation: 12,
        publication_generation: 13,
    };
    assert_eq!(
        streams.attach(attach, endpoint).unwrap(),
        ControlMessageV1_1::StreamReady {
            identity: identity(11),
            stream_generation: 12,
            publication_generation: 13,
        }
    );
    assert_eq!(
        streams.attach(attach, endpoint),
        Err(StreamAttachError::Busy)
    );
    let (detached, released) = streams.detach().unwrap();
    assert_eq!(released, endpoint);
    assert_eq!(
        detached,
        ControlMessageV1_1::StreamDetached {
            identity: identity(11),
            stream_generation: 12,
            publication_generation: 13,
        }
    );
    let fresh = ControlMessageV1_1::AttachStream {
        identity: identity(14),
        stream_generation: 15,
        publication_generation: 13,
    };
    assert!(streams.attach(fresh, endpoint).is_ok());

    let mut malformed_endpoint = endpoint;
    malformed_endpoint.reserved0 = 1;
    streams.detach().unwrap();
    assert_eq!(
        streams.attach(fresh, malformed_endpoint),
        Err(StreamAttachError::WrongHandle)
    );
}

#[test]
fn interrupt_stage_is_exact_fresh_and_activation_is_last() {
    let mut stage =
        DeviceStage::validate(identity(99), message(), resource(), FakeIo::new()).unwrap();
    stage.initialize_quiesced().unwrap();
    let (interrupt_message, interrupt) = interrupt(8);
    let mut driver = stage
        .validate_interrupt(interrupt_message, interrupt)
        .unwrap();
    assert_eq!(driver.uart().state(), CoreState::Quiesced);
    assert_eq!(
        driver.activate().unwrap(),
        ControlMessageV1_1::Ready {
            identity: identity(9)
        }
    );
    assert_eq!(driver.uart().state(), CoreState::Active);

    let mut stale = interrupt_message;
    if let ControlMessageV1_1::InterruptStage {
        ref mut identity, ..
    } = stale
    {
        identity.transaction_id = 6;
    }
    let mut stage =
        DeviceStage::validate(identity(99), message(), resource(), FakeIo::new()).unwrap();
    stage.initialize_quiesced().unwrap();
    assert!(matches!(
        stage.validate_interrupt(stale, interrupt),
        Err(StageError::WrongCorrelation)
    ));

    let mut wrong = interrupt;
    wrong.info.binding_generation = 0;
    let mut stage =
        DeviceStage::validate(identity(99), message(), resource(), FakeIo::new()).unwrap();
    stage.initialize_quiesced().unwrap();
    assert!(matches!(
        stage.validate_interrupt(interrupt_message, wrong),
        Err(StageError::WrongResource)
    ));
}

#[test]
fn irq_drain_precedes_one_ack_and_ack_failure_is_fatal() {
    let trace = Rc::new(RefCell::new(Vec::new()));
    let mut io = ScriptedIo::new(trace.clone());
    // Quiesced stale drain consumes IIR=NO_INT. Active wake sees THRI,
    // then NO_INT after filling one queued byte.
    io.push_reads(2, [1, 2, 1]);
    let mut driver = production(io);
    driver.activate().unwrap();
    assert_eq!(driver.uart_mut().enqueue_tx(b"x"), 1);
    trace.borrow_mut().clear();
    let drained = driver.drain_interrupt().unwrap();
    assert_ne!(trace.borrow().last(), Some(&"ack"));
    let work = driver
        .acknowledge_interrupt(drained, true, |handle| {
            assert_eq!(handle, DwHandle(12));
            trace.borrow_mut().push("ack");
            Ok(())
        })
        .unwrap();
    assert_eq!(work.transmitted, 1);
    let trace = trace.borrow();
    assert_eq!(trace.last(), Some(&"ack"));
    assert_eq!(trace.iter().filter(|entry| **entry == "ack").count(), 1);
    drop(trace);

    let drained = driver.drain_interrupt().unwrap();
    assert_eq!(
        driver.acknowledge_interrupt(drained, true, |_| Err(())),
        Err(DriverError::InterruptAck)
    );
    assert_eq!(driver.counters().ack_failures, 1);
}

#[test]
fn unknown_interrupt_fails_without_ack() {
    let trace = Rc::new(RefCell::new(Vec::new()));
    let mut io = ScriptedIo::new(trace);
    io.push_reads(2, [1, 0x0a]);
    let mut driver = production(io);
    driver.activate().unwrap();
    assert!(matches!(
        driver.drain_interrupt(),
        Err(DriverError::Interrupt(CoreError::UnknownInterruptCause(
            0x0a
        )))
    ));
    assert!(matches!(driver.uart().state(), CoreState::Failed(_)));
}

#[test]
fn graceful_retire_requires_fresh_channel_empty_software_empty_and_paced_temt() {
    let start = 10_000_000;
    let mut drain = GracefulRetireDrain::new(start, false).unwrap();
    assert_eq!(drain.deadline(), start + GRACEFUL_RETIRE_TIMEOUT_NS);
    assert!(!drain.channel_empty());
    assert!(!drain.temt_probe_due(start, true).unwrap());

    drain.observe_stream_empty();
    assert!(drain.channel_empty());
    assert!(!drain.temt_probe_due(start, false).unwrap());
    assert!(drain.temt_probe_due(start, true).unwrap());
    assert!(!drain.observe_temt(start, true, false).unwrap());
    assert_eq!(
        drain.wait_deadline(start, true).unwrap(),
        start + GRACEFUL_RETIRE_TEMT_POLL_NS
    );
    assert!(
        !drain
            .temt_probe_due(start + GRACEFUL_RETIRE_TEMT_POLL_NS - 1, true)
            .unwrap()
    );

    drain.observe_stream_record();
    assert!(!drain.channel_empty());
    assert!(
        !drain
            .temt_probe_due(start + GRACEFUL_RETIRE_TEMT_POLL_NS, true)
            .unwrap()
    );
    drain.observe_stream_empty();
    assert!(
        drain
            .temt_probe_due(start + GRACEFUL_RETIRE_TEMT_POLL_NS, true)
            .unwrap()
    );
    assert!(
        drain
            .observe_temt(start + GRACEFUL_RETIRE_TEMT_POLL_NS, true, true)
            .unwrap()
    );
}

#[test]
fn graceful_retire_uses_one_absolute_deadline_and_rejects_early_probe() {
    let start = u64::MAX - GRACEFUL_RETIRE_TIMEOUT_NS - 1;
    let mut drain = GracefulRetireDrain::new(start, true).unwrap();
    assert_eq!(drain.deadline(), u64::MAX - 1);
    assert_eq!(
        drain.observe_temt(start, false, true),
        Err(GracefulRetireError::ProbeOutOfOrder)
    );
    assert!(!drain.observe_temt(start, true, false).unwrap());
    assert_eq!(drain.deadline(), u64::MAX - 1);
    assert_eq!(
        drain.wait_deadline(u64::MAX - 1, true),
        Err(GracefulRetireError::TimedOut)
    );
    assert_eq!(
        GracefulRetireDrain::new(start + 1, true),
        Err(GracefulRetireError::DeadlineOverflow)
    );
}

#[test]
fn stream_backpressure_malformed_isolation_and_reconnect_preserve_driver() {
    let mut driver = production(FakeIo::new());
    driver.activate().unwrap();
    let endpoint = ReceivedStreamEndpoint {
        handle: DwHandle(20),
        object_type: DW_OBJECT_TYPE_CHANNEL,
        rights: RAW_STREAM_RIGHTS,
        reserved0: 0,
        reserved: [0; 2],
    };
    let attach = ControlMessageV1_1::AttachStream {
        identity: identity(21),
        stream_generation: 22,
        publication_generation: 23,
    };
    driver.attach_stream(attach, endpoint).unwrap();
    assert_eq!(
        driver.accept_stream_record(b"bad", 0),
        Err(DriverError::StreamProtocol)
    );
    let (_, released) = driver.detach_stream().unwrap();
    assert_eq!(released.handle, DwHandle(20));
    let fresh = ControlMessageV1_1::AttachStream {
        identity: identity(24),
        stream_generation: 25,
        publication_generation: 23,
    };
    assert!(driver.attach_stream(fresh, endpoint).is_ok());
    assert_eq!(driver.uart().state(), CoreState::Active);

    let payload = [0x5a; MAX_PAYLOAD_BYTES];
    let mut wire = [0; MAX_RECORD_BYTES];
    let size = encode_data(&payload, &mut wire).unwrap();
    for _ in 0..4 {
        assert_eq!(driver.accept_stream_record(&wire[..size], 0), Ok(1024));
    }
    assert!(!driver.wants_stream_readable());
    assert_eq!(
        driver.accept_stream_record(&wire[..size], 0),
        Err(DriverError::StreamCapacity)
    );
}

#[test]
fn control_priority_close_order_and_counters_are_bounded() {
    assert_eq!(
        ReadySet {
            control_retire: true,
            interrupt: true,
            stream_readable: true,
            ..ReadySet::default()
        }
        .highest_priority(),
        Some(ReadyWork::ControlRetire)
    );
    assert_eq!(
        ReadySet {
            interrupt: true,
            stream_peer_closed: true,
            ..ReadySet::default()
        }
        .highest_priority(),
        Some(ReadyWork::Interrupt)
    );

    let mut driver = production(FakeIo::new());
    driver.activate().unwrap();
    driver
        .attach_stream(
            ControlMessageV1_1::AttachStream {
                identity: identity(21),
                stream_generation: 22,
                publication_generation: 23,
            },
            ReceivedStreamEndpoint {
                handle: DwHandle(20),
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: RAW_STREAM_RIGHTS,
                reserved0: 0,
                reserved: [0; 2],
            },
        )
        .unwrap();
    let mut steps = [None; 6];
    assert_eq!(driver.close_steps(DwHandle(30), &mut steps), 6);
    assert_eq!(
        steps,
        [
            Some(CloseStep::DisableInterrupts),
            Some(CloseStep::ClearStreamState),
            Some(CloseStep::CloseStream(DwHandle(20))),
            Some(CloseStep::CloseInterrupt(DwHandle(12))),
            Some(CloseStep::CloseDeviceResource(DwHandle(9))),
            Some(CloseStep::CloseControl(DwHandle(30))),
        ]
    );

    driver.test_counters_mut().interrupt_wakes = u32::MAX;
    let drained = driver.drain_interrupt().unwrap();
    driver
        .acknowledge_interrupt(drained, true, |_| Ok(()))
        .unwrap();
    assert_eq!(driver.counters().interrupt_wakes, u32::MAX);
}

#[test]
fn every_stream_detach_cause_reaches_its_own_counter() {
    let mut driver = production(FakeIo::new());
    driver.record_stream_detach(StreamDetachCause::NoStream);
    driver.record_stream_detach(StreamDetachCause::Native(0x1234));
    driver.record_stream_detach(StreamDetachCause::Native(0x0042));
    driver.record_stream_detach(StreamDetachCause::Overflow);
    driver.record_stream_detach(StreamDetachCause::Record(DriverError::StreamHandles));
    driver.record_stream_detach(StreamDetachCause::Record(DriverError::StreamProtocol));
    driver.record_stream_detach(StreamDetachCause::Record(DriverError::StreamCapacity));
    driver.record_stream_detach(StreamDetachCause::Record(DriverError::NotActive));
    assert_eq!(
        driver.counters().detach_causes,
        DetachCauseCounters {
            no_stream: 1,
            native: 2,
            last_native: 0x0042,
            overflow: 1,
            record_handles: 1,
            record_protocol: 1,
            record_capacity: 1,
            record_other: 1,
        }
    );

    driver.test_counters_mut().detach_causes.overflow = u32::MAX;
    driver.record_stream_detach(StreamDetachCause::Overflow);
    assert_eq!(driver.counters().detach_causes.overflow, u32::MAX);
}

#[test]
fn startup_peer_close_wins_and_stream_readable_drains_before_detach() {
    let both = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
    assert!(!startup_control_is_readable(0, both));
    assert!(!startup_control_is_readable(1, DW_SIGNAL_READABLE));
    assert!(startup_control_is_readable(0, DW_SIGNAL_READABLE));

    assert_eq!(
        ReadySet {
            stream_peer_closed: true,
            stream_readable: true,
            ..ReadySet::default()
        }
        .highest_priority(),
        Some(ReadyWork::StreamReadable)
    );

    let mut driver = production(FakeIo::new());
    driver.activate().unwrap();
    let endpoint = ReceivedStreamEndpoint {
        handle: DwHandle(20),
        object_type: DW_OBJECT_TYPE_CHANNEL,
        rights: RAW_STREAM_RIGHTS,
        reserved0: 0,
        reserved: [0; 2],
    };
    driver
        .attach_stream(
            ControlMessageV1_1::AttachStream {
                identity: identity(21),
                stream_generation: 22,
                publication_generation: 23,
            },
            endpoint,
        )
        .unwrap();
    let payload = b"final queued WRST data";
    let mut wire = [0; MAX_RECORD_BYTES];
    let size = encode_data(payload, &mut wire).unwrap();
    assert_eq!(
        driver.accept_stream_record(&wire[..size], 0),
        Ok(payload.len())
    );
    let (_, detached) = driver.detach_stream().unwrap();
    assert_eq!(detached, endpoint);
    assert_eq!(driver.uart().tx_len(), payload.len());
}

#[test]
fn peer_close_drain_pauses_at_capacity_then_accepts_the_fifth_record() {
    let trace = Rc::new(RefCell::new(Vec::new()));
    let mut io = ScriptedIo::new(trace);
    let interrupt_reads = core::iter::once(1).chain((0..64).flat_map(|_| [2, 1]));
    io.push_reads(2, interrupt_reads);
    let mut driver = production(io);
    driver.activate().unwrap();
    let endpoint = ReceivedStreamEndpoint {
        handle: DwHandle(20),
        object_type: DW_OBJECT_TYPE_CHANNEL,
        rights: RAW_STREAM_RIGHTS,
        reserved0: 0,
        reserved: [0; 2],
    };
    driver
        .attach_stream(
            ControlMessageV1_1::AttachStream {
                identity: identity(21),
                stream_generation: 22,
                publication_generation: 23,
            },
            endpoint,
        )
        .unwrap();

    let payload = [0x5a; MAX_PAYLOAD_BYTES];
    let mut wire = [0; MAX_RECORD_BYTES];
    let size = encode_data(&payload, &mut wire).unwrap();
    let mut queued = VecDeque::from([wire; 5]);
    let mut drain = PeerCloseDrain::new();
    drain.observe();
    while drain.is_pending() && driver.wants_stream_readable() && !queued.is_empty() {
        assert_eq!(
            driver.accept_stream_record(&queued.front().unwrap()[..size], 0),
            Ok(payload.len())
        );
        queued.pop_front();
    }
    assert_eq!(queued.len(), 1);
    assert_eq!(driver.uart().tx_len(), RING_CAPACITY);
    assert!(!drain.include_stream_wait(driver.wants_stream_readable()));
    assert_eq!(driver.stream_endpoint(), Some(endpoint));

    let mut transmitted = 0;
    for _ in 0..64 {
        let drained = driver.drain_interrupt().unwrap();
        transmitted += driver
            .acknowledge_interrupt(drained, true, |_| Ok(()))
            .unwrap()
            .transmitted;
    }
    assert!(driver.wants_stream_readable());
    assert!(drain.include_stream_wait(driver.wants_stream_readable()));
    assert_eq!(
        driver.accept_stream_record(&queued.front().unwrap()[..size], 0),
        Ok(payload.len())
    );
    queued.pop_front();
    assert!(queued.is_empty());

    drain.clear();
    let (_, detached) = driver.detach_stream().unwrap();
    assert_eq!(detached, endpoint);
    assert_eq!(transmitted, 1024);
    assert_eq!(driver.uart().tx_len(), RING_CAPACITY);
    assert_eq!(
        usize::from(transmitted) + driver.uart().tx_len(),
        5 * MAX_PAYLOAD_BYTES
    );
}

#[test]
fn send_peer_close_preserves_final_inbound_data_until_empty_queue_proof() {
    fn driver_with_pending_rx() -> (ProductionDriver<ScriptedIo>, ReceivedStreamEndpoint) {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut io = ScriptedIo::new(trace);
        io.push_reads(2, [1, 4, 1]);
        io.push_reads(5, [0, 1, 0]);
        io.push_reads(0, [0x41]);
        let mut driver = production(io);
        driver.activate().unwrap();
        let endpoint = ReceivedStreamEndpoint {
            handle: DwHandle(20),
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: RAW_STREAM_RIGHTS,
            reserved0: 0,
            reserved: [0; 2],
        };
        driver
            .attach_stream(
                ControlMessageV1_1::AttachStream {
                    identity: identity(21),
                    stream_generation: 22,
                    publication_generation: 23,
                },
                endpoint,
            )
            .unwrap();
        let drained = driver.drain_interrupt().unwrap();
        assert_eq!(drained.work().received, 1);
        driver
            .acknowledge_interrupt(drained, true, |_| Ok(()))
            .unwrap();
        let mut wire = [0; MAX_RECORD_BYTES];
        assert!(driver.prepare_stream_send(&mut wire).unwrap().is_some());
        (driver, endpoint)
    }

    let (mut driver, endpoint) = driver_with_pending_rx();
    let mut drain = PeerCloseDrain::new();
    assert_eq!(driver.pending_stream_bytes(), 1);
    assert_eq!(driver.rx_len(), 1);
    assert!(driver.wants_stream_writable());
    assert_eq!(driver.counters().tx_records, 0);

    assert_eq!(
        driver.resolve_stream_send(&mut drain, StreamSendResult::PeerClosed),
        StreamSendAction::Continue
    );
    assert_eq!(driver.stream_endpoint(), Some(endpoint));
    assert!(drain.is_pending());
    assert_eq!(driver.pending_stream_bytes(), 1);
    assert_eq!(driver.rx_len(), 1);
    assert_eq!(driver.counters().tx_records, 0);
    assert!(!(!drain.is_pending() && driver.wants_stream_writable()));
    assert!(drain.include_stream_wait(driver.wants_stream_readable()));

    let payload = b"final queued WRST data";
    let mut wire = [0; MAX_RECORD_BYTES];
    let size = encode_data(payload, &mut wire).unwrap();
    assert_eq!(
        driver.accept_stream_record(&wire[..size], 0),
        Ok(payload.len())
    );
    assert_eq!(driver.stream_endpoint(), Some(endpoint));
    assert_eq!(driver.uart().tx_len(), payload.len());

    let (_, detached) = driver.detach_stream().unwrap();
    drain.clear();
    assert_eq!(detached, endpoint);
    assert_eq!(driver.stream_endpoint(), None);
    assert_eq!(driver.uart().tx_len(), payload.len());
    assert_eq!(driver.pending_stream_bytes(), 0);
    assert_eq!(driver.rx_len(), 1);
    assert_eq!(driver.counters().tx_records, 0);
    assert_eq!(driver.counters().rx_records, 1);

    let (mut failed, endpoint) = driver_with_pending_rx();
    let mut failed_drain = PeerCloseDrain::new();
    failed_drain.observe();
    let StreamSendAction::Detached(_, detached) =
        failed.resolve_stream_send(&mut failed_drain, StreamSendResult::Failed)
    else {
        panic!("non-peer send failure must detach");
    };
    assert_eq!(detached, endpoint);
    assert!(!failed_drain.is_pending());
    assert_eq!(failed.stream_endpoint(), None);
    assert_eq!(failed.pending_stream_bytes(), 0);
    assert_eq!(failed.rx_len(), 1);
    assert_eq!(failed.counters().tx_records, 0);

    let (mut blocked, endpoint) = driver_with_pending_rx();
    let mut blocked_drain = PeerCloseDrain::new();
    assert_eq!(
        blocked.resolve_stream_send(&mut blocked_drain, StreamSendResult::WouldBlock),
        StreamSendAction::Continue
    );
    assert_eq!(blocked.stream_endpoint(), Some(endpoint));
    assert_eq!(blocked.pending_stream_bytes(), 1);
    assert_eq!(blocked.rx_len(), 1);

    assert_eq!(
        blocked.resolve_stream_send(&mut blocked_drain, StreamSendResult::Sent),
        StreamSendAction::Continue
    );
    assert_eq!(blocked.pending_stream_bytes(), 0);
    assert_eq!(blocked.rx_len(), 0);
    assert_eq!(blocked.counters().tx_records, 1);
}
