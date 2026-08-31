#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::{cell::Cell, panic::PanicInfo};

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_SIGNAL_SIGNALED, DW_SIGNAL_WRITABLE,
    DW_STATUS_PEER_CLOSED, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK, DwDeadline, DwHandle,
    DwReceivedHandleInfoV1, DwSignals, DwWaitItemV1,
};
use wyrmroot_device_proto::control::ControlEndpoint;
use wyrmroot_device_proto::control_v1_1::{
    ControlIdentityV1_1, ControlMessageV1_1, DEVICE_QUIESCED_BYTES, DEVICE_STAGE_BYTES,
    INTERRUPT_STAGE_BYTES, encode, parse,
};
use wyrmroot_device_proto::coordinator::{
    AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId,
};
use wyrmroot_device_proto::manifest::RoleId;
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS, parse_device_driver_init,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, NativeError, StartupBlock, close_handle, device_pio_read,
    device_pio_write, device_resource_info, interrupt_ack, interrupt_info, panic_abort,
    query_capability_info, receive_channel, send_channel, validate_bootstrap_channel, wait_many,
};
use wyrmroot_stream_proto::MAX_RECORD_BYTES;
use wyrmroot_uart16550_core::ByteRegisterIo;
use wyrmroot_uart16550d::{
    DeviceStage, PeerCloseDrain, ProductionDriver, ReceivedDeviceResource, ReceivedInterrupt,
    ReceivedStreamEndpoint, startup_control_is_readable,
};

const FAILURE_BASE: u32 = 0xD3A0_0000;

struct NativeResourceIo<'a> {
    handle: DwHandle,
    failed: &'a Cell<bool>,
}

impl ByteRegisterIo for NativeResourceIo<'_> {
    fn read(&mut self, offset: u8) -> u8 {
        if self.failed.get() {
            return 0;
        }
        match device_pio_read(self.handle, u32::from(offset), 1) {
            Ok(value) if value <= u32::from(u8::MAX) => value as u8,
            _ => {
                self.failed.set(true);
                0
            }
        }
    }

    fn write(&mut self, offset: u8, value: u8) {
        if !self.failed.get()
            && device_pio_write(self.handle, u32::from(offset), 1, u32::from(value)).is_err()
        {
            self.failed.set(true);
        }
    }
}

fn uart_main(startup: StartupBlock<'_>) -> u32 {
    run(startup).unwrap_or_else(|step| FAILURE_BASE | step)
}

fn run(startup: StartupBlock<'_>) -> Result<u32, u32> {
    let bootstrap = startup.bootstrap_channel().as_abi();
    validate_bootstrap_channel(
        query_capability_info(bootstrap).map_err(|_| 1u32)?,
        BOOTSTRAP_CHANNEL_EXPECTATION,
    )
    .map_err(|_| 2u32)?;
    let mut startup_bytes = [0; DEVICE_DRIVER_BYTES];
    let mut startup_handles = [DwReceivedHandleInfoV1::default(); 2];
    let startup_counts =
        receive_channel(bootstrap, &mut startup_bytes, &mut startup_handles).map_err(|_| 3u32)?;
    if startup_counts.bytes != DEVICE_DRIVER_BYTES
        || startup_counts.handles != 2
        || !valid_received(
            startup_handles[0],
            DW_OBJECT_TYPE_ADDRESS_REGION,
            SELF_ROOT_RIGHTS,
        )
        || !valid_received(
            startup_handles[1],
            DW_OBJECT_TYPE_CHANNEL,
            CHILD_CHANNEL_RIGHTS,
        )
    {
        close_received(&startup_handles, startup_counts.handles);
        return Err(4);
    }
    let launch = match parse_device_driver_init(&startup_bytes, &startup_handles) {
        Ok(launch) => launch,
        Err(_) => {
            close_received(&startup_handles, 2);
            let _ = close_handle(bootstrap);
            return Err(5);
        }
    };
    let control = startup_handles[1].handle;
    if close_handle(startup_handles[0].handle).is_err() {
        let _ = close_handle(control);
        let _ = close_handle(bootstrap);
        return Err(6);
    }
    if close_handle(bootstrap).is_err() {
        let _ = close_handle(control);
        return Err(7);
    }

    let observed = match wait_many(
        core::slice::from_ref(&DwWaitItemV1 {
            handle: control,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        }),
        DW_DEADLINE_INFINITE,
    ) {
        Ok(observed) => observed,
        Err(_) => {
            let _ = close_handle(control);
            return Err(8);
        }
    };
    if !startup_control_is_readable(observed.index, observed.observed) {
        close_handle(control).map_err(|_| 9u32)?;
        return Err(10);
    }
    let mut stage_bytes = [0; DEVICE_STAGE_BYTES];
    let mut stage_handles = [DwReceivedHandleInfoV1::default(); 1];
    let stage_counts = match receive_channel(control, &mut stage_bytes, &mut stage_handles) {
        Ok(counts) => counts,
        Err(_) => {
            let _ = close_handle(control);
            return Err(11);
        }
    };
    if stage_counts.bytes != DEVICE_STAGE_BYTES || stage_counts.handles != 1 {
        close_received(&stage_handles, stage_counts.handles);
        close_handle(control).map_err(|_| 12u32)?;
        return Err(13);
    }
    let message = match parse(&stage_bytes) {
        Ok(message) => message,
        Err(_) => return fail_stage(control, &stage_handles, 1, 14),
    };
    let ControlMessageV1_1::DeviceStage { identity, .. } = message else {
        return fail_stage(control, &stage_handles, 1, 16);
    };
    let startup_identity = ControlIdentityV1_1 {
        role_id: RoleId(launch.role_id),
        bundle_generation: BundleGeneration(identity.bundle_generation.0),
        attempt_generation: AttemptGeneration(launch.attempt_generation),
        endpoint: ControlEndpoint {
            id: EndpointId(launch.endpoint_id),
            generation: EndpointGeneration(launch.endpoint_generation),
        },
        transaction_id: launch.transaction_id,
    };
    let info = match device_resource_info(stage_handles[0].handle) {
        Ok(info) => info,
        Err(_) => return fail_stage(control, &stage_handles, 1, 17),
    };
    let received = ReceivedDeviceResource {
        handle: stage_handles[0].handle,
        object_type: stage_handles[0].object_type,
        rights: stage_handles[0].rights,
        reserved0: stage_handles[0].reserved0,
        reserved: stage_handles[0].reserved,
        info,
    };
    let pio_failed = Cell::new(false);
    let io = NativeResourceIo {
        handle: received.handle,
        failed: &pio_failed,
    };
    let mut stage = match DeviceStage::validate(startup_identity, message, received, io) {
        Ok(stage) => stage,
        Err(_) => return fail_stage(control, &stage_handles, 1, 18),
    };
    let response = match stage.initialize_quiesced() {
        Ok(response) => response,
        Err(_) => {
            let (resource, _) = stage.into_parts();
            return fail_owned_stage(control, resource.handle, 19);
        }
    };
    if pio_failed.get() {
        return fail_owned_stage(control, received.handle, 22);
    }
    let mut response_bytes = [0; DEVICE_QUIESCED_BYTES];
    if encode(response, &mut response_bytes).is_err() {
        return fail_owned_stage(control, received.handle, 23);
    }
    if send_channel(control, &response_bytes, &[]).is_err() {
        return fail_owned_stage(control, received.handle, 24);
    }

    let observed = match wait_many(
        core::slice::from_ref(&DwWaitItemV1 {
            handle: control,
            signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        }),
        DW_DEADLINE_INFINITE,
    ) {
        Ok(observed) => observed,
        Err(_) => return fail_owned_stage(control, received.handle, 25),
    };
    if !startup_control_is_readable(observed.index, observed.observed) {
        let _ = device_pio_write(received.handle, 1, 1, 0);
        return fail_owned_stage(control, received.handle, 26);
    }
    let mut interrupt_bytes = [0; INTERRUPT_STAGE_BYTES];
    let mut interrupt_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match receive_channel(control, &mut interrupt_bytes, &mut interrupt_handles) {
        Ok(counts) => counts,
        Err(_) => return fail_owned_stage(control, received.handle, 27),
    };
    if counts.bytes != INTERRUPT_STAGE_BYTES || counts.handles != 1 {
        close_received(&interrupt_handles, counts.handles);
        let _ = device_pio_write(received.handle, 1, 1, 0);
        return fail_owned_stage(control, received.handle, 28);
    }
    let interrupt_message = match parse(&interrupt_bytes) {
        Ok(message) => message,
        Err(_) => {
            return fail_second_stage(control, received.handle, interrupt_handles[0].handle, 29);
        }
    };
    let basic = match query_capability_info(interrupt_handles[0].handle) {
        Ok(info) => info,
        Err(_) => {
            return fail_second_stage(control, received.handle, interrupt_handles[0].handle, 30);
        }
    };
    let irq_info = match interrupt_info(interrupt_handles[0].handle) {
        Ok(info) => info,
        Err(_) => {
            return fail_second_stage(control, received.handle, interrupt_handles[0].handle, 31);
        }
    };
    let interrupt = ReceivedInterrupt {
        handle: interrupt_handles[0].handle,
        object_type: basic.object_type,
        rights: basic.rights,
        reserved0: interrupt_handles[0].reserved0,
        reserved: interrupt_handles[0].reserved,
        info: irq_info,
    };
    let mut driver = match stage.validate_interrupt(interrupt_message, interrupt) {
        Ok(driver) => driver,
        Err(_) => {
            return fail_second_stage(control, received.handle, interrupt.handle, 32);
        }
    };
    let ready = match driver.activate() {
        Ok(ready) if !pio_failed.get() => ready,
        _ => return fail_driver(&mut driver, control, 33),
    };
    if send_control(control, ready).is_err() {
        return fail_driver(&mut driver, control, 34);
    }
    run_event_loop(&mut driver, control, &pio_failed)
}

fn run_event_loop<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
    pio_failed: &Cell<bool>,
) -> Result<u32, u32> {
    let mut peer_close_drain = PeerCloseDrain::new();
    loop {
        let mut items = [DwWaitItemV1::default(); 3];
        items[0] = DwWaitItemV1 {
            handle: control,
            signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        };
        items[1] = DwWaitItemV1 {
            handle: driver.interrupt().handle,
            signals: DW_SIGNAL_SIGNALED,
        };
        let mut count = 2;
        if let Some(stream) = driver.stream_endpoint() {
            let receive_capacity = driver.wants_stream_readable();
            if peer_close_drain.include_stream_wait(receive_capacity) {
                let mut signals = DW_SIGNAL_PEER_CLOSED.0;
                if receive_capacity {
                    signals |= DW_SIGNAL_READABLE.0;
                }
                if !peer_close_drain.is_pending() && driver.wants_stream_writable() {
                    signals |= DW_SIGNAL_WRITABLE.0;
                }
                items[2] = DwWaitItemV1 {
                    handle: stream.handle,
                    signals: DwSignals(signals),
                };
                count = 3;
            }
        }
        let observed = match wait_many(&items[..count], DW_DEADLINE_INFINITE) {
            Ok(observed) => observed,
            Err(_) => return fail_driver(driver, control, 35),
        };

        // Control retirement/revocation wins even when the wait selected an
        // Interrupt or stream item whose readiness coexists with control.
        let control_signals = match probe_control(control) {
            Ok(signals) => signals,
            Err(_) => return fail_driver(driver, control, 36),
        };
        if observed.index == 0 || control_signals.0 != 0 {
            let signals = if observed.index == 0 {
                observed.observed
            } else {
                control_signals
            };
            if signals.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                return graceful_shutdown(driver, control, 0);
            }
            if signals.0 & DW_SIGNAL_READABLE.0 != 0 {
                match service_control(driver, control) {
                    Ok(ControlOutcome::Continue) => continue,
                    Ok(ControlOutcome::Retire) => return graceful_shutdown(driver, control, 0),
                    Err(code) => return fail_driver(driver, control, code),
                }
            }
            return fail_driver(driver, control, 37);
        }

        if observed.index == 1 {
            if observed.observed.0 & DW_SIGNAL_SIGNALED.0 == 0 {
                return fail_driver(driver, control, 38);
            }
            let drained = match driver.drain_interrupt() {
                Ok(drained) => drained,
                Err(_) => return fail_driver(driver, control, 39),
            };
            let acked = driver.acknowledge_interrupt(drained, !pio_failed.get(), |handle| {
                interrupt_ack(handle).map_err(|_| ())
            });
            if acked.is_err() {
                return fail_driver(driver, control, 40);
            }
            continue;
        }

        if observed.index == 2 {
            let peer_closed = observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0;
            let readable = observed.observed.0 & DW_SIGNAL_READABLE.0 != 0;
            if peer_closed {
                peer_close_drain.observe();
            }
            if peer_close_drain.is_pending() {
                while driver.wants_stream_readable() {
                    match service_stream_read(driver, control, pio_failed) {
                        Ok(StreamReadOutcome::Accepted) => {}
                        Ok(StreamReadOutcome::WouldBlock) => {
                            if isolate_stream(driver, control).is_err() {
                                return fail_driver(driver, control, 41);
                            }
                            peer_close_drain.clear();
                            break;
                        }
                        Ok(StreamReadOutcome::Detached) => {
                            peer_close_drain.clear();
                            break;
                        }
                        Err(()) => return fail_driver(driver, control, 42),
                    }
                }
                continue;
            }
            if readable {
                match service_stream_read(driver, control, pio_failed) {
                    Ok(StreamReadOutcome::Accepted | StreamReadOutcome::WouldBlock) => {}
                    Ok(StreamReadOutcome::Detached) => {
                        peer_close_drain.clear();
                        continue;
                    }
                    Err(()) => return fail_driver(driver, control, 42),
                }
            }
            if driver.stream_endpoint().is_some()
                && observed.observed.0 & DW_SIGNAL_WRITABLE.0 != 0
                && service_stream_write(driver, control).is_err()
            {
                return fail_driver(driver, control, 43);
            }
            continue;
        }
        return fail_driver(driver, control, 44);
    }
}

enum ControlOutcome {
    Continue,
    Retire,
}

fn service_control<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
) -> Result<ControlOutcome, u32> {
    let mut bytes = [0; DEVICE_STAGE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(control, &mut bytes, &mut handles).map_err(|_| 45u32)?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        close_received(&handles, counts.handles);
        return Err(46);
    }
    let message = match parse(&bytes[..counts.bytes]) {
        Ok(message) => message,
        Err(_) => {
            close_received(&handles, counts.handles);
            return Err(47);
        }
    };
    match message {
        ControlMessageV1_1::Retire { identity }
            if counts.handles == 0 && identity == driver.identity() =>
        {
            Ok(ControlOutcome::Retire)
        }
        ControlMessageV1_1::AttachStream { .. } if counts.handles == 1 => {
            let endpoint = ReceivedStreamEndpoint {
                handle: handles[0].handle,
                object_type: handles[0].object_type,
                rights: handles[0].rights,
                reserved0: handles[0].reserved0,
                reserved: handles[0].reserved,
            };
            let ready = match driver.attach_stream(message, endpoint) {
                Ok(ready) => ready,
                Err(_) => {
                    let _ = close_handle(endpoint.handle);
                    return Err(48);
                }
            };
            if send_control(control, ready).is_err() {
                if let Some((_, endpoint)) = driver.detach_stream() {
                    let _ = close_handle(endpoint.handle);
                }
                return Err(49);
            }
            Ok(ControlOutcome::Continue)
        }
        _ => {
            close_received(&handles, counts.handles);
            Err(50)
        }
    }
}

fn service_stream_read<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
    pio_failed: &Cell<bool>,
) -> Result<StreamReadOutcome, ()> {
    let Some(endpoint) = driver.stream_endpoint() else {
        return Ok(StreamReadOutcome::Detached);
    };
    let mut bytes = [0; MAX_RECORD_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 16];
    let counts = match receive_channel(endpoint.handle, &mut bytes, &mut handles) {
        Ok(counts) => counts,
        Err(error)
            if status_is(error, DW_STATUS_WOULD_BLOCK)
                || status_is(error, DW_STATUS_PEER_CLOSED) =>
        {
            return Ok(StreamReadOutcome::WouldBlock);
        }
        Err(_) => {
            isolate_stream(driver, control)?;
            return Ok(StreamReadOutcome::Detached);
        }
    };
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        close_received(&handles, counts.handles);
        isolate_stream(driver, control)?;
        return Ok(StreamReadOutcome::Detached);
    }
    if driver
        .accept_stream_record(&bytes[..counts.bytes], counts.handles)
        .is_err()
    {
        close_received(&handles, counts.handles);
        isolate_stream(driver, control)?;
        return Ok(StreamReadOutcome::Detached);
    }
    if pio_failed.get() {
        return Err(());
    }
    Ok(StreamReadOutcome::Accepted)
}

enum StreamReadOutcome {
    Accepted,
    WouldBlock,
    Detached,
}

fn service_stream_write<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
) -> Result<(), ()> {
    let Some(endpoint) = driver.stream_endpoint() else {
        return Ok(());
    };
    let mut bytes = [0; MAX_RECORD_BYTES];
    let Some(size) = driver.prepare_stream_send(&mut bytes).map_err(|_| ())? else {
        return Ok(());
    };
    match send_channel(endpoint.handle, &bytes[..size], &[]) {
        Ok(()) => {
            driver.commit_stream_send();
            Ok(())
        }
        Err(error) if status_is(error, DW_STATUS_WOULD_BLOCK) => Ok(()),
        Err(error) if status_is(error, DW_STATUS_PEER_CLOSED) => isolate_stream(driver, control),
        Err(_) => isolate_stream(driver, control),
    }
}

fn isolate_stream<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
) -> Result<(), ()> {
    let Some((detached, endpoint)) = driver.detach_stream() else {
        return Ok(());
    };
    let _ = close_handle(endpoint.handle);
    send_control(control, detached)
}

fn probe_control(control: DwHandle) -> Result<DwSignals, ()> {
    let item = DwWaitItemV1 {
        handle: control,
        signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    match wait_many(core::slice::from_ref(&item), DwDeadline(0)) {
        Ok(result) if result.index == 0 => Ok(result.observed),
        Ok(_) => Err(()),
        Err(error) if status_is(error, DW_STATUS_TIMED_OUT) => Ok(DwSignals(0)),
        Err(_) => Err(()),
    }
}

fn status_is(error: NativeError, status: deepwyrm_syscall::DwStatus) -> bool {
    matches!(error, NativeError::Status(actual) if actual == status)
}

fn send_control(control: DwHandle, message: ControlMessageV1_1) -> Result<(), ()> {
    let mut bytes = [0; DEVICE_STAGE_BYTES];
    let size = message.wire_size();
    encode(message, &mut bytes[..size]).map_err(|_| ())?;
    send_channel(control, &bytes[..size], &[]).map_err(|_| ())
}

fn graceful_shutdown<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
    result: u32,
) -> Result<u32, u32> {
    let _ = device_pio_write(driver.resource().handle, 1, 1, 0);
    if let Some((_, endpoint)) = driver.detach_stream() {
        let _ = close_handle(endpoint.handle);
    }
    let _ = close_handle(driver.interrupt().handle);
    let _ = close_handle(driver.resource().handle);
    let _ = close_handle(control);
    Ok(result)
}

fn fail_driver<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
    code: u32,
) -> Result<u32, u32> {
    let _ = graceful_shutdown(driver, control, FAILURE_BASE | code);
    Err(code)
}

fn valid_received(
    info: DwReceivedHandleInfoV1,
    object_type: deepwyrm_syscall::DwObjectType,
    rights: deepwyrm_syscall::DwRights,
) -> bool {
    info.handle.0 != 0
        && info.object_type == object_type
        && info.rights == rights
        && info.reserved0 == 0
        && info.reserved == [0; 2]
}

fn close_received(handles: &[DwReceivedHandleInfoV1], count: usize) {
    for info in handles.iter().take(count) {
        let _ = close_handle(info.handle);
    }
}

fn fail_stage(
    control: DwHandle,
    handles: &[DwReceivedHandleInfoV1],
    count: usize,
    code: u32,
) -> Result<u32, u32> {
    close_received(handles, count);
    let _ = close_handle(control);
    Err(code)
}

fn fail_owned_stage(control: DwHandle, resource: DwHandle, code: u32) -> Result<u32, u32> {
    let _ = device_pio_write(resource, 1, 1, 0);
    let _ = close_handle(resource);
    let _ = close_handle(control);
    Err(code)
}

fn fail_second_stage(
    control: DwHandle,
    resource: DwHandle,
    interrupt: DwHandle,
    code: u32,
) -> Result<u32, u32> {
    let _ = device_pio_write(resource, 1, 1, 0);
    let _ = close_handle(interrupt);
    let _ = close_handle(resource);
    let _ = close_handle(control);
    Err(code)
}

wyrmroot_runtime::native_entry!(crate::uart_main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
