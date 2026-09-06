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
#[cfg(feature = "dw1e3-selector31")]
use deepwyrm_syscall::{DW_RIGHT_INSPECT, DW_RIGHT_MODIFY, DW_RIGHT_WAIT, DwRights};
use wyrmroot_device_proto::control::ControlEndpoint;
use wyrmroot_device_proto::control_v1_1::{
    ControlIdentityV1_1, ControlMessageV1_1, DEVICE_QUIESCED_BYTES, DEVICE_STAGE_BYTES,
    INTERRUPT_STAGE_BYTES, encode, parse,
};
use wyrmroot_device_proto::coordinator::{
    AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId,
};
#[cfg(feature = "wyr1d-selector32")]
use wyrmroot_device_proto::d5_controller::{
    D5ControllerMessage, D5DrainIdentity, D5DriverIdentity, RECORD_BYTES as D5_BYTES,
    encode as encode_d5, parse as parse_d5,
};
use wyrmroot_device_proto::manifest::RoleId;
#[cfg(feature = "dw1e3-selector31")]
use wyrmroot_dw1e3_com2_test::{
    CHALLENGE_BYTES, CHALLENGE_GENERATION, ChallengeBinding, TRANSPORT_EMPTY_TEMT_MAX_POLLS,
    TransportEmptyFact, challenge, encode_binding_ready, encode_transport_empty_fact, fnv1a64,
    parse_begin_retire, parse_challenge_binding, parse_finalize_retire, response,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS, parse_device_driver_init,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, NativeError, StartupBlock, close_handle, device_pio_read,
    device_pio_write, device_resource_info, interrupt_ack, interrupt_info, monotonic_active_now,
    panic_abort, query_capability_info, receive_channel, send_channel, validate_bootstrap_channel,
    wait_many,
};
#[cfg(feature = "dw1e3-selector31")]
use wyrmroot_runtime::{
    Dw1e3ReportEvent, create_timer, dw1e3_bind_driver, dw1e3_build_nonce, dw1e3_challenge_nonce,
    dw1e3_report, set_timer, wait_one,
};
use wyrmroot_stream_proto::MAX_RECORD_BYTES;
#[cfg(feature = "dw1e3-selector31")]
use wyrmroot_stream_proto::decode_data;
use wyrmroot_uart16550_core::ByteRegisterIo;
#[cfg(feature = "wyr1d-selector32")]
use wyrmroot_uart16550d::d5_drain::DrainFence;
use wyrmroot_uart16550d::{
    DeviceStage, GracefulRetireDrain, PeerCloseDrain, ProductionDriver, ReceivedDeviceResource,
    ReceivedInterrupt, ReceivedStreamEndpoint, StreamSendAction, StreamSendResult,
    startup_control_is_readable,
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
    #[cfg(feature = "dw1e3-selector31")]
    let evidence_nonce = match dw1e3_build_nonce() {
        Ok(nonce) => nonce,
        Err(_) => return fail_driver(&mut driver, control, 60),
    };
    #[cfg(feature = "dw1e3-selector31")]
    dw1e3_bind_driver(
        driver.interrupt().handle,
        driver.identity().attempt_generation.0,
        evidence_nonce,
    )
    .map_err(|_| 61u32)?;
    let ready = match driver.activate() {
        Ok(ready) if !pio_failed.get() => ready,
        _ => return fail_driver(&mut driver, control, 33),
    };
    if send_control(control, ready).is_err() {
        return fail_driver(&mut driver, control, 34);
    }
    #[cfg(feature = "dw1e3-selector31")]
    return run_event_loop(&mut driver, control, &pio_failed, evidence_nonce);
    #[cfg(not(feature = "dw1e3-selector31"))]
    run_event_loop(
        &mut driver,
        control,
        &pio_failed,
        #[cfg(feature = "wyr1d-selector32")]
        startup_identity,
    )
}

fn run_event_loop<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
    pio_failed: &Cell<bool>,
    #[cfg(feature = "dw1e3-selector31")] evidence_nonce: u64,
    #[cfg(feature = "wyr1d-selector32")] startup_identity: ControlIdentityV1_1,
) -> Result<u32, u32> {
    let mut peer_close_drain = PeerCloseDrain::new();
    #[cfg(feature = "wyr1d-selector32")]
    let mut d5 = DrainFence::new(D5DriverIdentity {
        device_role_id: startup_identity.role_id.0,
        bundle_generation: startup_identity.bundle_generation.0,
        driver_attempt_generation: startup_identity.attempt_generation.0,
        driver_control_endpoint_id: startup_identity.endpoint.id.0,
        driver_control_endpoint_generation: startup_identity.endpoint.generation.0,
        launch_transaction_id: startup_identity.transaction_id,
    });
    #[cfg(feature = "wyr1d-selector32")]
    let mut d5_polls = 0u32;
    #[cfg(feature = "dw1e3-selector31")]
    let mut evidence = None;
    #[cfg(feature = "dw1e3-selector31")]
    let mut selector_retiring = false;
    #[cfg(feature = "dw1e3-selector31")]
    let mut selector_retirement_binding = None;
    let mut graceful_retire = None;
    loop {
        if let Some(drain) = graceful_retire.as_mut() {
            // Once an exact Retire is admitted, no later control request may
            // overtake a fast transport-empty observation.  Peer loss keeps
            // the established best-effort shutdown behavior; any queued
            // message is a conflicting post-Retire request.
            let control_signals = match probe_control(control) {
                Ok(signals) => signals,
                Err(_) => return fail_driver(driver, control, 36),
            };
            if control_signals.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                return graceful_shutdown(driver, control, 0);
            }
            if control_signals.0 & DW_SIGNAL_READABLE.0 != 0 {
                return fail_driver(driver, control, 114);
            }
            let completed = service_graceful_retire_drain(
                driver,
                control,
                pio_failed,
                drain,
                #[cfg(feature = "dw1e3-selector31")]
                &mut evidence,
                #[cfg(feature = "wyr1d-selector32")]
                &mut d5,
            );
            match completed {
                Ok(true) => return complete_graceful_retire(driver, control, pio_failed),
                Ok(false) => {}
                Err(code) => return fail_driver(driver, control, code),
            }
        }
        #[cfg(feature = "wyr1d-selector32")]
        if d5.pending().is_some() {
            if let Err(code) = service_d5_drain(driver, control, pio_failed, &mut d5) {
                return fail_driver(driver, control, code);
            }
        }
        let mut items = [DwWaitItemV1::default(); 3];
        items[0] = DwWaitItemV1 {
            handle: control,
            signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        };
        #[cfg(not(feature = "dw1e3-selector31"))]
        let mut count = 2;
        #[cfg(not(feature = "dw1e3-selector31"))]
        {
            items[1] = DwWaitItemV1 {
                handle: driver.interrupt().handle,
                signals: DW_SIGNAL_SIGNALED,
            };
        }
        #[cfg(feature = "dw1e3-selector31")]
        let mut count = if selector_retiring { 1 } else { 2 };
        #[cfg(feature = "dw1e3-selector31")]
        if !selector_retiring {
            items[1] = DwWaitItemV1 {
                handle: driver.interrupt().handle,
                signals: DW_SIGNAL_SIGNALED,
            };
        }
        if let Some(stream) = driver.stream_endpoint() {
            let receive_capacity = driver.wants_stream_readable();
            if peer_close_drain.include_stream_wait(receive_capacity) {
                let mut signals = DW_SIGNAL_PEER_CLOSED.0;
                if receive_capacity {
                    signals |= DW_SIGNAL_READABLE.0;
                }
                if graceful_retire.is_none()
                    && !peer_close_drain.is_pending()
                    && driver.wants_stream_writable()
                {
                    signals |= DW_SIGNAL_WRITABLE.0;
                }
                items[2] = DwWaitItemV1 {
                    handle: stream.handle,
                    signals: DwSignals(signals),
                };
                count = 3;
            }
        }
        let deadline = if let Some(drain) = graceful_retire {
            let now = match monotonic_active_now() {
                Ok(now) => now,
                Err(_) => return fail_driver(driver, control, 112),
            };
            let software_empty = driver.tx_free() == wyrmroot_uart16550_core::RING_CAPACITY;
            let deadline = match drain.wait_deadline(now, software_empty) {
                Ok(deadline) => deadline,
                Err(_) => return fail_driver(driver, control, 113),
            };
            DwDeadline(deadline)
        } else {
            DW_DEADLINE_INFINITE
        };
        #[cfg(feature = "wyr1d-selector32")]
        let deadline = if graceful_retire.is_none() && d5.pending().is_some() {
            DwDeadline(
                monotonic_active_now()
                    .map_err(|_| 100u32)?
                    .checked_add(1_000_000)
                    .ok_or(101u32)?,
            )
        } else {
            deadline
        };
        let observed = match wait_many(&items[..count], deadline) {
            Ok(observed) => observed,
            Err(error) if graceful_retire.is_some() && status_is(error, DW_STATUS_TIMED_OUT) => {
                continue;
            }
            #[cfg(feature = "wyr1d-selector32")]
            Err(error) if d5.pending().is_some() && status_is(error, DW_STATUS_TIMED_OUT) => {
                d5_polls += 1;
                if d5_polls > 2000 {
                    return fail_driver(driver, control, 102);
                }
                continue;
            }
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
            if graceful_retire.is_some() {
                return fail_driver(driver, control, 114);
            }
            if signals.0 & DW_SIGNAL_READABLE.0 != 0 {
                match service_control(driver, control) {
                    Ok(ControlOutcome::Continue) => continue,
                    Ok(ControlOutcome::Retire) => {
                        let now = match monotonic_active_now() {
                            Ok(now) => now,
                            Err(_) => return fail_driver(driver, control, 112),
                        };
                        graceful_retire =
                            match GracefulRetireDrain::new(now, driver.stream_endpoint().is_none())
                            {
                                Ok(drain) => Some(drain),
                                Err(_) => return fail_driver(driver, control, 113),
                            };
                        peer_close_drain.clear();
                        continue;
                    }
                    #[cfg(feature = "wyr1d-selector32")]
                    Ok(ControlOutcome::Drain(identity)) => {
                        if d5
                            .request(identity, driver.stream_attach_identity())
                            .is_err()
                        {
                            return fail_driver(driver, control, 103);
                        }
                        continue;
                    }
                    #[cfg(feature = "dw1e3-selector31")]
                    Ok(ControlOutcome::ChallengeBinding(binding)) => {
                        if evidence.is_some() {
                            return fail_driver(driver, control, 77);
                        }
                        let (stream_generation, publication_generation) =
                            driver.stream_generations().ok_or(78u32)?;
                        if binding.nonce != evidence_nonce
                            || binding.attempt_generation != driver.identity().attempt_generation.0
                            || binding.publication_generation != publication_generation
                            || binding.stream_generation != stream_generation
                        {
                            return fail_driver(driver, control, 79);
                        }
                        let challenge_nonce =
                            match dw1e3_challenge_nonce(binding.challenge_generation) {
                                Ok(nonce) => nonce,
                                Err(_) => return fail_driver(driver, control, 80),
                            };
                        let candidate = EvidenceDrain::new(
                            evidence_nonce,
                            binding.challenge_generation,
                            challenge_nonce,
                        );
                        if binding.expected_length != CHALLENGE_BYTES as u64
                            || binding.expected_hash != candidate.expected_hash
                        {
                            return fail_driver(driver, control, 81);
                        }
                        evidence = Some(candidate);
                        let mut ready = [0u8; wyrmroot_dw1e3_com2_test::TRANSPORT_EMPTY_FACT_BYTES];
                        if encode_binding_ready(binding, &mut ready).is_err() {
                            return fail_driver(driver, control, 83);
                        }
                        if send_channel(control, &ready, &[]).is_err() {
                            return fail_driver(driver, control, 84);
                        }
                        continue;
                    }
                    #[cfg(feature = "dw1e3-selector31")]
                    Ok(ControlOutcome::BeginRetire(binding)) => {
                        let Some(evidence) = evidence.as_ref() else {
                            return fail_driver(driver, control, 85);
                        };
                        if !same_binding(driver, evidence_nonce, evidence, binding) {
                            return fail_driver(driver, control, 86);
                        }
                        driver.begin_selector_retire();
                        if pio_failed.get()
                            || !driver.selector_interrupts_disabled()
                            || pio_failed.get()
                        {
                            return fail_driver(driver, control, 87);
                        }
                        if let Some((detached, endpoint)) = driver.detach_stream() {
                            let mut ready =
                                [0u8; wyrmroot_dw1e3_com2_test::TRANSPORT_EMPTY_FACT_BYTES];
                            if wyrmroot_dw1e3_com2_test::encode_retire_stage1_ready(
                                binding, &mut ready,
                            )
                            .is_err()
                            {
                                return fail_driver(driver, control, 88);
                            }
                            if close_handle(endpoint.handle).is_err() {
                                return fail_driver(driver, control, 89);
                            }
                            if send_channel(control, &ready, &[]).is_err() {
                                return fail_driver(driver, control, 90);
                            }
                            let _ = detached;
                            selector_retiring = true;
                            selector_retirement_binding = Some(binding);
                            continue;
                        }
                        return fail_driver(driver, control, 91);
                    }
                    #[cfg(feature = "dw1e3-selector31")]
                    Ok(ControlOutcome::FinalizeRetire(binding)) => {
                        if !selector_retiring || selector_retirement_binding != Some(binding) {
                            return fail_driver(driver, control, 92);
                        }
                        return graceful_shutdown(driver, control, 0);
                    }
                    Err(code) => return fail_driver(driver, control, code),
                }
            }
            return fail_driver(driver, control, 37);
        }

        if observed.index == 1 {
            if observed.observed.0 & DW_SIGNAL_SIGNALED.0 == 0 {
                return fail_driver(driver, control, 38);
            }
            #[cfg(feature = "dw1e3-selector31")]
            let rx_before = driver.rx_len();
            let drained = match driver.drain_interrupt() {
                Ok(drained) => drained,
                Err(_) => return fail_driver(driver, control, 39),
            };
            #[cfg(feature = "dw1e3-selector31")]
            {
                let mut added = [0u8; CHALLENGE_BYTES];
                let copied = driver.copy_rx_from(rx_before, &mut added);
                let Some(evidence) = evidence.as_mut() else {
                    return fail_driver(driver, control, 63);
                };
                if copied != usize::from(drained.work().received)
                    || evidence.record(&added[..copied]).is_err()
                {
                    return fail_driver(driver, control, 63);
                }
            }
            let acked = driver.acknowledge_interrupt(drained, !pio_failed.get(), |handle| {
                interrupt_ack(handle).map_err(|_| ())
            });
            let work = match acked {
                Ok(work) => work,
                Err(_) => return fail_driver(driver, control, 40),
            };
            #[cfg(not(feature = "dw1e3-selector31"))]
            let _ = work;
            #[cfg(feature = "wyr1d-selector32")]
            d5.irq_acknowledged();
            #[cfg(feature = "dw1e3-selector31")]
            if evidence
                .as_ref()
                .is_some_and(EvidenceDrain::response_reported)
                && work.transmitted != 0
                && driver.tx_free() == wyrmroot_uart16550_core::RING_CAPACITY
            {
                // The TX ring being empty does not prove that the stream
                // receive queue has no later WRST DATA.  Re-enter receive at
                // the exact post-ack boundary: only WOULD_BLOCK/clean close
                // proves no extra record can be hidden behind the response.
                if selector_response_input_drained(driver, control, pio_failed, &mut evidence)
                    .is_err()
                {
                    return fail_driver(driver, control, 82);
                }
                let Some(evidence) = evidence.as_mut() else {
                    return fail_driver(driver, control, 83);
                };
                if let Err(code) = prove_transport_empty(driver, control, pio_failed, evidence) {
                    return fail_driver(driver, control, code);
                }
            }
            continue;
        }

        if graceful_retire.is_some() && observed.index == 2 {
            // The retirement helper drains every immediately available raw
            // record and owns the fresh empty observation. Keep the normal
            // stream path from detaching or emitting RX data mid-retirement.
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
                    #[cfg(feature = "dw1e3-selector31")]
                    let stream_result = service_stream_read(
                        driver,
                        control,
                        pio_failed,
                        &mut evidence,
                        #[cfg(feature = "wyr1d-selector32")]
                        &mut d5,
                    );
                    #[cfg(not(feature = "dw1e3-selector31"))]
                    let stream_result = service_stream_read(
                        driver,
                        control,
                        pio_failed,
                        #[cfg(feature = "wyr1d-selector32")]
                        &mut d5,
                    );
                    match stream_result {
                        Ok(StreamReadOutcome::Accepted) => {}
                        #[cfg(feature = "dw1e3-selector31")]
                        Ok(StreamReadOutcome::EmptyData) => {}
                        Ok(StreamReadOutcome::WouldBlock | StreamReadOutcome::PeerClosed) => {
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
                #[cfg(feature = "dw1e3-selector31")]
                let stream_result = service_stream_read(
                    driver,
                    control,
                    pio_failed,
                    &mut evidence,
                    #[cfg(feature = "wyr1d-selector32")]
                    &mut d5,
                );
                #[cfg(not(feature = "dw1e3-selector31"))]
                let stream_result = service_stream_read(
                    driver,
                    control,
                    pio_failed,
                    #[cfg(feature = "wyr1d-selector32")]
                    &mut d5,
                );
                match stream_result {
                    Ok(StreamReadOutcome::Accepted | StreamReadOutcome::WouldBlock) => {}
                    #[cfg(feature = "dw1e3-selector31")]
                    Ok(StreamReadOutcome::EmptyData) => {}
                    Ok(StreamReadOutcome::PeerClosed | StreamReadOutcome::Detached) => {
                        if isolate_stream(driver, control).is_err() {
                            return fail_driver(driver, control, 41);
                        }
                        peer_close_drain.clear();
                        continue;
                    }
                    Err(()) => return fail_driver(driver, control, 42),
                }
            }
            if driver.stream_endpoint().is_some() && observed.observed.0 & DW_SIGNAL_WRITABLE.0 != 0
            {
                match service_stream_write(driver, control, &mut peer_close_drain) {
                    Ok(StreamSendAction::Continue) => {}
                    Ok(StreamSendAction::Detached(..)) => {
                        peer_close_drain.clear();
                        continue;
                    }
                    Err(()) => return fail_driver(driver, control, 43),
                }
            }
            continue;
        }
        return fail_driver(driver, control, 44);
    }
}

fn service_graceful_retire_drain<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
    pio_failed: &Cell<bool>,
    drain: &mut GracefulRetireDrain,
    #[cfg(feature = "dw1e3-selector31")] evidence: &mut Option<EvidenceDrain>,
    #[cfg(feature = "wyr1d-selector32")] d5: &mut DrainFence,
) -> Result<bool, u32> {
    while driver.wants_stream_readable() {
        #[cfg(feature = "dw1e3-selector31")]
        let result = service_stream_read(
            driver,
            control,
            pio_failed,
            evidence,
            #[cfg(feature = "wyr1d-selector32")]
            d5,
        );
        #[cfg(not(feature = "dw1e3-selector31"))]
        let result = service_stream_read(
            driver,
            control,
            pio_failed,
            #[cfg(feature = "wyr1d-selector32")]
            d5,
        );
        match result {
            Ok(StreamReadOutcome::Accepted) => drain.observe_stream_record(),
            #[cfg(feature = "dw1e3-selector31")]
            Ok(StreamReadOutcome::EmptyData) => drain.observe_stream_record(),
            Ok(StreamReadOutcome::WouldBlock) => {
                drain.observe_stream_empty();
                break;
            }
            Ok(StreamReadOutcome::PeerClosed | StreamReadOutcome::Detached) | Err(()) => {
                return Err(115);
            }
        }
    }

    let now = monotonic_active_now().map_err(|_| 112u32)?;
    let software_empty = driver.tx_free() == wyrmroot_uart16550_core::RING_CAPACITY;
    if !drain
        .temt_probe_due(now, software_empty)
        .map_err(|_| 113u32)?
    {
        return Ok(false);
    }
    if pio_failed.get() {
        return Err(116);
    }
    let transport_empty = driver.uart_mut().transport_empty();
    if pio_failed.get() {
        return Err(116);
    }
    drain
        .observe_temt(now, software_empty, transport_empty)
        .map_err(|_| 113u32)
}

fn complete_graceful_retire<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
    pio_failed: &Cell<bool>,
) -> Result<u32, u32> {
    driver.begin_graceful_retire();
    if pio_failed.get() || !driver.graceful_retire_interrupts_disabled() || pio_failed.get() {
        return fail_driver(driver, control, 117);
    }
    release_driver(driver, control, 0)
}

#[cfg(feature = "wyr1d-selector32")]
fn service_d5_drain<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
    pio_failed: &Cell<bool>,
    fence: &mut DrainFence,
) -> Result<(), u32> {
    let Some(identity) = fence.pending() else {
        return Ok(());
    };
    if driver.stream_attach_identity()
        != Some((identity.attach_transaction_id, identity.stream_generation))
    {
        return Err(106);
    }
    // Control may arrive before the final WRST DATA. Keep receiving it before
    // considering retirement; fresh WOULD_BLOCK is required on every probe.
    let mut channel_empty = false;
    while driver.wants_stream_readable() {
        match service_stream_read(driver, control, pio_failed, fence) {
            Ok(StreamReadOutcome::Accepted) => {}
            Ok(StreamReadOutcome::WouldBlock) => {
                channel_empty = true;
                break;
            }
            Ok(StreamReadOutcome::PeerClosed | StreamReadOutcome::Detached) | Err(()) => {
                return Err(107);
            }
        }
    }
    let software_empty = driver.tx_free() == wyrmroot_uart16550_core::RING_CAPACITY;
    if fence.ready(channel_empty, software_empty, true).is_none() {
        return Ok(());
    }
    let temt = driver.uart_mut().transport_empty();
    if pio_failed.get() {
        return Err(108);
    }
    if let Some(identity) = fence.ready(channel_empty, software_empty, temt) {
        let mut bytes = [0; D5_BYTES];
        encode_d5(D5ControllerMessage::TxDrained(identity), &mut bytes).map_err(|_| 109u32)?;
        send_channel(control, &bytes, &[]).map_err(|_| 110u32)?;
        fence.sent(identity).map_err(|_| 111u32)?;
    }
    Ok(())
}

#[cfg(feature = "dw1e3-selector31")]
fn selector_response_input_drained<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
    pio_failed: &Cell<bool>,
    evidence: &mut Option<EvidenceDrain>,
) -> Result<(), ()> {
    loop {
        match service_stream_read(driver, control, pio_failed, evidence) {
            // A fresh receive-side empty/closed observation is the only
            // positive proof. Legal empty DATA records are no-ops and must be
            // drained first; any nonempty/handle-bearing/malformed record
            // after the exact response fails before TEMT is emitted.
            Ok(StreamReadOutcome::WouldBlock | StreamReadOutcome::PeerClosed) => return Ok(()),
            Ok(StreamReadOutcome::EmptyData) => continue,
            Ok(StreamReadOutcome::Accepted | StreamReadOutcome::Detached) | Err(()) => {
                return Err(());
            }
        }
    }
}

#[cfg(feature = "dw1e3-selector31")]
struct EvidenceDrain {
    nonce: u64,
    challenge_generation: u64,
    expected: [u8; CHALLENGE_BYTES],
    expected_hash: u64,
    bytes: usize,
    hash: u64,
    reported: bool,
    transport_empty_reported: bool,
    response_bytes: usize,
    response_hash: u64,
}

#[cfg(feature = "dw1e3-selector31")]
impl EvidenceDrain {
    fn new(nonce: u64, challenge_generation: u64, challenge_nonce: u64) -> Self {
        let expected = challenge(challenge_nonce);
        Self {
            nonce,
            challenge_generation,
            expected,
            expected_hash: fnv1a64(&expected),
            bytes: 0,
            hash: 0xcbf2_9ce4_8422_2325,
            reported: false,
            transport_empty_reported: false,
            response_bytes: 0,
            response_hash: 0xcbf2_9ce4_8422_2325,
        }
    }

    fn record(&mut self, bytes: &[u8]) -> Result<(), ()> {
        // One physical burst may coalesce while the first pending epoch is
        // being drained. The follow-up ack epoch can therefore contain no new
        // UART bytes; it must remain admissible so the driver can rearm the
        // exact Interrupt. Any bytes after the challenge was reported still
        // fail closed as an unexpected second challenge.
        if bytes.is_empty() {
            return Ok(());
        }
        if self.reported || self.bytes.checked_add(bytes.len()).ok_or(())? > CHALLENGE_BYTES {
            return Err(());
        }
        for (offset, byte) in bytes.iter().enumerate() {
            if *byte != self.expected[self.bytes + offset] {
                return Err(());
            }
            self.hash ^= u64::from(*byte);
            self.hash = self.hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.bytes += bytes.len();
        if self.bytes == CHALLENGE_BYTES {
            if self.hash != self.expected_hash {
                return Err(());
            }
            dw1e3_report(
                if self.challenge_generation == CHALLENGE_GENERATION {
                    Dw1e3ReportEvent::Challenge1UartDrain
                } else {
                    Dw1e3ReportEvent::Challenge2UartDrain
                },
                self.bytes as u64,
                self.hash,
                self.nonce,
            )
            .map_err(|_| ())?;
            self.reported = true;
        }
        Ok(())
    }

    fn response_reported(&self) -> bool {
        self.reported
            && self.response_bytes == CHALLENGE_BYTES
            && self.response_hash == fnv1a64(&response(&self.expected))
            && !self.transport_empty_reported
    }

    fn mark_transport_empty(&mut self) {
        self.transport_empty_reported = true;
    }

    fn response_hash(&self) -> u64 {
        self.response_hash
    }

    fn record_response(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let expected = response(&self.expected);
        // A legal zero-length WRST DATA record does not alter the exact
        // response accumulator.  Nonempty data after completion remains an
        // error, including at the post-ack queue-empty proof.
        if bytes.is_empty() {
            return Ok(());
        }
        if self.response_bytes == expected.len()
            || self.response_bytes.checked_add(bytes.len()).ok_or(())? > expected.len()
        {
            return Err(());
        }
        for (offset, byte) in bytes.iter().enumerate() {
            if *byte != expected[self.response_bytes + offset] {
                return Err(());
            }
            self.response_hash ^= u64::from(*byte);
            self.response_hash = self.response_hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.response_bytes += bytes.len();
        Ok(())
    }
}

#[cfg(feature = "dw1e3-selector31")]
fn same_binding<I: ByteRegisterIo>(
    driver: &ProductionDriver<I>,
    nonce: u64,
    evidence: &EvidenceDrain,
    binding: ChallengeBinding,
) -> bool {
    driver
        .stream_generations()
        .is_some_and(|(stream, publication)| {
            binding.nonce == nonce
                && binding.attempt_generation == driver.identity().attempt_generation.0
                && binding.stream_generation == stream
                && binding.publication_generation == publication
                && binding.challenge_generation == evidence.challenge_generation
                && binding.expected_length == CHALLENGE_BYTES as u64
                && binding.expected_hash == evidence.expected_hash
        })
}

#[cfg(feature = "dw1e3-selector31")]
fn prove_transport_empty<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
    pio_failed: &Cell<bool>,
    evidence: &mut EvidenceDrain,
) -> Result<(), u32> {
    let (stream_generation, publication_generation) = driver.stream_generations().ok_or(64u32)?;
    let timer = create_timer(DwRights(
        DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0,
    ))
    .map_err(|_| 65u32)?;
    let result = (|| {
        for _ in 0..TRANSPORT_EMPTY_TEMT_MAX_POLLS {
            let deadline = monotonic_active_now()
                .map_err(|_| 66u32)?
                .checked_add(1_000_000)
                .ok_or(67u32)?;
            set_timer(timer, DwDeadline(deadline)).map_err(|_| 68u32)?;
            let waited = wait_one(
                timer,
                DW_SIGNAL_SIGNALED,
                DwDeadline(deadline.checked_add(1_000_000).ok_or(69u32)?),
            )
            .map_err(|_| 70u32)?;
            if waited.observed.0 & DW_SIGNAL_SIGNALED.0 == 0 {
                return Err(70);
            }
            if pio_failed.get() {
                return Err(71);
            }
            let temt = driver.uart_mut().transport_empty();
            // Check the sticky I/O failure immediately after LSR before a
            // false TEMT sample is allowed to schedule another paced poll.
            if pio_failed.get() {
                return Err(72);
            }
            if temt {
                if pio_failed.get() {
                    return Err(73);
                }
                let mut bytes = [0u8; wyrmroot_dw1e3_com2_test::TRANSPORT_EMPTY_FACT_BYTES];
                encode_transport_empty_fact(
                    TransportEmptyFact {
                        nonce: evidence.nonce,
                        attempt_generation: driver.identity().attempt_generation.0,
                        publication_generation,
                        stream_generation,
                        challenge_generation: evidence.challenge_generation,
                        response_length: CHALLENGE_BYTES as u64,
                        response_hash: evidence.response_hash(),
                    },
                    &mut bytes,
                )
                .map_err(|_| 74u32)?;
                send_channel(control, &bytes, &[]).map_err(|_| 75u32)?;
                evidence.mark_transport_empty();
                return Ok(());
            }
        }
        Err(76)
    })();
    let closed = close_handle(timer).map_err(|_| 77u32);
    result.and(closed)
}

enum ControlOutcome {
    Continue,
    Retire,
    #[cfg(feature = "wyr1d-selector32")]
    Drain(D5DrainIdentity),
    #[cfg(feature = "dw1e3-selector31")]
    ChallengeBinding(ChallengeBinding),
    #[cfg(feature = "dw1e3-selector31")]
    BeginRetire(ChallengeBinding),
    #[cfg(feature = "dw1e3-selector31")]
    FinalizeRetire(ChallengeBinding),
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
    #[cfg(feature = "wyr1d-selector32")]
    if counts.bytes == D5_BYTES && bytes[..4] == *b"WDR5" {
        if counts.handles != 0 {
            close_received(&handles, counts.handles);
            return Err(104);
        }
        return match parse_d5(&bytes[..counts.bytes]) {
            Ok(D5ControllerMessage::RequestDrain(identity)) => Ok(ControlOutcome::Drain(identity)),
            _ => Err(105),
        };
    }
    #[cfg(feature = "dw1e3-selector31")]
    if counts.handles == 0
        && counts.bytes == wyrmroot_dw1e3_com2_test::TRANSPORT_EMPTY_FACT_BYTES
        && bytes[..4] == wyrmroot_dw1e3_com2_test::DEVMGR_CONFIG_MAGIC
    {
        return match u16::from_le_bytes([bytes[6], bytes[7]]) {
            4 => parse_challenge_binding(&bytes[..counts.bytes])
                .map(ControlOutcome::ChallengeBinding)
                .map_err(|_| 47),
            6 => parse_begin_retire(&bytes[..counts.bytes])
                .map(ControlOutcome::BeginRetire)
                .map_err(|_| 47),
            7 => parse_finalize_retire(&bytes[..counts.bytes])
                .map(ControlOutcome::FinalizeRetire)
                .map_err(|_| 47),
            _ => Err(47),
        };
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
    #[cfg(feature = "dw1e3-selector31")] evidence: &mut Option<EvidenceDrain>,
    #[cfg(feature = "wyr1d-selector32")] d5: &mut DrainFence,
) -> Result<StreamReadOutcome, ()> {
    let Some(endpoint) = driver.stream_endpoint() else {
        return Ok(StreamReadOutcome::Detached);
    };
    let mut bytes = [0; MAX_RECORD_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 16];
    let counts = match receive_channel(endpoint.handle, &mut bytes, &mut handles) {
        Ok(counts) => counts,
        Err(error) if status_is(error, DW_STATUS_WOULD_BLOCK) => {
            return Ok(StreamReadOutcome::WouldBlock);
        }
        Err(error) if status_is(error, DW_STATUS_PEER_CLOSED) => {
            return Ok(StreamReadOutcome::PeerClosed);
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
    let accepted = match driver.accept_stream_record(&bytes[..counts.bytes], counts.handles) {
        Ok(accepted) => accepted,
        Err(_) => {
            close_received(&handles, counts.handles);
            isolate_stream(driver, control)?;
            return Ok(StreamReadOutcome::Detached);
        }
    };
    #[cfg(feature = "wyr1d-selector32")]
    d5.accept(accepted).map_err(|_| ())?;
    #[cfg(not(feature = "wyr1d-selector32"))]
    let _ = accepted;
    #[cfg(feature = "dw1e3-selector31")]
    {
        let payload = decode_data(&bytes[..counts.bytes])
            .map_err(|_| ())?
            .payload();
        if payload.is_empty() {
            evidence.as_mut().ok_or(())?.record_response(payload)?;
            if pio_failed.get() {
                return Err(());
            }
            return Ok(StreamReadOutcome::EmptyData);
        }
        evidence.as_mut().ok_or(())?.record_response(payload)?;
    }
    if pio_failed.get() {
        return Err(());
    }
    Ok(StreamReadOutcome::Accepted)
}

enum StreamReadOutcome {
    Accepted,
    #[cfg(feature = "dw1e3-selector31")]
    EmptyData,
    WouldBlock,
    PeerClosed,
    Detached,
}

fn service_stream_write<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
    peer_close_drain: &mut PeerCloseDrain,
) -> Result<StreamSendAction, ()> {
    let Some(endpoint) = driver.stream_endpoint() else {
        return Ok(StreamSendAction::Continue);
    };
    let mut bytes = [0; MAX_RECORD_BYTES];
    let Some(size) = driver.prepare_stream_send(&mut bytes).map_err(|_| ())? else {
        return Ok(StreamSendAction::Continue);
    };
    let result = match send_channel(endpoint.handle, &bytes[..size], &[]) {
        Ok(()) => StreamSendResult::Sent,
        Err(error) if status_is(error, DW_STATUS_WOULD_BLOCK) => StreamSendResult::WouldBlock,
        Err(error) if status_is(error, DW_STATUS_PEER_CLOSED) => StreamSendResult::PeerClosed,
        Err(_) => StreamSendResult::Failed,
    };
    match driver.resolve_stream_send(peer_close_drain, result) {
        StreamSendAction::Continue => Ok(StreamSendAction::Continue),
        StreamSendAction::Detached(detached, endpoint) => {
            let _ = close_handle(endpoint.handle);
            send_control(control, detached)?;
            Ok(StreamSendAction::Detached(detached, endpoint))
        }
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
    release_driver(driver, control, result)
}

fn release_driver<I: ByteRegisterIo>(
    driver: &mut ProductionDriver<I>,
    control: DwHandle,
    result: u32,
) -> Result<u32, u32> {
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
