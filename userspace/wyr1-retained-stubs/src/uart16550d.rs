#![no_std]
#![no_main]
use core::panic::PanicInfo;
#[cfg(feature = "wyr1c5-production")]
use deepwyrm_syscall::{
    DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_DEVICE_RESOURCE_INFO_V1_VERSION,
    DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DW_INTERRUPT_INFO_V1_SIZE,
    DW_INTERRUPT_INFO_V1_VERSION, DW_INTERRUPT_STATE_ARMED, DW_OBJECT_TYPE_DEVICE_RESOURCE,
    DW_OBJECT_TYPE_INTERRUPT, DW_RIGHT_INSPECT, DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_WAIT,
    DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwRights, DwWaitItemV1,
};
use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DwReceivedHandleInfoV1,
};
#[cfg(feature = "wyr1c5-production")]
use wyrmroot_device_proto::control::{
    FAILURE_BYTES, READY_BYTES, RESOURCE_BUNDLE_BYTES, RETIRE_BYTES, TRIGGER_FAILURE_BYTES, parse,
};
#[cfg(feature = "wyr1c6-selector29")]
use wyrmroot_device_proto::selector29_should_fail;
#[cfg(not(feature = "wyr1c5-production"))]
use wyrmroot_device_proto::{ControlEndpoint, control::CONTROL_READY_BYTES};
use wyrmroot_device_proto::{
    ControlMessage, RoleId,
    control::encode,
    coordinator::{AttemptGeneration, EndpointGeneration, EndpointId},
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS, parse_device_driver_init,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, StartupBlock, close_handle, query_capability_info,
    receive_channel, send_channel, validate_bootstrap_channel,
};
#[cfg(feature = "wyr1c5-production")]
use wyrmroot_runtime::{device_resource_info, interrupt_info, wait_many};

/// C3 acceptance actor: validate the exact driver startup record, announce
/// only direct-control readiness, then return without UART or resource I/O.
fn main(startup: StartupBlock<'_>) -> u32 {
    run(startup).unwrap_or(0xAF03_0000)
}

fn run(startup: StartupBlock<'_>) -> Result<u32, u32> {
    let bootstrap = startup.bootstrap_channel().as_abi();
    validate_bootstrap_channel(
        query_capability_info(bootstrap).map_err(|_| 1u32)?,
        BOOTSTRAP_CHANNEL_EXPECTATION,
    )
    .map_err(|_| 2u32)?;
    let mut init = [0u8; DEVICE_DRIVER_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 2];
    let counts = receive_channel(bootstrap, &mut init, &mut handles).map_err(|_| 3u32)?;
    if counts.bytes > init.len() || counts.handles != 2 {
        close_received(&handles, counts.handles);
        return Err(4);
    }
    let parsed = parse_device_driver_init(&init[..counts.bytes], &handles).map_err(|_| 5u32)?;
    if !valid(handles[0], DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS)
        || !valid(handles[1], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS)
    {
        close_received(&handles, counts.handles);
        return Err(6);
    }
    #[cfg(not(feature = "wyr1c5-production"))]
    let message = ControlMessage::ControlReady {
        role_id: RoleId(parsed.role_id),
        attempt_generation: AttemptGeneration(parsed.attempt_generation),
        endpoint: ControlEndpoint {
            id: EndpointId(parsed.endpoint_id),
            generation: EndpointGeneration(parsed.endpoint_generation),
        },
        transaction_id: parsed.transaction_id,
    };
    #[cfg(not(feature = "wyr1c5-production"))]
    {
        let mut bytes = [0u8; CONTROL_READY_BYTES];
        encode(message, &mut bytes).map_err(|_| 7u32)?;
        send_channel(handles[1].handle, &bytes, &[]).map_err(|_| 8u32)?;
        close_handle(handles[0].handle).map_err(|_| 9u32)?;
        close_handle(handles[1].handle).map_err(|_| 10u32)?;
        Ok(0)
    }
    #[cfg(feature = "wyr1c5-production")]
    {
        close_handle(handles[0].handle).map_err(|_| 9u32)?;
        close_handle(bootstrap).map_err(|_| 10u32)?;
        run_c5_driver(handles[1].handle, parsed)
    }
}

#[cfg(feature = "wyr1c5-production")]
fn run_c5_driver(
    control: deepwyrm_syscall::DwHandle,
    startup: wyrmroot_loader::launch::DeviceDriverInit,
) -> Result<u32, u32> {
    let mut bytes = [0u8; RESOURCE_BUNDLE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 2];
    let observed = match wait_many(
        core::slice::from_ref(&DwWaitItemV1 {
            handle: control,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        }),
        deepwyrm_syscall::DW_DEADLINE_INFINITE,
    ) {
        Ok(observed) => observed,
        Err(_) => {
            let _ = close_handle(control);
            return Err(11);
        }
    };
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        close_handle(control).map_err(|_| 12u32)?;
        return Err(13);
    }
    let counts = match receive_channel(control, &mut bytes, &mut handles) {
        Ok(counts) => counts,
        Err(_) => {
            let _ = close_handle(control);
            return Err(14);
        }
    };
    if counts.bytes != bytes.len() || counts.handles != 2 {
        close_received(&handles, counts.handles);
        let _ = close_handle(control);
        return Err(15);
    }
    let bundle = match parse(&bytes) {
        Ok(ControlMessage::ResourceBundle {
            role_id,
            bundle_generation,
            attempt_generation,
            endpoint,
            transaction_id,
        }) if role_id == RoleId(startup.role_id)
            && attempt_generation == AttemptGeneration(startup.attempt_generation)
            && endpoint.id == EndpointId(startup.endpoint_id)
            && endpoint.generation == EndpointGeneration(startup.endpoint_generation)
            && transaction_id == startup.transaction_id =>
        {
            (
                role_id,
                bundle_generation,
                attempt_generation,
                endpoint,
                transaction_id,
            )
        }
        _ => {
            return close_c5_intake(control, &handles, 16);
        }
    };
    let resource_rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_INSPECT.0);
    let interrupt_rights = DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);
    if !valid(handles[0], DW_OBJECT_TYPE_DEVICE_RESOURCE, resource_rights)
        || !valid(handles[1], DW_OBJECT_TYPE_INTERRUPT, interrupt_rights)
    {
        return close_c5_intake(control, &handles, 17);
    }
    let resource = match device_resource_info(handles[0].handle) {
        Ok(info) => info,
        Err(_) => return close_c5_intake(control, &handles, 18),
    };
    let interrupt = match interrupt_info(handles[1].handle) {
        Ok(info) => info,
        Err(_) => return close_c5_intake(control, &handles, 19),
    };
    if resource.size != DW_DEVICE_RESOURCE_INFO_V1_SIZE
        || resource.version != DW_DEVICE_RESOURCE_INFO_V1_VERSION
        || resource.kind != DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT
        || resource.flags != 0
        || resource.resource_id != 1
        || resource.lease_generation != bundle.1.0
        || resource.pio_base != 0x2f8
        || resource.pio_length != 8
        || resource.interrupt_source != 3
        || resource.reserved != 0
        || interrupt.size != DW_INTERRUPT_INFO_V1_SIZE
        || interrupt.version != DW_INTERRUPT_INFO_V1_VERSION
        || interrupt.source != 3
        || interrupt.state != DW_INTERRUPT_STATE_ARMED
        || interrupt.object_generation == 0
        || interrupt.binding_generation == 0
        || interrupt.parent_resource_id != resource.resource_id
        || interrupt.parent_lease_generation != resource.lease_generation
        || interrupt.flags.0 != 0
        || interrupt.reserved0 != 0
        || interrupt.reserved != 0
    {
        return close_c5_intake(control, &handles, 20);
    }
    let ready = ControlMessage::Ready {
        role_id: bundle.0,
        bundle_generation: bundle.1,
        attempt_generation: bundle.2,
        endpoint: bundle.3,
        transaction_id: bundle.4,
    };
    let mut ready_bytes = [0u8; READY_BYTES];
    if encode(ready, &mut ready_bytes).is_err() {
        return close_c5_intake(control, &handles, 21);
    }
    if send_channel(control, &ready_bytes, &[]).is_err() {
        return close_c5_intake(control, &handles, 22);
    }

    #[cfg(feature = "wyr1c6-selector29")]
    if selector29_should_fail(
        wyrmroot_device_proto::coordinator::SupervisorGeneration(startup.supervisor_generation),
        AttemptGeneration(startup.attempt_generation),
    ) {
        let result = hold_until_failure_trigger(control, ready);
        let failure = ControlMessage::Failure {
            role_id: bundle.0,
            bundle_generation: bundle.1,
            attempt_generation: bundle.2,
            endpoint: bundle.3,
            transaction_id: bundle.4,
            code: wyrmroot_device_proto::FailureCode::IntentionalRestart,
        };
        let mut failure_bytes = [0u8; FAILURE_BYTES];
        let sent = result.is_ok()
            && encode(failure, &mut failure_bytes).is_ok()
            && send_channel(control, &failure_bytes, &[]).is_ok();
        let mut cleanup_failed = close_handle(handles[1].handle).is_err();
        cleanup_failed |= close_handle(handles[0].handle).is_err();
        cleanup_failed |= close_handle(control).is_err();
        return if sent && !cleanup_failed {
            Ok(0)
        } else {
            Err(31)
        };
    }

    #[cfg(feature = "wyr1c6-selector29")]
    let probe = hold_until_malformed_resource_probe(control, ready);
    #[cfg(not(feature = "wyr1c6-selector29"))]
    let probe = Ok(());
    let result = probe.and_then(|()| hold_until_retire(control, ready));
    let mut cleanup_failed = close_handle(handles[1].handle).is_err();
    cleanup_failed |= close_handle(handles[0].handle).is_err();
    cleanup_failed |= close_handle(control).is_err();
    if cleanup_failed { Err(23) } else { result }
}

#[cfg(feature = "wyr1c6-selector29")]
fn hold_until_failure_trigger(
    control: deepwyrm_syscall::DwHandle,
    ready: ControlMessage,
) -> Result<(), u32> {
    let observed = wait_many(
        core::slice::from_ref(&DwWaitItemV1 {
            handle: control,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        }),
        deepwyrm_syscall::DW_DEADLINE_INFINITE,
    )
    .map_err(|_| 32u32)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(33);
    }
    let mut bytes = [0u8; TRIGGER_FAILURE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(control, &mut bytes, &mut handles).map_err(|_| 34u32)?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(35);
    }
    let expected = match ready {
        ControlMessage::Ready {
            role_id,
            bundle_generation,
            attempt_generation,
            endpoint,
            transaction_id,
        } => ControlMessage::TriggerFailure {
            role_id,
            bundle_generation,
            attempt_generation,
            endpoint,
            transaction_id,
        },
        _ => return Err(36),
    };
    if parse(&bytes) == Ok(expected) {
        Ok(())
    } else {
        Err(37)
    }
}

#[cfg(feature = "wyr1c6-selector29")]
fn hold_until_malformed_resource_probe(
    control: deepwyrm_syscall::DwHandle,
    ready: ControlMessage,
) -> Result<(), u32> {
    let observed = wait_many(
        core::slice::from_ref(&DwWaitItemV1 {
            handle: control,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        }),
        deepwyrm_syscall::DW_DEADLINE_INFINITE,
    )
    .map_err(|_| 38u32)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(39);
    }
    let mut bytes = [0u8; RESOURCE_BUNDLE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 2];
    let counts = receive_channel(control, &mut bytes, &mut handles).map_err(|_| 40u32)?;
    if counts.bytes != bytes.len() || counts.handles != 2 {
        close_received(&handles, counts.handles);
        return Err(41);
    }
    let (role_id, active_generation, attempt_generation, endpoint, transaction_id) = match ready {
        ControlMessage::Ready {
            role_id,
            bundle_generation,
            attempt_generation,
            endpoint,
            transaction_id,
        } => (
            role_id,
            bundle_generation,
            attempt_generation,
            endpoint,
            transaction_id,
        ),
        _ => {
            close_received(&handles, counts.handles);
            return Err(42);
        }
    };
    match parse(&bytes) {
        Ok(ControlMessage::ResourceBundle {
            role_id: observed_role,
            bundle_generation,
            attempt_generation: observed_attempt,
            endpoint: observed_endpoint,
            transaction_id: observed_transaction,
        }) if observed_role == role_id
            && observed_attempt == attempt_generation
            && observed_endpoint == endpoint
            && observed_transaction == transaction_id
            && bundle_generation == active_generation => {}
        _ => {
            close_received(&handles, counts.handles);
            return Err(43);
        }
    }
    let resource_rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_INSPECT.0);
    let valid_types = valid(handles[0], DW_OBJECT_TYPE_DEVICE_RESOURCE, resource_rights)
        && valid(handles[1], DW_OBJECT_TYPE_DEVICE_RESOURCE, resource_rights);
    let first_resource = device_resource_info(handles[0].handle);
    let second_resource = device_resource_info(handles[1].handle);
    let valid_mapping = match (first_resource, second_resource) {
        (Ok(first), Ok(second)) => {
            let valid_resource = |resource: deepwyrm_syscall::DwDeviceResourceInfoV1| {
                resource.size == DW_DEVICE_RESOURCE_INFO_V1_SIZE
                    && resource.version == DW_DEVICE_RESOURCE_INFO_V1_VERSION
                    && resource.kind == DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT
                    && resource.flags == 0
                    && resource.resource_id == 1
                    && resource.lease_generation == active_generation.0
                    && resource.pio_base == 0x2f8
                    && resource.pio_length == 8
                    && resource.interrupt_source == 3
                    && resource.reserved == 0
            };
            valid_resource(first) && valid_resource(second)
        }
        _ => false,
    };
    let mut cleanup_failed = close_handle(handles[1].handle).is_err();
    cleanup_failed |= close_handle(handles[0].handle).is_err();
    if !valid_types || !valid_mapping || cleanup_failed {
        return Err(44);
    }
    let failure = ControlMessage::Failure {
        role_id,
        bundle_generation: active_generation,
        attempt_generation,
        endpoint,
        transaction_id,
        code: wyrmroot_device_proto::FailureCode::MalformedResource,
    };
    let mut failure_bytes = [0u8; FAILURE_BYTES];
    encode(failure, &mut failure_bytes).map_err(|_| 45u32)?;
    send_channel(control, &failure_bytes, &[]).map_err(|_| 46u32)
}

#[cfg(feature = "wyr1c5-production")]
fn close_c5_intake(
    control: deepwyrm_syscall::DwHandle,
    handles: &[DwReceivedHandleInfoV1; 2],
    code: u32,
) -> Result<u32, u32> {
    let mut cleanup_failed = close_handle(handles[1].handle).is_err();
    cleanup_failed |= close_handle(handles[0].handle).is_err();
    cleanup_failed |= close_handle(control).is_err();
    Err(if cleanup_failed { 30 } else { code })
}

#[cfg(feature = "wyr1c5-production")]
fn hold_until_retire(
    control: deepwyrm_syscall::DwHandle,
    ready: ControlMessage,
) -> Result<u32, u32> {
    let observed = wait_many(
        core::slice::from_ref(&DwWaitItemV1 {
            handle: control,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        }),
        deepwyrm_syscall::DW_DEADLINE_INFINITE,
    )
    .map_err(|_| 24u32)?;
    if observed.index != 0 {
        return Err(25);
    }
    if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Ok(0);
    }
    let mut bytes = [0u8; RETIRE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(control, &mut bytes, &mut handles).map_err(|_| 26u32)?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(27);
    }
    let expected = match ready {
        ControlMessage::Ready {
            role_id,
            bundle_generation,
            attempt_generation,
            endpoint,
            transaction_id,
        } => ControlMessage::Retire {
            role_id,
            bundle_generation,
            attempt_generation,
            endpoint,
            transaction_id,
        },
        _ => return Err(28),
    };
    if parse(&bytes) != Ok(expected) {
        return Err(29);
    }
    Ok(0)
}

fn valid(
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
wyrmroot_runtime::native_entry!(crate::main);
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    wyrmroot_runtime::panic_abort()
}
