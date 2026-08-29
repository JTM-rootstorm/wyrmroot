#![no_std]
#![no_main]
use core::panic::PanicInfo;
use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DwReceivedHandleInfoV1,
};
use wyrmroot_device_proto::{
    ControlEndpoint, ControlMessage, RoleId,
    control::{CONTROL_READY_BYTES, encode},
    coordinator::{AttemptGeneration, EndpointGeneration, EndpointId},
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS, parse_device_driver_init,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, StartupBlock, close_handle, query_capability_info,
    receive_channel, send_channel, validate_bootstrap_channel,
};

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
    let message = ControlMessage::ControlReady {
        role_id: RoleId(parsed.role_id),
        attempt_generation: AttemptGeneration(parsed.attempt_generation),
        endpoint: ControlEndpoint {
            id: EndpointId(parsed.endpoint_id),
            generation: EndpointGeneration(parsed.endpoint_generation),
        },
        transaction_id: parsed.transaction_id,
    };
    let mut bytes = [0u8; CONTROL_READY_BYTES];
    encode(message, &mut bytes).map_err(|_| 7u32)?;
    send_channel(handles[1].handle, &bytes, &[]).map_err(|_| 8u32)?;
    close_handle(handles[0].handle).map_err(|_| 9u32)?;
    close_handle(handles[1].handle).map_err(|_| 10u32)?;
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
