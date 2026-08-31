#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle, DwReceivedHandleInfoV1, DwWaitItemV1,
};
use wyrmroot_device_proto::control::ControlEndpoint;
use wyrmroot_device_proto::control_v1_1::{
    ControlIdentityV1_1, ControlMessageV1_1, DEVICE_QUIESCED_BYTES, DEVICE_STAGE_BYTES, encode,
    parse,
};
use wyrmroot_device_proto::coordinator::{
    AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId,
};
use wyrmroot_device_proto::manifest::RoleId;
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS, parse_device_driver_init,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, StartupBlock, close_handle, device_pio_read, device_pio_write,
    device_resource_info, panic_abort, query_capability_info, receive_channel, send_channel,
    validate_bootstrap_channel, wait_many,
};
use wyrmroot_uart16550_core::ByteRegisterIo;
use wyrmroot_uart16550d::{DeviceStage, ReceivedDeviceResource};

const FAILURE_BASE: u32 = 0xD3A0_0000;

struct NativeResourceIo {
    handle: DwHandle,
    failed: bool,
}

impl ByteRegisterIo for NativeResourceIo {
    fn read(&mut self, offset: u8) -> u8 {
        if self.failed {
            return 0;
        }
        match device_pio_read(self.handle, u32::from(offset), 1) {
            Ok(value) if value <= u32::from(u8::MAX) => value as u8,
            _ => {
                self.failed = true;
                0
            }
        }
    }

    fn write(&mut self, offset: u8, value: u8) {
        if !self.failed
            && device_pio_write(self.handle, u32::from(offset), 1, u32::from(value)).is_err()
        {
            self.failed = true;
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
    close_handle(startup_handles[0].handle).map_err(|_| 6u32)?;
    close_handle(bootstrap).map_err(|_| 7u32)?;

    let observed = wait_many(
        core::slice::from_ref(&DwWaitItemV1 {
            handle: control,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        }),
        DW_DEADLINE_INFINITE,
    )
    .map_err(|_| 8u32)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        close_handle(control).map_err(|_| 9u32)?;
        return Err(10);
    }
    let mut stage_bytes = [0; DEVICE_STAGE_BYTES];
    let mut stage_handles = [DwReceivedHandleInfoV1::default(); 1];
    let stage_counts =
        receive_channel(control, &mut stage_bytes, &mut stage_handles).map_err(|_| 11u32)?;
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
    let io = NativeResourceIo {
        handle: received.handle,
        failed: false,
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
    let (_, uart) = stage.into_parts();
    let io = uart.into_io();
    if io.failed {
        return fail_owned_stage(control, received.handle, 22);
    }
    let mut response_bytes = [0; DEVICE_QUIESCED_BYTES];
    if encode(response, &mut response_bytes).is_err() {
        return fail_owned_stage(control, received.handle, 23);
    }
    if send_channel(control, &response_bytes, &[]).is_err() {
        return fail_owned_stage(control, received.handle, 24);
    }

    // D3A ends at the silent pre-Interrupt authority gate. This process does
    // not parse INTERRUPT_STAGE or activate the UART before D3B is joined.
    close_handle(received.handle).map_err(|_| 25u32)?;
    close_handle(control).map_err(|_| 26u32)?;
    Ok(0)
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
    let _ = close_handle(resource);
    let _ = close_handle(control);
    Err(code)
}

wyrmroot_runtime::native_entry!(crate::uart_main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
