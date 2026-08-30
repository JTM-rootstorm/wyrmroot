#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_RIGHT_INSPECT, DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_WAIT,
    DW_RIGHT_WRITE, DW_SIGNAL_SIGNALED, DwReceivedHandleInfoV1, DwRights, DwSignals,
};
use wyrmroot_dw1d6_device_test::{
    BUILD_CHALLENGE, BUILD_NONCE, ControllerMessage, EXPECTED_SOURCE, MessageKind, RESOURCE_ID,
};
use wyrmroot_loader::launch::{HEADER_BYTES, LaunchProfile, parse_init};
use wyrmroot_runtime::{
    StartupBlock, claim_device_resource, create_interrupt, d6_bind, device_resource_info,
    interrupt_info, panic_abort, receive_channel, send_channel, wait_one,
};

const RESOURCE_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);
const INTERRUPT_RIGHTS: DwRights =
    DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}

fn fail(detail: u32) -> u32 {
    0xd6_20_0000 | detail
}

fn send_status(channel: deepwyrm_syscall::DwHandle, kind: MessageKind) -> bool {
    send_channel(channel, &ControllerMessage::new(kind, 0, 0).encode(), &[]).is_ok()
}

fn replacement_main(startup: StartupBlock<'_>) -> u32 {
    let channel = startup.bootstrap_channel().as_abi();
    let mut bytes = [0_u8; HEADER_BYTES + 8];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match receive_channel(channel, &mut bytes, &mut handles) {
        Ok(value) => value,
        Err(_) => return fail(1),
    };
    if counts.bytes != bytes.len()
        || counts.handles != 1
        || parse_init(LaunchProfile::D6ResourceOwner, &bytes, &handles).is_err()
    {
        return fail(2);
    }
    let domain = handles[0].handle;
    let resource = match claim_device_resource(domain, RESOURCE_ID, RESOURCE_RIGHTS) {
        Ok(value) => value,
        Err(_) => return fail(3),
    };
    let resource_info = match device_resource_info(resource) {
        Ok(value) => value,
        Err(_) => return fail(4),
    };
    if resource_info.resource_id != RESOURCE_ID
        || resource_info.interrupt_source != EXPECTED_SOURCE
        || resource_info.lease_generation == 0
    {
        return fail(5);
    }
    let interrupt = match create_interrupt(resource, INTERRUPT_RIGHTS) {
        Ok(value) => value,
        Err(_) => return fail(6),
    };
    let interrupt_info = match interrupt_info(interrupt) {
        Ok(value) => value,
        Err(_) => return fail(7),
    };
    if interrupt_info.source != EXPECTED_SOURCE
        || interrupt_info.binding_generation == 0
        || interrupt_info.parent_lease_generation != resource_info.lease_generation
    {
        return fail(8);
    }
    if d6_bind(
        interrupt,
        resource_info.lease_generation,
        BUILD_NONCE,
        BUILD_CHALLENGE,
    )
    .is_err()
    {
        return fail(9);
    }
    if !send_status(channel, MessageKind::ReplacementBound) {
        return fail(10);
    }
    // Logical intent is observable only by the controller. The ordinary wait
    // registration and teardown paths own events 14 and 15.
    if !send_status(channel, MessageKind::ReplacementWaitIntent) {
        return fail(11);
    }
    match wait_one(
        interrupt,
        DwSignals(DW_SIGNAL_SIGNALED.0),
        DW_DEADLINE_INFINITE,
    ) {
        Ok(_) => fail(12),
        Err(_) => fail(13),
    }
}

wyrmroot_runtime::native_entry!(crate::replacement_main);
