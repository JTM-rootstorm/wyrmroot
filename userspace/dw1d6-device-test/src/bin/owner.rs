#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_RIGHT_INSPECT, DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_WAIT,
    DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_SIGNAL_SIGNALED,
    DwReceivedHandleInfoV1, DwRights, DwSignals,
};
use wyrmroot_dw1d6_device_test::{
    BUILD_CHALLENGE, BUILD_NONCE, CONTROLLER_MESSAGE_BYTES, ControllerMessage, DELIVERY_CYCLES,
    EXPECTED_SOURCE, MessageKind, PIO_WIDTH_1, RESOURCE_ID, SCRATCH_OFFSET, owner_start_permit,
};
use wyrmroot_loader::launch::{HEADER_BYTES, LaunchProfile, parse_init};
use wyrmroot_runtime::{
    D6ReportEvent, StartupBlock, claim_device_resource, close_handle, create_interrupt, d6_bind,
    d6_report, device_pio_read, device_pio_write, device_resource_info, interrupt_ack,
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
    0xD6_00_0000 | detail
}

fn send_status(channel: deepwyrm_syscall::DwHandle, kind: MessageKind, sequence: u64) -> bool {
    send_channel(
        channel,
        &ControllerMessage::new(kind, sequence, 0).encode(),
        &[],
    )
    .is_ok()
}

fn receive_command(channel: deepwyrm_syscall::DwHandle) -> Option<ControllerMessage> {
    let observed = wait_one(
        channel,
        DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        DW_DEADLINE_INFINITE,
    )
    .ok()?;
    if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return None;
    }
    let mut bytes = [0_u8; CONTROLLER_MESSAGE_BYTES];
    let mut handles = [];
    let counts = receive_channel(channel, &mut bytes, &mut handles).ok()?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        return None;
    }
    ControllerMessage::decode(&bytes).ok()
}

fn owner_main(startup: StartupBlock<'_>) -> u32 {
    let channel = startup.bootstrap_channel().as_abi();
    let mut bytes = [0_u8; HEADER_BYTES + 8];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match receive_channel(channel, &mut bytes, &mut handles) {
        Ok(value) => value,
        Err(_) => return fail(1),
    };
    if counts.bytes != bytes.len() || counts.handles != 1 {
        return fail(2);
    }
    if parse_init(LaunchProfile::D6ResourceOwner, &bytes, &handles).is_err() {
        return fail(3);
    }
    let domain = handles[0].handle;
    if receive_command(channel) != Some(owner_start_permit()) {
        return fail(33);
    }
    let resource = match claim_device_resource(domain, RESOURCE_ID, RESOURCE_RIGHTS) {
        Ok(value) => value,
        Err(_) => return fail(4),
    };
    let resource_info = match device_resource_info(resource) {
        Ok(value) => value,
        Err(_) => return fail(5),
    };
    if resource_info.resource_id != RESOURCE_ID
        || resource_info.interrupt_source != EXPECTED_SOURCE
        || resource_info.lease_generation == 0
    {
        return fail(6);
    }
    let saved = match device_pio_read(resource, SCRATCH_OFFSET, PIO_WIDTH_1) {
        Ok(value) => value,
        Err(_) => return fail(7),
    };
    if d6_report(
        D6ReportEvent::OwnerScratchSaved,
        u64::from(saved),
        u64::from(SCRATCH_OFFSET),
        BUILD_NONCE,
        BUILD_CHALLENGE,
    )
    .is_err()
    {
        return fail(8);
    }
    let challenge_byte = BUILD_CHALLENGE as u32 & 0xff;
    if device_pio_write(resource, SCRATCH_OFFSET, PIO_WIDTH_1, challenge_byte).is_err() {
        return fail(9);
    }
    if d6_report(
        D6ReportEvent::OwnerChallengeWritten,
        u64::from(challenge_byte),
        u64::from(saved),
        BUILD_NONCE,
        BUILD_CHALLENGE,
    )
    .is_err()
    {
        return fail(10);
    }
    let readback = match device_pio_read(resource, SCRATCH_OFFSET, PIO_WIDTH_1) {
        Ok(value) => value,
        Err(_) => return fail(11),
    };
    if readback != challenge_byte {
        return fail(12);
    }
    if d6_report(
        D6ReportEvent::OwnerChallengeReadBack,
        u64::from(readback),
        u64::from(saved),
        BUILD_NONCE,
        BUILD_CHALLENGE,
    )
    .is_err()
    {
        return fail(13);
    }
    if device_pio_write(resource, SCRATCH_OFFSET, PIO_WIDTH_1, saved).is_err() {
        return fail(14);
    }
    if d6_report(
        D6ReportEvent::OwnerScratchRestored,
        u64::from(saved),
        u64::from(challenge_byte),
        BUILD_NONCE,
        BUILD_CHALLENGE,
    )
    .is_err()
    {
        return fail(15);
    }
    let interrupt = match create_interrupt(resource, INTERRUPT_RIGHTS) {
        Ok(value) => value,
        Err(_) => return fail(16),
    };
    let interrupt_info = match interrupt_info(interrupt) {
        Ok(value) => value,
        Err(_) => return fail(17),
    };
    if interrupt_info.source != EXPECTED_SOURCE
        || interrupt_info.binding_generation == 0
        || interrupt_info.parent_lease_generation != resource_info.lease_generation
    {
        return fail(18);
    }
    if d6_bind(
        interrupt,
        resource_info.lease_generation,
        BUILD_NONCE,
        BUILD_CHALLENGE,
    )
    .is_err()
    {
        return fail(19);
    }
    if !send_status(channel, MessageKind::FirstOwnerBound, 0) {
        return fail(20);
    }
    let mut sequence = 1_u64;
    while sequence <= DELIVERY_CYCLES {
        // This is only logical intent. The ordinary kernel wait registry owns
        // the event-0A proof and gates DELIVER until this public wait is live.
        if !send_status(channel, MessageKind::OwnerWaitIntent, sequence) {
            return fail(21);
        }
        let observed = match wait_one(
            interrupt,
            DwSignals(DW_SIGNAL_SIGNALED.0),
            DW_DEADLINE_INFINITE,
        ) {
            Ok(value) => value,
            Err(_) => return fail(22),
        };
        if observed.observed.0 & DW_SIGNAL_SIGNALED.0 == 0 {
            return fail(23);
        }
        if !send_status(channel, MessageKind::OwnerWaitComplete, sequence) {
            return fail(24);
        }
        if receive_command(channel)
            != Some(ControllerMessage::new(
                MessageKind::OwnerAckPermit,
                sequence,
                0,
            ))
        {
            return fail(25);
        }
        if interrupt_ack(interrupt).is_err() {
            return fail(26);
        }
        if !send_status(channel, MessageKind::OwnerAckComplete, sequence) {
            return fail(27);
        }
        sequence += 1;
    }
    // Public finalization order is part of the proof: I1 first, then its
    // parent grant. Kernel hooks own events 0F and 10.
    if close_handle(interrupt).is_err() {
        return fail(28);
    }
    if close_handle(resource).is_err() {
        return fail(29);
    }
    if close_handle(domain).is_err() {
        return fail(30);
    }
    if !send_status(channel, MessageKind::FirstOwnerClosed, 0) {
        return fail(31);
    }
    if close_handle(channel).is_err() {
        return fail(32);
    }
    0
}

wyrmroot_runtime::native_entry!(crate::owner_main);
