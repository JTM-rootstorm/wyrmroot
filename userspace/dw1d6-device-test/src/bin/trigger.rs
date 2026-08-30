#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_STATUS_BAD_STATE,
    DW_STATUS_WOULD_BLOCK, DwReceivedHandleInfoV1, DwSignals,
};
use wyrmroot_dw1d6_device_test::{
    BAD_STATE_STATUS, BUILD_CHALLENGE, BUILD_NONCE, CONTROLLER_MESSAGE_BYTES, ControllerMessage,
    MessageKind, RACE_PERMIT_SEQUENCE, STALE_DELIVERY_SEQUENCE,
};
use wyrmroot_loader::launch::{HEADER_BYTES, LaunchProfile, parse_init};
use wyrmroot_runtime::{
    NativeError, d6_deliver, panic_abort, receive_channel, send_channel, wait_one,
};

const REGISTRATION_RETRIES: u32 = 1_000_000;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
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

fn delivery_status(sequence: u64, expected_status: i32) -> i32 {
    let mut attempts = 0_u32;
    loop {
        match d6_deliver(sequence, BUILD_NONCE, BUILD_CHALLENGE) {
            Ok(()) => return 0,
            Err(NativeError::Status(status)) => {
                // Logical wait intent deliberately precedes public wait
                // registration. For successful deliveries, bounded retries
                // let the kernel registration gate—not controller timing—win.
                if expected_status == 0
                    && (status == DW_STATUS_WOULD_BLOCK || status == DW_STATUS_BAD_STATE)
                    && attempts < REGISTRATION_RETRIES
                {
                    attempts += 1;
                    core::hint::spin_loop();
                    continue;
                }
                return status.0;
            }
            Err(NativeError::Output(_)) => return i32::MIN,
        }
    }
}

fn trigger_main(startup: wyrmroot_runtime::StartupBlock<'_>) -> u32 {
    let channel = startup.bootstrap_channel().as_abi();
    let mut init = [0_u8; HEADER_BYTES];
    let mut none = [];
    let counts = match receive_channel(channel, &mut init, &mut none) {
        Ok(value) => value,
        Err(_) => return 0xd6_10_0001,
    };
    if counts.bytes != HEADER_BYTES
        || counts.handles != 0
        || parse_init(
            LaunchProfile::Hello,
            &init,
            &[] as &[DwReceivedHandleInfoV1],
        )
        .is_err()
    {
        return 0xd6_10_0002;
    }
    let mut expected_sequence = 1_u64;
    loop {
        let Some(command) = receive_command(channel) else {
            return 0xd6_10_0003 | expected_sequence as u32;
        };
        if command.kind == MessageKind::TriggerFinish
            && command.sequence == 0
            && command.status == 0
            && expected_sequence == STALE_DELIVERY_SEQUENCE + 1
        {
            let finished = ControllerMessage::new(MessageKind::TriggerFinished, 0, 0).encode();
            return if send_channel(channel, &finished, &[]).is_ok() {
                0
            } else {
                0xd6_10_0010
            };
        }
        if command.kind != MessageKind::TriggerDeliver
            || command.sequence != expected_sequence
            || (expected_sequence <= RACE_PERMIT_SEQUENCE && command.status != 0)
            || (expected_sequence == STALE_DELIVERY_SEQUENCE && command.status != BAD_STATE_STATUS)
        {
            return 0xd6_10_0004 | expected_sequence as u32;
        }
        let status = delivery_status(expected_sequence, command.status);
        let completion =
            ControllerMessage::new(MessageKind::TriggerComplete, expected_sequence, status)
                .encode();
        if send_channel(channel, &completion, &[]).is_err() {
            return 0xd6_10_0005 | expected_sequence as u32;
        }
        if status != command.status {
            return 0xd6_10_0006 | expected_sequence as u32;
        }
        expected_sequence += 1;
    }
}

wyrmroot_runtime::native_entry!(crate::trigger_main);
