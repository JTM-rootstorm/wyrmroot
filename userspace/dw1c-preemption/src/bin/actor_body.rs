use core::panic::PanicInfo;
use deepwyrm_syscall as _;
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_HANDLE_TRANSFER_MOVE, DW_RIGHT_INSPECT, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE,
    DW_STATUS_WOULD_BLOCK, DwHandleTransferV1, DwRights, DwSignals,
};
use wyrmroot_loader::launch::{HEADER_BYTES, LaunchProfile, encode_ready_for_profile, parse_init};
use wyrmroot_runtime::{
    StartupBlock, close_handle, create_channel, panic_abort, receive_channel, send_channel,
    submit_dw1c_progress, wait_one,
};

const DIGEST: u64 = parse_hex(env!("DEEPWYRM_DW1C_PROGRESS_DIGEST"));
const TOKEN7_SIDE_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);
const TOKEN7_SETUP: [u8; 2] = [0xA7, 0x01];
const TOKEN7_SETUP_ACK: [u8; 2] = [0xA7, 0x02];
const TOKEN7_FULL: [u8; 2] = [0xA7, 0x03];
const TOKEN7_WOKE: [u8; 2] = [0xA7, 0x04];
const ACTOR_ACK_PREFIX: u8 = 0xAC;

const fn parse_hex(text: &str) -> u64 {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut value = 0_u64;
    while index < 16 {
        value = (value << 4) | hex(bytes[index]);
        index += 1;
    }
    value
}
const fn hex(byte: u8) -> u64 {
    match byte {
        b'0'..=b'9' => (byte - b'0') as u64,
        b'A'..=b'F' => (byte - b'A' + 10) as u64,
        _ => panic!("invalid digest"),
    }
}

fn payload_main(startup: StartupBlock<'_>) -> u32 {
    let channel = startup.bootstrap_channel().as_abi();
    let mut header = [0_u8; HEADER_BYTES];
    let mut handles = [];
    let counts = match receive_channel(channel, &mut header, &mut handles) {
        Ok(value) => value,
        Err(_) => return 0xD1C0_0001 | TOKEN as u32,
    };
    if counts.bytes != HEADER_BYTES || counts.handles != 0 {
        return 0xD1C0_0002 | TOKEN as u32;
    }
    let init = match parse_init(LaunchProfile::Hello, &header, &[]) {
        Ok(value) => value,
        Err(_) => return 0xD1C0_0003 | TOKEN as u32,
    };
    let mut ready = [0_u8; HEADER_BYTES];
    let size = match encode_ready_for_profile(LaunchProfile::Hello, init.transaction_id, &mut ready)
    {
        Ok(value) => value,
        Err(_) => return 0xD1C0_0004 | TOKEN as u32,
    };
    if send_channel(channel, &ready[..size], &[]).is_err() {
        return 0xD1C0_0005 | TOKEN as u32;
    }
    let mut go = [0_u8; 1];
    let gate = match wait_one(
        channel,
        DwSignals(DW_SIGNAL_READABLE.0),
        DW_DEADLINE_INFINITE,
    ) {
        Ok(_) => {
            let mut handles = [];
            receive_channel(channel, &mut go, &mut handles)
        }
        Err(_) => return 0xD1C0_0006 | TOKEN as u32,
    };
    if gate.map_or(true, |counts| {
        counts.bytes != 1 || counts.handles != 0 || go[0] != 1
    }) {
        return 0xD1C0_0007 | TOKEN as u32;
    }
    if TOKEN <= 5 {
        if submit_dw1c_progress(TOKEN, 1, DIGEST).is_err() {
            return 0xD1C0_0100 | TOKEN as u32;
        }
    }
    if TOKEN <= 6 {
        if send_channel(channel, &[ACTOR_ACK_PREFIX, TOKEN], &[]).is_err() {
            return 0xD1C0_0200 | TOKEN as u32;
        }
    }
    if TOKEN >= 9 {
        return 0;
    }
    if TOKEN == 7 {
        let (side, offered) = match create_channel(TOKEN7_SIDE_RIGHTS) {
            Ok(pair) => pair,
            Err(_) => return 0xD1C0_0701,
        };
        let transfer = DwHandleTransferV1 {
            handle: offered,
            requested_rights: TOKEN7_SIDE_RIGHTS,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        };
        if send_channel(channel, &TOKEN7_SETUP, &[transfer]).is_err() {
            let _ = close_handle(side);
            let _ = close_handle(offered);
            return 0xD1C0_0702;
        }
        if wait_one(
            channel,
            DwSignals(DW_SIGNAL_READABLE.0),
            DW_DEADLINE_INFINITE,
        )
        .is_err()
        {
            let _ = close_handle(side);
            return 0xD1C0_0703;
        }
        let mut setup_ack = [0_u8; 2];
        let mut no_handles = [];
        let counts = receive_channel(channel, &mut setup_ack, &mut no_handles);
        if counts.map_or(true, |counts| {
            counts.bytes != TOKEN7_SETUP_ACK.len()
                || counts.handles != 0
                || setup_ack != TOKEN7_SETUP_ACK
        }) {
            let _ = close_handle(side);
            return 0xD1C0_0704;
        }
        let payload = [0xA7_u8; 128];
        loop {
            match send_channel(channel, &payload, &[]) {
                Ok(()) => {}
                Err(wyrmroot_runtime::NativeError::Status(status))
                    if status == DW_STATUS_WOULD_BLOCK =>
                {
                    break;
                }
                Err(_) => {
                    let _ = close_handle(side);
                    return 0xD1C0_0705;
                }
            }
        }
        if send_channel(side, &TOKEN7_FULL, &[]).is_err() {
            let _ = close_handle(side);
            return 0xD1C0_0706;
        }
        if wait_one(
            channel,
            DwSignals(DW_SIGNAL_WRITABLE.0),
            DW_DEADLINE_INFINITE,
        )
        .is_err()
        {
            let _ = close_handle(side);
            return 0xD1C0_0707;
        }
        if send_channel(side, &TOKEN7_WOKE, &[]).is_err() {
            let _ = close_handle(side);
            return 0xD1C0_0708;
        }
        if close_handle(side).is_err() {
            return 0xD1C0_0709;
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
wyrmroot_runtime::native_entry!(crate::payload_main);
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
