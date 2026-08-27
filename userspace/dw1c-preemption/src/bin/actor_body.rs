use core::panic::PanicInfo;
use deepwyrm_syscall as _;
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE, DW_STATUS_WOULD_BLOCK, DwSignals,
};
use wyrmroot_loader::launch::{HEADER_BYTES, LaunchProfile, encode_ready_for_profile, parse_init};
use wyrmroot_runtime::{
    StartupBlock, panic_abort, receive_channel, send_channel, submit_dw1c_progress, wait_one,
};

const DIGEST: u64 = parse_hex(env!("DEEPWYRM_DW1C_PROGRESS_DIGEST"));

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
    if TOKEN >= 9 {
        return 0;
    }
    if TOKEN == 6 {
        if wait_one(
            channel,
            DwSignals(DW_SIGNAL_READABLE.0),
            DW_DEADLINE_INFINITE,
        )
        .is_err()
        {
            return 0xD1C0_0600;
        }
        let mut byte = [0_u8; 1];
        if receive_channel(channel, &mut byte, &mut []).is_err() {
            return 0xD1C0_0601;
        }
    }
    if TOKEN == 7 {
        let payload = [0xA7_u8; 128];
        loop {
            match send_channel(channel, &payload, &[]) {
                Ok(()) => {}
                Err(wyrmroot_runtime::NativeError::Status(status))
                    if status == DW_STATUS_WOULD_BLOCK =>
                {
                    break;
                }
                Err(_) => return 0xD1C0_0701,
            }
        }
        if wait_one(
            channel,
            DwSignals(DW_SIGNAL_WRITABLE.0),
            DW_DEADLINE_INFINITE,
        )
        .is_err()
        {
            return 0xD1C0_0700;
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
