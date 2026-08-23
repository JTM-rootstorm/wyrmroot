#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use wyrmroot_loader::launch::{self, LaunchProfile};
use wyrmroot_loader_smoke as _;
use wyrmroot_runtime::{StartupBlock, panic_abort, receive_channel, send_channel};

const FAILURE: u32 = 1;

fn loader_smoke_main(startup: StartupBlock<'_>) -> u32 {
    let channel = startup.bootstrap_channel().as_abi();
    let mut message = [0_u8; launch::HEADER_BYTES];
    let mut handles = [];
    let received = match receive_channel(channel, &mut message, &mut handles) {
        Ok(received) if received.bytes == message.len() && received.handles == 0 => received,
        _ => return FAILURE,
    };
    let parsed =
        match launch::parse_init(LaunchProfile::Hello, &message, &handles[..received.handles]) {
            Ok(parsed) => parsed,
            Err(_) => return FAILURE,
        };

    let mut ready = [0_u8; launch::HEADER_BYTES];
    let ready_size = match launch::encode_ready(parsed.transaction_id, &mut ready) {
        Ok(size) => size,
        Err(_) => return FAILURE,
    };
    if send_channel(channel, &ready[..ready_size], &[]).is_err() {
        return FAILURE;
    }
    0
}

wyrmroot_runtime::native_entry!(crate::loader_smoke_main);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}
