use core::panic::PanicInfo;
use deepwyrm_syscall as _;
use wyrmroot_loader as _;
use wyrmroot_runtime::{StartupBlock, panic_abort, submit_dw1c_progress};

const DIGEST: u64 = parse_hex(env!("DEEPWYRM_DW1C_PROGRESS_DIGEST"));

const fn parse_hex(text: &str) -> u64 {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut value = 0_u64;
    while index < 16 { value = (value << 4) | hex(bytes[index]); index += 1; }
    value
}
const fn hex(byte: u8) -> u64 { match byte { b'0'..=b'9' => (byte - b'0') as u64, b'A'..=b'F' => (byte - b'A' + 10) as u64, _ => panic!("invalid digest") } }

fn payload_main(_: StartupBlock<'_>) -> u32 {
    if TOKEN <= 5 { if submit_dw1c_progress(TOKEN, 1, DIGEST).is_err() { return 0xD1C0_0100 | TOKEN as u32; } }
    if TOKEN >= 9 { return 0; }
    loop { core::hint::spin_loop(); }
}
wyrmroot_runtime::native_entry!(crate::payload_main);
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! { panic_abort() }
