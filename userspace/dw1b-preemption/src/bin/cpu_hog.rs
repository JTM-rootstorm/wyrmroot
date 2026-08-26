#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;
use deepwyrm_syscall as _;
use wyrmroot_dw1b_preemption::run_cpu_hog;
use wyrmroot_loader as _;
use wyrmroot_runtime::{StartupBlock, panic_abort};

#[used]
static DW1B_HOG_MARKER: [u8; 32] = *b"WYRMDW1B-HOG-V1:steady-spin-only";

fn payload_main(startup: StartupBlock<'_>) -> u32 {
    match run_cpu_hog(startup.bootstrap_channel().as_abi()) {
        Err(code) => code,
    }
}

wyrmroot_runtime::native_entry!(crate::payload_main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
