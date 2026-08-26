#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;
use deepwyrm_syscall as _;
use wyrmroot_dw1b_preemption::run_progress;
use wyrmroot_loader as _;
use wyrmroot_runtime::{StartupBlock, panic_abort};

fn payload_main(startup: StartupBlock<'_>) -> u32 {
    match run_progress(startup.bootstrap_channel().as_abi()) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

wyrmroot_runtime::native_entry!(crate::payload_main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
