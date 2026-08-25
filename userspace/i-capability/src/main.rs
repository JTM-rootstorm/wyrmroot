#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall as _;
use wyrmroot_bootfs as _;
use wyrmroot_i_capability::run_i_capability;
use wyrmroot_loader as _;
use wyrmroot_runtime::{StartupBlock, panic_abort};

fn capability_main(startup: StartupBlock<'_>) -> u32 {
    match run_i_capability(startup.bootstrap_channel().as_abi()) {
        Ok(()) => 0,
        Err(detail) => detail,
    }
}

wyrmroot_runtime::native_entry!(crate::capability_main);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}
