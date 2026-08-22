#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use wyrmroot_init0 as _;
use wyrmroot_runtime::{StartupBlock, panic_abort};

fn init0_main(_startup: StartupBlock<'_>) -> u32 {
    0
}

wyrmroot_runtime::native_entry!(crate::init0_main);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}
