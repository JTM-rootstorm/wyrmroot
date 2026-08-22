#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use wyrmroot_hello as _;
use wyrmroot_runtime::{StartupBlock, panic_abort};

fn hello_main(_startup: StartupBlock<'_>) -> u32 {
    0
}

wyrmroot_runtime::native_entry!(crate::hello_main);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}
