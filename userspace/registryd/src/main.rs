#![no_std]
#![no_main]

use core::panic::PanicInfo;
use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_registryd as _;
use wyrmroot_runtime::StartupBlock;

fn main(_startup: StartupBlock<'_>) -> u32 {
    // The resident native Channel loop is entered by the WYR1-B system-init
    // integration path after WRLP 1.3 startup validation. A zero return here
    // is not used as registry readiness evidence.
    0xB101_0001
}

wyrmroot_runtime::native_entry!(crate::main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    wyrmroot_runtime::panic_abort()
}
