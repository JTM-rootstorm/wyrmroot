#![no_std]
#![no_main]

use core::panic::PanicInfo;
use wyrmroot_loader as _;
use wyrmroot_runtime::StartupBlock;

#[path = "native.rs"]
mod native;

const EXPECTED_PRE_READY_FAILURE: u32 = 0xA101_F001;

fn main(startup: StartupBlock<'_>) -> u32 {
    wyrmroot_wyr1_bootstrap_stubs::run_fail_before_ready(
        &mut native::NativeSystem,
        startup.bootstrap_channel().as_abi(),
    )
    .map_or(0xA101_F002, |_| EXPECTED_PRE_READY_FAILURE)
}

wyrmroot_runtime::native_entry!(crate::main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    wyrmroot_runtime::panic_abort()
}
