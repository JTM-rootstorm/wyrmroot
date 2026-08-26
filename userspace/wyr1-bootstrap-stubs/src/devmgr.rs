#![no_std]
#![no_main]
use core::panic::PanicInfo;
use wyrmroot_loader as _;
use wyrmroot_runtime::StartupBlock;
#[path = "native.rs"]
mod native;
fn main(startup: StartupBlock<'_>) -> u32 {
    wyrmroot_wyr1_bootstrap_stubs::stub_application_status(
        wyrmroot_wyr1_bootstrap_stubs::run_stub(
            &mut native::NativeSystem,
            startup.bootstrap_channel().as_abi(),
        ),
        0xA102_0001,
    )
}
wyrmroot_runtime::native_entry!(crate::main);
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    wyrmroot_runtime::panic_abort()
}
