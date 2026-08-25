#![no_std]
#![no_main]
use core::panic::PanicInfo;
fn main(_: wyrmroot_runtime::StartupBlock<'_>) -> u32 {
    0xAF03_0000
}
wyrmroot_runtime::native_entry!(crate::main);
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    wyrmroot_runtime::panic_abort()
}
