#![cfg_attr(target_os = "wyrmroot", no_std)]
#![cfg_attr(target_os = "wyrmroot", no_main)]
#![deny(unsafe_code)]

use wyrmroot_consoled::role::{FAILURE_BASE, run};
use wyrmroot_runtime::{NativePlatform, StartupBlock};
use {
    deepwyrm_syscall as _, wyrmroot_console_proto as _, wyrmroot_device_proto as _,
    wyrmroot_launch_proto as _, wyrmroot_loader as _, wyrmroot_registry_proto as _,
    wyrmroot_stream_proto as _,
};

fn native_main(startup: StartupBlock<'_>) -> u32 {
    run(&mut NativePlatform, startup.bootstrap_channel().as_abi())
        .unwrap_or_else(|step| FAILURE_BASE | step)
}

#[cfg(target_os = "wyrmroot")]
wyrmroot_runtime::native_entry!(crate::native_main);

#[cfg(target_os = "wyrmroot")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    wyrmroot_runtime::panic_abort()
}

// This is a guest binary for `x86_64-unknown-wyrmroot`. A host build exists
// so the role binary can be type-checked and linted on the host: `_start`
// and a `#[panic_handler]` would each collide with the std that a host build
// links. Naming the freestanding entry keeps it, and everything it reaches,
// live for host type-checking; nothing here ever runs on the host.
#[cfg(not(target_os = "wyrmroot"))]
fn main() {
    let _: fn(StartupBlock<'_>) -> u32 = native_main;
}
