#![cfg_attr(target_os = "wyrmroot", no_std)]
#![cfg_attr(target_os = "wyrmroot", no_main)]
#![deny(unsafe_code)]

#[cfg(target_os = "wyrmroot")]
use core::panic::PanicInfo;
#[cfg(target_os = "wyrmroot")]
use wyrmroot_runtime::panic_abort;
use wyrmroot_runtime::{NativePlatform, StartupBlock};
use {
    deepwyrm_syscall as _, wyrmroot_device_proto as _, wyrmroot_loader as _,
    wyrmroot_registry_proto as _,
};

fn native_main(startup: StartupBlock<'_>) -> u32 {
    wyrmroot_devmgr::role::run(&mut NativePlatform, startup.bootstrap_channel().as_abi())
        .unwrap_or_else(|code| code)
}

#[cfg(target_os = "wyrmroot")]
wyrmroot_runtime::native_entry!(crate::native_main);

#[cfg(target_os = "wyrmroot")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}

// This is a guest binary for `x86_64-unknown-wyrmroot`. A host build exists
// only so a workspace-wide `cargo test` can build the target at all: `_start`
// and a `#[panic_handler]` would each collide with the std that the host test
// profile links. Naming the freestanding entry keeps it, and everything it
// reaches, live for host type-checking; nothing here ever runs on the host.
#[cfg(not(target_os = "wyrmroot"))]
fn main() {
    let _: fn(StartupBlock<'_>) -> u32 = native_main;
}
