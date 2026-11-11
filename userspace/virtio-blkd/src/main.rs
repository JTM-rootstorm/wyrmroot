#![cfg_attr(target_os = "wyrmroot", no_std)]
#![cfg_attr(target_os = "wyrmroot", no_main)]
#![deny(unsafe_code)]

use wyrmroot_runtime::{NativePlatform, StartupBlock};
use {
    deepwyrm_syscall as _, wyrmroot_block_proto as _, wyrmroot_device_proto as _,
    wyrmroot_loader as _, wyrmroot_registry_proto as _,
};

fn blk_main(startup: StartupBlock<'_>) -> u32 {
    wyrmroot_virtio_blkd::role::blk_main(
        &mut NativePlatform,
        &mut wyrmroot_virtio_blkd::role::NativeMapper,
        startup.bootstrap_channel().as_abi(),
    )
}

#[cfg(target_os = "wyrmroot")]
wyrmroot_runtime::native_entry!(crate::blk_main);

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
    let _: fn(StartupBlock<'_>) -> u32 = blk_main;
}
