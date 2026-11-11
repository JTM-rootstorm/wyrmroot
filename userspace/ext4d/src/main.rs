#![cfg_attr(target_os = "wyrmroot", no_std)]
#![cfg_attr(target_os = "wyrmroot", no_main)]
#![deny(unsafe_code)]

use wyrmroot_runtime::{NativePlatform, StartupBlock};
use {
    deepwyrm_syscall as _, wyrmroot_block_proto as _, wyrmroot_ext4 as _, wyrmroot_fs_proto as _,
    wyrmroot_loader as _, wyrmroot_service_proto as _,
};

fn ext4d_main(startup: StartupBlock<'_>) -> u32 {
    wyrmroot_ext4d::ext4d_main(
        &mut NativePlatform,
        &mut wyrmroot_service::memory::NativeMapper,
        startup.bootstrap_channel().as_abi(),
    )
}

#[cfg(target_os = "wyrmroot")]
wyrmroot_runtime::native_entry!(crate::ext4d_main);

#[cfg(target_os = "wyrmroot")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    wyrmroot_runtime::panic_abort()
}

// A guest binary for `x86_64-unknown-wyrmroot`; the host build only
// type-checks the entry (see virtio-blkd's main.rs).
#[cfg(not(target_os = "wyrmroot"))]
fn main() {
    let _: fn(StartupBlock<'_>) -> u32 = ext4d_main;
}
