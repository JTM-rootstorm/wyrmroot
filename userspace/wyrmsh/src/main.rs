// SPDX-License-Identifier: GPL-3.0-or-later
#![cfg_attr(target_os = "wyrmroot", no_std)]
#![cfg_attr(target_os = "wyrmroot", no_main)]
#![deny(unsafe_code)]

use deepwyrm_syscall as _;
use wyrmroot_console_proto as _;
use wyrmroot_fs_proto as _;
use wyrmroot_launch_proto as _;
use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_runtime::{NativePlatform, StartupBlock};
use wyrmroot_service_proto as _;
use wyrmroot_wyrmsh::run_wyrmsh;
use wyrmroot_wyrmsh_core as _;

fn wyrmsh_main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativePlatform;
    // F3A.7d. The session terminator reaches the supervisor as an application
    // status, because that is the one channel a supervised child already has
    // and it needs no new capability. `Termination::Shell` stays 0 so `exit`
    // is byte-for-byte what it was.
    run_wyrmsh(&mut system, startup).map_or_else(
        |error| error.exit_code(),
        |termination| match termination {
            wyrmroot_wyrmsh::Termination::Shell => 0,
            wyrmroot_wyrmsh::Termination::Session => {
                wyrmroot_launch_proto::SHELL_SESSION_SHUTDOWN_STATUS
            }
        },
    )
}

#[cfg(target_os = "wyrmroot")]
wyrmroot_runtime::native_entry!(crate::wyrmsh_main);

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
    let _: fn(StartupBlock<'_>) -> u32 = wyrmsh_main;
}
