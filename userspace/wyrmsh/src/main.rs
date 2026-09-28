// SPDX-License-Identifier: GPL-3.0-or-later
#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall as _;
use wyrmroot_console_proto as _;
use wyrmroot_launch_proto as _;
use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_runtime::{NativePlatform, StartupBlock, panic_abort};
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

wyrmroot_runtime::native_entry!(crate::wyrmsh_main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
