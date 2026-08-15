//! 64-bit UEFI loader entry orchestration.
//!
//! This is intentionally not an `efi_main` symbol yet: the selected UEFI crate
//! and entry ABI belong to centralized target/toolchain integration. The pure
//! boundary below can be wired to that entry without assuming a raw Deepwyrm
//! kernel address, stack, register, flags, return, or mapping contract.

use crate::diagnostics::LoaderDiagnostic;
use crate::firmware::{
    BootServicesExited, DEFAULT_EXIT_BOOT_SERVICES_RETRY_LIMIT, ExitBootServicesFailure, Firmware,
    exit_boot_services_with_retry,
};

/// The deliberately closed post-firmware handoff boundary.
///
/// A future owner may replace this only after the shared RSP/RDI/direction-flag/
/// interrupt-flag/return/mapping contract has been reconciled with Deepwyrm.
/// This type carries no raw address or ABI values, preventing an accidental
/// local handoff convention.
#[derive(Debug)]
pub struct PendingKernelHandoff {
    _boot_services_exited: BootServicesExited,
}

/// Result of entering the WYR0-B 64-bit UEFI boundary.
#[derive(Debug)]
pub enum UefiEntryResult<E> {
    /// Firmware is exited, but a raw kernel transfer is intentionally blocked.
    HandoffPending(PendingKernelHandoff),
    /// Firmware transition failed before any kernel transfer could occur.
    FirmwareFailure(ExitBootServicesFailure<E>),
}

/// Executes the 64-bit UEFI pre-handoff sequence.
///
/// Diagnostics are emitted before final-map capture. On a successful
/// boot-services exit, this function returns a closed handoff token rather than
/// attempting a raw transfer with guessed machine state.
pub fn enter_x86_64_uefi<F: Firmware>(firmware: &mut F) -> UefiEntryResult<F::Error> {
    if let Err(error) = firmware.emit_diagnostic(LoaderDiagnostic::Entry) {
        return UefiEntryResult::FirmwareFailure(ExitBootServicesFailure::Diagnostic(error));
    }

    match exit_boot_services_with_retry(firmware, DEFAULT_EXIT_BOOT_SERVICES_RETRY_LIMIT) {
        Ok(boot_services_exited) => UefiEntryResult::HandoffPending(PendingKernelHandoff {
            _boot_services_exited: boot_services_exited,
        }),
        Err(error) => UefiEntryResult::FirmwareFailure(error),
    }
}
