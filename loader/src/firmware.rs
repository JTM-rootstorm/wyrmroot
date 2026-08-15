//! UEFI boot-services exit orchestration.
//!
//! This module models the small but security-sensitive final-map /
//! `ExitBootServices()` transition. It has no UEFI implementation dependency so
//! its state machine can be host tested. A future firmware adapter must uphold
//! the trait's no-allocation critical-section contract.

use crate::diagnostics::LoaderDiagnostic;

/// The opaque key associated with one UEFI memory-map snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryMapKey(u64);

impl MemoryMapKey {
    /// Creates a key returned by a firmware memory-map query.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the opaque firmware value for the paired exit call.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// The result of acquiring the final UEFI memory map.
///
/// WYR0-B only transports the opaque map key here. Construction and validation
/// of the canonical `DwBootInfoV1` memory-map data remains separate, generated
/// ABI work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalMemoryMap {
    key: MemoryMapKey,
}

impl FinalMemoryMap {
    /// Creates a final-map token from the key returned by firmware.
    pub const fn new(key: MemoryMapKey) -> Self {
        Self { key }
    }

    const fn key(self) -> MemoryMapKey {
        self.key
    }
}

/// The reason firmware rejected an `ExitBootServices()` attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExitBootServicesError<E> {
    /// Firmware reports that the memory map changed after capture.
    StaleMemoryMap,
    /// Firmware failed for a reason that cannot be safely retried here.
    Firmware(E),
}

/// A narrow firmware surface used by the final boot-services transition.
///
/// `capture_final_memory_map` must return a key for the final complete map and
/// prepare all storage needed by the eventual BootInfo producer. Once it
/// returns successfully, the adapter must not perform diagnostics, allocation,
/// protocol lookup, or any other action that can change the map before the
/// paired `exit_boot_services` call.
pub trait Firmware {
    /// Adapter-specific firmware failure value.
    type Error;

    /// Emits a loader marker while boot services are still active.
    fn emit_diagnostic(&mut self, marker: LoaderDiagnostic) -> Result<(), Self::Error>;

    /// Captures the final memory map and returns its opaque key.
    fn capture_final_memory_map(&mut self) -> Result<FinalMemoryMap, Self::Error>;

    /// Exits boot services with the key from the immediately preceding capture.
    fn exit_boot_services(
        &mut self,
        key: MemoryMapKey,
    ) -> Result<(), ExitBootServicesError<Self::Error>>;
}

/// A nonzero upper bound for final-map / boot-services-exit attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitBootServicesRetryLimit(u8);

impl ExitBootServicesRetryLimit {
    /// Returns `None` for a zero-attempt policy.
    pub const fn new(attempts: u8) -> Option<Self> {
        if attempts == 0 {
            None
        } else {
            Some(Self(attempts))
        }
    }

    const fn attempts(self) -> u8 {
        self.0
    }
}

/// The WYR0-B bounded-retry default.
pub const DEFAULT_EXIT_BOOT_SERVICES_RETRY_LIMIT: ExitBootServicesRetryLimit =
    ExitBootServicesRetryLimit(3);

/// Proof that UEFI boot services have exited through this state machine.
///
/// The value does not contain a raw kernel entry address, BootInfo pointer, or
/// mapping assumption. Those are unavailable until the shared handoff contract
/// is reconciled.
#[derive(Debug)]
pub struct BootServicesExited {
    _private: (),
}

/// Failure while reaching the post-firmware boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExitBootServicesFailure<E> {
    /// Pre-exit diagnostics failed; proceeding would lose required evidence.
    Diagnostic(E),
    /// Final memory-map capture failed.
    MemoryMap(E),
    /// Firmware failed to exit boot services for a non-retryable reason.
    Firmware(E),
    /// Every bounded retry observed a stale memory-map key.
    RetryLimitExceeded,
}

/// Acquires the final UEFI memory map and exits boot services.
///
/// Every retry obtains a fresh map key. The last diagnostic is emitted before
/// each capture so no marker can invalidate a captured key. Any diagnostic,
/// map, or firmware failure returns an error before a kernel handoff is
/// attempted.
pub fn exit_boot_services_with_retry<F: Firmware>(
    firmware: &mut F,
    retry_limit: ExitBootServicesRetryLimit,
) -> Result<BootServicesExited, ExitBootServicesFailure<F::Error>> {
    for attempt in 1..=retry_limit.attempts() {
        firmware
            .emit_diagnostic(LoaderDiagnostic::FinalMemoryMapAttempt { attempt })
            .map_err(ExitBootServicesFailure::Diagnostic)?;
        firmware
            .emit_diagnostic(LoaderDiagnostic::LastHandoffMarker { attempt })
            .map_err(ExitBootServicesFailure::Diagnostic)?;

        let final_map = firmware
            .capture_final_memory_map()
            .map_err(ExitBootServicesFailure::MemoryMap)?;

        match firmware.exit_boot_services(final_map.key()) {
            Ok(()) => return Ok(BootServicesExited { _private: () }),
            Err(ExitBootServicesError::StaleMemoryMap) if attempt < retry_limit.attempts() => {
                firmware
                    .emit_diagnostic(LoaderDiagnostic::ExitBootServicesRetry {
                        rejected_attempt: attempt,
                    })
                    .map_err(ExitBootServicesFailure::Diagnostic)?;
            }
            Err(ExitBootServicesError::StaleMemoryMap) => {
                return Err(ExitBootServicesFailure::RetryLimitExceeded);
            }
            Err(ExitBootServicesError::Firmware(error)) => {
                return Err(ExitBootServicesFailure::Firmware(error));
            }
        }
    }

    Err(ExitBootServicesFailure::RetryLimitExceeded)
}
