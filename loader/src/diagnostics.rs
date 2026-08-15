//! Loader-stage diagnostics that remain valid before UEFI boot services exit.
//!
//! These structured markers deliberately avoid a text or serial transport. The
//! UEFI backend owns that transport; the state machine owns when a marker may be
//! emitted. In particular, no marker may be emitted after final memory-map
//! capture and before `ExitBootServices()`.

/// A pre-`ExitBootServices()` loader diagnostic marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoaderDiagnostic {
    /// The 64-bit UEFI loader boundary has started.
    Entry,
    /// The loader is about to acquire the final UEFI memory map.
    FinalMemoryMapAttempt {
        /// One-based attempt number.
        attempt: u8,
    },
    /// Last marker before the final-map/boot-services-exit critical section.
    ///
    /// This is intentionally emitted *before* memory-map capture. Firmware
    /// diagnostic output can itself allocate, which would otherwise invalidate
    /// the map key used by `ExitBootServices()`.
    LastHandoffMarker {
        /// One-based attempt number.
        attempt: u8,
    },
    /// A stale memory-map key requires a fresh acquisition and retry.
    ExitBootServicesRetry {
        /// The attempt whose map key was rejected.
        rejected_attempt: u8,
    },
}
