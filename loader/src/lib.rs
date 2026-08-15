//! Host-testable policy and transition logic for the Wyrmroot EFI loader.
//!
//! The loader executes under x86_64 UEFI firmware, not on the Gentoo build host
//! and not inside Wyrmroot. This crate therefore remains `no_std`. Its pure
//! WYR0-B components are host tested, but those tests neither exercise real
//! firmware nor prove that a UEFI image can boot.
//!
//! Firmware adapters, the PE/COFF application entry, BootInfo construction,
//! transition mappings, and the raw kernel transfer remain explicit boundaries
//! rather than being hidden inside parser code.

#![no_std]
#![forbid(unsafe_code)]

pub mod artifacts;
pub mod boot_info;
pub mod config;
pub mod diagnostics;
pub mod entry;
pub mod firmware;
pub mod kernel_elf;
pub mod memory_map;
pub mod modules;
pub mod transition;

/// Canonical Deepwyrm definitions consumed by the UEFI loader boundary.
///
/// Re-exporting the generated types keeps the loader from maintaining a
/// parallel copy of the kernel ABI while WYR0-B remains unimplemented.
pub mod abi {
    pub use deepwyrm_abi::{DW_ABI_VERSION, DW_BOOT_INFO_V1_SIZE, DwBootInfoV1};
}

/// The execution environment for the future loader artifact.
///
/// WYR0-A keeps this as an explicit boundary so host-side validation cannot be
/// mistaken for a host-executed loader implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoaderExecutionEnvironment {
    /// A 64-bit UEFI firmware application.
    X86_64Uefi,
}

/// The phase-A contract for a loader build profile.
///
/// This is descriptive metadata, not a substitute for the centralized target
/// and linker configuration owned by WYR0 tooling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoaderBuildProfile {
    /// The environment in which the finished loader will execute.
    pub execution_environment: LoaderExecutionEnvironment,
    /// Whether production loader code may rely on a host operating system.
    pub permits_host_os_services: bool,
    /// Whether the finished loader runs after Deepwyrm userspace is available.
    pub permits_wyrmroot_runtime: bool,
    /// Whether host tests may validate this boundary without firmware access.
    pub permits_host_validation: bool,
}

/// The only WYR0-A loader profile.
///
/// A host test harness may link this `no_std` library for validation, but the
/// production loader itself has neither host OS services nor a Wyrmroot runtime
/// available. Firmware/artifact/BootInfo behavior remains deliberately absent.
pub const WYR0_A_UEFI_LOADER_PROFILE: LoaderBuildProfile = LoaderBuildProfile {
    execution_environment: LoaderExecutionEnvironment::X86_64Uefi,
    permits_host_os_services: false,
    permits_wyrmroot_runtime: false,
    permits_host_validation: true,
};
