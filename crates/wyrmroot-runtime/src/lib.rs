//! Allocation-free native startup, bootstrap validation, and syscall support.
//!
//! All native calls and ABI records come from the exact pinned Deepwyrm consumer package. This
//! crate adds only safe Wyrmroot policy: bounded startup parsing, exact metadata validation,
//! read-only bootfs mapping, native status preservation, and deterministic exit behavior.

#![no_std]
#![deny(unsafe_code)]
#![deny(unused_crate_dependencies)]

mod bootstrap;
mod diagnostics;
mod entry;
#[allow(
    unsafe_code,
    reason = "the WYR0 loader adapter confines one validated temporary writable mapping to a non-escaping slice"
)]
mod loader_native;
#[cfg(target_os = "wyrmroot")]
mod memory;
mod native;
mod startup;
#[cfg(feature = "primordial-test-support")]
#[allow(
    unsafe_code,
    reason = "explicitly selected primordial kernel-test variants own their isolated generated-veneer and terminal-fault boundaries"
)]
mod test_support;

pub use bootstrap::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityExpectation, CapabilityInfo,
    CapabilityValidationError, InitCapability, MAX_BOOTFS_LOGICAL_SIZE, MappingPlan,
    MappingPlanError, PAGE_SIZE, SELF_ROOT_EXPECTATION, validate_bootstrap_channel,
    validate_init_capabilities,
};
pub use loader_native::NativeLoaderPlatform;
pub use native::{
    MappedBootfs, NativeError, NativeOutputError, PANIC_EXIT_CODE, ReceiveCounts, close_handle,
    exit_process, exit_thread, map_bootfs_read_only, panic_abort, query_capability_info,
    query_memory_object_size, receive_channel, send_channel, unmap_bootfs,
};
pub use startup::{
    AUXILIARY_VECTOR_TERMINATOR, BootstrapChannelHandle, STARTUP_ABI_V1, STARTUP_BLOCK_SIZE,
    StartupBlock, StartupError, StartupRegisters, StartupString, with_native_startup,
};
#[cfg(feature = "primordial-test-support")]
pub use test_support::{
    PrimordialTestError, primordial_blocking_cleanup, trigger_invalid_syscall_return,
    trigger_user_exception,
};
