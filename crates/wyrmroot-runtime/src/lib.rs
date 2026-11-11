//! Allocation-free native startup, bootstrap validation, and syscall support.
//!
//! All native calls and ABI records come from the exact pinned Deepwyrm consumer package. This
//! crate adds only safe Wyrmroot policy: bounded startup parsing, exact metadata validation,
//! read-only bootfs mapping, native status preservation, and deterministic exit behavior.

#![no_std]
#![deny(unsafe_code)]
#![deny(unused_crate_dependencies)]

#[cfg(any(test, feature = "platform-recording"))]
extern crate std;

mod bootstrap;
mod bounded_accounting;
#[allow(
    unsafe_code,
    reason = "WYR0-I safe capability wrappers confine mapped-slice and generated raw-call boundaries"
)]
mod capability_native;
mod device;
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
pub mod platform;
pub mod sha256;
mod startup;
mod stream;
mod supervision;

pub use bootstrap::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityExpectation, CapabilityInfo,
    CapabilityValidationError, InitCapability, LOADER_TASK_GROUP_EXPECTATION,
    MAX_BOOTFS_LOGICAL_SIZE, MappingPlan, MappingPlanError, PAGE_SIZE,
    RESOURCE_DOMAIN_TASK_GROUP_EXPECTATION, SELF_ROOT_EXPECTATION, validate_bootstrap_channel,
    validate_init_capabilities, validate_init_capabilities_v2, validate_init_capabilities_v3,
};
pub use bounded_accounting::{
    AccountedResource, AccountingError, EnforcementClass, GenerationRetirement,
    GenericContainmentGap, MAX_ACCOUNTED_PEERS, MAX_LIVE_TRANSACTIONS_PER_PEER,
    MAX_REPLAY_ENTRIES_PER_PEER, ReadinessAccounting, ReservationRequest, ReservationState,
    ReservationToken, ResourceBudget, TransactionToken, WYR0_I_RESOURCE_BUDGETS,
    kernel_channel_enforcement, validate_kernel_channel_envelope,
};
pub use capability_native::{
    OwnedMemoryMapping, create_channel, create_task_group, create_timer, duplicate_handle,
    limit_task_group, materialize_read_only_memory, set_timer, terminate_process,
    terminate_task_group, wait_one, with_private_memory,
};
pub(crate) use capability_native::{
    cancel_timer, create_event, create_memory_object, map_memory_read_only, map_memory_read_write,
    signal_event, unmap_memory,
};
pub(crate) use device::abi_info;
pub use device::{
    claim_device_resource, create_interrupt, device_mmio_object_create, device_pci_command,
    device_pci_config_read, device_pio_read, device_pio_write, device_resource_info, dma_map,
    dma_unmap, interrupt_ack, interrupt_info, require_device_resource_interrupt_feature,
};
pub use loader_native::{LOADER_ABORT_CODE, NativeLoaderPlatform};
pub(crate) use native::exit_thread;
pub use native::{
    MappedBootfs, NativeError, NativeOutputError, PANIC_EXIT_CODE, ReceiveCounts, close_handle,
    exit_process, map_bootfs_read_only, monotonic_active_now, monotonic_deadline_after,
    native_error_code, panic_abort, query_capability_info, query_memory_object_size,
    query_task_termination_info, receive_channel, send_channel, unmap_bootfs, wait_many,
};
pub use platform::{
    ChannelPlatform, ClockPlatform, DevicePlatform, EvidencePlatform, HandlePlatform,
    MemoryPlatform, NativePlatform, Platform, ProcessPlatform, WaitPlatform,
};
pub use startup::{
    AUXILIARY_VECTOR_TERMINATOR, BootstrapChannelHandle, STARTUP_ABI_V1, STARTUP_ABI_V2,
    STARTUP_BLOCK_SIZE, STARTUP_BLOCK_V2_SIZE, StartupBlock, StartupError, StartupRegisters,
    StartupString, startup_error_exit_code, with_native_startup,
};
pub use stream::{
    INPUT_WAIT_SIGNALS, JOB_V2_STREAM_RIGHTS, JobV2Streams, NativeInput, NativeOutput,
    OUTPUT_WAIT_SIGNALS, StreamEndpoint, StreamError, StreamSystem, extract_job_v2_streams,
};
pub use supervision::{
    AttemptFailure, AttemptRecord, CleanupAction, CleanupDisposition, ExitObservedReadinessError,
    ExitValidationError, NativeSupervisionPlatform, ObservedSupervisionError, RestartHistory,
    RestartState, RestartSupervisor, RestartTransitionError, SupervisionError, SupervisionPlatform,
    SupervisionPolicy, TerminalDisposition, WYR0_I_SUPERVISION_POLICY,
    await_child_ready_profile_observed, supervise_child, supervise_ready_child_profile,
    validate_successful_exit,
};
