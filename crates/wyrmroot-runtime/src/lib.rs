//! Allocation-free native startup, bootstrap validation, and syscall support.
//!
//! All native calls and ABI records come from the exact pinned Deepwyrm consumer package. This
//! crate adds only safe Wyrmroot policy: bounded startup parsing, exact metadata validation,
//! read-only bootfs mapping, native status preservation, and deterministic exit behavior.

#![no_std]
#![deny(unsafe_code)]
#![deny(unused_crate_dependencies)]

mod bootstrap;
mod bounded_accounting;
#[allow(
    unsafe_code,
    reason = "WYR0-I safe capability wrappers confine mapped-slice and generated raw-call boundaries"
)]
mod capability_native;
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
pub mod sha256;
mod startup;
mod supervision;
#[cfg(feature = "primordial-test-support")]
#[allow(
    unsafe_code,
    reason = "explicitly selected primordial kernel-test variants own their isolated generated-veneer and terminal-fault boundaries"
)]
mod test_support;

pub use bootstrap::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityExpectation, CapabilityInfo,
    CapabilityValidationError, InitCapability, LOADER_TASK_GROUP_EXPECTATION,
    MAX_BOOTFS_LOGICAL_SIZE, MappingPlan, MappingPlanError, PAGE_SIZE, SELF_ROOT_EXPECTATION,
    validate_bootstrap_channel, validate_init_capabilities, validate_init_capabilities_v2,
};
pub use bounded_accounting::{
    AccountedResource, AccountingError, EnforcementClass, GenerationRetirement,
    GenericContainmentGap, MAX_ACCOUNTED_PEERS, MAX_LIVE_TRANSACTIONS_PER_PEER,
    MAX_REPLAY_ENTRIES_PER_PEER, ReadinessAccounting, ReservationRequest, ReservationState,
    ReservationToken, ResourceBudget, TransactionToken, WYR0_I_RESOURCE_BUDGETS,
    kernel_channel_enforcement, validate_kernel_channel_envelope,
};
#[cfg(feature = "dw1c-test-evidence")]
pub use capability_native::{
    DW1C_ACTOR_COUNT, Dw1cActorBindV1, arm_dw1c_preemption, submit_dw1c_progress,
    submit_dw1c_workload_complete,
};
pub use capability_native::{
    OwnedMemoryMapping, cancel_timer, create_channel, create_event, create_memory_object,
    create_task_group, create_timer, duplicate_handle, map_memory_read_only, map_memory_read_write,
    set_timer, signal_event, terminate_process, terminate_task_group, unmap_memory, wait_one,
};
#[cfg(feature = "wyr1-test-evidence")]
pub use capability_native::{WYR1_EVIDENCE_RECORD_BYTES, submit_wyr1_evidence};
#[cfg(feature = "wyr1b-test-evidence")]
pub use capability_native::{WYR1B_EVIDENCE_RECORD_BYTES, submit_wyr1b_evidence};
#[cfg(feature = "dw1b-test-evidence")]
pub use capability_native::{arm_dw1b_preemption, submit_dw1b_progress};
pub use loader_native::{LOADER_ABORT_CODE, NativeLoaderPlatform};
pub use native::{
    MappedBootfs, NativeError, NativeOutputError, PANIC_EXIT_CODE, ReceiveCounts, close_handle,
    exit_process, exit_thread, map_bootfs_read_only, monotonic_active_now,
    monotonic_deadline_after, native_error_code, panic_abort, query_capability_info,
    query_memory_object_size, query_task_termination_info, receive_channel, send_channel,
    unmap_bootfs, wait_many,
};
pub use startup::{
    AUXILIARY_VECTOR_TERMINATOR, BootstrapChannelHandle, STARTUP_ABI_V1, STARTUP_ABI_V2,
    STARTUP_BLOCK_SIZE, STARTUP_BLOCK_V2_SIZE, StartupBlock, StartupError, StartupRegisters,
    StartupString, startup_error_exit_code, with_native_startup,
};
pub use supervision::{
    AttemptFailure, AttemptRecord, CleanupAction, CleanupDisposition, ExitObservedReadinessError,
    ExitValidationError, NativeSupervisionPlatform, ObservedSupervisionError, RestartHistory,
    RestartState, RestartSupervisor, RestartTransitionError, SupervisionError, SupervisionPlatform,
    SupervisionPolicy, TerminalDisposition, WYR0_I_SUPERVISION_POLICY, await_child_ready_profile,
    await_child_ready_profile_observed, supervise_child, supervise_child_profile,
    supervise_native_child, supervise_native_child_profile, supervise_ready_child_profile,
    validate_successful_exit,
};
#[cfg(feature = "primordial-test-support")]
pub use test_support::{
    PrimordialTestError, primordial_blocking_cleanup, trigger_invalid_syscall_return,
    trigger_user_exception,
};
