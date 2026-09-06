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
mod device;
mod diagnostics;
#[cfg(feature = "dw1d6-test-evidence")]
#[allow(
    unsafe_code,
    reason = "selector-30 confines generated DW1-D calls and one private carrier to a test-only facade"
)]
mod dw1d6;
#[cfg(feature = "dw1e3-test-evidence")]
#[allow(
    unsafe_code,
    reason = "selector-31 confines one private six-word evidence carrier to a test-only facade"
)]
mod dw1e3;
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
mod stream;
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
#[cfg(feature = "dw1c-test-evidence")]
pub use capability_native::{
    DW1C_ACTOR_COUNT, Dw1cActorBindV1, arm_dw1c_preemption, await_dw1c_token2_relay_ready,
    submit_dw1c_progress, submit_dw1c_workload_complete,
};
pub use capability_native::{
    OwnedMemoryMapping, cancel_timer, create_channel, create_event, create_memory_object,
    create_task_group, create_timer, duplicate_handle, map_memory_read_only, map_memory_read_write,
    materialize_read_only_memory, set_timer, signal_event, terminate_process, terminate_task_group,
    unmap_memory, wait_one,
};
#[cfg(feature = "wyr1-test-evidence")]
pub use capability_native::{WYR1_EVIDENCE_RECORD_BYTES, submit_wyr1_evidence};
#[cfg(feature = "wyr1b-test-evidence")]
pub use capability_native::{WYR1B_EVIDENCE_RECORD_BYTES, submit_wyr1b_evidence};
#[cfg(feature = "wyr1c6-test-evidence")]
pub use capability_native::{WYR1C6_EVIDENCE_RECORD_BYTES, submit_wyr1c6_evidence};
#[cfg(feature = "wyr1e7-test-evidence")]
pub use capability_native::{WYR1E7_EVIDENCE_RECORD_BYTES, submit_wyr1e7_evidence};
#[cfg(feature = "wyr1e8-test-evidence")]
pub use capability_native::{WYR1E8_EVIDENCE_RECORD_BYTES, submit_wyr1e8_evidence};
#[cfg(feature = "wyr1d-test-evidence")]
pub use capability_native::{announce_wyr1d_ready, submit_wyr1d_evidence};
#[cfg(feature = "dw1b-test-evidence")]
pub use capability_native::{arm_dw1b_preemption, submit_dw1b_progress};
pub use device::{
    abi_info, claim_device_resource, create_interrupt, device_pio_read, device_pio_write,
    device_resource_info, interrupt_ack, interrupt_info, require_device_resource_interrupt_feature,
};
#[cfg(feature = "dw1d6-test-evidence")]
pub use dw1d6::{D6ReportEvent, d6_arm, d6_bind, d6_deliver, d6_report};
#[cfg(feature = "dw1e3-test-evidence")]
pub use dw1e3::{
    Dw1e3ReportEvent, dw1e3_arm_challenge, dw1e3_bind_driver, dw1e3_bind_probe, dw1e3_build_nonce,
    dw1e3_challenge_nonce, dw1e3_report, dw1e3_terminal_claim,
};
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
pub use stream::{
    INPUT_WAIT_SIGNALS, JOB_V2_STREAM_RIGHTS, JobV2Streams, NativeInput, NativeOutput,
    OUTPUT_WAIT_SIGNALS, StreamEndpoint, StreamError, StreamSystem, extract_job_v2_streams,
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
