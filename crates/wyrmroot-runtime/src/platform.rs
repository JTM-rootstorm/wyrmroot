//! One platform trait family over the runtime's syscall wrappers.
//!
//! Each method is exactly one runtime wrapper function: same name, same
//! arguments, same result, `&mut self` added. [`NativePlatform`] implements
//! every trait by calling that free function and nothing else, so moving a
//! call site from `wrapper(args)` to `platform.wrapper(args)` changes no
//! behavior. The traits are split by concern so a role names only what it
//! uses:
//!
//! | Trait | Wrappers |
//! |---|---|
//! | [`HandlePlatform`] | handle close/duplicate and the three object queries |
//! | [`ChannelPlatform`] | Channel create, send, receive |
//! | [`WaitPlatform`] | WAIT_ANY, single waits, Events |
//! | [`ClockPlatform`] | the active monotonic clock and Timers |
//! | [`MemoryPlatform`] | MemoryObjects, mappings, bootfs mapping |
//! | [`ProcessPlatform`] | TaskGroups, Process termination, self exit |
//! | [`DevicePlatform`] | ABI discovery, DeviceResource, Interrupt |
//! | [`EvidencePlatform`] | selector-private evidence carriers, per feature |
//!
//! [`Platform`] names the seven production traits together.
//!
//! Every fallible method returns [`NativeError`], which carries the exact
//! kernel [`NativeError::Status`] or the named malformed-output class. The
//! family adds no error type and no numeric code of its own.
//!
//! Two of the runtime's 65 exported lowercase functions are deliberately not
//! methods: [`crate::native_error_code`] is a pure encoding with no syscall,
//! and [`crate::panic_abort`] is the panic-handler policy, which stays in each
//! binary's target-only `#[panic_handler]`.
//!
//! The recording fake that implements the same family for host tests is
//! [`recording::RecordingPlatform`], behind the `platform-recording` feature.

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DwAbiInfoV1, DwDeadline, DwDeviceResourceInfoV1, DwHandle,
    DwHandleTransferV1, DwInterruptInfoV1, DwObjectType, DwReceivedHandleInfoV1, DwRights,
    DwSignals, DwTaskTerminationInfoV1, DwTerminationReason, DwWaitItemV1, DwWaitResultV1,
};

use crate::{
    CapabilityInfo, MappedBootfs, MappingPlan, NativeError, OwnedMemoryMapping, ReceiveCounts,
    StreamSystem,
};

#[cfg(any(test, feature = "platform-recording"))]
pub mod recording;

/// Handle lifetime and fresh object metadata.
pub trait HandlePlatform {
    /// [`crate::close_handle`].
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
    /// [`crate::duplicate_handle`].
    fn duplicate_handle(
        &mut self,
        handle: DwHandle,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError>;
    /// [`crate::query_capability_info`].
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError>;
    /// [`crate::query_memory_object_size`].
    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError>;
    /// [`crate::query_task_termination_info`].
    fn query_task_termination_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, NativeError>;
}

/// Native Channel datagrams.
pub trait ChannelPlatform {
    /// [`crate::create_channel`].
    fn create_channel(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError>;
    /// [`crate::send_channel`].
    fn send_channel(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError>;
    /// [`crate::receive_channel`].
    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError>;
}

/// Signal waits and Events.
pub trait WaitPlatform {
    /// [`crate::wait_many`].
    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError>;
    /// [`crate::wait_one`].
    fn wait_one(
        &mut self,
        handle: DwHandle,
        signals: DwSignals,
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError>;
    /// [`crate::create_event`].
    fn create_event(&mut self, rights: DwRights) -> Result<DwHandle, NativeError>;
    /// [`crate::signal_event`].
    fn signal_event(
        &mut self,
        event: DwHandle,
        clear: DwSignals,
        set: DwSignals,
    ) -> Result<(), NativeError>;
}

/// The active monotonic clock and Timers.
pub trait ClockPlatform {
    /// [`crate::monotonic_active_now`].
    fn monotonic_active_now(&mut self) -> Result<u64, NativeError>;
    /// [`crate::monotonic_deadline_after`].
    fn monotonic_deadline_after(
        &mut self,
        interval_nanoseconds: u64,
    ) -> Result<DwDeadline, NativeError>;
    /// [`crate::create_timer`].
    fn create_timer(&mut self, rights: DwRights) -> Result<DwHandle, NativeError>;
    /// [`crate::set_timer`].
    fn set_timer(&mut self, timer: DwHandle, deadline: DwDeadline) -> Result<(), NativeError>;
    /// [`crate::cancel_timer`].
    fn cancel_timer(&mut self, timer: DwHandle) -> Result<(), NativeError>;
}

/// MemoryObjects, their mappings, and the read-only bootfs mapping.
pub trait MemoryPlatform {
    /// [`crate::create_memory_object`].
    fn create_memory_object(
        &mut self,
        bytes: u64,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError>;
    /// [`crate::map_memory_read_write`].
    fn map_memory_read_write(
        &mut self,
        root: DwHandle,
        memory: DwHandle,
        bytes: u64,
    ) -> Result<OwnedMemoryMapping, NativeError>;
    /// [`crate::map_memory_read_only`].
    fn map_memory_read_only(
        &mut self,
        root: DwHandle,
        memory: DwHandle,
        bytes: u64,
    ) -> Result<OwnedMemoryMapping, NativeError>;
    /// [`crate::unmap_memory`].
    fn unmap_memory(&mut self, mapping: OwnedMemoryMapping) -> Result<(), NativeError>;
    /// [`crate::materialize_read_only_memory`].
    fn materialize_read_only_memory(
        &mut self,
        root: DwHandle,
        source: &[u8],
        child_rights: DwRights,
    ) -> Result<DwHandle, NativeError>;
    /// [`crate::map_bootfs_read_only`].
    fn map_bootfs_read_only(
        &mut self,
        root_region: DwHandle,
        bootfs: DwHandle,
        plan: MappingPlan,
    ) -> Result<MappedBootfs, NativeError>;
    /// [`crate::unmap_bootfs`].
    fn unmap_bootfs(&mut self, mapping: MappedBootfs) -> Result<(), NativeError>;
}

/// TaskGroups, Process termination, and exiting the caller.
pub trait ProcessPlatform {
    /// [`crate::create_task_group`].
    fn create_task_group(
        &mut self,
        parent: DwHandle,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError>;
    /// [`crate::terminate_task_group`].
    fn terminate_task_group(
        &mut self,
        task_group: DwHandle,
        reason: DwTerminationReason,
    ) -> Result<(), NativeError>;
    /// [`crate::terminate_process`].
    fn terminate_process(
        &mut self,
        process: DwHandle,
        reason: DwTerminationReason,
        detail: u32,
    ) -> Result<(), NativeError>;
    /// [`crate::exit_process`].
    fn exit_process(&mut self, exit_code: u32) -> !;
    /// [`crate::exit_thread`].
    fn exit_thread(&mut self, exit_code: u32) -> !;
}

/// ABI discovery, DeviceResource PIO, and Interrupts.
pub trait DevicePlatform {
    /// [`crate::abi_info`].
    fn abi_info(&mut self) -> Result<DwAbiInfoV1, NativeError>;
    /// [`crate::require_device_resource_interrupt_feature`].
    fn require_device_resource_interrupt_feature(&mut self) -> Result<DwAbiInfoV1, NativeError>;
    /// [`crate::claim_device_resource`].
    fn claim_device_resource(
        &mut self,
        resource_domain: DwHandle,
        resource_id: u64,
        requested_rights: DwRights,
    ) -> Result<DwHandle, NativeError>;
    /// [`crate::device_pio_read`].
    fn device_pio_read(
        &mut self,
        resource: DwHandle,
        offset: u32,
        width: u32,
    ) -> Result<u32, NativeError>;
    /// [`crate::device_pio_write`].
    fn device_pio_write(
        &mut self,
        resource: DwHandle,
        offset: u32,
        width: u32,
        value: u32,
    ) -> Result<(), NativeError>;
    /// [`crate::create_interrupt`].
    fn create_interrupt(
        &mut self,
        resource: DwHandle,
        requested_rights: DwRights,
    ) -> Result<DwHandle, NativeError>;
    /// [`crate::interrupt_ack`].
    fn interrupt_ack(&mut self, interrupt: DwHandle) -> Result<(), NativeError>;
    /// [`crate::device_resource_info`].
    fn device_resource_info(
        &mut self,
        resource: DwHandle,
    ) -> Result<DwDeviceResourceInfoV1, NativeError>;
    /// [`crate::interrupt_info`].
    fn interrupt_info(&mut self, interrupt: DwHandle) -> Result<DwInterruptInfoV1, NativeError>;
}

/// The seven production traits together.
pub trait Platform:
    HandlePlatform
    + ChannelPlatform
    + WaitPlatform
    + ClockPlatform
    + MemoryPlatform
    + ProcessPlatform
    + DevicePlatform
{
}

impl<P> Platform for P where
    P: HandlePlatform
        + ChannelPlatform
        + WaitPlatform
        + ClockPlatform
        + MemoryPlatform
        + ProcessPlatform
        + DevicePlatform
        + ?Sized
{
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::NativePlatform {}
    #[cfg(any(test, feature = "platform-recording"))]
    impl Sealed for super::recording::RecordingPlatform {}
}

/// Selector-private evidence carriers.
///
/// Each method exists only while its runtime evidence feature is enabled,
/// exactly like the free function it forwards to. Because the method set
/// depends on features, the trait is sealed: only [`NativePlatform`] and the
/// recording fake implement it, so enabling a feature can never break an
/// implementation elsewhere.
pub trait EvidencePlatform: sealed::Sealed {
    /// [`crate::submit_wyr1_evidence`].
    #[cfg(feature = "wyr1-test-evidence")]
    fn submit_wyr1_evidence(
        &mut self,
        record: &[u8; crate::WYR1_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError>;
    /// [`crate::submit_wyr1b_evidence`].
    #[cfg(feature = "wyr1b-test-evidence")]
    fn submit_wyr1b_evidence(
        &mut self,
        record: &[u8; crate::WYR1B_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError>;
    /// [`crate::submit_wyr1c6_evidence`].
    #[cfg(feature = "wyr1c6-test-evidence")]
    fn submit_wyr1c6_evidence(
        &mut self,
        record: &[u8; crate::WYR1C6_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError>;
    /// [`crate::submit_wyr1d_evidence`].
    #[cfg(feature = "wyr1d-test-evidence")]
    fn submit_wyr1d_evidence(&mut self, record: &[u8; 192]) -> Result<(), NativeError>;
    /// [`crate::announce_wyr1d_ready`].
    #[cfg(feature = "wyr1d-test-evidence")]
    fn announce_wyr1d_ready(&mut self, record: &[u8; 178]) -> Result<(), NativeError>;
    /// [`crate::submit_wyr1e7_evidence`].
    #[cfg(feature = "wyr1e7-test-evidence")]
    fn submit_wyr1e7_evidence(
        &mut self,
        record: &[u8; crate::WYR1E7_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError>;
    /// [`crate::submit_wyr1e8_evidence`].
    #[cfg(feature = "wyr1e8-test-evidence")]
    fn submit_wyr1e8_evidence(
        &mut self,
        record: &[u8; crate::WYR1E8_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError>;
    /// [`crate::submit_r1_evidence`].
    #[cfg(feature = "r1-test-evidence")]
    fn submit_r1_evidence(
        &mut self,
        record: &[u8; crate::R1_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError>;
    /// [`crate::arm_dw1b_preemption`].
    #[cfg(feature = "dw1b-test-evidence")]
    fn arm_dw1b_preemption(
        &mut self,
        hog_process: DwHandle,
        progress_process: DwHandle,
    ) -> Result<(), NativeError>;
    /// [`crate::submit_dw1b_progress`].
    #[cfg(feature = "dw1b-test-evidence")]
    fn submit_dw1b_progress(&mut self, digest: u64) -> Result<(), NativeError>;
    /// [`crate::arm_dw1c_preemption`].
    #[cfg(feature = "dw1c-test-evidence")]
    fn arm_dw1c_preemption(
        &mut self,
        bindings: &[crate::Dw1cActorBindV1; crate::DW1C_ACTOR_COUNT],
        deadline: DwDeadline,
    ) -> Result<(), NativeError>;
    /// [`crate::submit_dw1c_progress`].
    #[cfg(feature = "dw1c-test-evidence")]
    fn submit_dw1c_progress(
        &mut self,
        token: u64,
        count: u64,
        digest: u64,
    ) -> Result<(), NativeError>;
    /// [`crate::submit_dw1c_workload_complete`].
    #[cfg(feature = "dw1c-test-evidence")]
    fn submit_dw1c_workload_complete(&mut self, digest: u64) -> Result<(), NativeError>;
    /// [`crate::await_dw1c_token2_relay_ready`].
    #[cfg(feature = "dw1c-test-evidence")]
    fn await_dw1c_token2_relay_ready(&mut self, deadline: DwDeadline) -> Result<(), NativeError>;
    /// [`crate::d6_arm`].
    #[cfg(feature = "dw1d6-test-evidence")]
    fn d6_arm(
        &mut self,
        owner: DwHandle,
        trigger: DwHandle,
        nonce: u64,
        challenge: u64,
    ) -> Result<(), NativeError>;
    /// [`crate::d6_bind`].
    #[cfg(feature = "dw1d6-test-evidence")]
    fn d6_bind(
        &mut self,
        interrupt: DwHandle,
        lease_generation: u64,
        nonce: u64,
        challenge: u64,
    ) -> Result<(), NativeError>;
    /// [`crate::d6_deliver`].
    #[cfg(feature = "dw1d6-test-evidence")]
    fn d6_deliver(&mut self, sequence: u64, nonce: u64, challenge: u64) -> Result<(), NativeError>;
    /// [`crate::d6_report`].
    #[cfg(feature = "dw1d6-test-evidence")]
    fn d6_report(
        &mut self,
        event: crate::D6ReportEvent,
        value: u64,
        auxiliary: u64,
        nonce: u64,
        challenge: u64,
    ) -> Result<(), NativeError>;
    /// [`crate::dw1e3_build_nonce`].
    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_build_nonce(&mut self) -> Result<u64, NativeError>;
    /// [`crate::dw1e3_challenge_nonce`].
    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_challenge_nonce(&mut self, generation: u64) -> Result<u64, NativeError>;
    /// [`crate::dw1e3_bind_driver`].
    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_bind_driver(
        &mut self,
        interrupt: DwHandle,
        attempt_generation: u64,
        nonce: u64,
    ) -> Result<(), NativeError>;
    /// [`crate::dw1e3_bind_probe`].
    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_bind_probe(&mut self, probe: DwHandle, nonce: u64) -> Result<(), NativeError>;
    /// [`crate::dw1e3_arm_challenge`].
    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_arm_challenge(
        &mut self,
        stream_generation: u64,
        challenge_generation: u64,
        expected_length: u64,
        expected_fnv1a64: u64,
        nonce: u64,
    ) -> Result<(), NativeError>;
    /// [`crate::dw1e3_report`].
    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_report(
        &mut self,
        event: crate::Dw1e3ReportEvent,
        value: u64,
        auxiliary: u64,
        nonce: u64,
    ) -> Result<(), NativeError>;
    /// [`crate::dw1e3_terminal_claim`].
    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_terminal_claim(&mut self, nonce: u64) -> Result<(), NativeError>;
}

/// Any Channel, handle, and wait platform is a [`StreamSystem`] with an
/// infinite endpoint wait.
///
/// This is the stream adapter every native role wrote by hand: receive and
/// send without transfers on the Channel, close the handle, and wait on one
/// endpoint with no deadline, returning the full observed signal snapshot. A
/// role that needs a finite stream wait wraps its platform in a type of its
/// own instead.
impl<P> StreamSystem for P
where
    P: ChannelPlatform + HandlePlatform + WaitPlatform + ?Sized,
{
    fn receive(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        ChannelPlatform::receive_channel(self, channel, bytes, handles)
    }

    fn send(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        ChannelPlatform::send_channel(self, channel, bytes, &[])
    }

    fn close(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        HandlePlatform::close_handle(self, handle)
    }

    fn wait(&mut self, channel: DwHandle, signals: DwSignals) -> Result<DwSignals, NativeError> {
        WaitPlatform::wait_one(self, channel, signals, DW_DEADLINE_INFINITE)
            .map(|result| result.observed)
    }
}

/// The production platform: every method is the runtime free function of the
/// same name.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativePlatform;

impl HandlePlatform for NativePlatform {
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        crate::close_handle(handle)
    }

    fn duplicate_handle(
        &mut self,
        handle: DwHandle,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        crate::duplicate_handle(handle, rights)
    }

    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        crate::query_capability_info(handle)
    }

    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError> {
        crate::query_memory_object_size(handle)
    }

    fn query_task_termination_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, NativeError> {
        crate::query_task_termination_info(handle)
    }
}

impl ChannelPlatform for NativePlatform {
    fn create_channel(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
        crate::create_channel(rights)
    }

    fn send_channel(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError> {
        crate::send_channel(channel, bytes, transfers)
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        crate::receive_channel(channel, bytes, handles)
    }
}

impl WaitPlatform for NativePlatform {
    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        crate::wait_many(items, deadline)
    }

    fn wait_one(
        &mut self,
        handle: DwHandle,
        signals: DwSignals,
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        crate::wait_one(handle, signals, deadline)
    }

    fn create_event(&mut self, rights: DwRights) -> Result<DwHandle, NativeError> {
        crate::create_event(rights)
    }

    fn signal_event(
        &mut self,
        event: DwHandle,
        clear: DwSignals,
        set: DwSignals,
    ) -> Result<(), NativeError> {
        crate::signal_event(event, clear, set)
    }
}

impl ClockPlatform for NativePlatform {
    fn monotonic_active_now(&mut self) -> Result<u64, NativeError> {
        crate::monotonic_active_now()
    }

    fn monotonic_deadline_after(
        &mut self,
        interval_nanoseconds: u64,
    ) -> Result<DwDeadline, NativeError> {
        crate::monotonic_deadline_after(interval_nanoseconds)
    }

    fn create_timer(&mut self, rights: DwRights) -> Result<DwHandle, NativeError> {
        crate::create_timer(rights)
    }

    fn set_timer(&mut self, timer: DwHandle, deadline: DwDeadline) -> Result<(), NativeError> {
        crate::set_timer(timer, deadline)
    }

    fn cancel_timer(&mut self, timer: DwHandle) -> Result<(), NativeError> {
        crate::cancel_timer(timer)
    }
}

impl MemoryPlatform for NativePlatform {
    fn create_memory_object(
        &mut self,
        bytes: u64,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        crate::create_memory_object(bytes, rights)
    }

    fn map_memory_read_write(
        &mut self,
        root: DwHandle,
        memory: DwHandle,
        bytes: u64,
    ) -> Result<OwnedMemoryMapping, NativeError> {
        crate::map_memory_read_write(root, memory, bytes)
    }

    fn map_memory_read_only(
        &mut self,
        root: DwHandle,
        memory: DwHandle,
        bytes: u64,
    ) -> Result<OwnedMemoryMapping, NativeError> {
        crate::map_memory_read_only(root, memory, bytes)
    }

    fn unmap_memory(&mut self, mapping: OwnedMemoryMapping) -> Result<(), NativeError> {
        crate::unmap_memory(mapping)
    }

    fn materialize_read_only_memory(
        &mut self,
        root: DwHandle,
        source: &[u8],
        child_rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        crate::materialize_read_only_memory(root, source, child_rights)
    }

    fn map_bootfs_read_only(
        &mut self,
        root_region: DwHandle,
        bootfs: DwHandle,
        plan: MappingPlan,
    ) -> Result<MappedBootfs, NativeError> {
        crate::map_bootfs_read_only(root_region, bootfs, plan)
    }

    fn unmap_bootfs(&mut self, mapping: MappedBootfs) -> Result<(), NativeError> {
        crate::unmap_bootfs(mapping)
    }
}

impl ProcessPlatform for NativePlatform {
    fn create_task_group(
        &mut self,
        parent: DwHandle,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        crate::create_task_group(parent, rights)
    }

    fn terminate_task_group(
        &mut self,
        task_group: DwHandle,
        reason: DwTerminationReason,
    ) -> Result<(), NativeError> {
        crate::terminate_task_group(task_group, reason)
    }

    fn terminate_process(
        &mut self,
        process: DwHandle,
        reason: DwTerminationReason,
        detail: u32,
    ) -> Result<(), NativeError> {
        crate::terminate_process(process, reason, detail)
    }

    fn exit_process(&mut self, exit_code: u32) -> ! {
        crate::exit_process(exit_code)
    }

    fn exit_thread(&mut self, exit_code: u32) -> ! {
        crate::exit_thread(exit_code)
    }
}

impl DevicePlatform for NativePlatform {
    fn abi_info(&mut self) -> Result<DwAbiInfoV1, NativeError> {
        crate::abi_info()
    }

    fn require_device_resource_interrupt_feature(&mut self) -> Result<DwAbiInfoV1, NativeError> {
        crate::require_device_resource_interrupt_feature()
    }

    fn claim_device_resource(
        &mut self,
        resource_domain: DwHandle,
        resource_id: u64,
        requested_rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        crate::claim_device_resource(resource_domain, resource_id, requested_rights)
    }

    fn device_pio_read(
        &mut self,
        resource: DwHandle,
        offset: u32,
        width: u32,
    ) -> Result<u32, NativeError> {
        crate::device_pio_read(resource, offset, width)
    }

    fn device_pio_write(
        &mut self,
        resource: DwHandle,
        offset: u32,
        width: u32,
        value: u32,
    ) -> Result<(), NativeError> {
        crate::device_pio_write(resource, offset, width, value)
    }

    fn create_interrupt(
        &mut self,
        resource: DwHandle,
        requested_rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        crate::create_interrupt(resource, requested_rights)
    }

    fn interrupt_ack(&mut self, interrupt: DwHandle) -> Result<(), NativeError> {
        crate::interrupt_ack(interrupt)
    }

    fn device_resource_info(
        &mut self,
        resource: DwHandle,
    ) -> Result<DwDeviceResourceInfoV1, NativeError> {
        crate::device_resource_info(resource)
    }

    fn interrupt_info(&mut self, interrupt: DwHandle) -> Result<DwInterruptInfoV1, NativeError> {
        crate::interrupt_info(interrupt)
    }
}

impl EvidencePlatform for NativePlatform {
    #[cfg(feature = "wyr1-test-evidence")]
    fn submit_wyr1_evidence(
        &mut self,
        record: &[u8; crate::WYR1_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError> {
        crate::submit_wyr1_evidence(record)
    }

    #[cfg(feature = "wyr1b-test-evidence")]
    fn submit_wyr1b_evidence(
        &mut self,
        record: &[u8; crate::WYR1B_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError> {
        crate::submit_wyr1b_evidence(record)
    }

    #[cfg(feature = "wyr1c6-test-evidence")]
    fn submit_wyr1c6_evidence(
        &mut self,
        record: &[u8; crate::WYR1C6_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError> {
        crate::submit_wyr1c6_evidence(record)
    }

    #[cfg(feature = "wyr1d-test-evidence")]
    fn submit_wyr1d_evidence(&mut self, record: &[u8; 192]) -> Result<(), NativeError> {
        crate::submit_wyr1d_evidence(record)
    }

    #[cfg(feature = "wyr1d-test-evidence")]
    fn announce_wyr1d_ready(&mut self, record: &[u8; 178]) -> Result<(), NativeError> {
        crate::announce_wyr1d_ready(record)
    }

    #[cfg(feature = "wyr1e7-test-evidence")]
    fn submit_wyr1e7_evidence(
        &mut self,
        record: &[u8; crate::WYR1E7_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError> {
        crate::submit_wyr1e7_evidence(record)
    }

    #[cfg(feature = "wyr1e8-test-evidence")]
    fn submit_wyr1e8_evidence(
        &mut self,
        record: &[u8; crate::WYR1E8_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError> {
        crate::submit_wyr1e8_evidence(record)
    }

    #[cfg(feature = "r1-test-evidence")]
    fn submit_r1_evidence(
        &mut self,
        record: &[u8; crate::R1_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError> {
        crate::submit_r1_evidence(record)
    }

    #[cfg(feature = "dw1b-test-evidence")]
    fn arm_dw1b_preemption(
        &mut self,
        hog_process: DwHandle,
        progress_process: DwHandle,
    ) -> Result<(), NativeError> {
        crate::arm_dw1b_preemption(hog_process, progress_process)
    }

    #[cfg(feature = "dw1b-test-evidence")]
    fn submit_dw1b_progress(&mut self, digest: u64) -> Result<(), NativeError> {
        crate::submit_dw1b_progress(digest)
    }

    #[cfg(feature = "dw1c-test-evidence")]
    fn arm_dw1c_preemption(
        &mut self,
        bindings: &[crate::Dw1cActorBindV1; crate::DW1C_ACTOR_COUNT],
        deadline: DwDeadline,
    ) -> Result<(), NativeError> {
        crate::arm_dw1c_preemption(bindings, deadline)
    }

    #[cfg(feature = "dw1c-test-evidence")]
    fn submit_dw1c_progress(
        &mut self,
        token: u64,
        count: u64,
        digest: u64,
    ) -> Result<(), NativeError> {
        crate::submit_dw1c_progress(token, count, digest)
    }

    #[cfg(feature = "dw1c-test-evidence")]
    fn submit_dw1c_workload_complete(&mut self, digest: u64) -> Result<(), NativeError> {
        crate::submit_dw1c_workload_complete(digest)
    }

    #[cfg(feature = "dw1c-test-evidence")]
    fn await_dw1c_token2_relay_ready(&mut self, deadline: DwDeadline) -> Result<(), NativeError> {
        crate::await_dw1c_token2_relay_ready(deadline)
    }

    #[cfg(feature = "dw1d6-test-evidence")]
    fn d6_arm(
        &mut self,
        owner: DwHandle,
        trigger: DwHandle,
        nonce: u64,
        challenge: u64,
    ) -> Result<(), NativeError> {
        crate::d6_arm(owner, trigger, nonce, challenge)
    }

    #[cfg(feature = "dw1d6-test-evidence")]
    fn d6_bind(
        &mut self,
        interrupt: DwHandle,
        lease_generation: u64,
        nonce: u64,
        challenge: u64,
    ) -> Result<(), NativeError> {
        crate::d6_bind(interrupt, lease_generation, nonce, challenge)
    }

    #[cfg(feature = "dw1d6-test-evidence")]
    fn d6_deliver(&mut self, sequence: u64, nonce: u64, challenge: u64) -> Result<(), NativeError> {
        crate::d6_deliver(sequence, nonce, challenge)
    }

    #[cfg(feature = "dw1d6-test-evidence")]
    fn d6_report(
        &mut self,
        event: crate::D6ReportEvent,
        value: u64,
        auxiliary: u64,
        nonce: u64,
        challenge: u64,
    ) -> Result<(), NativeError> {
        crate::d6_report(event, value, auxiliary, nonce, challenge)
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_build_nonce(&mut self) -> Result<u64, NativeError> {
        crate::dw1e3_build_nonce()
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_challenge_nonce(&mut self, generation: u64) -> Result<u64, NativeError> {
        crate::dw1e3_challenge_nonce(generation)
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_bind_driver(
        &mut self,
        interrupt: DwHandle,
        attempt_generation: u64,
        nonce: u64,
    ) -> Result<(), NativeError> {
        crate::dw1e3_bind_driver(interrupt, attempt_generation, nonce)
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_bind_probe(&mut self, probe: DwHandle, nonce: u64) -> Result<(), NativeError> {
        crate::dw1e3_bind_probe(probe, nonce)
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_arm_challenge(
        &mut self,
        stream_generation: u64,
        challenge_generation: u64,
        expected_length: u64,
        expected_fnv1a64: u64,
        nonce: u64,
    ) -> Result<(), NativeError> {
        crate::dw1e3_arm_challenge(
            stream_generation,
            challenge_generation,
            expected_length,
            expected_fnv1a64,
            nonce,
        )
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_report(
        &mut self,
        event: crate::Dw1e3ReportEvent,
        value: u64,
        auxiliary: u64,
        nonce: u64,
    ) -> Result<(), NativeError> {
        crate::dw1e3_report(event, value, auxiliary, nonce)
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_terminal_claim(&mut self, nonce: u64) -> Result<(), NativeError> {
        crate::dw1e3_terminal_claim(nonce)
    }
}
