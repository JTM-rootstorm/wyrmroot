//! A recording, scripted implementation of the platform family for host tests.
//!
//! [`RecordingPlatform`] appends one [`Call`] per method, in order, and answers
//! each fallible method with the next [`Reply`] from one ordered script. A
//! reply of the wrong kind, or an empty script, panics with the call that was
//! being answered: a test that scripts `[channel send, close]` fails loudly if
//! the code under test closes first. Nothing here performs a syscall.
//!
//! Enable it from another crate's tests with
//! `wyrmroot-runtime = { ..., features = ["platform-recording"] }` under
//! `[dev-dependencies]`. The feature links `std` and refuses the guest target.
//!
//! Two kernel-minted tokens have limits here:
//! - [`crate::OwnedMemoryMapping`] is minted only by a real mapping, so the
//!   `map_memory_*` methods can be scripted to fail
//!   ([`Reply::MappingFailure`]) but not to succeed.
//! - [`crate::MappedBootfs`] is answered from a caller-owned `'static` byte
//!   slice ([`Reply::Bootfs`]), whose length must equal the plan's logical
//!   size. The token then views exactly those bytes.

#[cfg(target_os = "wyrmroot")]
compile_error!("platform-recording is host test support; it must never reach a guest build");

use std::collections::VecDeque;
use std::vec::Vec;

use deepwyrm_syscall::{
    DwAbiInfoV1, DwDeadline, DwDeviceResourceInfoV1, DwHandle, DwHandleTransferV1,
    DwInterruptInfoV1, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwSignals,
    DwTaskTerminationInfoV1, DwTerminationReason, DwWaitItemV1, DwWaitResultV1,
};

use super::{
    ChannelPlatform, ClockPlatform, DevicePlatform, EvidencePlatform, HandlePlatform,
    MemoryPlatform, ProcessPlatform, WaitPlatform,
};
use crate::{
    CapabilityInfo, MappedBootfs, MappingPlan, NativeError, OwnedMemoryMapping, ReceiveCounts,
};

/// One recorded platform call, with its arguments copied out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Call {
    CloseHandle {
        handle: DwHandle,
    },
    DuplicateHandle {
        handle: DwHandle,
        rights: DwRights,
    },
    QueryCapabilityInfo {
        handle: DwHandle,
    },
    QueryMemoryObjectSize {
        handle: DwHandle,
    },
    QueryTaskTerminationInfo {
        handle: DwHandle,
    },
    CreateChannel {
        rights: DwRights,
    },
    SendChannel {
        channel: DwHandle,
        bytes: Vec<u8>,
        transfers: Vec<DwHandleTransferV1>,
    },
    /// The capacities of the caller's buffers, not their contents.
    ReceiveChannel {
        channel: DwHandle,
        byte_capacity: usize,
        handle_capacity: usize,
    },
    WaitMany {
        items: Vec<DwWaitItemV1>,
        deadline: DwDeadline,
    },
    WaitOne {
        handle: DwHandle,
        signals: DwSignals,
        deadline: DwDeadline,
    },
    CreateEvent {
        rights: DwRights,
    },
    SignalEvent {
        event: DwHandle,
        clear: DwSignals,
        set: DwSignals,
    },
    MonotonicActiveNow,
    MonotonicDeadlineAfter {
        interval_nanoseconds: u64,
    },
    CreateTimer {
        rights: DwRights,
    },
    SetTimer {
        timer: DwHandle,
        deadline: DwDeadline,
    },
    CancelTimer {
        timer: DwHandle,
    },
    CreateMemoryObject {
        bytes: u64,
        rights: DwRights,
    },
    MapMemoryReadWrite {
        root: DwHandle,
        memory: DwHandle,
        bytes: u64,
    },
    MapMemoryReadOnly {
        root: DwHandle,
        memory: DwHandle,
        bytes: u64,
    },
    UnmapMemory {
        root: DwHandle,
        bytes: u64,
    },
    MaterializeReadOnlyMemory {
        root: DwHandle,
        source: Vec<u8>,
        child_rights: DwRights,
    },
    MapBootfsReadOnly {
        root_region: DwHandle,
        bootfs: DwHandle,
        plan: MappingPlan,
    },
    UnmapBootfs {
        root_region: DwHandle,
        logical_size: u64,
        mapped_size: u64,
    },
    CreateTaskGroup {
        parent: DwHandle,
        rights: DwRights,
    },
    TerminateTaskGroup {
        task_group: DwHandle,
        reason: DwTerminationReason,
    },
    TerminateProcess {
        process: DwHandle,
        reason: DwTerminationReason,
        detail: u32,
    },
    ExitProcess {
        exit_code: u32,
    },
    ExitThread {
        exit_code: u32,
    },
    AbiInfo,
    RequireDeviceResourceInterruptFeature,
    ClaimDeviceResource {
        resource_domain: DwHandle,
        resource_id: u64,
        requested_rights: DwRights,
    },
    DevicePioRead {
        resource: DwHandle,
        offset: u32,
        width: u32,
    },
    DevicePioWrite {
        resource: DwHandle,
        offset: u32,
        width: u32,
        value: u32,
    },
    CreateInterrupt {
        resource: DwHandle,
        requested_rights: DwRights,
    },
    InterruptAck {
        interrupt: DwHandle,
    },
    DeviceResourceInfo {
        resource: DwHandle,
    },
    InterruptInfo {
        interrupt: DwHandle,
    },
    #[cfg(feature = "wyr1-test-evidence")]
    SubmitWyr1Evidence {
        record: Vec<u8>,
    },
    #[cfg(feature = "wyr1b-test-evidence")]
    SubmitWyr1bEvidence {
        record: Vec<u8>,
    },
    #[cfg(feature = "wyr1c6-test-evidence")]
    SubmitWyr1c6Evidence {
        record: Vec<u8>,
    },
    #[cfg(feature = "wyr1d-test-evidence")]
    SubmitWyr1dEvidence {
        record: Vec<u8>,
    },
    #[cfg(feature = "wyr1d-test-evidence")]
    AnnounceWyr1dReady {
        record: Vec<u8>,
    },
    #[cfg(feature = "wyr1e7-test-evidence")]
    SubmitWyr1e7Evidence {
        record: Vec<u8>,
    },
    #[cfg(feature = "wyr1e8-test-evidence")]
    SubmitWyr1e8Evidence {
        record: Vec<u8>,
    },
    #[cfg(feature = "dw1c-test-evidence")]
    ArmDw1cPreemption {
        bindings: [crate::Dw1cActorBindV1; crate::DW1C_ACTOR_COUNT],
        deadline: DwDeadline,
    },
    #[cfg(feature = "dw1c-test-evidence")]
    SubmitDw1cProgress {
        token: u64,
        count: u64,
        digest: u64,
    },
    #[cfg(feature = "dw1c-test-evidence")]
    SubmitDw1cWorkloadComplete {
        digest: u64,
    },
    #[cfg(feature = "dw1c-test-evidence")]
    AwaitDw1cToken2RelayReady {
        deadline: DwDeadline,
    },
    #[cfg(feature = "dw1d6-test-evidence")]
    D6Arm {
        owner: DwHandle,
        trigger: DwHandle,
        nonce: u64,
        challenge: u64,
    },
    #[cfg(feature = "dw1d6-test-evidence")]
    D6Bind {
        interrupt: DwHandle,
        lease_generation: u64,
        nonce: u64,
        challenge: u64,
    },
    #[cfg(feature = "dw1d6-test-evidence")]
    D6Deliver {
        sequence: u64,
        nonce: u64,
        challenge: u64,
    },
    #[cfg(feature = "dw1d6-test-evidence")]
    D6Report {
        event: crate::D6ReportEvent,
        value: u64,
        auxiliary: u64,
        nonce: u64,
        challenge: u64,
    },
    #[cfg(feature = "dw1e3-test-evidence")]
    Dw1e3BuildNonce,
    #[cfg(feature = "dw1e3-test-evidence")]
    Dw1e3ChallengeNonce {
        generation: u64,
    },
    #[cfg(feature = "dw1e3-test-evidence")]
    Dw1e3BindDriver {
        interrupt: DwHandle,
        attempt_generation: u64,
        nonce: u64,
    },
    #[cfg(feature = "dw1e3-test-evidence")]
    Dw1e3BindProbe {
        probe: DwHandle,
        nonce: u64,
    },
    #[cfg(feature = "dw1e3-test-evidence")]
    Dw1e3ArmChallenge {
        stream_generation: u64,
        challenge_generation: u64,
        expected_length: u64,
        expected_fnv1a64: u64,
        nonce: u64,
    },
    #[cfg(feature = "dw1e3-test-evidence")]
    Dw1e3Report {
        event: crate::Dw1e3ReportEvent,
        value: u64,
        auxiliary: u64,
        nonce: u64,
    },
    #[cfg(feature = "dw1e3-test-evidence")]
    Dw1e3TerminalClaim {
        nonce: u64,
    },
}

/// One complete Channel datagram a scripted receive delivers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Datagram {
    pub bytes: Vec<u8>,
    pub handles: Vec<DwReceivedHandleInfoV1>,
}

/// The scripted answer to one fallible call, by result type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reply {
    /// Any method returning `Result<(), NativeError>`.
    Unit(Result<(), NativeError>),
    /// Any method returning one handle.
    Handle(Result<DwHandle, NativeError>),
    /// `create_channel`.
    HandlePair(Result<(DwHandle, DwHandle), NativeError>),
    /// `query_capability_info`.
    CapabilityInfo(Result<CapabilityInfo<DwObjectType, DwRights>, NativeError>),
    /// `query_memory_object_size`, `monotonic_active_now`, and the selector-31
    /// nonce methods.
    Value(Result<u64, NativeError>),
    /// `monotonic_deadline_after`.
    Deadline(Result<DwDeadline, NativeError>),
    /// `query_task_termination_info`.
    TaskTermination(Result<DwTaskTerminationInfoV1, NativeError>),
    /// `receive_channel`. The datagram must fit the caller's buffers.
    Receive(Result<Datagram, NativeError>),
    /// `wait_many` and `wait_one`.
    Wait(Result<DwWaitResultV1, NativeError>),
    /// `map_memory_read_write` and `map_memory_read_only`: failure only.
    MappingFailure(NativeError),
    /// `map_bootfs_read_only`. The slice length must equal the plan's
    /// logical size.
    Bootfs(Result<&'static [u8], NativeError>),
    /// `device_pio_read`.
    Pio(Result<u32, NativeError>),
    /// `abi_info` and `require_device_resource_interrupt_feature`.
    AbiInfo(Result<DwAbiInfoV1, NativeError>),
    /// `device_resource_info`.
    DeviceResourceInfo(Result<DwDeviceResourceInfoV1, NativeError>),
    /// `interrupt_info`.
    InterruptInfo(Result<DwInterruptInfoV1, NativeError>),
}

/// Records every platform call and answers from one ordered script.
#[derive(Debug, Default)]
pub struct RecordingPlatform {
    calls: Vec<Call>,
    script: VecDeque<Reply>,
}

impl RecordingPlatform {
    /// An empty recorder with an empty script.
    pub fn new() -> Self {
        Self::default()
    }

    /// A recorder that answers from `replies`, in order.
    pub fn scripted(replies: impl IntoIterator<Item = Reply>) -> Self {
        Self {
            calls: Vec::new(),
            script: replies.into_iter().collect(),
        }
    }

    /// Appends one reply to the end of the script.
    pub fn push_reply(&mut self, reply: Reply) {
        self.script.push_back(reply);
    }

    /// Every call so far, in order.
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    /// Removes and returns every call so far.
    pub fn take_calls(&mut self) -> Vec<Call> {
        core::mem::take(&mut self.calls)
    }

    /// Replies not yet consumed.
    pub fn remaining_replies(&self) -> usize {
        self.script.len()
    }

    /// Panics unless every scripted reply was consumed.
    pub fn assert_script_consumed(&self) {
        assert!(
            self.script.is_empty(),
            "RecordingPlatform: {} scripted replies unconsumed, next {:?}; calls {:?}",
            self.script.len(),
            self.script.front(),
            self.calls
        );
    }

    fn next(&mut self, call: Call) -> Reply {
        self.calls.push(call);
        let Some(reply) = self.script.pop_front() else {
            panic!(
                "RecordingPlatform: no scripted reply for {:?}",
                self.calls.last()
            );
        };
        reply
    }

    fn mismatch(&self, expected: &str, reply: &Reply) -> ! {
        panic!(
            "RecordingPlatform: {:?} needs a Reply::{expected}, script had {reply:?}",
            self.calls.last()
        )
    }

    fn unit(&mut self, call: Call) -> Result<(), NativeError> {
        let reply = self.next(call);
        let Reply::Unit(result) = reply else {
            self.mismatch("Unit", &reply)
        };
        result
    }

    fn handle(&mut self, call: Call) -> Result<DwHandle, NativeError> {
        let reply = self.next(call);
        let Reply::Handle(result) = reply else {
            self.mismatch("Handle", &reply)
        };
        result
    }

    fn value(&mut self, call: Call) -> Result<u64, NativeError> {
        let reply = self.next(call);
        let Reply::Value(result) = reply else {
            self.mismatch("Value", &reply)
        };
        result
    }

    fn wait(&mut self, call: Call) -> Result<DwWaitResultV1, NativeError> {
        let reply = self.next(call);
        let Reply::Wait(result) = reply else {
            self.mismatch("Wait", &reply)
        };
        result
    }

    fn mapping(&mut self, call: Call) -> Result<OwnedMemoryMapping, NativeError> {
        let reply = self.next(call);
        let Reply::MappingFailure(error) = reply else {
            self.mismatch("MappingFailure", &reply)
        };
        Err(error)
    }

    fn abi_info_reply(&mut self, call: Call) -> Result<DwAbiInfoV1, NativeError> {
        let reply = self.next(call);
        let Reply::AbiInfo(result) = reply else {
            self.mismatch("AbiInfo", &reply)
        };
        result
    }
}

impl HandlePlatform for RecordingPlatform {
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.unit(Call::CloseHandle { handle })
    }

    fn duplicate_handle(
        &mut self,
        handle: DwHandle,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        self.handle(Call::DuplicateHandle { handle, rights })
    }

    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        let reply = self.next(Call::QueryCapabilityInfo { handle });
        let Reply::CapabilityInfo(result) = reply else {
            self.mismatch("CapabilityInfo", &reply)
        };
        result
    }

    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError> {
        self.value(Call::QueryMemoryObjectSize { handle })
    }

    fn query_task_termination_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, NativeError> {
        let reply = self.next(Call::QueryTaskTerminationInfo { handle });
        let Reply::TaskTermination(result) = reply else {
            self.mismatch("TaskTermination", &reply)
        };
        result
    }
}

impl ChannelPlatform for RecordingPlatform {
    fn create_channel(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
        let reply = self.next(Call::CreateChannel { rights });
        let Reply::HandlePair(result) = reply else {
            self.mismatch("HandlePair", &reply)
        };
        result
    }

    fn send_channel(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError> {
        self.unit(Call::SendChannel {
            channel,
            bytes: bytes.to_vec(),
            transfers: transfers.to_vec(),
        })
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        let reply = self.next(Call::ReceiveChannel {
            channel,
            byte_capacity: bytes.len(),
            handle_capacity: handles.len(),
        });
        let Reply::Receive(result) = reply else {
            self.mismatch("Receive", &reply)
        };
        let datagram = result?;
        assert!(
            datagram.bytes.len() <= bytes.len() && datagram.handles.len() <= handles.len(),
            "RecordingPlatform: scripted datagram of {} bytes and {} handles exceeds the \
             caller's {} bytes and {} handles; script the kernel status instead",
            datagram.bytes.len(),
            datagram.handles.len(),
            bytes.len(),
            handles.len()
        );
        bytes[..datagram.bytes.len()].copy_from_slice(&datagram.bytes);
        handles[..datagram.handles.len()].copy_from_slice(&datagram.handles);
        Ok(ReceiveCounts {
            bytes: datagram.bytes.len(),
            handles: datagram.handles.len(),
        })
    }
}

impl WaitPlatform for RecordingPlatform {
    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        self.wait(Call::WaitMany {
            items: items.to_vec(),
            deadline,
        })
    }

    fn wait_one(
        &mut self,
        handle: DwHandle,
        signals: DwSignals,
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        self.wait(Call::WaitOne {
            handle,
            signals,
            deadline,
        })
    }

    fn create_event(&mut self, rights: DwRights) -> Result<DwHandle, NativeError> {
        self.handle(Call::CreateEvent { rights })
    }

    fn signal_event(
        &mut self,
        event: DwHandle,
        clear: DwSignals,
        set: DwSignals,
    ) -> Result<(), NativeError> {
        self.unit(Call::SignalEvent { event, clear, set })
    }
}

impl ClockPlatform for RecordingPlatform {
    fn monotonic_active_now(&mut self) -> Result<u64, NativeError> {
        self.value(Call::MonotonicActiveNow)
    }

    fn monotonic_deadline_after(
        &mut self,
        interval_nanoseconds: u64,
    ) -> Result<DwDeadline, NativeError> {
        let reply = self.next(Call::MonotonicDeadlineAfter {
            interval_nanoseconds,
        });
        let Reply::Deadline(result) = reply else {
            self.mismatch("Deadline", &reply)
        };
        result
    }

    fn create_timer(&mut self, rights: DwRights) -> Result<DwHandle, NativeError> {
        self.handle(Call::CreateTimer { rights })
    }

    fn set_timer(&mut self, timer: DwHandle, deadline: DwDeadline) -> Result<(), NativeError> {
        self.unit(Call::SetTimer { timer, deadline })
    }

    fn cancel_timer(&mut self, timer: DwHandle) -> Result<(), NativeError> {
        self.unit(Call::CancelTimer { timer })
    }
}

impl MemoryPlatform for RecordingPlatform {
    fn create_memory_object(
        &mut self,
        bytes: u64,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        self.handle(Call::CreateMemoryObject { bytes, rights })
    }

    fn map_memory_read_write(
        &mut self,
        root: DwHandle,
        memory: DwHandle,
        bytes: u64,
    ) -> Result<OwnedMemoryMapping, NativeError> {
        self.mapping(Call::MapMemoryReadWrite {
            root,
            memory,
            bytes,
        })
    }

    fn map_memory_read_only(
        &mut self,
        root: DwHandle,
        memory: DwHandle,
        bytes: u64,
    ) -> Result<OwnedMemoryMapping, NativeError> {
        self.mapping(Call::MapMemoryReadOnly {
            root,
            memory,
            bytes,
        })
    }

    fn unmap_memory(&mut self, mapping: OwnedMemoryMapping) -> Result<(), NativeError> {
        let (root, bytes) = mapping.recorded_extent();
        self.unit(Call::UnmapMemory { root, bytes })
    }

    fn materialize_read_only_memory(
        &mut self,
        root: DwHandle,
        source: &[u8],
        child_rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        self.handle(Call::MaterializeReadOnlyMemory {
            root,
            source: source.to_vec(),
            child_rights,
        })
    }

    fn map_bootfs_read_only(
        &mut self,
        root_region: DwHandle,
        bootfs: DwHandle,
        plan: MappingPlan,
    ) -> Result<MappedBootfs, NativeError> {
        let reply = self.next(Call::MapBootfsReadOnly {
            root_region,
            bootfs,
            plan,
        });
        let Reply::Bootfs(result) = reply else {
            self.mismatch("Bootfs", &reply)
        };
        let bytes = result?;
        assert!(
            u64::try_from(bytes.len()).is_ok_and(|length| length == plan.logical_size()),
            "RecordingPlatform: scripted bootfs of {} bytes does not match the plan's logical \
             size {}",
            bytes.len(),
            plan.logical_size()
        );
        Ok(MappedBootfs::recorded(root_region, bytes, plan))
    }

    fn unmap_bootfs(&mut self, mapping: MappedBootfs) -> Result<(), NativeError> {
        self.unit(Call::UnmapBootfs {
            root_region: mapping.recorded_root_region(),
            logical_size: mapping.logical_size(),
            mapped_size: mapping.mapped_size(),
        })
    }
}

impl ProcessPlatform for RecordingPlatform {
    fn create_task_group(
        &mut self,
        parent: DwHandle,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        self.handle(Call::CreateTaskGroup { parent, rights })
    }

    fn terminate_task_group(
        &mut self,
        task_group: DwHandle,
        reason: DwTerminationReason,
    ) -> Result<(), NativeError> {
        self.unit(Call::TerminateTaskGroup { task_group, reason })
    }

    fn terminate_process(
        &mut self,
        process: DwHandle,
        reason: DwTerminationReason,
        detail: u32,
    ) -> Result<(), NativeError> {
        self.unit(Call::TerminateProcess {
            process,
            reason,
            detail,
        })
    }

    /// Records the exit, then panics: a host test observes it with
    /// `catch_unwind` or `#[should_panic]`.
    fn exit_process(&mut self, exit_code: u32) -> ! {
        self.calls.push(Call::ExitProcess { exit_code });
        panic!("RecordingPlatform: exit_process({exit_code:#x})")
    }

    /// Records the exit, then panics, like [`Self::exit_process`].
    fn exit_thread(&mut self, exit_code: u32) -> ! {
        self.calls.push(Call::ExitThread { exit_code });
        panic!("RecordingPlatform: exit_thread({exit_code:#x})")
    }
}

impl DevicePlatform for RecordingPlatform {
    fn abi_info(&mut self) -> Result<DwAbiInfoV1, NativeError> {
        self.abi_info_reply(Call::AbiInfo)
    }

    fn require_device_resource_interrupt_feature(&mut self) -> Result<DwAbiInfoV1, NativeError> {
        self.abi_info_reply(Call::RequireDeviceResourceInterruptFeature)
    }

    fn claim_device_resource(
        &mut self,
        resource_domain: DwHandle,
        resource_id: u64,
        requested_rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        self.handle(Call::ClaimDeviceResource {
            resource_domain,
            resource_id,
            requested_rights,
        })
    }

    fn device_pio_read(
        &mut self,
        resource: DwHandle,
        offset: u32,
        width: u32,
    ) -> Result<u32, NativeError> {
        let reply = self.next(Call::DevicePioRead {
            resource,
            offset,
            width,
        });
        let Reply::Pio(result) = reply else {
            self.mismatch("Pio", &reply)
        };
        result
    }

    fn device_pio_write(
        &mut self,
        resource: DwHandle,
        offset: u32,
        width: u32,
        value: u32,
    ) -> Result<(), NativeError> {
        self.unit(Call::DevicePioWrite {
            resource,
            offset,
            width,
            value,
        })
    }

    fn create_interrupt(
        &mut self,
        resource: DwHandle,
        requested_rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        self.handle(Call::CreateInterrupt {
            resource,
            requested_rights,
        })
    }

    fn interrupt_ack(&mut self, interrupt: DwHandle) -> Result<(), NativeError> {
        self.unit(Call::InterruptAck { interrupt })
    }

    fn device_resource_info(
        &mut self,
        resource: DwHandle,
    ) -> Result<DwDeviceResourceInfoV1, NativeError> {
        let reply = self.next(Call::DeviceResourceInfo { resource });
        let Reply::DeviceResourceInfo(result) = reply else {
            self.mismatch("DeviceResourceInfo", &reply)
        };
        result
    }

    fn interrupt_info(&mut self, interrupt: DwHandle) -> Result<DwInterruptInfoV1, NativeError> {
        let reply = self.next(Call::InterruptInfo { interrupt });
        let Reply::InterruptInfo(result) = reply else {
            self.mismatch("InterruptInfo", &reply)
        };
        result
    }
}

impl EvidencePlatform for RecordingPlatform {
    #[cfg(feature = "wyr1-test-evidence")]
    fn submit_wyr1_evidence(
        &mut self,
        record: &[u8; crate::WYR1_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError> {
        self.unit(Call::SubmitWyr1Evidence {
            record: record.to_vec(),
        })
    }

    #[cfg(feature = "wyr1b-test-evidence")]
    fn submit_wyr1b_evidence(
        &mut self,
        record: &[u8; crate::WYR1B_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError> {
        self.unit(Call::SubmitWyr1bEvidence {
            record: record.to_vec(),
        })
    }

    #[cfg(feature = "wyr1c6-test-evidence")]
    fn submit_wyr1c6_evidence(
        &mut self,
        record: &[u8; crate::WYR1C6_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError> {
        self.unit(Call::SubmitWyr1c6Evidence {
            record: record.to_vec(),
        })
    }

    #[cfg(feature = "wyr1d-test-evidence")]
    fn submit_wyr1d_evidence(&mut self, record: &[u8; 192]) -> Result<(), NativeError> {
        self.unit(Call::SubmitWyr1dEvidence {
            record: record.to_vec(),
        })
    }

    #[cfg(feature = "wyr1d-test-evidence")]
    fn announce_wyr1d_ready(&mut self, record: &[u8; 178]) -> Result<(), NativeError> {
        self.unit(Call::AnnounceWyr1dReady {
            record: record.to_vec(),
        })
    }

    #[cfg(feature = "wyr1e7-test-evidence")]
    fn submit_wyr1e7_evidence(
        &mut self,
        record: &[u8; crate::WYR1E7_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError> {
        self.unit(Call::SubmitWyr1e7Evidence {
            record: record.to_vec(),
        })
    }

    #[cfg(feature = "wyr1e8-test-evidence")]
    fn submit_wyr1e8_evidence(
        &mut self,
        record: &[u8; crate::WYR1E8_EVIDENCE_RECORD_BYTES],
    ) -> Result<(), NativeError> {
        self.unit(Call::SubmitWyr1e8Evidence {
            record: record.to_vec(),
        })
    }

    #[cfg(feature = "dw1c-test-evidence")]
    fn arm_dw1c_preemption(
        &mut self,
        bindings: &[crate::Dw1cActorBindV1; crate::DW1C_ACTOR_COUNT],
        deadline: DwDeadline,
    ) -> Result<(), NativeError> {
        self.unit(Call::ArmDw1cPreemption {
            bindings: *bindings,
            deadline,
        })
    }

    #[cfg(feature = "dw1c-test-evidence")]
    fn submit_dw1c_progress(
        &mut self,
        token: u64,
        count: u64,
        digest: u64,
    ) -> Result<(), NativeError> {
        self.unit(Call::SubmitDw1cProgress {
            token,
            count,
            digest,
        })
    }

    #[cfg(feature = "dw1c-test-evidence")]
    fn submit_dw1c_workload_complete(&mut self, digest: u64) -> Result<(), NativeError> {
        self.unit(Call::SubmitDw1cWorkloadComplete { digest })
    }

    #[cfg(feature = "dw1c-test-evidence")]
    fn await_dw1c_token2_relay_ready(&mut self, deadline: DwDeadline) -> Result<(), NativeError> {
        self.unit(Call::AwaitDw1cToken2RelayReady { deadline })
    }

    #[cfg(feature = "dw1d6-test-evidence")]
    fn d6_arm(
        &mut self,
        owner: DwHandle,
        trigger: DwHandle,
        nonce: u64,
        challenge: u64,
    ) -> Result<(), NativeError> {
        self.unit(Call::D6Arm {
            owner,
            trigger,
            nonce,
            challenge,
        })
    }

    #[cfg(feature = "dw1d6-test-evidence")]
    fn d6_bind(
        &mut self,
        interrupt: DwHandle,
        lease_generation: u64,
        nonce: u64,
        challenge: u64,
    ) -> Result<(), NativeError> {
        self.unit(Call::D6Bind {
            interrupt,
            lease_generation,
            nonce,
            challenge,
        })
    }

    #[cfg(feature = "dw1d6-test-evidence")]
    fn d6_deliver(&mut self, sequence: u64, nonce: u64, challenge: u64) -> Result<(), NativeError> {
        self.unit(Call::D6Deliver {
            sequence,
            nonce,
            challenge,
        })
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
        self.unit(Call::D6Report {
            event,
            value,
            auxiliary,
            nonce,
            challenge,
        })
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_build_nonce(&mut self) -> Result<u64, NativeError> {
        self.value(Call::Dw1e3BuildNonce)
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_challenge_nonce(&mut self, generation: u64) -> Result<u64, NativeError> {
        self.value(Call::Dw1e3ChallengeNonce { generation })
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_bind_driver(
        &mut self,
        interrupt: DwHandle,
        attempt_generation: u64,
        nonce: u64,
    ) -> Result<(), NativeError> {
        self.unit(Call::Dw1e3BindDriver {
            interrupt,
            attempt_generation,
            nonce,
        })
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_bind_probe(&mut self, probe: DwHandle, nonce: u64) -> Result<(), NativeError> {
        self.unit(Call::Dw1e3BindProbe { probe, nonce })
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
        self.unit(Call::Dw1e3ArmChallenge {
            stream_generation,
            challenge_generation,
            expected_length,
            expected_fnv1a64,
            nonce,
        })
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_report(
        &mut self,
        event: crate::Dw1e3ReportEvent,
        value: u64,
        auxiliary: u64,
        nonce: u64,
    ) -> Result<(), NativeError> {
        self.unit(Call::Dw1e3Report {
            event,
            value,
            auxiliary,
            nonce,
        })
    }

    #[cfg(feature = "dw1e3-test-evidence")]
    fn dw1e3_terminal_claim(&mut self, nonce: u64) -> Result<(), NativeError> {
        self.unit(Call::Dw1e3TerminalClaim { nonce })
    }
}

#[cfg(test)]
mod tests {
    use deepwyrm_syscall::{
        DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_READ, DW_SIGNAL_PEER_CLOSED,
        DW_SIGNAL_READABLE, DW_STATUS_PEER_CLOSED, DW_STATUS_TIMED_OUT,
    };

    use super::*;
    use crate::{NativeInput, StreamEndpoint, StreamError, StreamSystem};

    #[test]
    fn calls_are_recorded_in_order_and_answered_from_the_script() {
        let mut platform = RecordingPlatform::scripted([
            Reply::Unit(Ok(())),
            Reply::Unit(Err(NativeError::Status(DW_STATUS_PEER_CLOSED))),
        ]);
        assert_eq!(
            ChannelPlatform::send_channel(&mut platform, DwHandle(7), b"ab", &[]),
            Ok(())
        );
        assert_eq!(
            HandlePlatform::close_handle(&mut platform, DwHandle(7)),
            Err(NativeError::Status(DW_STATUS_PEER_CLOSED))
        );
        assert_eq!(
            platform.calls(),
            [
                Call::SendChannel {
                    channel: DwHandle(7),
                    bytes: b"ab".to_vec(),
                    transfers: Vec::new(),
                },
                Call::CloseHandle {
                    handle: DwHandle(7)
                },
            ]
        );
        platform.assert_script_consumed();
    }

    #[test]
    #[should_panic(expected = "needs a Reply::Handle")]
    fn a_reply_of_the_wrong_kind_panics() {
        let mut platform = RecordingPlatform::scripted([Reply::Unit(Ok(()))]);
        let _ = HandlePlatform::duplicate_handle(&mut platform, DwHandle(1), DwRights(0));
    }

    #[test]
    #[should_panic(expected = "no scripted reply")]
    fn an_empty_script_panics() {
        let _ = ClockPlatform::monotonic_active_now(&mut RecordingPlatform::new());
    }

    #[test]
    fn a_scripted_receive_fills_the_caller_buffers() {
        let handle = DwReceivedHandleInfoV1 {
            handle: DwHandle(9),
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: DW_RIGHT_READ,
            ..DwReceivedHandleInfoV1::default()
        };
        let mut platform = RecordingPlatform::scripted([Reply::Receive(Ok(Datagram {
            bytes: b"xyz".to_vec(),
            handles: std::vec![handle],
        }))]);
        let mut bytes = [0_u8; 8];
        let mut handles = [DwReceivedHandleInfoV1::default(); 2];
        let counts =
            ChannelPlatform::receive_channel(&mut platform, DwHandle(3), &mut bytes, &mut handles)
                .unwrap();
        assert_eq!(
            counts,
            ReceiveCounts {
                bytes: 3,
                handles: 1
            }
        );
        assert_eq!(&bytes[..3], b"xyz");
        assert_eq!(handles[0], handle);
        assert_eq!(
            platform.calls(),
            [Call::ReceiveChannel {
                channel: DwHandle(3),
                byte_capacity: 8,
                handle_capacity: 2,
            }]
        );
    }

    #[test]
    fn a_scripted_bootfs_mapping_views_exactly_its_bytes() {
        static ARCHIVE: [u8; 5] = *b"WRBF!";
        let plan = MappingPlan::for_bootfs(5).unwrap();
        let mut platform =
            RecordingPlatform::scripted([Reply::Bootfs(Ok(&ARCHIVE)), Reply::Unit(Ok(()))]);
        let mapping =
            MemoryPlatform::map_bootfs_read_only(&mut platform, DwHandle(1), DwHandle(2), plan)
                .unwrap();
        assert_eq!(mapping.with_logical_bytes(<[u8]>::to_vec), b"WRBF!");
        MemoryPlatform::unmap_bootfs(&mut platform, mapping).unwrap();
        assert_eq!(
            platform.calls()[1],
            Call::UnmapBootfs {
                root_region: DwHandle(1),
                logical_size: 5,
                mapped_size: plan.mapped_size(),
            }
        );
    }

    #[test]
    #[should_panic(expected = "does not match the plan's logical size")]
    fn a_short_scripted_bootfs_is_refused() {
        static ARCHIVE: [u8; 4] = *b"WRBF";
        let plan = MappingPlan::for_bootfs(5).unwrap();
        let mut platform = RecordingPlatform::scripted([Reply::Bootfs(Ok(&ARCHIVE))]);
        let _ = MemoryPlatform::map_bootfs_read_only(&mut platform, DwHandle(1), DwHandle(2), plan);
    }

    #[test]
    #[should_panic(expected = "exit_process(0x7)")]
    fn exit_is_recorded_before_it_diverges() {
        let mut platform = RecordingPlatform::new();
        ProcessPlatform::exit_process(&mut platform, 7);
    }

    /// The blanket stream adapter waits on one endpoint with no deadline and
    /// returns the full snapshot, which is what every hand-written native
    /// `StreamSystem` did.
    #[test]
    fn the_stream_adapter_waits_forever_on_one_endpoint() {
        let observed = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
        let mut platform = RecordingPlatform::scripted([Reply::Wait(Ok(DwWaitResultV1 {
            observed,
            ..DwWaitResultV1::default()
        }))]);
        assert_eq!(
            StreamSystem::wait(&mut platform, DwHandle(4), DW_SIGNAL_READABLE),
            Ok(observed)
        );
        assert_eq!(
            platform.calls(),
            [Call::WaitOne {
                handle: DwHandle(4),
                signals: DW_SIGNAL_READABLE,
                deadline: DW_DEADLINE_INFINITE,
            }]
        );
    }

    /// A native status reaches the stream layer unchanged.
    #[test]
    fn a_stream_read_carries_the_kernel_status() {
        let endpoint = StreamEndpoint::from_validated_handle(DwHandle(5)).unwrap();
        let mut input = NativeInput::new(endpoint);
        let mut platform = RecordingPlatform::scripted([Reply::Receive(Err(NativeError::Status(
            DW_STATUS_TIMED_OUT,
        )))]);
        let mut bytes = [0_u8; 4];
        assert_eq!(
            input.read(&mut platform, &mut bytes),
            Err(StreamError::Native(NativeError::Status(
                DW_STATUS_TIMED_OUT
            )))
        );
        platform.assert_script_consumed();
    }
}
