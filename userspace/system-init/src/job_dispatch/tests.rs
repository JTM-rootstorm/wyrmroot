use super::*;
use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_TRANSFER, DW_STATUS_NO_MEMORY,
    DW_STATUS_NO_RESOURCES, DW_TERMINATION_NORMAL_EXIT,
};
use wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS;

/// F3A.6n. `ErrorCode::Capacity` was unreachable from the case it names,
/// and `loader-failure` was the answer to a full machine.
#[test]
fn a_kernel_exhaustion_is_capacity_and_only_the_loader_is_a_loader_failure() {
    use deepwyrm_syscall::DwStatus;

    // The two kernel exhaustion statuses reach the code that describes
    // them, on both launch paths.
    for status in [DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES] {
        let error = InitError::Native(NativeError::Status(status));
        assert_eq!(launch_error_code(&error), LaunchErrorCode::Capacity);
        assert_eq!(shell_launch_error_code(&error), LaunchErrorCode::Capacity);
    }

    // Any other native failure is not capacity. An output-contract fault
    // is our own ABI handling, not the machine's limits.
    let other = InitError::Native(NativeError::Status(DwStatus(-5)));
    assert_eq!(launch_error_code(&other), LaunchErrorCode::LoaderFailure);
    let output = InitError::Native(NativeError::Output(
        wyrmroot_runtime::NativeOutputError::InvalidChannelReceive,
    ));
    assert_eq!(launch_error_code(&output), LaunchErrorCode::LoaderFailure);

    // A malformed ELF keeps `loader-failure`, because `tools/e7_vm.py`
    // pins exactly that answer for `run test/wyr1-e/malformed-elf`.
    assert_eq!(
        launch_error_code(&InitError::Loader(
            wyrmroot_loader::process::LoadError::Elf(wyrmroot_loader::elf::ElfError::BadMagic)
        )),
        LaunchErrorCode::LoaderFailure
    );

    // But an exhaustion inside a platform stage of the same load is
    // capacity, which is where this actually bites: the kernel's cause is
    // nested in `LoadError::Platform`, not in a bare `InitError::Native`.
    assert_eq!(
        launch_error_code(&InitError::Loader(
            wyrmroot_loader::process::LoadError::Platform {
                stage: wyrmroot_loader::process::LoadStage::ChannelCreate,
                cause: NativeError::Status(DW_STATUS_NO_RESOURCES),
                rollback_failed: false,
            }
        )),
        LaunchErrorCode::Capacity
    );

    // And the shell path no longer defaults to claiming the loader failed.
    // An unclassified error says the request was refused, which claims
    // nothing about where the fault was.
    assert_eq!(
        shell_launch_error_code(&InitError::WrongActivationOrder),
        LaunchErrorCode::PolicyRejected
    );
    assert_ne!(
        shell_launch_error_code(&InitError::WrongActivationOrder),
        LaunchErrorCode::LoaderFailure
    );

    // The shell job table filling up is still its own code, unchanged:
    // that is what `Capacity` already meant and it must not be confused
    // with the kernel's exhaustion above.
    assert_eq!(
        shell_launch_error_code(&InitError::Jobs(JobError::Capacity)),
        LaunchErrorCode::Capacity
    );
}
extern crate alloc;

use crate::job_sessions::LaunchSessionScope;
use alloc::{vec, vec::Vec};
use deepwyrm_syscall::{DwMemoryProtection, DwStatus, DwWaitResultV1};

use wyrmroot_loader::process::{ParentMapping, ProcessCreateRequest, ProcessCreateResult};

const FAILURE: NativeError = NativeError::Status(DwStatus(-1));

struct MockPlatform {
    sent: [u8; 256],
    sent_len: usize,
    transfer: DwHandleTransferV1,
    fresh_rights: DwRights,
    queried: [DwHandle; 4],
    query_count: usize,
    created_rights: DwRights,
    closed: [DwHandle; 8],
    close_count: usize,
    fail_close: Option<DwHandle>,
    now: Option<u64>,
    terminate_count: usize,
    fail_terminate: bool,
    allow_wait: bool,
    session_poll_timeout: bool,
    task_group: Option<DwHandle>,
    fail_send: bool,
    inbound: [u8; 256],
    inbound_len: usize,
    inbound_handles: [DwReceivedHandleInfoV1; 16],
    inbound_handle_count: usize,
    bootfs: Option<Vec<u8>>,
    session_poll_readable: bool,
    /// Reports the session's peer as gone, for R6C's cancel edge.
    session_poll_peer_closed: bool,
    /// What R6C's parked-launch poll should see, when a test has a parked
    /// launch at all.
    ///
    /// A poll of a parked child is the only wait on this platform that asks
    /// for `EXITED`, so it is distinguishable from the session poll without
    /// the mock having to know which handle is which. `None` means the test
    /// has no opinion and the child poll answers the same way the session
    /// poll does, which is what every test written before R6C expects.
    child_poll_readable: Option<bool>,
    /// The signals the last parked-child poll asked about, for R6D.
    child_poll_signals: Vec<u64>,
    /// The deadline of every platform wait, in order, for R6D.
    wait_deadlines: Vec<u64>,
    /// Which session Channel the last reply went to, so a test with two
    /// launch clients can say which one was answered.
    last_sent_channel: Option<DwHandle>,
}

impl MockPlatform {
    fn new() -> Self {
        Self {
            sent: [0; 256],
            sent_len: 0,
            transfer: DwHandleTransferV1::default(),
            fresh_rights: CONTROLLER_CHANNEL_RIGHTS,
            queried: [DwHandle(0); 4],
            query_count: 0,
            created_rights: DwRights(0),
            closed: [DwHandle(0); 8],
            close_count: 0,
            fail_close: None,
            now: None,
            terminate_count: 0,
            fail_terminate: false,
            allow_wait: false,
            session_poll_timeout: false,
            task_group: None,
            fail_send: true,
            inbound: [0; 256],
            inbound_len: 0,
            inbound_handles: [DwReceivedHandleInfoV1::default(); 16],
            inbound_handle_count: 0,
            bootfs: None,
            session_poll_readable: false,
            session_poll_peer_closed: false,
            child_poll_readable: None,
            child_poll_signals: Vec::new(),
            wait_deadlines: Vec::new(),
            last_sent_channel: None,
        }
    }
}

struct InitSendLoader {
    next: u64,
    closed: [DwHandle; 32],
    close_count: usize,
    transferred_service: Option<DwHandle>,
    sent_init: Vec<u8>,
    sent_transfers: Vec<DwHandleTransferV1>,
    fail_init: bool,
}

impl InitSendLoader {
    const fn new() -> Self {
        Self {
            next: 0x1000,
            closed: [DwHandle(0); 32],
            close_count: 0,
            transferred_service: None,
            sent_init: Vec::new(),
            sent_transfers: Vec::new(),
            fail_init: true,
        }
    }

    fn handle(&mut self) -> DwHandle {
        let handle = DwHandle(self.next);
        self.next += 1;
        handle
    }
}

impl LoaderPlatform for InitSendLoader {
    type Error = NativeError;

    fn channel_create(&mut self, _rights: DwRights) -> Result<(DwHandle, DwHandle), Self::Error> {
        Ok((self.handle(), self.handle()))
    }

    fn duplicate(&mut self, _handle: DwHandle, _rights: DwRights) -> Result<DwHandle, Self::Error> {
        Ok(self.handle())
    }

    fn close(&mut self, handle: DwHandle) -> Result<(), Self::Error> {
        self.closed[self.close_count] = handle;
        self.close_count += 1;
        Ok(())
    }

    fn process_create(
        &mut self,
        _request: ProcessCreateRequest,
    ) -> Result<ProcessCreateResult, Self::Error> {
        Ok(ProcessCreateResult {
            process: self.handle(),
            root: self.handle(),
            child_bootstrap: self.handle(),
        })
    }

    fn memory_create(&mut self, _bytes: u64, _rights: DwRights) -> Result<DwHandle, Self::Error> {
        Ok(self.handle())
    }

    fn materialize_parent(
        &mut self,
        _parent_root: DwHandle,
        memory: DwHandle,
        object_size: u64,
        _destination_offset: u64,
        _source: &[u8],
    ) -> Result<ParentMapping, Self::Error> {
        Ok(ParentMapping {
            address: 0x6000_0000 + memory.0 * 0x10_0000,
            bytes: object_size,
        })
    }

    fn materialize_parent_with(
        &mut self,
        _parent_root: DwHandle,
        memory: DwHandle,
        object_size: u64,
        _destination_offset: u64,
        destination_size: usize,
        materialize: impl FnOnce(&mut [u8]),
    ) -> Result<ParentMapping, Self::Error> {
        let mut destination = vec![0; destination_size];
        materialize(&mut destination);
        Ok(ParentMapping {
            address: 0x6000_0000 + memory.0 * 0x10_0000,
            bytes: object_size,
        })
    }

    fn unmap_parent(
        &mut self,
        _parent_root: DwHandle,
        _mapping: ParentMapping,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn map_child(
        &mut self,
        _child_root: DwHandle,
        _memory: DwHandle,
        _address: u64,
        _bytes: u64,
        _protection: DwMemoryProtection,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn unmap_child(
        &mut self,
        _child_root: DwHandle,
        _address: u64,
        _bytes: u64,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn thread_create(
        &mut self,
        _process: DwHandle,
        _rights: DwRights,
    ) -> Result<DwHandle, Self::Error> {
        Ok(self.handle())
    }

    fn send_init(
        &mut self,
        _channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), Self::Error> {
        self.transferred_service = transfers.last().map(|transfer| transfer.handle);
        self.sent_init = bytes.to_vec();
        self.sent_transfers = transfers.to_vec();
        if self.fail_init { Err(FAILURE) } else { Ok(()) }
    }

    fn thread_start(
        &mut self,
        _thread: DwHandle,
        _entry: u64,
        _stack_pointer: u64,
        _child_bootstrap: DwHandle,
        _startup_abi: u64,
    ) -> Result<(), Self::Error> {
        if self.fail_init {
            panic!("failed INIT must prevent thread start")
        }
        Ok(())
    }

    fn thread_terminate(&mut self, _thread: DwHandle) -> Result<(), Self::Error> {
        Ok(())
    }

    fn process_terminate(&mut self, _process: DwHandle) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn executable() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x2000];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&0x1000_u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[88..96].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&16_u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&32_u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&4096_u64.to_le_bytes());
    bytes
}

impl InitPlatform for MockPlatform {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        self.queried[self.query_count] = handle;
        self.query_count += 1;
        Ok(CapabilityInfo {
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: self.fresh_rights,
        })
    }
    fn receive_channel(
        &mut self,
        _channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        if self.inbound_len == 0 {
            return Err(FAILURE);
        }
        if self.inbound_len > bytes.len() || self.inbound_handle_count > handles.len() {
            return Err(FAILURE);
        }
        bytes[..self.inbound_len].copy_from_slice(&self.inbound[..self.inbound_len]);
        handles[..self.inbound_handle_count]
            .copy_from_slice(&self.inbound_handles[..self.inbound_handle_count]);
        let bytes = self.inbound_len;
        let handles = self.inbound_handle_count;
        self.inbound_len = 0;
        self.inbound_handle_count = 0;
        Ok(ReceiveCounts { bytes, handles })
    }
    fn query_memory_object_size(&mut self, _handle: DwHandle) -> Result<u64, NativeError> {
        self.bootfs
            .as_ref()
            .map(|bootfs| bootfs.len() as u64)
            .ok_or(FAILURE)
    }
    fn with_bootfs_bytes<R>(
        &mut self,
        _root: DwHandle,
        _bootfs: DwHandle,
        _plan: MappingPlan,
        use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
    ) -> Result<R, NativeError> {
        let bootfs = self.bootfs.take().ok_or(FAILURE)?;
        let result = use_bytes(self, &bootfs);
        self.bootfs = Some(bootfs);
        Ok(result)
    }
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        if self.fail_send {
            return Err(FAILURE);
        }
        self.sent[..bytes.len()].copy_from_slice(bytes);
        self.sent_len = bytes.len();
        self.last_sent_channel = Some(channel);
        Ok(())
    }
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.closed[self.close_count] = handle;
        self.close_count += 1;
        if self.fail_close == Some(handle) {
            Err(FAILURE)
        } else {
            Ok(())
        }
    }
    fn create_attempt_task_group(&mut self, _parent: DwHandle) -> Result<DwHandle, NativeError> {
        self.task_group.ok_or(FAILURE)
    }
    fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
        self.terminate_count += 1;
        if self.fail_terminate {
            Err(FAILURE)
        } else {
            Ok(())
        }
    }
    fn now(&mut self) -> Result<u64, NativeError> {
        self.now.ok_or(FAILURE)
    }
    fn wait_until(&mut self, deadline_ns: u64) -> Result<(), NativeError> {
        if self.allow_wait {
            self.now = Some(deadline_ns);
            Ok(())
        } else {
            Err(FAILURE)
        }
    }
}

struct TerminalWaits;

impl SupervisionPlatform for TerminalWaits {
    type Error = NativeError;

    fn wait_many(
        &mut self,
        _items: &[DwWaitItemV1],
        _deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, Self::Error> {
        Err(FAILURE)
    }

    fn receive_channel(
        &mut self,
        _channel: DwHandle,
        _bytes: &mut [u8],
        _handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, Self::Error> {
        Err(FAILURE)
    }

    fn query_task_termination(
        &mut self,
        _process: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
        Ok(DwTaskTerminationInfoV1 {
            state: DW_TASK_STATE_EXITED,
            reason: DW_TERMINATION_NORMAL_EXIT,
            ..DwTaskTerminationInfoV1::default()
        })
    }
}

impl ResidentPlatform for MockPlatform {
    fn channel_create(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
        self.created_rights = rights;
        Ok((DwHandle(20), DwHandle(21)))
    }
    fn send_channel_with_handles(
        &mut self,
        _channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError> {
        assert_eq!(transfers.len(), 1);
        self.sent[..bytes.len()].copy_from_slice(bytes);
        self.sent_len = bytes.len();
        self.transfer = transfers[0];
        Ok(())
    }
    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        self.wait_deadlines.push(deadline.0);
        let child_poll = items
            .iter()
            .any(|item| item.signals.0 & DW_SIGNAL_EXITED.0 != 0);
        if child_poll {
            self.child_poll_signals = items.iter().map(|item| item.signals.0).collect();
        }
        if let (true, Some(readable)) = (child_poll, self.child_poll_readable) {
            return if readable {
                Ok(DwWaitResultV1 {
                    index: 0,
                    observed: DW_SIGNAL_READABLE,
                    ..DwWaitResultV1::default()
                })
            } else {
                Err(NativeError::Status(DW_STATUS_TIMED_OUT))
            };
        }
        if self.session_poll_peer_closed {
            Ok(DwWaitResultV1 {
                index: 0,
                observed: DW_SIGNAL_PEER_CLOSED,
                ..DwWaitResultV1::default()
            })
        } else if self.session_poll_readable {
            Ok(DwWaitResultV1 {
                index: 0,
                observed: DW_SIGNAL_READABLE,
                ..DwWaitResultV1::default()
            })
        } else if self.session_poll_timeout {
            Err(NativeError::Status(DW_STATUS_TIMED_OUT))
        } else {
            Err(FAILURE)
        }
    }

    fn materialize_read_only_memory(
        &mut self,
        _root: DwHandle,
        _bytes: &[u8],
        _rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        Ok(DwHandle(0x7fff))
    }
}

fn grant(kind: EndpointKind, endpoint_id: u64, role_generation: u64) -> EndpointGrant {
    EndpointGrant {
        registry_generation: 7,
        endpoint_id,
        endpoint_generation: 3,
        role_generation,
        kind,
    }
}

fn reservation(transaction_id: u64) -> LaunchReservation {
    LaunchReservation {
        connection_id: 1,
        generation: 3,
        transaction_id,
    }
}

#[test]
fn console_shell_v1_admission_cleans_handles_and_stops_at_e3c_boundary() {
    let mut platform = MockPlatform::new();
    platform.fail_send = false;
    let mut waits = TerminalWaits;
    let mut loader = InitSendLoader::new();
    let mut jobs = JobDispatcher::new();
    let owner = grant(EndpointKind::LaunchSession, 1, 1);
    jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
        .unwrap();
    let authority = LoadAuthority {
        parent_root: DwHandle(1),
        bootfs: DwHandle(2),
        task_group: DwHandle(3),
    };
    let request = wyrmroot_launch_proto::ShellV1Request {
        console_generation: 2,
        status_generation: 3,
        requested_child_generation: 4,
    };

    platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
        reservation(1),
        request,
        &mut platform.inbound,
    )
    .unwrap();
    platform.inbound_handle_count = 4;
    for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
        info.handle = DwHandle(41 + index as u64);
    }
    assert_eq!(
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        ),
        Ok(JobDispatchOutcome::Responded)
    );
    assert_eq!(
        platform.closed[..4],
        [DwHandle(44), DwHandle(43), DwHandle(42), DwHandle(41)]
    );
    assert_eq!(
        platform.queried,
        [DwHandle(41), DwHandle(42), DwHandle(43), DwHandle(44)]
    );
    assert_eq!(platform.query_count, 4);
    assert_eq!(
        CONTROLLER_CHANNEL_RIGHTS.0 & deepwyrm_syscall::DW_RIGHT_DUPLICATE.0,
        0
    );
    assert_eq!(
        wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
            .unwrap()
            .reply,
        wyrmroot_launch_proto::ShellV1Reply::Error {
            code: LaunchErrorCode::LoaderFailure,
        }
    );
    assert_eq!(jobs.jobs.live_jobs(), 0);

    platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
        reservation(1),
        request,
        &mut platform.inbound,
    )
    .unwrap();
    platform.inbound_handle_count = 4;
    for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
        info.handle = DwHandle(51 + index as u64);
    }
    dispatch_one_job_request(
        &mut platform,
        &mut loader,
        &mut waits,
        authority,
        None,
        &mut jobs,
        DwHandle(90),
        owner,
    )
    .unwrap();
    assert_eq!(
        platform.closed[4..8],
        [DwHandle(54), DwHandle(53), DwHandle(52), DwHandle(51)]
    );
    assert_eq!(
        wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
            .unwrap()
            .reply,
        wyrmroot_launch_proto::ShellV1Reply::Error {
            code: LaunchErrorCode::TransactionReplay,
        }
    );
}

#[test]
fn e3c_shell_identity_namespaces_are_independently_fresh() {
    let mut state = ShellControllerState::new(1).unwrap();
    state
        .reserve_shell_generation(wyrmroot_launch_proto::ShellV1Request {
            console_generation: 2,
            status_generation: 3,
            requested_child_generation: 4,
        })
        .unwrap();
    assert_eq!(
        state.reserve_shell_generation(wyrmroot_launch_proto::ShellV1Request {
            console_generation: 3,
            status_generation: 3,
            requested_child_generation: 5,
        }),
        Err(InitError::Jobs(JobError::StaleGeneration))
    );
    assert_eq!(
        state.reserve_shell_generation(wyrmroot_launch_proto::ShellV1Request {
            console_generation: 3,
            status_generation: 4,
            requested_child_generation: 4,
        }),
        Err(InitError::Jobs(JobError::StaleGeneration))
    );
    state
        .reserve_shell_generation(wyrmroot_launch_proto::ShellV1Request {
            console_generation: 2,
            status_generation: 4,
            requested_child_generation: 5,
        })
        .unwrap();
}

#[test]
fn malformed_shell_v1_is_cleaned_and_its_fresh_transaction_replays() {
    let mut platform = MockPlatform::new();
    platform.fail_send = false;
    let mut waits = TerminalWaits;
    let mut loader = InitSendLoader::new();
    let mut jobs = JobDispatcher::new();
    let owner = grant(EndpointKind::LaunchSession, 1, 1);
    jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
        .unwrap();
    let authority = LoadAuthority {
        parent_root: DwHandle(1),
        bootfs: DwHandle(2),
        task_group: DwHandle(3),
    };
    let request = wyrmroot_launch_proto::ShellV1Request {
        console_generation: 2,
        status_generation: 3,
        requested_child_generation: 4,
    };
    platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
        reservation(1),
        request,
        &mut platform.inbound,
    )
    .unwrap();
    platform.inbound[112] ^= 1;
    platform.inbound_handle_count = 4;
    for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
        info.handle = DwHandle(41 + index as u64);
    }
    dispatch_one_job_request(
        &mut platform,
        &mut loader,
        &mut waits,
        authority,
        None,
        &mut jobs,
        DwHandle(90),
        owner,
    )
    .unwrap();
    assert_eq!(
        wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
            .unwrap()
            .reply,
        wyrmroot_launch_proto::ShellV1Reply::Error {
            code: LaunchErrorCode::MalformedRequest,
        }
    );
    assert_eq!(platform.close_count, 4);
    assert_eq!(platform.query_count, 0);

    platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
        reservation(1),
        request,
        &mut platform.inbound,
    )
    .unwrap();
    platform.inbound_handle_count = 4;
    for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
        info.handle = DwHandle(51 + index as u64);
    }
    dispatch_one_job_request(
        &mut platform,
        &mut loader,
        &mut waits,
        authority,
        None,
        &mut jobs,
        DwHandle(90),
        owner,
    )
    .unwrap();
    assert_eq!(
        wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
            .unwrap()
            .reply,
        wyrmroot_launch_proto::ShellV1Reply::Error {
            code: LaunchErrorCode::TransactionReplay,
        }
    );
    assert_eq!(platform.close_count, 8);
    assert_eq!(platform.query_count, 0);
}

#[test]
fn shell_v1_receive_failure_retains_uncommitted_sender_handles() {
    let mut platform = MockPlatform::new();
    platform.fail_send = false;
    let mut waits = TerminalWaits;
    let mut loader = InitSendLoader::new();
    let mut jobs = JobDispatcher::new();
    let owner = grant(EndpointKind::LaunchSession, 1, 1);
    jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
        .unwrap();
    let authority = LoadAuthority {
        parent_root: DwHandle(1),
        bootfs: DwHandle(2),
        task_group: DwHandle(3),
    };
    platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
        reservation(1),
        wyrmroot_launch_proto::ShellV1Request {
            console_generation: 2,
            status_generation: 3,
            requested_child_generation: 4,
        },
        &mut platform.inbound,
    )
    .unwrap();
    platform.inbound_handle_count = 5;
    for (index, info) in platform.inbound_handles[..5].iter_mut().enumerate() {
        info.handle = DwHandle(41 + index as u64);
    }

    assert_eq!(
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        ),
        Err(InitError::Native(FAILURE))
    );
    assert_eq!(platform.inbound_handle_count, 5);
    assert_eq!(platform.close_count, 0);
    assert_eq!(platform.sent_len, 0);
}

#[test]
fn shell_v1_rejects_duplicate_rights_after_committed_move_cleanup() {
    let mut platform = MockPlatform::new();
    platform.fail_send = false;
    platform.fresh_rights =
        DwRights(CONTROLLER_CHANNEL_RIGHTS.0 | deepwyrm_syscall::DW_RIGHT_DUPLICATE.0);
    let mut waits = TerminalWaits;
    let mut loader = InitSendLoader::new();
    let mut jobs = JobDispatcher::new();
    let owner = grant(EndpointKind::LaunchSession, 1, 1);
    jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
        .unwrap();
    platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
        reservation(1),
        wyrmroot_launch_proto::ShellV1Request {
            console_generation: 2,
            status_generation: 3,
            requested_child_generation: 4,
        },
        &mut platform.inbound,
    )
    .unwrap();
    platform.inbound_handle_count = 4;
    for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
        info.handle = DwHandle(41 + index as u64);
    }
    dispatch_one_job_request(
        &mut platform,
        &mut loader,
        &mut waits,
        LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        },
        None,
        &mut jobs,
        DwHandle(90),
        owner,
    )
    .unwrap();
    assert_eq!(platform.query_count, 1);
    assert_eq!(platform.close_count, 4);
    assert_eq!(
        wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
            .unwrap()
            .reply,
        wyrmroot_launch_proto::ShellV1Reply::Error {
            code: LaunchErrorCode::PolicyRejected,
        }
    );
}

#[test]
fn scoped_sessions_keep_minor_zero_job_operations() {
    let authority = LoadAuthority {
        parent_root: DwHandle(1),
        bootfs: DwHandle(2),
        task_group: DwHandle(3),
    };
    for scope in [
        LaunchSessionScope::ConsoleLauncher,
        LaunchSessionScope::ShellJobs,
    ] {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_scoped_session(owner, DwHandle(90), scope)
            .unwrap();
        platform.inbound[..wyrmroot_launch_proto::HEADER_BYTES].fill(0);
        wyrmroot_launch_proto::encode(reservation(1), &mut platform.inbound).unwrap();
        platform.inbound[40..44]
            .copy_from_slice(&(LaunchMessageType::ListJobs as u32).to_le_bytes());
        platform.inbound_len = wyrmroot_launch_proto::HEADER_BYTES;
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::JobList(ids) if ids.is_empty()
        ));
    }
}

fn ready_registry() -> (SystemInit, RegistryNativeAttempt) {
    let mut controller = SystemInit {
        mode: SystemMode::Bootstrap,
        roles: [
            RoleController::new(RoleId::Registryd, [1; 32]).unwrap(),
            RoleController::new(RoleId::Devmgr, [2; 32]).unwrap(),
        ],
        degraded_transitions: 0,
        activated: [false; EARLY_ROLE_COUNT],
        accounting: AttemptLedger::new(),
        registry_startup_profile: StartupProfile::BootstrapRegistry,
        devmgr_startup_profile: StartupProfile::EarlyBootStub,
    };
    controller.become_operational().unwrap();
    controller.begin_registry(0, 1, 0x1001).unwrap();
    let reservation = controller
        .reserve_attempt(RoleId::Registryd, 1, 0x1001)
        .unwrap();
    let loaded = LoadedProcess {
        process: DwHandle(31),
        launch_channel: DwHandle(32),
    };
    let task_group = DwHandle(30);
    controller
        .install_attempt(AttemptResources {
            role: RoleId::Registryd,
            generation: 1,
            transaction_id: 0x1001,
            executable_identity: [1; 32],
            startup_profile: StartupProfile::BootstrapRegistry,
            task_group,
            process: loaded.process,
            launch_channel: loaded.launch_channel,
            mappings: 0,
            reservation,
        })
        .unwrap();
    controller
        .child_started(RoleId::Registryd, 1, 0x1001, 1)
        .unwrap();
    controller.ready(RoleId::Registryd, 1, 0x1001, 2).unwrap();
    (
        controller,
        RegistryNativeAttempt {
            active: ActiveNativeRole {
                role: RoleId::Registryd,
                generation: 1,
                transaction_id: 0x1001,
                loaded,
                task_group,
            },
            control_channel: DwHandle(33),
            ready_at: 2,
        },
    )
}

#[test]
fn poison_consumes_every_native_owner_when_clock_transition_cannot_start() {
    let (mut controller, registry) = ready_registry();
    let mut platform = MockPlatform::new();
    let mut waits = TerminalWaits;

    assert_eq!(
        poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
        Err(InitError::Native(FAILURE))
    );
    assert_eq!(platform.terminate_count, 1);
    assert_eq!(
        platform.closed[..platform.close_count],
        [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
    );
    assert!(controller.resources(RoleId::Registryd).is_none());
    assert_eq!(controller.mode(), SystemMode::Fatal);
}

#[test]
fn poison_transition_rejection_still_consumes_native_owners_and_retires_fatal() {
    let (mut controller, mut registry) = ready_registry();
    registry.active.transaction_id += 1;
    let mut platform = MockPlatform::new();
    platform.now = Some(3);
    let mut waits = TerminalWaits;

    assert_eq!(
        poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
        Err(InitError::Restart(
            RestartTransitionError::TransactionMismatch
        ))
    );
    assert_eq!(platform.terminate_count, 1);
    assert_eq!(
        platform.closed[..platform.close_count],
        [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
    );
    assert!(controller.resources(RoleId::Registryd).is_none());
    assert_eq!(controller.mode(), SystemMode::Fatal);
    assert!(!matches!(
        controller.role_state(RoleId::Registryd),
        Some(RestartState::CleaningUp { .. })
    ));
}

#[test]
fn poison_cleanup_failure_is_permanent_and_blocks_replacement() {
    let (mut controller, registry) = ready_registry();
    let mut platform = MockPlatform::new();
    platform.now = Some(3);
    platform.fail_close = Some(registry.control_channel);
    let mut waits = TerminalWaits;

    assert_eq!(
        poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, true,),
        Ok(true)
    );
    assert!(matches!(
        controller.role_state(RoleId::Registryd),
        Some(RestartState::PermanentFailure { .. })
    ));
    assert_eq!(controller.mode(), SystemMode::Degraded);
    assert!(
        controller
            .start_replacement(RoleId::Registryd, 4, 2, 0x1002)
            .is_err()
    );
}

#[test]
fn poison_complete_cleanup_admits_exact_next_registry_generation() {
    let (mut controller, registry) = ready_registry();
    let mut platform = MockPlatform::new();
    platform.now = Some(3);
    platform.allow_wait = true;
    let mut waits = TerminalWaits;

    assert_eq!(
        poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
        Ok(false)
    );
    assert!(matches!(
        controller.role_state(RoleId::Registryd),
        Some(RestartState::Starting {
            generation: 2,
            transaction_id: 0x1002,
            ..
        })
    ));
}

#[test]
fn consoled_stream_descriptors_survive_init_then_reduce_at_actual_loader_move() {
    use deepwyrm_syscall::DW_RIGHT_DUPLICATE;
    use wyrmroot_loader::launch::{CHILD_CHANNEL_TRANSFER_RIGHTS, parse_init};
    use wyrmroot_loader::process::{JobLoadRequest, load_job_process};

    let streams = [DwHandle(0x901), DwHandle(0x902), DwHandle(0x903)];
    let mut platform = MockPlatform::new();
    for stream in streams {
        let transfer = consoled_stream_transfer::move_transfer(stream);
        assert_eq!(transfer.handle, stream);
        assert_eq!(transfer.operation, DW_HANDLE_TRANSFER_MOVE);
        assert_eq!(transfer.requested_rights, CHILD_CHANNEL_TRANSFER_RIGHTS);
        assert_eq!(transfer.requested_rights.0 & DW_RIGHT_DUPLICATE.0, 0);
        assert_eq!((transfer.reserved0, transfer.reserved), (0, [0; 2]));
        // Query the authority delivered by the actual first-hop descriptor.
        platform.fresh_rights = transfer.requested_rights;
        validate_controller_channel(&mut platform, stream).unwrap();
    }
    assert_eq!(platform.queried[..platform.query_count], streams);

    let image = executable();
    let mut loader = InitSendLoader::new();
    loader.fail_init = false;
    load_job_process(
        &mut loader,
        LoadAuthority {
            parent_root: DwHandle(1),
            task_group: DwHandle(2),
            bootfs: DwHandle(3),
        },
        JobLoadRequest {
            image: &image,
            policy_path: "bin/console-echo",
            argv: &["bin/console-echo"],
            environment: &[],
            streams: &streams,
            transaction_id: 0xd500,
        },
    )
    .unwrap();
    assert_eq!(loader.sent_transfers.len(), 3);
    let mut received = [DwReceivedHandleInfoV1::default(); 3];
    for (index, transfer) in loader.sent_transfers.iter().enumerate() {
        assert_eq!(transfer.handle, streams[index]);
        assert_eq!(transfer.operation, DW_HANDLE_TRANSFER_MOVE);
        assert_eq!(transfer.requested_rights, CHILD_CHANNEL_RIGHTS);
        assert_eq!(
            transfer.requested_rights.0 & (DW_RIGHT_TRANSFER.0 | DW_RIGHT_DUPLICATE.0),
            0
        );
        received[index] = DwReceivedHandleInfoV1 {
            handle: transfer.handle,
            rights: transfer.requested_rights,
            object_type: DW_OBJECT_TYPE_CHANNEL,
            ..DwReceivedHandleInfoV1::default()
        };
    }
    parse_init(LaunchProfile::JobV2Streams, &loader.sent_init, &received).unwrap();
}

#[test]
fn consoled_stream_ingress_rejects_early_reduction_and_duplicate_authority() {
    use deepwyrm_syscall::DW_RIGHT_DUPLICATE;

    let transfer = consoled_stream_transfer::move_transfer(DwHandle(0x901));
    for rights in [
        DwRights(transfer.requested_rights.0 & !DW_RIGHT_TRANSFER.0),
        DwRights(transfer.requested_rights.0 | DW_RIGHT_DUPLICATE.0),
    ] {
        let mut platform = MockPlatform::new();
        platform.fresh_rights = rights;
        assert_eq!(
            validate_controller_channel(&mut platform, transfer.handle),
            Err(InitError::ResourceIdentityMismatch)
        );
        assert_eq!(platform.query_count, 1);
    }
}

#[test]
fn staged_channel_cleanup_is_affine_and_reverse_ordered() {
    let mut platform = MockPlatform::new();
    let mut owner = StagedChannelPair::new(DwHandle(20), DwHandle(21));
    assert!(owner.cleanup(&mut platform));
    assert!(owner.cleanup(&mut platform));
    assert_eq!(
        platform.closed[..platform.close_count],
        [DwHandle(21), DwHandle(20)]
    );
}

/// Sends one request on a session of `scope` and returns the error code of
/// the reply, after checking every received handle was closed.
fn rejected_on(
    scope: LaunchSessionScope,
    encode_request: impl FnOnce(&mut [u8]) -> usize,
    handles: usize,
    shell_v1_reply: bool,
) -> LaunchErrorCode {
    let mut platform = MockPlatform::new();
    platform.fail_send = false;
    let mut waits = TerminalWaits;
    let mut loader = InitSendLoader::new();
    let mut jobs = JobDispatcher::new();
    let owner = grant(EndpointKind::LaunchSession, 1, 1);
    jobs.install_scoped_session(owner, DwHandle(90), scope)
        .unwrap();
    platform.inbound_len = encode_request(&mut platform.inbound);
    platform.inbound_handle_count = handles;
    for (index, info) in platform.inbound_handles[..handles].iter_mut().enumerate() {
        info.handle = DwHandle(41 + index as u64);
    }
    assert_eq!(
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        ),
        Ok(JobDispatchOutcome::Responded)
    );
    let mut closed = platform.closed[..platform.close_count].to_vec();
    closed.sort_by_key(|handle| handle.0);
    let expected: Vec<_> = (0..handles)
        .map(|index| DwHandle(41 + index as u64))
        .collect();
    assert_eq!(closed, expected, "every received handle is closed");
    assert_eq!(jobs.jobs.live_jobs(), 0);
    let reply = &platform.sent[..platform.sent_len];
    if shell_v1_reply {
        match wyrmroot_launch_proto::parse_shell_v1_reply(reply, 0)
            .unwrap()
            .reply
        {
            wyrmroot_launch_proto::ShellV1Reply::Error { code } => code,
            other => panic!("unexpected reply {other:?}"),
        }
    } else {
        match parse_launch_message(reply, 0).unwrap().message {
            LaunchMessage::Error { code } => code,
            other => panic!("unexpected reply {other:?}"),
        }
    }
}

fn legacy_launch(path: &'static str, streams: bool) -> impl FnOnce(&mut [u8]) -> usize {
    move |out| {
        wyrmroot_launch_proto::encode_launch(reservation(1), path, &[path], &[], streams, out)
            .unwrap()
    }
}

/// F4 WR-F4-L1: a refused legacy LAUNCH on the console launcher closes every
/// received handle and replies `PolicyRejected`. With no policy loaded this
/// reply is also what a missing policy gives, so the scope table itself is
/// pinned by `job_sessions::tests::launch_scopes_admit_exactly_their_table`.
#[test]
fn console_launcher_refuses_every_legacy_launch() {
    for (path, streams, handles) in [("bin/hello", false, 0), ("bin/cpu-hog", true, 3)] {
        assert_eq!(
            rejected_on(
                LaunchSessionScope::ConsoleLauncher,
                legacy_launch(path, streams),
                handles,
                false,
            ),
            LaunchErrorCode::PolicyRejected
        );
    }
}

/// F4 WR-F4-L1: a refused ShellJobs LAUNCH of a system service or look-alike
/// path closes every received handle and replies `PolicyRejected`. The scope
/// table itself is pinned by
/// `job_sessions::tests::launch_scopes_admit_exactly_their_table`.
#[test]
fn shell_jobs_refuse_system_services_and_unlisted_paths() {
    for path in [
        "system/consoled",
        "system/init",
        "system/wyrmsh",
        "system/devmgr",
        "bin/hello-extra",
        "bin/cpu-hog2",
    ] {
        for (streams, handles) in [(false, 0), (true, 3)] {
            assert_eq!(
                rejected_on(
                    LaunchSessionScope::ShellJobs,
                    legacy_launch(path, streams),
                    handles,
                    false,
                ),
                LaunchErrorCode::PolicyRejected,
                "{path}"
            );
        }
    }
}

/// F4 WR-F4-L1: a shell cannot start another shell through its job session.
#[test]
fn shell_jobs_refuse_shell_v1() {
    let code = rejected_on(
        LaunchSessionScope::ShellJobs,
        |out| {
            wyrmroot_launch_proto::encode_shell_v1_request(
                reservation(1),
                wyrmroot_launch_proto::ShellV1Request {
                    console_generation: 2,
                    status_generation: 3,
                    requested_child_generation: 4,
                },
                out,
            )
            .unwrap()
        },
        4,
        true,
    );
    assert_eq!(code, LaunchErrorCode::PolicyRejected);
}
