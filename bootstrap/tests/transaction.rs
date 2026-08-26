#[cfg(feature = "i-capability-relay")]
use deepwyrm_syscall::DW_STATUS_TIMED_OUT;
use deepwyrm_syscall::DW_STATUS_WOULD_BLOCK;
use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_OBJECT_TYPE_TASK_GROUP, DW_STATUS_BAD_HANDLE, DwHandle, DwObjectType,
    DwReceivedHandleInfoV1, DwRights,
};
use deepwyrm_syscall::{
    DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_TASK_STATE_EXITED,
    DW_TASK_STATE_RUNNING, DW_TASK_TERMINATION_INFO_V1_SIZE, DW_TERMINATION_NORMAL_EXIT,
    DwDeadline, DwHandleTransferV1, DwMemoryProtection, DwTaskState, DwTaskTerminationInfoV1,
    DwWaitItemV1, DwWaitResultV1,
};
use wyrmroot_bootfs::builder::{Builder, FileMode};
#[cfg(feature = "primordial-test-support")]
use wyrmroot_bootstrap::run_bootstrap_with_before_ready;
use wyrmroot_bootstrap::{
    BootstrapError, BootstrapSystem, ChildCleanupError, ChildCleanupStage, HELLO_PATH,
    I0_NEGATIVE_CAPABILITY_COUNT_DETAIL, I0_NEGATIVE_CAPABILITY_RIGHTS_DETAIL,
    I0_NEGATIVE_CAPABILITY_TYPE_DETAIL, I0_NEGATIVE_MALFORMED_ELF_DETAIL,
    I0_NEGATIVE_MALFORMED_STARTUP_DETAIL, INIT0_PATH, SYSTEM_INIT_PATH, SYSTEM_INIT_TRANSACTION_ID,
    i0_negative_terminal_detail, run_bootstrap, run_init0_bootstrap,
    run_init0_bootstrap_with_fault, run_supervisor_bootstrap,
};
#[cfg(feature = "loader-smoke-integration")]
use wyrmroot_bootstrap::{LOADER_SMOKE_PATH, run_loader_smoke_bootstrap};
#[cfg(feature = "i-capability-relay")]
use wyrmroot_bootstrap::{
    WRCAP1_KINDS, WRCAP1_RECORD_COUNT, WRCAP1_RECORD_SIZE, Wrcap1RelayError,
    run_init0_capability_bootstrap,
};
use wyrmroot_bootstrap_proto::{
    BOOTSTRAP_INIT_V2_SIZE, BootstrapMessage, InitMessageV2, ReadyMessageV2, decode,
};
use wyrmroot_loader::{
    elf::ElfError,
    launch,
    process::{
        LoadError, LoadFault, LoadStage, LoaderPlatform, ParentMapping, ProcessCreateRequest,
        ProcessCreateResult,
    },
};
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo,
    LOADER_TASK_GROUP_EXPECTATION, MappingPlan, NativeError, ReceiveCounts, SELF_ROOT_EXPECTATION,
};
use wyrmroot_runtime::{ExitValidationError, SupervisionError, SupervisionPlatform};
use wyrmroot_runtime::{StartupError, startup_error_exit_code};

const CHANNEL: DwHandle = DwHandle(11);
const ROOT: DwHandle = DwHandle(21);
const BOOTFS: DwHandle = DwHandle(22);
const TASK_GROUP: DwHandle = DwHandle(23);
#[cfg(feature = "i-capability-relay")]
const WRCAP1_READABLE_EVENTS: [deepwyrm_syscall::DwSignals; WRCAP1_RECORD_COUNT] =
    [DW_SIGNAL_READABLE; WRCAP1_RECORD_COUNT];

#[test]
fn live_exit_code_identifies_bootstrap_owned_failure() {
    assert_eq!(
        BootstrapError::MissingRequiredEntry.exit_code(),
        0xB000_000A
    );
    assert_eq!(
        BootstrapError::Native(NativeError::Status(
            deepwyrm_syscall::DW_STATUS_NO_RESOURCES
        ))
        .exit_code(),
        0xB001_000D
    );
    assert_eq!(
        BootstrapError::Loader(LoadError::Platform {
            stage: LoadStage::ChannelCreate,
            cause: NativeError::Status(deepwyrm_syscall::DW_STATUS_NO_RESOURCES),
            rollback_failed: false,
        })
        .exit_code(),
        0xB101_000D
    );
    assert_eq!(
        BootstrapError::Loader(LoadError::Platform {
            stage: LoadStage::SuccessCleanup,
            cause: NativeError::Output(wyrmroot_runtime::NativeOutputError::InvalidLoaderOutput),
            rollback_failed: true,
        })
        .exit_code(),
        0xB18C_8005
    );
    for status in [
        deepwyrm_syscall::DwStatus(-32_769),
        deepwyrm_syscall::DwStatus(i32::MIN),
    ] {
        assert_eq!(
            BootstrapError::Loader(LoadError::Platform {
                stage: LoadStage::ChannelCreate,
                cause: NativeError::Status(status),
                rollback_failed: false,
            })
            .exit_code(),
            0xB101_7FFF
        );
    }
    assert_eq!(
        BootstrapError::Loader(LoadError::Platform {
            stage: LoadStage::ChannelCreate,
            cause: NativeError::Output(wyrmroot_runtime::NativeOutputError::InvalidObjectInfo),
            rollback_failed: false,
        })
        .exit_code(),
        0xB101_8001
    );
    assert_eq!(
        BootstrapError::Cleanup(ChildCleanupError {
            stage: ChildCleanupStage::ProcessTerminate,
            cause: NativeError::Status(deepwyrm_syscall::DwStatus(-73)),
        })
        .exit_code(),
        0xB201_0049
    );
    assert_eq!(
        BootstrapError::Cleanup(ChildCleanupError {
            stage: ChildCleanupStage::ProcessHandleClose,
            cause: NativeError::Output(wyrmroot_runtime::NativeOutputError::InvalidWaitResult),
        })
        .exit_code(),
        0xB203_8006
    );
    #[cfg(feature = "i-capability-relay")]
    assert_eq!(
        BootstrapError::CapabilityRelay(Wrcap1RelayError::UnexpectedKind).exit_code(),
        0xB000_0D0A
    );
}

struct Fixture {
    init: [u8; BOOTSTRAP_INIT_V2_SIZE],
    init_size: usize,
    handles: [DwReceivedHandleInfoV1; 3],
    bootfs: Vec<u8>,
    sent: Vec<u8>,
    closed: Vec<DwHandle>,
    mapped: bool,
    mapping_error_after_callback: bool,
    relay_records: Vec<Vec<u8>>,
    relay_index: usize,
    relay_handle_count: usize,
    relay_receive_error: Option<NativeError>,
    relay_send_would_block_once: bool,
    startup_counts: Option<ReceiveCounts>,
}

impl Fixture {
    fn valid() -> Self {
        let mut init = [0_u8; BOOTSTRAP_INIT_V2_SIZE];
        let init_size = InitMessageV2::primordial().encode_into(&mut init).unwrap();
        Self {
            init,
            init_size,
            handles: [
                DwReceivedHandleInfoV1 {
                    handle: ROOT,
                    rights: SELF_ROOT_EXPECTATION.rights,
                    object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
                    ..DwReceivedHandleInfoV1::default()
                },
                DwReceivedHandleInfoV1 {
                    handle: BOOTFS,
                    rights: BOOTFS_EXPECTATION.rights,
                    object_type: DW_OBJECT_TYPE_MEMORY_OBJECT,
                    ..DwReceivedHandleInfoV1::default()
                },
                DwReceivedHandleInfoV1 {
                    handle: TASK_GROUP,
                    rights: LOADER_TASK_GROUP_EXPECTATION.rights,
                    object_type: DW_OBJECT_TYPE_TASK_GROUP,
                    ..DwReceivedHandleInfoV1::default()
                },
            ],
            bootfs: bootfs(&[(HELLO_PATH, b"hello"), (INIT0_PATH, b"init0")]),
            sent: Vec::new(),
            closed: Vec::new(),
            mapped: false,
            mapping_error_after_callback: false,
            relay_records: Vec::new(),
            relay_index: 0,
            relay_handle_count: 0,
            relay_receive_error: None,
            relay_send_would_block_once: false,
            startup_counts: None,
        }
    }
}

impl BootstrapSystem for Fixture {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        match handle {
            CHANNEL => Ok(CapabilityInfo {
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
            }),
            ROOT => Ok(CapabilityInfo {
                object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
                rights: SELF_ROOT_EXPECTATION.rights,
            }),
            BOOTFS => Ok(CapabilityInfo {
                object_type: DW_OBJECT_TYPE_MEMORY_OBJECT,
                rights: BOOTFS_EXPECTATION.rights,
            }),
            TASK_GROUP => Ok(CapabilityInfo {
                object_type: DW_OBJECT_TYPE_TASK_GROUP,
                rights: LOADER_TASK_GROUP_EXPECTATION.rights,
            }),
            _ => Err(NativeError::Status(DW_STATUS_BAD_HANDLE)),
        }
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        if channel == CHANNEL {
            bytes[..self.init_size].copy_from_slice(&self.init[..self.init_size]);
            handles[..3].copy_from_slice(&self.handles);
            return Ok(self.startup_counts.unwrap_or(ReceiveCounts {
                bytes: self.init_size,
                handles: 3,
            }));
        }
        let record = self
            .relay_records
            .get(self.relay_index)
            .expect("unexpected init0 launch receive");
        if let Some(error) = self.relay_receive_error {
            return Err(error);
        }
        self.relay_index += 1;
        if record.len() <= bytes.len() {
            bytes[..record.len()].copy_from_slice(record);
        }
        Ok(ReceiveCounts {
            bytes: record.len(),
            handles: self.relay_handle_count,
        })
    }

    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError> {
        assert_eq!(handle, BOOTFS);
        Ok(self.bootfs.len() as u64)
    }

    fn with_bootfs_bytes<R>(
        &mut self,
        root_region: DwHandle,
        bootfs: DwHandle,
        plan: MappingPlan,
        use_bytes: impl for<'bytes> FnOnce(&'bytes [u8]) -> R,
    ) -> Result<R, NativeError> {
        assert_eq!(root_region, ROOT);
        assert_eq!(bootfs, BOOTFS);
        assert_eq!(plan.logical_size(), self.bootfs.len() as u64);
        assert!(plan.mapped_size() >= plan.logical_size());
        self.mapped = true;
        let result = use_bytes(&self.bootfs);
        if self.mapping_error_after_callback {
            return Err(NativeError::Status(DW_STATUS_BAD_HANDLE));
        }
        Ok(result)
    }

    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        assert_eq!(channel, CHANNEL);
        if self.relay_send_would_block_once && bytes.starts_with(b"WRCAP1|") {
            self.relay_send_would_block_once = false;
            return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
        }
        self.sent.extend_from_slice(bytes);
        Ok(())
    }

    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.closed.push(handle);
        Ok(())
    }
}

fn bootfs(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut builder = Builder::new();
    for (path, bytes) in entries {
        builder.add(path, bytes, FileMode::Executable).unwrap();
    }
    builder.build().unwrap()
}

#[test]
fn synthetic_transaction_validates_bootfs_sends_ready_and_closes_handles() {
    let mut fixture = Fixture::valid();
    assert_eq!(run_bootstrap(&mut fixture, CHANNEL), Ok(()));
    assert!(fixture.mapped);
    assert_eq!(
        decode(&fixture.sent, 0),
        Ok(BootstrapMessage::ReadyV2(ReadyMessageV2 {
            transaction_id: 1
        }))
    );
    assert_eq!(fixture.closed, [ROOT, BOOTFS, TASK_GROUP, CHANNEL]);
}

#[test]
fn malformed_protocol_closes_received_handles_without_ready() {
    let mut fixture = Fixture::valid();
    fixture.init[0] = b'X';
    assert!(matches!(
        run_bootstrap(&mut fixture, CHANNEL),
        Err(BootstrapError::Protocol(_))
    ));
    assert_eq!(fixture.closed, [ROOT, BOOTFS, TASK_GROUP]);
    assert!(fixture.sent.is_empty());
}

#[cfg(feature = "primordial-test-support")]
#[test]
fn test_hook_runs_after_capability_cleanup_and_before_ready_or_channel_close() {
    let mut fixture = Fixture::valid();
    assert_eq!(
        run_bootstrap_with_before_ready(&mut fixture, CHANNEL, |_| {
            Err(BootstrapError::UnexpectedMessage)
        }),
        Err(BootstrapError::UnexpectedMessage)
    );
    assert!(fixture.mapped);
    assert_eq!(fixture.closed, [ROOT, BOOTFS, TASK_GROUP]);
    assert!(fixture.sent.is_empty());
}

#[test]
fn nonprimordial_transaction_id_is_rejected_and_received_handles_are_closed() {
    let mut fixture = Fixture::valid();
    fixture.init[24..32].copy_from_slice(&2_u64.to_le_bytes());
    assert_eq!(
        run_bootstrap(&mut fixture, CHANNEL),
        Err(BootstrapError::UnexpectedTransactionId)
    );
    assert_eq!(fixture.closed, [ROOT, BOOTFS, TASK_GROUP]);
    assert!(fixture.sent.is_empty());
}

#[test]
fn missing_or_nonexecutable_required_entries_fail_before_ready() {
    let mut missing = Fixture::valid();
    missing.bootfs = bootfs(&[(INIT0_PATH, b"init0")]);
    assert_eq!(
        run_bootstrap(&mut missing, CHANNEL),
        Err(BootstrapError::MissingRequiredEntry)
    );
    assert_eq!(missing.closed, [ROOT, BOOTFS, TASK_GROUP]);
    assert!(missing.sent.is_empty());

    let mut builder = Builder::new();
    builder
        .add(HELLO_PATH, b"hello", FileMode::ReadOnly)
        .unwrap();
    builder
        .add(INIT0_PATH, b"init0", FileMode::Executable)
        .unwrap();
    let mut nonexecutable = Fixture::valid();
    nonexecutable.bootfs = builder.build().unwrap();
    assert_eq!(
        run_bootstrap(&mut nonexecutable, CHANNEL),
        Err(BootstrapError::RequiredEntryNotExecutable)
    );
    assert!(nonexecutable.sent.is_empty());
}

struct SmokeLoader {
    next: u64,
    init_profiles: Vec<launch::LaunchProfile>,
    terminated: Vec<DwHandle>,
    fail_terminate: bool,
    expected_profile: launch::LaunchProfile,
    expected_transaction: u64,
}

impl SmokeLoader {
    fn new() -> Self {
        Self {
            next: 40,
            init_profiles: Vec::new(),
            terminated: Vec::new(),
            fail_terminate: false,
            expected_profile: launch::LaunchProfile::Hello,
            expected_transaction: 2,
        }
    }

    fn init0() -> Self {
        Self {
            expected_profile: launch::LaunchProfile::Init0,
            expected_transaction: 1,
            ..Self::new()
        }
    }

    fn supervisor() -> Self {
        Self {
            expected_profile: launch::LaunchProfile::Supervisor,
            expected_transaction: SYSTEM_INIT_TRANSACTION_ID,
            ..Self::new()
        }
    }

    fn handle(&mut self) -> DwHandle {
        let handle = DwHandle(self.next);
        self.next += 1;
        handle
    }
}

impl LoaderPlatform for SmokeLoader {
    type Error = NativeError;

    fn channel_create(&mut self, _: DwRights) -> Result<(DwHandle, DwHandle), Self::Error> {
        Ok((self.handle(), self.handle()))
    }

    fn duplicate(&mut self, _: DwHandle, _: DwRights) -> Result<DwHandle, Self::Error> {
        Ok(self.handle())
    }

    fn close(&mut self, _: DwHandle) -> Result<(), Self::Error> {
        Ok(())
    }

    fn process_create(
        &mut self,
        _: ProcessCreateRequest,
    ) -> Result<ProcessCreateResult, Self::Error> {
        Ok(ProcessCreateResult {
            process: self.handle(),
            root: self.handle(),
            child_bootstrap: self.handle(),
        })
    }

    fn memory_create(&mut self, _: u64, _: DwRights) -> Result<DwHandle, Self::Error> {
        Ok(self.handle())
    }

    fn materialize_parent(
        &mut self,
        _: DwHandle,
        _: DwHandle,
        bytes: u64,
        _: u64,
        _: &[u8],
    ) -> Result<ParentMapping, Self::Error> {
        Ok(ParentMapping {
            address: 0x5000_0000,
            bytes,
        })
    }

    fn unmap_parent(&mut self, _: DwHandle, _: ParentMapping) -> Result<(), Self::Error> {
        Ok(())
    }

    fn map_child(
        &mut self,
        _: DwHandle,
        _: DwHandle,
        _: u64,
        _: u64,
        _: DwMemoryProtection,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn unmap_child(&mut self, _: DwHandle, _: u64, _: u64) -> Result<(), Self::Error> {
        Ok(())
    }

    fn thread_create(&mut self, _: DwHandle, _: DwRights) -> Result<DwHandle, Self::Error> {
        Ok(self.handle())
    }

    fn send_init(
        &mut self,
        _: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), Self::Error> {
        let received = [
            DwReceivedHandleInfoV1 {
                handle: DwHandle(1),
                object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
                rights: wyrmroot_loader::launch::SELF_ROOT_RIGHTS,
                ..DwReceivedHandleInfoV1::default()
            },
            DwReceivedHandleInfoV1 {
                handle: DwHandle(2),
                object_type: DW_OBJECT_TYPE_MEMORY_OBJECT,
                rights: wyrmroot_loader::launch::BOOTFS_RIGHTS,
                ..DwReceivedHandleInfoV1::default()
            },
            DwReceivedHandleInfoV1 {
                handle: DwHandle(3),
                object_type: DW_OBJECT_TYPE_TASK_GROUP,
                rights: wyrmroot_loader::launch::LOADER_TASK_GROUP_RIGHTS,
                ..DwReceivedHandleInfoV1::default()
            },
        ];
        let handles = match self.expected_profile {
            launch::LaunchProfile::Hello
            | launch::LaunchProfile::EarlyBootStub
            | launch::LaunchProfile::JobV2 => {
                assert!(transfers.is_empty());
                &received[..0]
            }
            launch::LaunchProfile::Init0
            | launch::LaunchProfile::I2Stress
            | launch::LaunchProfile::CapabilityController
            | launch::LaunchProfile::Supervisor => {
                assert_eq!(transfers.len(), 3);
                assert!(transfers.iter().all(|transfer| {
                    transfer.operation == deepwyrm_syscall::DW_HANDLE_TRANSFER_MOVE
                }));
                &received[..]
            }
            launch::LaunchProfile::ProbeChild => {
                assert_eq!(transfers.len(), 1);
                assert_eq!(
                    transfers[0].operation,
                    deepwyrm_syscall::DW_HANDLE_TRANSFER_MOVE
                );
                &received[..1]
            }
            launch::LaunchProfile::BootstrapRegistry
            | launch::LaunchProfile::BootstrapService
            | launch::LaunchProfile::RegistryClient
            | launch::LaunchProfile::LaunchClient
            | launch::LaunchProfile::JobV2Streams => {
                return Err(NativeError::Status(DW_STATUS_BAD_HANDLE));
            }
        };
        let parsed = launch::parse_init(self.expected_profile, bytes, handles)
            .map_err(|_| NativeError::Status(DW_STATUS_BAD_HANDLE))?;
        assert_eq!(parsed.transaction_id, self.expected_transaction);
        self.init_profiles.push(parsed.profile);
        Ok(())
    }

    fn thread_start(
        &mut self,
        _: DwHandle,
        _: u64,
        _: u64,
        _: DwHandle,
        _: u64,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn thread_terminate(&mut self, _: DwHandle) -> Result<(), Self::Error> {
        Ok(())
    }

    fn process_terminate(&mut self, process: DwHandle) -> Result<(), Self::Error> {
        self.terminated.push(process);
        if self.fail_terminate {
            Err(NativeError::Status(DW_STATUS_BAD_HANDLE))
        } else {
            Ok(())
        }
    }
}

struct SmokeSupervisor {
    events: &'static [bool],
    index: usize,
    received: usize,
    ready_handle_count: usize,
    termination_query_error: bool,
    termination_state: DwTaskState,
    termination_application_code: u32,
    termination_queries: usize,
    exit_on_query: Option<usize>,
    transaction_id: u64,
    ready_profile: launch::LaunchProfile,
    relay_events: &'static [deepwyrm_syscall::DwSignals],
    relay_index: usize,
    relay_wait_error: Option<NativeError>,
    relay_invalid_wait_result: bool,
    ready_receive_counts: Option<ReceiveCounts>,
    writable_waits: usize,
}

impl SmokeSupervisor {
    fn successful() -> Self {
        Self {
            events: &[true, false],
            index: 0,
            received: 0,
            ready_handle_count: 0,
            termination_query_error: false,
            termination_state: DW_TASK_STATE_EXITED,
            termination_application_code: 0,
            termination_queries: 0,
            exit_on_query: None,
            transaction_id: 2,
            ready_profile: launch::LaunchProfile::Hello,
            relay_events: &[],
            relay_index: 0,
            relay_wait_error: None,
            relay_invalid_wait_result: false,
            ready_receive_counts: None,
            writable_waits: 0,
        }
    }

    fn successful_init0() -> Self {
        Self {
            transaction_id: 1,
            ..Self::successful()
        }
    }

    fn successful_supervisor() -> Self {
        Self {
            events: &[true],
            transaction_id: SYSTEM_INIT_TRANSACTION_ID,
            ready_profile: launch::LaunchProfile::Supervisor,
            ..Self::successful()
        }
    }

    fn exited_before_ready() -> Self {
        Self {
            events: &[false],
            index: 0,
            received: 0,
            ready_handle_count: 0,
            termination_query_error: false,
            termination_state: DW_TASK_STATE_EXITED,
            termination_application_code: 0,
            termination_queries: 0,
            exit_on_query: None,
            transaction_id: 2,
            ready_profile: launch::LaunchProfile::Hello,
            relay_events: &[],
            relay_index: 0,
            relay_wait_error: None,
            relay_invalid_wait_result: false,
            ready_receive_counts: None,
            writable_waits: 0,
        }
    }
}

impl SupervisionPlatform for SmokeSupervisor {
    type Error = NativeError;

    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, Self::Error> {
        assert_eq!(deadline, DwDeadline(99));
        if let Some(error) = self.relay_wait_error.take() {
            return Err(error);
        }
        if items.len() == 1 && items[0].handle == CHANNEL {
            assert_eq!(
                items[0].signals.0,
                deepwyrm_syscall::DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0
            );
            self.writable_waits += 1;
            return Ok(DwWaitResultV1 {
                size: deepwyrm_syscall::DW_WAIT_RESULT_V1_SIZE,
                version: 1,
                index: 0,
                observed: deepwyrm_syscall::DW_SIGNAL_WRITABLE,
                ..DwWaitResultV1::default()
            });
        }
        if items.len() == 1 && items[0].signals == DW_SIGNAL_EXITED {
            return Ok(DwWaitResultV1 {
                size: deepwyrm_syscall::DW_WAIT_RESULT_V1_SIZE,
                version: 1,
                index: 0,
                observed: DW_SIGNAL_EXITED,
                ..DwWaitResultV1::default()
            });
        }
        if self.relay_invalid_wait_result {
            self.relay_invalid_wait_result = false;
            return Ok(DwWaitResultV1 {
                size: deepwyrm_syscall::DW_WAIT_RESULT_V1_SIZE,
                version: 1,
                index: 1,
                observed: DW_SIGNAL_READABLE,
                ..DwWaitResultV1::default()
            });
        }
        if let Some(&observed) = self.relay_events.get(self.relay_index) {
            self.relay_index += 1;
            assert_eq!(items.len(), 1);
            assert_eq!(
                items[0].signals.0,
                DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0
            );
            return Ok(DwWaitResultV1 {
                size: deepwyrm_syscall::DW_WAIT_RESULT_V1_SIZE,
                version: 1,
                index: 0,
                observed,
                ..DwWaitResultV1::default()
            });
        }
        let (index, observed) = if items.len() == 1 {
            (0, DW_SIGNAL_PEER_CLOSED)
        } else {
            let ready = self.events[self.index];
            self.index += 1;
            if ready {
                (0, DW_SIGNAL_READABLE)
            } else {
                (items.len() as u32 - 1, DW_SIGNAL_EXITED)
            }
        };
        Ok(DwWaitResultV1 {
            size: deepwyrm_syscall::DW_WAIT_RESULT_V1_SIZE,
            version: 1,
            index,
            observed,
            ..DwWaitResultV1::default()
        })
    }

    fn receive_channel(
        &mut self,
        _: DwHandle,
        bytes: &mut [u8],
        _: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, Self::Error> {
        self.received += 1;
        if let Some(counts) = self.ready_receive_counts {
            return Ok(counts);
        }
        let size = launch::encode_ready_for_profile(self.ready_profile, self.transaction_id, bytes)
            .map_err(|_| NativeError::Status(DW_STATUS_BAD_HANDLE))?;
        Ok(ReceiveCounts {
            bytes: size,
            handles: self.ready_handle_count,
        })
    }

    fn query_task_termination(
        &mut self,
        _: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
        self.termination_queries += 1;
        if self.termination_query_error {
            return Err(NativeError::Status(DW_STATUS_BAD_HANDLE));
        }
        let state = if self
            .exit_on_query
            .is_some_and(|query| self.termination_queries >= query)
        {
            DW_TASK_STATE_EXITED
        } else {
            self.termination_state
        };
        Ok(DwTaskTerminationInfoV1 {
            size: DW_TASK_TERMINATION_INFO_V1_SIZE,
            version: 1,
            state,
            reason: DW_TERMINATION_NORMAL_EXIT,
            application_code: self.termination_application_code,
            ..DwTaskTerminationInfoV1::default()
        })
    }
}

#[test]
fn primordial_bootstrap_launches_only_init0_and_supervises_it_before_ready() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();

    assert_eq!(
        run_init0_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Ok(())
    );
    assert_eq!(loader.init_profiles, [launch::LaunchProfile::Init0]);
    assert_eq!(supervisor.received, 1);
    assert_eq!(
        decode(&fixture.sent, 0),
        Ok(BootstrapMessage::ReadyV2(ReadyMessageV2 {
            transaction_id: 1
        }))
    );
    assert_eq!(
        fixture.closed,
        [
            DwHandle(42),
            DwHandle(43),
            ROOT,
            BOOTFS,
            TASK_GROUP,
            CHANNEL
        ]
    );
}

#[test]
fn wyr1_primordial_launches_only_system_init_and_retires_after_operational_ready() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(SYSTEM_INIT_PATH, &image)]);
    let mut loader = SmokeLoader::supervisor();
    let mut supervisor = SmokeSupervisor::successful_supervisor();

    assert_eq!(
        run_supervisor_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Ok(())
    );
    assert_eq!(loader.init_profiles, [launch::LaunchProfile::Supervisor]);
    assert!(loader.terminated.is_empty());
    assert_eq!(supervisor.received, 1);
    assert_eq!(
        decode(&fixture.sent, 0),
        Ok(BootstrapMessage::ReadyV2(ReadyMessageV2 {
            transaction_id: 1
        }))
    );
    assert_eq!(
        fixture.closed,
        [
            DwHandle(42),
            DwHandle(43),
            ROOT,
            BOOTFS,
            TASK_GROUP,
            CHANNEL
        ]
    );
}

#[test]
fn wyr1_primordial_oversized_receive_closes_initialized_handles_and_channel() {
    let mut fixture = Fixture::valid();
    fixture.startup_counts = Some(ReceiveCounts {
        bytes: BOOTSTRAP_INIT_V2_SIZE,
        handles: usize::MAX,
    });
    let mut loader = SmokeLoader::supervisor();
    let mut supervisor = SmokeSupervisor::successful_supervisor();
    assert_eq!(
        run_supervisor_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::ReceiveCounts(ReceiveCounts {
            bytes: BOOTSTRAP_INIT_V2_SIZE,
            handles: usize::MAX,
        }))
    );
    assert_eq!(fixture.closed, [ROOT, BOOTFS, TASK_GROUP, CHANNEL]);
    assert!(loader.init_profiles.is_empty());
    assert_eq!(supervisor.received, 0);
}

#[cfg(feature = "i-capability-relay")]
#[test]
fn capability_bootstrap_relays_fifteen_exact_wrcap1_records_before_init0_supervision() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    fixture.relay_records = WRCAP1_KINDS
        .into_iter()
        .enumerate()
        .map(|(sequence, kind)| wrcap1_record(sequence as u32, kind))
        .collect();
    let expected_records = fixture.relay_records.concat();
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_events = &WRCAP1_READABLE_EVENTS;

    assert_eq!(
        run_init0_capability_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Ok(())
    );
    assert_eq!(fixture.relay_index, WRCAP1_RECORD_COUNT);
    assert_eq!(supervisor.relay_index, WRCAP1_RECORD_COUNT);
    assert_eq!(supervisor.received, 1);
    assert_eq!(&fixture.sent[..expected_records.len()], expected_records);
    assert_eq!(
        decode(&fixture.sent[expected_records.len()..], 0),
        Ok(BootstrapMessage::ReadyV2(ReadyMessageV2 {
            transaction_id: 1
        }))
    );
}

#[cfg(feature = "i-capability-relay")]
#[test]
fn capability_bootstrap_retries_a_would_block_upstream_send_after_writable() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    fixture.relay_records = WRCAP1_KINDS
        .into_iter()
        .enumerate()
        .map(|(sequence, kind)| wrcap1_record(sequence as u32, kind))
        .collect();
    let expected_records = fixture.relay_records.concat();
    fixture.relay_send_would_block_once = true;
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_events = &WRCAP1_READABLE_EVENTS;

    assert_eq!(
        run_init0_capability_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Ok(())
    );
    assert!(fixture.sent.starts_with(&expected_records));
    assert_eq!(supervisor.writable_waits, 1);
}

#[cfg(feature = "i-capability-relay")]
#[test]
fn capability_bootstrap_rejects_malformed_first_relay_record_before_supervision() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut malformed = wrcap1_record(0, 1);
    malformed[0] = b'w';
    fixture.relay_records = vec![malformed];
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_events = &WRCAP1_READABLE_EVENTS;

    assert_eq!(
        run_init0_capability_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::MalformedFraming
        ))
    );
    assert_eq!(supervisor.received, 0);

    let mut kind_fixture = Fixture::valid();
    kind_fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    kind_fixture.relay_records = vec![wrcap1_record(0, 1), wrcap1_record(1, 3)];
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_events = &WRCAP1_READABLE_EVENTS;
    assert_eq!(
        run_init0_capability_bootstrap(
            &mut kind_fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::UnexpectedKind
        ))
    );
    assert_eq!(supervisor.received, 0);
    assert!(fixture.sent.is_empty());
    assert_eq!(
        fixture.closed,
        [DwHandle(42), DwHandle(43), ROOT, BOOTFS, TASK_GROUP]
    );
}

#[cfg(feature = "i-capability-relay")]
#[test]
fn capability_bootstrap_preserves_terminal_child_failure_before_relay_cleanup() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_events = &[DW_SIGNAL_PEER_CLOSED];
    supervisor.termination_state = DW_TASK_STATE_RUNNING;
    supervisor.exit_on_query = Some(2);
    supervisor.termination_application_code = 0x2408_0130;

    assert_eq!(
        run_init0_capability_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::Supervision(SupervisionError::Exit(
            wyrmroot_runtime::ExitValidationError::NonzeroApplicationCode(0x2408_0130),
        )))
    );
    assert!(loader.terminated.is_empty());
}

#[cfg(feature = "i-capability-relay")]
#[test]
fn capability_bootstrap_rejects_noncontiguous_or_capability_bearing_relay_records() {
    let image = executable();
    let mut sequence_fixture = Fixture::valid();
    sequence_fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    sequence_fixture.relay_records = vec![wrcap1_record(1, 1)];
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_events = &WRCAP1_READABLE_EVENTS;
    assert_eq!(
        run_init0_capability_bootstrap(
            &mut sequence_fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::UnexpectedSequence
        ))
    );
    assert_eq!(supervisor.received, 0);

    let mut handle_fixture = Fixture::valid();
    handle_fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    handle_fixture.relay_records = vec![wrcap1_record(0, 1)];
    handle_fixture.relay_handle_count = 1;
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_events = &WRCAP1_READABLE_EVENTS;
    assert_eq!(
        run_init0_capability_bootstrap(
            &mut handle_fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::CapabilityBearing
        ))
    );
    assert_eq!(supervisor.received, 0);

    let mut invalid_wait_fixture = Fixture::valid();
    invalid_wait_fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_invalid_wait_result = true;
    assert_eq!(
        run_init0_capability_bootstrap(
            &mut invalid_wait_fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::InvalidWaitResult
        ))
    );
    assert_eq!(supervisor.received, 0);

    let mut extra_fixture = Fixture::valid();
    extra_fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut extra = wrcap1_record(0, 1);
    extra.push(b'X');
    extra_fixture.relay_records = vec![extra];
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_events = &WRCAP1_READABLE_EVENTS;
    assert_eq!(
        run_init0_capability_bootstrap(
            &mut extra_fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::ReceiveCounts(ReceiveCounts {
            bytes: WRCAP1_RECORD_SIZE + 1,
            handles: 0,
        }))
    );
    assert_eq!(supervisor.received, 0);
}

#[cfg(feature = "i-capability-relay")]
#[test]
fn capability_bootstrap_waits_each_record_and_rejects_terminal_or_racing_receives() {
    let image = executable();

    let mut would_block_fixture = Fixture::valid();
    would_block_fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    would_block_fixture.relay_records = vec![wrcap1_record(0, 1)];
    would_block_fixture.relay_receive_error = Some(NativeError::Status(DW_STATUS_WOULD_BLOCK));
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_events = &WRCAP1_READABLE_EVENTS;
    assert_eq!(
        run_init0_capability_bootstrap(
            &mut would_block_fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::ReceiveWouldBlock
        ))
    );
    assert_eq!(supervisor.received, 0);

    let mut peer_closed_fixture = Fixture::valid();
    peer_closed_fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_events = &[DW_SIGNAL_PEER_CLOSED];
    assert_eq!(
        run_init0_capability_bootstrap(
            &mut peer_closed_fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::PeerClosed
        ))
    );
    assert_eq!(supervisor.received, 0);

    let mut timeout_fixture = Fixture::valid();
    timeout_fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_wait_error = Some(NativeError::Status(DW_STATUS_TIMED_OUT));
    assert_eq!(
        run_init0_capability_bootstrap(
            &mut timeout_fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::CapabilityRelay(Wrcap1RelayError::TimedOut))
    );
    assert_eq!(supervisor.received, 0);

    let mut partial_fixture = Fixture::valid();
    partial_fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    partial_fixture.relay_records = vec![wrcap1_record(0, 1)[..16].to_vec()];
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_events = &WRCAP1_READABLE_EVENTS;
    assert_eq!(
        run_init0_capability_bootstrap(
            &mut partial_fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::MalformedFraming
        ))
    );
    assert_eq!(supervisor.received, 0);
}

#[cfg(feature = "i-capability-relay")]
#[test]
fn capability_bootstrap_rejects_a_sixteenth_record_through_ordinary_ready_validation() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    fixture.relay_records = WRCAP1_KINDS
        .into_iter()
        .enumerate()
        .map(|(sequence, kind)| wrcap1_record(sequence as u32, kind))
        .collect();
    let expected_records = fixture.relay_records.concat();
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.relay_events = &WRCAP1_READABLE_EVENTS;
    supervisor.ready_receive_counts = Some(ReceiveCounts {
        bytes: WRCAP1_RECORD_SIZE,
        handles: 0,
    });

    assert_eq!(
        run_init0_capability_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::Supervision(
            SupervisionError::InvalidReadyReceive(ReceiveCounts {
                bytes: WRCAP1_RECORD_SIZE,
                handles: 0,
            })
        ))
    );
    assert_eq!(fixture.relay_index, WRCAP1_RECORD_COUNT);
    assert_eq!(supervisor.relay_index, WRCAP1_RECORD_COUNT);
    assert_eq!(fixture.sent, expected_records);
}

#[cfg(feature = "i-capability-relay")]
fn wrcap1_record(sequence: u32, kind: u8) -> Vec<u8> {
    let prefix = format!(
        "WRCAP1|01|0000000000000001|{sequence:08X}|{kind:02X}|00000000|00000001|0000000000000001|0000000000000000|0000000000000000|"
    );
    let checksum = fnv1a32(prefix.as_bytes());
    let record = format!("{prefix}{checksum:08X}\n");
    assert_eq!(record.len(), WRCAP1_RECORD_SIZE);
    record.into_bytes()
}

#[cfg(feature = "i-capability-relay")]
fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5_u32, |hash, &byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
    })
}

#[test]
fn primordial_bootstrap_rejects_missing_hello_without_launching_a_fallback() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image)]);
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();

    assert_eq!(
        run_init0_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::MissingRequiredEntry)
    );
    assert!(loader.init_profiles.is_empty());
    assert_eq!(supervisor.received, 0);
    assert!(fixture.sent.is_empty());
    assert_eq!(fixture.closed, [ROOT, BOOTFS, TASK_GROUP]);
}

#[test]
fn malformed_elf_variant_fails_before_publishing_init0() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();

    assert!(matches!(
        run_init0_bootstrap_with_fault(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
            LoadFault::MalformedElf,
        ),
        Err(BootstrapError::Loader(LoadError::Elf(_)))
    ));
    assert!(loader.init_profiles.is_empty());
    assert_eq!(supervisor.received, 0);
    assert!(fixture.sent.is_empty());
}

#[test]
fn i0_negative_terminal_details_are_unique_and_failure_class_bound() {
    let elf = BootstrapError::Loader(LoadError::Elf(ElfError::BadMagic));
    let startup = BootstrapError::Supervision(SupervisionError::Exit(
        ExitValidationError::NonzeroApplicationCode(startup_error_exit_code(
            StartupError::StringPointerOutOfRange,
        )),
    ));
    let count = BootstrapError::Supervision(SupervisionError::Exit(
        ExitValidationError::NonzeroApplicationCode(0x1000_0307),
    ));
    let capability = BootstrapError::Supervision(SupervisionError::Exit(
        ExitValidationError::NonzeroApplicationCode(0x1000_0330),
    ));
    assert_eq!(
        i0_negative_terminal_detail(LoadFault::MalformedElf, &elf),
        Some(I0_NEGATIVE_MALFORMED_ELF_DETAIL)
    );
    assert_eq!(
        i0_negative_terminal_detail(LoadFault::MalformedStartup, &startup),
        Some(I0_NEGATIVE_MALFORMED_STARTUP_DETAIL)
    );
    assert_eq!(
        i0_negative_terminal_detail(LoadFault::InitCapabilityCount, &count),
        Some(I0_NEGATIVE_CAPABILITY_COUNT_DETAIL)
    );
    assert_eq!(
        i0_negative_terminal_detail(LoadFault::InitCapabilityType, &capability),
        Some(I0_NEGATIVE_CAPABILITY_TYPE_DETAIL)
    );
    assert_eq!(
        i0_negative_terminal_detail(LoadFault::InitCapabilityRights, &capability),
        Some(I0_NEGATIVE_CAPABILITY_RIGHTS_DETAIL)
    );
    assert_ne!(
        I0_NEGATIVE_CAPABILITY_TYPE_DETAIL,
        I0_NEGATIVE_CAPABILITY_RIGHTS_DETAIL
    );
    assert_eq!(
        i0_negative_terminal_detail(LoadFault::MalformedStartup, &capability),
        None
    );
}

#[test]
fn primordial_bootstrap_closes_exited_init0_without_redundant_termination() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::exited_before_ready();

    assert!(matches!(
        run_init0_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::Supervision(_))
    ));
    assert!(loader.terminated.is_empty());
    assert!(fixture.sent.is_empty());
    assert_eq!(
        fixture.closed,
        [DwHandle(42), DwHandle(43), ROOT, BOOTFS, TASK_GROUP]
    );
}

#[test]
fn primordial_bootstrap_terminates_init0_after_unproven_readiness_failure() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.ready_handle_count = 1;
    supervisor.termination_state = DW_TASK_STATE_RUNNING;

    assert!(matches!(
        run_init0_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::Supervision(_))
    ));
    assert_eq!(loader.terminated, [DwHandle(43)]);
    assert!(fixture.sent.is_empty());
    assert_eq!(
        fixture.closed,
        [DwHandle(42), DwHandle(43), ROOT, BOOTFS, TASK_GROUP]
    );
}

#[test]
fn primordial_bootstrap_rechecks_a_late_exit_before_termination() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.ready_handle_count = 1;

    assert!(matches!(
        run_init0_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::Supervision(_))
    ));
    assert!(loader.terminated.is_empty());
    assert!(fixture.sent.is_empty());
    assert_eq!(
        fixture.closed,
        [DwHandle(42), DwHandle(43), ROOT, BOOTFS, TASK_GROUP]
    );
}

#[test]
fn primordial_bootstrap_reconciles_exit_racing_failed_termination() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut loader = SmokeLoader::init0();
    loader.fail_terminate = true;
    let mut supervisor = SmokeSupervisor::successful_init0();
    supervisor.ready_handle_count = 1;
    supervisor.termination_state = DW_TASK_STATE_RUNNING;
    supervisor.exit_on_query = Some(2);

    assert!(matches!(
        run_init0_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::Supervision(_))
    ));
    assert_eq!(loader.terminated, [DwHandle(43)]);
    assert_eq!(supervisor.termination_queries, 2);
    assert_eq!(
        fixture.closed,
        [DwHandle(42), DwHandle(43), ROOT, BOOTFS, TASK_GROUP]
    );
}

#[test]
fn primordial_bootstrap_closes_exited_init0_when_termination_query_fails() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(INIT0_PATH, &image), (HELLO_PATH, b"hello")]);
    let mut loader = SmokeLoader::init0();
    let mut supervisor = SmokeSupervisor::exited_before_ready();
    supervisor.termination_query_error = true;

    assert_eq!(
        run_init0_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::Supervision(SupervisionError::ExitQuery(
            NativeError::Status(DW_STATUS_BAD_HANDLE)
        )))
    );
    assert!(loader.terminated.is_empty());
    assert_eq!(
        fixture.closed,
        [DwHandle(42), DwHandle(43), ROOT, BOOTFS, TASK_GROUP]
    );
}

#[cfg(feature = "loader-smoke-integration")]
#[test]
fn loader_smoke_runs_hello_then_exits_before_primordial_ready() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(LOADER_SMOKE_PATH, &image)]);
    let mut loader = SmokeLoader::new();
    let mut supervisor = SmokeSupervisor::successful();

    assert_eq!(
        run_loader_smoke_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Ok(())
    );
    assert_eq!(loader.init_profiles, [launch::LaunchProfile::Hello]);
    assert_eq!(supervisor.received, 1);
    assert_eq!(
        decode(&fixture.sent, 0),
        Ok(BootstrapMessage::ReadyV2(ReadyMessageV2 {
            transaction_id: 1
        }))
    );
    assert_eq!(
        fixture.closed,
        [
            DwHandle(42),
            DwHandle(43),
            ROOT,
            BOOTFS,
            TASK_GROUP,
            CHANNEL
        ]
    );
}

#[cfg(feature = "loader-smoke-integration")]
#[test]
fn loader_smoke_closes_an_exited_child_without_redundant_termination() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(LOADER_SMOKE_PATH, &image)]);
    let mut loader = SmokeLoader::new();
    let mut supervisor = SmokeSupervisor::exited_before_ready();

    assert!(matches!(
        run_loader_smoke_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::Supervision(_))
    ));
    assert!(loader.terminated.is_empty());
    assert_eq!(fixture.sent, []);
    assert_eq!(
        fixture.closed,
        [DwHandle(42), DwHandle(43), ROOT, BOOTFS, TASK_GROUP]
    );
}

#[cfg(feature = "loader-smoke-integration")]
#[test]
fn loader_smoke_surfaces_cleanup_failure_after_unproven_readiness_failure() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(LOADER_SMOKE_PATH, &image)]);
    let mut loader = SmokeLoader::new();
    loader.fail_terminate = true;
    let mut supervisor = SmokeSupervisor::successful();
    supervisor.ready_handle_count = 1;
    supervisor.termination_state = DW_TASK_STATE_RUNNING;

    assert_eq!(
        run_loader_smoke_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::Cleanup(ChildCleanupError {
            stage: ChildCleanupStage::ProcessTerminate,
            cause: NativeError::Status(DW_STATUS_BAD_HANDLE),
        }))
    );
    assert_eq!(loader.terminated, [DwHandle(43)]);
    assert!(fixture.sent.is_empty());
}

#[cfg(feature = "loader-smoke-integration")]
#[test]
fn loader_smoke_mapping_teardown_failure_still_terminates_and_closes_the_child() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(LOADER_SMOKE_PATH, &image)]);
    fixture.mapping_error_after_callback = true;
    let mut loader = SmokeLoader::new();
    let mut supervisor = SmokeSupervisor::successful();

    assert_eq!(
        run_loader_smoke_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::Native(NativeError::Status(
            DW_STATUS_BAD_HANDLE
        )))
    );
    assert_eq!(loader.terminated, [DwHandle(43)]);
    assert_eq!(supervisor.received, 0);
    assert!(fixture.sent.is_empty());
    assert_eq!(
        fixture.closed,
        [DwHandle(42), DwHandle(43), ROOT, BOOTFS, TASK_GROUP]
    );
}

fn executable() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x2000];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put16(&mut bytes, 16, 2);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, 0x400000);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 1);
    put32(&mut bytes, 64, 1);
    put32(&mut bytes, 68, 5);
    put64(&mut bytes, 72, 0x1000);
    put64(&mut bytes, 80, 0x400000);
    put64(&mut bytes, 88, 0x400000);
    put64(&mut bytes, 96, 16);
    put64(&mut bytes, 104, 32);
    put64(&mut bytes, 112, 4096);
    bytes
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
