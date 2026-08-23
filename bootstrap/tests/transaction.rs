use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_OBJECT_TYPE_TASK_GROUP, DW_STATUS_BAD_HANDLE, DwHandle, DwObjectType,
    DwReceivedHandleInfoV1, DwRights,
};
use deepwyrm_syscall::{
    DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_TASK_STATE_EXITED,
    DW_TASK_TERMINATION_INFO_V1_SIZE, DW_TERMINATION_NORMAL_EXIT, DwDeadline, DwHandleTransferV1,
    DwMemoryProtection, DwTaskTerminationInfoV1, DwWaitItemV1, DwWaitResultV1,
};
use wyrmroot_bootfs::builder::{Builder, FileMode};
#[cfg(feature = "primordial-test-support")]
use wyrmroot_bootstrap::run_bootstrap_with_before_ready;
use wyrmroot_bootstrap::{
    BootstrapError, BootstrapSystem, HELLO_PATH, INIT0_PATH, run_bootstrap, run_init0_bootstrap,
};
#[cfg(feature = "loader-smoke-integration")]
use wyrmroot_bootstrap::{
    LOADER_SMOKE_PATH, LOADER_SMOKE_TRANSACTION_ID, run_loader_smoke_bootstrap,
};
use wyrmroot_bootstrap_proto::{
    BOOTSTRAP_INIT_V2_SIZE, BootstrapMessage, InitMessageV2, ReadyMessageV2, decode,
};
use wyrmroot_loader::{
    launch,
    process::{
        LoadError, LoadStage, LoaderPlatform, ParentMapping, ProcessCreateRequest,
        ProcessCreateResult,
    },
};
use wyrmroot_runtime::SupervisionPlatform;
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo,
    LOADER_TASK_GROUP_EXPECTATION, MappingPlan, NativeError, ReceiveCounts, SELF_ROOT_EXPECTATION,
};

const CHANNEL: DwHandle = DwHandle(11);
const ROOT: DwHandle = DwHandle(21);
const BOOTFS: DwHandle = DwHandle(22);
const TASK_GROUP: DwHandle = DwHandle(23);

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
        assert_eq!(channel, CHANNEL);
        bytes[..self.init_size].copy_from_slice(&self.init[..self.init_size]);
        handles[..3].copy_from_slice(&self.handles);
        Ok(ReceiveCounts {
            bytes: self.init_size,
            handles: 3,
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
            launch::LaunchProfile::Hello => {
                assert!(transfers.is_empty());
                &received[..0]
            }
            launch::LaunchProfile::Init0 => {
                assert_eq!(transfers.len(), 3);
                assert!(transfers.iter().all(|transfer| {
                    transfer.operation == deepwyrm_syscall::DW_HANDLE_TRANSFER_MOVE
                }));
                &received[..]
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
    transaction_id: u64,
}

impl SmokeSupervisor {
    fn successful() -> Self {
        Self {
            events: &[true, false],
            index: 0,
            received: 0,
            transaction_id: 2,
        }
    }

    fn successful_init0() -> Self {
        Self {
            transaction_id: 1,
            ..Self::successful()
        }
    }

    fn exited_before_ready() -> Self {
        Self {
            events: &[false],
            index: 0,
            received: 0,
            transaction_id: 2,
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
        let size = launch::encode_ready(self.transaction_id, bytes)
            .map_err(|_| NativeError::Status(DW_STATUS_BAD_HANDLE))?;
        Ok(ReceiveCounts {
            bytes: size,
            handles: 0,
        })
    }

    fn query_task_termination(
        &mut self,
        _: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
        Ok(DwTaskTerminationInfoV1 {
            size: DW_TASK_TERMINATION_INFO_V1_SIZE,
            version: 1,
            state: DW_TASK_STATE_EXITED,
            reason: DW_TERMINATION_NORMAL_EXIT,
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
fn primordial_bootstrap_terminates_init0_after_bounded_readiness_failure() {
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
    assert_eq!(loader.terminated, [DwHandle(43)]);
    assert!(fixture.sent.is_empty());
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
fn loader_smoke_failure_terminates_and_closes_child_before_authority_cleanup() {
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
    assert_eq!(loader.terminated, [DwHandle(43)]);
    assert_eq!(fixture.sent, []);
    assert_eq!(
        fixture.closed,
        [DwHandle(42), DwHandle(43), ROOT, BOOTFS, TASK_GROUP]
    );
}

#[cfg(feature = "loader-smoke-integration")]
#[test]
fn loader_smoke_surfaces_cleanup_failure_after_supervision_failure() {
    let image = executable();
    let mut fixture = Fixture::valid();
    fixture.bootfs = bootfs(&[(LOADER_SMOKE_PATH, &image)]);
    let mut loader = SmokeLoader::new();
    loader.fail_terminate = true;
    let mut supervisor = SmokeSupervisor::exited_before_ready();

    assert_eq!(
        run_loader_smoke_bootstrap(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DwDeadline(99),
        ),
        Err(BootstrapError::Cleanup(NativeError::Status(
            DW_STATUS_BAD_HANDLE
        )))
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
