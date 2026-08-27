#![cfg_attr(
    any(
        feature = "i-capability-integration",
        feature = "dw1b-preemption-integration"
    ),
    allow(unused_crate_dependencies)
)]
#![cfg(not(any(
    feature = "i-capability-integration",
    feature = "dw1b-preemption-integration"
)))]

// This fixture locks the ordinary `init0 -> hello` profile. The capability selector changes the
// child launch contract and has dedicated feature-gated library tests instead.

use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_OBJECT_TYPE_TASK_GROUP, DW_RIGHT_INSPECT, DW_RIGHT_MAP, DW_RIGHT_MODIFY, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED,
    DW_SIGNAL_READABLE, DW_STATUS_BAD_HANDLE, DW_TASK_STATE_EXITED, DW_TASK_STATE_RUNNING,
    DW_TASK_TERMINATION_INFO_V1_SIZE, DW_TERMINATION_NORMAL_EXIT, DW_WAIT_RESULT_V1_SIZE,
    DwDeadline, DwHandle, DwHandleTransferV1, DwMemoryProtection, DwObjectType,
    DwReceivedHandleInfoV1, DwRights, DwStatus, DwTaskTerminationInfoV1, DwWaitItemV1,
    DwWaitResultV1,
};
use wyrmroot_bootfs::builder::{Builder, FileMode};
use wyrmroot_init0::{HELLO_PATH, Init0Error, Init0System, run_init0};
use wyrmroot_loader::{
    launch::{self, LaunchError, LaunchProfile, encode_init, parse_ready},
    process::{
        LoadError, LoadStage, LoaderPlatform, ParentMapping, ProcessCreateRequest,
        ProcessCreateResult,
    },
};
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, ExitObservedReadinessError,
    ExitValidationError, LOADER_TASK_GROUP_EXPECTATION, MappingPlan, NativeError,
    NativeOutputError, ReceiveCounts, SELF_ROOT_EXPECTATION, SupervisionError, SupervisionPlatform,
};

const CHANNEL: DwHandle = DwHandle(11);
const ROOT: DwHandle = DwHandle(21);
const BOOTFS: DwHandle = DwHandle(22);
const TASK_GROUP: DwHandle = DwHandle(23);
const DEADLINE: DwDeadline = DwDeadline(99);
const CHILD_CHANNEL: DwHandle = DwHandle(42);
const CHILD_PROCESS: DwHandle = DwHandle(43);
const MAPPING_TEARDOWN_FAILURE: NativeError = NativeError::Status(DwStatus(-71));
const TERMINATE_FAILURE: NativeError = NativeError::Status(DwStatus(-72));
const CHILD_CLOSE_FAILURE: NativeError = NativeError::Status(DwStatus(-73));

#[test]
fn live_exit_code_identifies_init0_owned_failure() {
    assert_eq!(Init0Error::MissingHello.exit_code(), 0x1000_0008);
    assert_eq!(
        Init0Error::Launch(LaunchError::BadCapabilityCount).exit_code(),
        0x1000_0307
    );
    assert_eq!(
        Init0Error::Launch(LaunchError::HandleMetadata { index: 0 }).exit_code(),
        0x1000_0330
    );
    assert_eq!(
        Init0Error::Launch(LaunchError::BadCapabilityRole { index: 2 }).exit_code(),
        0x1000_0312
    );
    assert_eq!(
        Init0Error::Cleanup(NativeError::Status(DwStatus(-73))).exit_code(),
        0x1200_0049
    );
    assert_eq!(
        Init0Error::Cleanup(NativeError::Output(NativeOutputError::InvalidWaitResult)).exit_code(),
        0x1200_8006
    );
    assert_eq!(
        Init0Error::Supervision(SupervisionError::Platform(NativeError::Status(DwStatus(
            -7
        ))))
        .exit_code(),
        0x1302_0007
    );
    assert_eq!(
        Init0Error::Supervision(SupervisionError::Exit(ExitValidationError::NotNormalExit,))
            .exit_code(),
        0x130A_0003
    );
    assert_eq!(
        Init0Error::Supervision(SupervisionError::ExitObservedReadiness(
            ExitObservedReadinessError::Ready(LaunchError::TransactionMismatch),
        ))
        .exit_code(),
        0x130B_4009
    );
}

#[test]
fn live_exit_code_exhaustively_encodes_init0_loader_platform_failures() {
    let stages = [
        (LoadStage::ChannelCreate, 1_u32),
        (LoadStage::ChannelReduce, 2),
        (LoadStage::ProcessCreate, 3),
        (LoadStage::MemoryCreate, 4),
        (LoadStage::ParentMaterialize, 5),
        (LoadStage::ParentUnmap, 6),
        (LoadStage::ChildMap, 7),
        (LoadStage::ThreadCreate, 8),
        (LoadStage::CapabilityDuplicate, 9),
        (LoadStage::InitSend, 10),
        (LoadStage::ThreadStart, 11),
        (LoadStage::SuccessCleanup, 12),
    ];
    let outputs = [
        (NativeOutputError::InvalidObjectInfo, 1_u32),
        (NativeOutputError::InvalidMemoryObjectInfo, 2),
        (NativeOutputError::InvalidChannelReceive, 3),
        (NativeOutputError::InvalidMappedRange, 4),
        (NativeOutputError::InvalidLoaderOutput, 5),
        (NativeOutputError::InvalidWaitResult, 6),
        (NativeOutputError::InvalidTaskTerminationInfo, 7),
        (NativeOutputError::DeadlineOverflow, 8),
    ];

    for (stage, stage_code) in stages {
        let status = Init0Error::Loader(LoadError::Platform {
            stage,
            cause: NativeError::Status(DwStatus(-13)),
            rollback_failed: false,
        });
        assert_eq!(status.exit_code(), 0x1100_000D | (stage_code << 16));

        let status_rollback = Init0Error::Loader(LoadError::Platform {
            stage,
            cause: NativeError::Status(DwStatus(-13)),
            rollback_failed: true,
        });
        assert_eq!(
            status_rollback.exit_code(),
            0x1180_000D | (stage_code << 16)
        );

        for (native_output, output_code) in outputs {
            let output = Init0Error::Loader(LoadError::Platform {
                stage,
                cause: NativeError::Output(native_output),
                rollback_failed: false,
            });
            assert_eq!(
                output.exit_code(),
                0x1100_8000 | (stage_code << 16) | output_code
            );

            let output_rollback = Init0Error::Loader(LoadError::Platform {
                stage,
                cause: NativeError::Output(native_output),
                rollback_failed: true,
            });
            assert_eq!(
                output_rollback.exit_code(),
                0x1180_8000 | (stage_code << 16) | output_code
            );
        }
    }

    for status in [DwStatus(-32_769), DwStatus(i32::MIN)] {
        let bounded_status = Init0Error::Loader(LoadError::Platform {
            stage: LoadStage::ChildMap,
            cause: NativeError::Status(status),
            rollback_failed: false,
        });
        assert_eq!(bounded_status.exit_code(), 0x1107_7FFF);
    }
    let output = Init0Error::Loader(LoadError::Platform {
        stage: LoadStage::ChildMap,
        cause: NativeError::Output(NativeOutputError::InvalidObjectInfo),
        rollback_failed: false,
    });
    assert_eq!(output.exit_code(), 0x1107_8001);
}

struct Fixture {
    init: [u8; 64],
    received_handles: [DwReceivedHandleInfoV1; 3],
    bootfs: Vec<u8>,
    fresh_bootfs_rights: DwRights,
    mapping_error_after_callback: bool,
    close_failures: Vec<DwHandle>,
    sent: Vec<u8>,
    closed: Vec<DwHandle>,
}

impl Fixture {
    fn valid() -> Self {
        let mut init = [0_u8; 64];
        encode_init(LaunchProfile::Init0, 7, &mut init).unwrap();
        Self {
            init,
            received_handles: [
                received(
                    ROOT,
                    DW_OBJECT_TYPE_ADDRESS_REGION,
                    SELF_ROOT_EXPECTATION.rights,
                ),
                received(
                    BOOTFS,
                    DW_OBJECT_TYPE_MEMORY_OBJECT,
                    BOOTFS_EXPECTATION.rights,
                ),
                received(
                    TASK_GROUP,
                    DW_OBJECT_TYPE_TASK_GROUP,
                    LOADER_TASK_GROUP_EXPECTATION.rights,
                ),
            ],
            bootfs: bootfs(&[(HELLO_PATH, &executable())]),
            fresh_bootfs_rights: BOOTFS_EXPECTATION.rights,
            mapping_error_after_callback: false,
            close_failures: Vec::new(),
            sent: Vec::new(),
            closed: Vec::new(),
        }
    }
}

impl Init0System for Fixture {
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
                rights: self.fresh_bootfs_rights,
            }),
            TASK_GROUP => Ok(CapabilityInfo {
                object_type: DW_OBJECT_TYPE_TASK_GROUP,
                rights: LOADER_TASK_GROUP_EXPECTATION.rights,
            }),
            _ => panic!("unexpected capability query: {handle:?}"),
        }
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        assert_eq!(channel, CHANNEL);
        bytes.copy_from_slice(&self.init);
        handles.copy_from_slice(&self.received_handles);
        Ok(ReceiveCounts {
            bytes: self.init.len(),
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
        let result = use_bytes(&self.bootfs);
        if self.mapping_error_after_callback {
            return Err(MAPPING_TEARDOWN_FAILURE);
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
        if self.close_failures.contains(&handle) {
            Err(CHILD_CLOSE_FAILURE)
        } else {
            Ok(())
        }
    }
}

struct Loader {
    next: u64,
    creates: Vec<ProcessCreateRequest>,
    duplicate_sources: Vec<DwHandle>,
    hello_init: bool,
    terminated: Vec<DwHandle>,
    terminate_error: Option<NativeError>,
}

impl Loader {
    fn new() -> Self {
        Self {
            next: 40,
            creates: Vec::new(),
            duplicate_sources: Vec::new(),
            hello_init: false,
            terminated: Vec::new(),
            terminate_error: None,
        }
    }

    fn handle(&mut self) -> DwHandle {
        let handle = DwHandle(self.next);
        self.next += 1;
        handle
    }
}

impl LoaderPlatform for Loader {
    type Error = NativeError;

    fn channel_create(&mut self, _: DwRights) -> Result<(DwHandle, DwHandle), Self::Error> {
        Ok((self.handle(), self.handle()))
    }

    fn duplicate(&mut self, handle: DwHandle, _: DwRights) -> Result<DwHandle, Self::Error> {
        self.duplicate_sources.push(handle);
        Ok(self.handle())
    }

    fn close(&mut self, _: DwHandle) -> Result<(), Self::Error> {
        Ok(())
    }

    fn process_create(
        &mut self,
        request: ProcessCreateRequest,
    ) -> Result<ProcessCreateResult, Self::Error> {
        self.creates.push(request);
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
        object_size: u64,
        _: u64,
        _: &[u8],
    ) -> Result<ParentMapping, Self::Error> {
        Ok(ParentMapping {
            address: 0x5000_0000,
            bytes: object_size,
        })
    }

    fn materialize_parent_with(
        &mut self,
        _: DwHandle,
        _: DwHandle,
        object_size: u64,
        _: u64,
        destination_size: usize,
        materialize: impl FnOnce(&mut [u8]),
    ) -> Result<ParentMapping, Self::Error> {
        let mut destination = vec![0; destination_size];
        materialize(&mut destination);
        Ok(ParentMapping {
            address: 0x5000_0000,
            bytes: object_size,
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
        assert!(transfers.is_empty());
        assert_eq!(
            launch::parse_init(LaunchProfile::Hello, bytes, &[])
                .unwrap()
                .transaction_id,
            2
        );
        self.hello_init = true;
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
        self.terminate_error.map_or(Ok(()), Err)
    }
}

struct Supervisor {
    application_code: u32,
    ready_handle_count: usize,
    termination_query_error: bool,
    exit_selected_first: bool,
    malformed_ready_after_exit: bool,
    exit_on_termination_query: Option<usize>,
    termination_queries: usize,
    phase: usize,
}

impl Supervisor {
    fn successful() -> Self {
        Self {
            application_code: 0,
            ready_handle_count: 0,
            termination_query_error: false,
            exit_selected_first: false,
            malformed_ready_after_exit: false,
            exit_on_termination_query: None,
            termination_queries: 0,
            phase: 0,
        }
    }
}

impl SupervisionPlatform for Supervisor {
    type Error = NativeError;

    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, Self::Error> {
        assert_eq!(deadline, DEADLINE);
        let (observed, index, expected_items) = if self.exit_selected_first {
            match self.phase {
                0 => (DW_SIGNAL_EXITED, 1, 2),
                1 => (DW_SIGNAL_READABLE, 0, 1),
                _ => panic!("unexpected exit-first wait"),
            }
        } else {
            match self.phase {
                0 => (DW_SIGNAL_READABLE, 0, 2),
                1 => (DW_SIGNAL_EXITED, 1, 2),
                2 => (DW_SIGNAL_PEER_CLOSED, 0, 1),
                _ => panic!("unexpected wait"),
            }
        };
        assert_eq!(items.len(), expected_items);
        self.phase += 1;
        Ok(DwWaitResultV1 {
            size: DW_WAIT_RESULT_V1_SIZE,
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
        if self.malformed_ready_after_exit {
            bytes.fill(0);
        } else {
            launch::encode_ready(2, bytes).unwrap();
        }
        Ok(ReceiveCounts {
            bytes: bytes.len(),
            handles: self.ready_handle_count,
        })
    }

    fn query_task_termination(
        &mut self,
        _: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
        if self.termination_query_error {
            return Err(NativeError::Status(DW_STATUS_BAD_HANDLE));
        }
        self.termination_queries += 1;
        let state = match self.exit_on_termination_query {
            Some(query) if self.termination_queries < query => DW_TASK_STATE_RUNNING,
            Some(_) => DW_TASK_STATE_EXITED,
            None if self.ready_handle_count != 0 => DW_TASK_STATE_RUNNING,
            None => DW_TASK_STATE_EXITED,
        };
        Ok(DwTaskTerminationInfoV1 {
            size: DW_TASK_TERMINATION_INFO_V1_SIZE,
            version: 1,
            state,
            reason: DW_TERMINATION_NORMAL_EXIT,
            application_code: self.application_code,
            ..DwTaskTerminationInfoV1::default()
        })
    }
}

#[test]
fn init0_launches_hello_in_its_delegated_subtree_and_reports_only_zero_exit() {
    let mut fixture = Fixture::valid();
    let mut loader = Loader::new();
    let mut supervisor = Supervisor::successful();

    assert_eq!(
        run_init0(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DEADLINE
        ),
        Ok(())
    );
    assert_eq!(loader.creates.len(), 1);
    let request = loader.creates[0];
    assert_eq!(request.task_group, TASK_GROUP);
    assert_eq!(
        request.process_rights,
        DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0)
    );
    assert_eq!(
        request.root_rights,
        DwRights(DW_RIGHT_MAP.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0)
    );
    assert_eq!(
        request.child_bootstrap_rights,
        DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0)
    );
    assert!(loader.hello_init);
    assert!(!loader.duplicate_sources.contains(&ROOT));
    assert!(!loader.duplicate_sources.contains(&BOOTFS));
    assert!(!loader.duplicate_sources.contains(&TASK_GROUP));
    assert!(loader.terminated.is_empty());
    assert_eq!(parse_ready(&fixture.sent, 7), Ok(()));
}

#[test]
fn init0_preserves_a_nonzero_hello_exit_and_closes_without_redundant_termination() {
    let mut fixture = Fixture::valid();
    let mut loader = Loader::new();
    let mut supervisor = Supervisor::successful();
    supervisor.application_code = 7;

    assert_eq!(
        run_init0(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DEADLINE
        ),
        Err(Init0Error::Supervision(
            wyrmroot_runtime::SupervisionError::Exit(
                wyrmroot_runtime::ExitValidationError::NonzeroApplicationCode(7)
            )
        ))
    );
    assert!(loader.terminated.is_empty());
    assert_eq!(
        fixture.closed,
        [CHILD_CHANNEL, CHILD_PROCESS, ROOT, BOOTFS, TASK_GROUP]
    );
    assert!(fixture.sent.is_empty());
}

#[test]
fn init0_terminates_hello_after_unproven_readiness_failure() {
    let mut fixture = Fixture::valid();
    let mut loader = Loader::new();
    let mut supervisor = Supervisor::successful();
    supervisor.ready_handle_count = 1;

    assert!(matches!(
        run_init0(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DEADLINE
        ),
        Err(Init0Error::Supervision(_))
    ));
    assert_eq!(loader.terminated, [CHILD_PROCESS]);
    assert_eq!(
        fixture.closed,
        [CHILD_CHANNEL, CHILD_PROCESS, ROOT, BOOTFS, TASK_GROUP]
    );
    assert!(fixture.sent.is_empty());
}

#[test]
fn init0_closes_post_ready_exited_hello_when_termination_query_fails() {
    let mut fixture = Fixture::valid();
    let mut loader = Loader::new();
    let mut supervisor = Supervisor::successful();
    supervisor.termination_query_error = true;

    assert_eq!(
        run_init0(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DEADLINE
        ),
        Err(Init0Error::Supervision(
            wyrmroot_runtime::SupervisionError::ExitQuery(NativeError::Status(
                DW_STATUS_BAD_HANDLE
            ))
        ))
    );
    assert!(loader.terminated.is_empty());
    assert_eq!(
        fixture.closed,
        [CHILD_CHANNEL, CHILD_PROCESS, ROOT, BOOTFS, TASK_GROUP]
    );
}

#[test]
fn init0_closes_exit_observed_malformed_terminal_ready_without_retermination() {
    let mut fixture = Fixture::valid();
    let mut loader = Loader::new();
    let mut supervisor = Supervisor::successful();
    supervisor.exit_selected_first = true;
    supervisor.malformed_ready_after_exit = true;

    assert_eq!(
        run_init0(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DEADLINE
        ),
        Err(Init0Error::Supervision(
            wyrmroot_runtime::SupervisionError::ExitObservedReadiness(
                wyrmroot_runtime::ExitObservedReadinessError::Ready(LaunchError::BadMagic)
            )
        ))
    );
    assert!(loader.terminated.is_empty());
    assert_eq!(
        fixture.closed,
        [CHILD_CHANNEL, CHILD_PROCESS, ROOT, BOOTFS, TASK_GROUP]
    );
    assert!(fixture.sent.is_empty());
}

#[test]
fn init0_mapping_teardown_failure_terminates_and_closes_hello_before_authority_cleanup() {
    let mut fixture = Fixture::valid();
    fixture.mapping_error_after_callback = true;
    let mut loader = Loader::new();
    let mut supervisor = Supervisor::successful();

    assert_eq!(
        run_init0(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DEADLINE
        ),
        Err(Init0Error::Native(MAPPING_TEARDOWN_FAILURE))
    );
    assert_eq!(loader.terminated, [CHILD_PROCESS]);
    assert_eq!(
        fixture.closed,
        [CHILD_CHANNEL, CHILD_PROCESS, ROOT, BOOTFS, TASK_GROUP]
    );
    assert!(fixture.sent.is_empty());
}

#[test]
fn init0_cleanup_prefers_termination_failure_and_still_closes_children_first() {
    let mut fixture = Fixture::valid();
    fixture.close_failures = vec![CHILD_CHANNEL, CHILD_PROCESS];
    let mut loader = Loader::new();
    loader.terminate_error = Some(TERMINATE_FAILURE);
    let mut supervisor = Supervisor::successful();
    supervisor.ready_handle_count = 1;

    assert_eq!(
        run_init0(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DEADLINE
        ),
        Err(Init0Error::Cleanup(TERMINATE_FAILURE))
    );
    assert_eq!(loader.terminated, [CHILD_PROCESS]);
    assert_eq!(
        fixture.closed,
        [CHILD_CHANNEL, CHILD_PROCESS, ROOT, BOOTFS, TASK_GROUP]
    );
    assert!(fixture.sent.is_empty());
}

#[test]
fn init0_reconciles_an_exit_racing_failed_termination_without_masking_supervision() {
    let mut fixture = Fixture::valid();
    let mut loader = Loader::new();
    loader.terminate_error = Some(TERMINATE_FAILURE);
    let mut supervisor = Supervisor::successful();
    supervisor.ready_handle_count = 1;
    supervisor.exit_on_termination_query = Some(2);

    assert!(matches!(
        run_init0(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DEADLINE
        ),
        Err(Init0Error::Supervision(
            SupervisionError::InvalidReadyReceive(_)
        ))
    ));
    assert_eq!(supervisor.termination_queries, 2);
    assert_eq!(loader.terminated, [CHILD_PROCESS]);
    assert_eq!(
        fixture.closed,
        [CHILD_CHANNEL, CHILD_PROCESS, ROOT, BOOTFS, TASK_GROUP]
    );
}

#[test]
fn init0_preserves_terminal_detail_from_an_exit_racing_failed_termination() {
    let mut fixture = Fixture::valid();
    let mut loader = Loader::new();
    loader.terminate_error = Some(TERMINATE_FAILURE);
    let mut supervisor = Supervisor::successful();
    supervisor.ready_handle_count = 1;
    supervisor.application_code = 0x2402_8c0d;
    supervisor.exit_on_termination_query = Some(2);

    assert_eq!(
        run_init0(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DEADLINE
        ),
        Err(Init0Error::Supervision(SupervisionError::Exit(
            ExitValidationError::NonzeroApplicationCode(0x2402_8c0d)
        )))
    );
    assert_eq!(supervisor.termination_queries, 2);
    assert_eq!(loader.terminated, [CHILD_PROCESS]);
}

#[test]
fn init0_rejects_stale_bootfs_rights_before_descendant_creation() {
    let mut fixture = Fixture::valid();
    fixture.fresh_bootfs_rights = DwRights(0);
    let mut loader = Loader::new();
    let mut supervisor = Supervisor::successful();

    assert!(matches!(
        run_init0(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DEADLINE
        ),
        Err(Init0Error::Capability(
            wyrmroot_runtime::CapabilityValidationError::InvalidFreshCapability
        ))
    ));
    assert!(loader.creates.is_empty());
    assert!(fixture.sent.is_empty());
}

#[test]
fn init0_rejects_a_non_init0_launch_before_descendant_creation() {
    let mut fixture = Fixture::valid();
    encode_init(LaunchProfile::Hello, 7, &mut fixture.init).unwrap();
    let mut loader = Loader::new();
    let mut supervisor = Supervisor::successful();

    assert!(matches!(
        run_init0(
            &mut fixture,
            &mut loader,
            &mut supervisor,
            CHANNEL,
            DEADLINE
        ),
        Err(Init0Error::Launch(_))
    ));
    assert!(loader.creates.is_empty());
    assert!(fixture.sent.is_empty());
}

#[test]
fn init0_preserves_distinct_init_parser_failures_before_descendant_creation() {
    let mut count_fixture = Fixture::valid();
    count_fixture.init[20..24].copy_from_slice(&2_u32.to_le_bytes());
    assert_init_parser_failure(
        count_fixture,
        Init0Error::Launch(LaunchError::BadCapabilityCount),
        0x1000_0307,
    );

    let mut type_fixture = Fixture::valid();
    type_fixture.received_handles[0].object_type = DW_OBJECT_TYPE_TASK_GROUP;
    assert_init_parser_failure(
        type_fixture,
        Init0Error::Launch(LaunchError::HandleMetadata { index: 0 }),
        0x1000_0330,
    );

    let mut rights_fixture = Fixture::valid();
    rights_fixture.received_handles[0].rights = DwRights(0);
    assert_init_parser_failure(
        rights_fixture,
        Init0Error::Launch(LaunchError::HandleMetadata { index: 0 }),
        0x1000_0330,
    );
}

fn assert_init_parser_failure(fixture: Fixture, expected: Init0Error, expected_exit: u32) {
    let mut loader = Loader::new();
    let mut supervisor = Supervisor::successful();
    let mut fixture = fixture;
    let error = run_init0(
        &mut fixture,
        &mut loader,
        &mut supervisor,
        CHANNEL,
        DEADLINE,
    )
    .expect_err("init parser failure was accepted");
    assert_eq!(error, expected);
    assert_eq!(error.exit_code(), expected_exit);
    assert!(loader.creates.is_empty());
    assert!(fixture.sent.is_empty());
}

fn received(
    handle: DwHandle,
    object_type: DwObjectType,
    rights: DwRights,
) -> DwReceivedHandleInfoV1 {
    DwReceivedHandleInfoV1 {
        handle,
        object_type,
        rights,
        ..DwReceivedHandleInfoV1::default()
    }
}

fn bootfs(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut builder = Builder::new();
    for (path, bytes) in entries {
        builder.add(path, bytes, FileMode::Executable).unwrap();
    }
    builder.build().unwrap()
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
