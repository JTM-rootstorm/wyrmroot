use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_OBJECT_TYPE_TASK_GROUP, DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DW_TASK_STATE_EXITED, DW_TASK_TERMINATION_INFO_V1_SIZE, DW_TERMINATION_NORMAL_EXIT,
    DW_WAIT_RESULT_V1_SIZE, DwDeadline, DwHandle, DwHandleTransferV1, DwMemoryProtection,
    DwObjectType, DwReceivedHandleInfoV1, DwRights, DwTaskTerminationInfoV1, DwWaitItemV1,
    DwWaitResultV1,
};
use wyrmroot_bootfs::builder::{Builder, FileMode};
use wyrmroot_init0::{HELLO_PATH, Init0Error, Init0System, run_init0};
use wyrmroot_loader::{
    launch::{self, LaunchProfile, encode_init, parse_ready},
    process::{LoaderPlatform, ParentMapping, ProcessCreateRequest, ProcessCreateResult},
};
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo,
    LOADER_TASK_GROUP_EXPECTATION, MappingPlan, NativeError, ReceiveCounts, SELF_ROOT_EXPECTATION,
    SupervisionPlatform,
};

const CHANNEL: DwHandle = DwHandle(11);
const ROOT: DwHandle = DwHandle(21);
const BOOTFS: DwHandle = DwHandle(22);
const TASK_GROUP: DwHandle = DwHandle(23);
const DEADLINE: DwDeadline = DwDeadline(99);

struct Fixture {
    init: [u8; 64],
    bootfs: Vec<u8>,
    fresh_bootfs_rights: DwRights,
    sent: Vec<u8>,
    closed: Vec<DwHandle>,
}

impl Fixture {
    fn valid() -> Self {
        let mut init = [0_u8; 64];
        encode_init(LaunchProfile::Init0, 7, &mut init).unwrap();
        Self {
            init,
            bootfs: bootfs(&[(HELLO_PATH, &executable())]),
            fresh_bootfs_rights: BOOTFS_EXPECTATION.rights,
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
        handles.copy_from_slice(&[
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
        ]);
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
        Ok(use_bytes(&self.bootfs))
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

struct Loader {
    next: u64,
    creates: Vec<ProcessCreateRequest>,
    duplicate_sources: Vec<DwHandle>,
    hello_init: bool,
    terminated: Vec<DwHandle>,
}

impl Loader {
    fn new() -> Self {
        Self {
            next: 40,
            creates: Vec::new(),
            duplicate_sources: Vec::new(),
            hello_init: false,
            terminated: Vec::new(),
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
        Ok(())
    }
}

struct Supervisor {
    application_code: u32,
    phase: usize,
}

impl Supervisor {
    fn successful() -> Self {
        Self {
            application_code: 0,
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
        let observed = match self.phase {
            0 => DW_SIGNAL_READABLE,
            1 => DW_SIGNAL_EXITED,
            2 => DW_SIGNAL_PEER_CLOSED,
            _ => panic!("unexpected wait"),
        };
        let index = if self.phase == 1 { 1 } else { 0 };
        assert_eq!(items.len(), if self.phase == 2 { 1 } else { 2 });
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
        let bytes = launch::encode_ready(2, bytes).unwrap();
        Ok(ReceiveCounts { bytes, handles: 0 })
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
    assert_eq!(loader.creates[0].task_group, TASK_GROUP);
    assert!(loader.hello_init);
    assert!(!loader.duplicate_sources.contains(&ROOT));
    assert!(!loader.duplicate_sources.contains(&BOOTFS));
    assert!(!loader.duplicate_sources.contains(&TASK_GROUP));
    assert!(loader.terminated.is_empty());
    assert_eq!(parse_ready(&fixture.sent, 7), Ok(()));
}

#[test]
fn init0_rejects_a_nonzero_hello_exit_without_reporting_ready() {
    let mut fixture = Fixture::valid();
    let mut loader = Loader::new();
    let mut supervisor = Supervisor::successful();
    supervisor.application_code = 7;

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
    assert_eq!(loader.terminated.len(), 1);
    assert!(fixture.sent.is_empty());
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
