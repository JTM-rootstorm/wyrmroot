use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_STATUS_BAD_HANDLE, DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights,
};
use wyrmroot_bootfs::builder::{Builder, FileMode};
#[cfg(feature = "primordial-test-support")]
use wyrmroot_bootstrap::run_bootstrap_with_before_ready;
use wyrmroot_bootstrap::{BootstrapError, BootstrapSystem, HELLO_PATH, INIT0_PATH, run_bootstrap};
use wyrmroot_bootstrap_proto::{
    BOOTSTRAP_INIT_V1_SIZE, BootstrapMessage, InitMessage, ReadyMessage, decode,
};
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, MappingPlan, NativeError,
    ReceiveCounts, SELF_ROOT_EXPECTATION,
};

const CHANNEL: DwHandle = DwHandle(11);
const ROOT: DwHandle = DwHandle(21);
const BOOTFS: DwHandle = DwHandle(22);

struct Fixture {
    init: [u8; BOOTSTRAP_INIT_V1_SIZE],
    init_size: usize,
    handles: [DwReceivedHandleInfoV1; 2],
    bootfs: Vec<u8>,
    sent: Vec<u8>,
    closed: Vec<DwHandle>,
    mapped: bool,
}

impl Fixture {
    fn valid() -> Self {
        let mut init = [0_u8; BOOTSTRAP_INIT_V1_SIZE];
        let init_size = InitMessage::primordial().encode_into(&mut init).unwrap();
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
            ],
            bootfs: bootfs(&[(HELLO_PATH, b"hello"), (INIT0_PATH, b"init0")]),
            sent: Vec::new(),
            closed: Vec::new(),
            mapped: false,
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
        handles[..2].copy_from_slice(&self.handles);
        Ok(ReceiveCounts {
            bytes: self.init_size,
            handles: 2,
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
        Ok(BootstrapMessage::Ready(ReadyMessage { transaction_id: 1 }))
    );
    assert_eq!(fixture.closed, [ROOT, BOOTFS, CHANNEL]);
}

#[test]
fn malformed_protocol_closes_received_handles_without_ready() {
    let mut fixture = Fixture::valid();
    fixture.init[0] = b'X';
    assert!(matches!(
        run_bootstrap(&mut fixture, CHANNEL),
        Err(BootstrapError::Protocol(_))
    ));
    assert_eq!(fixture.closed, [ROOT, BOOTFS]);
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
    assert_eq!(fixture.closed, [ROOT, BOOTFS]);
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
    assert_eq!(fixture.closed, [ROOT, BOOTFS]);
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
    assert_eq!(missing.closed, [ROOT, BOOTFS]);
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
