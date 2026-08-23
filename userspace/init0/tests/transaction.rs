use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_OBJECT_TYPE_TASK_GROUP, DW_STATUS_BAD_HANDLE, DwHandle, DwObjectType,
    DwReceivedHandleInfoV1, DwRights,
};
use wyrmroot_init0::{Init0Error, Init0System, run_init0};
use wyrmroot_loader::launch::{LaunchProfile, encode_init, parse_ready};
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo,
    LOADER_TASK_GROUP_EXPECTATION, NativeError, ReceiveCounts, SELF_ROOT_EXPECTATION,
};

const CHANNEL: DwHandle = DwHandle(11);
const ROOT: DwHandle = DwHandle(21);
const BOOTFS: DwHandle = DwHandle(22);
const TASK_GROUP: DwHandle = DwHandle(23);

struct Fixture {
    init: [u8; 64],
    handles: [DwReceivedHandleInfoV1; 3],
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
            handles: [
                DwReceivedHandleInfoV1 {
                    handle: ROOT,
                    object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
                    rights: SELF_ROOT_EXPECTATION.rights,
                    ..DwReceivedHandleInfoV1::default()
                },
                DwReceivedHandleInfoV1 {
                    handle: BOOTFS,
                    object_type: DW_OBJECT_TYPE_MEMORY_OBJECT,
                    rights: BOOTFS_EXPECTATION.rights,
                    ..DwReceivedHandleInfoV1::default()
                },
                DwReceivedHandleInfoV1 {
                    handle: TASK_GROUP,
                    object_type: DW_OBJECT_TYPE_TASK_GROUP,
                    rights: LOADER_TASK_GROUP_EXPECTATION.rights,
                    ..DwReceivedHandleInfoV1::default()
                },
            ],
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
        bytes.copy_from_slice(&self.init);
        handles.copy_from_slice(&self.handles);
        Ok(ReceiveCounts {
            bytes: self.init.len(),
            handles: self.handles.len(),
        })
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

#[test]
fn init0_freshly_validates_all_delegated_handles_before_ready() {
    let mut fixture = Fixture::valid();
    assert_eq!(run_init0(&mut fixture, CHANNEL), Ok(()));
    assert_eq!(parse_ready(&fixture.sent, 7), Ok(()));
    assert_eq!(fixture.closed, [ROOT, BOOTFS, TASK_GROUP, CHANNEL]);
}

#[test]
fn init0_rejects_stale_bootfs_rights_before_ready() {
    let mut fixture = Fixture::valid();
    fixture.fresh_bootfs_rights = DwRights(0);
    assert_eq!(
        run_init0(&mut fixture, CHANNEL),
        Err(Init0Error::Capability(
            wyrmroot_runtime::CapabilityValidationError::InvalidFreshCapability
        ))
    );
    assert!(fixture.sent.is_empty());
    assert_eq!(fixture.closed, [ROOT, BOOTFS, TASK_GROUP]);
}

#[test]
fn init0_rejects_a_non_init0_launch_before_ready() {
    let mut fixture = Fixture::valid();
    encode_init(LaunchProfile::Hello, 7, &mut fixture.init).unwrap();
    assert!(matches!(
        run_init0(&mut fixture, CHANNEL),
        Err(Init0Error::Launch(_))
    ));
    assert!(fixture.sent.is_empty());
    assert_eq!(fixture.closed, [ROOT, BOOTFS, TASK_GROUP]);
}
