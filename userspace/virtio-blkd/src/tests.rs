//! virtio-blkd's admission checks, and its role driven end to end through the
//! runtime's recording platform.

use std::vec;
use std::vec::Vec;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_DEVICE_RESOURCE_INFO_V1_VERSION,
    DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION, DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_DEVICE_RESOURCE,
    DW_RIGHT_DUPLICATE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwDeadline,
    DwDeviceResourceInfoV1, DwHandle, DwReceivedHandleInfoV1, DwSignals, DwWaitItemV1,
    DwWaitResultV1,
};
use wyrmroot_device_proto::control::ControlEndpoint;
use wyrmroot_device_proto::control_v1_1::ControlIdentityV1_1;
use wyrmroot_device_proto::coordinator::{
    AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId,
};
use wyrmroot_device_proto::manifest::{
    BLOCK_DEVICE_PROTOCOL_ID, BOOT_DISK_POLICY, BOOT_DISK_SERVICE_NAME, RoleId,
};
use wyrmroot_device_proto::pci_driver::{
    self, GRANT_BYTES, PciDriverMessage, PublicationGrant, READY_BYTES, STAGE_BYTES,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS, encode_device_driver_init,
};
use wyrmroot_registry_proto::{
    HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader, Lookup,
    MessageType as RegistryMessageType, ProtocolVersion, encode_empty, encode_lookup,
};
use wyrmroot_runtime::platform::recording::{Call, Datagram, RecordingPlatform, Reply};
use wyrmroot_runtime::{BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo};

use super::*;

const BOOTSTRAP: DwHandle = DwHandle(0x10);
const SELF_ROOT: DwHandle = DwHandle(0x20);
const CONTROL: DwHandle = DwHandle(0x21);
const PUBLICATION: DwHandle = DwHandle(0x22);
const RESOURCE: DwHandle = DwHandle(0x23);
const OFFERED: DwHandle = DwHandle(0x24);
const LEASE: u64 = 0x77;
const LAUNCH_TRANSACTION: u64 = 10;

fn launch() -> LaunchCorrelation {
    LaunchCorrelation {
        role_id: BOOT_DISK_POLICY.role_id.0,
        attempt_generation: 4,
        endpoint_id: 6,
        endpoint_generation: 1,
        transaction_id: LAUNCH_TRANSACTION,
    }
}

fn identity() -> ControlIdentityV1_1 {
    ControlIdentityV1_1 {
        role_id: BOOT_DISK_POLICY.role_id,
        bundle_generation: BundleGeneration(LEASE),
        attempt_generation: AttemptGeneration(4),
        endpoint: ControlEndpoint {
            id: EndpointId(6),
            generation: EndpointGeneration(1),
        },
        transaction_id: LAUNCH_TRANSACTION + 1,
    }
}

fn stage_message() -> PciDriverMessage {
    PciDriverMessage::Stage {
        identity: identity(),
        resource_id: BOOT_DISK_POLICY.resource_id,
        function: BOOT_DISK_POLICY.pci,
    }
}

fn resource_handle() -> DwReceivedHandleInfoV1 {
    DwReceivedHandleInfoV1 {
        handle: RESOURCE,
        object_type: DW_OBJECT_TYPE_DEVICE_RESOURCE,
        rights: PCI_DRIVER_RESOURCE_RIGHTS,
        ..DwReceivedHandleInfoV1::default()
    }
}

fn resource_info() -> DwDeviceResourceInfoV1 {
    DwDeviceResourceInfoV1 {
        size: DW_DEVICE_RESOURCE_INFO_V1_SIZE,
        version: DW_DEVICE_RESOURCE_INFO_V1_VERSION,
        kind: DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
        resource_id: BOOT_DISK_POLICY.resource_id,
        lease_generation: LEASE,
        ..DwDeviceResourceInfoV1::default()
    }
}

fn admitted() -> AdmittedStage {
    admit_stage_message(launch(), stage_message()).unwrap()
}

#[test]
fn a_stage_must_carry_this_attempt_and_the_boot_disk_policy() {
    assert_eq!(admitted().identity, identity());
    let refused = |change: fn(&mut ControlIdentityV1_1)| {
        let mut identity = identity();
        change(&mut identity);
        admit_stage_message(
            launch(),
            PciDriverMessage::Stage {
                identity,
                resource_id: BOOT_DISK_POLICY.resource_id,
                function: BOOT_DISK_POLICY.pci,
            },
        )
    };
    for change in [
        (|identity: &mut ControlIdentityV1_1| identity.attempt_generation.0 += 1)
            as fn(&mut ControlIdentityV1_1),
        |identity| identity.endpoint.id.0 += 1,
        |identity| identity.endpoint.generation.0 += 1,
        |identity| identity.role_id = RoleId(1),
        // The STAGE has its own transaction, after the launch's.
        |identity| identity.transaction_id = LAUNCH_TRANSACTION,
    ] {
        assert_eq!(refused(change), Err(StageError::WrongIdentity));
    }
    let other_function = PciDriverMessage::Stage {
        identity: identity(),
        resource_id: BOOT_DISK_POLICY.resource_id,
        function: wyrmroot_device_proto::manifest::PciFunction {
            address: 2 << 3,
            ..BOOT_DISK_POLICY.pci
        },
    };
    assert_eq!(
        admit_stage_message(launch(), other_function),
        Err(StageError::WrongPolicy)
    );
    let other_resource = PciDriverMessage::Stage {
        identity: identity(),
        resource_id: 1,
        function: BOOT_DISK_POLICY.pci,
    };
    assert_eq!(
        admit_stage_message(launch(), other_resource),
        Err(StageError::WrongPolicy)
    );
    assert_eq!(
        admit_stage_message(
            launch(),
            PciDriverMessage::Ready {
                identity: identity()
            }
        ),
        Err(StageError::NotStage)
    );
}

/// devmgr moves exactly the rights the driver admits.
#[test]
fn devmgr_stages_exactly_the_rights_the_driver_admits() {
    assert_eq!(
        PCI_DRIVER_RESOURCE_RIGHTS,
        wyrmroot_devmgr::role::PCI_DRIVER_RESOURCE_RIGHTS
    );
}

#[test]
fn the_staged_handle_must_be_a_device_resource_with_exactly_the_driver_rights() {
    assert_eq!(admit_stage_handle(resource_handle()), Ok(()));
    let mut wider = resource_handle();
    wider.rights = DwRights(PCI_DRIVER_RESOURCE_RIGHTS.0 | DW_RIGHT_DUPLICATE.0);
    assert_eq!(admit_stage_handle(wider), Err(StageError::WrongHandle));
    let mut channel = resource_handle();
    channel.object_type = DW_OBJECT_TYPE_CHANNEL;
    assert_eq!(admit_stage_handle(channel), Err(StageError::WrongHandle));
    let mut reserved = resource_handle();
    reserved.reserved0 = 1;
    assert_eq!(admit_stage_handle(reserved), Err(StageError::WrongHandle));
}

#[test]
fn the_kernel_facts_must_name_the_staged_pci_resource_and_lease() {
    assert_eq!(admit_resource_info(admitted(), resource_info()), Ok(()));
    let cases: [fn(&mut DwDeviceResourceInfoV1); 6] = [
        |info| info.kind = DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
        |info| info.resource_id = 1,
        |info| info.lease_generation += 1,
        |info| info.pio_length = 8,
        |info| info.flags = 1,
        |info| info.version += 1,
    ];
    for change in cases {
        let mut info = resource_info();
        change(&mut info);
        assert_eq!(
            admit_resource_info(admitted(), info),
            Err(StageError::WrongResource)
        );
    }
}

#[test]
fn the_live_config_ids_must_be_the_modern_virtio_block_device() {
    assert_eq!(admit_config_ids(admitted(), 0x1042_1af4), Ok(()));
    // The transitional (legacy-capable) virtio block device is not admitted.
    assert_eq!(
        admit_config_ids(admitted(), 0x1001_1af4),
        Err(StageError::WrongIds)
    );
    assert_eq!(
        admit_config_ids(admitted(), u32::MAX),
        Err(StageError::WrongIds)
    );
}

// --- The role, end to end. ---

fn grant() -> PublicationGrant {
    PublicationGrant {
        registry_generation: 3,
        endpoint_id: 9,
        endpoint_generation: 1,
        transaction_id: 0x55,
        service_generation: 0x66,
    }
}

fn ready_wait(index: u32, signals: DwSignals) -> Reply {
    Reply::Wait(Ok(DwWaitResultV1 {
        index,
        observed: signals,
        ..DwWaitResultV1::default()
    }))
}

fn receive(bytes: Vec<u8>, handles: Vec<DwReceivedHandleInfoV1>) -> Reply {
    Reply::Receive(Ok(Datagram { bytes, handles }))
}

fn channel(handle: DwHandle) -> DwReceivedHandleInfoV1 {
    DwReceivedHandleInfoV1 {
        handle,
        object_type: DW_OBJECT_TYPE_CHANNEL,
        rights: CHILD_CHANNEL_RIGHTS,
        ..DwReceivedHandleInfoV1::default()
    }
}

fn startup_replies() -> Vec<Reply> {
    let mut init = vec![0; DEVICE_DRIVER_BYTES];
    encode_device_driver_init(LAUNCH_TRANSACTION, 1, 2, 4, 5, 6, 1, &mut init).unwrap();
    let mut grant_bytes = [0; GRANT_BYTES];
    pci_driver::encode_grant(grant(), &mut grant_bytes).unwrap();
    vec![
        Reply::CapabilityInfo(Ok(CapabilityInfo {
            object_type: BOOTSTRAP_CHANNEL_EXPECTATION.object_type,
            rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
        })),
        receive(
            init,
            vec![
                DwReceivedHandleInfoV1 {
                    handle: SELF_ROOT,
                    object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
                    rights: SELF_ROOT_RIGHTS,
                    ..DwReceivedHandleInfoV1::default()
                },
                channel(CONTROL),
            ],
        ),
        Reply::Deadline(Ok(DwDeadline(100))),
        ready_wait(0, DW_SIGNAL_READABLE),
        receive(grant_bytes.to_vec(), vec![channel(PUBLICATION)]),
        // Close the launch Channel.
        Reply::Unit(Ok(())),
    ]
}

fn stage_replies(ids: u32) -> Vec<Reply> {
    let mut stage = vec![0; STAGE_BYTES];
    pci_driver::encode(stage_message(), &mut stage).unwrap();
    vec![
        Reply::Deadline(Ok(DwDeadline(200))),
        ready_wait(0, DW_SIGNAL_READABLE),
        receive(stage, vec![resource_handle()]),
        Reply::DeviceResourceInfo(Ok(resource_info())),
        Reply::Pio(Ok(ids)),
    ]
}

fn published_header() -> RegistryHeader {
    RegistryHeader {
        message_type: RegistryMessageType::Publish,
        registry_generation: 3,
        endpoint_id: 9,
        endpoint_generation: 1,
        transaction_id: 0x55,
    }
}

fn registry_bytes(message_type: RegistryMessageType) -> Vec<u8> {
    let mut bytes = vec![0; REGISTRY_HEADER_BYTES];
    let size = encode_empty(
        RegistryHeader {
            message_type,
            ..published_header()
        },
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(size);
    bytes
}

fn offer_bytes() -> Vec<u8> {
    let mut bytes = vec![0; 512];
    let size = encode_lookup(
        RegistryHeader {
            message_type: RegistryMessageType::ConnectOffer,
            ..published_header()
        },
        Lookup {
            protocol_id: BLOCK_DEVICE_PROTOCOL_ID,
            version: ProtocolVersion { major: 1, minor: 0 },
            service_name: BOOT_DISK_SERVICE_NAME,
        },
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(size);
    bytes
}

fn run_scripted(script: Vec<Reply>) -> (u32, Vec<Call>) {
    let mut platform = RecordingPlatform::scripted(script);
    let code = role::blk_main(&mut platform, BOOTSTRAP);
    platform.assert_script_consumed();
    (code, platform.take_calls())
}

fn sent_on(calls: &[Call], channel: DwHandle) -> Vec<Vec<u8>> {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::SendChannel {
                channel: target,
                bytes,
                transfers,
            } if *target == channel => {
                assert!(transfers.is_empty(), "the driver never sends a handle");
                Some(bytes.clone())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn the_driver_stages_publishes_refuses_offers_and_exits_when_devmgr_closes() {
    let mut script = startup_replies();
    script.extend(stage_replies(BOOT_DISK_POLICY.pci.ids));
    script.extend([
        // READY to devmgr, PUBLISH to the registry and its PUBLISHED.
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Deadline(Ok(DwDeadline(300))),
        ready_wait(0, DW_SIGNAL_READABLE),
        receive(registry_bytes(RegistryMessageType::Published), vec![]),
        // One connection offer, whose endpoint is closed.
        ready_wait(1, DW_SIGNAL_READABLE),
        receive(offer_bytes(), vec![channel(OFFERED)]),
        Reply::Unit(Ok(())),
        // devmgr closes the control Channel.
        ready_wait(0, DW_SIGNAL_PEER_CLOSED),
        // Resource, publication, control and self root are closed.
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    let (code, calls) = run_scripted(script);
    assert_eq!(code, 0);

    let mut ready = [0; READY_BYTES];
    pci_driver::encode(
        PciDriverMessage::Ready {
            identity: identity(),
        },
        &mut ready,
    )
    .unwrap();
    assert_eq!(sent_on(&calls, CONTROL), [ready.to_vec()]);
    assert_eq!(
        sent_on(&calls, PUBLICATION),
        [registry_bytes(RegistryMessageType::Publish)]
    );
    assert!(calls.contains(&Call::DevicePciConfigRead {
        resource: RESOURCE,
        offset: PCI_CONFIG_IDS,
        width: 4,
    }));
    // The serve loop waits on both endpoints with no deadline.
    assert!(calls.contains(&Call::WaitMany {
        items: vec![
            DwWaitItemV1 {
                handle: CONTROL,
                signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            },
            DwWaitItemV1 {
                handle: PUBLICATION,
                signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            },
        ],
        deadline: DW_DEADLINE_INFINITE,
    }));
    let closes: Vec<_> = calls
        .iter()
        .filter_map(|call| match call {
            Call::CloseHandle { handle } => Some(*handle),
            _ => None,
        })
        .collect();
    assert_eq!(
        closes,
        [
            BOOTSTRAP,
            OFFERED,
            RESOURCE,
            PUBLICATION,
            CONTROL,
            SELF_ROOT
        ]
    );
}

#[test]
fn a_function_with_other_ids_gets_no_ready_and_no_publication() {
    let mut script = startup_replies();
    script.extend(stage_replies(0x1001_1af4));
    script.extend([
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    let (code, calls) = run_scripted(script);
    assert_eq!(code, role::FAILURE_BASE | StageError::WrongIds.code());
    assert!(sent_on(&calls, CONTROL).is_empty());
    assert!(sent_on(&calls, PUBLICATION).is_empty());
    assert!(calls.ends_with(&[
        Call::CloseHandle { handle: RESOURCE },
        Call::CloseHandle {
            handle: PUBLICATION
        },
        Call::CloseHandle { handle: CONTROL },
        Call::CloseHandle { handle: SELF_ROOT },
    ]));
}

#[test]
fn a_launch_channel_closed_before_the_grant_stops_the_driver_unstaged() {
    let mut script = startup_replies();
    script.truncate(3);
    script.extend([
        ready_wait(0, DW_SIGNAL_PEER_CLOSED),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    let (code, calls) = run_scripted(script);
    assert_eq!(code, role::FAILURE_BASE | 11);
    assert!(calls.ends_with(&[
        Call::CloseHandle { handle: CONTROL },
        Call::CloseHandle { handle: SELF_ROOT },
        Call::CloseHandle { handle: BOOTSTRAP },
    ]));
}
